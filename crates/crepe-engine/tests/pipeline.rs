use crepe_engine::{ingest, Config};
use std::{fs, path::PathBuf};
#[test]
fn protocols_fragments_restart_and_stable_identity() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = std::env::temp_dir().join(format!("crepe-engine-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let c = Config::default();
    let summary = ingest(&repo.join("fixtures/protocols.pcap"), &root, &c).unwrap();
    assert_eq!(summary.packets, 9);
    let mut out = vec![];
    crepe_storage::query(&root, "event.type == tls.client_hello", &mut out).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(value["payload"].as_str().unwrap().contains("example.test"));
    let id = value["flow_id"].as_str().unwrap();
    let mut trace = vec![];
    crepe_storage::query(&root, &format!("flow.id == {id} | count"), &mut trace).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&trace).unwrap()["count"],
        5
    );
    let summary = ingest(&repo.join("fixtures/fragments.pcap"), &root, &c).unwrap();
    assert_eq!(summary.incomplete_datagrams, 0);
    let mut out = vec![];
    crepe_storage::query(&root, "event.type == dns.query | count", &mut out).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["count"],
        2
    );
    assert!(ingest(&repo.join("fixtures/protocols.pcap"), &root, &c).is_err());
    let other = root.join("reimport");
    ingest(&repo.join("fixtures/protocols.pcap"), &other, &c).unwrap();
    let mut same = vec![];
    crepe_storage::query(&other, "event.type == tls.client_hello", &mut same).unwrap();
    let same: serde_json::Value = serde_json::from_slice(&same).unwrap();
    assert_eq!(same["event_id"], value["event_id"]);
    assert_eq!(same["flow_id"], value["flow_id"]);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn streaming_observations_are_emitted_before_source_finishes() {
    use std::cell::Cell;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dns.pcap");
    let observed = Cell::new(0);
    let summary = crepe_engine::stream(
        "test-live-source",
        None,
        &Default::default(),
        |emit| {
            crepe_capture::read_records(crepe_capture::open(&path)?, |record| {
                let result = emit(record)?;
                assert!(observed.get() > 0, "events must appear before end-of-input");
                Ok(result)
            })
        },
        &mut |_| {
            observed.set(observed.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.observations, observed.get());
}

#[test]
fn indicator_matches_persist_with_original_event_identity() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = std::env::temp_dir().join(format!("crepe-intel-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let config = Config {
        intel_feed: Some(repo.join("config/intel-example.jsonl")),
        policy_rules: Some(repo.join("config/policies-example.jsonl")),
        ..Default::default()
    };
    ingest(&repo.join("fixtures/dns.pcap"), &root, &config).unwrap();
    let mut out = Vec::new();
    crepe_storage::query(&root, "event.type == intel.match", &mut out).unwrap();
    assert!(!out.is_empty());
    for line in std::str::from_utf8(&out).unwrap().lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            row["packets"].is_null() && row["bytes"].is_null(),
            "derived findings must not duplicate wire counters"
        );
        let payload: serde_json::Value =
            serde_json::from_str(row["payload"].as_str().unwrap()).unwrap();
        let id = payload["source_event_id"].as_str().unwrap();
        let mut original = Vec::new();
        crepe_storage::query(&root, &format!("event.id == {id} | count"), &mut original).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&original).unwrap()["count"],
            1
        );
    }
    let mut out = Vec::new();
    crepe_storage::query(&root, "event.type == notice.policy", &mut out).unwrap();
    assert!(!out.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "plugins")]
#[test]
fn component_plugin_notices_are_correlated_and_persisted() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let config = Config {
        plugins: vec![repo.join("plugins/example/manifest.json")],
        ..Default::default()
    };
    let mut notices = Vec::new();
    crepe_engine::stream(
        "plugin-integration",
        None,
        &config,
        |emit| {
            crepe_capture::read_records(crepe_capture::open(&repo.join("fixtures/dns.pcap"))?, emit)
        },
        &mut |row| {
            if row.event_type == "notice.plugin" {
                notices.push(row.clone());
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(!notices.is_empty());
    for row in notices {
        let value: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        assert_eq!(value["plugin"], "example-notice");
        assert_eq!(value["source_event_id"].as_str().unwrap().len(), 64);
    }
}

#[test]
fn tolerant_decode_emits_anomalies_and_preserves_valid_following_packets() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for tolerant in [false, true] {
        let config = Config {
            tolerant_decode: tolerant,
            ..Default::default()
        };
        let mut malformed = 0;
        let mut packets = 0;
        let result = crepe_engine::stream(
            "malformed",
            None,
            &config,
            |emit| {
                crepe_capture::read_records(
                    crepe_capture::open(&repo.join("example.pcap"))?,
                    |record| {
                        let bad = crepe_capture::Record {
                            data: &[0],
                            header: record.header.clone(),
                            linktype: 1,
                        };
                        emit(bad)?;
                        emit(record)
                    },
                )
            },
            &mut |row| {
                if row.event_type == "anomaly.decode" {
                    malformed += 1;
                }
                if row.event_type == "packet" {
                    packets += 1;
                }
                Ok(())
            },
        );
        if tolerant {
            assert!(result.is_ok());
            assert_eq!(malformed, 6);
            assert_eq!(packets, 6);
        } else {
            assert_eq!(result.unwrap_err().code, "CREPE-PKT-001");
        }
    }
}

#[test]
fn parallel_workers_preserve_reassembly_counts_and_stop_on_sink_failure() {
    use std::collections::BTreeMap;
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut reference = None;
    for workers in [1, 2, 4] {
        let config = Config {
            workers,
            ..Default::default()
        };
        let mut counts = BTreeMap::new();
        for name in [
            "fixtures/fragments.pcap",
            "fixtures/protocols.pcap",
            "fixtures/dns.pcap",
        ] {
            crepe_engine::stream(
                name,
                None,
                &config,
                |emit| crepe_capture::read_records(crepe_capture::open(&repo.join(name))?, emit),
                &mut |row| {
                    *counts.entry(row.event_type.clone()).or_insert(0) += 1;
                    Ok(())
                },
            )
            .unwrap();
        }
        if let Some(reference) = &reference {
            assert_eq!(reference, &counts);
        } else {
            reference = Some(counts);
        }
    }
    let config = Config {
        workers: 4,
        ..Default::default()
    };
    let mut count = 0;
    let error = crepe_engine::stream(
        "failed-output",
        None,
        &config,
        |emit| {
            for _ in 0..1000 {
                crepe_capture::read_records(
                    crepe_capture::open(&repo.join("example.pcap"))?,
                    &mut *emit,
                )?;
            }
            Ok(())
        },
        &mut |_| {
            count += 1;
            if count > 2 {
                Err(crepe_core::Error::new(
                    "CREPE-IO-002",
                    "intentional sink failure",
                ))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "CREPE-IO-002");
}
