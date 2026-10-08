use crepe_storage::{identity, query, Row, Writer};
use std::fs;
#[test]
fn atomic_restart_query_schema_and_idempotency() {
    let root = std::env::temp_dir().join(format!("crepe-store-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let id = identity(&["sensor", "capture"]);
    {
        let mut w = Writer::begin(&root, &id).unwrap();
        assert!(Writer::begin(&root, &identity(&["other"])).is_err());
        for n in 0..1100 {
            w.push(Row {
                event_id: identity(&[&n.to_string()]),
                flow_id: "flow1".into(),
                sensor: "test".into(),
                source: "capture".into(),
                event_type: "packet".into(),
                dst_port: Some(443),
                bytes: Some(100),
                packets: Some(1),
                src_ip: Some("10.0.0.1".into()),
                payload: "{}".into(),
                ..Default::default()
            })
            .unwrap();
        }
        let mut before = vec![];
        assert_eq!(query(&root, "* | count", &mut before).unwrap(), 1);
        assert!(String::from_utf8(before).unwrap().contains("\"count\":0"));
        assert_eq!(w.commit().unwrap(), 1100);
    }
    assert!(Writer::begin(&root, &id).is_err());
    let mut out = vec![];
    query(
        &root,
        "dst.port == 443 | group src.ip | sort bytes desc",
        &mut out,
    )
    .unwrap();
    let rows: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(rows["count"], 1100);
    assert_eq!(rows["bytes"], 110000);
    {
        let mut w = Writer::begin(&root, &identity(&["aborted"])).unwrap();
        w.push(Row::default()).unwrap();
    }
    assert!(fs::read(root.join("writer.lock")).unwrap().is_empty());
    fs::write(root.join("schema.json"), "{\"schema_version\":99}").unwrap();
    assert!(query(&root, "*", &mut vec![]).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn checkpoint_survives_aborted_next_batch_and_keeps_writer_lock() {
    let root = std::env::temp_dir().join(format!("crepe-checkpoint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut writer =
        crepe_storage::Writer::begin(&root, &crepe_storage::identity(&["live-first"])).unwrap();
    writer
        .push(crepe_storage::Row {
            event_id: "published".into(),
            event_type: "packet".into(),
            ..Default::default()
        })
        .unwrap();
    writer
        .checkpoint(&crepe_storage::identity(&["live-second"]))
        .unwrap();
    assert!(
        crepe_storage::Writer::begin(&root, &crepe_storage::identity(&["other-writer"])).is_err()
    );
    writer
        .push(crepe_storage::Row {
            event_id: "aborted".into(),
            ..Default::default()
        })
        .unwrap();
    drop(writer);
    let mut output = Vec::new();
    crepe_storage::query(&root, "* | select event.id", &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("published"));
    assert!(!text.contains("aborted"));
    assert!(fs::read(root.join("writer.lock")).unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn application_fields_cidr_units_and_explicit_aggregates() {
    let root = std::env::temp_dir().join(format!("crepe-rich-query-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut writer = Writer::begin(&root, &identity(&["rich-query"])).unwrap();
    for (source, bytes) in [
        ("192.0.2.1", 1024),
        ("192.0.2.1", 3072),
        ("198.51.100.1", 8192),
    ] {
        writer
            .push(Row {
                event_type: "tls.client_hello".into(),
                src_ip: Some(source.into()),
                bytes: Some(bytes),
                dst_port: Some(443),
                timestamp_ms: Some(61000),
                payload: r#"{"protocol":{"server_name":"api.example.test"}}"#.into(),
                ..Default::default()
            })
            .unwrap();
    }
    writer.commit().unwrap();
    let mut out = Vec::new();
    query(&root, "src.ip in 192.0.2.0/24 && tls.server_name ends_with \".example.test\" && bytes >= 1KB | group src.ip | avg bytes as mean | sort mean desc", &mut out).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["mean"], 2048.0);
    let mut out = Vec::new();
    query(
        &root,
        "tls.server_name contains \"example\" | select tls.server_name | distinct tls.server_name",
        &mut out,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["tls_server_name"],
        "api.example.test"
    );
    let mut out = Vec::new();
    query(&root, "time >= now() - 30m | count", &mut out).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["count"],
        0
    );
    let mut out = Vec::new();
    query(
        &root,
        "dst.port in [80, 443] | window 1m | group src.ip | count | sort count desc",
        &mut out,
    )
    .unwrap();
    let values: Vec<serde_json::Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0]["count"], 2);
    assert_eq!(values[0]["window_start_ms"], 60000);
    let mut out = Vec::new();
    query(&root, "* | top 1 src.ip", &mut out).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["count"],
        2
    );
    assert!(crepe_storage::compile("src.ip in not-a-network").is_err());
    assert!(crepe_storage::compile("* | sum proto as total").is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn compaction_retains_ids_untimed_rows_and_import_guards() {
    let base = std::env::temp_dir().join(format!("crepe-compaction-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir(&base).unwrap();
    let source = base.join("source");
    let destination = base.join("copy");
    let original = identity(&["original-capture"]);
    let mut writer = Writer::begin(&source, &original).unwrap();
    for (id, time) in [("old", Some(100)), ("new", Some(200)), ("unknown", None)] {
        writer
            .push(Row {
                event_id: id.into(),
                timestamp_ms: time,
                ..Default::default()
            })
            .unwrap();
    }
    assert!(crepe_storage::compact(&source, &destination, None).is_err());
    writer.commit().unwrap();
    let result = crepe_storage::compact(&source, &destination, Some(150)).unwrap();
    assert_eq!((result.read, result.retained, result.discarded), (3, 2, 1));
    assert!(Writer::begin(&destination, &original).is_err());
    assert!(crepe_storage::compact(&source, &destination, None).is_err());
    let mut out = Vec::new();
    query(&destination, "* | select event.id", &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("new") && text.contains("unknown") && !text.contains("old"));
    let mut out = Vec::new();
    query(&source, "* | count", &mut out).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["count"],
        3
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn legacy_locks_fail_closed_and_abandoned_modern_staging_is_recovered() {
    let root = std::env::temp_dir().join(format!("crepe-lock-migration-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::write(root.join("writer.lock"), "12345\n").unwrap();
    assert!(Writer::begin(&root, &identity(&["new"]))
        .err()
        .unwrap()
        .message
        .contains("legacy"));
    assert_eq!(
        fs::read_to_string(root.join("writer.lock")).unwrap(),
        "12345\n"
    );
    fs::write(root.join("writer.lock"), "crepe-lock-v1 12345\n").unwrap();
    let abandoned = root.join(format!(".staging-{}", identity(&["abandoned"])));
    fs::create_dir(&abandoned).unwrap();
    fs::write(abandoned.join("unfinished.parquet"), b"partial").unwrap();
    let writer = Writer::begin(&root, &identity(&["new"])).unwrap();
    assert!(!abandoned.exists());
    writer.commit().unwrap();
    assert!(fs::read(root.join("writer.lock")).unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn live_queries_include_hot_rows_without_checkpoint_duplicates() {
    let root = std::env::temp_dir().join(format!("crepe-hot-query-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let mut writer = Writer::begin(&root, &identity(&["hot-first"])).unwrap();
    writer.enable_hot_queries().unwrap();
    writer
        .push(Row {
            event_id: "hot-one".into(),
            ..Default::default()
        })
        .unwrap();
    let count = || {
        let mut out = Vec::new();
        query(&root, "* | count", &mut out).unwrap();
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["count"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(count(), 1);
    writer.checkpoint(&identity(&["hot-second"])).unwrap();
    assert_eq!(count(), 1);
    writer
        .push(Row {
            event_id: "hot-two".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(count(), 2);
    drop(writer);
    assert_eq!(count(), 1);
    assert!(!root.join(".hot.jsonl").exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn concurrent_hot_journal_rotation_has_no_gaps_or_duplicates() {
    let root = std::env::temp_dir().join(format!("crepe-hot-concurrent-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let mut writer = Writer::begin(&root, &identity(&["concurrent-first"])).unwrap();
    writer.enable_hot_queries().unwrap();
    let thread = std::thread::spawn(move || {
        for n in 0..50 {
            for i in 0..10 {
                writer
                    .push(Row {
                        event_id: format!("{n}-{i}"),
                        ..Default::default()
                    })
                    .unwrap();
            }
            writer
                .checkpoint(&identity(&["concurrent", &n.to_string()]))
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(3));
        }
        writer.commit().unwrap();
    });
    let mut previous = 0;
    loop {
        let mut out = Vec::new();
        query(&root, "* | count", &mut out).unwrap();
        let count = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["count"]
            .as_u64()
            .unwrap();
        assert!(
            count >= previous && count <= 500,
            "previous={previous}, current={count}"
        );
        previous = count;
        if thread.is_finished() {
            break;
        }
    }
    thread.join().unwrap();
    let mut out = Vec::new();
    query(&root, "* | count", &mut out).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap()["count"],
        500
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_schema_is_readable_but_never_silently_reinterpreted_or_upgraded() {
    use datafusion::arrow::{datatypes::Schema, record_batch::RecordBatch};
    use parquet::arrow::{arrow_reader::ParquetRecordBatchReaderBuilder, ArrowWriter};
    use std::{fs::File, sync::Arc};
    let root =
        std::env::temp_dir().join(format!("crepe-legacy-schema-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let mut writer = Writer::begin(&root, &identity(&["legacy-fixture"])).unwrap();
    writer
        .push(Row {
            event_id: identity(&["old-event"]),
            flow_id: "old-tuple".into(),
            event_type: "packet".into(),
            payload: "{}".into(),
            ..Default::default()
        })
        .unwrap();
    writer.commit().unwrap();
    fn parts(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                parts(&path, out)
            } else if path.extension().is_some_and(|e| e == "parquet") {
                out.push(path)
            }
        }
    }
    let mut files = Vec::new();
    parts(&root.join("data"), &mut files);
    for path in files {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let batches: Vec<_> = reader.map(|r| r.unwrap()).collect();
        let old_schema = batches[0].schema();
        let indexes: Vec<_> = old_schema
            .fields()
            .iter()
            .enumerate()
            .filter(|(_, f)| !["conversation_id", "identity_status"].contains(&f.name().as_str()))
            .map(|(i, _)| i)
            .collect();
        let schema = Arc::new(Schema::new(
            indexes
                .iter()
                .map(|&i| old_schema.field(i).clone())
                .collect::<Vec<_>>(),
        ));
        let mut writer =
            ArrowWriter::try_new(File::create(&path).unwrap(), schema.clone(), None).unwrap();
        for b in batches {
            writer
                .write(
                    &RecordBatch::try_new(
                        schema.clone(),
                        indexes.iter().map(|&i| b.column(i).clone()).collect(),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        writer.close().unwrap();
    }
    fs::write(root.join("schema.json"), "{\"schema_version\":1}").unwrap();
    let mut result = vec![];
    query(&root, "* | select flow.id", &mut result).unwrap();
    assert!(String::from_utf8(result).unwrap().contains("old-tuple"));
    assert_eq!(crepe_storage::schema_version(&root).unwrap(), 1);
    assert!(Writer::begin(&root, &identity(&["new-import"]))
        .err()
        .unwrap()
        .message
        .contains("read-only"));
    assert_eq!(
        fs::read_to_string(root.join("schema.json")).unwrap(),
        "{\"schema_version\":1}"
    );
    fs::remove_dir_all(root).unwrap();
}
