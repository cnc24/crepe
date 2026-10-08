use std::{path::PathBuf, process::Command};
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name)
}
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_crepe"))
}
#[test]
fn target_command_and_json() {
    let table = cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .arg("dst.port == 443")
        .output()
        .unwrap();
    assert!(table.status.success());
    let text = String::from_utf8(table.stdout).unwrap();
    assert_eq!(text.lines().count(), 3);
    assert!(text.contains("2001:db8::20"));
    let json = cli()
        .arg("read")
        .arg(fixture("fixtures/example.pcapng"))
        .args(["dst.port == 443", "--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert!(json.stderr.is_empty());
    let rows: Vec<serde_json::Value> = String::from_utf8(json.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["dst"]["port"], 443);
    assert_eq!(rows[0]["header"]["event_type"], "packet");
}
#[test]
fn errors_have_stable_codes_and_exit_statuses() {
    let query = cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .arg("dst.port == baguette")
        .output()
        .unwrap();
    assert_eq!(query.status.code(), Some(2));
    assert!(query.stdout.is_empty());
    assert!(String::from_utf8(query.stderr)
        .unwrap()
        .contains("Sacré bleu! [CREPE-CQL-001]"));
    let missing = cli()
        .args(["read", "does-not-exist.pcap"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8(missing.stderr)
        .unwrap()
        .contains("CREPE-IO-001"));
    let usage = cli().arg("read").output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
    assert!(String::from_utf8(usage.stderr)
        .unwrap()
        .contains("CREPE-CLI-001"));
}
#[test]
fn help_version_empty_results_and_unfiltered() {
    for flag in ["--help", "--version"] {
        assert!(cli().arg(flag).output().unwrap().status.success());
    }
    let none = cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .args(["proto == 255", "--format", "json"])
        .output()
        .unwrap();
    assert!(none.status.success());
    assert!(none.stdout.is_empty());
    let all = cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(all.status.success());
    assert_eq!(String::from_utf8(all.stdout).unwrap().lines().count(), 6);
}

fn temp_dir() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "crepe-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}
#[test]
fn export_roundtrip_limit_and_no_overwrite() {
    let dir = temp_dir();
    let capture = dir.join("selected.pcap");
    let result = cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .args([
            "dst.port in [443, 53]",
            "--limit",
            "2",
            "--format",
            "csv",
            "--write",
        ])
        .arg(&capture)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let csv = String::from_utf8(result.stdout).unwrap();
    assert_eq!(csv.lines().count(), 3);
    assert!(csv.lines().all(|line| line.split(',').count() == 17));
    let replay = cli()
        .arg("read")
        .arg(&capture)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(replay.status.success());
    let rows: Vec<serde_json::Value> = String::from_utf8(replay.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["dst"]["port"], 443);
    assert_eq!(rows[1]["dst"]["port"], 53);
    assert_eq!(rows[0]["header"]["timestamp_ns"], "1700000000123456000");
    let original = std::fs::read(&capture).unwrap();
    let again = cli()
        .arg("read")
        .arg(&capture)
        .arg("--write")
        .arg(&capture)
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(1));
    assert!(String::from_utf8(again.stderr)
        .unwrap()
        .contains("CREPE-IO-002"));
    assert_eq!(std::fs::read(&capture).unwrap(), original);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn empty_export_is_valid_and_missing_timestamp_is_rejected() {
    let dir = temp_dir();
    let capture = dir.join("empty.pcap");
    assert!(cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .args(["proto == 255", "--write"])
        .arg(&capture)
        .output()
        .unwrap()
        .status
        .success());
    let replay = cli()
        .arg("read")
        .arg(&capture)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(replay.status.success());
    assert!(replay.stdout.is_empty());
    let missing = cli()
        .arg("read")
        .arg(fixture("fixtures/simple.pcapng"))
        .arg("--write")
        .arg(dir.join("missing.pcap"))
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8(missing.stderr)
        .unwrap()
        .contains("CREPE-CAP-004"));
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn flow_cli_reports_counters_and_csv() {
    let result = cli()
        .arg("flows")
        .arg(fixture("fixtures/flows.pcap"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let rows: Vec<serde_json::Value> = String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 3);
    let tcp = rows.iter().find(|f| f["end_reason"] == "tcp_fin").unwrap();
    assert_eq!(tcp["packets_a"], 3);
    assert_eq!(tcp["packets_b"], 2);
    let csv = cli()
        .arg("flows")
        .arg(fixture("fixtures/flows.pcap"))
        .args(["proto == udp", "--format", "csv"])
        .output()
        .unwrap();
    assert!(csv.status.success());
    let csv = String::from_utf8(csv.stdout).unwrap();
    assert_eq!(csv.lines().count(), 2);
    assert!(csv.lines().all(|l| l.split(',').count() == 18));
    let limit = cli()
        .arg("flows")
        .arg(fixture("example.pcap"))
        .args(["--max-flows", "0"])
        .output()
        .unwrap();
    assert_eq!(limit.status.code(), Some(2));
    let no_time = cli()
        .arg("flows")
        .arg(fixture("fixtures/simple.pcapng"))
        .output()
        .unwrap();
    assert_eq!(no_time.status.code(), Some(1));
    assert!(String::from_utf8(no_time.stderr)
        .unwrap()
        .contains("CREPE-FLOW-001"));
}
#[cfg(feature = "live")]
#[test]
fn live_usage_and_missing_interface_are_clear() {
    let help = cli().args(["capture", "--help"]).output().unwrap();
    assert!(help.status.success());
    let duration = cli()
        .args(["capture", "-i", "lo", "--duration", "0"])
        .output()
        .unwrap();
    assert_eq!(duration.status.code(), Some(2));
    let missing = cli()
        .args([
            "capture",
            "-i",
            "crepe_nonexistent_interface",
            "--duration",
            "1",
        ])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8(missing.stderr)
        .unwrap()
        .contains("CREPE-CAP-001"));
}

#[test]
fn loopback_export_preserves_native_family_byte_order() {
    let dir = temp_dir();
    let fixture_data = std::fs::read(fixture("example.pcap")).unwrap();
    let mut data = fixture_data[..24].to_vec();
    data[20..24].copy_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&fixture_data[24..32]);
    data.extend_from_slice(&44u32.to_le_bytes());
    data.extend_from_slice(&44u32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&fixture_data[54..94]);
    let input = dir.join("input.pcap");
    let output = dir.join("output.pcap");
    std::fs::write(&input, &data).unwrap();
    let result = cli()
        .arg("read")
        .arg(&input)
        .arg("--write")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let file = std::fs::File::open(&output).unwrap();
    let mut reader = pcap_file::pcap::PcapReader::new(file).unwrap();
    assert_eq!(reader.header().endianness, pcap_file::Endianness::Little);
    assert_eq!(
        reader.next_packet().unwrap().unwrap().data.as_ref(),
        &data[40..]
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn analyze_cli_dns_and_anomaly_output() {
    let result = cli()
        .arg("analyze")
        .arg(fixture("fixtures/dns.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let rows: Vec<serde_json::Value> = String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0]["dns"]["questions"][0]["name"], "example.test.");
    assert_eq!(rows[1]["dns"]["answers"][0]["data"]["value"], "203.0.113.7");
    assert_eq!(rows[3]["packet"]["header"]["sequence"], 7);
    let result = cli()
        .arg("analyze")
        .arg(fixture("fixtures/dns-malformed.pcap"))
        .args(["--format", "csv"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let csv = String::from_utf8(result.stdout).unwrap();
    assert_eq!(csv.lines().count(), 3);
    assert!(csv.contains("CREPE-TCP-002"));
    let result = cli()
        .arg("analyze")
        .arg(fixture("fixtures/dns.pcap"))
        .args(["--max-streams", "0"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn profile_menu_and_overrides_select_stored_observations() {
    let menu = cli().arg("profiles").output().unwrap();
    assert!(menu.status.success());
    let menu: serde_json::Value = serde_json::from_slice(&menu.stdout).unwrap();
    assert_eq!(menu["profiles"].as_object().unwrap().len(), 6);
    for profile in ["sucre", "chocolate", "suzette", "maison", "complete"] {
        let dir = temp_dir();
        let config = dir.join("config.toml");
        std::fs::write(&config, "profile = \"complete\"\n").unwrap();
        let store = dir.join("history");
        let imported = cli()
            .arg("ingest")
            .arg(fixture("fixtures/dns.pcap"))
            .arg("--store")
            .arg(&store)
            .arg("--config")
            .arg(&config)
            .args(["--profile", profile])
            .output()
            .unwrap();
        assert!(
            imported.status.success(),
            "{}",
            String::from_utf8_lossy(&imported.stderr)
        );
        let queried = cli()
            .arg("query")
            .arg(&store)
            .arg("* | select event.type")
            .output()
            .unwrap();
        assert!(queried.status.success());
        let kinds: Vec<String> = String::from_utf8(queried.stdout)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["event_type"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert!(!kinds.is_empty());
        match profile {
            "sucre" => assert!(kinds.iter().all(|k| k == "packet")),
            _ => {
                assert!(kinds.iter().any(|k| k == "packet"));
                assert!(kinds.iter().any(|k| k == "flow.end"));
                assert!(kinds.iter().any(|k| k.starts_with("dns.")));
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    let invalid = cli()
        .arg("ingest")
        .arg(fixture("fixtures/dns.pcap"))
        .args(["--store", "unused", "--profile", "baguette"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("CREPE-CLI-001"));
}

#[test]
fn direct_recipes_match_the_design_and_maison_uses_configuration() {
    for name in ["chocolate", "suzette", "complete"] {
        let case_root = tempfile::tempdir().unwrap();
        let output = cli()
            .current_dir(case_root.path())
            .arg(name)
            .arg(fixture("fixtures/protocols.pcap"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rows: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for kind in [
            "packet",
            "flow.end",
            "tls.client_hello",
            "http.request",
            "ssh.banner",
        ] {
            assert!(
                rows.iter().any(|row| row["event_type"] == kind),
                "{name}: missing {kind}"
            );
        }
    }
    let dir = temp_dir();
    let config = dir.join("custom.toml");
    std::fs::write(&config, "profile = \"sucre\"\nsensor = \"custom\"\n").unwrap();
    let output = cli()
        .arg("maison")
        .arg(fixture("example.pcap"))
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    assert!(output.status.success());
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(row["event_type"], "packet");
        assert_eq!(row["sensor"], "custom");
    }
    let output = cli().arg("chocolate").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("source menu"));
    let output = cli()
        .arg("ingest")
        .arg(fixture("example.pcap"))
        .arg("--store")
        .arg(dir.join("unused"))
        .args(["--profile", "banane"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Banane collects NetFlow/IPFIX"));
    assert!(!dir.join("unused").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn banane_accepts_udp_address_and_rejects_non_udp() {
    let output = cli()
        .args(["banane", "--listen", "udp://127.0.0.1:0", "--duration", "1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Collector listening"));
    let output = cli()
        .args(["banane", "--listen", "tcp://127.0.0.1:0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn serious_and_json_logs_keep_error_codes_without_flair() {
    let result = cli()
        .args(["--serious", "read", "missing.pcap"])
        .output()
        .unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("CREPE-IO-001"));
    assert!(!stderr.contains("Sacré"));
    let result = cli()
        .args(["--log-format", "json", "read", "missing.pcap"])
        .output()
        .unwrap();
    let log: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(log["severity"], "error");
    assert_eq!(log["code"], "CREPE-IO-001");
    let result = cli().args(["--log-format=json", "read"]).output().unwrap();
    let log: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(log["code"], "CREPE-CLI-001");
}
#[test]
fn config_layers_and_module_overrides() {
    let dir = temp_dir();
    std::fs::create_dir_all(dir.join("crepe")).unwrap();
    std::fs::write(
        dir.join("crepe/crepe.toml"),
        "sensor='user'\nmax_streams=42\n",
    )
    .unwrap();
    let explicit = dir.join("explicit.toml");
    std::fs::write(&explicit, "sensor='explicit'\n").unwrap();
    let result = cli()
        .env("XDG_CONFIG_HOME", &dir)
        .env("CREPE_SENSOR", "env")
        .arg("config")
        .arg(&explicit)
        .output()
        .unwrap();
    assert!(result.status.success());
    let config: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(config["sensor"], "env");
    assert_eq!(config["max_streams"], 42);
    let result = cli()
        .arg("chocolate")
        .arg(fixture("fixtures/protocols.pcap"))
        .args(["--disable", "tls"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(!rows.iter().any(|r| r["event_type"] == "tls.client_hello"));
    assert!(rows.iter().any(|r| r["event_type"] == "http.request"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tolerant_read_skips_bad_packet_but_not_container_errors() {
    let directory = temp_dir();
    let path = directory.join("corrupt.pcap");
    let mut capture = std::fs::read(fixture("example.pcap")).unwrap();
    // Fixture's first Ethernet frame is IPv4; invalidate version/IHL, preserving framing.
    capture[24 + 16 + 14] = 0;
    std::fs::write(&path, &capture).unwrap();
    assert!(!cli()
        .arg("read")
        .arg(&path)
        .output()
        .unwrap()
        .status
        .success());
    let output = cli()
        .arg("read")
        .arg(&path)
        .args(["--tolerant", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 5);
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("Skipped 1 malformed"));
    std::fs::write(&path, &capture[..30]).unwrap();
    assert!(!cli()
        .arg("read")
        .arg(&path)
        .arg("--tolerant")
        .output()
        .unwrap()
        .status
        .success());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn explicit_notice_enable_overrides_config_and_disable_wins() {
    let directory = temp_dir();
    let config = directory.join("notices.toml");
    std::fs::write(
        &config,
        format!(
            "notices = false\npolicy_rules = {:?}\n",
            fixture("config/policies-example.jsonl")
        ),
    )
    .unwrap();
    for (flags, expected) in [
        (vec![], false),
        (vec!["--enable", "notices"], true),
        (vec!["--enable", "notices", "--disable", "notices"], false),
    ] {
        let out = cli()
            .arg("chocolate")
            .arg(fixture("fixtures/dns.pcap"))
            .arg("--config")
            .arg(&config)
            .args(flags)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8(out.stdout)
                .unwrap()
                .contains("notice.policy"),
            expected
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn packet_summary_shows_time_direction_tcp_and_dns() {
    let output = cli()
        .args(["read"])
        .arg(fixture("fixtures/flows.pcap"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("22:13:20.123456000Z IP 192.0.2.10:50000 > 198.51.100.20:443"));
    assert!(text.contains("Flags [S], seq 1, win 65535, length 0, wire 54 bytes"));
    assert!(text.contains("Flags [S.], seq 1, ack 0"));
    assert!(!text.contains("UNIX_NS"));
    let output = cli()
        .arg("read")
        .arg(fixture("fixtures/dns.pcap"))
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("DNS query id 4660 rcode 0 A \"example.test.\""));
    assert!(text.contains("DNS response id 4660 rcode 0 A \"example.test.\" answers 1"));
    let output = cli()
        .arg("read")
        .arg(fixture("fixtures/simple.pcapng"))
        .output()
        .unwrap();
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("time unknown"));
}

#[test]
fn chocolate_is_canonical_and_old_spelling_is_compatible() {
    let run = |name: &str| {
        cli()
            .arg(name)
            .arg(fixture("fixtures/protocols.pcap"))
            .output()
            .unwrap()
    };
    let canonical = run("chocolate");
    let legacy = run("choclate");
    assert!(canonical.status.success() && legacy.status.success());
    let sorted = |bytes: Vec<u8>| {
        let text = String::from_utf8(bytes).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        lines.sort();
        lines
    };
    assert_eq!(sorted(canonical.stdout), sorted(legacy.stdout));
    let help = cli().arg("--help").output().unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("chocolate"));
    assert!(!help.contains("choclate"));
}

#[cfg(feature = "live")]
#[test]
fn bpf_and_cql_select_identical_packets_and_flows() {
    for file in [
        "example.pcap",
        "fixtures/example.pcapng",
        "fixtures/big-endian.pcap",
        "fixtures/multi-section.pcapng",
    ] {
        for (bpf, cql) in [
            ("dst port 443", "dst.port == 443"),
            ("tcp", "proto == tcp"),
            (
                "src net 192.0.2.0/24 and not udp",
                "src.ip in 192.0.2.0/24 && !(proto == udp)",
            ),
        ] {
            for command in ["read", "flows"] {
                let run = |filter: &str| {
                    cli()
                        .arg(command)
                        .arg(fixture(file))
                        .args([filter, "--format", "json"])
                        .output()
                        .unwrap()
                };
                let a = run(bpf);
                let b = run(cql);
                assert!(a.status.success(), "{file} {bpf}: {:?}", a);
                assert!(b.status.success());
                assert_eq!(a.stdout, b.stdout);
            }
        }
    }
    for expression in ["tcp[tcpflags] & tcp-syn != 0", "len == 54"] {
        let out = cli()
            .arg("read")
            .arg(fixture("example.pcap"))
            .arg(expression)
            .output()
            .unwrap();
        assert!(out.status.success(), "{:?}", out);
        assert!(String::from_utf8(out.stdout).unwrap().contains("Flags [S]"));
    }
    let out = cli()
        .args(["read", "does-not-exist.pcap", "tcp and ("])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("CREPE-CAP-005"));
}

#[cfg(not(feature = "live"))]
#[test]
fn portable_build_explains_missing_bpf_feature() {
    let out = cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .arg("dst port 443")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("CREPE-CAP-005") && text.contains("--features live"));
}

#[test]
fn flow_summary_is_compact_directional_and_distinguishes_eof_from_close() {
    let output = cli()
        .args(["flows", "--details"])
        .arg(fixture("fixtures/flows.pcap"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.lines().all(|line| line.chars().count() <= 80));
    assert!(text.contains("2023-11-14 22:13:20.123Z TCP | duration 6.000s"));
    assert!(text.contains("192.0.2.10:50000 <-> 198.51.100.20:443"));
    assert!(text.contains("-> 3 packets, 162 bytes [FS.] | <- 2 packets, 108 bytes [FS.]"));
    assert!(text.contains("end: FIN both ways | observed TCP: closed"));
    assert!(text.contains("end: TCP reset | observed TCP: reset"));
    assert!(text.contains("-> 1 packet, 42 bytes | <- 1 packet, 42 bytes"));
    assert!(text.contains("end: input ended"));
    assert!(!text.contains("PKTS_A"));
    let output = cli()
        .args(["flows", "--details"])
        .arg(fixture("example.pcap"))
        .args(["proto == tcp"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("end: input ended | observed TCP: SYN seen"));
    assert!(!text.contains("observed TCP: closed"));
}

#[test]
fn default_flow_table_is_one_record_per_line() {
    let output = cli()
        .arg("flows")
        .arg(fixture("fixtures/flows.pcap"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        text.lines().count(),
        4,
        "one header and three flows: {text}"
    );
    assert!(text.contains("START (UTC)") && text.contains("WIRE BYTES"));
    let tcp = text.lines().find(|line| line.contains("50000")).unwrap();
    assert!(tcp.contains("00:00:06.000") && tcp.contains("<->"));
    let columns: Vec<_> = tcp.split_whitespace().collect();
    assert_eq!(&columns[columns.len() - 2..], &["5", "270"]);
    assert!(!text.contains("CX-") && !text.contains("end:"));
    let output = cli()
        .arg("flows")
        .arg(fixture("example.pcap"))
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text
        .lines()
        .any(|line| line.contains("[2001:db8::10]:50001") && line.contains("[2001:db8::20]:443")));
}

#[test]
fn flow_details_does_not_change_machine_formats() {
    for format in ["json", "csv"] {
        let run = |details: bool| {
            let mut command = cli();
            command
                .arg("flows")
                .arg(fixture("fixtures/flows.pcap"))
                .args(["--format", format]);
            if details {
                command.arg("--details");
            }
            let result = command.output().unwrap();
            assert!(result.status.success());
            result.stdout
        };
        assert_eq!(run(false), run(true));
    }
}

#[test]
fn recipe_help_and_processing_feedback_are_factual() {
    let help = cli().args(["--serious", "--help"]).output().unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(help.status.success());
    assert!(text.contains("ALIAS"));
    assert!(!text.contains("Bon appétit"));
    let help = cli().args(["suzette", "--help"]).output().unwrap();
    assert!(String::from_utf8(help.stdout)
        .unwrap()
        .contains("fully processed"));
    let root = tempfile::tempdir().unwrap();
    let run = cli()
        .current_dir(root.path())
        .args(["--serious", "suzette"])
        .arg(fixture("example.pcap"))
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let messages = String::from_utf8(run.stderr).unwrap();
    assert!(messages.contains("Analyzing"));
    assert!(messages.contains("JSON Lines"));
    assert!(!messages.contains("Magnifique"));
    assert!(!run.stdout.is_empty());
    for line in String::from_utf8(run.stdout).unwrap().lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
}

#[cfg(feature = "live")]
#[test]
fn singular_interface_alias_is_accepted() {
    let output = cli().args(["interface", "--help"]).output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("capture interfaces"));
}

#[test]
fn suzette_retains_a_queryable_case_by_default() {
    let root = tempfile::tempdir().unwrap();
    let run = cli()
        .current_dir(root.path())
        .arg("suzette")
        .arg(fixture("fixtures/protocols.pcap"))
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let cases: Vec<_> = std::fs::read_dir(root.path().join("crepe-cases"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(cases.len(), 1);
    let store = cases[0].join("history");
    let stats = cli()
        .arg("query")
        .arg(&store)
        .arg("* | group event.type | count")
        .output()
        .unwrap();
    assert!(
        stats.status.success(),
        "{}",
        String::from_utf8_lossy(&stats.stderr)
    );
    assert!(!stats.stdout.is_empty());
    let timeline = cli()
        .arg("timeline")
        .arg(&store)
        .args(["--limit", "10000"])
        .output()
        .unwrap();
    assert!(timeline.status.success());
    let rows: Vec<serde_json::Value> = String::from_utf8(timeline.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let flow_id = rows.iter().find_map(|row| row["flow_id"].as_str()).unwrap();
    let trace = cli()
        .arg("trace")
        .arg(&store)
        .arg(flow_id)
        .output()
        .unwrap();
    assert!(
        trace.status.success(),
        "{}",
        String::from_utf8_lossy(&trace.stderr)
    );
    assert!(!trace.stdout.is_empty());
    let explicit_root = tempfile::tempdir().unwrap();
    let explicit_store = explicit_root.path().join("selected-history");
    let explicit = cli()
        .current_dir(explicit_root.path())
        .arg("suzette")
        .arg(fixture("fixtures/protocols.pcap"))
        .arg("--store")
        .arg(&explicit_store)
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert!(explicit_store.join("schema.json").exists());
    assert!(!explicit_root.path().join("crepe-cases").exists());
    let chocolate_root = tempfile::tempdir().unwrap();
    let chocolate = cli()
        .current_dir(chocolate_root.path())
        .arg("chocolate")
        .arg(fixture("fixtures/protocols.pcap"))
        .output()
        .unwrap();
    assert!(chocolate.status.success());
    assert!(!chocolate_root.path().join("crepe-cases").exists());
    let menu = cli().args(["--serious", "profiles"]).output().unwrap();
    assert!(!String::from_utf8(menu.stdout)
        .unwrap()
        .contains("Bon appétit"));
}

#[test]
fn layer_two_application_filters_and_payload_are_visible() {
    let capture = fixture("fixtures/packet-display.pcap");
    let read = cli().arg("read").arg(&capture).output().unwrap();
    assert!(
        read.status.success(),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    let text = String::from_utf8(read.stdout).unwrap();
    assert_eq!(text.lines().count(), 7);
    assert!(text.contains("ARP Request who-has 192.0.2.1 tell 192.0.2.10"));
    assert!(text.contains("LLDP") && text.contains("vlan [7]"));
    assert!(text.contains("HTTP: GET /search?q=crepe HTTP/1.1"));
    assert!(text.contains("HTTP: HTTP/1.1 200 OK"));
    let http = cli()
        .arg("read")
        .arg(&capture)
        .args(["http", "-A"])
        .output()
        .unwrap();
    assert!(http.status.success());
    let text = String::from_utf8(http.stdout).unwrap();
    assert!(text.contains("Host: example.test") && text.contains("hello web"));
    assert!(text.contains("\\x1b[31munsafe") && !text.contains('\u{1b}'));
    assert!(!text.contains("not an HTTP request"));
    let json = cli()
        .arg("read")
        .arg(&capture)
        .args(["http", "--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert_eq!(String::from_utf8(json.stdout).unwrap().lines().count(), 2);
    let arp = cli()
        .arg("read")
        .arg(&capture)
        .args(["arp", "--format", "json"])
        .output()
        .unwrap();
    assert!(arp.status.success());
    let row: serde_json::Value = serde_json::from_slice(&arp.stdout).unwrap();
    assert_eq!(row["proto"], "arp");
    assert_eq!(row["src_mac"], "02:00:00:00:00:01");
    assert!(row.get("src").is_none());
    let csv = cli()
        .arg("read")
        .arg(&capture)
        .args(["--format", "csv"])
        .output()
        .unwrap();
    assert!(csv.status.success());
    assert!(String::from_utf8(csv.stdout)
        .unwrap()
        .lines()
        .all(|l| l.split(',').count() == 17));
    let hex = cli()
        .arg("read")
        .arg(&capture)
        .args(["arp", "-X"])
        .output()
        .unwrap();
    assert!(hex.status.success());
    assert!(String::from_utf8(hex.stdout)
        .unwrap()
        .contains("0000  00 01 08 00"));
    let dir = tempfile::tempdir().unwrap();
    let selected = dir.path().join("arp.pcap");
    let export = cli()
        .arg("read")
        .arg(&capture)
        .args(["arp", "-w"])
        .arg(&selected)
        .output()
        .unwrap();
    assert!(export.status.success());
    let replay = cli()
        .arg("read")
        .arg(&selected)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(replay.status.success());
    assert_eq!(replay.stdout, arp.stdout);
    let ip = cli()
        .arg("read")
        .arg(&capture)
        .args(["proto == tcp", "--format", "json"])
        .output()
        .unwrap();
    assert!(ip.status.success());
    assert_eq!(String::from_utf8(ip.stdout).unwrap().lines().count(), 3);
}

#[test]
fn forensic_alias_and_update_help() {
    for cmd in ["forensics", "update"] {
        let result = cli().args([cmd, "--help"]).output().unwrap();
        assert!(result.status.success());
    }
    let help = cli().arg("--help").output().unwrap();
    assert!(String::from_utf8(help.stdout)
        .unwrap()
        .contains("forensics"));
}

#[cfg(unix)]
#[test]
fn update_checks_and_installs_verified_archive_without_touching_current_binary() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let platform = if cfg!(target_os = "macos") {
        "darwin-arm64"
    } else {
        "linux-x86_64"
    };
    let name = format!("crepe-9.0.0-{platform}.tar.gz");
    let archive = root.path().join(&name);
    let gz = flate2::write::GzEncoder::new(
        std::fs::File::create(&archive).unwrap(),
        flate2::Compression::default(),
    );
    let mut builder = tar::Builder::new(gz);
    let body = b"#!/bin/sh\nprintf 'crepe 9.0.0\\n'\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    builder
        .append_data(&mut header, "crepe", &body[..])
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();
    let digest = format!("{:x}", Sha256::digest(std::fs::read(&archive).unwrap()));
    std::fs::write(
        root.path().join(format!("{name}.sha256")),
        format!("{digest}  {name}\n"),
    )
    .unwrap();
    let base = "https://github.com/cnc24/crepe/releases/download/v9.0.0";
    let metadata = serde_json::json!({"tag_name":"v9.0.0","draft":false,"prerelease":false,"assets":[
        {"name":name,"browser_download_url":format!("{base}/{name}"),"digest":format!("sha256:{digest}")},
        {"name":format!("{name}.sha256"),"browser_download_url":format!("{base}/{name}.sha256")}
    ]});
    std::fs::write(root.path().join("release.json"), metadata.to_string()).unwrap();
    let curl = root.path().join("curl");
    std::fs::write(&curl,b"#!/bin/sh\nwhile [ $# -gt 0 ]; do\n if [ \"$1\" = --output ]; then shift; destination=$1; fi\n url=$1; shift\ndone\ncase \"$url\" in\n */latest) name=release.json ;;\n *) name=${url##*/} ;;\nesac\ncp \"$CREPE_TEST_RELEASE_DIR/$name\" \"$destination\"\n").unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let command = || {
        let mut cmd = cli();
        cmd.env("CREPE_TEST_RELEASE_DIR", root.path()).env(
            "PATH",
            format!(
                "{}:{}",
                root.path().display(),
                std::env::var("PATH").unwrap()
            ),
        );
        cmd
    };
    let check = command().args(["update", "--check"]).output().unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(String::from_utf8(check.stderr)
        .unwrap()
        .contains("Update available"));
    let installed = root.path().join("installed-crepe");
    let update = command()
        .args(["update", "--output"])
        .arg(&installed)
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "{}",
        String::from_utf8_lossy(&update.stderr)
    );
    assert_eq!(std::fs::read(&installed).unwrap(), body);
    let rerun = command()
        .args(["update", "--output"])
        .arg(&installed)
        .output()
        .unwrap();
    assert!(!rerun.status.success());
    assert_eq!(std::fs::read(&installed).unwrap(), body);
    std::fs::write(&archive, b"tampered").unwrap();
    let bad = root.path().join("bad-install");
    let update = command()
        .args(["update", "--output"])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!update.status.success());
    assert!(!bad.exists());
    assert!(String::from_utf8(update.stderr)
        .unwrap()
        .contains("SHA-256 mismatch"));
}

#[test]
fn wireshark_fields_and_combined_verbose_flags() {
    let capture = fixture("fixtures/packet-display.pcap");
    for (filter, expected) in [
        ("ip.src == 192.0.2.10", 2),
        ("ip.addr == 192.0.2.10", 3),
        ("tcp.port == 8088", 2),
        ("tcp.port != 8088", 1),
        ("udp.port == 8088", 0),
        ("http and ip.src == 192.0.2.10", 1),
        ("http && tcp.dstport == 8088", 1),
        ("ipv6.src != 2001:db8::1", 0),
    ] {
        let run = cli()
            .arg("read")
            .arg(&capture)
            .args([filter, "--format", "json"])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{filter}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert_eq!(
            String::from_utf8(run.stdout).unwrap().lines().count(),
            expected,
            "{filter}"
        );
    }
    let verbose = cli()
        .arg("read")
        .arg(&capture)
        .args(["http", "-vvX"])
        .output()
        .unwrap();
    assert!(
        verbose.status.success(),
        "{}",
        String::from_utf8_lossy(&verbose.stderr)
    );
    let text = String::from_utf8(verbose.stdout).unwrap();
    assert!(text.contains("IPv4 ttl 64"));
    assert!(text.contains("Host: example.test"));
    assert!(text.contains("0000  45 00")); // tcpdump-style -X starts at IP, not TCP payload.
    let link = cli()
        .arg("read")
        .arg(&capture)
        .args(["http", "-XX"])
        .output()
        .unwrap();
    assert!(link.status.success());
    assert!(String::from_utf8(link.stdout)
        .unwrap()
        .contains("0000  02 00 00 00 00 02"));
}

#[test]
fn flow_database_and_direct_queries_use_the_same_rows_and_grammar() {
    let root = tempfile::tempdir().unwrap();
    let store = root.path().join("flows");
    let capture = fixture("fixtures/flows.pcap");
    let save = cli()
        .arg("flows")
        .arg(&capture)
        .arg("--store")
        .arg(&store)
        .output()
        .unwrap();
    assert!(
        save.status.success(),
        "{}",
        String::from_utf8_lossy(&save.stderr)
    );
    assert!(store.join("schema.json").exists());
    for query in [
        "* | sort packets desc | limit 2",
        "bytes > 0 | sort bytes desc | limit 3",
        "* | count",
        "* | group src.ip,dst.ip | sort count desc",
        "ip.src == 192.0.2.10 | count",
    ] {
        let direct = cli()
            .arg("flows")
            .arg(&capture)
            .args(["--query", query, "--format", "json"])
            .output()
            .unwrap();
        let history = cli().arg("query").arg(&store).arg(query).output().unwrap();
        let reopened = cli()
            .arg("flows")
            .arg(&store)
            .args([query, "--format", "json"])
            .output()
            .unwrap();
        for run in [&direct, &history, &reopened] {
            assert!(
                run.status.success(),
                "{query}: {}",
                String::from_utf8_lossy(&run.stderr)
            );
        }
        let decode = |bytes: &[u8]| {
            let mut rows: Vec<_> = String::from_utf8_lossy(bytes)
                .lines()
                .map(|line| {
                    serde_json::from_str::<serde_json::Value>(line)
                        .unwrap()
                        .to_string()
                })
                .collect();
            rows.sort();
            rows
        };
        assert_eq!(decode(&direct.stdout), decode(&history.stdout), "{query}");
        assert_eq!(decode(&reopened.stdout), decode(&history.stdout), "{query}");
    }
    let shorthand = cli()
        .arg("flows")
        .arg(&capture)
        .args(["* | count", "--format", "json"])
        .output()
        .unwrap();
    assert!(shorthand.status.success());
    let options = cli()
        .arg("flows")
        .arg(&capture)
        .args([
            "--group", "src.ip", "--sort", "flows", "--limit", "2", "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        options.status.success(),
        "{}",
        String::from_utf8_lossy(&options.stderr)
    );
    let identities = cli()
        .arg("query")
        .arg(&store)
        .arg("* | select flow.id | limit 1")
        .output()
        .unwrap();
    assert!(identities.status.success());
    let identity: serde_json::Value = serde_json::from_slice(&identities.stdout).unwrap();
    let trace = cli()
        .arg("trace")
        .arg(&store)
        .arg(identity["flow_id"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(trace.status.success());
    assert!(!trace.stdout.is_empty());
    let help = cli().args(["flows", "-h"]).output().unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    for phrase in [
        "sort packets",
        "sort bytes",
        "group src.ip",
        "crepe query",
        "crepe trace",
    ] {
        assert!(text.contains(phrase), "{phrase}");
    }
}

#[test]
fn flow_import_survives_closed_output_pipe() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("many.pcap");
    let original = std::fs::read(fixture("fixtures/flows.pcap")).unwrap();
    let mut bytes = original[..24].to_vec();
    for _ in 0..2000 {
        bytes.extend_from_slice(&original[24..]);
    }
    std::fs::write(&capture, bytes).unwrap();
    let baseline = cli()
        .arg("flows")
        .arg(&capture)
        .args(["--count", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        baseline.status.success(),
        "{}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let store = dir.path().join("store");
    let mut child = cli()
        .arg("flows")
        .arg(&capture)
        .arg("--store")
        .arg(&store)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    drop(output); // Like `head`: close before the writer's next flush.
    let finished = child.wait_with_output().unwrap();
    assert!(
        finished.status.success(),
        "{}",
        String::from_utf8_lossy(&finished.stderr)
    );
    assert!(String::from_utf8_lossy(&finished.stderr).contains("Saved"));
    let query = cli()
        .arg("query")
        .arg(&store)
        .arg("* | count")
        .output()
        .unwrap();
    assert!(query.status.success());
    assert_eq!(query.stdout, baseline.stdout);
    let result: serde_json::Value = serde_json::from_slice(&query.stdout).unwrap();
    assert!(result["count"].as_u64().unwrap() > 1000);
}

#[test]
fn flow_query_detection_and_option_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("flows");
    let created = cli()
        .arg("flows")
        .arg(fixture("fixtures/flows.pcap"))
        .arg("--store")
        .arg(&store)
        .output()
        .unwrap();
    assert!(created.status.success());
    for query in [
        "(bytes > 0)",
        "!(packets == 0)",
        "proto == tcp && (bytes > 0)",
    ] {
        let direct = cli()
            .arg("flows")
            .arg(fixture("fixtures/flows.pcap"))
            .arg(query)
            .args(["--format", "json"])
            .output()
            .unwrap();
        let explicit = cli()
            .arg("flows")
            .arg(fixture("fixtures/flows.pcap"))
            .args(["--query", query, "--format", "json"])
            .output()
            .unwrap();
        assert!(
            direct.status.success(),
            "{}",
            String::from_utf8_lossy(&direct.stderr)
        );
        assert!(explicit.status.success());
        assert_eq!(direct.stdout, explicit.stdout);
    }
    for options in [
        ["--tcp-idle", "120"],
        ["--udp-idle", "30"],
        ["--max-flows", "65536"],
        ["--active-timeout", "300"],
        ["--filter-syntax", "auto"],
    ] {
        let r = cli()
            .arg("flows")
            .arg(&store)
            .args(options)
            .output()
            .unwrap();
        assert!(!r.status.success());
        assert!(String::from_utf8_lossy(&r.stderr).contains("not an existing store"));
    }
    let r = cli()
        .arg("flows")
        .arg(fixture("fixtures/flows.pcap"))
        .args(["--sort", "flows"])
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("--group"));
    let r = cli()
        .arg("read")
        .arg(fixture("example.pcap"))
        .args(["-v", "--format", "json"])
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("--verbose"));
}
