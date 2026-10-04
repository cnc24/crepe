use crepe_analysis::{Analyzer, Config, Event, Kind};
fn analyze(bytes: &[u8], config: Config) -> Vec<Event> {
    let mut analyzer = Analyzer::new(config).unwrap();
    let mut events = vec![];
    crepe_capture::read_records(bytes, |r| {
        if let Some(view) = crepe_packet::decode_view(r.data, r.header, r.linktype)? {
            analyzer.process(&view, |e| {
                events.push(e);
                Ok(())
            })?;
        }
        Ok(true)
    })
    .unwrap();
    analyzer
        .finish(|e| {
            events.push(e);
            Ok(())
        })
        .unwrap();
    assert_eq!(analyzer.stream_count(), 0);
    assert_eq!(analyzer.buffered_bytes(), 0);
    events
}
#[test]
fn udp_ipv4_ipv6_and_reordered_tcp_dns_without_duplicate_retransmits() {
    let e = analyze(
        include_bytes!("../../../fixtures/dns.pcap"),
        Config::default(),
    );
    assert_eq!(e.len(), 5);
    assert_eq!(
        e.iter()
            .filter(|e| matches!(e.event_type, Kind::DnsQuery))
            .count(),
        3
    );
    assert_eq!(
        e.iter()
            .filter(|e| matches!(e.event_type, Kind::DnsResponse))
            .count(),
        2
    );
    assert!(e.iter().all(|e| !e.midstream && e.anomaly.is_none()));
    assert!(e
        .iter()
        .all(|e| e.dns.as_ref().unwrap().questions[0].name == "example.test."));
}
#[test]
fn malformed_udp_and_incomplete_tcp_are_explicit_events() {
    let e = analyze(
        include_bytes!("../../../fixtures/dns-malformed.pcap"),
        Config::default(),
    );
    assert_eq!(e.len(), 2);
    assert_eq!(e[0].anomaly.as_ref().unwrap().code, "CREPE-DNS-001");
    assert_eq!(e[1].anomaly.as_ref().unwrap().code, "CREPE-TCP-002");
}
#[test]
fn byte_and_stream_limits_emit_anomalies() {
    for config in [
        Config {
            max_streams: 1,
            ..Default::default()
        },
        Config {
            max_buffer_bytes: 4,
            ..Default::default()
        },
    ] {
        let e = analyze(include_bytes!("../../../fixtures/dns.pcap"), config);
        assert!(e.iter().any(|e| e
            .anomaly
            .as_ref()
            .is_some_and(|a| a.code == "CREPE-ANA-002")));
    }
}
#[test]
fn idle_timeout_discards_gap_state() {
    let e = analyze(
        include_bytes!("../../../fixtures/dns.pcap"),
        Config {
            idle_secs: 1,
            ..Default::default()
        },
    );
    assert!(e.iter().any(|e| e
        .anomaly
        .as_ref()
        .is_some_and(|a| a.message.contains("idle timeout"))));
}

fn tcp_packet() -> crepe_core::PacketEvent {
    let mut packet = None;
    crepe_capture::read_records(&include_bytes!("../../../fixtures/dns.pcap")[..], |r| {
        let view = crepe_packet::decode_view(r.data, r.header, r.linktype)?.unwrap();
        if view.event.proto == crepe_core::Protocol::Tcp {
            packet = Some(view.event);
            return Ok(false);
        }
        Ok(true)
    })
    .unwrap();
    packet.unwrap()
}
fn framed() -> Vec<u8> {
    let query =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\0\0\x01\0\x01";
    let mut bytes = (query.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(query);
    bytes
}
#[test]
fn fin_followed_by_ack_is_not_an_anomaly() {
    let mut a = Analyzer::new(Config::default()).unwrap();
    let mut events = vec![];
    let mut p = tcp_packet();
    let bytes = framed();
    for (flags, sequence, payload) in [
        (2, 100, &[][..]),
        (16, 101, bytes.as_slice()),
        (17, 101 + bytes.len() as u32, &[][..]),
        (16, 102 + bytes.len() as u32, &[][..]),
    ] {
        p.tcp_flags = Some(flags);
        let view = crepe_packet::PacketView {
            event: p.clone(),
            payload,
            tcp_sequence: Some(sequence),
        };
        a.process(&view, |e| {
            events.push(e);
            Ok(())
        })
        .unwrap();
    }
    a.finish(|e| {
        events.push(e);
        Ok(())
    })
    .unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].event_type, Kind::DnsQuery));
}
#[test]
fn midstream_pipelining_duplicates_and_rst() {
    let mut a = Analyzer::new(Config::default()).unwrap();
    let mut events = vec![];
    let mut p = tcp_packet();
    p.tcp_flags = Some(16);
    let bytes = framed().repeat(2);
    let view = crepe_packet::PacketView {
        event: p.clone(),
        payload: &bytes,
        tcp_sequence: Some(500),
    };
    a.process(&view, |e| {
        events.push(e);
        Ok(())
    })
    .unwrap();
    a.process(&view, |e| {
        events.push(e);
        Ok(())
    })
    .unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.midstream));
    let more = framed();
    let view = crepe_packet::PacketView {
        event: p.clone(),
        payload: &more[..4],
        tcp_sequence: Some(500 + bytes.len() as u32),
    };
    a.process(&view, |e| {
        events.push(e);
        Ok(())
    })
    .unwrap();
    p.tcp_flags = Some(4);
    let view = crepe_packet::PacketView {
        event: p,
        payload: &[],
        tcp_sequence: Some(504 + bytes.len() as u32),
    };
    a.process(&view, |e| {
        events.push(e);
        Ok(())
    })
    .unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].anomaly.as_ref().unwrap().code, "CREPE-TCP-002");
    assert_eq!(a.stream_count(), 0);
}
