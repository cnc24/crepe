use crepe_capture as capture;
use crepe_core::PacketEvent;
use crepe_flow::{Config, EndReason, FlowKey, FlowRecord, FlowTable};
fn packet(second: i64) -> PacketEvent {
    let mut packets = Vec::new();
    capture::read(&include_bytes!("../../../example.pcap")[..], |p| {
        packets.push(p);
        Ok(())
    })
    .unwrap();
    let mut p = packets.remove(0);
    p.header.timestamp_ns = Some((i128::from(second) * 1_000_000_000).to_string());
    p
}
fn push(t: &mut FlowTable, p: &PacketEvent, output: &mut Vec<FlowRecord>) {
    t.push(p, |f| {
        output.push(f);
        Ok(())
    })
    .unwrap();
}
fn finish(t: &mut FlowTable, output: &mut Vec<FlowRecord>) {
    t.finish(|f| {
        output.push(f);
        Ok(())
    })
    .unwrap();
}
#[test]
fn bidirectional_key_counters_and_stable_ids() {
    let mut t = FlowTable::new(Config::default()).unwrap();
    let mut out = vec![];
    let a = packet(10);
    let mut b = packet(11);
    std::mem::swap(&mut b.src, &mut b.dst);
    assert_eq!(FlowKey::from_packet(&a).0, FlowKey::from_packet(&b).0);
    push(&mut t, &a, &mut out);
    push(&mut t, &b, &mut out);
    finish(&mut t, &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].packets_a, out[0].packets_b), (1, 1));
    assert_eq!((out[0].bytes_a, out[0].bytes_b), (54, 54));
    assert_eq!(out[0].flow_id, "CX-0000000000000001");
    assert!(t.is_empty());
}
#[test]
fn vlan_and_interface_identity_are_not_merged() {
    let mut t = FlowTable::new(Config::default()).unwrap();
    let mut out = vec![];
    let mut p = packet(0);
    push(&mut t, &p, &mut out);
    p.vlans = vec![1];
    push(&mut t, &p, &mut out);
    p.header.interface = 1;
    push(&mut t, &p, &mut out);
    p.header.section = 1;
    push(&mut t, &p, &mut out);
    assert_eq!(t.len(), 4);
    finish(&mut t, &mut out);
    assert_eq!(out.len(), 4);
}
#[test]
fn idle_boundary_and_active_timeout() {
    let mut t = FlowTable::new(Config {
        tcp_idle_secs: 5,
        active_secs: 12,
        ..Default::default()
    })
    .unwrap();
    let mut out = vec![];
    for second in [0, 4, 8, 12, 17] {
        push(&mut t, &packet(second), &mut out);
    }
    assert_eq!(out[0].end_reason, EndReason::ActiveTimeout);
    assert_eq!(out[0].packets_a, 3);
    assert_eq!(out[1].end_reason, EndReason::IdleTimeout);
    assert_eq!(out[1].packets_a, 1);
    finish(&mut t, &mut out);
    assert_eq!(out.len(), 3);
}
#[test]
fn capacity_evicts_and_does_not_drop_accounting() {
    let mut t = FlowTable::new(Config {
        max_flows: 2,
        ..Default::default()
    })
    .unwrap();
    let mut out = vec![];
    for port in 1..=1000 {
        let mut p = packet(0);
        p.src.port = Some(port);
        push(&mut t, &p, &mut out);
        assert!(t.len() <= 2);
    }
    finish(&mut t, &mut out);
    assert_eq!(out.len(), 1000);
    assert_eq!(
        out.iter()
            .filter(|f| f.end_reason == EndReason::Capacity)
            .count(),
        998
    );
    assert_eq!(
        out.iter().map(|f| f.packets_a + f.packets_b).sum::<u64>(),
        1000
    );
}
#[test]
fn fin_requires_both_directions_and_rst_closes_immediately() {
    let mut t = FlowTable::new(Config::default()).unwrap();
    let mut out = vec![];
    let mut p = packet(0);
    p.tcp_flags = Some(1);
    push(&mut t, &p, &mut out);
    assert!(out.is_empty());
    std::mem::swap(&mut p.src, &mut p.dst);
    push(&mut t, &p, &mut out);
    assert_eq!(out[0].end_reason, EndReason::TcpFin);
    p.tcp_flags = Some(4);
    push(&mut t, &p, &mut out);
    assert_eq!(out[1].end_reason, EndReason::TcpReset);
    assert_eq!(out[1].packets_a + out[1].packets_b, 1);
}
#[test]
fn out_of_order_updates_time_bounds_without_rewinding_clock() {
    let mut t = FlowTable::new(Config::default()).unwrap();
    let mut out = vec![];
    for second in [20, 10, 15] {
        push(&mut t, &packet(second), &mut out);
    }
    finish(&mut t, &mut out);
    assert_eq!(out[0].start_ns, "10000000000");
    assert_eq!(out[0].end_ns, "20000000000");
}
#[test]
fn missing_timestamps_and_invalid_limits_fail() {
    assert!(FlowTable::new(Config {
        max_flows: 0,
        ..Default::default()
    })
    .is_err());
    assert!(FlowTable::new(Config {
        udp_idle_secs: 0,
        ..Default::default()
    })
    .is_err());
    let mut t = FlowTable::new(Config::default()).unwrap();
    let mut p = packet(0);
    p.header.timestamp_ns = None;
    assert_eq!(t.push(&p, |_| Ok(())).unwrap_err().code, "CREPE-FLOW-001");
}
#[test]
fn fragments_and_icmp_are_not_misrepresented_as_connections() {
    let mut t = FlowTable::new(Config::default()).unwrap();
    let mut p = packet(0);
    p.fragmented = true;
    t.push(&p, |_| panic!("unexpected flow")).unwrap();
    p.fragmented = false;
    p.proto = crepe_core::Protocol::Icmp;
    t.push(&p, |_| panic!("unexpected flow")).unwrap();
    assert!(t.is_empty());
    assert_eq!(t.skipped_fragments, 1);
    assert_eq!(t.skipped_other_protocols, 1);
}
#[test]
fn fixture_lifecycle_and_udp_timeout() {
    let mut t = FlowTable::new(Config {
        udp_idle_secs: 2,
        ..Default::default()
    })
    .unwrap();
    let mut out = vec![];
    capture::read(&include_bytes!("../../../fixtures/flows.pcap")[..], |p| {
        push(&mut t, &p, &mut out);
        Ok(())
    })
    .unwrap();
    finish(&mut t, &mut out);
    assert_eq!(out.len(), 3);
    let tcp = out
        .iter()
        .find(|f| f.end_reason == EndReason::TcpFin)
        .unwrap();
    assert_eq!((tcp.packets_a, tcp.packets_b), (3, 2));
    assert_eq!((tcp.bytes_a, tcp.bytes_b), (162, 108));
    assert!(out
        .iter()
        .any(|f| f.proto == crepe_core::Protocol::Udp && f.end_reason == EndReason::IdleTimeout));
}
