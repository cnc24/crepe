use crepe_collector::{Collector, Limits};
fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    p.extend_from_slice(body);
    p
}
fn message(v: u16, seq: u32, sets: &[u8]) -> Vec<u8> {
    let mut p = vec![0; if v == 9 { 20 } else { 16 }];
    p[..2].copy_from_slice(&v.to_be_bytes());
    if v == 10 {
        p[2..4].copy_from_slice(&((16 + sets.len()) as u16).to_be_bytes());
        p[8..12].copy_from_slice(&seq.to_be_bytes());
    } else {
        p[12..16].copy_from_slice(&seq.to_be_bytes());
    }
    p.extend_from_slice(sets);
    p
}
fn template(v: u16) -> Vec<u8> {
    let mut body = vec![1, 0, 0, 7];
    for (id, n) in [
        (8u16, 4u16),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 4),
        (2, 4),
    ] {
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(&n.to_be_bytes());
    }
    set(if v == 9 { 0 } else { 2 }, &body)
}
fn data() -> Vec<u8> {
    set(
        256,
        &[
            10, 0, 0, 1, 10, 0, 0, 2, 0x12, 0x34, 1, 0xbb, 6, 0, 0, 4, 0, 0, 0, 0, 8,
        ],
    )
}
#[test]
fn v9_ipfix_template_scopes_sequence_and_expiry() {
    for v in [9, 10] {
        let mut c = Collector::new(Limits::default()).unwrap();
        let a = "127.0.0.1:1234".parse().unwrap();
        let b = "127.0.0.1:1235".parse().unwrap();
        let mut sets = template(v);
        sets.extend(data());
        let out = c.decode(a, &message(v, 0, &sets), 0).unwrap();
        assert_eq!(out.flows.len(), 1);
        assert_eq!(out.flows[0].dst_port, Some(443));
        assert_eq!(out.flows[0].bytes, Some(1024));
        assert!(out.notices.is_empty());
        assert!(c
            .decode(b, &message(v, 0, &data()), 1)
            .unwrap()
            .flows
            .is_empty());
        assert!(c
            .decode(a, &message(v, 1, &data()), 1)
            .unwrap()
            .notices
            .is_empty());
        assert!(c
            .decode(a, &message(v, 4, &data()), 2)
            .unwrap()
            .notices
            .iter()
            .any(|n| n.code.ends_with("SEQUENCE")));
        assert!(c
            .decode(a, &message(v, 5, &data()), 1801)
            .unwrap()
            .flows
            .is_empty());
    }
}
#[test]
fn v5_counter_and_sampling() {
    let mut p = vec![0; 72];
    p[..4].copy_from_slice(&[0, 5, 0, 1]);
    p[8..12].copy_from_slice(&100u32.to_be_bytes());
    p[16..20].copy_from_slice(&42u32.to_be_bytes());
    p[22..24].copy_from_slice(&100u16.to_be_bytes());
    p[24..28].copy_from_slice(&[10, 0, 0, 1]);
    p[28..32].copy_from_slice(&[10, 0, 0, 2]);
    p[44..48].copy_from_slice(&1000u32.to_be_bytes());
    p[58..60].copy_from_slice(&443u16.to_be_bytes());
    let mut c = Collector::new(Limits::default()).unwrap();
    let out = c.decode("127.0.0.1:9".parse().unwrap(), &p, 0).unwrap();
    assert_eq!(out.flows[0].sequence, 42);
    assert_eq!(out.flows[0].sampling_interval, Some(100));
    assert_eq!(out.flows[0].bytes, Some(1000));
    assert_eq!(out.flows[0].dst_port, Some(443));
}
#[test]
fn variable_enterprise_options_and_truncations() {
    let mut c = Collector::new(Limits::default()).unwrap();
    let a = "127.0.0.1:1234".parse().unwrap();
    let mut s = set(3, &[1, 1, 0, 2, 0, 1, 0, 149, 0, 4, 0, 34, 0, 4]);
    s.extend(set(257, &[0, 0, 0, 1, 0, 0, 0, 100]));
    let o = c.decode(a, &message(10, 0, &s), 0).unwrap();
    assert_eq!(o.options.len(), 1);
    assert!(o.options[0][0].scope);
    assert_eq!(o.options[0][1].value, [0, 0, 0, 100]);
    let mut s = set(2, &[1, 2, 0, 1, 0x80, 1, 255, 255, 0, 0, 0, 42]);
    s.extend(set(258, &[3, 1, 2, 3]));
    let o = c.decode(a, &message(10, 1, &s), 1).unwrap();
    assert_eq!(o.flows[0].fields[0].enterprise, 42);
    assert_eq!(o.flows[0].fields[0].value, [1, 2, 3]);
    let m = message(10, 2, &s);
    for n in 0..m.len() {
        assert!(c.decode(a, &m[..n], 2).is_err());
    }
}
#[test]
fn replacement_capacity_and_long_session() {
    let peer = "127.0.0.1:9".parse().unwrap();
    let mut collector = Collector::new(Limits {
        templates: 1,
        sessions: 1,
        ..Limits::default()
    })
    .unwrap();
    collector
        .decode(peer, &message(10, 0, &template(10)), 0)
        .unwrap();
    let replacement = set(2, &[1, 0, 0, 1, 0, 11, 0, 2]);
    collector
        .decode(peer, &message(10, 0, &replacement), 1)
        .unwrap();
    let record = set(256, &443u16.to_be_bytes());
    for seq in 0..10000 {
        let b = collector
            .decode(peer, &message(10, seq, &record), 2)
            .unwrap();
        assert_eq!(b.flows[0].dst_port, Some(443));
        assert_eq!(collector.template_count(), 1);
        assert_eq!(collector.session_count(), 1);
    }
    assert!(collector
        .decode("127.0.0.1:10".parse().unwrap(), &message(10, 0, &record), 2)
        .is_err());
    let other = set(2, &[1, 1, 0, 1, 0, 11, 0, 2]);
    assert!(collector
        .decode(peer, &message(10, 10000, &other), 2)
        .is_err());
}
