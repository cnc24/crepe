use crepe_fragment::{Limits, Scope, Table};
fn fragment(v6: bool, offset: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    if v6 {
        let mut p = vec![0; 48];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[6] = 44;
        p[7] = 64;
        p[23] = 1;
        p[39] = 2;
        p[40] = 17;
        p[42..44].copy_from_slice(&(offset | u16::from(more)).to_be_bytes());
        p[47] = 7;
        p.extend_from_slice(payload);
        p
    } else {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p[5] = 7;
        p[6..8].copy_from_slice(&((offset / 8) | if more { 0x2000 } else { 0 }).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12] = 10;
        p[16] = 11;
        p.extend_from_slice(payload);
        p
    }
}
#[test]
fn reorder_and_repair_both_ip_versions() {
    for v6 in [false, true] {
        let mut t = Table::new(Limits::default()).unwrap();
        let scope = Scope::default();
        assert!(t
            .process(&fragment(v6, 8, false, b"tail"), &scope, 1)
            .unwrap()
            .is_none());
        let p = t
            .process(&fragment(v6, 0, true, b"12345678"), &scope, 2)
            .unwrap()
            .unwrap()
            .into_owned();
        assert_eq!(&p[if v6 { 40 } else { 20 }..], b"12345678tail");
        assert_eq!(p[if v6 { 6 } else { 9 }], 17);
        assert_eq!(t.stats.completed, 1);
        assert!(t.is_empty());
        assert_eq!(t.buffered_bytes(), 0);
        if !v6 {
            let mut sum: u32 = p[..20]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
                .sum();
            while sum >> 16 != 0 {
                sum = (sum & 65535) + (sum >> 16)
            }
            assert_eq!(sum, 65535);
        }
    }
}
#[test]
fn overlap_scope_timeout_and_budget() {
    let mut t = Table::new(Limits::default()).unwrap();
    let s = Scope::default();
    let p = fragment(true, 0, true, b"12345678");
    t.process(&p, &s, 0).unwrap();
    assert!(t.process(&p, &s, 1).is_err());
    assert!(t.is_empty());
    t.process(&p, &s, 2).unwrap();
    let other = Scope {
        interface: 1,
        ..s.clone()
    };
    assert!(t
        .process(&fragment(true, 8, false, b"tail"), &other, 3)
        .unwrap()
        .is_none());
    assert_eq!(t.len(), 2);
    t.expire(60_000_000_003).unwrap();
    assert!(t.is_empty());
    assert_eq!(t.stats.expired, 2);
    let mut tiny = Table::new(Limits {
        bytes: 8,
        ..Limits::default()
    })
    .unwrap();
    assert!(tiny.process(&p, &s, 0).is_err());
    assert_eq!(tiny.buffered_bytes(), 0);
}
#[test]
fn atomic_is_independent_and_malformed_is_rejected() {
    let mut t = Table::new(Limits::default()).unwrap();
    let s = Scope::default();
    t.process(&fragment(true, 0, true, b"12345678"), &s, 0)
        .unwrap();
    assert!(t
        .process(&fragment(true, 0, false, b"atomic"), &s, 1)
        .unwrap()
        .is_some());
    assert_eq!(t.len(), 1);
    assert!(t
        .process(&fragment(false, 0, true, b"short"), &s, 2)
        .is_err());
    assert!(t.process(&[0x45], &s, 2).is_err());
    assert_eq!(t.finish(), 1);
}
