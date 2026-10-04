use crepe_core::PacketEvent;
use crepe_query::{self as cql, Compare, Expr, Predicate, Side};
const PCAP: &[u8] = include_bytes!("../../../example.pcap");
fn events(bytes: &[u8]) -> Vec<PacketEvent> {
    let mut packets = vec![];
    crepe_capture::read(bytes, |p| {
        packets.push(p);
        Ok(())
    })
    .unwrap();
    packets
}
#[test]
fn typed_ast() {
    assert_eq!(
        cql::parse("dst.port == 443").unwrap(),
        Expr::Predicate(Predicate::Port(Side::Dst, Compare::Eq, 443))
    );
}
#[test]
fn cql_precedence_parentheses_and_negation() {
    let e = events(PCAP);
    let cases = [
        ("dst.port == 443", vec![0, 2]),
        (
            "proto == udp || proto == tcp && src.ip == 192.0.2.10",
            vec![0, 1, 3],
        ),
        (
            "(proto == udp || proto == tcp) && src.ip == 192.0.2.10",
            vec![0, 1],
        ),
        ("!(proto == tcp || proto == udp)", vec![4, 5]),
        ("src.ip in 2001:db8::/32 && dst.port != 443", vec![3]),
        ("dst.ip in 198.51.100.0/24 && src.port == 50000", vec![0]),
        ("proto == 58", vec![5]),
        ("dst.ip != 2001:db8::20 && proto != tcp", vec![1, 4]),
        ("dst.port != 443", vec![1, 3]),
        ("!!(proto == ICMP)", vec![4]),
    ];
    for (query, expected) in cases {
        let filter = cql::parse(query).unwrap();
        assert_eq!(
            e.iter()
                .enumerate()
                .filter(|(_, e)| filter.matches(e))
                .map(|(i, _)| i)
                .collect::<Vec<_>>(),
            expected,
            "{query}"
        );
    }
}
#[test]
fn bad_queries_are_errors() {
    for q in [
        "",
        "src.ip == tcp",
        "dst.port == 65536",
        "dst.port == -1",
        "proto == pizza",
        "proto == 256",
        "src.port in 10.0.0.0/8",
        "src.ip in 10.0.0.0/33",
        "unknown == 1",
        "proto = tcp",
        "proto == tcp & proto == udp",
        "proto == tcp trailing",
        "(proto == tcp",
        "proto == tcp)",
        "src.ip == 999.1.1.1",
        "proto == tcp ||",
        "💥",
    ] {
        assert_eq!(cql::parse(q).unwrap_err().code, "CREPE-CQL-001", "{q}");
    }
    assert!(cql::parse(&format!("{}proto == tcp", "!".repeat(34))).is_err());
    assert!(cql::parse(&"a".repeat(4097)).is_err());
    assert!(cql::parse(&"!".repeat(257)).is_err());
}
#[test]
fn port_lists_are_typed_and_validate_syntax() {
    let p = events(PCAP);
    let filter = cql::parse("dst.port in [53, 443, 53] && proto != icmp").unwrap();
    assert_eq!(p.iter().filter(|p| filter.matches(p)).count(), 4);
    for q in [
        "dst.port in []",
        "dst.port in [65536]",
        "dst.port in [80,]",
        "dst.port in [80 443]",
        "src.ip in [80]",
        "proto in [tcp]",
    ] {
        assert!(cql::parse(q).is_err(), "{q}");
    }
}
