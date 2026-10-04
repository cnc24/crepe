//! Conservative Ethernet BPF hints. Unsupported subexpressions widen, never narrow.
use crate::{Compare, Expr, Predicate, Side};
use crepe_core::Protocol;
fn side(side: &Side) -> &'static str {
    match side {
        Side::Src => "src",
        Side::Dst => "dst",
    }
}
fn hint(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Predicate(Predicate::Ip(direction, Compare::Eq, ip)) => Some(format!(
            "{} {} host {ip}",
            if ip.is_ipv4() { "ip" } else { "ip6" },
            side(direction)
        )),
        Expr::Predicate(Predicate::In(direction, network)) => Some(format!(
            "{} {} net {}",
            if matches!(network, ipnet::IpNet::V4(_)) {
                "ip"
            } else {
                "ip6"
            },
            side(direction),
            network.trunc()
        )),
        Expr::Predicate(Predicate::Proto(Compare::Eq, protocol)) => {
            let number = match protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
                Protocol::Icmp => 1,
                Protocol::Icmpv6 => 58,
                Protocol::Other(n) => *n,
            };
            // IPv6 extension/fragment chains are deliberately left to the authoritative decoder.
            Some(format!("(ip proto {number} or ip6)"))
        }
        Expr::And(a, b) => match (hint(a), hint(b)) {
            (Some(a), Some(b)) => Some(format!("({a} and {b})")),
            (Some(a), None) | (None, Some(a)) => Some(a),
            _ => None,
        },
        Expr::Or(a, b) => Some(format!("({} or {})", hint(a)?, hint(b)?)),
        // Negation of a superset is not a safe prefilter; ports may follow extension headers.
        _ => None,
    }
}
impl Expr {
    /// A superset for Ethernet only. Always run `matches` after decoding as the authority.
    pub fn ethernet_prefilter(&self) -> Option<String> {
        hint(self).map(|hint| {
            format!("({hint}) or ether proto 0x8100 or ether proto 0x88a8 or ether proto 0x9100")
        })
    }
}
#[cfg(test)]
mod tests {
    use crate::parse;
    #[test]
    fn unsupported_or_and_negation_never_drop_matches() {
        assert!(parse("! (proto == tcp)")
            .unwrap()
            .ethernet_prefilter()
            .is_none());
        assert!(parse("proto == tcp || dst.port == 53")
            .unwrap()
            .ethernet_prefilter()
            .is_none());
        assert!(parse("proto == tcp && dst.port == 443")
            .unwrap()
            .ethernet_prefilter()
            .unwrap()
            .contains("ip proto 6"));
    }
}
