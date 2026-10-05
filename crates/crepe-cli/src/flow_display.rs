//! Compact human flow output. Endpoints remain canonical, never guessed client/server.
use crate::packet_display::{endpoint, flags};
use crepe_core::Protocol;
use crepe_flow::{EndReason, FlowRecord, TcpState};

fn timestamp(ns: &str) -> String {
    let time = ns.parse::<i128>().ok().and_then(|ns| {
        let seconds = i64::try_from(ns.div_euclid(1_000_000_000)).ok()?;
        chrono::DateTime::from_timestamp(seconds, ns.rem_euclid(1_000_000_000) as u32)
    });
    time.map(|t| t.format("%Y-%m-%d %H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| "time unknown".into())
}
fn duration(start: &str, end: &str) -> String {
    let delta = start
        .parse::<i128>()
        .ok()
        .zip(end.parse::<i128>().ok())
        .and_then(|(s, e)| e.checked_sub(s))
        .filter(|n| *n >= 0);
    match delta {
        Some(ns) => format!(
            "{}.{:03}s",
            ns / 1_000_000_000,
            ns % 1_000_000_000 / 1_000_000
        ),
        None => "unknown".into(),
    }
}
/// Word-wrap at 80 columns, including when stdout is piped; never truncate addresses.
fn wrap(line: &str) -> String {
    let mut result = String::new();
    let mut column = 0;
    for word in line.split_whitespace() {
        let width = word.chars().count();
        if column > 0 && column + 1 + width > 80 {
            result.push_str("\n    ");
            column = 4;
        } else if column > 0 {
            result.push(' ');
            column += 1;
        }
        result.push_str(word);
        column += width;
    }
    result
}
pub(crate) fn summary(f: &FlowRecord) -> String {
    let reason = match f.end_reason {
        EndReason::Eof => "input ended",
        EndReason::IdleTimeout => "idle timeout",
        EndReason::ActiveTimeout => "active timeout",
        EndReason::Capacity => "capacity eviction",
        EndReason::TcpFin => "FIN both ways",
        EndReason::TcpReset => "TCP reset",
    };
    let state = match f.tcp_state {
        Some(TcpState::SynSeen) => "SYN seen",
        Some(TcpState::Established) => "established",
        Some(TcpState::Midstream) => "midstream",
        Some(TcpState::HalfClosed) => "half closed",
        Some(TcpState::Closed) => "closed",
        Some(TcpState::Reset) => "reset",
        None => "not applicable",
    };
    let counters = |arrow, packets, bytes, bits| {
        let tcp = if f.proto == Protocol::Tcp {
            format!(" [{}]", flags(bits))
        } else {
            String::new()
        };
        format!(
            "{arrow} {packets} {}, {bytes} bytes{tcp}",
            if packets == 1 { "packet" } else { "packets" }
        )
    };
    let mut lines = vec![
        format!(
            "{} {} | duration {} | {}",
            timestamp(&f.start_ns),
            f.proto.to_string().to_uppercase(),
            duration(&f.start_ns, &f.end_ns),
            f.flow_id
        ),
        format!("{} <-> {}", endpoint(&f.a), endpoint(&f.b)),
        format!(
            "{} | {}",
            counters("->", f.packets_a, f.bytes_a, f.tcp_flags_a),
            counters("<-", f.packets_b, f.bytes_b, f.tcp_flags_b)
        ),
        format!("end: {reason}"),
    ];
    if f.proto == Protocol::Tcp {
        lines[3].push_str(&format!(" | observed TCP: {state}"));
    }
    if f.section != 0 || f.interface != 0 || !f.vlans.is_empty() {
        lines.push(format!(
            "section {} | interface {} | VLAN {:?}",
            f.section, f.interface, f.vlans
        ));
    }
    lines.iter().map(|s| wrap(s)).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_date_and_duration_cross_midnight_without_float_rounding() {
        assert_eq!(timestamp("1700000000123456789"), "2023-11-14 22:13:20.123Z");
        assert_eq!(timestamp("-1"), "1969-12-31 23:59:59.999Z");
        assert_eq!(timestamp("invalid"), "time unknown");
        assert_eq!(duration("86399999000000", "86401000000000"), "1.001s");
        assert_eq!(duration("2", "1"), "unknown");
    }
    #[test]
    fn long_ipv6_endpoints_and_large_counters_wrap_without_losing_values() {
        let text="[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535 <-> [aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa]:65535";
        let rendered = wrap(text);
        assert!(rendered.lines().all(|l| l.len() <= 80));
        assert_eq!(
            rendered.split_whitespace().collect::<Vec<_>>(),
            text.split_whitespace().collect::<Vec<_>>()
        );
        let text="-> 18446744073709551615 packets, 18446744073709551615 bytes [FSRP.UEW] | <- 18446744073709551615 packets, 18446744073709551615 bytes [FSRP.UEW]";
        assert!(wrap(text).lines().all(|l| l.len() <= 80));
    }
}
