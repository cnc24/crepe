//! Human packet summaries. Machine-readable packet schemas remain unchanged.
use crepe_core::{Endpoint, Protocol};
use crepe_packet::PacketView;
use std::fmt::Write;

fn timestamp(value: Option<&str>) -> String {
    let Some(ns) = value.and_then(|v| v.parse::<i128>().ok()) else {
        return "time unknown".into();
    };
    let secs = ns.div_euclid(1_000_000_000).rem_euclid(86400);
    format!(
        "{:02}:{:02}:{:02}.{:09}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        ns.rem_euclid(1_000_000_000)
    )
}
pub(crate) fn endpoint(e: &Endpoint) -> String {
    match (e.ip.is_ipv6(), e.port) {
        (true, Some(port)) => format!("[{}]:{port}", e.ip),
        (false, Some(port)) => format!("{}:{port}", e.ip),
        (_, None) => e.ip.to_string(),
    }
}
pub(crate) fn flags(value: u8) -> String {
    let mut result = String::new();
    for (bit, symbol) in [
        (1, 'F'),
        (2, 'S'),
        (4, 'R'),
        (8, 'P'),
        (16, '.'),
        (32, 'U'),
        (64, 'E'),
        (128, 'W'),
    ] {
        if value & bit != 0 {
            result.push(symbol);
        }
    }
    if result.is_empty() {
        result.push_str("none");
    }
    result
}
fn options(mut bytes: &[u8]) -> String {
    let mut values = Vec::new();
    while let Some(&kind) = bytes.first() {
        if kind == 0 {
            values.push("eol".into());
            break;
        }
        if kind == 1 {
            values.push("nop".into());
            bytes = &bytes[1..];
            continue;
        }
        let Some(&len) = bytes.get(1) else {
            values.push("malformed".into());
            break;
        };
        if len < 2 || usize::from(len) > bytes.len() {
            values.push("malformed".into());
            break;
        }
        let data = &bytes[2..usize::from(len)];
        let text = match (kind, data) {
            (2, [a, b]) => format!("mss {}", u16::from_be_bytes([*a, *b])),
            (3, [scale]) => format!("wscale {scale}"),
            (4, []) => "sackOK".into(),
            (5, blocks) if !blocks.is_empty() && blocks.len() % 8 == 0 => {
                let blocks = blocks
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|b| {
                        format!(
                            "{}:{}",
                            u32::from_be_bytes(b[..4].try_into().unwrap()),
                            u32::from_be_bytes(b[4..].try_into().unwrap())
                        )
                    })
                    .collect::<Vec<_>>();
                format!("sack {}", blocks.join(" "))
            }
            (8, [a, b, c, d, e, f, g, h]) => format!(
                "TS val {} ecr {}",
                u32::from_be_bytes([*a, *b, *c, *d]),
                u32::from_be_bytes([*e, *f, *g, *h])
            ),
            _ => format!("kind {kind} len {len}"),
        };
        values.push(text);
        bytes = &bytes[usize::from(len)..];
    }
    values.join(",")
}
fn dns(view: &PacketView<'_>) -> String {
    let p = &view.event;
    if p.proto != Protocol::Udp || ![p.src.port, p.dst.port].contains(&Some(53)) {
        return String::new();
    }
    match crepe_dns::parse(view.payload) {
        Ok(message) => {
            let mut text = format!(
                ", DNS {} id {} rcode {}",
                if message.response {
                    "response"
                } else {
                    "query"
                },
                message.id,
                message.rcode
            );
            if let Some(q) = message.questions.first() {
                let kind = match q.qtype {
                    1 => "A".into(),
                    28 => "AAAA".into(),
                    5 => "CNAME".into(),
                    15 => "MX".into(),
                    16 => "TXT".into(),
                    12 => "PTR".into(),
                    n => format!("TYPE{n}"),
                };
                // JSON quoting escapes hostile/control characters from packet contents.
                let _ = write!(text, " {kind} {}", serde_json::to_string(&q.name).unwrap());
            }
            if message.response {
                let _ = write!(text, " answers {}", message.answers.len());
            }
            if message.truncated {
                text.push_str(" truncated");
            }
            text
        }
        Err(_) => ", DNS malformed/incomplete".into(),
    }
}
pub(crate) fn line(view: &PacketView<'_>) -> String {
    let p = &view.event;
    let mut result = format!(
        "{} {} {} > {}: {}",
        timestamp(p.header.timestamp_ns.as_deref()),
        if p.src.ip.is_ipv6() { "IP6" } else { "IP" },
        endpoint(&p.src),
        endpoint(&p.dst),
        p.proto.to_string().to_uppercase()
    );
    if p.fragmented {
        result.push_str(" fragment (transport details unavailable)");
    } else if let Some(header) = view.tcp_header {
        let seq = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let ack = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let win = u16::from_be_bytes(header[14..16].try_into().unwrap());
        let bits = p.tcp_flags.unwrap_or(0);
        let _ = write!(result, " Flags [{}], seq {seq}", flags(bits));
        if !view.payload.is_empty() {
            let _ = write!(result, ":{}", seq.wrapping_add(view.payload.len() as u32));
        }
        if bits & 16 != 0 {
            let _ = write!(result, ", ack {ack}");
        }
        let _ = write!(result, ", win {win}");
        if header.len() > 20 {
            let _ = write!(result, ", options [{}]", options(&header[20..]));
        }
        let _ = write!(result, ", length {}", view.payload.len());
    } else if p.proto == Protocol::Udp {
        let _ = write!(result, ", length {}{}", view.payload.len(), dns(view));
    } else if let (Some(kind), Some(code)) = (p.icmp_type, p.icmp_code) {
        let label = match (p.proto, kind) {
            (Protocol::Icmp, 8) | (Protocol::Icmpv6, 128) => "echo request",
            (Protocol::Icmp, 0) | (Protocol::Icmpv6, 129) => "echo reply",
            (Protocol::Icmp, 3) | (Protocol::Icmpv6, 1) => "destination unreachable",
            _ => "message",
        };
        let _ = write!(result, " {label}, type {kind}, code {code}");
    }
    let _ = write!(result, ", wire {} bytes", p.header.original_len);
    if !p.vlans.is_empty() {
        let _ = write!(result, ", vlan {:?}", p.vlans);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_and_tcp_options() {
        assert_eq!(
            timestamp(Some("1700000000123456789")),
            "22:13:20.123456789Z"
        );
        assert_eq!(timestamp(Some("-1")), "23:59:59.999999999Z");
        assert_eq!(timestamp(None), "time unknown");
        assert_eq!(flags(0x12), "S.");
        assert_eq!(flags(0x18), "P.");
        assert_eq!(
            options(&[2, 4, 5, 180, 1, 3, 3, 7, 4, 2, 0]),
            "mss 1460,nop,wscale 7,sackOK,eol"
        );
        assert_eq!(options(&[8, 10, 0, 0, 0, 2, 0, 0, 0, 1]), "TS val 2 ecr 1");
        assert_eq!(options(&[2, 1]), "malformed");
    }
}
