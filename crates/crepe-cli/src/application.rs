//! Packet-local application recognition; no port-only guesses or TCP reassembly.
use crepe_core::Protocol;
use crepe_packet::PacketView;

pub fn http_line(payload: &[u8]) -> Option<&str> {
    let end = payload.iter().position(|b| *b == b'\n')?;
    let line = std::str::from_utf8(&payload[..end])
        .ok()?
        .trim_end_matches('\r');
    let parts: Vec<_> = line.split(' ').collect();
    let response = parts.len() >= 2
        && matches!(parts[0], "HTTP/1.0" | "HTTP/1.1")
        && parts[1].len() == 3
        && parts[1].bytes().all(|b| b.is_ascii_digit());
    let request = parts.len() == 3
        && !parts[0].is_empty()
        && parts[0].len() <= 32
        && parts[0]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'-')
        && !parts[1].is_empty()
        && matches!(parts[2], "HTTP/1.0" | "HTTP/1.1");
    (request || response).then_some(line)
}
pub fn protocol(view: &PacketView<'_>) -> Option<&'static str> {
    let data = view.payload;
    if view.event.proto == Protocol::Tcp {
        if http_line(data).is_some() {
            return Some("http");
        }
        if data.starts_with(b"SSH-") {
            return Some("ssh");
        }
        if data.len() >= 5 && (20..=24).contains(&data[0]) && data[1] == 3 && data[2] <= 4 {
            return Some("tls");
        }
    }
    if [view.event.src.port, view.event.dst.port].contains(&Some(53)) {
        let dns = match view.event.proto {
            Protocol::Udp => Some(data),
            Protocol::Tcp if data.len() >= 2 => {
                data.get(2..2 + usize::from(u16::from_be_bytes([data[0], data[1]])))
            }
            _ => None,
        };
        if dns.is_some_and(|b| crepe_dns::parse(b).is_ok()) {
            return Some("dns");
        }
    }
    None
}
/// Printable text for grep without terminal escape sequences from untrusted traffic.
pub fn text(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\n' => out.push('\n'),
            b'\r' => {}
            b'\t' => out.push_str("\\t"),
            32..=126 => out.push(char::from(b)),
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out
}
