//! Non-IP link records retain their real addresses, never fabricated IP endpoints.
use crepe_capture::Record;
use crepe_core::{Error, Result};
use serde::Serialize;

#[derive(Serialize)]
pub struct LinkRecord<'a> {
    pub header: &'a crepe_core::EventHeader,
    pub linktype: u32,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub ether_type: u16,
    pub vlans: Vec<u16>,
    pub proto: &'static str,
    pub details: String,
    #[serde(skip)]
    pub payload: &'a [u8],
}
fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|v| format!("{v:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
pub fn decode<'a>(r: &'a Record<'a>) -> Result<Option<LinkRecord<'a>>> {
    let data = r.data;
    let bad = || Error::new("CREPE-PKT-001", "truncated link header");
    let (src, dst, mut kind, mut offset) = match r.linktype {
        1 => {
            if data.len() < 14 {
                return Err(bad());
            }
            (
                Some(mac(&data[6..12])),
                Some(mac(&data[..6])),
                u16::from_be_bytes([data[12], data[13]]),
                14,
            )
        }
        113 => {
            if data.len() < 16 {
                return Err(bad());
            }
            (None, None, u16::from_be_bytes([data[14], data[15]]), 16)
        }
        276 => {
            if data.len() < 20 {
                return Err(bad());
            }
            (None, None, u16::from_be_bytes([data[0], data[1]]), 20)
        }
        _ => return Ok(None),
    };
    let mut vlans = Vec::new();
    while matches!(kind, 0x8100 | 0x88a8 | 0x9100) {
        let tag = data.get(offset..offset + 4).ok_or_else(bad)?;
        vlans.push(u16::from_be_bytes([tag[0], tag[1]]) & 0xfff);
        kind = u16::from_be_bytes([tag[2], tag[3]]);
        offset += 4;
    }
    if matches!(kind, 0x0800 | 0x86dd) {
        return Ok(None);
    }
    let payload = &data[offset..];
    let proto = match kind {
        0x0806 => "arp",
        0x88cc => "lldp",
        0x888e => "eapol",
        0..=1500 => "llc",
        _ => "ethernet",
    };
    let mut details = format!("EtherType 0x{kind:04x}");
    if kind == 0x0806 {
        if payload.len() < 8 {
            return Err(Error::new("CREPE-PKT-001", "truncated ARP header"));
        }
        let h = usize::from(payload[4]);
        let p = usize::from(payload[5]);
        if payload.len() < 8 + 2 * (h + p) {
            return Err(Error::new("CREPE-PKT-001", "truncated ARP addresses"));
        }
        let op = u16::from_be_bytes([payload[6], payload[7]]);
        details = format!("operation {op}");
        if h == 6 && p == 4 && payload[2..4] == [8, 0] {
            let ip = |b: &[u8]| std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let sender = ip(&payload[14..18]);
            let target = ip(&payload[24..28]);
            details = match op {
                1 => format!("Request who-has {target} tell {sender}"),
                2 => format!("Reply {sender} is-at {}", mac(&payload[8..14])),
                _ => format!("operation {op}, {sender} > {target}"),
            };
        }
    }
    Ok(Some(LinkRecord {
        header: &r.header,
        linktype: r.linktype,
        src_mac: src,
        dst_mac: dst,
        ether_type: kind,
        vlans,
        proto,
        details,
        payload,
    }))
}
