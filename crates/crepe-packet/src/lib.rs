use crepe_core::{Endpoint, Error, EventHeader, PacketEvent, Protocol, Result};
use etherparse::{LinkExtSlice, NetSlice, SlicedPacket, TransportSlice};

/// Strict Ethernet decoding. Non-IP Ethernet frames are intentionally skipped.
/// Fragments retain IP metadata but have no ports; reassembly is out of scope.
pub fn decode(data: &[u8], header: EventHeader) -> Result<Option<PacketEvent>> {
    decode_link(data, header, 1)
}

/// Decode standard LINKTYPE values (not platform-dependent DLT values).
pub fn decode_link(data: &[u8], header: EventHeader, link: u32) -> Result<Option<PacketEvent>> {
    Ok(decode_view(data, header, link)?.map(|view| view.event))
}

/// Borrowed transport payload; no payload copy on the packet path.
#[derive(Debug)]
pub struct PacketView<'a> {
    pub event: PacketEvent,
    pub payload: &'a [u8],
    pub tcp_sequence: Option<u32>,
}

pub fn decode_view(data: &[u8], header: EventHeader, link: u32) -> Result<Option<PacketView<'_>>> {
    let Some(packet) = sliced(data, link)? else {
        return Ok(None);
    };
    let (src, dst, payload) = match &packet.net {
        Some(NetSlice::Ipv4(ip)) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
            ip.payload(),
        ),
        Some(NetSlice::Ipv6(ip)) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
            ip.payload(),
        ),
        _ => return Ok(None),
    };
    let mut event = PacketEvent {
        header,
        src: Endpoint {
            ip: src,
            port: None,
        },
        dst: Endpoint {
            ip: dst,
            port: None,
        },
        proto: Protocol::from_number(payload.ip_number.0),
        fragmented: payload.fragmented,
        vlans: packet
            .link_exts
            .iter()
            .filter_map(|e| match e {
                LinkExtSlice::Vlan(v) => Some(v.vlan_identifier().value()),
                _ => None,
            })
            .collect(),
        tcp_flags: None,
        icmp_type: None,
        icmp_code: None,
    };
    let mut transport_payload = &[][..];
    let mut tcp_sequence = None;
    if !event.fragmented {
        match packet.transport {
            Some(TransportSlice::Tcp(t)) => {
                transport_payload = t.payload();
                tcp_sequence = Some(t.sequence_number());
                event.tcp_flags = Some(t.slice()[13]);
                event.src.port = Some(t.source_port());
                event.dst.port = Some(t.destination_port());
            }
            Some(TransportSlice::Udp(t)) => {
                transport_payload = t.payload();
                event.src.port = Some(t.source_port());
                event.dst.port = Some(t.destination_port());
            }
            Some(TransportSlice::Icmpv4(t)) => {
                event.icmp_type = Some(t.slice()[0]);
                event.icmp_code = Some(t.slice()[1]);
            }
            Some(TransportSlice::Icmpv6(t)) => {
                event.icmp_type = Some(t.slice()[0]);
                event.icmp_code = Some(t.slice()[1]);
            }
            _ => {}
        }
    }
    Ok(Some(PacketView {
        event,
        payload: transport_payload,
        tcp_sequence,
    }))
}

fn sliced(data: &[u8], link: u32) -> Result<Option<SlicedPacket<'_>>> {
    let malformed = |message: &str| Error::new("CREPE-PKT-001", message);
    let packet = match link {
        1 => SlicedPacket::from_ethernet(data),
        101 | 228 | 229 => SlicedPacket::from_ip(data),
        113 => SlicedPacket::from_linux_sll(data),
        0 | 108 => {
            let family: [u8; 4] = data
                .get(..4)
                .ok_or_else(|| malformed("short loopback header"))?
                .try_into()
                .unwrap();
            // NULL family is producer-native endian; accept both byte orders.
            let is_ip = |f| matches!(f, 2 | 10 | 24 | 28 | 30);
            if !is_ip(u32::from_be_bytes(family))
                && !(link == 0 && is_ip(u32::from_le_bytes(family)))
            {
                return Ok(None);
            }
            SlicedPacket::from_ip(&data[4..])
        }
        276 => {
            // Linux cooked v2 has a fixed 20-byte header.
            if data.len() < 20 {
                return Err(malformed("short Linux SLL2 header"));
            }
            let kind = u16::from_be_bytes([data[0], data[1]]);
            if !matches!(kind, 0x0800 | 0x86dd) {
                return Ok(None);
            }
            SlicedPacket::from_ip(&data[20..])
        }
        _ => {
            return Err(Error::new(
                "CREPE-CAP-003",
                format!("unsupported LINKTYPE {link}"),
            ))
        }
    }
    .map_err(|e| Error::new("CREPE-PKT-001", e))?;
    Ok(Some(packet))
}

/// Borrow the complete IP datagram and its VLAN scope from a supported link frame.
pub fn network(data: &[u8], link: u32) -> Result<Option<(&[u8], Vec<u16>)>> {
    let Some(packet) = sliced(data, link)? else {
        return Ok(None);
    };
    let (header, length) = match &packet.net {
        Some(NetSlice::Ipv4(ip)) => (ip.header().slice(), usize::from(ip.header().total_len())),
        Some(NetSlice::Ipv6(ip)) => (
            ip.header().slice(),
            40 + usize::from(ip.header().payload_length()),
        ),
        _ => return Ok(None),
    };
    let offset = (header.as_ptr() as usize)
        .checked_sub(data.as_ptr() as usize)
        .ok_or_else(|| Error::new("CREPE-PKT-001", "invalid IP slice offset"))?;
    let bytes = data
        .get(offset..offset + length)
        .ok_or_else(|| Error::new("CREPE-PKT-001", "invalid IP slice length"))?;
    let vlans = packet
        .link_exts
        .iter()
        .filter_map(|e| match e {
            LinkExtSlice::Vlan(v) => Some(v.vlan_identifier().value()),
            _ => None,
        })
        .collect();
    Ok(Some((bytes, vlans)))
}
