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
    /// Borrowed TCP header, including options, for packet presentation.
    pub tcp_header: Option<&'a [u8]>,
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
    let mut tcp_header = None;
    if !event.fragmented {
        match packet.transport {
            Some(TransportSlice::Tcp(t)) => {
                transport_payload = t.payload();
                tcp_sequence = Some(t.sequence_number());
                tcp_header = Some(&t.slice()[..usize::from(t.data_offset()) * 4]);
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
                transport_payload = t.payload();
                event.icmp_type = Some(t.slice()[0]);
                event.icmp_code = Some(t.slice()[1]);
            }
            Some(TransportSlice::Icmpv6(t)) => {
                transport_payload = t.payload();
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
        tcp_header,
    }))
}

fn sliced(data: &[u8], link: u32) -> Result<Option<SlicedPacket<'_>>> {
    let malformed = |message: &str| Error::new("CREPE-PKT-001", message);
    let packet = match link {
        1 => SlicedPacket::from_ethernet(data),
        101 | 228 | 229 => SlicedPacket::from_ip(data),
        113 => {
            if data.len() < 16 {
                return Err(malformed("short Linux SLL header"));
            }
            // libpcap's Linux `any` device includes ARPHRD_LOOPBACK (772).
            // etherparse's SLL parser currently rejects that hardware type,
            // although its protocol field carries the same EtherType as Ethernet.
            if u16::from_be_bytes([data[2], data[3]]) == 772 {
                etherparse::LinuxSllPacketType::try_from(u16::from_be_bytes([data[0], data[1]]))
                    .map_err(|e| Error::new("CREPE-PKT-001", e))?;
                SlicedPacket::from_ether_type(
                    etherparse::EtherType(u16::from_be_bytes([data[14], data[15]])),
                    &data[16..],
                )
            } else {
                SlicedPacket::from_linux_sll(data)
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_any_loopback_sll_and_sll2() {
        for ipv6 in [false, true] {
            let mut ip = Vec::new();
            let builder = if ipv6 {
                etherparse::PacketBuilder::ipv6([0; 16], [1; 16], 64)
            } else {
                etherparse::PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 1], 64)
            };
            builder.udp(1234, 53).write(&mut ip, b"loopback").unwrap();
            let kind: u16 = if ipv6 { 0x86dd } else { 0x0800 };
            for link in [113, 276] {
                let mut frame = if link == 113 {
                    let mut h = vec![0; 16];
                    h[2..4].copy_from_slice(&772u16.to_be_bytes());
                    h[14..16].copy_from_slice(&kind.to_be_bytes());
                    h
                } else {
                    let mut h = vec![0; 20];
                    h[..2].copy_from_slice(&kind.to_be_bytes());
                    h[8..10].copy_from_slice(&772u16.to_be_bytes());
                    h
                };
                frame.extend_from_slice(&ip);
                assert_eq!(network(&frame, link).unwrap().unwrap().0, ip);
                let packet = sliced(&frame, link).unwrap().unwrap();
                assert!(matches!(packet.transport, Some(TransportSlice::Udp(_))));
                assert!(sliced(&frame[..10], link).is_err());
                assert!(sliced(&frame[..frame.len() - 1], link).is_err());
            }
        }
        let mut non_ip = [0; 16];
        non_ip[2..4].copy_from_slice(&772u16.to_be_bytes());
        non_ip[14..16].copy_from_slice(&0x88b5u16.to_be_bytes());
        assert!(network(&non_ip, 113).unwrap().is_none());
        non_ip[0] = 255;
        assert!(network(&non_ip, 113).is_err());
    }
}
