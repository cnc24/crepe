use crepe_capture as capture;
use crepe_core::{PacketEvent, Protocol};
const PCAP: &[u8] = include_bytes!("../../../example.pcap");
const NG: &[u8] = include_bytes!("../../../fixtures/example.pcapng");
fn events(bytes: &[u8]) -> Vec<PacketEvent> {
    let mut events = Vec::new();
    let stats = capture::read(bytes, |e| {
        events.push(e);
        Ok(())
    })
    .unwrap();
    assert_eq!(stats.ip_packets as usize, events.len());
    events
}
#[test]
fn decode_all_protocols_and_addresses() {
    let e = events(PCAP);
    assert_eq!(e.len(), 6);
    assert_eq!(
        e.iter().map(|e| e.proto).collect::<Vec<_>>(),
        [
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Icmp,
            Protocol::Icmpv6
        ]
    );
    assert_eq!(e[0].src.ip.to_string(), "192.0.2.10");
    assert_eq!(e[2].dst.ip.to_string(), "2001:db8::20");
    assert_eq!(e[0].dst.port, Some(443));
    assert_eq!(e[3].dst.port, Some(53));
    assert_eq!((e[4].icmp_type, e[4].icmp_code), (Some(8), Some(0)));
    assert_eq!((e[5].icmp_type, e[5].icmp_code), (Some(128), Some(0)));
    assert_eq!(e[4].src.port, None);
    assert_eq!(
        e[0].header.timestamp_ns.as_deref(),
        Some("1700000000123456000")
    );
}
#[test]
fn pcap_endianness_and_precision() {
    assert_eq!(
        events(PCAP),
        events(include_bytes!("../../../fixtures/big-endian.pcap"))
    );
    assert_eq!(
        events(include_bytes!("../../../fixtures/nanosecond.pcap"))[0]
            .header
            .timestamp_ns
            .as_deref(),
        Some("1700000000123456789")
    );
}
#[test]
fn pcapng_endianness_resolution_offset_and_sections() {
    let e = events(NG);
    assert_eq!(
        e,
        events(include_bytes!("../../../fixtures/big-endian.pcapng"))
    );
    assert_eq!(
        e[0].header.timestamp_ns.as_deref(),
        Some("1700000000500000000")
    );
    assert_eq!(
        events(include_bytes!("../../../fixtures/binary-resolution.pcapng"))[0]
            .header
            .timestamp_ns
            .as_deref(),
        Some("1699999999500000000")
    );
    let multi = events(include_bytes!("../../../fixtures/multi-section.pcapng"));
    assert_eq!(multi.len(), 12);
    assert_eq!(multi[0].header.timestamp_ns, multi[6].header.timestamp_ns);
    assert_eq!(multi[6].header.sequence, 7);
}
#[test]
fn simple_packets_have_no_timestamp_or_padding() {
    let e = events(include_bytes!("../../../fixtures/simple.pcapng"));
    assert_eq!(e.len(), 6);
    assert!(e.iter().all(|e| e.header.timestamp_ns.is_none()));
    assert_eq!(e[0].header.captured_len, 54);
}
#[test]
fn truncated_captures_and_bad_magic_fail() {
    for data in [PCAP, NG] {
        for len in 0..data.len() {
            // At exact record/block boundaries a shortened capture is valid.
            let _ = capture::read(&data[..len], |_| Ok(()));
        }
        assert!(capture::read(&data[..data.len() - 1], |_| Ok(())).is_err());
    }
    assert_eq!(
        capture::read(&b"pizza"[..], |_| Ok(())).unwrap_err().code,
        "CREPE-CAP-002"
    );
}
#[test]
fn unsupported_link_and_malformed_packet_are_distinct() {
    let mut data = PCAP.to_vec();
    data[20..24].copy_from_slice(&147u32.to_le_bytes());
    assert_eq!(
        capture::read(data.as_slice(), |_| Ok(())).unwrap_err().code,
        "CREPE-CAP-003"
    );
    data = PCAP.to_vec();
    data[54] = 0x4f; // IPv4 IHL exceeds available bytes.
    assert_eq!(
        capture::read(data.as_slice(), |_| Ok(())).unwrap_err().code,
        "CREPE-PKT-001"
    );
}
#[test]
fn fragments_have_no_invented_ports() {
    let mut data = PCAP.to_vec();
    data[60..62].copy_from_slice(&0x2000u16.to_be_bytes()); // IPv4 more fragments.
    let e = events(&data);
    assert!(e[0].fragmented);
    assert_eq!(e[0].dst.port, None);
}
#[test]
fn non_ip_frames_are_counted_and_skipped() {
    let mut data = PCAP.to_vec();
    data[52..54].copy_from_slice(&0x88b5u16.to_be_bytes());
    let stats = capture::read(data.as_slice(), |_| Ok(())).unwrap();
    assert_eq!(stats.records, 6);
    assert_eq!(stats.skipped_non_ip, 1);
    assert_eq!(stats.ip_packets, 5);
}
#[test]
fn unknown_protocol_is_preserved() {
    let mut data = PCAP.to_vec();
    data[63] = 253;
    assert_eq!(events(&data)[0].proto, Protocol::Other(253));
}
#[test]
fn invalid_pcapng_interface_fails() {
    let mut data = NG.to_vec();
    // SHB (28) + IDB (44) + EPB header (8).
    data[80..84].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(
        capture::read(data.as_slice(), |_| Ok(())).unwrap_err().code,
        "CREPE-CAP-002"
    );
}
#[test]
fn consumer_errors_propagate() {
    let e = capture::read(PCAP, |_| Err(crepe_core::Error::new("TEST", "stop"))).unwrap_err();
    assert_eq!(e.code, "TEST");
}

#[test]
fn short_reads_work_for_both_formats() {
    use std::io::{self, Read};
    struct Slow<'a>(&'a [u8]);
    impl Read for Slow<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = buf.len().min(1);
            self.0.read(&mut buf[..len])
        }
    }
    for data in [PCAP, NG] {
        assert_eq!(capture::read(Slow(data), |_| Ok(())).unwrap().ip_packets, 6);
    }
}
#[test]
fn vlan_and_ipv6_extension_headers() {
    let header = events(PCAP)[0].header.clone();
    let raw = &PCAP[40..94];
    let mut vlan = raw[..12].to_vec();
    vlan.extend_from_slice(&[0x81, 0x00, 0, 42]);
    vlan.extend_from_slice(&raw[12..]);
    assert_eq!(
        crepe_packet::decode(&vlan, header.clone())
            .unwrap()
            .unwrap()
            .dst
            .port,
        Some(443)
    );
    let mut reader = pcap_file::pcap::PcapReader::new(PCAP).unwrap();
    reader.next_packet().unwrap().unwrap();
    reader.next_packet().unwrap().unwrap();
    let packet = reader.next_packet().unwrap().unwrap();
    let mut ipv6 = packet.data.to_vec();
    ipv6[18..20].copy_from_slice(&28u16.to_be_bytes());
    ipv6[20] = 0; // Hop-by-hop extension follows IPv6.
    ipv6.splice(54..54, [6, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        crepe_packet::decode(&ipv6, header.clone())
            .unwrap()
            .unwrap()
            .dst
            .port,
        Some(443)
    );
    ipv6[20] = 44; // IPv6 fragment, M bit set.
    ipv6[56..58].copy_from_slice(&1u16.to_be_bytes());
    let event = crepe_packet::decode(&ipv6, header).unwrap().unwrap();
    assert!(event.fragmented);
    assert_eq!(event.dst.port, None);
}
#[test]
fn multiple_pcapng_interfaces_use_their_own_metadata() {
    let mut data = NG[..72].to_vec();
    let mut idb = NG[28..72].to_vec();
    idb[28..36].copy_from_slice(&2i64.to_le_bytes()); // if_tsoffset value.
    data.extend_from_slice(&idb);
    let mut packets = NG[72..].to_vec();
    packets[8..12].copy_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&packets);
    let result = events(&data);
    assert_eq!(
        result[0].header.timestamp_ns.as_deref(),
        Some("1700000002500000000")
    );
    assert_eq!(
        result[1].header.timestamp_ns.as_deref(),
        Some("1700000001500000000")
    );
}

#[test]
fn loopback_raw_and_linux_cooked_decode() {
    let p = &PCAP[40..94];
    let header = events(PCAP)[0].header.clone();
    for (link, prefix) in [
        (0, 2u32.to_le_bytes().to_vec()),
        (0, 2u32.to_be_bytes().to_vec()),
        (108, 2u32.to_be_bytes().to_vec()),
        (101, vec![]),
        (113, vec![0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0]),
        (
            276,
            vec![8, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
    ] {
        let mut data = prefix;
        data.extend_from_slice(&p[14..]);
        let parsed = crepe_packet::decode_link(&data, header.clone(), link)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.dst.port, Some(443), "link {link}");
    }
    for link in [0, 108, 113, 276] {
        assert!(crepe_packet::decode_link(&[0], header.clone(), link).is_err());
    }
}
#[test]
fn record_callback_can_stop_before_corrupt_tail() {
    let mut data = PCAP[..94].to_vec();
    data.extend_from_slice(&[0; 5]);
    let mut seen = 0;
    capture::read_records(data.as_slice(), |_| {
        seen += 1;
        Ok(false)
    })
    .unwrap();
    assert_eq!(seen, 1);
    assert!(capture::read_records(data.as_slice(), |_| Ok(true)).is_err());
}
