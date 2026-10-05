//! Optional libpcap backend. Signals, deadlines and presentation belong to the caller.
use crate::{supported_link, Record};
use crepe_core::{Error, EventHeader, EventType, Result};

pub struct Interface {
    pub name: String,
    pub description: Option<String>,
}
pub struct Statistics {
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}
pub struct Capture {
    inner: pcap::Capture<pcap::Active>,
    linktype: u32,
    sequence: u64,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-CAP-001", e)
}
pub fn interfaces() -> Result<Vec<Interface>> {
    Ok(pcap::Device::list()
        .map_err(error)?
        .into_iter()
        .map(|d| Interface {
            name: d.name,
            description: d.desc,
        })
        .collect())
}
impl Capture {
    pub fn open(interface: &str, bpf: Option<&str>, promisc: bool) -> Result<Self> {
        let mut inner = pcap::Capture::from_device(interface)
            .map_err(error)?
            .promisc(promisc)
            .snaplen(65535)
            .buffer_size(4 * 1024 * 1024)
            .timeout(100)
            .immediate_mode(true)
            .open()
            .map_err(error)?
            .setnonblock()
            .map_err(error)?;
        if let Some(bpf) = bpf {
            inner
                .filter(bpf, true)
                .map_err(|e| Error::new("CREPE-CAP-005", e))?;
        }
        let dlt = inner.get_datalink();
        let linktype = match dlt.get_name().map_err(error)?.as_str() {
            "RAW" => 101,
            "LOOP" => 108,
            _ => u32::try_from(dlt.0).map_err(error)?,
        };
        supported_link(linktype)?;
        Ok(Self {
            inner,
            linktype,
            sequence: 0,
        })
    }
    pub fn set_filter(&mut self, expression: &str) -> Result<()> {
        self.inner
            .filter(expression, true)
            .map_err(|e| Error::new("CREPE-CAP-005", e))
    }
    pub fn linktype(&self) -> u32 {
        self.linktype
    }
    /// Nonblocking: None means no packet is available right now.
    pub fn next_record(&mut self) -> Result<Option<Record<'_>>> {
        let packet = match self.inner.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => return Ok(None),
            Err(e) => return Err(error(e)),
        };
        self.sequence += 1;
        let sec = i128::from(packet.header.ts.tv_sec);
        let micros = i128::from(packet.header.ts.tv_usec);
        if !(0..1_000_000).contains(&micros)
            || packet.data.len() != packet.header.caplen as usize
            || packet.header.caplen > packet.header.len
        {
            return Err(error("invalid live packet metadata"));
        }
        let header = EventHeader {
            schema_version: 2,
            event_type: EventType::Packet,
            sequence: self.sequence,
            section: 0,
            interface: 0,
            timestamp_ns: Some((sec * 1_000_000_000 + micros * 1000).to_string()),
            captured_len: packet.header.caplen,
            original_len: packet.header.len,
        };
        Ok(Some(Record {
            data: packet.data,
            header,
            linktype: self.linktype,
        }))
    }
    pub fn statistics(&mut self) -> Result<Statistics> {
        let s = self.inner.stats().map_err(error)?;
        Ok(Statistics {
            received: s.received,
            dropped: s.dropped,
            interface_dropped: s.if_dropped,
        })
    }
}

/// Compile/evaluate an Ethernet BPF filter without opening a network device.
pub struct EthernetFilter(pcap::BpfProgram);
impl EthernetFilter {
    pub fn compile(expression: &str) -> Result<Self> {
        Ok(Self(
            pcap::Capture::dead(pcap::Linktype::ETHERNET)
                .map_err(error)?
                .compile(expression, true)
                .map_err(error)?,
        ))
    }
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.0.filter(bytes)
    }
}

/// Per-linktype offline BPF programs. Uses the same compiler as tcpdump.
pub struct PacketFilter {
    expression: String,
    programs: std::collections::BTreeMap<u32, pcap::BpfProgram>,
}
impl PacketFilter {
    pub fn new(expression: &str) -> Result<Self> {
        if expression.len() > 4096 {
            return Err(Error::new("CREPE-CAP-005", "BPF filter exceeds 4096 bytes"));
        }
        let mut result = Self {
            expression: expression.into(),
            programs: Default::default(),
        };
        // Validate even if the input is empty. Our packet reader supports IP linktypes.
        result.compile(1)?;
        Ok(result)
    }
    fn compile(&mut self, link: u32) -> Result<()> {
        supported_link(link)?;
        // pcap crate constants are file LINKTYPE values, not always native DLTs.
        // Ask libpcap by name (notably RAW is 101 in files but 12 on Linux/macOS).
        let name = match link {
            0 => "NULL",
            1 => "EN10MB",
            101 => "RAW",
            108 => "LOOP",
            113 => "LINUX_SLL",
            228 => "IPV4",
            229 => "IPV6",
            276 => "LINUX_SLL2",
            _ => unreachable!("supported_link checked above"),
        };
        let dlt = pcap::Linktype::from_name(name).map_err(|e| Error::new("CREPE-CAP-005", e))?;
        let program = pcap::Capture::dead(dlt)
            .and_then(|c| c.compile(&self.expression, true))
            .map_err(|e| {
                Error::new(
                    "CREPE-CAP-005",
                    format!("BPF filter for LINKTYPE {link}: {e}"),
                )
            })?;
        self.programs.insert(link, program);
        Ok(())
    }
    pub fn matches(&mut self, record: &Record<'_>) -> Result<bool> {
        // pcap 2.x's safe evaluator uses the slice length as both caplen and wirelen.
        // Never silently give incorrect answers for `len`, `greater` or `less`.
        if record.header.original_len != record.header.captured_len {
            return Err(Error::new("CREPE-CAP-005", format!(
                "record {} is snaplen-truncated; offline BPF requires complete frames in this build (use CQL with --tolerant or capture with a larger snaplen)", record.header.sequence)));
        }
        if !self.programs.contains_key(&record.linktype) {
            self.compile(record.linktype)?;
        }
        Ok(self.programs[&record.linktype].filter(record.data))
    }
}

#[cfg(test)]
mod offline_filter_tests {
    use super::*;
    #[test]
    fn bpf_handles_linktypes_and_rejects_truncation_instead_of_wrong_length() {
        let bytes = include_bytes!("../../../example.pcap");
        let mut filter = PacketFilter::new("tcp and dst port 443").unwrap();
        crate::read_records(&bytes[..], |record| {
            if record.header.sequence != 1 {
                return Ok(false);
            }
            assert!(filter.matches(&record).unwrap());
            let mut header = record.header.clone();
            let ip = &record.data[14..];
            for linktype in [101, 228] {
                header.captured_len = ip.len() as u32;
                header.original_len = header.captured_len;
                assert!(filter
                    .matches(&Record {
                        data: ip,
                        header: header.clone(),
                        linktype
                    })
                    .unwrap());
            }
            let mut loopback = 2_u32.to_ne_bytes().to_vec();
            loopback.extend_from_slice(ip);
            header.captured_len = loopback.len() as u32;
            header.original_len = header.captured_len;
            assert!(filter
                .matches(&Record {
                    data: &loopback,
                    header: header.clone(),
                    linktype: 0
                })
                .unwrap());
            header.original_len += 100;
            let error = filter
                .matches(&Record {
                    data: &loopback,
                    header,
                    linktype: 0,
                })
                .unwrap_err();
            assert_eq!(error.code, "CREPE-CAP-005");
            assert!(error.message.contains("snaplen-truncated"));
            Ok(false)
        })
        .unwrap();
        assert!(PacketFilter::new("tcp and (").is_err());
    }
}
