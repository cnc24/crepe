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
        let linktype = if dlt == pcap::Linktype::RAW {
            101
        } else {
            u32::try_from(dlt.0).map_err(error)?
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
