//! Streaming capture input. Output may be partial on failure.
pub mod export;
#[cfg(feature = "live")]
pub mod live;
use crepe_core::{Error, EventHeader, EventType, PacketEvent, Result};
use crepe_packet as packet;
use pcap_file::{
    pcap::PcapReader,
    pcapng::{blocks::interface_description::InterfaceDescriptionOption, Block, PcapNgReader},
};
use std::{fs::File, io::Read, path::Path};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub records: u64,
    pub ip_packets: u64,
    pub skipped_non_ip: u64,
}
/// Raw bytes borrow the capture reader buffer only for the callback duration.
pub struct Record<'a> {
    pub data: &'a [u8],
    pub header: EventHeader,
    pub linktype: u32,
}
impl Record<'_> {
    pub fn decode(&self) -> Result<Option<PacketEvent>> {
        packet::decode_link(self.data, self.header.clone(), self.linktype).map_err(|e| {
            Error::new(
                e.code,
                format!("record {}: {}", self.header.sequence, e.message),
            )
        })
    }
}
fn error(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-CAP-002", e)
}
pub fn supported_link(link: u32) -> Result<()> {
    if matches!(link, 0 | 1 | 101 | 108 | 113 | 228 | 229 | 276) {
        Ok(())
    } else {
        Err(Error::new(
            "CREPE-CAP-003",
            format!("unsupported LINKTYPE {link}"),
        ))
    }
}
pub fn open(path: &Path) -> Result<File> {
    File::open(path).map_err(|e| Error::new("CREPE-IO-001", format!("{}: {e}", path.display())))
}
pub fn read_file(path: &Path, emit: impl FnMut(PacketEvent) -> Result<()>) -> Result<Stats> {
    read(open(path)?, emit)
}
pub fn read(reader: impl Read, mut emit: impl FnMut(PacketEvent) -> Result<()>) -> Result<Stats> {
    let mut stats = Stats::default();
    read_records(reader, |record| {
        stats.records += 1;
        match record.decode()? {
            Some(event) => {
                stats.ip_packets += 1;
                emit(event)?;
            }
            None => stats.skipped_non_ip += 1,
        }
        Ok(true)
    })?;
    Ok(stats)
}
/// Return false from the callback to stop without consuming the rest of the file.
pub fn read_records(
    mut reader: impl Read,
    mut emit: impl FnMut(Record<'_>) -> Result<bool>,
) -> Result<()> {
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).map_err(error)?;
    let ng = magic == [0x0a, 0x0d, 0x0d, 0x0a];
    let reader = magic.as_slice().chain(reader);
    let mut sequence = 0;
    let mut process = |data: &[u8],
                       original_len: u32,
                       timestamp_ns: Option<String>,
                       section: u32,
                       interface: u32,
                       linktype: u32| {
        let captured_len = u32::try_from(data.len()).map_err(error)?;
        if captured_len > original_len {
            return Err(error("captured length exceeds original length"));
        }
        sequence += 1;
        emit(Record {
            data,
            linktype,
            header: EventHeader {
                schema_version: 2,
                event_type: EventType::Packet,
                sequence,
                section,
                interface,
                timestamp_ns,
                captured_len,
                original_len,
            },
        })
    };
    if ng {
        let mut reader = PcapNgReader::new(reader).map_err(error)?;
        let mut interfaces: Vec<Interface> = Vec::new();
        let mut section = 0;
        while let Some(block) = reader.next_block() {
            match block.map_err(error)? {
                Block::SectionHeader(_) => { interfaces.clear(); section += 1; }
                Block::InterfaceDescription(idb) => {
                    if interfaces.len() >= 4096 { return Err(error("section exceeds 4096 interfaces")); }
                    let mut interface = Interface { link: idb.linktype.into(), snaplen: idb.snaplen, resolution: 6, offset: 0 };
                    for option in idb.options {
                        match option {
                            InterfaceDescriptionOption::IfTsResol(r) => interface.resolution = r,
                            InterfaceDescriptionOption::IfTsOffset(o) => interface.offset = o as i64,
                            _ => {}
                        }
                    }
                    interfaces.push(interface);
                }
                Block::EnhancedPacket(p) => {
                    let interface = interfaces.get(p.interface_id as usize).ok_or_else(|| error("packet references missing interface"))?;
                    supported_link(interface.link)?;
                    if interface.snaplen != 0 && p.data.len() > interface.snaplen as usize { return Err(error("packet exceeds interface snaplen")); }
                    // pcap-file 2 stores raw EPB timestamp ticks in Duration's nanoseconds.
                    let timestamp = interface.timestamp(p.timestamp.as_nanos())?;
                    if !process(&p.data, p.original_len, Some(timestamp), section, p.interface_id, interface.link)? { break; }
                }
                Block::SimplePacket(p) => {
                    let interface = interfaces.first().ok_or_else(|| error("simple packet has no interface"))?;
                    supported_link(interface.link)?;
                    let len = if interface.snaplen == 0 { p.original_len } else { p.original_len.min(interface.snaplen) } as usize;
                    if p.data.len() != (len + 3) & !3 { return Err(error("invalid simple packet length")); }
                    if !process(&p.data[..len], p.original_len, None, section, 0, interface.link)? { break; }
                }
                Block::Packet(_) => return Err(Error::new("CREPE-CAP-003", "obsolete PCAPNG Packet Blocks are unsupported; convert to Enhanced Packet Blocks")),
                _ => {}
            }
        }
    } else {
        let mut reader = PcapReader::new(reader).map_err(error)?;
        let link = reader.header().datalink.into();
        supported_link(link)?;
        while let Some(packet) = reader.next_packet() {
            let p = packet.map_err(error)?;
            if !process(
                &p.data,
                p.orig_len,
                Some(p.timestamp.as_nanos().to_string()),
                0,
                0,
                link,
            )? {
                break;
            }
        }
    }
    Ok(())
}
struct Interface {
    link: u32,
    snaplen: u32,
    resolution: u8,
    offset: i64,
}
impl Interface {
    fn timestamp(&self, ticks: u128) -> Result<String> {
        let units = if self.resolution & 0x80 == 0 {
            10u128.checked_pow(self.resolution.into())
        } else {
            2u128.checked_pow((self.resolution & 0x7f).into())
        }
        .ok_or_else(|| error("timestamp resolution exceeds supported range"))?;
        let ns = ticks * 1_000_000_000 / units;
        Ok((ns as i128 + i128::from(self.offset) * 1_000_000_000).to_string())
    }
}
