//! PCAP output preserving raw bytes and nanosecond timestamps.
use crate::Record;
use crepe_core::{Error, Result};
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    Endianness, TsResolution,
};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    time::Duration,
};

pub struct Export {
    file: Option<BufWriter<File>>,
    writer: Option<PcapWriter<BufWriter<File>>>,
    link: Option<u32>,
    endianness: Option<Endianness>,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-IO-002", e)
}
impl Export {
    /// Refuses to overwrite any existing file, including the capture being read.
    pub fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(error)?;
        Ok(Self {
            file: Some(BufWriter::new(file)),
            writer: None,
            link: None,
            endianness: None,
        })
    }
    fn initialize(&mut self, link: u32, endianness: Endianness) -> Result<()> {
        if self.link.is_some_and(|old| old != link) {
            return Err(Error::new(
                "CREPE-CAP-004",
                "PCAP cannot represent mixed link types",
            ));
        }
        if link == 0 && self.endianness.is_some_and(|old| old != endianness) {
            return Err(Error::new(
                "CREPE-CAP-004",
                "PCAP cannot preserve mixed NULL header byte orders",
            ));
        }
        if self.writer.is_none() {
            self.writer = Some(
                PcapWriter::with_header(
                    self.file.take().ok_or_else(|| {
                        error("export writer unavailable after an earlier write error")
                    })?,
                    PcapHeader {
                        datalink: link.into(),
                        endianness,
                        snaplen: 8_000_000,
                        ts_resolution: TsResolution::NanoSecond,
                        ..Default::default()
                    },
                )
                .map_err(error)?,
            );
            self.link = Some(link);
            self.endianness = Some(endianness);
        }
        Ok(())
    }
    pub fn write(&mut self, record: &Record<'_>) -> Result<()> {
        let ns = record
            .header
            .timestamp_ns
            .as_ref()
            .and_then(|s| s.parse::<u128>().ok())
            .ok_or_else(|| {
                Error::new(
                    "CREPE-CAP-004",
                    "PCAP export requires a nonnegative timestamp",
                )
            })?;
        let seconds = ns / 1_000_000_000;
        if seconds > u128::from(u32::MAX) {
            return Err(Error::new(
                "CREPE-CAP-004",
                "timestamp exceeds PCAP seconds range",
            ));
        }
        // DLT_NULL family uses producer-native byte order; the PCAP container
        // must use the same order so other readers can interpret unchanged bytes.
        let endianness = if record.linktype == 0 {
            let bytes: [u8; 4] = record
                .data
                .get(..4)
                .ok_or_else(|| Error::new("CREPE-CAP-004", "short NULL header"))?
                .try_into()
                .unwrap();
            if matches!(u32::from_be_bytes(bytes), 2 | 10 | 24 | 28 | 30) {
                Endianness::Big
            } else {
                Endianness::Little
            }
        } else {
            Endianness::Big
        };
        self.initialize(record.linktype, endianness)?;
        let packet = PcapPacket::new(
            Duration::new(seconds as u64, (ns % 1_000_000_000) as u32),
            record.header.original_len,
            record.data,
        );
        self.writer
            .as_mut()
            .unwrap()
            .write_packet(&packet)
            .map_err(error)?;
        Ok(())
    }
    pub fn finish(mut self) -> Result<()> {
        // An empty result is still a valid empty Ethernet PCAP.
        if self.writer.is_none() {
            self.initialize(1, Endianness::Big)?;
        }
        self.writer
            .take()
            .unwrap()
            .into_writer()
            .flush()
            .map_err(error)
    }
}
