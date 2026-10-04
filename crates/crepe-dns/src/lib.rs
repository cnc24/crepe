//! Bounded DNS wire parser, including compression and common resource records.
use crepe_core::{Error, Result};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String),
    Mx { preference: u16, exchange: String },
    Txt(Vec<String>),
    Unknown { length: usize },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub truncated: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}
fn error(text: &str) -> Error {
    Error::new("CREPE-DNS-001", text)
}
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    work: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| error("DNS offset overflow"))?;
        let data = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| error("truncated DNS field"))?;
        self.pos = end;
        Ok(data)
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    }
    fn name(&mut self) -> Result<String> {
        let mut cursor = self.pos;
        let mut consumed = None;
        let mut seen = BTreeSet::new();
        let mut result = String::new();
        let mut expanded = 1;
        loop {
            self.work += 1;
            if self.work > 16384 || seen.len() >= 128 || !seen.insert(cursor) {
                return Err(error("DNS compression loop or work limit"));
            }
            let first = *self
                .bytes
                .get(cursor)
                .ok_or_else(|| error("truncated DNS name"))?;
            if first & 0xc0 == 0xc0 {
                let low = *self
                    .bytes
                    .get(cursor + 1)
                    .ok_or_else(|| error("truncated DNS pointer"))?;
                let target = (usize::from(first & 0x3f) << 8) | usize::from(low);
                if target >= cursor {
                    return Err(error("DNS pointer must reference earlier data"));
                }
                consumed.get_or_insert(cursor + 2);
                cursor = target;
                continue;
            }
            if first & 0xc0 != 0 {
                return Err(error("unsupported DNS label encoding"));
            }
            cursor += 1;
            if first == 0 {
                self.pos = consumed.unwrap_or(cursor);
                if result.is_empty() {
                    result.push('.');
                }
                return Ok(result);
            }
            expanded += usize::from(first) + 1;
            if expanded > 255 {
                return Err(error("DNS name exceeds 255 octets"));
            }
            let label = self
                .bytes
                .get(cursor..cursor + usize::from(first))
                .ok_or_else(|| error("truncated DNS label"))?;
            result.push_str(&escape(label));
            result.push('.');
            cursor += usize::from(first);
        }
    }
    fn records(&mut self, count: u16) -> Result<Vec<ResourceRecord>> {
        let mut records = Vec::new();
        for _ in 0..count {
            let name = self.name()?;
            let rr_type = self.u16()?;
            let class = self.u16()?;
            let ttl = self.u32()?;
            let len = usize::from(self.u16()?);
            let start = self.pos;
            let bytes = self.take(len)?;
            let end = self.pos;
            let data = match rr_type {
                1 if class == 1 => RData::A(Ipv4Addr::from(
                    <[u8; 4]>::try_from(bytes).map_err(|_| error("invalid DNS A length"))?,
                )),
                28 if class == 1 => RData::Aaaa(Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).map_err(|_| error("invalid DNS AAAA length"))?,
                )),
                2 | 5 | 12 => {
                    self.pos = start;
                    let value = self.name()?;
                    if self.pos != end {
                        return Err(error("invalid DNS name RDATA length"));
                    }
                    RData::Name(value)
                }
                15 => {
                    self.pos = start;
                    let preference = self.u16()?;
                    let exchange = self.name()?;
                    if self.pos != end {
                        return Err(error("invalid DNS MX length"));
                    }
                    RData::Mx {
                        preference,
                        exchange,
                    }
                }
                16 => {
                    let mut items = Vec::new();
                    let mut pos = 0;
                    while pos < bytes.len() {
                        let len = usize::from(bytes[pos]);
                        pos += 1;
                        let value = bytes
                            .get(pos..pos + len)
                            .ok_or_else(|| error("invalid DNS TXT length"))?;
                        items.push(escape(value));
                        pos += len;
                    }
                    RData::Txt(items)
                }
                _ => RData::Unknown { length: len },
            };
            records.push(ResourceRecord {
                name,
                rr_type,
                class,
                ttl,
                data,
            });
        }
        Ok(records)
    }
}
fn escape(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
            out.push(*byte as char);
        } else {
            let _ = write!(out, "\\{byte:03}");
        }
    }
    out
}
pub fn parse(bytes: &[u8]) -> Result<Message> {
    if bytes.len() > 65535 {
        return Err(error("DNS message exceeds 65535 bytes"));
    }
    let mut r = Reader {
        bytes,
        pos: 0,
        work: 0,
    };
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let ns = r.u16()?;
    let ar = r.u16()?;
    if u32::from(qd) + u32::from(an) + u32::from(ns) + u32::from(ar) > 256 {
        return Err(error("DNS message exceeds 256 records"));
    }
    let mut questions = Vec::new();
    for _ in 0..qd {
        questions.push(Question {
            name: r.name()?,
            qtype: r.u16()?,
            class: r.u16()?,
        });
    }
    let answers = r.records(an)?;
    let authorities = r.records(ns)?;
    let additionals = r.records(ar)?;
    if r.pos != bytes.len() {
        return Err(error("trailing DNS bytes"));
    }
    Ok(Message {
        id,
        response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 15) as u8,
        rcode: (flags & 15) as u8,
        truncated: flags & 0x200 != 0,
        questions,
        answers,
        authorities,
        additionals,
    })
}
