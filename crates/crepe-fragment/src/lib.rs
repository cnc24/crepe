//! Bounded IPv4/IPv6 reassembly with conservative rejection of all overlaps.
use crepe_core::{Error, Result};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Scope {
    pub section: u32,
    pub interface: u32,
    pub vlans: Vec<u16>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    scope: Scope,
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    protocol: u8,
}
#[derive(Clone, Copy)]
pub struct Limits {
    pub datagrams: usize,
    pub bytes: usize,
    pub fragments: usize,
    pub timeout_secs: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            datagrams: 1024,
            bytes: 8 * 1024 * 1024,
            fragments: 64,
            timeout_secs: 60,
        }
    }
}
#[derive(Debug, Default)]
pub struct Statistics {
    pub completed: u64,
    pub expired: u64,
    pub evicted: u64,
    pub rejected: u64,
}
struct Datagram {
    created: i128,
    pieces: BTreeMap<usize, Vec<u8>>,
    prefix: Option<Vec<u8>>,
    total: Option<usize>,
    next: u8,
    previous: usize,
    ipv6: bool,
    bytes: usize,
}
struct Fragment<'a> {
    key: Key,
    offset: usize,
    more: bool,
    prefix: &'a [u8],
    payload: &'a [u8],
    next: u8,
    previous: usize,
    ipv6: bool,
}
pub struct Table {
    limits: Limits,
    entries: BTreeMap<Key, Datagram>,
    expiry: BTreeSet<(i128, Key)>,
    bytes: usize,
    watermark: Option<i128>,
    pub stats: Statistics,
}
fn error(m: &str) -> Error {
    Error::new("CREPE-IP-001", m)
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn parse<'a>(ip: &'a [u8], scope: &Scope) -> Result<Option<Fragment<'a>>> {
    match ip.first().map(|b| b >> 4) {
        Some(4) => {
            if ip.len() < 20 {
                return Err(error("short IPv4 header"));
            }
            let header = usize::from(ip[0] & 15) * 4;
            let total = usize::from(be16(&ip[2..4]));
            if header < 20 || total < header || total > ip.len() {
                return Err(error("invalid IPv4 lengths"));
            }
            let flags = be16(&ip[6..8]);
            let offset = usize::from(flags & 0x1fff) * 8;
            let more = flags & 0x2000 != 0;
            if offset == 0 && !more {
                return Ok(None);
            }
            Ok(Some(Fragment {
                key: Key {
                    scope: scope.clone(),
                    src: Ipv4Addr::from(<[u8; 4]>::try_from(&ip[12..16]).unwrap()).into(),
                    dst: Ipv4Addr::from(<[u8; 4]>::try_from(&ip[16..20]).unwrap()).into(),
                    id: u32::from(be16(&ip[4..6])),
                    protocol: ip[9],
                },
                offset,
                more,
                prefix: &ip[..header],
                payload: &ip[header..total],
                next: ip[9],
                previous: 9,
                ipv6: false,
            }))
        }
        Some(6) => {
            if ip.len() < 40 {
                return Err(error("short IPv6 header"));
            }
            let total = 40 + usize::from(be16(&ip[4..6]));
            if total > ip.len() {
                return Err(error("truncated IPv6 packet"));
            }
            let mut next = ip[6];
            let mut pos = 40;
            let mut previous = 6;
            for _ in 0..16 {
                if next == 44 {
                    let h = ip
                        .get(pos..pos + 8)
                        .filter(|_| pos + 8 <= total)
                        .ok_or_else(|| error("short IPv6 fragment header"))?;
                    let field = be16(&h[2..4]);
                    if field & 6 != 0 || h[1] != 0 {
                        return Err(error("reserved IPv6 fragment bits"));
                    }
                    return Ok(Some(Fragment {
                        key: Key {
                            scope: scope.clone(),
                            src: Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()).into(),
                            dst: Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap()).into(),
                            id: u32::from_be_bytes(h[4..8].try_into().unwrap()),
                            protocol: 0,
                        },
                        offset: usize::from(field & 0xfff8),
                        more: field & 1 != 0,
                        prefix: &ip[..pos],
                        payload: &ip[pos + 8..total],
                        next: h[0],
                        previous,
                        ipv6: true,
                    }));
                }
                if !matches!(next, 0 | 43 | 60 | 51) {
                    return Ok(None);
                }
                let h = ip
                    .get(pos..pos + 2)
                    .filter(|_| pos + 2 <= total)
                    .ok_or_else(|| error("short IPv6 extension"))?;
                let length = if next == 51 {
                    (usize::from(h[1]) + 2) * 4
                } else {
                    (usize::from(h[1]) + 1) * 8
                };
                if pos + length > total {
                    return Err(error("truncated IPv6 extension"));
                }
                previous = pos;
                next = h[0];
                pos += length;
            }
            Err(error("IPv6 extension chain limit"))
        }
        _ => Err(error("expected IPv4/IPv6")),
    }
}
impl Table {
    pub fn new(limits: Limits) -> Result<Self> {
        if limits.datagrams == 0
            || limits.datagrams > 65536
            || limits.bytes == 0
            || limits.bytes > 256 * 1024 * 1024
            || limits.fragments == 0
            || limits.fragments > 1024
            || limits.timeout_secs == 0
            || limits.timeout_secs > 60
        {
            return Err(error("invalid fragment limits"));
        }
        Ok(Self {
            limits,
            entries: BTreeMap::new(),
            expiry: BTreeSet::new(),
            bytes: 0,
            watermark: None,
            stats: Statistics::default(),
        })
    }
    pub fn buffered_bytes(&self) -> usize {
        self.bytes
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    fn remove(&mut self, key: &Key) -> Option<Datagram> {
        let d = self.entries.remove(key)?;
        self.bytes -= d.bytes;
        self.expiry.remove(&(d.created, key.clone()));
        Some(d)
    }
    pub fn expire(&mut self, now: i128) -> Result<()> {
        if now.abs_diff(0) > i128::MAX as u128 / 4 {
            return Err(error("invalid fragment timestamp"));
        }
        let now = self.watermark.map_or(now, |old| old.max(now));
        self.watermark = Some(now);
        while let Some((time, key)) = self.expiry.first().cloned() {
            if now - time < i128::from(self.limits.timeout_secs) * 1_000_000_000 {
                break;
            }
            self.remove(&key);
            self.stats.expired += 1;
        }
        Ok(())
    }
    /// None is an incomplete datagram; borrowed output is an unfragmented packet.
    pub fn process<'a>(
        &mut self,
        ip: &'a [u8],
        scope: &Scope,
        now: i128,
    ) -> Result<Option<Cow<'a, [u8]>>> {
        self.expire(now)?;
        let Some(f) = parse(ip, scope)? else {
            return Ok(Some(Cow::Borrowed(ip)));
        };
        if f.payload.is_empty()
            || (f.more && !f.payload.len().is_multiple_of(8))
            || f.offset + f.payload.len() > 65535
        {
            self.remove(&f.key);
            self.stats.rejected += 1;
            return Err(error("invalid fragment payload/offset"));
        }
        if f.ipv6 && f.offset == 0 && !f.more {
            return Ok(Some(Cow::Owned(assemble(
                f.prefix, f.payload, f.next, f.previous, true,
            )?)));
        }
        let result = self.insert(&f, now);
        if result.is_err() {
            self.remove(&f.key);
            self.stats.rejected += 1;
        }
        result.map(|p| p.map(Cow::Owned))
    }
    fn insert(&mut self, f: &Fragment<'_>, now: i128) -> Result<Option<Vec<u8>>> {
        if !self.entries.contains_key(&f.key) {
            if self.entries.len() == self.limits.datagrams {
                let (_, key) = self.expiry.first().unwrap().clone();
                self.remove(&key);
                self.stats.evicted += 1;
            }
            self.entries.insert(
                f.key.clone(),
                Datagram {
                    created: now,
                    pieces: BTreeMap::new(),
                    prefix: None,
                    total: None,
                    next: f.next,
                    previous: f.previous,
                    ipv6: f.ipv6,
                    bytes: 0,
                },
            );
            self.expiry.insert((now, f.key.clone()));
        }
        let d = self.entries.get_mut(&f.key).unwrap();
        let end = f.offset + f.payload.len();
        if d.next != f.next || d.previous != f.previous || d.ipv6 != f.ipv6 {
            return Err(error("inconsistent fragment headers"));
        }
        if d.total
            .is_some_and(|total| end > total || (!f.more && end != total))
            || (!f.more && d.pieces.iter().any(|(offset, p)| offset + p.len() > end))
        {
            return Err(error("inconsistent final fragment length"));
        }
        if d.pieces
            .range(..=f.offset)
            .next_back()
            .is_some_and(|(o, p)| o + p.len() > f.offset)
            || d.pieces
                .range(f.offset..)
                .next()
                .is_some_and(|(o, _)| *o < end)
        {
            return Err(error("overlapping fragments rejected"));
        }
        let extra = f.payload.len() + if f.offset == 0 { f.prefix.len() } else { 0 };
        if d.pieces.len() == self.limits.fragments || self.bytes + extra > self.limits.bytes {
            return Err(error("fragment count/memory budget exceeded"));
        }
        if f.offset == 0 {
            d.prefix = Some(f.prefix.to_vec());
        }
        if !f.more {
            d.total = Some(end);
        }
        d.pieces.insert(f.offset, f.payload.to_vec());
        d.bytes += extra;
        self.bytes += extra;
        if let (Some(total), Some(prefix)) = (d.total, d.prefix.as_ref()) {
            let mut cursor = 0;
            for (offset, p) in &d.pieces {
                if *offset != cursor {
                    return Ok(None);
                }
                cursor += p.len();
            }
            if cursor == total {
                let mut payload = Vec::with_capacity(total);
                for p in d.pieces.values() {
                    payload.extend_from_slice(p);
                }
                let packet = assemble(prefix, &payload, d.next, d.previous, d.ipv6)?;
                self.remove(&f.key);
                self.stats.completed += 1;
                return Ok(Some(packet));
            }
        }
        Ok(None)
    }
    pub fn finish(&mut self) -> usize {
        let remaining = self.len();
        self.entries.clear();
        self.expiry.clear();
        self.bytes = 0;
        remaining
    }
}
fn assemble(
    prefix: &[u8],
    payload: &[u8],
    next: u8,
    previous: usize,
    ipv6: bool,
) -> Result<Vec<u8>> {
    let mut out = prefix.to_vec();
    out.extend_from_slice(payload);
    if ipv6 {
        let length = u16::try_from(out.len() - 40)
            .map_err(|_| error("IPv6 reassembled length exceeds 65535"))?;
        out[4..6].copy_from_slice(&length.to_be_bytes());
        out[previous] = next;
    } else {
        let length =
            u16::try_from(out.len()).map_err(|_| error("IPv4 reassembled length exceeds 65535"))?;
        out[2..4].copy_from_slice(&length.to_be_bytes());
        out[6] = 0;
        out[7] = 0;
        out[10] = 0;
        out[11] = 0;
        let mut sum = 0u32;
        for b in out[..prefix.len()].as_chunks::<2>().0.iter() {
            sum += u32::from(be16(b));
        }
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16);
        }
        out[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }
    Ok(out)
}
