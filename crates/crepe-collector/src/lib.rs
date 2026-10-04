//! UDP NetFlow v5/v9 and IPFIX decoding. Templates are scoped to transport session/domain.
use crepe_core::{Error, Result};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
#[derive(Debug, Clone, Serialize)]
pub struct Flow {
    pub exporter: SocketAddr,
    pub domain: u32,
    pub version: u16,
    pub sequence: u32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    pub tcp_flags: Option<u16>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    pub export_time: u32,
    /// Reported sampling interval; counters are never silently extrapolated.
    pub sampling_interval: Option<u64>,
    pub fields: Vec<FieldValue>,
}
#[derive(Debug, Clone, Serialize)]
pub struct FieldValue {
    pub enterprise: u32,
    pub id: u16,
    pub value: Vec<u8>,
    pub scope: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Notice {
    pub code: &'static str,
    pub message: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Batch {
    pub version: u16,
    pub domain: u32,
    pub sequence: u32,
    pub flows: Vec<Flow>,
    pub options: Vec<Vec<FieldValue>>,
    pub notices: Vec<Notice>,
}
#[derive(Clone, Copy)]
pub struct Limits {
    pub templates: usize,
    pub sessions: usize,
    pub ttl_secs: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            templates: 4096,
            sessions: 1024,
            ttl_secs: 1800,
        }
    }
}
#[derive(Clone)]
struct Field {
    id: u16,
    length: u16,
    enterprise: u32,
    scope: bool,
}
#[derive(Clone)]
struct Template {
    fields: Vec<Field>,
    options: bool,
    seen: u64,
}
type SessionKey = (SocketAddr, u32, u16);
#[derive(Default)]
struct Session {
    next: Option<u32>,
    seen: u64,
    uptime: Option<u32>,
}
pub struct Collector {
    limits: Limits,
    templates: BTreeMap<(SessionKey, u16), Template>,
    sessions: BTreeMap<SessionKey, Session>,
}
fn err(m: impl Into<String>) -> Error {
    Error::new("CREPE-NETFLOW-001", m.into())
}
fn u16be(b: &[u8]) -> u16 {
    u16::from_be_bytes(b[..2].try_into().unwrap())
}
fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}
fn uint(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 8 {
        None
    } else {
        Some(b.iter().fold(0, |n, b| (n << 8) | u64::from(*b)))
    }
}
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .p
            .checked_add(n)
            .ok_or_else(|| err("length overflow"))?;
        let out = self
            .b
            .get(self.p..end)
            .ok_or_else(|| err("truncated flow record"))?;
        self.p = end;
        Ok(out)
    }
    fn short(&mut self) -> Result<u16> {
        Ok(u16be(self.take(2)?))
    }
    fn left(&self) -> usize {
        self.b.len() - self.p
    }
}
impl Collector {
    pub fn new(limits: Limits) -> Result<Self> {
        if limits.templates == 0
            || limits.templates > 65536
            || limits.sessions == 0
            || limits.sessions > 65536
            || limits.ttl_secs == 0
            || limits.ttl_secs > 86400
        {
            return Err(err("invalid collector limits"));
        }
        Ok(Self {
            limits,
            templates: BTreeMap::new(),
            sessions: BTreeMap::new(),
        })
    }
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    pub fn decode(&mut self, peer: SocketAddr, packet: &[u8], now: u64) -> Result<Batch> {
        if packet.len() < 2 || packet.len() > 65535 {
            return Err(err("invalid export datagram length"));
        }
        let version = u16be(packet);
        let header = match version {
            5 => 24,
            9 => 20,
            10 => 16,
            _ => return Err(err("unsupported export version")),
        };
        if packet.len() < header {
            return Err(err("short export header"));
        }
        if version == 10 && usize::from(u16be(&packet[2..])) != packet.len() {
            return Err(err("IPFIX message length mismatch"));
        }
        self.templates
            .retain(|_, t| now.saturating_sub(t.seen) < self.limits.ttl_secs);
        self.sessions
            .retain(|_, s| now.saturating_sub(s.seen) < self.limits.ttl_secs);
        let domain = match version {
            5 => u32::from(u16be(&packet[20..])),
            9 => u32be(&packet[16..]),
            _ => u32be(&packet[12..]),
        };
        let sequence = u32be(
            &packet[if version == 5 {
                16
            } else if version == 9 {
                12
            } else {
                8
            }..],
        );
        let key = (peer, domain, version);
        let export_time = u32be(&packet[if version == 10 { 4 } else { 8 }..]);
        let uptime = (version != 10).then(|| u32be(&packet[4..]));
        let mut batch = Batch {
            version,
            domain,
            sequence,
            ..Default::default()
        };
        if !self.sessions.contains_key(&key) && self.sessions.len() >= self.limits.sessions {
            return Err(err("exporter session capacity exceeded"));
        }
        let session = self.sessions.entry(key).or_default();
        if session
            .uptime
            .zip(uptime)
            .is_some_and(|(old, new)| new < old && old - new < 0x80000000)
        {
            self.templates.retain(|(k, _), _| *k != key);
            session.next = None;
            batch.notices.push(Notice {
                code: "CREPE-NETFLOW-RESTART",
                message: "exporter uptime moved backwards; templates reset".into(),
            });
        }
        if session.next.is_some_and(|n| n != sequence) {
            batch.notices.push(Notice {
                code: "CREPE-NETFLOW-SEQUENCE",
                message: format!(
                    "expected sequence {:?}, received {sequence}; loss, reorder or restart",
                    session.next
                ),
            });
        }
        session.seen = now;
        session.uptime = uptime;
        let mut records = 0u32;
        let mut known = true;
        if version == 5 {
            if u32be(&packet[12..]) >= 1_000_000_000 {
                return Err(err("invalid v5 nanoseconds"));
            }
            let count = usize::from(u16be(&packet[2..]));
            if count > 30 || packet.len() != 24 + 48 * count {
                return Err(err("invalid v5 count/length"));
            }
            for b in packet[24..].as_chunks::<48>().0.iter() {
                let mut flow = empty(peer, domain, version, sequence, export_time);
                flow.src_ip = Some(Ipv4Addr::from(<[u8; 4]>::try_from(&b[..4]).unwrap()).into());
                flow.dst_ip = Some(Ipv4Addr::from(<[u8; 4]>::try_from(&b[4..8]).unwrap()).into());
                flow.src_port = Some(u16be(&b[32..]));
                flow.dst_port = Some(u16be(&b[34..]));
                flow.protocol = Some(b[38]);
                flow.tcp_flags = Some(u16::from(b[37]));
                flow.packets = Some(u64::from(u32be(&b[16..])));
                flow.bytes = Some(u64::from(u32be(&b[20..])));
                let base =
                    u64::from(export_time) * 1000 + u64::from(u32be(&packet[12..16])) / 1_000_000;
                // v5 sequence is at offset 16; nanoseconds at 12.
                flow.sequence = u32be(&packet[16..]);
                flow.start_ms =
                    base.checked_sub(u64::from(uptime.unwrap().wrapping_sub(u32be(&b[24..]))));
                flow.end_ms =
                    base.checked_sub(u64::from(uptime.unwrap().wrapping_sub(u32be(&b[28..]))));
                let sample = u16be(&packet[22..]);
                flow.sampling_interval =
                    (sample & 0x3fff != 0).then_some(u64::from(sample & 0x3fff));
                batch.flows.push(flow);
            }
            records = count as u32;
        } else {
            let mut c = Cursor {
                b: &packet[header..],
                p: 0,
            };
            while c.left() != 0 {
                if c.left() < 4 {
                    return Err(err("short set header"));
                }
                let id = c.short()?;
                let length = usize::from(c.short()?);
                if length < 4 {
                    return Err(err("invalid set length"));
                }
                let data = c.take(length - 4)?;
                let template_id = if version == 9 { 0 } else { 2 };
                let options_id = if version == 9 { 1 } else { 3 };
                if id == template_id || id == options_id {
                    self.templates(key, data, id == options_id, now)?;
                } else if id >= 256 {
                    let Some(template) = self.templates.get(&(key, id)).cloned() else {
                        known = false;
                        batch.notices.push(Notice {
                            code: "CREPE-NETFLOW-TEMPLATE",
                            message: format!("unknown/expired template {id}; set skipped"),
                        });
                        continue;
                    };
                    let mut d = Cursor { b: data, p: 0 };
                    let minimum: usize = template
                        .fields
                        .iter()
                        .map(|f| {
                            if f.length == 65535 {
                                1
                            } else {
                                usize::from(f.length)
                            }
                        })
                        .sum();
                    while d.left() >= minimum {
                        if records >= 4096 {
                            return Err(err("data record work limit"));
                        }
                        let mut fields = Vec::with_capacity(template.fields.len());
                        for f in &template.fields {
                            let mut n = usize::from(f.length);
                            if n == 65535 {
                                n = usize::from(d.take(1)?[0]);
                                if n == 255 {
                                    n = usize::from(d.short()?);
                                }
                            }
                            let value = d.take(n)?.to_vec();
                            fields.push(FieldValue {
                                enterprise: f.enterprise,
                                id: f.id,
                                value,
                                scope: f.scope,
                            });
                        }
                        records += 1;
                        if template.options {
                            batch.options.push(fields);
                        } else {
                            batch.flows.push(normalize(
                                peer,
                                domain,
                                version,
                                sequence,
                                export_time,
                                uptime,
                                fields,
                            )?);
                        }
                    }
                    if d.left() > 3 || d.take(d.left())?.iter().any(|b| *b != 0) {
                        return Err(err("invalid data set padding"));
                    }
                } else {
                    return Err(err("reserved set identifier"));
                }
            }
        }
        let seq = if version == 5 {
            u32be(&packet[16..])
        } else {
            sequence
        };
        self.sessions.get_mut(&key).unwrap().next =
            known.then(|| seq.wrapping_add(if version == 9 { 1 } else { records }));
        Ok(batch)
    }
    fn templates(&mut self, key: SessionKey, data: &[u8], options: bool, now: u64) -> Result<()> {
        let mut c = Cursor { b: data, p: 0 };
        while c.left() >= 4 {
            let id = c.short()?;
            let count = c.short()?;
            if id < 256 {
                return Err(err("invalid template id / UDP withdrawal unsupported"));
            }
            if count == 0 {
                return Err(err("template withdrawal is not allowed over UDP"));
            }
            let (count, scope) = if options {
                if key.2 == 9 {
                    let option_bytes = usize::from(c.short()?);
                    if count % 4 != 0 || option_bytes % 4 != 0 {
                        return Err(err("invalid v9 options lengths"));
                    }
                    (
                        (usize::from(count) + option_bytes) / 4,
                        usize::from(count) / 4,
                    )
                } else {
                    (usize::from(count), usize::from(c.short()?))
                }
            } else {
                (usize::from(count), 0)
            };
            if count == 0 || count > 128 || scope > count || (options && scope == 0) {
                return Err(err("template field/scope limit"));
            }
            let mut fields = Vec::with_capacity(count);
            for index in 0..count {
                let raw = c.short()?;
                let length = c.short()?;
                if length == 0 || key.2 == 9 && length == 65535 {
                    return Err(err("invalid template field length"));
                }
                let enterprise = if key.2 == 10 && raw & 0x8000 != 0 {
                    u32be(c.take(4)?)
                } else {
                    0
                };
                fields.push(Field {
                    id: if key.2 == 10 { raw & 0x7fff } else { raw },
                    length,
                    enterprise,
                    scope: index < scope,
                });
            }
            if !self.templates.contains_key(&(key, id))
                && self.templates.len() >= self.limits.templates
            {
                return Err(err("template capacity exceeded"));
            }
            self.templates.insert(
                (key, id),
                Template {
                    fields,
                    options,
                    seen: now,
                },
            );
        }
        if c.take(c.left())?.iter().any(|b| *b != 0) {
            return Err(err("invalid template padding"));
        }
        Ok(())
    }
}
fn empty(exporter: SocketAddr, domain: u32, version: u16, sequence: u32, export_time: u32) -> Flow {
    Flow {
        exporter,
        domain,
        version,
        sequence,
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        protocol: None,
        packets: None,
        bytes: None,
        tcp_flags: None,
        start_ms: None,
        end_ms: None,
        export_time,
        sampling_interval: None,
        fields: vec![],
    }
}
fn normalize(
    peer: SocketAddr,
    domain: u32,
    version: u16,
    sequence: u32,
    time: u32,
    uptime: Option<u32>,
    fields: Vec<FieldValue>,
) -> Result<Flow> {
    let mut out = empty(peer, domain, version, sequence, time);
    for f in &fields {
        if f.enterprise != 0 {
            continue;
        }
        let b = &f.value;
        let n = uint(b);
        match f.id {
            8 | 12 if b.len() == 4 => {
                let ip = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.as_slice()).unwrap()));
                if f.id == 8 {
                    out.src_ip = Some(ip)
                } else {
                    out.dst_ip = Some(ip)
                }
            }
            27 | 28 if b.len() == 16 => {
                let ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.as_slice()).unwrap()));
                if f.id == 27 {
                    out.src_ip = Some(ip)
                } else {
                    out.dst_ip = Some(ip)
                }
            }
            7 => out.src_port = n.and_then(|n| n.try_into().ok()),
            11 => out.dst_port = n.and_then(|n| n.try_into().ok()),
            4 => out.protocol = n.and_then(|n| n.try_into().ok()),
            1 => out.bytes = n,
            2 => out.packets = n,
            6 => out.tcp_flags = n.and_then(|n| n.try_into().ok()),
            34 => out.sampling_interval = n,
            152 => out.start_ms = n,
            153 => out.end_ms = n,
            150 => out.start_ms = n.and_then(|n| n.checked_mul(1000)),
            151 => out.end_ms = n.and_then(|n| n.checked_mul(1000)),
            21 | 22 => {
                if let (Some(up), Some(n)) = (uptime, n.and_then(|n| u32::try_from(n).ok())) {
                    let t = (u64::from(time) * 1000).checked_sub(u64::from(up.wrapping_sub(n)));
                    if f.id == 22 {
                        out.start_ms = t
                    } else {
                        out.end_ms = t
                    }
                }
            }
            _ => {}
        }
    }
    out.fields = fields;
    Ok(out)
}
