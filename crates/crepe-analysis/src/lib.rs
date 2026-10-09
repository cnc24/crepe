//! Bounded application analysis over reconstructed IP and TCP streams.
mod processor;
use crepe_core::{Error, PacketEvent, PacketEvidence, Protocol, Result};
use crepe_dns::Message;
use crepe_flow::FlowKey;
use crepe_packet::PacketView;
pub use crepe_protocol::Enabled as ProtocolModules;
use crepe_stream::{Limits, Stream};
pub use processor::Processor;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[serde(rename = "dns.query")]
    DnsQuery,
    #[serde(rename = "dns.response")]
    DnsResponse,
    Protocol,
    Anomaly,
}
#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub code: &'static str,
    pub message: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub evidence: PacketEvidence,
    pub schema_version: u16,
    pub event_type: Kind,
    pub packet: PacketEvent,
    pub dns: Option<Message>,
    pub protocol: Option<crepe_protocol::Event>,
    pub anomaly: Option<Anomaly>,
    pub midstream: bool,
    pub reassembled: bool,
}
#[derive(Debug, Clone)]
pub struct Config {
    pub dns: bool,
    pub files: bool,
    pub protocols: ProtocolModules,
    pub dns_ports: Vec<u16>,
    pub max_streams: usize,
    pub max_buffer_bytes: usize,
    pub idle_secs: u64,
    pub stream: Limits,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            dns_ports: vec![53],
            dns: true,
            files: true,
            protocols: Default::default(),
            max_streams: 1024,
            max_buffer_bytes: 4 * 1024 * 1024,
            idle_secs: 120,
            stream: Limits::default(),
        }
    }
}
#[derive(Debug)]
struct State {
    evidence: PacketEvidence,
    stream: Stream,
    framing: Vec<u8>,
    packet: PacketEvent,
    timestamp: i128,
    syn: Option<u32>,
    midstream: bool,
    done: bool,
    file: crepe_files::HttpFile,
    request_method: Option<String>,
}
impl State {
    fn size(&self) -> usize {
        self.stream.buffered_bytes()
            + self.framing.capacity()
            + self.file.buffered_bytes()
            + self.evidence.memory_bytes()
    }
}
type Key = (FlowKey, bool);
pub struct Analyzer {
    config: Config,
    streams: BTreeMap<Key, State>,
    deadlines: BTreeSet<(i128, Key)>,
    bytes: usize,
    watermark: Option<i128>,
    pub skipped_fragments: u64,
}
impl Analyzer {
    pub fn new(config: Config) -> Result<Self> {
        if config.dns_ports.is_empty()
            || config.dns_ports.len() > 32
            || config.max_streams == 0
            || config.max_streams > 65536
            || config.max_buffer_bytes == 0
            || config.max_buffer_bytes > 256 * 1024 * 1024
            || config.idle_secs == 0
        {
            return Err(Error::new("CREPE-ANA-001", "invalid analyzer limits"));
        }
        Stream::new(0, config.stream)?;
        Ok(Self {
            config,
            streams: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            bytes: 0,
            watermark: None,
            skipped_fragments: 0,
        })
    }
    pub fn advance(&mut self, now: i128, mut emit: impl FnMut(Event) -> Result<()>) -> Result<()> {
        let now = self.watermark.map_or(now, |old| old.max(now));
        self.watermark = Some(now);
        self.expire(now, &mut emit)
    }
    pub fn buffered_bytes(&self) -> usize {
        self.bytes
    }
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
    fn remove(&mut self, key: &Key) -> Option<State> {
        let state = self.streams.remove(key)?;
        self.bytes -= state.size();
        self.deadlines.remove(&(state.timestamp, key.clone()));
        Some(state)
    }
    fn incomplete(state: &State) -> bool {
        state.stream.pending_bytes() != 0 || !state.framing.is_empty() || state.file.incomplete()
    }
    fn anomaly(
        packet: &PacketEvent,
        midstream: bool,
        code: &'static str,
        message: impl Into<String>,
    ) -> Event {
        let mut evidence = PacketEvidence::packet(&packet.header);
        evidence.complete = false;
        evidence.scope = "anomaly anchor; complete reassembly is not established".into();
        Event {
            evidence,
            schema_version: 2,
            event_type: Kind::Anomaly,
            packet: packet.clone(),
            dns: None,
            protocol: None,
            anomaly: Some(Anomaly {
                code,
                message: message.into(),
            }),
            midstream,
            reassembled: false,
        }
    }
    fn dns(packet: &PacketEvent, bytes: &[u8], midstream: bool) -> Event {
        match crepe_dns::parse(bytes) {
            Ok(dns) => Event {
                evidence: PacketEvidence::packet(&packet.header),
                schema_version: 2,
                event_type: if dns.response {
                    Kind::DnsResponse
                } else {
                    Kind::DnsQuery
                },
                packet: packet.clone(),
                dns: Some(dns),
                protocol: None,
                anomaly: None,
                midstream,
                reassembled: false,
            },
            Err(e) => Self::anomaly(packet, midstream, e.code, e.message),
        }
    }
    fn expire(&mut self, now: i128, emit: &mut impl FnMut(Event) -> Result<()>) -> Result<()> {
        while let Some((time, key)) = self.deadlines.first().cloned() {
            if now - time < i128::from(self.config.idle_secs) * 1_000_000_000 {
                break;
            }
            let state = self.remove(&key).unwrap();
            if Self::incomplete(&state) {
                emit(Self::anomaly(
                    &state.packet,
                    state.midstream,
                    "CREPE-TCP-002",
                    "incomplete TCP application stream at idle timeout",
                ))?;
            }
        }
        Ok(())
    }
    pub fn process(
        &mut self,
        view: &PacketView<'_>,
        emit: impl FnMut(Event) -> Result<()>,
    ) -> Result<()> {
        self.process_referenced(view, PacketEvidence::packet(&view.event.header), emit)
    }
    pub fn process_referenced(
        &mut self,
        view: &PacketView<'_>,
        evidence: PacketEvidence,
        mut emit: impl FnMut(Event) -> Result<()>,
    ) -> Result<()> {
        let p = &view.event;
        let time = p
            .header
            .timestamp_ns
            .as_deref()
            .and_then(|t| t.parse::<i128>().ok())
            .filter(|t| t.abs_diff(0) <= i128::MAX as u128 / 4);
        if let Some(now) = time {
            let now = self.watermark.map_or(now, |old| old.max(now));
            self.watermark = Some(now);
            self.expire(now, &mut emit)?;
        }
        if p.fragmented {
            self.skipped_fragments += 1;
            return Ok(());
        }
        let dns_candidate = [p.src.port, p.dst.port]
            .iter()
            .flatten()
            .any(|port| self.config.dns_ports.contains(port));
        if dns_candidate && !self.config.dns {
            return Ok(());
        }
        if p.proto == Protocol::Udp {
            if dns_candidate {
                let mut event = Self::dns(p, view.payload, false);
                event.evidence = evidence;
                emit(event)?;
            }
            return Ok(());
        }
        if p.proto != Protocol::Tcp {
            return Ok(());
        }
        let Some(time) = time else {
            return emit(Self::anomaly(
                p,
                false,
                "CREPE-ANA-001",
                "TCP analysis requires a valid capture timestamp",
            ));
        };
        let Some(sequence) = view.tcp_sequence else {
            return emit(Self::anomaly(
                p,
                false,
                "CREPE-TCP-001",
                "missing TCP sequence",
            ));
        };
        let key = FlowKey::from_packet(p);
        let flags = p.tcp_flags.unwrap_or(0);
        let syn = flags & 2 != 0;
        let fin = flags & 1 != 0;
        if flags & 4 != 0 {
            for direction in [true, false] {
                if let Some(state) = self.remove(&(key.0.clone(), direction)) {
                    if Self::incomplete(&state) {
                        emit(Self::anomaly(
                            p,
                            state.midstream,
                            "CREPE-TCP-002",
                            "incomplete TCP application stream at RST",
                        ))?;
                    }
                }
            }
            return Ok(());
        }
        // Pure ACKs do not carry stream bytes (including the ACK after FIN).
        if !syn && !fin && view.payload.is_empty() {
            return Ok(());
        }
        if syn
            && self
                .streams
                .get(&key)
                .is_some_and(|state| state.syn != Some(sequence))
        {
            let state = self.remove(&key).unwrap();
            emit(Self::anomaly(
                p,
                state.midstream,
                "CREPE-TCP-002",
                "new SYN resets an existing directional stream",
            ))?;
            if flags & 16 == 0 {
                self.remove(&(key.0.clone(), !key.1));
            }
        }
        if !self.streams.contains_key(&key) && !syn && view.payload.is_empty() {
            return Ok(());
        }
        let mut state = if let Some(state) = self.remove(&key) {
            state
        } else {
            if self.streams.len() == self.config.max_streams {
                let (_, oldest) = self.deadlines.first().unwrap().clone();
                let victim = self.remove(&oldest).unwrap();
                emit(Self::anomaly(
                    &victim.packet,
                    victim.midstream,
                    "CREPE-ANA-002",
                    "stream capacity eviction",
                ))?;
            }
            State {
                evidence: evidence.clone(),
                stream: Stream::new(sequence.wrapping_add(u32::from(syn)), self.config.stream)?,
                framing: Vec::new(),
                packet: p.clone(),
                timestamp: time,
                syn: syn.then_some(sequence),
                midstream: !syn,
                done: false,
                file: Default::default(),
                request_method: None,
            }
        };
        state.evidence.merge(&evidence);
        state.timestamp = state.timestamp.max(time);
        state.packet = p.clone();
        let contiguous =
            match state
                .stream
                .push(sequence.wrapping_add(u32::from(syn)), view.payload, fin)
            {
                Ok(data) => data,
                Err(e) => return emit(Self::anomaly(p, state.midstream, e.code, e.message)),
            };
        if !dns_candidate && self.config.files {
            let opposite = self.streams.get(&(key.0.clone(), !key.1));
            let method = opposite.and_then(|state| state.request_method.as_deref());
            let mut file_evidence = state.evidence.clone();
            if let Some(opposite) = opposite.filter(|s| s.request_method.is_some()) {
                file_evidence.merge(&opposite.evidence);
            }
            state
                .file
                .allow_response(method.is_some_and(|m| m != "HEAD" && m != "CONNECT"));
            match state.file.push(&contiguous) {
                Ok(Some(file)) => emit(Event {
                    evidence: file_evidence,
                    schema_version: 2,
                    event_type: Kind::Protocol,
                    packet: p.clone(),
                    dns: None,
                    protocol: Some(crepe_protocol::Event::FileMetadata {
                        size: file.size,
                        sha256: file.sha256,
                        mime: file.mime,
                    }),
                    anomaly: None,
                    midstream: state.midstream,
                    reassembled: false,
                })?,
                Ok(None) => {}
                Err(error) => emit(Self::anomaly(p, state.midstream, error.code, error.message))?,
            }
        }
        if state.done {
            if self.bytes + state.size() > self.config.max_buffer_bytes {
                return emit(Self::anomaly(
                    p,
                    state.midstream,
                    "CREPE-ANA-002",
                    "stream tracking memory budget exceeded",
                ));
            }
            self.bytes += state.size();
            self.deadlines.insert((state.timestamp, key.clone()));
            self.streams.insert(key, state);
            return Ok(());
        }
        if state.framing.len() + contiguous.len() > 131072
            || self.bytes + state.size() + contiguous.len() > self.config.max_buffer_bytes
        {
            return emit(Self::anomaly(
                p,
                state.midstream,
                "CREPE-ANA-002",
                "analysis buffer budget exceeded; stream discarded",
            ));
        }
        state.framing.extend_from_slice(&contiguous);
        state.framing.shrink_to_fit();
        if self.bytes + state.size() > self.config.max_buffer_bytes {
            return emit(Self::anomaly(
                p,
                state.midstream,
                "CREPE-ANA-002",
                "analysis buffer allocation exceeds budget; stream discarded",
            ));
        }
        if !dns_candidate {
            match crepe_protocol::inspect_enabled(&state.framing, self.config.protocols) {
                Ok(crepe_protocol::Inspection::Event(protocol)) => {
                    if let crepe_protocol::Event::HttpRequest { method, .. } = &protocol {
                        state.request_method = Some(method.clone());
                    }
                    emit(Event {
                        evidence: state.evidence.clone(),
                        schema_version: 2,
                        event_type: Kind::Protocol,
                        packet: p.clone(),
                        dns: None,
                        protocol: Some(protocol),
                        anomaly: None,
                        midstream: state.midstream,
                        reassembled: false,
                    })?;
                    state.done = true;
                    state.framing.clear();
                    state.framing.shrink_to_fit();
                }
                Ok(crepe_protocol::Inspection::Ignore) => {
                    state.done = true;
                    state.framing.clear();
                    state.framing.shrink_to_fit();
                }
                Ok(crepe_protocol::Inspection::More) => {
                    if state.stream.is_closed() {
                        if !state.framing.is_empty() || state.stream.pending_bytes() != 0 {
                            emit(Self::anomaly(
                                p,
                                state.midstream,
                                "CREPE-TCP-002",
                                "incomplete or unrecognized application at FIN",
                            ))?;
                        }
                        state.framing.clear();
                        state.framing.shrink_to_fit();
                        state.done = true;
                    }
                }
                Err(e) => return emit(Self::anomaly(p, state.midstream, e.code, e.message)),
            }
            self.bytes += state.size();
            self.deadlines.insert((state.timestamp, key.clone()));
            self.streams.insert(key, state);
            return Ok(());
        }
        let mut consumed = 0;
        let mut messages = 0;
        while state.framing.len() - consumed >= 2 {
            let size = usize::from(u16::from_be_bytes([
                state.framing[consumed],
                state.framing[consumed + 1],
            ]));
            if size < 12 {
                return emit(Self::anomaly(
                    p,
                    state.midstream,
                    "CREPE-DNS-001",
                    "invalid DNS-over-TCP message length; stream discarded",
                ));
            }
            if state.framing.len() - consumed < size + 2 {
                break;
            }
            messages += 1;
            if messages > 128 {
                return emit(Self::anomaly(
                    p,
                    state.midstream,
                    "CREPE-ANA-002",
                    "DNS messages-per-packet work limit exceeded",
                ));
            }
            let mut event = Self::dns(
                p,
                &state.framing[consumed + 2..consumed + 2 + size],
                state.midstream,
            );
            event.evidence = state.evidence.clone();
            emit(event)?;
            consumed += size + 2;
        }
        state.framing.drain(..consumed);
        state.framing.shrink_to_fit();
        if state.stream.is_closed() && Self::incomplete(&state) {
            return emit(Self::anomaly(
                p,
                state.midstream,
                "CREPE-TCP-002",
                "incomplete DNS message at FIN",
            ));
        }
        self.bytes += state.size();
        self.deadlines.insert((state.timestamp, key.clone()));
        self.streams.insert(key, state);
        Ok(())
    }
    pub fn finish(&mut self, mut emit: impl FnMut(Event) -> Result<()>) -> Result<()> {
        while let Some(key) = self.streams.keys().next().cloned() {
            let state = self.remove(&key).unwrap();
            if Self::incomplete(&state) {
                emit(Self::anomaly(
                    &state.packet,
                    state.midstream,
                    "CREPE-TCP-002",
                    "incomplete TCP application stream at end of input",
                ))?;
            }
        }
        Ok(())
    }
}
