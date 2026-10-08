//! Bounded bidirectional packet-to-flow accounting, not TCP stream reassembly.
use crepe_core::{Endpoint, Error, EventType, PacketEvent, Protocol, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowKey {
    pub a: Endpoint,
    pub b: Endpoint,
    pub proto: Protocol,
    pub section: u32,
    pub interface: u32,
    pub vlans: Vec<u16>,
}
impl FlowKey {
    pub fn from_packet(p: &PacketEvent) -> (Self, bool) {
        let forward = p.src <= p.dst;
        let (a, b) = if forward {
            (p.src.clone(), p.dst.clone())
        } else {
            (p.dst.clone(), p.src.clone())
        };
        (
            Self {
                a,
                b,
                proto: p.proto,
                section: p.header.section,
                interface: p.header.interface,
                vlans: p.vlans.clone(),
            },
            forward,
        )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Eof,
    IdleTimeout,
    ActiveTimeout,
    Capacity,
    TcpFin,
    TcpReset,
}
/// Passive observations, not validation of endpoint TCP state or ACK numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    SynSeen,
    Established,
    Midstream,
    HalfClosed,
    Closed,
    Reset,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub schema_version: u16,
    pub event_type: EventType,
    pub flow_id: String,
    /// Capture record anchoring this observed instance; zero means legacy/unknown.
    #[serde(default)]
    pub first_sequence: u64,
    pub a: Endpoint,
    pub b: Endpoint,
    pub proto: Protocol,
    pub section: u32,
    pub interface: u32,
    pub vlans: Vec<u16>,
    pub start_ns: String,
    pub end_ns: String,
    pub packets_a: u64,
    pub packets_b: u64,
    pub bytes_a: u64,
    pub bytes_b: u64,
    pub tcp_flags_a: u8,
    pub tcp_flags_b: u8,
    pub end_reason: EndReason,
    pub tcp_state: Option<TcpState>,
}
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub max_flows: usize,
    pub tcp_idle_secs: u64,
    pub udp_idle_secs: u64,
    pub active_secs: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_flows: 65536,
            tcp_idle_secs: 120,
            udp_idle_secs: 30,
            active_secs: 300,
        }
    }
}
struct State {
    record: FlowRecord,
    start: i128,
    end: i128,
    deadline: i128,
    reason: EndReason,
}
pub struct FlowTable {
    config: Config,
    flows: BTreeMap<FlowKey, State>,
    deadlines: BTreeSet<(i128, FlowKey)>,
    watermark: Option<i128>,
    next_id: u64,
    last_assignment: Option<u64>,
    pub skipped_fragments: u64,
    pub skipped_other_protocols: u64,
}
fn error(message: &str) -> Error {
    Error::new("CREPE-FLOW-001", message)
}
impl FlowTable {
    pub fn new(config: Config) -> Result<Self> {
        if config.max_flows == 0
            || config.max_flows > 1_000_000
            || config.tcp_idle_secs == 0
            || config.udp_idle_secs == 0
            || config.active_secs == 0
        {
            return Err(error(
                "max-flows must be 1..1000000 and timeouts must be positive",
            ));
        }
        Ok(Self {
            config,
            flows: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            watermark: None,
            next_id: 1,
            last_assignment: None,
            skipped_fragments: 0,
            skipped_other_protocols: 0,
        })
    }
    /// Instance anchor assigned by the most recent push, including a closing packet.
    pub fn last_assignment(&self) -> Option<u64> {
        self.last_assignment
    }
    pub fn len(&self) -> usize {
        self.flows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
    fn remove(&mut self, key: &FlowKey, reason: EndReason) -> FlowRecord {
        let state = self.flows.remove(key).expect("indexed flow must exist");
        self.deadlines.remove(&(state.deadline, key.clone()));
        let mut record = state.record;
        record.end_reason = reason;
        record
    }
    fn expire(&mut self, now: i128, emit: &mut impl FnMut(FlowRecord) -> Result<()>) -> Result<()> {
        while let Some((deadline, key)) = self.deadlines.first().cloned() {
            if deadline > now {
                break;
            }
            let reason = self.flows[&key].reason;
            emit(self.remove(&key, reason))?;
        }
        Ok(())
    }
    pub fn push(
        &mut self,
        p: &PacketEvent,
        mut emit: impl FnMut(FlowRecord) -> Result<()>,
    ) -> Result<()> {
        self.last_assignment = None;
        let now = p
            .header
            .timestamp_ns
            .as_ref()
            .and_then(|s| s.parse::<i128>().ok())
            .ok_or_else(|| error("flow accounting requires capture timestamps"))?;
        // Reserve room for timeout arithmetic even for caller-constructed events.
        if now.abs_diff(0) > (i128::MAX as u128 / 2) {
            return Err(error("timestamp outside supported range"));
        }
        let watermark = self.watermark.map_or(now, |t| t.max(now));
        self.watermark = Some(watermark);
        self.expire(watermark, &mut emit)?;
        if p.fragmented {
            self.skipped_fragments += 1;
            return Ok(());
        }
        if !matches!(p.proto, Protocol::Tcp | Protocol::Udp) {
            self.skipped_other_protocols += 1;
            return Ok(());
        }
        if p.src.port.is_none() || p.dst.port.is_none() {
            return Err(error("TCP/UDP flow packet requires ports"));
        }
        let (key, forward) = FlowKey::from_packet(p);
        if !self.flows.contains_key(&key) {
            if self.flows.len() == self.config.max_flows {
                let (_, victim) = self.deadlines.first().unwrap().clone();
                emit(self.remove(&victim, EndReason::Capacity))?;
            }
            let id = self.next_id;
            self.next_id = self
                .next_id
                .checked_add(1)
                .ok_or_else(|| error("flow ID space exhausted"))?;
            self.flows.insert(
                key.clone(),
                State {
                    start: now,
                    end: now,
                    deadline: now,
                    reason: EndReason::Eof,
                    record: FlowRecord {
                        schema_version: 3,
                        event_type: EventType::FlowEnd,
                        flow_id: format!("CX-{id:016x}"),
                        first_sequence: p.header.sequence,
                        a: key.a.clone(),
                        b: key.b.clone(),
                        proto: key.proto,
                        section: key.section,
                        interface: key.interface,
                        vlans: key.vlans.clone(),
                        start_ns: now.to_string(),
                        end_ns: now.to_string(),
                        packets_a: 0,
                        packets_b: 0,
                        bytes_a: 0,
                        bytes_b: 0,
                        tcp_flags_a: 0,
                        tcp_flags_b: 0,
                        end_reason: EndReason::Eof,
                        tcp_state: None,
                    },
                },
            );
        }
        let state = self.flows.get_mut(&key).unwrap();
        self.last_assignment = Some(state.record.first_sequence);
        self.deadlines.remove(&(state.deadline, key.clone()));
        state.start = state.start.min(now);
        state.end = state.end.max(now);
        state.record.start_ns = state.start.to_string();
        state.record.end_ns = state.end.to_string();
        let (packets, bytes, flags) = if forward {
            (
                &mut state.record.packets_a,
                &mut state.record.bytes_a,
                &mut state.record.tcp_flags_a,
            )
        } else {
            (
                &mut state.record.packets_b,
                &mut state.record.bytes_b,
                &mut state.record.tcp_flags_b,
            )
        };
        *packets = packets
            .checked_add(1)
            .ok_or_else(|| error("packet counter overflow"))?;
        *bytes = bytes
            .checked_add(u64::from(p.header.original_len))
            .ok_or_else(|| error("byte counter overflow"))?;
        *flags |= p.tcp_flags.unwrap_or(0);
        if p.proto == Protocol::Tcp {
            let a = state.record.tcp_flags_a;
            let b = state.record.tcp_flags_b;
            state.record.tcp_state = Some(if (a | b) & 4 != 0 {
                TcpState::Reset
            } else if a & 1 != 0 && b & 1 != 0 {
                TcpState::Closed
            } else if (a | b) & 1 != 0 {
                TcpState::HalfClosed
            } else if a & 2 != 0 && b & 2 != 0 && (a | b) & 16 != 0 {
                TcpState::Established
            } else if (a | b) & 2 != 0 {
                TcpState::SynSeen
            } else {
                TcpState::Midstream
            });
        }
        let idle = if p.proto == Protocol::Tcp {
            self.config.tcp_idle_secs
        } else {
            self.config.udp_idle_secs
        };
        let idle_deadline = state.end + i128::from(idle) * 1_000_000_000;
        let active_deadline = state.start + i128::from(self.config.active_secs) * 1_000_000_000;
        (state.deadline, state.reason) = if active_deadline <= idle_deadline {
            (active_deadline, EndReason::ActiveTimeout)
        } else {
            (idle_deadline, EndReason::IdleTimeout)
        };
        self.deadlines.insert((state.deadline, key.clone()));
        let reason = if p.proto == Protocol::Tcp && p.tcp_flags.unwrap_or(0) & 4 != 0 {
            Some(EndReason::TcpReset)
        } else if state.record.tcp_flags_a & 1 != 0 && state.record.tcp_flags_b & 1 != 0 {
            Some(EndReason::TcpFin)
        } else {
            None
        };
        if let Some(reason) = reason {
            emit(self.remove(&key, reason))?;
        }
        self.expire(watermark, &mut emit)
    }
    pub fn advance(
        &mut self,
        now: i128,
        mut emit: impl FnMut(FlowRecord) -> Result<()>,
    ) -> Result<()> {
        let now = self.watermark.map_or(now, |old| old.max(now));
        self.watermark = Some(now);
        self.expire(now, &mut emit)
    }
    pub fn finish(&mut self, mut emit: impl FnMut(FlowRecord) -> Result<()>) -> Result<()> {
        while let Some(key) = self.flows.keys().next().cloned() {
            emit(self.remove(&key, EndReason::Eof))?;
        }
        Ok(())
    }
}
