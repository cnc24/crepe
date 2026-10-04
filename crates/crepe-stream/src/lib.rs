//! Bounded, directional TCP byte reassembly. The caller owns connection lifetimes.
use crepe_core::{Error, Result};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub queued_bytes: usize,
    pub history_bytes: usize,
    pub max_gap: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queued_bytes: 65536,
            history_bytes: 4096,
            max_gap: 1_048_576,
        }
    }
}
#[derive(Debug)]
pub struct Stream {
    limits: Limits,
    next_seq: u32,
    next_pos: u64,
    pending: BTreeMap<u64, u8>,
    history: VecDeque<u8>,
    fin_at: Option<u64>,
    closed: bool,
}
fn error(text: &str) -> Error {
    Error::new("CREPE-TCP-001", text)
}
impl Stream {
    /// `next_seq` is SYN sequence + 1, or the first observed data sequence for midstream input.
    pub fn new(next_seq: u32, limits: Limits) -> Result<Self> {
        if limits.queued_bytes == 0
            || limits.queued_bytes > 1_048_576
            || limits.history_bytes > 65536
            || limits.max_gap == 0
            || limits.max_gap > i32::MAX as u32
        {
            return Err(error("invalid TCP reassembly limits"));
        }
        Ok(Self {
            limits,
            next_seq,
            next_pos: 0,
            pending: BTreeMap::new(),
            history: VecDeque::new(),
            fin_at: None,
            closed: false,
        })
    }
    pub fn buffered_bytes(&self) -> usize {
        self.pending.len() + self.history.len()
    }
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    /// Sequence is the first payload byte (caller accounts for SYN). FIN follows payload.
    /// Errors make the stream unusable; caller must discard it and record the anomaly.
    pub fn push(&mut self, sequence: u32, payload: &[u8], fin: bool) -> Result<Vec<u8>> {
        if payload.len() > self.limits.queued_bytes {
            return Err(error("TCP segment exceeds buffer limit"));
        }
        let delta = sequence.wrapping_sub(self.next_seq) as i32;
        if delta.unsigned_abs() > self.limits.max_gap {
            return Err(error("TCP sequence outside reassembly window"));
        }
        let start = i128::from(self.next_pos) + i128::from(delta);
        let end = start + payload.len() as i128;
        if start < 0 {
            return Err(error("TCP segment precedes observed stream origin"));
        }
        let start = start as u64;
        let end = u64::try_from(end).map_err(|_| error("TCP stream offset overflow"))?;
        if let Some(end_of_stream) = self.fin_at {
            if end > end_of_stream || (fin && end != end_of_stream) {
                return Err(error("TCP data beyond FIN or conflicting FIN"));
            }
        }
        if fin {
            if end < self.next_pos
                || self
                    .pending
                    .last_key_value()
                    .is_some_and(|(p, _)| *p >= end)
            {
                return Err(error("FIN conflicts with observed TCP data"));
            }
            self.fin_at = Some(end);
        }
        for (offset, value) in payload.iter().enumerate() {
            let position = start + offset as u64;
            if position < self.next_pos {
                let history_start = self.next_pos - self.history.len() as u64;
                if position < history_start {
                    return Err(error("retransmission predates retained overlap history"));
                }
                if self.history[(position - history_start) as usize] != *value {
                    return Err(error("conflicting TCP retransmission"));
                }
            } else if let Some(old) = self.pending.get(&position) {
                if *old != *value {
                    return Err(error("conflicting TCP overlap"));
                }
            } else {
                if self.pending.len() == self.limits.queued_bytes {
                    return Err(error("TCP queued-byte limit exceeded"));
                }
                self.pending.insert(position, *value);
            }
        }
        let mut output = Vec::new();
        while let Some(value) = self.pending.remove(&self.next_pos) {
            output.push(value);
            self.history.push_back(value);
            if self.history.len() > self.limits.history_bytes {
                self.history.pop_front();
            }
            self.next_pos += 1;
            self.next_seq = self.next_seq.wrapping_add(1);
        }
        self.closed = self.fin_at == Some(self.next_pos);
        Ok(output)
    }
}
