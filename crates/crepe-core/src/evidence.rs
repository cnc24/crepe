//! Capture-local provenance. References never imply that raw bytes are retained.
use crate::EventHeader;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PacketRef {
    pub sequence: u64,
    pub section: u32,
    pub interface: u32,
}
impl From<&EventHeader> for PacketRef {
    fn from(h: &EventHeader) -> Self {
        Self {
            sequence: h.sequence,
            section: h.section,
            interface: h.interface,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvidence {
    pub records: Vec<PacketRef>,
    pub complete: bool,
    pub scope: String,
}
impl PacketEvidence {
    pub fn packet(header: &EventHeader) -> Self {
        Self {
            records: vec![header.into()],
            complete: true,
            scope: "observed input packets; may include retransmissions and stream context".into(),
        }
    }
    /// At most 4096 references per analysis state. Overflow is explicit, never guessed.
    pub fn merge(&mut self, other: &Self) {
        self.complete &= other.complete;
        for reference in &other.records {
            match self.records.binary_search(reference) {
                Ok(_) => {}
                Err(at) if self.records.len() < 4096 => self.records.insert(at, *reference),
                Err(_) => self.complete = false,
            }
        }
    }
    pub fn memory_bytes(&self) -> usize {
        self.records.capacity() * std::mem::size_of::<PacketRef>() + self.scope.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overflow_is_explicit_and_duplicates_do_not_consume_budget() {
        let mut e = PacketEvidence {
            records: vec![],
            complete: true,
            scope: String::new(),
        };
        for sequence in 1..=4097 {
            let p = PacketEvidence {
                records: vec![PacketRef {
                    sequence,
                    section: 0,
                    interface: 0,
                }],
                complete: true,
                scope: String::new(),
            };
            e.merge(&p);
            e.merge(&p);
        }
        assert_eq!(e.records.len(), 4096);
        assert!(!e.complete);
    }
}
