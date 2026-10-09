//! Bounded packet-to-instance evidence. Never guess when an anchor has expired.
use crepe_core::PacketEvent;
use crepe_storage::{identity, Row};
use std::collections::BTreeMap;
#[derive(Default)]
pub(super) struct Index {
    anchors: BTreeMap<(u32, u32, u64), u64>,
}
pub(super) fn instance(conversation: &str, first_sequence: u64) -> String {
    if first_sequence == 0 {
        String::new()
    } else {
        identity(&[
            "connection-instance-v2",
            conversation,
            &first_sequence.to_string(),
        ])
    }
}
impl Index {
    pub fn record(&mut self, p: &PacketEvent, anchor: Option<u64>) {
        let key = (p.header.section, p.header.interface, p.header.sequence);
        if let Some(anchor) = anchor {
            self.anchors.insert(key, anchor);
            while self.anchors.len() > 65536 {
                self.anchors.pop_first();
            }
        }
    }
    pub fn apply_evidence(&self, evidence: &crepe_core::PacketEvidence, row: &mut Row) {
        let anchors: std::collections::BTreeSet<_> = evidence
            .records
            .iter()
            .filter_map(|r| self.anchors.get(&(r.section, r.interface, r.sequence)))
            .collect();
        if anchors.len() == 1 {
            row.flow_id = instance(&row.conversation_id, **anchors.first().unwrap());
            row.identity_status = "instance".into();
        }
    }
    pub fn apply(&self, p: &PacketEvent, row: &mut Row) {
        if let Some(anchor) =
            self.anchors
                .get(&(p.header.section, p.header.interface, p.header.sequence))
        {
            row.flow_id = instance(&row.conversation_id, *anchor);
            row.identity_status = "instance".into();
        }
    }
}
