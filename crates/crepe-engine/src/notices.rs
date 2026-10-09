//! Central notice suppression across built-in policies and plugins.
use crepe_storage::{identity, Row};
use std::{collections::BTreeMap, time::Instant};
pub(super) struct Gate {
    seen: BTreeMap<String, Instant>,
    window: Instant,
    count: usize,
    pub suppressed: u64,
}
impl Default for Gate {
    fn default() -> Self {
        Self {
            seen: BTreeMap::new(),
            window: Instant::now(),
            count: 0,
            suppressed: 0,
        }
    }
}
impl Gate {
    pub fn allow(&mut self, row: &Row) -> bool {
        if !row.event_type.starts_with("notice.") {
            return true;
        }
        let now = Instant::now();
        if now.duration_since(self.window).as_secs() >= 1 {
            self.window = now;
            self.count = 0;
        }
        self.seen
            .retain(|_, at| now.duration_since(*at).as_secs() < 60);
        let mut payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap_or_default();
        if let Some(object) = payload.as_object_mut() {
            object.remove("source_event_id");
        }
        let key = identity(&[
            &row.sensor,
            &row.source,
            &row.flow_id,
            &row.event_type,
            &payload.to_string(),
        ]);
        if self.count >= 100 || self.seen.len() >= 4096 || self.seen.contains_key(&key) {
            self.suppressed = self.suppressed.saturating_add(1);
            return false;
        }
        self.count += 1;
        self.seen.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn central_gate_deduplicates_parents_and_bounds_bursts() {
        let mut gate = Gate::default();
        let mut row = Row {
            sensor: "s".into(),
            source: "c".into(),
            flow_id: "f".into(),
            event_type: "notice.policy".into(),
            payload: r#"{"message":"review","source_event_id":"one"}"#.into(),
            ..Default::default()
        };
        assert!(gate.allow(&row));
        row.payload = r#"{"message":"review","source_event_id":"two"}"#.into();
        assert!(!gate.allow(&row));
        for n in 1..100 {
            row.flow_id = n.to_string();
            assert!(gate.allow(&row));
        }
        row.flow_id = "overflow".into();
        assert!(!gate.allow(&row));
        assert_eq!(gate.suppressed, 2);
        row.event_type = "dns.query".into();
        assert!(gate.allow(&row));
        gate.window -= std::time::Duration::from_secs(2);
        row.event_type = "notice.policy".into();
        assert!(gate.allow(&row));
    }
}
