//! Bounded processing-time query windows. No implicit loss or unbounded buffering.
use crepe_core::{Error, Result};
use crepe_storage::Row;
use std::time::{Duration, Instant};
pub struct Window {
    query: String,
    duration: Duration,
    started: Instant,
    rows: Vec<Row>,
    bytes: usize,
    index: u64,
}
impl Window {
    pub fn new(query: &str, seconds: u64) -> Result<Self> {
        // Validate both CQL syntax and the DataFusion plan before capture begins.
        crepe_storage::query_rows(&[], query, &mut std::io::sink())?;
        Ok(Self {
            query: query.into(),
            duration: Duration::from_secs(seconds),
            started: Instant::now(),
            rows: Vec::new(),
            bytes: 0,
            index: 0,
        })
    }
    pub fn push(&mut self, row: &Row) -> Result<()> {
        let size = serde_json::to_vec(row)
            .map_err(|e| Error::new("CREPE-CQL-001", e))?
            .len();
        if self.rows.len() >= 10_000 || self.bytes + size > 16 * 1024 * 1024 {
            return Err(Error::new(
                "CREPE-CQL-LIMIT",
                "live query window exceeded 10000 observations or 16 MiB; shorten --query-interval",
            ));
        }
        self.rows.push(row.clone());
        self.bytes += size;
        Ok(())
    }
    pub fn flush(&mut self, force: bool) -> Result<()> {
        if !force && self.started.elapsed() < self.duration {
            return Ok(());
        }
        if !self.rows.is_empty() {
            let mut json = Vec::new();
            crepe_storage::query_rows(&self.rows, &self.query, &mut json)?;
            let result = std::str::from_utf8(&json)
                .map_err(|e| Error::new("CREPE-CQL-001", e))?
                .lines()
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::new("CREPE-CQL-001", e))?;
            self.index += 1;
            crate::history::print_json(
                &serde_json::json!({"event_type":"query.window", "schema_version":1,"index":self.index,"observations":self.rows.len(),"elapsed_ms":self.started.elapsed().as_millis(),"rows":result}),
            )?;
            self.rows.clear();
            self.bytes = 0;
        }
        self.started = Instant::now();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_fails_explicitly_at_capacity_without_evicting_rows() {
        let mut window = Window::new("* | count", 5).unwrap();
        for _ in 0..10_000 {
            window.push(&Row::default()).unwrap();
        }
        assert_eq!(
            window.push(&Row::default()).unwrap_err().code,
            "CREPE-CQL-LIMIT"
        );
        assert_eq!(window.rows.len(), 10_000);
    }
}
