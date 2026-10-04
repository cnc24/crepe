//! Link decoding and IP reassembly shared by offline analysis and ingestion.
use crate::{Analyzer, Config, Event};
use crepe_core::{EventHeader, Result};
use crepe_fragment::{Limits, Scope, Table};
use std::borrow::Cow;

pub struct Processor {
    pub analyzer: Analyzer,
    pub fragments: Table,
}
impl Processor {
    pub fn new(config: Config) -> Result<Self> {
        Self::partition(config, 1)
    }
    /// Divide datagram budgets across a bounded set of affinity workers.
    pub fn partition(config: Config, workers: usize) -> Result<Self> {
        if !(1..=16).contains(&workers) {
            return Err(crepe_core::Error::new(
                "CREPE-ANA-001",
                "invalid worker count",
            ));
        }
        let mut limits = Limits::default();
        limits.datagrams /= workers;
        limits.bytes /= workers;
        Ok(Self {
            analyzer: Analyzer::new(config)?,
            fragments: Table::new(limits)?,
        })
    }
    pub fn process(
        &mut self,
        data: &[u8],
        header: EventHeader,
        link: u32,
        mut emit: impl FnMut(Event) -> Result<()>,
    ) -> Result<()> {
        let Some((ip, vlans)) = crepe_packet::network(data, link)? else {
            return Ok(());
        };
        let scope = Scope {
            section: header.section,
            interface: header.interface,
            vlans: vlans.clone(),
        };
        let now = header
            .timestamp_ns
            .as_deref()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let assembled = self.fragments.process(ip, &scope, now);
        match assembled {
            Ok(Some(ip)) => {
                let reassembled = matches!(ip, Cow::Owned(_));
                if let Some(mut view) = crepe_packet::decode_view(&ip, header, 101)? {
                    view.event.vlans = vlans;
                    self.analyzer.process(&view, |mut e| {
                        e.reassembled = reassembled;
                        emit(e)
                    })?;
                }
            }
            Ok(None) => {}
            Err(e) => {
                if let Some(packet) = crepe_packet::decode_link(data, header, link)? {
                    emit(Analyzer::anomaly(&packet, false, e.code, e.message))?;
                }
            }
        }
        Ok(())
    }
    pub fn finish(&mut self, emit: impl FnMut(Event) -> Result<()>) -> Result<usize> {
        self.analyzer.finish(emit)?;
        Ok(self.fragments.finish())
    }
}
