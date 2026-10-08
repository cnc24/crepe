//! Bounded orchestration, stable observation identities and historical ingestion.
mod config;
pub mod correlation;
mod identity_index;
mod workers;
pub use config::{Config, Profile};
use crepe_core::{Error, PacketEvent, Result};
use crepe_storage::{identity, Row, Writer};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub packets: u64,
    pub malformed_packets: u64,
    pub observations: u64,
    pub notices: u64,
    pub incomplete_datagrams: usize,
    pub expired_datagrams: u64,
    pub evicted_datagrams: u64,
}
fn json(v: &impl Serialize) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::new("CREPE-ENGINE-001", e))
}
fn time(row: &mut Row, ns: Option<String>) {
    row.timestamp_ms = ns
        .as_deref()
        .and_then(|n| n.parse::<i128>().ok())
        .and_then(|n| n.div_euclid(1_000_000).try_into().ok());
    row.timestamp_ns = ns;
}
/// Conversation identity is bidirectional and scoped to sensor, source and link context.
/// Individual flow.end instances receive a distinct event ID even when a tuple is reused.
pub fn conversation(sensor: &str, source: &str, p: &PacketEvent) -> String {
    let (k, _) = crepe_flow::FlowKey::from_packet(p);
    identity(&[
        sensor,
        source,
        &serde_json::to_string(&k).expect("serializable flow key"),
    ])
}
fn packet_row(c: &Config, source: &str, p: &PacketEvent, kind: &str, payload: String) -> Row {
    let mut row = Row {
        conversation_id: conversation(&c.sensor, source, p),
        identity_status: "unassigned".into(),
        sensor: c.sensor.clone(),
        source: source.into(),
        event_type: kind.into(),
        src_ip: Some(p.src.ip.to_string()),
        dst_ip: Some(p.dst.ip.to_string()),
        src_port: p.src.port.map(u64::from),
        dst_port: p.dst.port.map(u64::from),
        proto: Some(p.proto.to_string()),
        payload,
        ..Default::default()
    };
    time(&mut row, p.header.timestamp_ns.clone());
    row
}
type Observer<'a> = Option<&'a mut dyn FnMut(&Row) -> Result<()>>;
struct Sink<'a, 'b> {
    writer: Option<&'a mut Writer>,
    observe: Observer<'b>,
    config: &'a Config,
    source: &'a str,
    ordinal: u64,
    identities: identity_index::Index,
    summary: Summary,
    seen: BTreeMap<String, String>,
    seen_bytes: usize,
    checkpoint: bool,
    checkpoint_at: std::time::Instant,
    checkpoint_rows: u64,
    checkpoint_index: u64,
    security: crepe_security::Engine,
    #[cfg(feature = "plugins")]
    plugins: Vec<crepe_plugin::Plugin>,
}
impl Sink<'_, '_> {
    fn has_plugins(&self) -> bool {
        #[cfg(feature = "plugins")]
        {
            !self.plugins.is_empty()
        }
        #[cfg(not(feature = "plugins"))]
        {
            false
        }
    }
    fn push(&mut self, mut row: Row) -> Result<()> {
        if self.security.is_empty() && (!self.has_plugins() || row.event_type == "packet") {
            return self.push_raw(row);
        }
        let mut fields = BTreeMap::new();
        for (key, value) in [
            ("src.ip", &row.src_ip),
            ("dst.ip", &row.dst_ip),
            ("proto", &row.proto),
        ] {
            if let Some(value) = value {
                fields.insert(key.into(), vec![value.clone()]);
            }
        }
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&row.payload) {
            let mut domains = Vec::new();
            if let Some(questions) = payload.pointer("/dns/questions").and_then(|v| v.as_array()) {
                for question in questions.iter().take(256) {
                    if let Some(name) = question["name"].as_str() {
                        domains.push(name.into());
                    }
                }
            }
            for pointer in ["/protocol/server_name", "/protocol/host"] {
                if let Some(name) = payload.pointer(pointer).and_then(|v| v.as_str()) {
                    domains.push(name.into());
                }
            }
            if !domains.is_empty() {
                fields.insert("domain".into(), domains);
            }
            if let Some(code) = payload.pointer("/anomaly/code").and_then(|v| v.as_str()) {
                fields.insert("anomaly.code".into(), vec![code.into()]);
            }
            if let Some(hash) = payload.pointer("/protocol/sha256").and_then(|v| v.as_str()) {
                fields.insert("sha256".into(), vec![hash.into()]);
            }
        }
        let findings = self.security.inspect(&row.event_type, &fields);
        let parent = identity(&[
            &self.config.sensor,
            self.source,
            &(self.ordinal + 1).to_string(),
        ]);
        row.event_id = parent.clone();
        self.push_raw(row.clone())?;
        for finding in findings {
            if !self.config.accepts(finding.event_type) {
                continue;
            }
            let mut notice = row.clone();
            notice.event_type = finding.event_type.into();
            notice.packets = None;
            notice.bytes = None;
            notice.payload =
                json(&serde_json::json!({"source_event_id":parent,"finding":finding}))?;
            self.summary.notices += 1;
            self.push_raw(notice)?;
        }
        #[cfg(feature = "plugins")]
        if row.event_type != "packet" && !self.plugins.is_empty() {
            let input = json(&serde_json::json!({"schema_version":1,"event":row}))?;
            let mut emitted = Vec::new();
            for plugin in &mut self.plugins {
                match plugin.inspect(&row.event_type, &input) {
                    Ok(values) => for value in values { emitted.push(("notice.plugin", serde_json::json!({"plugin":plugin.name,"source_event_id":parent,"data":value}))); },
                    Err(error) => emitted.push(("anomaly.plugin", serde_json::json!({"plugin":plugin.name,"source_event_id":parent,"code":error.code,"message":error.message,"disabled":true}))),
                }
            }
            for (kind, payload) in emitted {
                if !self.config.accepts(kind) {
                    continue;
                }
                let mut observation = row.clone();
                observation.event_type = kind.into();
                observation.packets = None;
                observation.bytes = None;
                observation.payload = json(&payload)?;
                self.summary.notices += 1;
                self.push_raw(observation)?;
            }
        }
        Ok(())
    }
    fn push_raw(&mut self, mut row: Row) -> Result<()> {
        self.ordinal += 1;
        row.event_id = identity(&[&self.config.sensor, self.source, &self.ordinal.to_string()]);
        self.summary.observations += 1;
        if let Some(observe) = &mut self.observe {
            observe(&row)?;
        }
        if let Some(writer) = &mut self.writer {
            writer.push(row)?;
            self.checkpoint_rows += 1;
        }
        self.maybe_checkpoint()
    }
    fn maybe_checkpoint(&mut self) -> Result<()> {
        if self.checkpoint
            && self.checkpoint_rows > 0
            && (self.checkpoint_rows >= 1024
                || self.checkpoint_at.elapsed().as_secs() >= 5
                || self
                    .writer
                    .as_ref()
                    .is_some_and(|writer| writer.hot_bytes() >= 4 * 1024 * 1024))
        {
            if let Some(writer) = &mut self.writer {
                self.checkpoint_index += 1;
                writer.checkpoint(&identity(&[
                    &self.config.sensor,
                    self.source,
                    "checkpoint",
                    &self.checkpoint_index.to_string(),
                ]))?;
                self.checkpoint_rows = 0;
                self.checkpoint_at = std::time::Instant::now();
            }
        }
        Ok(())
    }

    fn packet(&mut self, p: &PacketEvent, anchor: Option<u64>) -> Result<()> {
        self.identities.record(p, anchor);
        if self.config.packets() {
            let mut row = packet_row(self.config, self.source, p, "packet", json(p)?);
            self.identities.apply(p, &mut row);
            row.packets = Some(1);
            row.bytes = Some(u64::from(p.header.original_len));
            self.push(row)?;
        }
        Ok(())
    }
    fn malformed(&mut self, header: &crepe_core::EventHeader, error: &Error) -> Result<()> {
        self.summary.malformed_packets += 1;
        self.summary.notices += 1;
        let mut row = Row {
            sensor: self.config.sensor.clone(),
            source: self.source.into(),
            event_type: "anomaly.decode".into(),
            payload: json(
                &serde_json::json!({"header":header,"anomaly":{"code":error.code,"message":error.message}}),
            )?,
            ..Default::default()
        };
        time(&mut row, header.timestamp_ns.clone());
        self.push(row)
    }
    fn analysis(&mut self, event: crepe_analysis::Event) -> Result<()> {
        let kind = match event.event_type {
            crepe_analysis::Kind::DnsQuery => "dns.query",
            crepe_analysis::Kind::DnsResponse => "dns.response",
            crepe_analysis::Kind::Protocol => event
                .protocol
                .as_ref()
                .map(|p| p.kind())
                .unwrap_or("protocol"),
            crepe_analysis::Kind::Anomaly => "anomaly",
        };
        if !self.config.accepts(kind) {
            return Ok(());
        }
        if kind == "anomaly" {
            self.summary.notices += 1;
        }
        let mut row = packet_row(self.config, self.source, &event.packet, kind, json(&event)?);
        self.identities.apply(&event.packet, &mut row);
        self.push(row.clone())?;
        // A small observational policy: keep the first DNS answer per name and report changes.
        if self.config.notices {
            if let Some(dns) = &event.dns {
                if dns.response {
                    let mut rrsets: BTreeMap<String, Vec<String>> = BTreeMap::new();
                    for answer in &dns.answers {
                        rrsets
                            .entry(format!(
                                "{}:{}:{}",
                                answer.name, answer.rr_type, answer.class
                            ))
                            .or_default()
                            .push(json(&answer.data)?);
                    }
                    for (name, mut values) in rrsets {
                        values.sort();
                        values.dedup();
                        let value = json(&values)?;
                        if let Some(old) = self.seen.get(&name) {
                            if old != &value {
                                let mut notice = row.clone();
                                notice.event_type = "notice.dns_change".into();
                                notice.payload = json(
                                    &serde_json::json!({"code":"CREPE-NOTICE-DNS-CHANGE","rrset":name,"previous":old,"current":value}),
                                )?;
                                self.summary.notices += 1;
                                self.push(notice)?;
                            }
                        }
                        if let Some(previous) = self.seen.remove(&name) {
                            self.seen_bytes -= name.len() + previous.len();
                        }
                        let size = name.len() + value.len();
                        if self.seen.len() < 4096
                            && self.seen_bytes + size <= self.config.max_buffer_bytes
                        {
                            self.seen_bytes += size;
                            self.seen.insert(name, value);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn flow(&mut self, f: crepe_flow::FlowRecord) -> Result<()> {
        self.push(flow_row(&self.config.sensor, self.source, f)?)
    }
}
/// Convert a flow to the historical schema with the same conversation identity as packet analysis.
pub fn flow_row(sensor: &str, source: &str, mut f: crepe_flow::FlowRecord) -> Result<Row> {
    let key = crepe_flow::FlowKey {
        a: f.a.clone(),
        b: f.b.clone(),
        proto: f.proto,
        section: f.section,
        interface: f.interface,
        vlans: f.vlans.clone(),
    };
    let conversation_id = identity(&[
        sensor,
        source,
        &serde_json::to_string(&key).expect("serializable flow key"),
    ]);
    f.flow_id = identity_index::instance(&conversation_id, f.first_sequence);
    let mut row = Row {
        flow_id: f.flow_id.clone(),
        conversation_id,
        identity_status: if f.first_sequence == 0 {
            "unassigned"
        } else {
            "instance"
        }
        .into(),
        sensor: sensor.to_string(),
        source: source.into(),
        event_type: "flow.end".into(),
        src_ip: Some(f.a.ip.to_string()),
        dst_ip: Some(f.b.ip.to_string()),
        src_port: f.a.port.map(u64::from),
        dst_port: f.b.port.map(u64::from),
        proto: Some(f.proto.to_string()),
        packets: f.packets_a.checked_add(f.packets_b),
        bytes: f.bytes_a.checked_add(f.bytes_b),
        payload: json(&f)?,
        ..Default::default()
    };
    time(&mut row, Some(f.end_ns));
    row.event_id = identity(&[sensor, source, "flow-instance", &row.payload]);
    Ok(row)
}
/// Multiplexed sensor inputs; external rows must use this session's sensor/source.
pub enum Input<'a> {
    Packet(crepe_capture::Record<'a>),
    Tick(i128),
    Observation(Box<Row>),
}
pub fn ingest(file: &Path, store: &Path, config: &Config) -> Result<Summary> {
    ingest_with_progress(file, store, config, |_| {})
}

/// Import atomically, reporting capture records consumed (not committed observations).
pub fn ingest_with_progress(
    file: &Path,
    store: &Path,
    config: &Config,
    mut progress: impl FnMut(u64),
) -> Result<Summary> {
    config.validate()?;
    if matches!(config.profile, Profile::Banane) {
        return Err(Error::new("CREPE-CONFIG-001", "Banane collects NetFlow/IPFIX over UDP; use crepe banane --listen IP:PORT instead of importing a PCAP."));
    }
    let source = crepe_storage::hash_file(file)?;
    let batch = identity(&[&source, &config.sensor]);
    let mut writer = Writer::begin(store, &batch)?;
    let summary = process_records(config, &source, Some(&mut writer), None, |emit| {
        let mut records = 0u64;
        crepe_capture::read_records(crepe_capture::open(file)?, |record| {
            let more = emit(Input::Packet(record))?;
            records += 1;
            progress(records);
            Ok(more)
        })
    })?;
    if crepe_storage::hash_file(file)? != source {
        return Err(Error::new(
            "CREPE-ENGINE-001",
            "input changed during import; batch discarded",
        ));
    }
    writer.commit()?;
    Ok(summary)
}
/// Run the same bounded pipeline against a streaming capture source.
/// Observation callbacks run before capture finishes; optional history publishes periodic checkpoints and commits at clean shutdown.
pub fn stream(
    source: &str,
    store: Option<&Path>,
    config: &Config,
    read: impl FnOnce(&mut dyn FnMut(crepe_capture::Record<'_>) -> Result<bool>) -> Result<()>,
    observe: &mut dyn FnMut(&Row) -> Result<()>,
) -> Result<Summary> {
    stream_with_ticks(
        source,
        store,
        config,
        |emit| read(&mut |record| emit(Some(record), 0)),
        observe,
    )
}
/// Streaming source with wall-clock ticks for idle expiry and periodic durable checkpoints.
/// `None` represents a tick with Unix nanoseconds; packet timestamps remain capture timestamps.
pub fn stream_with_ticks(
    source: &str,
    store: Option<&Path>,
    config: &Config,
    read: impl FnOnce(
        &mut dyn FnMut(Option<crepe_capture::Record<'_>>, i128) -> Result<bool>,
    ) -> Result<()>,
    observe: &mut dyn FnMut(&Row) -> Result<()>,
) -> Result<Summary> {
    stream_inputs(
        source,
        store,
        config,
        |emit| {
            read(&mut |record, now| {
                emit(match record {
                    Some(record) => Input::Packet(record),
                    None => Input::Tick(now),
                })
            })
        },
        observe,
    )
}
/// Capture and exporter observations share one writer, ordered IDs and plugin/security pipeline.
pub fn stream_inputs(
    source: &str,
    store: Option<&Path>,
    config: &Config,
    read: impl FnOnce(&mut dyn FnMut(Input<'_>) -> Result<bool>) -> Result<()>,
    observe: &mut dyn FnMut(&Row) -> Result<()>,
) -> Result<Summary> {
    config.validate()?;
    if matches!(config.profile, Profile::Banane) {
        return Err(Error::new(
            "CREPE-CONFIG-001",
            "Banane requires the UDP collector.",
        ));
    }
    let batch = identity(&[source, &config.sensor]);
    let mut writer = store.map(|path| Writer::begin(path, &batch)).transpose()?;
    if let Some(writer) = &mut writer {
        writer.enable_hot_queries()?;
    }
    let summary = process_records(config, source, writer.as_mut(), Some(observe), read)?;
    if let Some(writer) = writer {
        writer.commit()?;
    }
    Ok(summary)
}

fn process_records(
    config: &Config,
    source: &str,
    writer: Option<&mut Writer>,
    observe: Observer<'_>,
    read: impl FnOnce(&mut dyn FnMut(Input<'_>) -> Result<bool>) -> Result<()>,
) -> Result<Summary> {
    #[cfg(not(feature = "plugins"))]
    if !config.plugins.is_empty() {
        return Err(Error::new(
            "CREPE-PLG-001",
            "This build has no plugin support.",
        ));
    }
    let checkpoint = observe.is_some();
    let mut sink = Sink {
        writer,
        observe,
        config,
        source,
        ordinal: 0,
        identities: identity_index::Index::default(),
        summary: Summary::default(),
        seen: BTreeMap::new(),
        seen_bytes: 0,
        checkpoint,
        checkpoint_at: std::time::Instant::now(),
        checkpoint_rows: 0,
        checkpoint_index: 0,
        security: load_security(config)?,
        #[cfg(feature = "plugins")]
        plugins: config
            .plugins
            .iter()
            .map(|path| crepe_plugin::Plugin::load(path))
            .collect::<Result<_>>()?,
    };
    if checkpoint && config.workers > 1 {
        workers::run(config, read, &mut sink)?;
        return Ok(sink.summary);
    }
    let mut analyzer = crepe_analysis::Processor::new(crepe_analysis::Config {
        dns_ports: vec![config.dns_port],
        max_streams: config.max_streams,
        max_buffer_bytes: config.max_buffer_bytes,
        ..Default::default()
    })?;
    let mut flows = crepe_flow::FlowTable::new(Default::default())?;
    read(&mut |input| {
        let record = match input {
            Input::Packet(record) => record,
            Input::Observation(row) => {
                if row.sensor != config.sensor || row.source != source {
                    return Err(Error::new(
                        "CREPE-ENGINE-001",
                        "external observation has a different sensor/source",
                    ));
                }
                if config.accepts(&row.event_type) {
                    if row.event_type.starts_with("notice.")
                        || row.event_type.starts_with("anomaly.")
                    {
                        sink.summary.notices += 1;
                    }
                    sink.push(*row)?;
                }
                return Ok(true);
            }
            Input::Tick(now) => {
                if config.flows() {
                    flows.advance(now, |f| sink.flow(f))?;
                }
                if config.analysis() {
                    analyzer.analyzer.advance(now, |e| sink.analysis(e))?;
                    analyzer.fragments.expire(now)?;
                }
                sink.maybe_checkpoint()?;
                return Ok(true);
            }
        };
        sink.summary.packets += 1;
        let decoded = match record.decode() {
            Ok(decoded) => decoded,
            Err(error) if config.tolerant_decode && error.code == "CREPE-PKT-001" => {
                sink.malformed(&record.header, &error)?;
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        if let Some(p) = decoded {
            let anchor = if config.flows() && p.header.timestamp_ns.is_some() {
                flows.push(&p, |f| sink.flow(f))?;
                flows.last_assignment()
            } else {
                None
            };
            sink.packet(&p, anchor)?;
        }
        if config.analysis() {
            if let Err(error) =
                analyzer.process(record.data, record.header.clone(), record.linktype, |e| {
                    sink.analysis(e)
                })
            {
                if config.tolerant_decode && error.code == "CREPE-PKT-001" {
                    sink.malformed(&record.header, &error)?;
                } else {
                    return Err(error);
                }
            }
        }
        Ok(true)
    })?;
    if config.flows() {
        flows.finish(|f| sink.flow(f))?;
    }
    if config.analysis() {
        sink.summary.incomplete_datagrams = analyzer.finish(|e| sink.analysis(e))?;
        sink.summary.expired_datagrams = analyzer.fragments.stats.expired;
        sink.summary.evicted_datagrams = analyzer.fragments.stats.evicted;
    }
    let summary = sink.summary;
    Ok(summary)
}

fn load_security(config: &Config) -> Result<crepe_security::Engine> {
    fn read(path: Option<&Path>) -> Result<String> {
        use std::io::Read;
        let mut text = String::new();
        if let Some(path) = path {
            std::fs::File::open(path)
                .and_then(|f| f.take(8 * 1024 * 1024 + 1).read_to_string(&mut text))
                .map_err(|e| Error::new("CREPE-INTEL-001", e))?;
        }
        Ok(text)
    }
    crepe_security::Engine::new(
        &read(config.intel_feed.as_deref())?,
        &read(config.policy_rules.as_deref())?,
    )
}

pub fn exported_row(
    sensor: &str,
    source: &str,
    index: u64,
    flow: &crepe_collector::Flow,
) -> Result<Row> {
    let mut row = Row {
        identity_status: "exported".into(),
        event_id: identity(&[sensor, source, &index.to_string()]),
        flow_id: identity(&[
            sensor,
            &flow.exporter.to_string(),
            &flow.domain.to_string(),
            &format!(
                "{:?}:{:?}-{:?}:{:?}-{:?}",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol
            ),
        ]),
        sensor: sensor.into(),
        source: source.into(),
        event_type: "flow.export".into(),
        src_ip: flow.src_ip.map(|v| v.to_string()),
        dst_ip: flow.dst_ip.map(|v| v.to_string()),
        src_port: flow.src_port.map(u64::from),
        dst_port: flow.dst_port.map(u64::from),
        proto: flow
            .protocol
            .map(|p| crepe_core::Protocol::from_number(p).to_string()),
        packets: flow.packets,
        bytes: flow.bytes,
        payload: json(flow)?,
        ..Default::default()
    };
    time(
        &mut row,
        Some(
            (u128::from(flow.end_ms.unwrap_or(u64::from(flow.export_time) * 1000)) * 1_000_000)
                .to_string(),
        ),
    );
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notice_rrsets_are_deduplicated_and_byte_bounded() {
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dns.pcap");
        let mut processor = crepe_analysis::Processor::new(Default::default()).unwrap();
        let mut response = None;
        crepe_capture::read_records(crepe_capture::open(&file).unwrap(), |r| {
            processor.process(r.data, r.header, r.linktype, |e| {
                if response.is_none() && e.dns.as_ref().is_some_and(|d| d.response) {
                    response = Some(e);
                }
                Ok(())
            })?;
            Ok(true)
        })
        .unwrap();
        let event = response.unwrap();
        let directory = std::env::temp_dir().join(format!("crepe-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let mut writer = Writer::begin(&directory, &identity(&["notice-test"])).unwrap();
        let config = Config {
            max_buffer_bytes: 128,
            ..Default::default()
        };
        let mut sink = Sink {
            writer: Some(&mut writer),
            observe: None,
            config: &config,
            source: "test",
            ordinal: 0,
            identities: identity_index::Index::default(),
            summary: Summary::default(),
            seen: BTreeMap::new(),
            seen_bytes: 0,
            checkpoint: false,
            checkpoint_at: std::time::Instant::now(),
            checkpoint_rows: 0,
            checkpoint_index: 0,
            security: Default::default(),
            #[cfg(feature = "plugins")]
            plugins: Vec::new(),
        };
        sink.analysis(event.clone()).unwrap();
        let mut repeated = event.clone();
        let answer = repeated.dns.as_ref().unwrap().answers[0].clone();
        repeated.dns.as_mut().unwrap().answers.push(answer);
        sink.analysis(repeated).unwrap();
        assert_eq!(sink.summary.notices, 0);
        for n in 0..100 {
            let mut e = event.clone();
            e.dns.as_mut().unwrap().answers[0].name = format!("name-{n}.example.test.");
            sink.analysis(e).unwrap();
            assert!(sink.seen_bytes <= 128);
        }
        assert!(sink.seen.len() < 100);
        drop(writer);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn timestamps_round_toward_the_previous_millisecond() {
        let mut row = Row::default();
        time(&mut row, Some("-1".into()));
        assert_eq!(row.timestamp_ms, Some(-1));
        assert_eq!(row.timestamp_ns.as_deref(), Some("-1"));
        time(&mut row, Some("1999999".into()));
        assert_eq!(row.timestamp_ms, Some(1));
        time(&mut row, Some(i128::MAX.to_string()));
        assert_eq!(row.timestamp_ms, None);
    }
}
