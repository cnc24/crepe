use crepe_core::{Error, Result};
use serde::Serialize;
use std::{
    io::{self, Write},
    net::{SocketAddr, UdpSocket},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn error(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-COLLECT-001", e)
}
pub fn print_json(value: &impl Serialize) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value).map_err(|e| {
        Error::new(
            if e.io_error_kind() == Some(io::ErrorKind::BrokenPipe) {
                "CREPE-IO-PIPE"
            } else {
                "CREPE-IO-002"
            },
            e,
        )
    })?;
    writeln!(out).map_err(crate::output_error)
}
pub fn config(file: Option<&Path>) -> Result<crepe_engine::Config> {
    let mut config = crepe_engine::Config::default();
    let mut paths = vec![std::path::PathBuf::from("/etc/crepe/crepe.toml")];
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".config")))
    {
        paths.push(base.join("crepe/crepe.toml"));
    }
    for path in paths {
        if path.exists() {
            config = config.overlay(&read_config(&path)?)?;
        }
    }
    if let Some(file) = file {
        config = config.overlay(&read_config(file)?)?;
    }
    for (key, name, quoted) in [
        ("sensor", "CREPE_SENSOR", true),
        ("profile", "CREPE_PROFILE", true),
        ("interface", "CREPE_INTERFACE", true),
        ("store", "CREPE_STORE", true),
        ("dns_port", "CREPE_DNS_PORT", false),
        ("flair", "CREPE_FLAIR", false),
        ("max_streams", "CREPE_MAX_STREAMS", false),
        ("max_buffer_bytes", "CREPE_MAX_BUFFER_BYTES", false),
    ] {
        if let Ok(value) = std::env::var(name) {
            let value = if quoted {
                serde_json::to_string(&value).expect("serializable string")
            } else {
                value
            };
            config = config.overlay(&format!("{key} = {value}"))?;
        }
    }
    crate::reporting::apply_flair(config.flair);
    Ok(config)
}
fn read_config(file: &Path) -> Result<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(file)
        .and_then(|f| f.take(65537).read_to_string(&mut text))
        .map_err(|e| Error::new("CREPE-CONFIG-001", e))?;
    if text.len() > 65536 {
        return Err(Error::new(
            "CREPE-CONFIG-001",
            "configuration exceeds 64 KiB",
        ));
    }
    Ok(text)
}
pub fn query(store: &Path, cql: &str) -> Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    crepe_storage::query(store, cql, &mut out)?;
    out.flush().map_err(crate::output_error)
}
pub fn collect(
    listen: SocketAddr,
    duration: u64,
    count: Option<u64>,
    store: Option<&Path>,
    sensor: &str,
) -> Result<()> {
    let c = crepe_engine::Config {
        sensor: sensor.into(),
        ..Default::default()
    };
    c.validate()?;
    let socket = UdpSocket::bind(listen).map_err(error)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(error)?;
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?;
    let source = crepe_storage::identity(&[
        sensor,
        &started.as_nanos().to_string(),
        &std::process::id().to_string(),
    ]);
    let mut writer = store
        .map(|p| crepe_storage::Writer::begin(p, &source))
        .transpose()?;
    if let Some(writer) = &mut writer {
        writer.enable_hot_queries()?;
    }
    let mut checkpoint_at = Instant::now();
    let mut checkpoint_count = 0_u64;
    let mut decoder = crepe_collector::Collector::new(Default::default())?;
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, std::sync::atomic::Ordering::Relaxed))
        .map_err(error)?;
    let deadline = Instant::now() + Duration::from_secs(duration);
    let mut buffer = [0u8; 65535];
    let mut ordinal = 0u64;
    let (mut datagrams, mut flows, mut malformed, mut notices) = (0u64, 0u64, 0u64, 0u64);
    crate::report!(
        "Bon appétit! Collector listening on {}",
        socket.local_addr().map_err(error)?
    );
    while !cancelled.load(std::sync::atomic::Ordering::Relaxed)
        && Instant::now() < deadline
        && count.is_none_or(|n| datagrams < n)
    {
        match socket.recv_from(&mut buffer) {
            Ok((len, peer)) => {
                datagrams += 1;
                crate::metrics::DATAGRAMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(error)?
                    .as_secs();
                match decoder.decode(peer, &buffer[..len], now) {
                    Ok(batch) => {
                        for flow in batch.flows {
                            flows += 1;
                            crate::metrics::EVENTS
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            ordinal += 1;
                            let row = crepe_engine::exported_row(sensor, &source, ordinal, &flow)?;
                            if let Some(writer) = &mut writer {
                                writer.push(row)?;
                            }
                            print_json(&flow)?;
                        }
                        for option in batch.options {
                            let value = serde_json::json!({"event_type":"export.options","exporter":peer,"domain":batch.domain,"version":batch.version,"sequence":batch.sequence,"fields":option});
                            ordinal += 1;
                            persist_notice(
                                &mut writer,
                                sensor,
                                &source,
                                ordinal,
                                now,
                                "export.options",
                                &value,
                            )?;
                            print_json(&value)?;
                        }
                        for notice in batch.notices {
                            notices += 1;
                            ordinal += 1;
                            let value = serde_json::json!({"notice":notice,"exporter":peer,"domain":batch.domain,"version":batch.version});
                            persist_notice(
                                &mut writer,
                                sensor,
                                &source,
                                ordinal,
                                now,
                                "notice.export",
                                &value,
                            )?;
                            crate::report!(
                                "Oh là là! [{}] {} ({peer})",
                                notice.code,
                                notice.message
                            );
                        }
                    }
                    Err(e) => {
                        malformed += 1;
                        crate::metrics::MALFORMED
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        crate::report!("Sacré bleu! {e} ({peer})");
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(error(e)),
        }
        if let Some(writer) = &mut writer {
            if writer.count > checkpoint_count
                && (writer.count - checkpoint_count >= 1024
                    || checkpoint_at.elapsed().as_secs() >= 5)
            {
                writer.checkpoint(&crepe_storage::identity(&[
                    &source,
                    "collector-checkpoint",
                    &writer.count.to_string(),
                ]))?;
                checkpoint_count = writer.count;
                checkpoint_at = Instant::now();
            }
        }
    }
    if let Some(writer) = writer {
        writer.commit()?;
    }
    crate::report!("Collector: {datagrams} datagrams, {flows} flows, {notices} notices, {malformed} malformed.");
    Ok(())
}

fn persist_notice(
    writer: &mut Option<crepe_storage::Writer>,
    sensor: &str,
    source: &str,
    index: u64,
    now: u64,
    kind: &str,
    value: &serde_json::Value,
) -> Result<()> {
    if let Some(writer) = writer {
        writer.push(crepe_storage::Row {
            event_id: crepe_storage::identity(&[sensor, source, &index.to_string()]),
            flow_id: String::new(),
            sensor: sensor.into(),
            source: source.into(),
            timestamp_ns: Some((u128::from(now) * 1_000_000_000).to_string()),
            timestamp_ms: i64::try_from(now).ok().and_then(|n| n.checked_mul(1000)),
            event_type: kind.into(),
            payload: serde_json::to_string(value).map_err(error)?,
            ..Default::default()
        })?;
    }
    Ok(())
}

/// Nonblocking exporter input for a combined packet/export sensor.
#[cfg(feature = "live")]
pub struct ExportSource {
    socket: UdpSocket,
    decoder: crepe_collector::Collector,
}
#[cfg(feature = "live")]
impl ExportSource {
    pub fn bind(address: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(address).map_err(error)?;
        socket.set_nonblocking(true).map_err(error)?;
        crate::report!(
            "Bon appétit! Collector listening on {}",
            socket.local_addr().map_err(error)?
        );
        Ok(Self {
            socket,
            decoder: crepe_collector::Collector::new(Default::default())?,
        })
    }
    pub fn poll(
        &mut self,
        sensor: &str,
        source: &str,
        emit: &mut dyn FnMut(crepe_storage::Row) -> Result<bool>,
    ) -> Result<()> {
        let mut bytes = [0; 65535];
        // Bound work per capture/timer callback so exporters cannot starve packet processing.
        for _ in 0..64 {
            let (size, peer) = match self.socket.recv_from(&mut bytes) {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(error(e)),
            };
            crate::metrics::DATAGRAMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(error)?
                .as_secs();
            let mut notice = |kind: &str, value: serde_json::Value| -> Result<()> {
                emit(crepe_storage::Row {
                    sensor: sensor.into(),
                    source: source.into(),
                    event_type: kind.into(),
                    timestamp_ns: Some((u128::from(now) * 1_000_000_000).to_string()),
                    timestamp_ms: i64::try_from(now).ok().and_then(|v| v.checked_mul(1000)),
                    payload: serde_json::to_string(&value).map_err(error)?,
                    ..Default::default()
                })?;
                Ok(())
            };
            match self.decoder.decode(peer, &bytes[..size], now) {
                Ok(batch) => {
                    for value in batch.options {
                        notice(
                            "export.options",
                            serde_json::json!({"exporter":peer,"domain":batch.domain,"version":batch.version,"sequence":batch.sequence,"fields":value}),
                        )?;
                    }
                    for value in batch.notices {
                        notice(
                            "notice.export",
                            serde_json::json!({"exporter":peer,"domain":batch.domain,"version":batch.version,"notice":value}),
                        )?;
                    }
                    for flow in batch.flows {
                        emit(crepe_engine::exported_row(sensor, source, 0, &flow)?)?;
                    }
                }
                Err(e) => {
                    crate::metrics::MALFORMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    notice(
                        "anomaly.export",
                        serde_json::json!({"exporter":peer,"code":e.code,"message":e.message}),
                    )?;
                }
            }
        }
        Ok(())
    }
}
