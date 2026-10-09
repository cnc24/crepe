//! Small loopback-only Prometheus endpoint, isolated from packet processing.
use crepe_core::{Error, Result};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
};
static POLICY: std::sync::LazyLock<std::sync::Mutex<std::collections::BTreeMap<String, u64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Default::default()));
pub(crate) fn observe(row: &crepe_storage::Row) {
    if row.event_type != "policy.metric" && row.event_type != "policy.log" {
        return;
    }
    if row.event_type == "policy.log" {
        crate::report!("Policy log: {}", row.payload);
        return;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&row.payload) else {
        return;
    };
    if let (Some(name), Some(increment)) = (
        value.pointer("/effect/data/name").and_then(|v| v.as_str()),
        value
            .pointer("/effect/data/increment")
            .and_then(|v| v.as_u64()),
    ) {
        if let Ok(mut counters) = POLICY.lock() {
            if counters.len() < 128 || counters.contains_key(name) {
                let counter = counters.entry(name.into()).or_default();
                *counter = counter.saturating_add(increment);
            }
        }
    }
}
fn policy_metrics() -> String {
    let Ok(counters) = POLICY.lock() else {
        return String::new();
    };
    counters
        .iter()
        .map(|(name, total)| {
            format!(
                "crepe_policy_counter_total{{policy={}}} {total}\n",
                serde_json::to_string(name).unwrap()
            )
        })
        .collect()
}
pub(crate) static PACKETS: AtomicU64 = AtomicU64::new(0);
pub(crate) static BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static EVENTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static DATAGRAMS: AtomicU64 = AtomicU64::new(0);
pub(crate) static MALFORMED: AtomicU64 = AtomicU64::new(0);
pub(crate) struct Server {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Server {
    pub fn start(address: SocketAddr) -> Result<Self> {
        if !address.ip().is_loopback() {
            return Err(Error::new(
                "CREPE-METRICS-001",
                "metrics endpoint must bind a loopback address",
            ));
        }
        let listener =
            TcpListener::bind(address).map_err(|e| Error::new("CREPE-METRICS-001", e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::new("CREPE-METRICS-001", e))?;
        crate::report!(
            "Metrics listening on {}",
            listener
                .local_addr()
                .map_err(|e| Error::new("CREPE-METRICS-001", e))?
        );
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let worker = std::thread::spawn(move || {
            while !signal.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let _ = socket.set_nonblocking(false);
                        let timeout = Some(std::time::Duration::from_millis(200));
                        let _ = socket.set_read_timeout(timeout);
                        let _ = socket.set_write_timeout(timeout);
                        let mut request = [0; 4096];
                        let mut size = 0;
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_millis(200);
                        while size < request.len()
                            && std::time::Instant::now() < deadline
                            && !request[..size].windows(4).any(|s| s == b"\r\n\r\n")
                        {
                            match socket.read(&mut request[size..]) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => size += n,
                            }
                        }
                        let (status, body) = if request[..size].starts_with(b"GET /metrics HTTP/1.")
                        {
                            ("200 OK", format!("# TYPE crepe_capture_records_total counter\ncrepe_capture_records_total {}\n# TYPE crepe_capture_bytes_total counter\ncrepe_capture_bytes_total {}\n# TYPE crepe_events_total counter\ncrepe_events_total {}\n# TYPE crepe_export_datagrams_total counter\ncrepe_export_datagrams_total {}\n# TYPE crepe_malformed_exports_total counter\ncrepe_malformed_exports_total {}\n", PACKETS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed), EVENTS.load(Ordering::Relaxed), DATAGRAMS.load(Ordering::Relaxed), MALFORMED.load(Ordering::Relaxed)) + &policy_metrics())
                        } else {
                            ("404 Not Found", "Not found\n".into())
                        };
                        let _ = write!(socket, "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
