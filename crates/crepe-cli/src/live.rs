use crepe_capture::{
    live::{self, Capture},
    Record,
};
use crepe_core::{Error, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub fn interfaces() -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    for device in live::interfaces()? {
        writeln!(
            out,
            "{}\t{}",
            device.name,
            device.description.as_deref().unwrap_or("")
        )
        .map_err(crate::output_error)?;
    }
    Ok(())
}
pub fn capture(
    interface: &str,
    filters: (Option<&str>, Option<&str>),
    seconds: u64,
    count: Option<u64>,
    promisc: bool,
    mut emit: impl FnMut(Record<'_>) -> Result<bool>,
) -> Result<()> {
    capture_events(
        interface,
        filters,
        seconds,
        count,
        promisc,
        |record, _| match record {
            Some(record) => emit(record),
            None => Ok(true),
        },
    )
}
pub fn capture_events(
    interface: &str,
    filters: (Option<&str>, Option<&str>),
    seconds: u64,
    count: Option<u64>,
    promisc: bool,
    mut emit: impl FnMut(Option<Record<'_>>, i128) -> Result<bool>,
) -> Result<()> {
    let (bpf, automatic) = filters;
    let mut cap = Capture::open(interface, bpf, promisc)?;
    if bpf.is_none() && cap.linktype() == 1 {
        if let Some(hint) = automatic {
            if let Err(error) = cap.set_filter(hint) {
                crate::report!("Oh là là! {error}; continuing without automatic prefilter.");
            }
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))
        .map_err(|e| Error::new("CREPE-CAP-001", e))?;
    crate::report!(
        "Voilà! Capture ready on {interface}; duration {seconds}s; LINKTYPE {}.",
        cap.linktype()
    );
    let started = Instant::now();
    let mut sequence = 0;
    let mut tick = Instant::now();
    while !stop.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(seconds) {
        if tick.elapsed() >= Duration::from_millis(100) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| Error::new("CREPE-CAP-001", e))?
                .as_nanos() as i128;
            if !emit(None, now)? {
                break;
            }
            tick = Instant::now();
        }
        if let Some(record) = cap.next_record()? {
            sequence = record.header.sequence;
            crate::metrics::PACKETS.fetch_add(1, Ordering::Relaxed);
            crate::metrics::BYTES.fetch_add(record.data.len() as u64, Ordering::Relaxed);
            if !emit(Some(record), 0)? || count.is_some_and(|limit| sequence >= limit) {
                break;
            }
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let stats = cap.statistics()?;
    crate::report!("Magnifique! {sequence} records read; libpcap received={}, dropped={}, interface_dropped={}.", stats.received, stats.dropped, stats.interface_dropped);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_bpf_is_a_superset_for_ip_fragments_extensions_and_vlans() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for query in [
            "proto == tcp",
            "proto == udp",
            "proto == icmpv6",
            "proto == 99",
            "src.ip in 10.0.0.0/8",
            "src.ip in 2001:db8::/32",
            "dst.ip == 10.0.0.2",
            "proto == tcp && dst.port == 443",
            "src.ip in 10.0.0.0/8 || proto == udp",
            "proto == tcp && !(dst.port == 443)",
        ] {
            let expr = crepe_query::parse(query).unwrap();
            let filter =
                crepe_capture::live::EthernetFilter::compile(&expr.ethernet_prefilter().unwrap())
                    .unwrap();
            for name in [
                "example.pcap",
                "fixtures/fragments.pcap",
                "fixtures/flows.pcap",
                "fixtures/protocols.pcap",
            ] {
                crepe_capture::read_records(
                    crepe_capture::open(&root.join(name)).unwrap(),
                    |record| {
                        if record.linktype != 1 || record.data.len() < 14 {
                            return Ok(true);
                        }
                        let mut tagged = record.data[..12].to_vec();
                        tagged.extend_from_slice(&[0x88, 0xa8, 0, 7, 0x81, 0, 0, 9]);
                        tagged.extend_from_slice(&record.data[12..]);
                        for bytes in [record.data, &tagged] {
                            let mut header = record.header.clone();
                            header.captured_len = bytes.len() as u32;
                            header.original_len = header.captured_len;
                            if let Some(packet) = crepe_packet::decode_link(bytes, header, 1)? {
                                if expr.matches(&packet) {
                                    assert!(
                                        filter.matches(bytes),
                                        "prefilter dropped {query}: {packet:?}"
                                    );
                                }
                            }
                        }
                        Ok(true)
                    },
                )
                .unwrap();
            }
        }
    }
}
