//! Synthetic sustained churn for bounded live-worker/reassembly state. No network IO.
use crepe_core::{EventHeader, EventType};
use crepe_engine::{Config, Input};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seconds = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "60".into())
        .parse::<u64>()?;
    if !(1..=300).contains(&seconds) {
        return Err("duration must be 1..300 seconds".into());
    }
    let config = Config {
        workers: 4,
        max_streams: 32,
        max_buffer_bytes: 8192,
        ..Default::default()
    };
    let mut frame = vec![b'A'; 14 + 20 + 20 + 512];
    frame[..54].fill(0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&552_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
    frame[30..34].copy_from_slice(&[198, 51, 100, 1]);
    frame[36..38].copy_from_slice(&80_u16.to_be_bytes());
    frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = 0x18;
    frame[54..59].copy_from_slice(b"GET /");
    let started = std::time::Instant::now();
    let mut packets = 0_u64;
    let mut anomalies = 0_u64;
    let summary = crepe_engine::stream_inputs(
        "synthetic-pressure",
        None,
        &config,
        |emit| {
            while started.elapsed().as_secs() < seconds {
                packets += 1;
                frame[29] = (packets % 251 + 1) as u8;
                frame[34..36].copy_from_slice(&((packets % 60001 + 1024) as u16).to_be_bytes());
                let header = EventHeader {
                    schema_version: 2,
                    event_type: EventType::Packet,
                    sequence: packets,
                    section: 0,
                    interface: 0,
                    timestamp_ns: Some(
                        (1_700_000_000_000_000_000_i128 + i128::from(packets) * 1000).to_string(),
                    ),
                    captured_len: frame.len() as u32,
                    original_len: frame.len() as u32,
                };
                emit(Input::Packet(crepe_capture::Record {
                    data: &frame,
                    header,
                    linktype: 1,
                }))?;
            }
            Ok(())
        },
        &mut |row| {
            if row.event_type == "anomaly" {
                anomalies += 1;
            }
            Ok(())
        },
    )?;
    assert_eq!(summary.packets, packets);
    assert!(
        anomalies > 0,
        "capacity/incomplete-state diagnostics expected"
    );
    println!(
        "{}",
        serde_json::json!({"seconds":started.elapsed().as_secs_f64(),"packets":packets,"anomalies":anomalies,"summary":summary})
    );
    Ok(())
}
