//! Deterministic mutated protocol corpus, run on stable Rust in every CI build.
use crepe_core::{EventHeader, EventType};
#[test]
fn mutation_corpus_does_not_panic_or_exceed_state_budgets() {
    let seeds: [&[u8]; 4] = [
        include_bytes!("../../../fixtures/dns.pcap"),
        include_bytes!("../../../fixtures/protocols.pcap"),
        include_bytes!("../../../fixtures/fragments.pcap"),
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ];
    let mut random = 0x12345678u64;
    let mut processor = crepe_analysis::Processor::new(crepe_analysis::Config {
        max_streams: 8,
        max_buffer_bytes: 65536,
        ..Default::default()
    })
    .unwrap();
    for n in 0..20000 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let seed = seeds[n % seeds.len()];
        let mut bytes = seed.to_vec();
        let i = random as usize % bytes.len();
        bytes[i] ^= (random >> 32) as u8;
        if n % 3 == 0 {
            bytes.truncate(i);
        }
        let _ = crepe_dns::parse(&bytes);
        let _ = crepe_protocol::inspect(&bytes);
        let header = EventHeader {
            schema_version: 2,
            event_type: EventType::Packet,
            sequence: n as u64,
            section: 0,
            interface: 0,
            timestamp_ns: Some((n as u64 * 1_000_000).to_string()),
            captured_len: bytes.len() as u32,
            original_len: bytes.len() as u32,
        };
        let _ = processor.process(&bytes, header, if n % 2 == 0 { 1 } else { 101 }, |_| Ok(()));
        assert!(processor.analyzer.buffered_bytes() <= 65536);
        assert!(processor.analyzer.stream_count() <= 8);
        assert!(processor.fragments.buffered_bytes() <= 8 * 1024 * 1024);
    }
}
