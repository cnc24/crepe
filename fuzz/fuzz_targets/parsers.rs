#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len()>65536{return}
    let mut file = crepe_files::HttpFile::default();
    file.allow_response(true);
    for part in data.chunks(31) { let _ = file.push(part); }
    if let Ok(text) = std::str::from_utf8(data) { let _ = crepe_security::Engine::new(text, ""); }
    let _=crepe_dns::parse(data);
    let _=crepe_protocol::inspect(data);
    if let Ok(s)=std::str::from_utf8(data){if let Ok(expr) = crepe_query::parse(s) { let _ = expr.ethernet_prefilter(); }}
    let mut fragments=crepe_fragment::Table::new(Default::default()).unwrap();
    let _=fragments.process(data,&Default::default(),0);
    let mut collector=crepe_collector::Collector::new(Default::default()).unwrap();
    let _=collector.decode("127.0.0.1:1234".parse().unwrap(),data,0);
    let header=crepe_core::EventHeader{schema_version:2,event_type:crepe_core::EventType::Packet,sequence:1,section:0,interface:0,timestamp_ns:Some("0".into()),captured_len:data.len()as u32,original_len:data.len()as u32};
    let _=crepe_packet::decode_view(data,header,1);
});
