use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
fn pipeline(c: &mut Criterion) {
    let filter = "proto == tcp && dst.port in [443, 8443] && src.ip in 192.0.2.0/24";
    c.bench_function("cql/parse", |b| {
        b.iter(|| crepe_query::parse(black_box(filter)).unwrap())
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../example.pcap");
    let mut events = Vec::new();
    crepe_capture::read(crepe_capture::open(&path).unwrap(), |event| {
        events.push(event);
        Ok(())
    })
    .unwrap();
    let query = crepe_query::parse(filter).unwrap();
    c.bench_function("cql/evaluate", |b| {
        b.iter(|| query.matches(black_box(&events[0])))
    });
    c.bench_function("protocol/http_header", |b| {
        b.iter(|| {
            crepe_protocol::inspect(black_box(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
                .unwrap()
        })
    });
    c.bench_function("files/sha256_body", |b| {
        b.iter(|| {
            crepe_files::HttpFile::default()
                .push(black_box(
                    b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
                ))
                .unwrap()
        })
    });
}
criterion_group!(benches, pipeline);
criterion_main!(benches);
