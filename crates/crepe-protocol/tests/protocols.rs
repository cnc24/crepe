use crepe_protocol::{inspect, Event, Inspection};
fn hello() -> Vec<u8> {
    let mut b = vec![3, 3];
    b.extend_from_slice(&[7; 32]);
    b.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let host = b"example.test";
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
    ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
    ext.extend_from_slice(host);
    ext.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4, 0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
    b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    b.extend(ext);
    let mut h = vec![1, 0, 0, b.len() as u8];
    h.extend(b);
    h
}
fn record(b: &[u8]) -> Vec<u8> {
    let mut r = vec![22, 3, 3];
    r.extend_from_slice(&(b.len() as u16).to_be_bytes());
    r.extend_from_slice(b);
    r
}
#[test]
fn tls_split_records_and_partial_prefixes() {
    let h = hello();
    let mut r = record(&h[..19]);
    r.extend(record(&h[19..]));
    for n in 0..r.len() {
        assert!(matches!(inspect(&r[..n]).unwrap(), Inspection::More));
    }
    match inspect(&r).unwrap() {
        Inspection::Event(Event::TlsClientHello {
            server_name,
            alpn,
            supported_versions,
            ..
        }) => {
            assert_eq!(server_name.as_deref(), Some("example.test"));
            assert_eq!(alpn, ["h2"]);
            assert_eq!(supported_versions, [0x304]);
        }
        v => panic!("{v:?}"),
    }
}
#[test]
fn http_and_ssh_metadata() {
    match inspect(b"GET /abc HTTP/1.1\r\nHost: example.test\r\n\r\n").unwrap() {
        Inspection::Event(Event::HttpRequest { host, target, .. }) => {
            assert_eq!(host.as_deref(), Some("example.test"));
            assert_eq!(target, "/abc")
        }
        v => panic!("{v:?}"),
    };
    assert!(matches!(
        inspect(b"HTTP/1.1 204 No Content\r\nServer: local\r\n\r\n").unwrap(),
        Inspection::Event(Event::HttpResponse { status: 204, .. })
    ));
    assert!(matches!(
        inspect(b"SSH-2.0-OpenSSH_test\r\n").unwrap(),
        Inspection::Event(Event::SshBanner { .. })
    ));
}
#[test]
fn bounded_and_malformed() {
    assert!(inspect(&vec![b'a'; 65537]).is_err());
    let mut h = hello();
    h[4 + 34] = 33;
    assert!(inspect(&record(&h)).is_err());
    assert!(matches!(
        inspect(b"GET / HTTP/1.1\r\nHost:").unwrap(),
        Inspection::More
    ));
}
