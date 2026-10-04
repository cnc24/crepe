use crepe_dns::{parse, RData};
fn query() -> Vec<u8> {
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\0\0\x01\0\x01".to_vec()
}
fn answer(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut m = query();
    m[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    m[6..8].copy_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&[0xc0, 12]);
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    m.extend_from_slice(&(data.len() as u16).to_be_bytes());
    m.extend_from_slice(data);
    m
}
#[test]
fn query_and_compressed_a_answer() {
    let q = parse(&query()).unwrap();
    assert_eq!(q.questions[0].name, "example.test.");
    assert!(!q.response);
    assert_eq!(q.id, 0x1234);
    let a = parse(&answer(1, &[203, 0, 113, 7])).unwrap();
    assert!(a.response);
    assert_eq!(a.answers[0].name, "example.test.");
    assert_eq!(a.answers[0].ttl, 60);
    assert_eq!(a.answers[0].data, RData::A("203.0.113.7".parse().unwrap()));
}
#[test]
fn aaaa_cname_mx_txt_and_unknown() {
    assert!(matches!(
        parse(&answer(28, &[0; 16])).unwrap().answers[0].data,
        RData::Aaaa(_)
    ));
    assert_eq!(
        parse(&answer(5, &[0xc0, 12])).unwrap().answers[0].data,
        RData::Name("example.test.".into())
    );
    assert_eq!(
        parse(&answer(15, &[0, 10, 0xc0, 12])).unwrap().answers[0].data,
        RData::Mx {
            preference: 10,
            exchange: "example.test.".into()
        }
    );
    assert_eq!(
        parse(&answer(16, &[3, b'a', b'b', b'c', 0]))
            .unwrap()
            .answers[0]
            .data,
        RData::Txt(vec!["abc".into(), "".into()])
    );
    assert_eq!(
        parse(&answer(65000, &[0, 1])).unwrap().answers[0].data,
        RData::Unknown { length: 2 }
    );
}
#[test]
fn every_truncation_and_bad_rdlength_is_an_error() {
    let q = query();
    for i in 0..q.len() {
        assert!(parse(&q[..i]).is_err(), "{i}");
    }
    for kind in [1, 28, 5, 15, 16] {
        assert!(parse(&answer(kind, &[255])).is_err());
    }
}
#[test]
fn pointers_counts_and_trailing_data_are_bounded() {
    let mut m = query();
    m[12..14].copy_from_slice(&[0xc0, 12]);
    assert!(parse(&m).is_err());
    let mut m = query();
    m[12..14].copy_from_slice(&[0xc0, 14]);
    assert!(parse(&m).is_err());
    let mut m = query();
    m[4..6].copy_from_slice(&257u16.to_be_bytes());
    assert!(parse(&m).is_err());
    let mut m = query();
    m.push(0);
    assert!(parse(&m).is_err());
}
#[test]
fn arbitrary_bytes_do_not_panic() {
    let mut state = 12345u64;
    for len in 0..512 {
        let mut data = vec![0; len];
        for byte in &mut data {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 32) as u8;
        }
        let _ = parse(&data);
    }
}
