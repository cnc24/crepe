use crepe_stream::{Limits, Stream};
#[test]
fn out_of_order_and_identical_retransmission() {
    let mut s = Stream::new(100, Limits::default()).unwrap();
    assert!(s.push(103, b"def", false).unwrap().is_empty());
    assert_eq!(s.push(100, b"abc", false).unwrap(), b"abcdef");
    assert!(s.push(101, b"bcde", false).unwrap().is_empty());
    assert_eq!(s.pending_bytes(), 0);
}
#[test]
fn overlapping_identical_pending_segments_are_merged() {
    let mut s = Stream::new(100, Limits::default()).unwrap();
    s.push(102, b"cdef", false).unwrap();
    s.push(104, b"efgh", false).unwrap();
    assert_eq!(s.push(100, b"abcd", false).unwrap(), b"abcdefgh");
}
#[test]
fn wraparound_sequence_space() {
    let mut s = Stream::new(u32::MAX - 1, Limits::default()).unwrap();
    s.push(1, b"d", false).unwrap();
    assert_eq!(s.push(u32::MAX - 1, b"abc", false).unwrap(), b"abcd");
    assert_eq!(s.push(2, b"ef", false).unwrap(), b"ef");
}
#[test]
fn conflicting_overlaps_are_rejected() {
    let mut s = Stream::new(0, Limits::default()).unwrap();
    s.push(2, b"cd", false).unwrap();
    assert!(s.push(2, b"XX", false).is_err());
    let mut s = Stream::new(0, Limits::default()).unwrap();
    s.push(0, b"abcd", false).unwrap();
    assert!(s.push(1, b"X", false).is_err());
}
#[test]
fn fin_waits_for_gap_and_rejects_data_after_end() {
    let mut s = Stream::new(0, Limits::default()).unwrap();
    s.push(3, b"def", true).unwrap();
    assert!(!s.is_closed());
    assert_eq!(s.push(0, b"abc", false).unwrap(), b"abcdef");
    assert!(s.is_closed());
    assert!(s.push(6, b"", true).unwrap().is_empty());
    assert!(s.push(6, b"g", false).is_err());
}
#[test]
fn limits_and_unverifiable_old_retransmission() {
    let limits = Limits {
        queued_bytes: 4,
        history_bytes: 2,
        max_gap: 8,
    };
    let mut s = Stream::new(0, limits).unwrap();
    assert!(s.push(9, b"x", false).is_err());
    let mut s = Stream::new(0, limits).unwrap();
    s.push(2, b"cdef", false).unwrap();
    assert!(s.push(1, b"b", false).is_err());
    let mut s = Stream::new(0, limits).unwrap();
    s.push(0, b"abcd", false).unwrap();
    assert!(s.push(0, b"a", false).is_err());
    assert!(s.buffered_bytes() <= 6);
}
#[test]
fn every_split_and_reordered_chunk_reconstructs_same_bytes() {
    let bytes: Vec<u8> = (0..200).collect();
    for split in 1..bytes.len() {
        let mut s = Stream::new(500, Limits::default()).unwrap();
        assert!(s
            .push(500 + split as u32, &bytes[split..], false)
            .unwrap()
            .is_empty());
        assert_eq!(s.push(500, &bytes[..split], false).unwrap(), bytes);
    }
}
