use std::collections::BTreeSet;
use uu_i2p::{
    error::I2PError,
    ssu2_ack::{
        AckLimits, AckRange, Ssu2AckBlock, SSU2_ACK_MIN_BODY_SIZE, SSU2_MAX_NUM_ACK_PACKETS,
        SSU2_MAX_NUM_ACK_RANGES, SSU2_MAX_NUM_ACNT,
    },
    ssu2_block::{Blocks, Ssu2Block, Ssu2BlockType},
};

// ---- hex helper ---------------------------------------------------------

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2, "hex string length mismatch");
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (hex_digit(s.as_bytes()[2 * i]) << 4) | hex_digit(s.as_bytes()[2 * i + 1]);
    }
    out
}

fn set(values: impl IntoIterator<Item = u32>) -> BTreeSet<u32> {
    values.into_iter().collect()
}

// ---- разбор -------------------------------------------------------------

#[test]
fn parse_ack_through_only() {
    let body = hex::<5>("0000000a00");
    let ack = Ssu2AckBlock::parse(&body).unwrap();
    assert_eq!(
        ack,
        Ssu2AckBlock {
            ack_through: 10,
            acnt: 0,
            ranges: vec![],
        }
    );
    assert_eq!(ack.acked_ranges(), vec![(10, 10)]);
    assert_eq!(Ssu2AckBlock::TYPE, Ssu2BlockType::Ack);
}

#[test]
fn parse_spec_range_8_10() {
    let body = hex::<5>("0000000a02");
    let ack = Ssu2AckBlock::parse(&body).unwrap();
    assert_eq!(ack.acked_ranges(), vec![(8, 10)]);
}

#[test]
fn parse_spec_full_example() {
    // ACK 10 9 8 6 5 2 1 0, NACK 7 4 3.
    let body = hex::<9>("0000000a0201020203");
    let ack = Ssu2AckBlock::parse(&body).unwrap();
    assert_eq!(ack.ack_through, 10);
    assert_eq!(ack.acnt, 2);
    assert_eq!(
        ack.ranges,
        vec![AckRange { nack: 1, ack: 2 }, AckRange { nack: 2, ack: 3 }]
    );
    assert_eq!(ack.acked_ranges(), vec![(8, 10), (5, 6), (0, 2)]);

    for acked in [0u32, 1, 2, 5, 6, 8, 9, 10] {
        assert!(ack.contains(acked), "packet {acked} should be acked");
    }
    for nacked in [3u32, 4, 7, 11] {
        assert!(!ack.contains(nacked), "packet {nacked} should not be acked");
    }
}

#[test]
fn parse_allows_zero_nack() {
    // nack = 0 разрешён (acking > 255 подряд).
    let body = hex::<7>("0000000a000005");
    let ack = Ssu2AckBlock::parse(&body).unwrap();
    assert_eq!(ack.acked_ranges(), vec![(10, 10), (5, 9)]);
}

#[test]
fn parse_too_short() {
    assert_eq!(
        Ssu2AckBlock::parse(&[0u8; 4]),
        Err(I2PError::InvalidLength {
            expected: SSU2_ACK_MIN_BODY_SIZE,
            got: 4,
        })
    );
}

#[test]
fn parse_odd_ranges_rejected() {
    let body = hex::<6>("0000000a0001");
    assert!(matches!(
        Ssu2AckBlock::parse(&body),
        Err(I2PError::Malformed(_))
    ));
}

#[test]
fn parse_zero_range_rejected() {
    let body = hex::<7>("0000000a000000");
    assert!(matches!(
        Ssu2AckBlock::parse(&body),
        Err(I2PError::Malformed(_))
    ));
}

#[test]
fn roundtrip_write_parse() {
    let ack = Ssu2AckBlock {
        ack_through: 10,
        acnt: 2,
        ranges: vec![AckRange { nack: 1, ack: 2 }, AckRange { nack: 2, ack: 3 }],
    };
    assert_eq!(ack.to_body(), hex::<9>("0000000a0201020203"));
    assert_eq!(Ssu2AckBlock::parse(&ack.to_body()).unwrap(), ack);
}

#[test]
fn framed_block_dispatch() {
    let ack = Ssu2AckBlock {
        ack_through: 42,
        acnt: 0,
        ranges: vec![],
    };
    let mut payload = Vec::new();
    ack.write(&mut payload).unwrap();

    assert_eq!(payload, hex::<8>("0c00050000002a00"));

    let raw = Blocks::new(&payload).next().unwrap().unwrap();
    assert_eq!(raw.kind(), Some(Ssu2BlockType::Ack));
    let parsed: Ssu2AckBlock = raw.parse().unwrap();
    assert_eq!(parsed, ack);
}

// ---- кодирование из множества полученных --------------------------------

#[test]
fn from_received_spec_example() {
    let received = set([10, 9, 8, 6, 5, 2, 1, 0]);
    let ack = Ssu2AckBlock::from_received(&received).unwrap();
    assert_eq!(ack.ack_through, 10);
    assert_eq!(ack.acnt, 2);
    assert_eq!(
        ack.ranges,
        vec![AckRange { nack: 1, ack: 2 }, AckRange { nack: 2, ack: 3 }]
    );
    assert_eq!(ack.to_body(), hex::<9>("0000000a0201020203"));
}

#[test]
fn from_received_empty_is_none() {
    assert!(Ssu2AckBlock::from_received(&BTreeSet::new()).is_none());
}

#[test]
fn from_received_single() {
    let ack = Ssu2AckBlock::from_received(&set([10])).unwrap();
    assert_eq!(ack.ack_through, 10);
    assert_eq!(ack.acnt, 0);
    assert_eq!(ack.ranges, []);
    assert_eq!(ack.acked_ranges(), vec![(10, 10)]);
}

#[test]
fn from_received_zero_packet() {
    let ack = Ssu2AckBlock::from_received(&set([0])).unwrap();
    assert_eq!(ack.ack_through, 0);
    assert_eq!(ack.acnt, 0);
    assert_eq!(ack.acked_ranges(), vec![(0, 0)]);
}

#[test]
fn from_received_consecutive() {
    let ack = Ssu2AckBlock::from_received(&set(0..=5)).unwrap();
    assert_eq!(ack.ack_through, 5);
    assert_eq!(ack.acnt, 5);
    assert_eq!(ack.ranges, []);
    assert_eq!(ack.acked_ranges(), vec![(0, 5)]);
}

#[test]
fn from_received_run_longer_than_acnt() {
    let received = set(0..=300);
    let ack = Ssu2AckBlock::from_received(&received).unwrap();
    assert_eq!(ack.ack_through, 300);
    assert_eq!(ack.acnt, SSU2_MAX_NUM_ACNT);
    assert_eq!(ack.ranges, vec![AckRange { nack: 0, ack: 45 }]);

    // Декодирование восстанавливает всё множество.
    for p in 0..=300u32 {
        assert!(ack.contains(p), "missing {p}");
    }
    assert!(!ack.contains(301));
}

#[test]
fn from_received_large_gap() {
    let received = set([0, 300]);
    let ack = Ssu2AckBlock::from_received(&received).unwrap();
    assert_eq!(ack.ack_through, 300);
    assert_eq!(ack.acnt, 0);
    assert_eq!(
        ack.ranges,
        vec![
            AckRange { nack: 255, ack: 0 },
            AckRange { nack: 44, ack: 1 }
        ]
    );
    assert_eq!(ack.acked_ranges(), vec![(300, 300), (0, 0)]);
}

#[test]
fn from_received_huge_gap_splits_nack() {
    let limits = AckLimits {
        max_packets: 1024,
        ..AckLimits::default()
    };
    let ack = Ssu2AckBlock::from_received_with(&set([0, 600]), limits).unwrap();
    assert_eq!(
        ack.ranges,
        vec![
            AckRange { nack: 255, ack: 0 },
            AckRange { nack: 255, ack: 0 },
            AckRange { nack: 89, ack: 1 },
        ]
    );
    assert_eq!(ack.acked_ranges(), vec![(600, 600), (0, 0)]);
}

#[test]
fn from_received_respects_max_ranges() {
    // Каждый полученный номер отстоит на 2 -> по одному диапазону (1,1).
    let received = set([10, 8, 6, 4, 2, 0]);
    let limits = AckLimits {
        max_ranges: 2,
        ..AckLimits::default()
    };
    let ack = Ssu2AckBlock::from_received_with(&received, limits).unwrap();
    assert_eq!(ack.ranges.len(), 2);
    // Последний диапазон всегда заканчивается подтверждением.
    assert!(ack.ranges.last().unwrap().ack >= 1);
    // Подмножество полученных.
    let acked: Vec<u32> = ack
        .acked_ranges()
        .iter()
        .flat_map(|&(lo, hi)| lo..=hi)
        .collect();
    assert!(acked.iter().all(|p| received.contains(p)));
}

#[test]
fn from_received_respects_max_acnt() {
    let limits = AckLimits {
        max_acnt: 2,
        ..AckLimits::default()
    };
    let ack = Ssu2AckBlock::from_received_with(&set(0..=10), limits).unwrap();
    assert_eq!(ack.acnt, 2);
    assert_eq!(ack.ranges, vec![AckRange { nack: 0, ack: 8 }]);
    let acked: BTreeSet<u32> = ack
        .acked_ranges()
        .iter()
        .flat_map(|&(lo, hi)| lo..=hi)
        .collect();
    assert_eq!(acked, set(0..=10));
}

#[test]
fn from_received_honours_window() {
    // Старые номера вне окна забываются.
    let limits = AckLimits {
        max_packets: 10,
        ..AckLimits::default()
    };
    let ack = Ssu2AckBlock::from_received_with(&set([100, 95, 1, 0]), limits).unwrap();
    assert_eq!(ack.ack_through, 100);
    assert!(ack.contains(100));
    assert!(ack.contains(95));
    assert!(!ack.contains(1));
    assert!(!ack.contains(0));
}

#[test]
fn limits_default_matches_constants() {
    let l = AckLimits::default();
    assert_eq!(l.max_acnt, SSU2_MAX_NUM_ACNT);
    assert_eq!(l.max_ranges, SSU2_MAX_NUM_ACK_RANGES);
    assert_eq!(l.max_packets, SSU2_MAX_NUM_ACK_PACKETS);
}
