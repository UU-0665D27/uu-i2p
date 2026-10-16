use uu_i2p::{
    EciesDelivery, EciesGarlicClove, GarlicBlock, IdentHash,
    error::I2PError,
    garlic_block::{
        BLK_ACK, BLK_ACK_REQUEST, BLK_DATETIME, BLK_GARLIC_CLOVE, BLK_NEXT_KEY, BLK_OPTIONS,
        BLK_PADDING, BLK_SESSION_ID, BLK_TERMINATION, NextKeyBlock,
    },
    i2np::I2npMessageType,
    parse_blocks, serialize_blocks,
};

const fn ident(n: u8) -> IdentHash {
    IdentHash::from_array([n; 32])
}
fn roundtrip_block(block: &GarlicBlock) {
    let bytes = block.to_buffer().unwrap();
    let (parsed, consumed) = GarlicBlock::from_buffer(&bytes).unwrap();
    assert_eq!(consumed, bytes.len(), "must consume full buffer");
    assert_eq!(&parsed, block);
}

// ---- constants ----------------------------------------------------

#[test]
fn block_type_constants_match_spec() {
    assert_eq!(BLK_DATETIME, 0);
    assert_eq!(BLK_SESSION_ID, 1);
    assert_eq!(BLK_TERMINATION, 4);
    assert_eq!(BLK_OPTIONS, 5);
    assert_eq!(BLK_NEXT_KEY, 7);
    assert_eq!(BLK_ACK, 8);
    assert_eq!(BLK_ACK_REQUEST, 9);
    assert_eq!(BLK_GARLIC_CLOVE, 11);
    assert_eq!(BLK_PADDING, 254);
}

// ---- round-trips ---------------------------------------------------

#[test]
fn roundtrip_datetime() {
    roundtrip_block(&GarlicBlock::DateTime(1_700_000_000));
}

#[test]
fn roundtrip_session_id() {
    roundtrip_block(&GarlicBlock::SessionId(vec![0, 5]));
}

#[test]
fn roundtrip_termination() {
    roundtrip_block(&GarlicBlock::Termination {
        seqn: 0xDEAD_BEEF_CAFE_BABE,
        reason: 3,
    });
}

#[test]
fn roundtrip_options() {
    roundtrip_block(&GarlicBlock::Options(vec![1, 2, 3]));
}

#[test]
fn roundtrip_next_key() {
    // Реальная структура NextKey будет разобрана в session-state
    // machine; пока блок хранит raw-байты, кладём осмысленный
    // пример: флаг KeyPresent (0x01) + keyID (u16 BE) + pub key.
    roundtrip_block(&GarlicBlock::NextKey(vec![
        0x01, 0x00, 0x00, 0xAA, 0xBB, 0xCC,
    ]));
}

#[test]
fn roundtrip_ack() {
    roundtrip_block(&GarlicBlock::Ack(vec![(1, 100), (2, 200), (3, 300)]));
}

#[test]
fn roundtrip_ack_request() {
    roundtrip_block(&GarlicBlock::AckRequest);
}

#[test]
fn roundtrip_garlic_clove() {
    let clove = EciesGarlicClove {
        delivery: EciesDelivery::Destination(ident(0x11)),
        message_type: I2npMessageType::Data,
        message_id: 42,
        // 1_700_000_000_000 мс = 1_700_000_000 сек
        expiration_secs: 1_700_000_000,
        payload: b"hello".to_vec(),
    };
    roundtrip_block(&GarlicBlock::EciesGarlicClove(clove));
}

#[test]
fn roundtrip_padding() {
    roundtrip_block(&GarlicBlock::Padding(13));
}

#[test]
fn roundtrip_padding_zero() {
    roundtrip_block(&GarlicBlock::Padding(0));
}

#[test]
fn roundtrip_unknown() {
    roundtrip_block(&GarlicBlock::Unknown {
        type_id: 99,
        data: vec![1, 2, 3, 4],
    });
}

// ---- lists ---------------------------------------------------------

#[test]
fn blocks_roundtrip_multiple() {
    let blocks = vec![
        GarlicBlock::DateTime(1_700_000_000),
        GarlicBlock::Ack(vec![(1, 2)]),
        GarlicBlock::EciesGarlicClove(EciesGarlicClove {
            delivery: EciesDelivery::Local,
            message_type: I2npMessageType::Data,
            message_id: 1,
            expiration_secs: 100,
            payload: b"a".to_vec(),
        }),
        GarlicBlock::EciesGarlicClove(EciesGarlicClove {
            delivery: EciesDelivery::Local,
            message_type: I2npMessageType::Data,
            message_id: 2,
            expiration_secs: 200,
            payload: b"bb".to_vec(),
        }),
        GarlicBlock::Padding(7),
    ];
    let wire = serialize_blocks(&blocks).unwrap();
    let parsed = parse_blocks(&wire).unwrap();
    assert_eq!(parsed, blocks);
}

#[test]
fn blocks_empty() {
    let wire = serialize_blocks(&[]).unwrap();
    assert!(wire.is_empty(), "wire must be empty");
    let parsed = parse_blocks(&wire).unwrap();
    assert!(parsed.is_empty(), "expected no blocks");
}

// ---- golden bytes --------------------------------------------------

#[test]
fn datetime_golden_bytes() {
    let block = GarlicBlock::DateTime(0x1122_3344);
    let bytes = block.to_buffer().unwrap();
    assert_eq!(
        bytes,
        [
            0x00, // type_id = DateTime
            0x00, 0x04, // size = 4
            0x11, 0x22, 0x33, 0x44, // timestamp
        ]
    );
}

#[test]
fn padding_golden_bytes() {
    let block = GarlicBlock::Padding(3);
    let bytes = block.to_buffer().unwrap();
    assert_eq!(
        bytes,
        [
            0xFE, // type_id = Padding
            0x00, 0x03, // size = 3
            0x00, 0x00, 0x00, // три нуля
        ]
    );
}

#[test]
fn ack_golden_bytes() {
    let block = GarlicBlock::Ack(vec![(0x0001, 0x000A), (0x0002, 0x0014)]);
    let bytes = block.to_buffer().unwrap();
    assert_eq!(
        bytes,
        [
            0x08, // type_id = Ack
            0x00, 0x08, // size = 8
            0x00, 0x01, 0x00, 0x0A, // (1, 10)
            0x00, 0x02, 0x00, 0x14, // (2, 20)
        ]
    );
}

#[test]
fn ack_request_golden_bytes() {
    let block = GarlicBlock::AckRequest;
    let bytes = block.to_buffer().unwrap();
    assert_eq!(
        bytes,
        [
            0x09, // type_id = AckRequest
            0x00, 0x01, // size = 1
            0x00, // flags
        ]
    );
}

#[test]
fn termination_golden_bytes() {
    let block = GarlicBlock::Termination {
        seqn: 0x0102_0304_0506_0708,
        reason: 42,
    };
    let bytes = block.to_buffer().unwrap();
    assert_eq!(
        bytes,
        [
            0x04, // type_id = Termination
            0x00, 0x09, // size = 9
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // seqn
            0x2A, // reason = 42
        ]
    );
}

// ---- errors --------------------------------------------------------

#[test]
fn short_buffer_fails() {
    let r = GarlicBlock::from_buffer(&[0, 0]);
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}

#[test]
fn size_exceeds_buffer_fails() {
    let r = GarlicBlock::from_buffer(&[BLK_DATETIME, 0, 0x10]);
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}

#[test]
fn datetime_wrong_size_fails() {
    let r = GarlicBlock::from_buffer(&[BLK_DATETIME, 0, 3, 0, 0, 0]);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn termination_wrong_size_fails() {
    let r = GarlicBlock::from_buffer(&[BLK_TERMINATION, 0, 4, 0, 0, 0, 0]);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn ack_wrong_size_fails() {
    // size = 5, не кратно 4
    let r = GarlicBlock::from_buffer(&[BLK_ACK, 0, 5, 0, 0, 0, 0, 0]);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn parse_blocks_partial_fails() {
    // Первый блок валидный, второй — size выходит за границы
    let mut buf = GarlicBlock::DateTime(1).to_buffer().unwrap();
    buf.extend_from_slice(&[BLK_DATETIME, 0, 0x10, 0, 0, 0, 0]);
    let r = parse_blocks(&buf);
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}
#[test]
fn next_key_block_roundtrip_with_key() {
    let block = NextKeyBlock::with_key(NextKeyBlock::REQUEST_REVERSE_KEY_FLAG, 42, [0xAB; 32]);
    let bytes = block.to_bytes();
    assert_eq!(bytes.len(), 35);
    assert_eq!(bytes[0], 0x01 | 0x04); // KEY_PRESENT | REQUEST_REVERSE
    assert_eq!(&bytes[1..3], &[0x00, 0x2A]);
    assert_eq!(&bytes[3..], &[0xAB; 32]);

    let back = NextKeyBlock::parse(&bytes).unwrap();
    assert_eq!(back, block);
}

#[test]
fn next_key_block_roundtrip_without_key() {
    let block = NextKeyBlock::without_key(NextKeyBlock::REVERSE_KEY_FLAG, 7);
    let bytes = block.to_bytes();
    assert_eq!(bytes.len(), 3);
    let back = NextKeyBlock::parse(&bytes).unwrap();
    assert_eq!(back, block);
    assert!(back.is_reverse_key());
    assert!(back.public_key.is_none());
}

#[test]
fn next_key_block_parse_short() {
    let r = NextKeyBlock::parse(&[0x01, 0x00]);
    assert!(matches!(
        r,
        Err(I2PError::InvalidLength {
            expected: 3,
            got: 2
        })
    ));
}

#[test]
fn next_key_block_parse_key_present_but_short() {
    let r = NextKeyBlock::parse(&[0x01, 0x00, 0x01]);
    assert!(matches!(
        r,
        Err(I2PError::InvalidLength {
            expected: 35,
            got: 3
        })
    ));
}

#[test]
fn next_key_block_parse_extra_bytes_without_key() {
    let r = NextKeyBlock::parse(&[0x00, 0x00, 0x01, 0xAA]);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}
