//! Тесты для [`uu_i2p::garlic_body::GarlicBody`].

use uu_i2p::error::I2PError;
use uu_i2p::garlic_body::GarlicBody;
use uu_i2p::i2np::I2npMessageType;
use uu_i2p::i2np_message::{I2npBody, I2npMessage};

// --- чистый GarlicBody ---------------------------------------------------

#[test]
fn empty_roundtrip() {
    let b = GarlicBody::new(vec![]);
    let wire = b.to_buffer().unwrap();
    assert_eq!(wire, [0, 0, 0, 0]);
    let parsed = GarlicBody::from_buffer(&wire).unwrap();
    assert_eq!(parsed, b);
}

#[test]
fn small_roundtrip() {
    let b = GarlicBody::new(vec![0x01, 0x02, 0x03]);
    let wire = b.to_buffer().unwrap();
    assert_eq!(wire, [0, 0, 0, 3, 0x01, 0x02, 0x03]);
    let parsed = GarlicBody::from_buffer(&wire).unwrap();
    assert_eq!(parsed, b);
}

#[test]
fn large_roundtrip() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let b = GarlicBody::new(payload);
    let wire = b.to_buffer().unwrap();
    let parsed = GarlicBody::from_buffer(&wire).unwrap();
    assert_eq!(parsed, b);
}

#[test]
fn max_realistic_payload_roundtrip() {
    // I2NP_MAX_MESSAGE_SIZE = 62_708; минус 16 байт I2NP-заголовка,
    // минус 4 байта length-префикса = 62_688 байт payload'а.
    let payload = vec![0xABu8; 62_688];
    let b = GarlicBody::new(payload);
    let wire = b.to_buffer().unwrap();
    let parsed = GarlicBody::from_buffer(&wire).unwrap();
    assert_eq!(parsed, b);
}

#[test]
fn empty_buffer_invalid() {
    assert!(matches!(
        GarlicBody::from_buffer(&[]),
        Err(I2PError::InvalidLength {
            expected: 4,
            got: 0
        })
    ));
}

#[test]
fn short_header_invalid() {
    assert!(matches!(
        GarlicBody::from_buffer(&[0, 0, 0]),
        Err(I2PError::InvalidLength {
            expected: 4,
            got: 3
        })
    ));
}

#[test]
fn declared_length_exceeds_buffer() {
    // length=10, но после префикса только 3 байта
    let buf = [0, 0, 0, 10, 0xAA, 0xBB, 0xCC];
    assert!(matches!(
        GarlicBody::from_buffer(&buf),
        Err(I2PError::InvalidLength {
            expected: 14,
            got: 7
        })
    ));
}

#[test]
fn trailing_bytes_ignored() {
    // length=2, payload=ABCD, хвост DEAD — игнорируется
    let buf = [0, 0, 0, 2, 0xAB, 0xCD, 0xDE, 0xAD];
    let b = GarlicBody::from_buffer(&buf).unwrap();
    assert_eq!(b.payload, vec![0xAB, 0xCD]);
    // Канонический ре-сериализованный вид — без хвоста.
    assert_eq!(b.to_buffer().unwrap(), [0, 0, 0, 2, 0xAB, 0xCD]);
}

#[test]
fn payload_len_matches_buffer() {
    let b = GarlicBody::new(vec![0u8; 517]);
    assert_eq!(b.payload_len(), 517);
    assert!(!b.is_empty());
}

#[test]
fn is_empty_after_new_empty() {
    let b = GarlicBody::new(vec![]);
    assert!(b.is_empty());
    assert_eq!(b.payload_len(), 0);
}

#[test]
fn to_buffer_is_stable() {
    let b = GarlicBody::new(vec![0xAB; 8]);
    let w1 = b.to_buffer().unwrap();
    let w2 = b.to_buffer().unwrap();
    assert_eq!(w1, w2);
}

#[test]
fn wire_layout_matches_spec() {
    // 4-байтовый BE u32 длина, затем payload. Никаких других полей.
    let b = GarlicBody::new(vec![0xAA, 0xBB]);
    let wire = b.to_buffer().unwrap();
    assert_eq!(wire.len(), 6);
    assert_eq!(&wire[..4], &[0, 0, 0, 2]); // BE u32
    assert_eq!(&wire[4..], &[0xAA, 0xBB]);
}

#[test]
fn length_prefix_size_constant() {
    assert_eq!(GarlicBody::LENGTH_PREFIX_SIZE, 4);
}

// --- conversions ---------------------------------------------------------

#[test]
fn from_vec_roundtrip() {
    let payload = vec![1, 2, 3, 4];
    let b: GarlicBody = payload.clone().into();
    assert_eq!(b.payload, payload);

    let back: Vec<u8> = b.into();
    assert_eq!(back, payload);
}

#[test]
fn as_ref_is_slice() {
    let b = GarlicBody::new(vec![0xAA, 0xBB, 0xCC]);
    let s: &[u8] = b.as_ref();
    assert_eq!(s, &[0xAA, 0xBB, 0xCC]);
}

// --- GarlicBody внутри I2npBody ------------------------------------------

#[test]
fn body_garlic_message_type() {
    let body = I2npBody::Garlic(GarlicBody::new(vec![1, 2, 3]));
    assert_eq!(body.message_type(), I2npMessageType::Garlic);
}

#[test]
fn body_garlic_roundtrip_via_i2np_message() {
    let payload: Vec<u8> = (0..200u8).collect();
    let body = I2npBody::Garlic(GarlicBody::new(payload.clone()));

    let msg = I2npMessage::from_body(body.clone()).unwrap();
    assert_eq!(msg.message_type(), I2npMessageType::Garlic);

    let parsed = msg.parse_body().unwrap();
    assert_eq!(parsed, body);
    match parsed {
        I2npBody::Garlic(g) => assert_eq!(g.payload, payload),
        other => panic!("unexpected body: {other:?}"),
    }
}

#[test]
fn body_garlic_to_payload_matches_direct_to_buffer() {
    let body = I2npBody::Garlic(GarlicBody::new(vec![9, 8, 7]));
    let via_body = body.to_payload().unwrap();
    let direct = GarlicBody::new(vec![9, 8, 7]).to_buffer().unwrap();
    assert_eq!(via_body, direct);
}

#[test]
fn body_garlic_into_payload_matches_to_payload() {
    let body = I2npBody::Garlic(GarlicBody::new(vec![1, 1, 2, 3, 5]));
    let a = body.to_payload().unwrap();
    let b = body.into_payload().unwrap();
    assert_eq!(a, b);
}

#[test]
fn body_garlic_empty_roundtrip_via_i2np_message() {
    let body = I2npBody::Garlic(GarlicBody::new(vec![]));
    let msg = I2npMessage::from_body(body.clone()).unwrap();
    // payload на wire = 4 байта (только length=0)
    assert_eq!(msg.payload().len(), 4);
    assert_eq!(msg.payload(), &[0, 0, 0, 0]);
    assert_eq!(msg.parse_body().unwrap(), body);
}

#[test]
fn body_garlic_via_i2np_ntcp2_bytes_roundtrip() {
    // Прогон через "короткий" NTCP2-формат I2NP-сообщения —
    // это то, что реально уходит в data phase NTCP2.
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let body = I2npBody::Garlic(GarlicBody::new(payload));
    let msg = I2npMessage::from_body(body.clone()).unwrap();

    let ntcp2_bytes = msg.to_ntcp2_bytes();
    let parsed_msg = I2npMessage::from_ntcp2_bytes(&ntcp2_bytes).unwrap();
    let parsed_body = parsed_msg.parse_body().unwrap();
    assert_eq!(parsed_body, body);
}

#[test]
fn body_garlic_malformed_payload_fails() {
    // Собираем I2NP с типом Garlic и payload короче 4 байт —
    // GarlicBody::from_buffer должен вернуть InvalidLength.
    let msg = I2npMessage::new(I2npMessageType::Garlic, vec![0, 0]);
    assert!(matches!(
        msg.parse_body(),
        Err(I2PError::InvalidLength { .. })
    ));
}

#[test]
fn body_garlic_declared_length_exceeds_payload_fails() {
    // length=100, но payload всего 4 байта
    let msg = I2npMessage::new(
        I2npMessageType::Garlic,
        vec![0, 0, 0, 100, 0xAA, 0xBB, 0xCC, 0xDD],
    );
    assert!(matches!(
        msg.parse_body(),
        Err(I2PError::InvalidLength {
            expected: 104,
            got: 8
        })
    ));
}
