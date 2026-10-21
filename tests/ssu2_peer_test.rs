//! Подписанные данные `PeerTest`: раскладка, подпись и проверка.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use uu_i2p::error::I2PError;
use uu_i2p::private_keys::I2PPrivateKeys;
use uu_i2p::ssu2_peer_test::{PEER_TEST_PROLOGUE, PEER_TEST_VERSION, PeerTestSignedData, sign};

const BHASH: [u8; 32] = [0x11; 32];
const AHASH: [u8; 32] = [0x22; 32];
const NONCE: u32 = 0xd3f0_a8c9;
const TS: u32 = 0x6ad7_f7f2;

fn alice() -> I2PPrivateKeys {
    I2PPrivateKeys::generate_default().expect("Alice keys")
}

fn charlie() -> I2PPrivateKeys {
    I2PPrivateKeys::generate_default().expect("Charlie keys")
}

#[test]
fn prologue_is_i2pd_string() {
    assert_eq!(PEER_TEST_PROLOGUE, b"PeerTestValidate");
    assert_eq!(PEER_TEST_PROLOGUE.len(), 16);
}

#[test]
fn unsigned_layout_matches_i2pd() {
    let data = sign(
        &alice(),
        &BHASH,
        None,
        NONCE,
        TS,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
    )
    .expect("sign");
    let bytes = data.unsigned_bytes();
    assert_eq!(bytes.len(), 16);
    assert_eq!(bytes[0], PEER_TEST_VERSION);
    assert_eq!(&bytes[1..5], &NONCE.to_be_bytes());
    assert_eq!(&bytes[5..9], &TS.to_be_bytes());
    assert_eq!(bytes[9], 6, "asz для IPv4");
    assert_eq!(&bytes[10..12], &12345u16.to_be_bytes());
    assert_eq!(&bytes[12..16], &[127, 0, 0, 1]);
}

#[test]
fn sign_and_verify_msg1() {
    let alice = alice();
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 12345));
    let data = sign(&alice, &BHASH, None, NONCE, TS, endpoint).expect("sign");
    let parsed = PeerTestSignedData::parse(&data.to_bytes()).expect("parse");
    assert_eq!(parsed.version, PEER_TEST_VERSION);
    assert_eq!(parsed.nonce, NONCE);
    assert_eq!(parsed.timestamp, TS);
    assert_eq!(parsed.endpoint, endpoint);
    parsed
        .verify(alice.public(), &BHASH, None)
        .expect("подпись Алисы");
}

#[test]
fn sign_and_verify_ipv6_endpoint() {
    let charlie = charlie();
    let endpoint = SocketAddr::from((Ipv6Addr::LOCALHOST, 12346));
    let data = sign(&charlie, &BHASH, Some(&AHASH), NONCE, TS, endpoint).expect("sign");
    let parsed = PeerTestSignedData::parse(&data.to_bytes()).expect("parse");
    assert_eq!(parsed.endpoint, endpoint);
    assert_eq!(parsed.unsigned_bytes().len(), 10 + 18);
    parsed
        .verify(charlie.public(), &BHASH, Some(&AHASH))
        .expect("подпись Charlie");
}

#[test]
fn verify_rejects_wrong_bhash() {
    let alice = alice();
    let data = sign(
        &alice,
        &BHASH,
        None,
        NONCE,
        TS,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
    )
    .expect("sign");
    let parsed = PeerTestSignedData::parse(&data.to_bytes()).expect("parse");
    let wrong = [0x33; 32];
    assert!(
        parsed.verify(alice.public(), &wrong, None).is_err(),
        "bhash входит в подпись"
    );
}

#[test]
fn verify_rejects_missing_ahash_for_charlie_signature() {
    let charlie = charlie();
    let data = sign(
        &charlie,
        &BHASH,
        Some(&AHASH),
        NONCE,
        TS,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
    )
    .expect("sign");
    let parsed = PeerTestSignedData::parse(&data.to_bytes()).expect("parse");
    assert!(
        parsed.verify(charlie.public(), &BHASH, None).is_err(),
        "ahash входит в подпись Charlie"
    );
    parsed
        .verify(charlie.public(), &BHASH, Some(&AHASH))
        .expect("с ahash подпись сходится");
}

#[test]
fn verify_rejects_tampered_nonce() {
    let alice = alice();
    let data = sign(
        &alice,
        &BHASH,
        None,
        NONCE,
        TS,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
    )
    .expect("sign");
    let mut bytes = data.to_bytes();
    bytes[4] ^= 0x01;
    let parsed = PeerTestSignedData::parse(&bytes).expect("parse");
    assert!(parsed.verify(alice.public(), &BHASH, None).is_err());
}

#[test]
fn verify_rejects_tampered_endpoint() {
    let alice = alice();
    let data = sign(
        &alice,
        &BHASH,
        None,
        NONCE,
        TS,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
    )
    .expect("sign");
    let mut bytes = data.to_bytes();
    bytes[10..12].copy_from_slice(&54321u16.to_be_bytes());
    let parsed = PeerTestSignedData::parse(&bytes).expect("parse");
    assert!(parsed.verify(alice.public(), &BHASH, None).is_err());
}

#[test]
fn verify_rejects_other_identity() {
    let alice = alice();
    let charlie = charlie();
    let data = sign(
        &alice,
        &BHASH,
        None,
        NONCE,
        TS,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
    )
    .expect("sign");
    let parsed = PeerTestSignedData::parse(&data.to_bytes()).expect("parse");
    assert!(parsed.verify(charlie.public(), &BHASH, None).is_err());
}

#[test]
fn parse_rejects_truncated_and_bad_sizes() {
    assert!(matches!(
        PeerTestSignedData::parse(&[0u8; 9]),
        Err(I2PError::Malformed(_))
    ));

    let mut bytes = Vec::new();
    bytes.push(PEER_TEST_VERSION);
    bytes.extend_from_slice(&NONCE.to_be_bytes());
    bytes.extend_from_slice(&TS.to_be_bytes());
    bytes.push(10); // asz, но endpoint'а нет
    assert!(matches!(
        PeerTestSignedData::parse(&bytes),
        Err(I2PError::Malformed(_))
    ));

    let mut bytes = Vec::new();
    bytes.push(PEER_TEST_VERSION);
    bytes.extend_from_slice(&NONCE.to_be_bytes());
    bytes.extend_from_slice(&TS.to_be_bytes());
    bytes.push(7); // asz, которого не бывает
    bytes.extend_from_slice(&[0u8; 7]);
    bytes.extend_from_slice(&[0u8; 64]);
    assert!(matches!(
        PeerTestSignedData::parse(&bytes),
        Err(I2PError::Malformed(_))
    ));

    let mut bytes = Vec::new();
    bytes.push(PEER_TEST_VERSION);
    bytes.extend_from_slice(&NONCE.to_be_bytes());
    bytes.extend_from_slice(&TS.to_be_bytes());
    bytes.push(6);
    bytes.extend_from_slice(&[0u8; 6]);
    assert!(matches!(
        PeerTestSignedData::parse(&bytes),
        Err(I2PError::Malformed(_))
    ));
}

#[test]
fn charlie_signature_is_reused_in_msg4() {
    // i2pd подписывает msg 2 теми же данными, что Боб затем пересылает в
    // msg 4 (`SSU2Session.cpp:2624` и `:2742`), поэтому подпись проверяется
    // одинаково.
    let charlie = charlie();
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 23456));
    let data = sign(&charlie, &BHASH, Some(&AHASH), NONCE, TS, endpoint).expect("sign");
    let bytes = data.to_bytes();
    let msg2 = PeerTestSignedData::parse(&bytes).expect("msg2");
    let msg4 = PeerTestSignedData::parse(&bytes).expect("msg4");
    msg2.verify(charlie.public(), &BHASH, Some(&AHASH))
        .expect("msg 2");
    msg4.verify(charlie.public(), &BHASH, Some(&AHASH))
        .expect("msg 4");
}

#[test]
fn out_of_session_packet_roundtrip() {
    let key = [7u8; 32];
    let source = uu_i2p::ssu2_header::ConnectionId::new([1u8; 8]);
    let dest = uu_i2p::ssu2_header::ConnectionId::new([2u8; 8]);
    let signed = vec![9u8; 70];
    let packet = uu_i2p::ssu2_peer_test::build_packet(&uu_i2p::ssu2_peer_test::PeerTestPacket {
        intro_key: &key,
        dest,
        source,
        msg: 5,
        signed_data: &signed,
        address: None,
        packet_num: 0x1234_5678,
        net_id: 2,
        timestamp_secs: 1_700_000_000,
        max_payload: 1452,
    })
    .expect("build");
    let mut raw = packet;
    let opened = uu_i2p::ssu2_peer_test::open_packet(&key, &mut raw).expect("open");
    assert_eq!(opened.dest, dest);
    assert_eq!(opened.source, source);
    let payload = uu_i2p::ssu2_peer_test::parse_payload(&opened.payload);
    assert_eq!(payload.peer_test.expect("block").msg, 5);
}
