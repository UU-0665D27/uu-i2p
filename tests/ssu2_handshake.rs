use uu_i2p::{
    crypto::I2PX25519Keys,
    ssu2_block::{Blocks, DateTimeBlock, Ssu2BlockType},
    ssu2_crypto::derive_data_phase_keys,
    ssu2_handshake::{
        InitiatorHandshake, ResponderHandshake, SessionCreatedParams, SessionRequestParams,
        SSU2_SESSION_REQUEST_MIN_LEN,
    },
    ssu2_header::ConnectionId,
    ssu2_policy::I2pdPolicy,
};

const NOW: u32 = 1_700_000_000;
const ALICE_ID: ConnectionId = ConnectionId::from_u64(0xAAAA_AAAA_AAAA_AAAA);
const BOB_ID: ConnectionId = ConnectionId::from_u64(0xBBBB_BBBB_BBBB_BBBB);
const TOKEN: u64 = 0x0123_4567_89AB_CDEF;

fn keys() -> I2PX25519Keys {
    I2PX25519Keys::generate()
}

struct Pair {
    alice: InitiatorHandshake,
    bob: ResponderHandshake,
    alice_id: ConnectionId,
    bob_id: ConnectionId,
}

fn pair(config: uu_i2p::ssu2_handshake::HandshakeConfig) -> Pair {
    let alice_static = keys();
    let bob_static = keys();
    let bob_intro = [0x11u8; 32];
    let alice = InitiatorHandshake::new(alice_static, *bob_static.public_key(), bob_intro, config);
    let bob = ResponderHandshake::new(bob_static, bob_intro, config);
    Pair {
        alice,
        bob,
        alice_id: ALICE_ID,
        bob_id: BOB_ID,
    }
}

fn request_params(relay_tag_requested: bool) -> SessionRequestParams {
    SessionRequestParams {
        dest_conn_id: BOB_ID,
        source_conn_id: ALICE_ID,
        token: TOKEN,
        packet_num: 7,
        now_secs: NOW,
        relay_tag_requested,
        pad_roll: 0xFF,
    }
}

#[test]
fn session_request_created_roundtrip() {
    let policy = I2pdPolicy;
    let config = uu_i2p::ssu2_handshake::HandshakeConfig::default();
    let mut p = pair(config);

    let mut sr = p
        .alice
        .build_session_request(&policy, &request_params(false))
        .unwrap();
    assert!(sr.len() >= SSU2_SESSION_REQUEST_MIN_LEN);

    let received = p.bob.handle_session_request(&policy, &mut sr).unwrap();
    assert_eq!(received.dest_conn_id, p.bob_id);
    assert_eq!(received.source_conn_id, p.alice_id);
    assert_eq!(received.token, TOKEN);

    // payload начинается с DateTime с ожидаемым временем.
    let mut blocks = Blocks::new(&received.payload);
    let first = blocks.next().unwrap().unwrap();
    assert_eq!(first.kind(), Some(Ssu2BlockType::DateTime));
    let dt: DateTimeBlock = first.parse().unwrap();
    assert_eq!(dt.timestamp, NOW);

    // Bob отвечает SessionCreated.
    let created = SessionCreatedParams {
        dest_conn_id: received.source_conn_id,
        source_conn_id: p.bob_id,
        packet_num: 9,
        now_secs: NOW + 1,
        extra_blocks: &[],
        pad_roll: 0xFF,
    };
    let mut sc = p.bob.build_session_created(&policy, &created).unwrap();
    let received_sc = p.alice.handle_session_created(&policy, &mut sc).unwrap();
    assert_eq!(received_sc.source_conn_id, p.bob_id);
    assert_eq!(received_sc.dest_conn_id, p.alice_id);

    let mut blocks = Blocks::new(&received_sc.payload);
    let first = blocks.next().unwrap().unwrap();
    assert_eq!(first.kind(), Some(Ssu2BlockType::DateTime));
    let dt: DateTimeBlock = first.parse().unwrap();
    assert_eq!(dt.timestamp, NOW + 1);

    // Обе стороны вышли на один chaining key -> одинаковые ключи data phase.
    assert_eq!(p.alice.chain_key(), p.bob.chain_key());
    assert_eq!(
        derive_data_phase_keys(p.alice.chain_key()),
        derive_data_phase_keys(p.bob.chain_key())
    );
}

#[test]
fn session_request_includes_relay_tag_request() {
    let policy = I2pdPolicy;
    let mut p = pair(uu_i2p::ssu2_handshake::HandshakeConfig::default());

    let mut sr = p
        .alice
        .build_session_request(&policy, &request_params(true))
        .unwrap();
    let received = p.bob.handle_session_request(&policy, &mut sr).unwrap();

    let kinds: Vec<_> = Blocks::new(&received.payload)
        .map(|b| b.unwrap().kind())
        .collect();
    assert_eq!(kinds[0], Some(Ssu2BlockType::DateTime));
    assert_eq!(kinds[1], Some(Ssu2BlockType::RelayTagRequest));
}

#[test]
fn session_created_pads_payload() {
    let policy = I2pdPolicy;
    let mut p = pair(uu_i2p::ssu2_handshake::HandshakeConfig::default());

    let mut sr = p
        .alice
        .build_session_request(&policy, &request_params(false))
        .unwrap();
    let received = p.bob.handle_session_request(&policy, &mut sr).unwrap();
    let created = SessionCreatedParams {
        dest_conn_id: received.source_conn_id,
        source_conn_id: p.bob_id,
        packet_num: 9,
        now_secs: NOW + 1,
        extra_blocks: &[],
        pad_roll: 0xFF,
    };
    let mut sc = p.bob.build_session_created(&policy, &created).unwrap();
    let received_sc = p.alice.handle_session_created(&policy, &mut sc).unwrap();

    let blocks: Vec<_> = Blocks::new(&received_sc.payload)
        .map(|b| b.unwrap())
        .collect();
    let last = blocks.last().unwrap();
    assert_eq!(last.kind(), Some(Ssu2BlockType::Padding));
    assert!(last.body.iter().all(|b| *b == 0));
}

#[test]
fn tampered_session_created_is_rejected() {
    let policy = I2pdPolicy;
    let mut p = pair(uu_i2p::ssu2_handshake::HandshakeConfig::default());

    let mut sr = p
        .alice
        .build_session_request(&policy, &request_params(false))
        .unwrap();
    let received = p.bob.handle_session_request(&policy, &mut sr).unwrap();
    let created = SessionCreatedParams {
        dest_conn_id: received.source_conn_id,
        source_conn_id: p.bob_id,
        packet_num: 9,
        now_secs: NOW + 1,
        extra_blocks: &[],
        pad_roll: 0xFF,
    };
    let mut sc = p.bob.build_session_created(&policy, &created).unwrap();
    let last = sc.len() - 1;
    sc[last] ^= 0x01;

    assert!(p.alice.handle_session_created(&policy, &mut sc).is_err());
}

#[test]
fn too_short_packets_are_rejected() {
    let policy = I2pdPolicy;
    let mut p = pair(uu_i2p::ssu2_handshake::HandshakeConfig::default());

    let mut request = vec![0u8; SSU2_SESSION_REQUEST_MIN_LEN - 1];
    assert!(p.bob.handle_session_request(&policy, &mut request).is_err());

    let mut created = vec![0u8; 40];
    assert!(p
        .alice
        .handle_session_created(&policy, &mut created)
        .is_err());
}

#[test]
fn session_created_needs_request_first() {
    let policy = I2pdPolicy;
    let mut p = pair(uu_i2p::ssu2_handshake::HandshakeConfig::default());
    let created = SessionCreatedParams {
        dest_conn_id: ALICE_ID,
        source_conn_id: BOB_ID,
        packet_num: 9,
        now_secs: NOW,
        extra_blocks: &[],
        pad_roll: 0,
    };
    assert!(p.bob.build_session_created(&policy, &created).is_err());
}

#[test]
fn oversized_session_created_is_rejected() {
    let policy = I2pdPolicy;
    let mut p = pair(uu_i2p::ssu2_handshake::HandshakeConfig::default());

    let mut sr = p
        .alice
        .build_session_request(&policy, &request_params(false))
        .unwrap();
    let received = p.bob.handle_session_request(&policy, &mut sr).unwrap();

    let big = vec![0u8; 4000];
    let created = SessionCreatedParams {
        dest_conn_id: received.source_conn_id,
        source_conn_id: p.bob_id,
        packet_num: 9,
        now_secs: NOW,
        extra_blocks: &big,
        pad_roll: 0,
    };
    assert!(p.bob.build_session_created(&policy, &created).is_err());
}
