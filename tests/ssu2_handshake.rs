use uu_i2p::{
    crypto::I2PX25519Keys,
    ssu2_block::{
        AddressBlock, Blocks, DateTimeBlock, RouterInfoBlock, Ssu2Block, Ssu2BlockType,
        Ssu2TerminationReason,
    },
    ssu2_crypto::derive_data_phase_keys,
    ssu2_handshake::{
        ConfirmedOutcome, HandshakeConfig, InitiatorHandshake, ResponderHandshake, RetryParams,
        SSU2_SESSION_CONFIRMED_MIN_LEN, SSU2_SESSION_REQUEST_MIN_LEN, SSU2_TOKEN_MESSAGE_MIN_LEN,
        SessionConfirmedParams, SessionCreatedParams, SessionRequestParams, TokenRequestParams,
        build_retry, build_token_request, handle_retry, handle_token_request,
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

fn pair(config: HandshakeConfig) -> Pair {
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
    let config = HandshakeConfig::default();
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
    let mut p = pair(HandshakeConfig::default());

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
    let mut p = pair(HandshakeConfig::default());

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
    let mut p = pair(HandshakeConfig::default());

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
    let mut p = pair(HandshakeConfig::default());

    let mut request = vec![0u8; SSU2_SESSION_REQUEST_MIN_LEN - 1];
    assert!(p.bob.handle_session_request(&policy, &mut request).is_err());

    let mut created = vec![0u8; 40];
    assert!(
        p.alice
            .handle_session_created(&policy, &mut created)
            .is_err()
    );
}

#[test]
fn session_created_needs_request_first() {
    let policy = I2pdPolicy;
    let mut p = pair(HandshakeConfig::default());
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
    let mut p = pair(HandshakeConfig::default());

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

// --- SessionConfirmed ---------------------------------------------------

/// Пара с сохранённым публичным статическим ключом Alice.
fn confirmed_pair() -> (Pair, [u8; 32]) {
    let alice_static = keys();
    let alice_pub = *alice_static.public_key();
    let bob_static = keys();
    let bob_intro = [0x11u8; 32];
    let config = HandshakeConfig::default();
    let alice = InitiatorHandshake::new(alice_static, *bob_static.public_key(), bob_intro, config);
    let bob = ResponderHandshake::new(bob_static, bob_intro, config);
    (
        Pair {
            alice,
            bob,
            alice_id: ALICE_ID,
            bob_id: BOB_ID,
        },
        alice_pub,
    )
}

/// Проводит пару через `SessionRequest` + `SessionCreated`.
fn complete_through_created(p: &mut Pair) {
    let policy = I2pdPolicy;
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
    p.alice.handle_session_created(&policy, &mut sc).unwrap();
}

fn confirmed_params(router_info: &[u8]) -> SessionConfirmedParams<'_> {
    SessionConfirmedParams {
        dest_conn_id: BOB_ID,
        router_info,
        pad_roll: 0xFF,
        frag_roll: 0,
    }
}

#[test]
fn session_confirmed_roundtrip() {
    let policy = I2pdPolicy;
    let (mut p, alice_pub) = confirmed_pair();
    complete_through_created(&mut p);

    let ri = vec![0xABu8; 64];
    let packets = p
        .alice
        .build_session_confirmed(&policy, &confirmed_params(&ri))
        .unwrap();
    assert!(
        packets.second.is_none(),
        "small RouterInfo must fit in one fragment"
    );
    assert!(packets.first.len() >= SSU2_SESSION_CONFIRMED_MIN_LEN);

    let mut first = packets.first;
    let outcome = p.bob.handle_session_confirmed(&policy, &mut first).unwrap();
    let ConfirmedOutcome::Complete(received) = outcome else {
        panic!("expected a complete SessionConfirmed");
    };
    assert_eq!(received.static_key, alice_pub);

    let mut blocks = Blocks::new(&received.payload);
    let router = blocks.next().unwrap().unwrap();
    assert_eq!(router.kind(), Some(Ssu2BlockType::RouterInfo));
    let ri_block: RouterInfoBlock = router.parse().unwrap();
    assert_eq!(ri_block.router_info, &ri[..]);
    assert_eq!(ri_block.fragment_number(), 0);
    assert_eq!(ri_block.num_fragments(), 1);

    // Padding идёт последним блоком.
    let kinds: Vec<_> = blocks.map(|b| b.unwrap().kind()).collect();
    assert_eq!(kinds.last(), Some(&Some(Ssu2BlockType::Padding)));

    // Ключи data phase совпали у обеих сторон.
    assert!(p.alice.data_keys().is_some());
    assert_eq!(p.alice.data_keys(), p.bob.data_keys());
}

#[test]
fn session_confirmed_fragmented_roundtrip() {
    let policy = I2pdPolicy;
    let (mut p, alice_pub) = confirmed_pair();
    complete_through_created(&mut p);

    let ri = vec![0x5Au8; 2000];
    let packets = p
        .alice
        .build_session_confirmed(&policy, &confirmed_params(&ri))
        .unwrap();
    let mut second = packets
        .second
        .expect("large RouterInfo must be split in two fragments");
    let mut first = packets.first;

    assert_eq!(
        p.bob.handle_session_confirmed(&policy, &mut first).unwrap(),
        ConfirmedOutcome::Incomplete
    );
    let outcome = p
        .bob
        .handle_session_confirmed(&policy, &mut second)
        .unwrap();
    let ConfirmedOutcome::Complete(received) = outcome else {
        panic!("expected a complete SessionConfirmed");
    };
    assert_eq!(received.static_key, alice_pub);

    let router = Blocks::new(&received.payload).next().unwrap().unwrap();
    let ri_block: RouterInfoBlock = router.parse().unwrap();
    assert_eq!(ri_block.router_info, &ri[..]);
    assert_eq!(p.alice.data_keys(), p.bob.data_keys());
}

#[test]
fn session_confirmed_fragments_out_of_order() {
    let policy = I2pdPolicy;
    let (mut p, alice_pub) = confirmed_pair();
    complete_through_created(&mut p);

    let ri = vec![0x5Au8; 2000];
    let packets = p
        .alice
        .build_session_confirmed(&policy, &confirmed_params(&ri))
        .unwrap();
    let mut second = packets.second.expect("must be fragmented");
    let mut first = packets.first;

    // Сначала второй фрагмент — ответчик ждёт.
    assert_eq!(
        p.bob
            .handle_session_confirmed(&policy, &mut second)
            .unwrap(),
        ConfirmedOutcome::Incomplete
    );
    let outcome = p.bob.handle_session_confirmed(&policy, &mut first).unwrap();
    let ConfirmedOutcome::Complete(received) = outcome else {
        panic!("expected a complete SessionConfirmed");
    };
    assert_eq!(received.static_key, alice_pub);
    assert_eq!(p.alice.data_keys(), p.bob.data_keys());
}

#[test]
fn session_confirmed_first_fragment_only_is_incomplete() {
    let policy = I2pdPolicy;
    let (mut p, _) = confirmed_pair();
    complete_through_created(&mut p);

    let ri = vec![0x5Au8; 2000];
    let packets = p
        .alice
        .build_session_confirmed(&policy, &confirmed_params(&ri))
        .unwrap();
    assert!(packets.second.is_some());

    let mut first = packets.first;
    assert_eq!(
        p.bob.handle_session_confirmed(&policy, &mut first).unwrap(),
        ConfirmedOutcome::Incomplete
    );
    // Ключи ещё не выведены.
    assert!(p.bob.data_keys().is_none());
}

#[test]
fn tampered_session_confirmed_is_rejected() {
    let policy = I2pdPolicy;
    let (mut p, _) = confirmed_pair();
    complete_through_created(&mut p);

    let ri = vec![0x11u8; 64];
    let mut packets = p
        .alice
        .build_session_confirmed(&policy, &confirmed_params(&ri))
        .unwrap();
    let last = packets.first.len() - 1;
    packets.first[last] ^= 0x01;

    assert!(
        p.bob
            .handle_session_confirmed(&policy, &mut packets.first)
            .is_err()
    );
}

#[test]
fn session_confirmed_needs_session_created() {
    let policy = I2pdPolicy;
    // Alice из отдельной пары проходит SC; её SConf отдаём «холодному» Bob'у.
    let (mut other, _) = confirmed_pair();
    complete_through_created(&mut other);
    let ri = vec![0x33u8; 64];
    let mut packets = other
        .alice
        .build_session_confirmed(&policy, &confirmed_params(&ri))
        .unwrap();

    let (mut fresh, _) = confirmed_pair();
    assert!(
        fresh
            .bob
            .handle_session_confirmed(&policy, &mut packets.first)
            .is_err()
    );
}

#[test]
fn too_short_session_confirmed_is_rejected() {
    let policy = I2pdPolicy;
    let (mut p, _) = confirmed_pair();
    complete_through_created(&mut p);

    let mut packet = vec![0u8; 16];
    assert!(
        p.bob
            .handle_session_confirmed(&policy, &mut packet)
            .is_err()
    );
}

#[test]
fn oversized_router_info_is_rejected() {
    let policy = I2pdPolicy;
    let (mut p, _) = confirmed_pair();
    complete_through_created(&mut p);

    let ri = vec![0u8; 40_000];
    assert!(
        p.alice
            .build_session_confirmed(&policy, &confirmed_params(&ri))
            .is_err()
    );
}

// --- TokenRequest / Retry -----------------------------------------------

const BOB_INTRO: [u8; 32] = [0x11; 32];

fn token_request_params() -> TokenRequestParams {
    TokenRequestParams {
        dest_conn_id: BOB_ID,
        source_conn_id: ALICE_ID,
        packet_num: 0x1020_3040,
        now_secs: NOW,
        pad_roll: 0xFF,
    }
}

#[test]
fn token_request_roundtrip() {
    let policy = I2pdPolicy;
    let config = HandshakeConfig::default();
    let mut packet =
        build_token_request(&policy, &config, &BOB_INTRO, &token_request_params()).unwrap();
    assert!(
        packet.len() >= SSU2_TOKEN_MESSAGE_MIN_LEN,
        "TokenRequest не короче 48 байт, получено {}",
        packet.len()
    );

    let received = handle_token_request(&BOB_INTRO, &mut packet).unwrap();
    assert_eq!(received.dest_conn_id, BOB_ID);
    assert_eq!(received.source_conn_id, ALICE_ID);

    let mut blocks = Blocks::new(&received.payload);
    let first = blocks.next().unwrap().unwrap();
    assert_eq!(first.kind(), Some(Ssu2BlockType::DateTime));
    let dt: DateTimeBlock = first.parse().unwrap();
    assert_eq!(dt.timestamp, NOW);
    // Дальше — только Padding.
    for block in blocks {
        assert_eq!(block.unwrap().kind(), Some(Ssu2BlockType::Padding));
    }
}

#[test]
fn retry_roundtrip_with_token_and_address() {
    let policy = I2pdPolicy;
    let config = HandshakeConfig::default();
    let address = AddressBlock {
        port: 9151,
        ip: "127.0.0.1".parse().unwrap(),
    };
    let params = RetryParams {
        dest_conn_id: ALICE_ID,
        source_conn_id: BOB_ID,
        packet_num: 0x5060_7080,
        token: TOKEN,
        now_secs: NOW + 2,
        valid_packets: 0,
        address: Some(&address),
        reason: None,
        pad_roll: 0xFF,
    };
    let mut packet = build_retry(&policy, &config, &BOB_INTRO, &params).unwrap();

    let received = handle_retry(&BOB_INTRO, &mut packet).unwrap();
    assert_eq!(received.source_conn_id, BOB_ID);
    assert_eq!(received.dest_conn_id, ALICE_ID);
    assert_eq!(received.token, TOKEN);

    let mut kinds = Vec::new();
    let mut seen_address = None;
    for block in Blocks::new(&received.payload) {
        let block = block.unwrap();
        kinds.push(block.kind());
        if block.kind() == Some(Ssu2BlockType::Address) {
            seen_address = Some(AddressBlock::parse(block.body).unwrap());
        }
    }
    assert_eq!(kinds.first(), Some(&Some(Ssu2BlockType::DateTime)));
    assert!(kinds.contains(&Some(Ssu2BlockType::Address)));
    assert_eq!(seen_address.unwrap().port, address.port);
}

#[test]
fn retry_with_termination_reason() {
    let policy = I2pdPolicy;
    let config = HandshakeConfig::default();
    let params = RetryParams {
        dest_conn_id: ALICE_ID,
        source_conn_id: BOB_ID,
        packet_num: 1,
        token: 0,
        now_secs: NOW,
        valid_packets: 0,
        address: None,
        reason: Some(Ssu2TerminationReason::BadToken),
        pad_roll: 0xFF,
    };
    let mut packet = build_retry(&policy, &config, &BOB_INTRO, &params).unwrap();
    let received = handle_retry(&BOB_INTRO, &mut packet).unwrap();
    assert_eq!(received.token, 0, "при отказе токен нулевой");

    let mut reason = None;
    for block in Blocks::new(&received.payload) {
        let block = block.unwrap();
        if block.kind() == Some(Ssu2BlockType::Termination) {
            // validPackets(8) + reason(1)
            reason = Ssu2TerminationReason::from_u8(block.body[8]);
        }
    }
    assert_eq!(reason, Some(Ssu2TerminationReason::BadToken));
}

#[test]
fn handle_retry_rejects_token_request() {
    let policy = I2pdPolicy;
    let config = HandshakeConfig::default();
    let mut packet =
        build_token_request(&policy, &config, &BOB_INTRO, &token_request_params()).unwrap();
    assert!(handle_retry(&BOB_INTRO, &mut packet).is_err());
}

#[test]
fn handle_token_request_rejects_tampered() {
    let policy = I2pdPolicy;
    let config = HandshakeConfig::default();
    let mut packet =
        build_token_request(&policy, &config, &BOB_INTRO, &token_request_params()).unwrap();
    let last = packet.len() - 1;
    packet[last] ^= 0x01;
    assert!(handle_token_request(&BOB_INTRO, &mut packet).is_err());
}

#[test]
fn token_messages_reject_short_packets() {
    let mut short = vec![0u8; SSU2_TOKEN_MESSAGE_MIN_LEN - 1];
    assert!(handle_token_request(&BOB_INTRO, &mut short).is_err());
    let mut short = vec![0u8; SSU2_TOKEN_MESSAGE_MIN_LEN - 1];
    assert!(handle_retry(&BOB_INTRO, &mut short).is_err());
}
