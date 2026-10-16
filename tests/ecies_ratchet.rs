use uu_i2p::{
    EciesDelivery, EciesGarlicClove, GarlicBlock, I2PX25519Keys, IdentHash, RatchetSession,
    SessionState,
    ecies_ratchet::{DHRatchet, MIN_RECEIVE_TAGS},
    error::I2PError,
    garlic_block::NextKeyBlock,
    i2np::I2npMessageType,
};

fn pair() -> (RatchetSession, RatchetSession) {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();
    (
        RatchetSession::new_initiator(alice_static, bob_pub),
        RatchetSession::new_responder(bob_static),
    )
}

#[test]
fn full_ns_nsr_handshake() {
    let (mut alice, mut bob) = pair();

    let ns = alice
        .create_new_session_message(b"hello from alice")
        .unwrap();
    assert_eq!(alice.state(), SessionState::NewSent);

    let got_ns = bob.handle_new_session_message(&ns).unwrap();
    assert_eq!(got_ns, b"hello from alice");
    assert_eq!(bob.state(), SessionState::NewReceived);
    // Bob теперь знает static Alice (после расшифровки enc_fs).
    assert!(bob.remote_static().is_some());

    let nsr = bob
        .create_new_session_reply_message(b"hello from bob")
        .unwrap();
    // Bob после NSR в NewReplySent — перейдёт в Established при
    // первом входящем сообщении от Alice.
    assert_eq!(bob.state(), SessionState::NewReplySent);

    let got_nsr = alice.handle_new_session_reply_message(&nsr).unwrap();
    assert_eq!(got_nsr, b"hello from bob");
    assert_eq!(alice.state(), SessionState::Established);

    // Tag-set'ы установлены
    assert!(alice.send_tagset().is_some());
    assert!(alice.receive_tagset().is_some());
    assert!(bob.send_tagset().is_some());
    assert!(bob.receive_tagset().is_some());
}

#[test]
fn empty_payloads() {
    let (mut alice, mut bob) = pair();
    let ns = alice.create_new_session_message(b"").unwrap();
    assert!(
        bob.handle_new_session_message(&ns).unwrap().is_empty(),
        "NS payload must be empty"
    );
    let nsr = bob.create_new_session_reply_message(b"").unwrap();
    assert!(
        alice
            .handle_new_session_reply_message(&nsr)
            .unwrap()
            .is_empty(),
        "NSR payload must be empty"
    );
}

#[test]
fn large_payloads() {
    let (mut alice, mut bob) = pair();
    let big = vec![0xCD_u8; 1000];
    let ns = alice.create_new_session_message(&big).unwrap();
    assert_eq!(bob.handle_new_session_message(&ns).unwrap(), big);
    let nsr = bob.create_new_session_reply_message(&big).unwrap();
    assert_eq!(alice.handle_new_session_reply_message(&nsr).unwrap(), big);
}

#[test]
fn ns_wire_layout() {
    let (mut alice, _) = pair();
    let ns = alice.create_new_session_message(b"abc").unwrap();
    // 32 aepk + 48 enc_fs + 3 payload + 16 MAC = 99
    assert_eq!(ns.len(), 32 + 48 + 3 + 16);
}

#[test]
fn nsr_wire_layout() {
    let (mut alice, mut bob) = pair();
    let ns = alice.create_new_session_message(b"").unwrap();
    let _ = bob.handle_new_session_message(&ns).unwrap();
    let nsr = bob.create_new_session_reply_message(b"xyz").unwrap();
    // 8 tag + 32 bepk + 16 reply_key + 3 payload + 16 MAC = 75
    assert_eq!(nsr.len(), 8 + 32 + 16 + 3 + 16);
}

#[test]
fn nsr_tag_mismatch_fails() {
    let (mut alice, mut bob) = pair();
    let ns = alice.create_new_session_message(b"").unwrap();
    let _ = bob.handle_new_session_message(&ns).unwrap();
    let mut nsr = bob.create_new_session_reply_message(b"").unwrap();
    nsr[0] ^= 0xFF;
    assert!(alice.handle_new_session_reply_message(&nsr).is_err());
}

#[test]
fn create_ns_twice_fails() {
    let (mut alice, _) = pair();
    let _ = alice.create_new_session_message(b"").unwrap();
    assert!(alice.create_new_session_message(b"").is_err());
}

#[test]
fn handle_ns_twice_fails() {
    let (mut alice, mut bob) = pair();
    let ns = alice.create_new_session_message(b"").unwrap();
    let _ = bob.handle_new_session_message(&ns).unwrap();
    assert!(bob.handle_new_session_message(&ns).is_err());
}

#[test]
fn wrong_bob_rejects_ns() {
    let bob_static = I2PX25519Keys::generate();
    let other_bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let mut wrong_bob = RatchetSession::new_responder(other_bob_static);
    let ns = alice.create_new_session_message(b"").unwrap();
    // wrong_bob's static другой, KDF1 не сойдётся.
    assert!(wrong_bob.handle_new_session_message(&ns).is_err());
}

#[test]
fn truncated_ns_fails() {
    let (_, mut bob) = pair();
    let r = bob.handle_new_session_message(&[0u8; 95]);
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}

#[test]
fn truncated_nsr_fails() {
    let (mut alice, _) = pair();
    let _ = alice.create_new_session_message(b"").unwrap();
    let r = alice.handle_new_session_reply_message(&[0u8; 71]);
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}
// ---- existing session messages --------------------------------------

/// Пара сессий после handshake. Bob переводится в `Established`
/// первым входящим сообщением — так требует протокол (Bob не
/// знает, что NSR дошёл, пока Alice не пришлёт что-то).
fn established_pair() -> (RatchetSession, RatchetSession) {
    let (mut alice, mut bob) = pair();
    let ns = alice.create_new_session_message(b"").unwrap();
    let _ = bob.handle_new_session_message(&ns).unwrap();
    let nsr = bob.create_new_session_reply_message(b"").unwrap();
    let _ = alice.handle_new_session_reply_message(&nsr).unwrap();
    assert_eq!(alice.state(), SessionState::Established);
    assert_eq!(bob.state(), SessionState::NewReplySent);

    // Alice шлёт первое сообщение — Bob переходит в Established.
    let hello = alice.create_existing_session_message(b"").unwrap();
    let _ = bob.handle_existing_session_message(&hello).unwrap();
    assert_eq!(bob.state(), SessionState::Established);
    (alice, bob)
}

#[test]
fn existing_message_roundtrip_alice_to_bob() {
    let (mut alice, mut bob) = established_pair();
    let msg = alice.create_existing_session_message(b"hello").unwrap();
    // 8 tag + 5 payload + 16 MAC = 29
    assert_eq!(msg.len(), 8 + 5 + 16);
    let got = bob.handle_existing_session_message(&msg).unwrap();
    assert_eq!(got, b"hello");
}

#[test]
fn existing_message_roundtrip_bob_to_alice() {
    let (mut alice, mut bob) = established_pair();
    let msg = bob.create_existing_session_message(b"hi back").unwrap();
    let got = alice.handle_existing_session_message(&msg).unwrap();
    assert_eq!(got, b"hi back");
}

#[test]
fn existing_message_bidirectional() {
    let (mut alice, mut bob) = established_pair();
    for i in 0..10_u8 {
        let m1 = alice.create_existing_session_message(&[i]).unwrap();
        assert_eq!(bob.handle_existing_session_message(&m1).unwrap(), [i]);
        let m2 = bob.create_existing_session_message(&[i + 100]).unwrap();
        assert_eq!(
            alice.handle_existing_session_message(&m2).unwrap(),
            [i + 100]
        );
    }
}

#[test]
fn existing_message_empty_payload() {
    let (mut alice, mut bob) = established_pair();
    let msg = alice.create_existing_session_message(b"").unwrap();
    // wire = tag(8) + payload(0) + MAC(16)
    assert_eq!(msg.len(), 8 + 16);
    let got = bob.handle_existing_session_message(&msg).unwrap();
    assert!(got.is_empty(), "expected empty payload");
}

#[test]
fn existing_message_large_payload() {
    let (mut alice, mut bob) = established_pair();
    let big = vec![0xCD_u8; 5000];
    let msg = alice.create_existing_session_message(&big).unwrap();
    let got = bob.handle_existing_session_message(&msg).unwrap();
    assert_eq!(got, big);
}

#[test]
fn existing_message_unknown_tag_fails() {
    let (mut alice, mut bob) = established_pair();
    let mut msg = alice.create_existing_session_message(b"x").unwrap();
    msg[0] ^= 0xFF; // портим tag
    let r = bob.handle_existing_session_message(&msg);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn existing_message_replayed_tag_fails() {
    let (mut alice, mut bob) = established_pair();
    let msg = alice.create_existing_session_message(b"x").unwrap();
    let _ = bob.handle_existing_session_message(&msg).unwrap();
    // Повторная отправка того же буфера — tag уже удалён из карты
    let r = bob.handle_existing_session_message(&msg);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn existing_message_tampered_payload_fails() {
    let (mut alice, mut bob) = established_pair();
    let mut msg = alice.create_existing_session_message(b"hello").unwrap();
    msg[10] ^= 0xFF; // портим данные внутри payload
    let r = bob.handle_existing_session_message(&msg);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn existing_message_out_of_order() {
    // Alice шлёт три сообщения, Bob принимает в обратном порядке
    let (mut alice, mut bob) = established_pair();
    let m0 = alice.create_existing_session_message(b"zero").unwrap();
    let m1 = alice.create_existing_session_message(b"one").unwrap();
    let m2 = alice.create_existing_session_message(b"two").unwrap();

    assert_eq!(bob.handle_existing_session_message(&m2).unwrap(), b"two");
    assert_eq!(bob.handle_existing_session_message(&m0).unwrap(), b"zero");
    assert_eq!(bob.handle_existing_session_message(&m1).unwrap(), b"one");
}

#[test]
fn existing_message_tag_capacity_refilled() {
    let (mut alice, mut bob) = established_pair();
    // Изначально refill даёт MIN_RECEIVE_TAGS.
    assert_eq!(alice.num_receive_tags(), MIN_RECEIVE_TAGS);
    assert_eq!(bob.num_receive_tags(), MIN_RECEIVE_TAGS);

    // Съедаем несколько — после каждой приёмки карта пополняется.
    for _ in 0..5 {
        let m = alice.create_existing_session_message(b"x").unwrap();
        let _ = bob.handle_existing_session_message(&m).unwrap();
    }
    // У Bob'а после каждой приёмки вызывался refill, карта всё ещё MIN.
    assert_eq!(bob.num_receive_tags(), MIN_RECEIVE_TAGS);
}

#[test]
fn existing_message_before_handshake_fails() {
    let (mut alice, _) = pair();
    let r = alice.create_existing_session_message(b"x");
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn existing_message_short_buffer_fails() {
    let (_, mut bob) = established_pair();
    let r = bob.handle_existing_session_message(&[0u8; 23]);
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}
// ---- wrap_blocks / handle_blocks ------------------------------------
const fn ident(n: u8) -> IdentHash {
    IdentHash::from_array([n; 32])
}
/// Детерминированный clove для тестов: фиксированный `message_id`
/// и `expiration_secs`, чтобы сравнение двух вызовов давало
/// одинаковый результат.
///
/// Облегчённый формат ECIES-X25519-AEAD: без `clove_id` и
/// `certificate`, expiration — в секундах. `I2npMessage::new`
/// генерирует random `msg_id` и берёт текущее время — здесь
/// нам это не нужно.
fn simple_clove(n: u8) -> EciesGarlicClove {
    EciesGarlicClove {
        delivery: EciesDelivery::Destination(ident(0x11)),
        message_type: I2npMessageType::Data,
        message_id: u32::from(n),
        // 1_700_000_000_000 мс = 1_700_000_000 сек
        expiration_secs: 1_700_000_000,
        payload: vec![n],
    }
}

#[test]
fn blocks_full_handshake_and_data_exchange() {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let mut bob = RatchetSession::new_responder(bob_static);

    // 1. Alice шлёт NS с clove[1].
    let ns = alice.wrap_blocks(&[simple_clove(1)]).unwrap();
    assert_eq!(alice.state(), SessionState::NewSent);

    // 2. Bob принимает NS, видит clove[1], нужен reply.
    let got = bob.handle_blocks(&ns).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0], simple_clove(1));
    assert!(bob.needs_reply());

    // 3. Bob шлёт NSR с clove[2].
    let nsr = bob.wrap_blocks(&[simple_clove(2)]).unwrap();
    assert!(!bob.needs_reply());

    // 4. Alice принимает NSR, видит clove[2], становится Established.
    let got = alice.handle_blocks(&nsr).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0], simple_clove(2));
    assert_eq!(alice.state(), SessionState::Established);

    // 5. Alice шлёт existing с clove[3]. Bob получает и переходит в Established.
    let ex = alice.wrap_blocks(&[simple_clove(3)]).unwrap();
    let got = bob.handle_blocks(&ex).unwrap();
    assert_eq!(got[0], simple_clove(3));
    assert_eq!(bob.state(), SessionState::Established);

    // 6. Обмен в обе стороны.
    for i in 4..10_u8 {
        let m = alice.wrap_blocks(&[simple_clove(i)]).unwrap();
        assert_eq!(bob.handle_blocks(&m).unwrap()[0], simple_clove(i));
        let m = bob.wrap_blocks(&[simple_clove(i + 100)]).unwrap();
        assert_eq!(alice.handle_blocks(&m).unwrap()[0], simple_clove(i + 100));
    }
}

#[test]
fn blocks_empty_list() {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let mut bob = RatchetSession::new_responder(bob_static);

    // NS с пустым списком
    let ns = alice.wrap_blocks(&[]).unwrap();
    let got = bob.handle_blocks(&ns).unwrap();
    assert!(got.is_empty(), "expected no blocks in NS");

    // NSR с пустым списком
    let nsr = bob.wrap_blocks(&[]).unwrap();
    let got = alice.handle_blocks(&nsr).unwrap();
    assert!(got.is_empty(), "expected no blocks in NSR");

    // Existing с пустым списком
    let ex = alice.wrap_blocks(&[]).unwrap();
    let got = bob.handle_blocks(&ex).unwrap();
    assert!(got.is_empty(), "expected no blocks in existing");
}

#[test]
fn blocks_multiple_in_one_message() {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let mut bob = RatchetSession::new_responder(bob_static);

    let blocks = vec![simple_clove(1), simple_clove(2), simple_clove(3)];
    let ns = alice.wrap_blocks(&blocks).unwrap();
    let got = bob.handle_blocks(&ns).unwrap();
    assert_eq!(got, blocks);
}

#[test]
fn blocks_wrap_in_new_sent_fails() {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let _ = alice.wrap_blocks(&[]).unwrap(); // NS отправлен
    // Повторный wrap_blocks — ошибка, ждём NSR.
    assert!(alice.wrap_blocks(&[]).is_err());
}

#[test]
fn blocks_handle_in_new_received_fails() {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let mut bob = RatchetSession::new_responder(bob_static);

    let ns = alice.wrap_blocks(&[]).unwrap();
    let _ = bob.handle_blocks(&ns).unwrap();
    // Bob теперь в NewReceived, приём не разрешён.
    assert!(bob.handle_blocks(&[]).is_err());
}

#[test]
fn blocks_needs_reply_transitions() {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let mut bob = RatchetSession::new_responder(bob_static);

    assert!(!alice.needs_reply());
    assert!(!bob.needs_reply());

    let ns = alice.wrap_blocks(&[]).unwrap();
    let _ = bob.handle_blocks(&ns).unwrap();
    assert!(bob.needs_reply());

    let _ = bob.wrap_blocks(&[]).unwrap();
    assert!(!bob.needs_reply());
}

#[test]
fn blocks_tampered_wire_fails() {
    let bob_static = I2PX25519Keys::generate();
    let alice_static = I2PX25519Keys::generate();
    let bob_pub = *bob_static.public_key();

    let mut alice = RatchetSession::new_initiator(alice_static, bob_pub);
    let mut bob = RatchetSession::new_responder(bob_static);

    let ns = alice.wrap_blocks(&[simple_clove(1)]).unwrap();
    let mut tampered = ns;
    // Портим байт в зашифрованной части
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(bob.handle_blocks(&tampered).is_err());
}
#[test]
fn dh_ratchet_receive_tagset_id_new_key() {
    let mut r = DHRatchet::new();
    r.key_id = 5;
    r.new_key = true;
    assert_eq!(r.receive_tagset_id(), 11);
}

#[test]
fn dh_ratchet_receive_tagset_id_reused_key() {
    let mut r = DHRatchet::new();
    r.key_id = 5;
    r.new_key = false;
    assert_eq!(r.receive_tagset_id(), 10);
}

// ---- DH ratchet (send side) -----------------------------------------

#[test]
fn new_next_send_ratchet_first_call_key_id_is_zero() {
    let (mut alice, _bob) = established_pair();
    assert!(!alice.send_forward_key);
    assert!(alice.next_send_ratchet.is_none());

    alice.new_next_send_ratchet().unwrap();

    assert!(alice.send_forward_key);
    let r = alice.next_send_ratchet.as_ref().expect("ratchet created");
    // По i2pd первый вызов оставляет keyID = 0 (важно: именно
    // `keyID == 0` затем даёт `REQUEST_REVERSE_KEY_FLAG`
    // в forward-блоке).
    assert_eq!(r.key_id, 0);
    assert!(r.new_key);
    assert!(r.key.is_some());
}

#[test]
fn new_next_send_ratchet_second_call_increments_key_id_to_one() {
    let (mut alice, _bob) = established_pair();
    alice.new_next_send_ratchet().unwrap();
    let first_pub = *alice
        .next_send_ratchet
        .as_ref()
        .unwrap()
        .key
        .as_ref()
        .unwrap()
        .public_key();

    alice.new_next_send_ratchet().unwrap();

    let r = alice.next_send_ratchet.as_ref().unwrap();
    assert_eq!(r.key_id, 1);
    assert!(r.new_key);
    let second_pub = *r.key.as_ref().unwrap().public_key();
    assert_ne!(first_pub, second_pub, "second call must regenerate key");
}

#[test]
fn new_next_send_ratchet_third_call_reuses_key_id_no_new_key() {
    // i2pd: (newKey=true, keyID>0) → else → newKey=false, ключ
    // переиспользуется.
    let (mut alice, _bob) = established_pair();
    alice.new_next_send_ratchet().unwrap(); // keyID=0, newKey=true
    alice.new_next_send_ratchet().unwrap(); // keyID=1, newKey=true
    let second_pub = *alice
        .next_send_ratchet
        .as_ref()
        .unwrap()
        .key
        .as_ref()
        .unwrap()
        .public_key();

    alice.new_next_send_ratchet().unwrap();

    let r = alice.next_send_ratchet.as_ref().unwrap();
    assert_eq!(r.key_id, 1);
    assert!(!r.new_key);
    let third_pub = *r.key.as_ref().unwrap().public_key();
    assert_eq!(second_pub, third_pub, "key must be reused, not regenerated");
}

#[test]
fn new_next_send_ratchet_fourth_call_increments_key_id_to_two() {
    let (mut alice, _bob) = established_pair();
    alice.new_next_send_ratchet().unwrap(); // keyID=0
    alice.new_next_send_ratchet().unwrap(); // keyID=1, newKey=true
    alice.new_next_send_ratchet().unwrap(); // keyID=1, newKey=false
    alice.new_next_send_ratchet().unwrap(); // keyID=2, newKey=true

    let r = alice.next_send_ratchet.as_ref().unwrap();
    assert_eq!(r.key_id, 2);
    assert!(r.new_key);
}

#[test]
fn build_forward_key_block_first_requests_reverse() {
    let (mut alice, _bob) = established_pair();
    alice.new_next_send_ratchet().unwrap(); // keyID=0

    let block = alice.build_forward_key_block().expect("block built");
    let GarlicBlock::NextKey(bytes) = block else {
        panic!("expected GarlicBlock::NextKey, got {block:?}");
    };
    let parsed = NextKeyBlock::parse(&bytes).unwrap();
    assert_eq!(parsed.key_id, 0);
    assert!(parsed.requests_reverse_key());
    assert!(parsed.public_key.is_some());
}

#[test]
fn build_forward_key_block_missing_ratchet() {
    // До `new_next_send_ratchet` блок построить нельзя.
    let (alice, _bob) = established_pair();
    assert!(alice.build_forward_key_block().is_none());
}

#[test]
fn wrap_blocks_keeps_forward_flag_until_reverse() {
    let (mut alice, mut bob) = established_pair();
    alice.new_next_send_ratchet().unwrap();
    assert!(alice.send_forward_key);

    // Первое сообщение: forward-key уходит.
    let wire1 = alice.wrap_blocks(&[]).unwrap();
    assert!(
        alice.send_forward_key,
        "flag must NOT be cleared after emit — i2pd retransmits until reverse"
    );
    let _ = bob.handle_blocks(&wire1).unwrap();
    assert!(bob.send_reverse_key);

    // Второе сообщение от Alice — тот же forward-key-блок, но
    // новый тег. Это retransmission, peer должен проигнорировать
    // дубликат.
    let wire2 = alice.wrap_blocks(&[]).unwrap();
    assert!(alice.send_forward_key, "flag still set");
    let _ = bob.handle_blocks(&wire2).unwrap();
    // У Bob'а по-прежнему только один receive-tagset — второй
    // forward-key был отброшен как дубликат.
    assert_eq!(bob.num_receive_tagsets(), 2, "1 + новый tagset");

    // Bob отвечает reverse, Alice принимает → флаг снят.
    let reverse = bob.wrap_blocks(&[]).unwrap();
    let _ = alice.handle_blocks(&reverse).unwrap();
    assert!(!alice.send_forward_key, "flag cleared after reverse");
}

// ---- DH ratchet (receive side + round-trip) -------------------------

/// Хелпер: полный NS → NSR → first existing, обе стороны в
/// `Established`. Совпадает с [`established_pair`] из блока
/// `wrap_blocks`, но продублирован локально, чтобы не тянуть
/// зависимость между разделами тестов.
fn established() -> (RatchetSession, RatchetSession) {
    let (mut alice, mut bob) = pair();
    let ns = alice.create_new_session_message(b"").unwrap();
    let _ = bob.handle_new_session_message(&ns).unwrap();
    let nsr = bob.create_new_session_reply_message(b"").unwrap();
    let _ = alice.handle_new_session_reply_message(&nsr).unwrap();
    let hello = alice.create_existing_session_message(b"").unwrap();
    let _ = bob.handle_existing_session_message(&hello).unwrap();
    assert_eq!(alice.state(), SessionState::Established);
    assert_eq!(bob.state(), SessionState::Established);
    (alice, bob)
}

#[test]
fn dh_ratchet_forward_then_reverse() {
    let (mut alice, mut bob) = established();
    let alice_send_id_before = alice.send_tagset().unwrap().tagset_id();
    let bob_recv_id_before = bob.current_receive_tagset().unwrap().tagset_id();

    // 1. Alice инициирует ratchet.
    alice.new_next_send_ratchet().unwrap();
    let forward = alice.wrap_blocks(&[]).unwrap();
    // `send_forward_key` не сбрасывается сразу — retransmission.
    assert!(alice.send_forward_key);

    // 2. Bob принимает forward.
    let _ = bob.handle_blocks(&forward).unwrap();
    assert!(bob.send_reverse_key, "Bob must reply with reverse");
    assert_eq!(
        bob.current_receive_tagset().unwrap().tagset_id(),
        bob_recv_id_before + 1,
        "Bob's new receive tagset id"
    );

    // 3. Bob отвечает reverse.
    let reverse = bob.wrap_blocks(&[]).unwrap();
    // Флаг ещё выставлен: i2pd шлёт reverse в каждом сообщении,
    // пока не увидит входящее на новом tagset'е от Alice.
    assert!(
        bob.send_reverse_key,
        "send_reverse_key must persist until Alice's new tagset is used"
    );

    // 4. Alice принимает reverse и делает DH.
    let _ = alice.handle_blocks(&reverse).unwrap();
    assert_ne!(
        alice.send_tagset().unwrap().tagset_id(),
        alice_send_id_before,
        "Alice's send tagset must be replaced"
    );
    assert!(
        !alice.send_forward_key,
        "forward flag cleared after reverse"
    );

    // 5. Alice шлёт сообщение под новым send-tagset'ом.
    // Bob принимает его на новом receive-tagset'е — это сигнал,
    // что DH состоялся, и Bob перестаёт слать reverse.
    let msg = alice.create_existing_session_message(&[]).unwrap();
    let _ = bob.handle_existing_session_message(&msg).unwrap();
    assert!(
        !bob.send_reverse_key,
        "flag cleared once Alice started using new tagset"
    );
}

#[test]
fn dh_ratchet_data_flows_on_new_tagsets() {
    let (mut alice, mut bob) = established();

    alice.new_next_send_ratchet().unwrap();
    let forward = alice.wrap_blocks(&[]).unwrap();
    let _ = bob.handle_blocks(&forward).unwrap();
    let reverse = bob.wrap_blocks(&[]).unwrap();
    let _ = alice.handle_blocks(&reverse).unwrap();

    // С этого момента Alice шлёт existing-сообщения под новым
    // send-tagset'ом, Bob принимает на новом receive-tagset'е.
    for i in 0..10_u8 {
        let msg = alice.create_existing_session_message(&[i]).unwrap();
        let got = bob.handle_existing_session_message(&msg).unwrap();
        assert_eq!(got, [i], "iteration {i}");
    }

    // Обратное направление Bob → Alice тоже работает: его
    // send-tagset не менялся, но его теги по-прежнему валидны.
    for i in 0..10_u8 {
        let msg = bob.create_existing_session_message(&[i + 100]).unwrap();
        let got = alice.handle_existing_session_message(&msg).unwrap();
        assert_eq!(got, [i + 100]);
    }
}

#[test]
fn dh_ratchet_dh_agreement_matches() {
    // Проверяем симметрию DH: shared secret, посчитанный Alice
    // (через свой эфемерный и pub Bob'а), равен shared secret
    // Bob'а (через свой эфемерный и pub Alice).
    let (mut alice, mut bob) = established();
    alice.new_next_send_ratchet().unwrap();

    // Вручную достаём эфемерный ключ Alice.
    let alice_pub = *alice
        .next_send_ratchet
        .as_ref()
        .unwrap()
        .key
        .as_ref()
        .unwrap()
        .public_key();
    let alice_priv = alice
        .next_send_ratchet
        .as_ref()
        .unwrap()
        .key
        .as_ref()
        .unwrap()
        .private_key();

    // Alice шлёт forward, Bob принимает.
    let forward = alice.wrap_blocks(&[]).unwrap();
    let _ = bob.handle_blocks(&forward).unwrap();

    // Bob's ephemeral
    let bob_pub = *bob
        .next_receive_ratchet
        .as_ref()
        .unwrap()
        .key
        .as_ref()
        .unwrap()
        .public_key();
    let bob_priv = bob
        .next_receive_ratchet
        .as_ref()
        .unwrap()
        .key
        .as_ref()
        .unwrap()
        .private_key();

    // DH симметрия на сырых ключах — sanity check.
    let alice_keys = I2PX25519Keys::from_private(&alice_priv, Some(&alice_pub));
    let bob_keys = I2PX25519Keys::from_private(&bob_priv, Some(&bob_pub));
    let s1 = alice_keys.agree(&bob_pub).unwrap();
    let s2 = bob_keys.agree(&alice_pub).unwrap();
    assert_eq!(s1, s2);
}

#[test]
fn dh_ratchet_duplicate_forward_ignored() {
    let (mut alice, mut bob) = established();
    alice.new_next_send_ratchet().unwrap();

    // Два подряд forward-key-блока — i2pd шлёт forward в каждом
    // outgoing, пока не придёт reverse. Это не идентичные wire'ы:
    // у каждого свой тег, но один и тот же key_id.
    let forward1 = alice.wrap_blocks(&[]).unwrap();
    let forward2 = alice.wrap_blocks(&[]).unwrap();

    let _ = bob.handle_blocks(&forward1).unwrap();
    let id_after_first = bob.current_receive_tagset().unwrap().tagset_id();
    let count_after_first = bob.num_receive_tagsets();

    let _ = bob.handle_blocks(&forward2).unwrap();

    assert_eq!(
        bob.current_receive_tagset().unwrap().tagset_id(),
        id_after_first,
        "duplicate forward must not create a second tagset"
    );
    assert_eq!(bob.num_receive_tagsets(), count_after_first);
}

#[test]
fn dh_ratchet_reverse_without_forward_ignored() {
    // Alice не инициировала forward; приходит чужой reverse.
    // Не должно паниковать — просто no-op.
    let (mut alice, mut bob) = established();
    bob.next_receive_ratchet = Some(DHRatchet::new());
    bob.next_receive_ratchet.as_mut().unwrap().key = Some(I2PX25519Keys::generate());
    bob.next_receive_ratchet.as_mut().unwrap().new_key = true;
    bob.send_reverse_key = true;
    let reverse = bob.wrap_blocks(&[]).unwrap();

    let before = alice.send_tagset().unwrap().tagset_id();
    let _ = alice.handle_blocks(&reverse).unwrap();
    assert_eq!(
        alice.send_tagset().unwrap().tagset_id(),
        before,
        "send tagset must be unchanged for unsolicited reverse"
    );
}
