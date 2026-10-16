
use uu_i2p::{
    EciesDelivery, EciesGarlicClove, EciesGarlicDestination, I2PError, SessionState,
    crypto::I2PX25519Keys, i2np::I2npMessageType,
};

/// Собирает облегчённый garlic-clove с delivery `Local`,
/// одним байтом payload'а и типом I2NP `DeliveryStatus`.
///
/// `message_id = u32::from(id)`, `expiration_secs = 0` — не
/// проверяется в тестах `ecies_destination`.
fn clove(id: u8) -> EciesGarlicClove {
    EciesGarlicClove {
        delivery: EciesDelivery::Local,
        message_type: I2npMessageType::DeliveryStatus,
        message_id: u32::from(id),
        expiration_secs: 0,
        payload: vec![id],
    }
}

/// Прогоняет полный NS → NSR → first existing message, возвращает
/// `(alice_dest, alice_session_key, bob_dest, bob_session_key)`,
/// где ключи — это ключи «с той стороны» для каждой стороны.
fn established_pair() -> (
    EciesGarlicDestination,
    [u8; 32],
    EciesGarlicDestination,
    [u8; 32],
) {
    let bob_keys = I2PX25519Keys::generate();
    let bob_pub = *bob_keys.public_key();

    let mut alice = EciesGarlicDestination::new(I2PX25519Keys::generate());
    let mut bob = EciesGarlicDestination::new(bob_keys);
    let alice_pub = *alice.local_static_public();

    // 1. Alice → NS
    let ns = alice.send_blocks(bob_pub, &[]).unwrap();
    assert_eq!(alice.session_state(&bob_pub), Some(SessionState::NewSent));
    assert_eq!(alice.session_count(), 1);

    // 2. Bob принимает NS, видит needs_reply
    let r = bob.handle_message(&ns).unwrap();
    assert_eq!(r.remote_static, alice_pub);
    assert!(r.needs_reply);
    assert_eq!(
        bob.session_state(&alice_pub),
        Some(SessionState::NewReceived)
    );

    // 3. Bob → NSR
    let nsr = bob.send_blocks(alice_pub, &[]).unwrap();
    assert_eq!(
        bob.session_state(&alice_pub),
        Some(SessionState::NewReplySent)
    );

    // 4. Alice принимает NSR
    let r = alice.handle_message(&nsr).unwrap();
    assert_eq!(r.remote_static, bob_pub);
    assert!(!r.needs_reply);
    assert_eq!(
        alice.session_state(&bob_pub),
        Some(SessionState::Established)
    );

    // 5. Alice → первое existing-session сообщение,
    //    Bob переходит в Established
    let hello = alice.send_blocks(bob_pub, &[]).unwrap();
    let r = bob.handle_message(&hello).unwrap();
    assert_eq!(r.remote_static, alice_pub);
    assert!(!r.needs_reply);
    assert_eq!(
        bob.session_state(&alice_pub),
        Some(SessionState::Established)
    );

    (alice, bob_pub, bob, alice_pub)
}

#[test]
fn full_handshake() {
    let (_alice, bob_pub, bob, alice_pub) = established_pair();
    assert_eq!(bob.session_count(), 1);
    assert!(bob.has_session(&alice_pub));
    assert_eq!(
        bob.session_state(&alice_pub),
        Some(SessionState::Established)
    );
    // sanity: bob_pub ≠ alice_pub
    assert_ne!(bob_pub, alice_pub);
}

#[test]
fn alice_to_bob_existing() {
    let (mut alice, bob_pub, mut bob, alice_pub) = established_pair();
    let msg = alice.send_blocks(bob_pub, &[clove(3)]).unwrap();
    let r = bob.handle_message(&msg).unwrap();
    assert_eq!(r.remote_static, alice_pub);
    assert_eq!(r.blocks, vec![clove(3)]);
}

#[test]
fn bob_to_alice_existing() {
    let (mut alice, bob_pub, mut bob, alice_pub) = established_pair();
    let msg = bob.send_blocks(alice_pub, &[clove(4)]).unwrap();
    let r = alice.handle_message(&msg).unwrap();
    assert_eq!(r.remote_static, bob_pub);
    assert_eq!(r.blocks, vec![clove(4)]);
}

#[test]
fn bidirectional_many() {
    let (mut alice, bob_pub, mut bob, alice_pub) = established_pair();
    for i in 0..10u8 {
        let m = alice.send_blocks(bob_pub, &[clove(i)]).unwrap();
        let r = bob.handle_message(&m).unwrap();
        assert_eq!(r.blocks, vec![clove(i)]);

        let m = bob.send_blocks(alice_pub, &[clove(i + 100)]).unwrap();
        let r = alice.handle_message(&m).unwrap();
        assert_eq!(r.blocks, vec![clove(i + 100)]);
    }
}

#[test]
fn multiple_blocks_in_one_message() {
    let (mut alice, bob_pub, mut bob, alice_pub) = established_pair();
    let blocks = vec![clove(1), clove(2), clove(3)];
    let msg = alice.send_blocks(bob_pub, &blocks).unwrap();
    let r = bob.handle_message(&msg).unwrap();
    assert_eq!(r.remote_static, alice_pub);
    assert_eq!(r.blocks, blocks);
}

#[test]
fn alice_send_creates_session_on_first_call() {
    let bob_keys = I2PX25519Keys::generate();
    let bob_pub = *bob_keys.public_key();
    let mut alice = EciesGarlicDestination::new(I2PX25519Keys::generate());
    assert_eq!(alice.session_count(), 0);
    let _ = alice.send_blocks(bob_pub, &[]).unwrap();
    assert_eq!(alice.session_count(), 1);
    assert_eq!(alice.session_state(&bob_pub), Some(SessionState::NewSent));
}

#[test]
fn send_to_unknown_after_establishing_is_new_session() {
    // Разные remote static'и — разные сессии.
    let b1 = I2PX25519Keys::generate();
    let b1_pub = *b1.public_key();
    let b2 = I2PX25519Keys::generate();
    let b2_pub = *b2.public_key();
    let mut alice = EciesGarlicDestination::new(I2PX25519Keys::generate());
    let _ = alice.send_blocks(b1_pub, &[]).unwrap();
    let _ = alice.send_blocks(b2_pub, &[]).unwrap();
    assert_eq!(alice.session_count(), 2);
    assert!(alice.has_session(&b1_pub));
    assert!(alice.has_session(&b2_pub));
    assert_eq!(alice.session_state(&b1_pub), Some(SessionState::NewSent));
    assert_eq!(alice.session_state(&b2_pub), Some(SessionState::NewSent));
}

#[test]
fn handle_message_too_short() {
    let mut d = EciesGarlicDestination::new(I2PX25519Keys::generate());
    let r = d.handle_message(&[0u8; 7]);
    assert_eq!(
        r.unwrap_err(),
        I2PError::InvalidLength {
            expected: 8,
            got: 7
        }
    );
}

#[test]
fn handle_unknown_garbage_fails() {
    // Не NS и не совпадает ни с одним тегом. Должно падать
    // на KDF внутри `handle_new_session_message`.
    let mut d = EciesGarlicDestination::new(I2PX25519Keys::generate());
    let r = d.handle_message(&[0x42u8; 200]);
    assert!(r.is_err(), "garbage must not be accepted as NS");
}

#[test]
fn remove_session_drops_it() {
    let bob_keys = I2PX25519Keys::generate();
    let bob_pub = *bob_keys.public_key();
    let mut alice = EciesGarlicDestination::new(I2PX25519Keys::generate());
    let _ = alice.send_blocks(bob_pub, &[]).unwrap();
    assert!(alice.has_session(&bob_pub));
    assert!(alice.remove_session(&bob_pub).is_some());
    assert!(!alice.has_session(&bob_pub));
    // Повторное удаление — None
    assert!(alice.remove_session(&bob_pub).is_none());
}

#[test]
fn remote_static_is_asymmetric() {
    // У Alice destination сессия ключуется по bob_pub,
    // у Bob — по alice_pub. Это разные ключи.
    let (alice, bob_pub, bob, alice_pub) = established_pair();
    assert!(alice.has_session(&bob_pub));
    assert!(!alice.has_session(&alice_pub));
    assert!(bob.has_session(&alice_pub));
    assert!(!bob.has_session(&bob_pub));
    assert_ne!(bob_pub, alice_pub);
}
#[test]
fn send_termination_removes_session() {
    let (mut alice, bob_pub, _bob, _alice_pub) = established_pair();
    assert!(alice.has_session(&bob_pub));

    let wire = alice.send_termination(&bob_pub).unwrap();
    // Сессия удалена — повторный `send_blocks` создаст новую (NS).
    assert!(!alice.has_session(&bob_pub));
    assert_eq!(alice.session_count(), 0);
    // wire не пустой (Termination-блок + AEAD).
    assert!(wire.len() > 8);
}

#[test]
fn send_termination_unknown_session_fails() {
    let mut alice = EciesGarlicDestination::new(I2PX25519Keys::generate());
    let bogus = [0xABu8; 32];
    let r = alice.send_termination(&bogus);
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn incoming_termination_terminates_and_removes_session() {
    let (mut alice, bob_pub, mut bob, alice_pub) = established_pair();

    // Alice шлёт termination.
    let wire = alice.send_termination(&bob_pub).unwrap();
    assert!(!alice.has_session(&bob_pub));

    // Bob принимает — сессия помечена terminated и удалена.
    let result = bob.handle_message(&wire).unwrap();
    assert_eq!(result.remote_static, alice_pub);
    assert!(result.terminated, "Termination must set the flag");
    assert!(!bob.has_session(&alice_pub));
    assert_eq!(bob.session_count(), 0);
}
