#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::{TcpListener, TcpStream};
    use uu_i2p::{
        I2PAddress, I2PX25519Keys,
        crypto::Aes256Cbc,
        error::I2PError,
        i2np::I2npMessageType,
        i2np_message::I2npMessage as I2npMsg,
        ntcp2::*,
        private_keys::I2PPrivateKeys,
        router_info::{FullRouterInfo, RouterInfo},
        tag::I2PTag,
    };

    // ---- constants ------------------------------------------------------

    #[test]
    fn constants_match_i2pd() {
        assert_eq!(NTCP2_UNENCRYPTED_FRAME_MAX_SIZE, 65519);
        assert_eq!(NTCP2_SEND_AFTER_FRAME_SIZE, 16386);
        assert_eq!(NTCP2_SESSION_HANDSHAKE_MAX_SIZE, 287);
        assert_eq!(NTCP2_SESSION_HANDSHAKE_LONG_MAX_SIZE, 944);
        assert_eq!(NTCP2_MAX_HANDSHAKE_PADDING_LEN, 223);
        assert_eq!(NTCP2_MAX_PADDING_RATIO, 6);
        assert_eq!(NTCP2_CLOCK_SKEW_SECS, 60);
        assert_eq!(NTCP2_MAX_OUTGOING_QUEUE_SIZE, 500);
        assert_eq!(NTCP2_ROUTER_INFO_FLAG_REQUEST_FLOOD, 0x01);
    }

    // ---- Ntcp2BlockType -------------------------------------------------

    #[test]
    fn block_type_roundtrip_all_variants() {
        let all = [
            Ntcp2BlockType::DateTime,
            Ntcp2BlockType::Options,
            Ntcp2BlockType::RouterInfo,
            Ntcp2BlockType::I2npMessage,
            Ntcp2BlockType::Termination,
            Ntcp2BlockType::Padding,
        ];
        for t in all {
            let v = t.as_u8();
            let back = Ntcp2BlockType::from_u8(v).unwrap();
            assert_eq!(back, t, "roundtrip for {t:?}");
        }
    }

    #[test]
    fn block_type_values_match_spec() {
        assert_eq!(Ntcp2BlockType::DateTime.as_u8(), 0);
        assert_eq!(Ntcp2BlockType::Options.as_u8(), 1);
        assert_eq!(Ntcp2BlockType::RouterInfo.as_u8(), 2);
        assert_eq!(Ntcp2BlockType::I2npMessage.as_u8(), 3);
        assert_eq!(Ntcp2BlockType::Termination.as_u8(), 4);
        assert_eq!(Ntcp2BlockType::Padding.as_u8(), 254);
    }

    #[test]
    fn block_type_unknown_returns_error() {
        for v in [5u8, 6, 7, 100, 200, 253, 255] {
            let r = Ntcp2BlockType::from_u8(v);
            assert_eq!(r, Err(I2PError::UnknownNtcp2BlockType(v)));
        }
    }

    #[test]
    fn block_type_names_are_unique() {
        let all = [
            Ntcp2BlockType::DateTime,
            Ntcp2BlockType::Options,
            Ntcp2BlockType::RouterInfo,
            Ntcp2BlockType::I2npMessage,
            Ntcp2BlockType::Termination,
            Ntcp2BlockType::Padding,
        ];
        let mut seen = std::collections::HashSet::new();
        for t in all {
            assert!(seen.insert(t.name()), "duplicate name: {}", t.name());
        }
    }

    #[test]
    fn block_type_display_matches_name() {
        for t in [Ntcp2BlockType::DateTime, Ntcp2BlockType::Padding] {
            assert_eq!(format!("{t}"), t.name());
        }
    }

    // ---- Ntcp2TerminationReason -----------------------------------------

    #[test]
    fn termination_reason_roundtrip_all_variants() {
        // Проверяем весь диапазон 0..=17.
        for v in 0u8..=17 {
            let r = Ntcp2TerminationReason::from_u8(v).unwrap();
            assert_eq!(r.as_u8(), v);
        }
    }

    #[test]
    fn termination_reason_unknown_returns_error() {
        for v in [18u8, 19, 100, 255] {
            let r = Ntcp2TerminationReason::from_u8(v);
            assert_eq!(r, Err(I2PError::UnknownNtcp2TerminationReason(v)));
        }
    }

    #[test]
    fn termination_reason_values_match_spec() {
        assert_eq!(Ntcp2TerminationReason::NormalClose.as_u8(), 0);
        assert_eq!(Ntcp2TerminationReason::TerminationReceived.as_u8(), 1);
        assert_eq!(Ntcp2TerminationReason::IdleTimeout.as_u8(), 2);
        assert_eq!(Ntcp2TerminationReason::DataPhaseAeadFailure.as_u8(), 4);
        assert_eq!(
            Ntcp2TerminationReason::RouterInfoSignatureVerificationFail.as_u8(),
            15
        );
        assert_eq!(Ntcp2TerminationReason::Banned.as_u8(), 17);
    }

    // ---- Establisher: KDF-цепочка ---------------------------------------

    /// Проверяет, что после каждой пары KDF'ов у Alice и Bob
    /// совпадают `h` и `ck`. Иначе handshake не сойдётся.
    #[test]
    fn kdf_chain_is_symmetric() {
        let alice_static = I2PX25519Keys::generate();
        let bob_static = I2PX25519Keys::generate();

        let mut alice = Ntcp2Establisher::new();
        alice.remote_static_pub = *bob_static.public_key();

        let mut bob = Ntcp2Establisher::new();
        bob.remote_ephemeral_pub = *alice.ephemeral_pub();
        bob.remote_static_pub = *alice_static.public_key();

        // KDF1
        alice.kdf1_alice().unwrap();
        bob.kdf1_bob(&bob_static).unwrap();
        assert_eq!(alice.noise.h, bob.noise.h, "h after KDF1");
        assert_eq!(alice.noise.ck, bob.noise.ck, "ck after KDF1");

        // Теперь Alice должна узнать эфемерный pub Bob'а —
        // в реальном протоколе это приходит в SessionCreated.
        alice.remote_ephemeral_pub = *bob.ephemeral_pub();

        // KDF2
        alice.kdf2_alice().unwrap();
        bob.kdf2_bob().unwrap();
        assert_eq!(alice.noise.h, bob.noise.h, "h after KDF2");
        assert_eq!(alice.noise.ck, bob.noise.ck, "ck after KDF2");

        // KDF3
        alice.kdf3_alice(&alice_static).unwrap();
        bob.kdf3_bob().unwrap();
        assert_eq!(alice.noise.h, bob.noise.h, "h after KDF3");
        assert_eq!(alice.noise.ck, bob.noise.ck, "ck after KDF3");
    }

    #[test]
    fn kdf1_differs_for_different_ephemeral_keys() {
        let bob_static = I2PX25519Keys::generate();

        let mut alice1 = Ntcp2Establisher::new();
        alice1.remote_static_pub = *bob_static.public_key();
        alice1.kdf1_alice().unwrap();

        let mut alice2 = Ntcp2Establisher::new();
        alice2.remote_static_pub = *bob_static.public_key();
        alice2.kdf1_alice().unwrap();

        // Разные эфемерные ключи → разные h.
        assert_ne!(alice1.noise.h, alice2.noise.h);
    }

    #[test]
    fn ephemeral_pub_matches_key() {
        let e = Ntcp2Establisher::new();
        assert_eq!(e.ephemeral_pub(), e.ephemeral.public_key());
    }

    #[test]
    fn default_matches_new() {
        let a = Ntcp2Establisher::default();
        let b = Ntcp2Establisher::new();
        // Ephemeral keys случайные — сравниваем структуру, не значения.
        assert_eq!(a.remote_ephemeral_pub, b.remote_ephemeral_pub);
        assert_eq!(a.remote_static_pub, b.remote_static_pub);
        assert_eq!(a.noise.h, b.noise.h);
        assert_eq!(a.noise.ck, b.noise.ck);
    }

    // ---- Ntcp2DataPhase: KDF и обфускация длины -------------------------

    /// Симметричность KDF: у Alice и Bob должны получиться зеркальные
    /// ключи. Если направления перепутаны (`is_alice` swap), этот тест
    /// упадёт.
    #[test]
    fn derive_data_phase_keys_are_mirrored() {
        let ck = [0xAAu8; 32];
        let h = [0xBBu8; 32];

        let alice = Ntcp2DataPhase::derive(&ck, &h, true);
        let bob = Ntcp2DataPhase::derive(&ck, &h, false);

        assert_eq!(alice.send_key, bob.receive_key, "alice.send == bob.recv");
        assert_eq!(alice.receive_key, bob.send_key, "alice.recv == bob.send");
    }

    /// SipHash-ключи и начальные IV тоже должны быть зеркальными.
    /// Проверяем косвенно — через round-trip обфускации длины.
    #[test]
    fn derive_data_phase_length_obfuscation_roundtrip() {
        let ck = [0xCCu8; 32];
        let h = [0xDDu8; 32];

        let mut alice = Ntcp2DataPhase::derive(&ck, &h, true);
        let mut bob = Ntcp2DataPhase::derive(&ck, &h, false);

        // Прогоняем разные длины, чтобы покрыть и IV-rolling.
        for len in [0u16, 1, 16, 287, 1024, 0xabcd, u16::MAX] {
            let wire = alice.obfuscate_send_length(len);
            let back = bob.deobfuscate_receive_length(wire);
            assert_eq!(back, len, "round-trip for len {len}");
        }
    }

    /// Разные `ck` → разные ключи. Защита от вырожденного KDF
    /// (например, если бы мы забыли подать `ck` в HKDF).
    #[test]
    fn derive_data_phase_different_ck_different_keys() {
        let h = [0u8; 32];
        let alice1 = Ntcp2DataPhase::derive(&[0x01; 32], &h, true);
        let alice2 = Ntcp2DataPhase::derive(&[0x02; 32], &h, true);
        assert_ne!(alice1.send_key, alice2.send_key);
        assert_ne!(alice1.receive_key, alice2.receive_key);
    }

    /// IV действительно rolling: обфускация одинаковой длины дважды
    /// подряд даёт разные wire-байты (с очень высокой вероятностью).
    #[test]
    fn length_obfuscation_iv_rolls() {
        let mut alice = Ntcp2DataPhase::derive(&[0x11; 32], &[0x22; 32], true);
        let w1 = alice.obfuscate_send_length(1024);
        let w2 = alice.obfuscate_send_length(1024);
        assert_ne!(
            w1, w2,
            "same length must obfuscate differently after IV roll"
        );
    }

    /// Nonce: 4 нулевых байта + LE u64. Первый = 0, второй = 1, и т. д.
    #[test]
    fn nonces_increment_le() {
        let mut dp = Ntcp2DataPhase::derive(&[0u8; 32], &[0u8; 32], true);

        for i in 0u64..16 {
            let nonce = dp.next_send_nonce();
            assert_eq!(&nonce[..4], &[0, 0, 0, 0], "nonce prefix must be zero");
            assert_eq!(&nonce[4..], &i.to_le_bytes(), "nonce counter mismatch");
        }
    }

    #[test]
    fn send_and_receive_nonces_independent() {
        let mut dp = Ntcp2DataPhase::derive(&[0u8; 32], &[0u8; 32], true);

        // Оба счётчика стартуют с 0.
        let s0 = dp.next_send_nonce();
        let r0 = dp.next_receive_nonce();
        assert_eq!(s0, r0, "both start at 0");

        // Send продвинулся один раз — счётчик = 1.
        let s1 = dp.next_send_nonce();
        assert_eq!(&s1[4..], &1u64.to_le_bytes());

        // Receive независим: продвигаем один раз — тоже = 1,
        // но не 0 (это подтверждает, что он шёл своим ходом,
        // а не сидел на нуле).
        let r1 = dp.next_receive_nonce();
        assert_eq!(
            r1, s1,
            "receive advances independently: at 1 after one call"
        );

        // Ещё один шаг в обе стороны — синхронно 2 и 2.
        let s2 = dp.next_send_nonce();
        let r2 = dp.next_receive_nonce();
        assert_eq!(&s2[4..], &2u64.to_le_bytes());
        assert_eq!(r2, s2);
    }

    /// Интеграция с `Ntcp2Establisher`: после KDF-цепочки
    /// `derive_data_phase` даёт зеркальные ключи на обеих сторонах.
    #[test]
    fn establisher_derives_data_phase() {
        let alice_static = I2PX25519Keys::generate();
        let bob_static = I2PX25519Keys::generate();

        let mut alice = Ntcp2Establisher::new();
        alice.remote_static_pub = *bob_static.public_key();

        let mut bob = Ntcp2Establisher::new();
        bob.remote_ephemeral_pub = *alice.ephemeral_pub();
        bob.remote_static_pub = *alice_static.public_key();

        alice.kdf1_alice().unwrap();
        bob.kdf1_bob(&bob_static).unwrap();
        alice.remote_ephemeral_pub = *bob.ephemeral_pub();
        alice.kdf2_alice().unwrap();
        bob.kdf2_bob().unwrap();
        alice.kdf3_alice(&alice_static).unwrap();
        bob.kdf3_bob().unwrap();

        let alice_dp = alice.derive_data_phase(true);
        let bob_dp = bob.derive_data_phase(false);

        assert_eq!(alice_dp.send_key, bob_dp.receive_key);
        assert_eq!(alice_dp.receive_key, bob_dp.send_key);
    }

    // ---- SessionRequest -------------------------------------------------

    /// Заполняет Establisher всеми нужными для `create_session_request`
    /// полями. Возвращает (`alice_est`, `bob_static_keys`, `bob_ident_hash`, `bob_iv`).
    fn alice_with_remote() -> (Ntcp2Establisher, I2PX25519Keys, [u8; 32], [u8; 16]) {
        let bob_static = I2PX25519Keys::generate();
        let bob_ident_hash = [0x42u8; 32];
        let bob_iv = [0x37u8; 16];

        let mut alice = Ntcp2Establisher::new();
        alice.remote_static_pub = *bob_static.public_key();
        alice.remote_ident_hash = bob_ident_hash;
        alice.iv = bob_iv;

        (alice, bob_static, bob_ident_hash, bob_iv)
    }

    #[test]
    fn session_request_wire_layout() {
        let (mut alice, _bob_static, _id, _iv) = alice_with_remote();
        let fake_ri = vec![0xAAu8; 100];
        let mut rng = StdRng::seed_from_u64(0);

        let wire = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();

        // 64 + padding. Padding ∈ [0, 223]. Проверяем границы.
        assert!(wire.len() >= 64, "wire too short: {}", wire.len());
        assert!(wire.len() <= 64 + 223, "wire too long: {}", wire.len());

        // Первые 32 байта — ciphertext X. Он не должен совпадать с pub-key.
        assert_ne!(&wire[..32], alice.ephemeral.public_key());
    }

    #[test]
    fn session_request_populates_m3p2() {
        let (mut alice, _bob_static, _id, _iv) = alice_with_remote();
        let fake_ri = vec![0x11u8; 50];
        let mut rng = StdRng::seed_from_u64(1);

        let _ = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();

        // m3p2 = block-type(1) + size(2) + flag(1) + RI(50) = 54 байта.
        assert_eq!(alice.m3p2_block.len(), 54);
        assert_eq!(alice.m3p2_block[0], Ntcp2BlockType::RouterInfo.as_u8());
        assert_eq!(&alice.m3p2_block[1..3], &51u16.to_be_bytes());
        assert_eq!(alice.m3p2_block[3], 0); // flag
        assert_eq!(&alice.m3p2_block[4..], &fake_ri[..]);
        // m3p2_len = 54 + 16 (MAC) = 70.
        assert_eq!(alice.m3p2_len, 70);
    }

    #[test]
    fn session_request_advances_iv() {
        let (mut alice, _bob_static, _id, orig_iv) = alice_with_remote();
        let fake_ri = vec![0x00u8; 20];
        let mut rng = StdRng::seed_from_u64(2);

        let wire = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();

        // IV должен быть обновлён (последние 16 байт ciphertext X).
        assert_ne!(alice.iv, orig_iv);
        assert_eq!(&alice.iv[..], &wire[16..32]);
    }

    #[test]
    fn session_request_options_encrypts_and_mixes() {
        let (mut alice, _bob_static, _id, _iv) = alice_with_remote();
        let fake_ri = vec![0x77u8; 30];
        let mut rng = StdRng::seed_from_u64(3);

        let h_before = alice.noise.h;
        let _ = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();
        let h_after = alice.noise.h;

        // h изменился (после MixHash(X), MixKey(DH), MixHash(enc_options), MixHash(padding)).
        assert_ne!(h_before, h_after);
    }

    #[test]
    fn session_request_deterministic_with_seed() {
        // Padding генерируется из seed — два прогона с одним seed'ом
        // дадут идентичный wire. Проверяем детерминизм.
        let fake_ri = vec![0xFFu8; 10];

        let (mut a1, _, _, _) = alice_with_remote();
        let (mut a2, _, _, _) = alice_with_remote();
        // Ключи разные (случайные), поэтому wire'ы различаются —
        // но с одним эфемерным ключом должны совпасть. Пропустим
        // эту проверку, оставим место для более точного теста после
        // 2y-7 (там будет полная сессия).

        let mut rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(42);
        let w1 = a1.create_session_request(&fake_ri, 2, &mut rng1).unwrap();
        let w2 = a2.create_session_request(&fake_ri, 2, &mut rng2).unwrap();
        // Padding'и одинаковые (тот же seed), но ciphertext X разный
        // (эфемерные ключи разные). Проверяем длину.
        assert_eq!(w1.len(), w2.len());
    }

    #[test]
    fn session_request_rejects_huge_ri() {
        let (mut alice, _bob_static, _id, _iv) = alice_with_remote();
        // RI > 65531 байт не влезает в u16 m3p2-блок.
        let huge_ri = vec![0u8; 65532];
        let mut rng = StdRng::seed_from_u64(4);

        let r = alice.create_session_request(&huge_ri, 2, &mut rng);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    /// X, будучи зашифрованным AES-CBC, при расшифровке тем же ключом и IV
    /// даёт исходный публичный ключ. Это косвенно подтверждает, что
    /// AES-CBC у нас работает симметрично на 32-байтовом входе.
    #[test]
    fn session_request_encrypted_x_is_decryptable() {
        let bob_static = I2PX25519Keys::generate();
        let bob_ident_hash = [0x42u8; 32];
        let bob_iv = [0x37u8; 16];

        let mut alice = Ntcp2Establisher::new();
        alice.remote_static_pub = *bob_static.public_key();
        alice.remote_ident_hash = bob_ident_hash;
        alice.iv = bob_iv;
        let alice_x_pub = *alice.ephemeral.public_key();

        let fake_ri = vec![0u8; 10];
        let mut rng = StdRng::seed_from_u64(5);
        let wire = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();

        // Симулируем Bob: расшифровываем первые 32 байта.
        let decrypted = Aes256Cbc::decrypt(&bob_ident_hash, &bob_iv, &wire[..32]).unwrap();
        assert_eq!(&decrypted[..], &alice_x_pub[..]);
    }

    // ---- process_session_request ----------------------------------------

    /// Возвращает `(alice_est, bob_est, wire, bob_static, bob_ident_hash, bob_iv)`.
    ///
    /// Alice готов отправить `SessionRequest`, Bob — принять.
    /// Bob'овы `iv` и `local_ident_hash` — его собственные
    /// (из его `RouterInfo`).
    fn alice_and_bob_session_request() -> (
        Ntcp2Establisher,
        Ntcp2Establisher,
        Vec<u8>,
        I2PX25519Keys,
        [u8; 32],
        [u8; 16],
    ) {
        let bob_static = I2PX25519Keys::generate();
        let bob_ident_hash = [0x42u8; 32];
        let bob_iv = [0x37u8; 16];

        let mut alice = Ntcp2Establisher::new();
        alice.remote_static_pub = *bob_static.public_key();
        alice.remote_ident_hash = bob_ident_hash;
        alice.iv = bob_iv;

        let mut bob = Ntcp2Establisher::new();
        bob.iv = bob_iv;

        let fake_ri = vec![0xAAu8; 100];
        let mut rng = StdRng::seed_from_u64(7);
        let wire = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();

        (alice, bob, wire, bob_static, bob_ident_hash, bob_iv)
    }

    #[test]
    fn process_session_request_roundtrip() {
        let (alice, mut bob, wire, bob_static, bob_ident, bob_iv) = alice_and_bob_session_request();
        let alice_x = *alice.ephemeral.public_key();
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let info = bob
            .process_session_request(&wire, &bob_ident, &bob_iv, &bob_static, 2, now_s)
            .unwrap();

        // X совпал.
        assert_eq!(info.remote_ephemeral_pub, alice_x);
        // Padding и m3p2 длины совпадают с тем, что Alice заявила.
        assert_eq!(info.m3p2_len, alice.m3p2_len);
        // Clock skew не сработал (время только что).
        assert!(!info.clock_skew);
    }

    #[test]
    fn process_session_request_noise_state_syncs() {
        let (alice, mut bob, wire, bob_static, bob_ident, bob_iv) = alice_and_bob_session_request();
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let _ = bob
            .process_session_request(&wire, &bob_ident, &bob_iv, &bob_static, 2, now_s)
            .unwrap();

        // h и ck после KDF1 + MixHash(options) + MixHash(padding)
        // должны совпасть у Alice и Bob.
        assert_eq!(
            alice.noise.h, bob.noise.h,
            "h mismatch after SessionRequest"
        );
        assert_eq!(
            alice.noise.ck, bob.noise.ck,
            "ck mismatch after SessionRequest"
        );
    }

    #[test]
    fn process_session_request_iv_updated() {
        let (_, mut bob, wire, bob_static, bob_ident, bob_iv) = alice_and_bob_session_request();
        let orig_iv = bob.iv;
        let now_s = 1_000_000;

        let _ = bob
            .process_session_request(&wire, &bob_ident, &bob_iv, &bob_static, 2, now_s)
            .unwrap();

        // IV обновлён на последние 16 байт ciphertext'а X.
        assert_ne!(bob.iv, orig_iv);
        assert_eq!(&bob.iv[..], &wire[16..32]);
    }

    #[test]
    fn process_session_request_rejects_wrong_net_id() {
        let (_, mut bob, wire, bob_static, bob_ident, bob_iv) = alice_and_bob_session_request();
        let now_s = 1_000_000;

        // Просим Bob'а ожидать netId = 3, а Alice прислала 2.
        let r = bob.process_session_request(&wire, &bob_ident, &bob_iv, &bob_static, 3, now_s);
        assert!(
            matches!(r, Err(I2PError::Malformed(msg)) if msg.contains("netId")),
            "expected netId mismatch, got {r:?}"
        );
    }

    #[test]
    fn process_session_request_rejects_wrong_iv() {
        let (_, mut bob, wire, bob_static, bob_id, _bob_iv) = alice_and_bob_session_request();
        let wrong_iv = [0x00u8; 16];
        let now_s = 1_000_000;

        // AES-CBC с другим IV даст «мусор» — последний байт
        // заведомо не подойдёт для KDF (или отклонится pq-флагом).
        let r = bob.process_session_request(&wire, &bob_id, &wrong_iv, &bob_static, 2, now_s);
        assert!(r.is_err(), "wrong IV must not succeed, got {r:?}");
    }

    #[test]
    fn process_session_request_rejects_short_wire() {
        let (_, mut bob, _wire, bob_static, bob_ident, bob_iv) = alice_and_bob_session_request();
        let now_s = 1_000_000;

        let r = bob.process_session_request(&[0u8; 30], &bob_ident, &bob_iv, &bob_static, 2, now_s);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn process_session_request_detects_clock_skew() {
        let (_, mut bob, wire, bob_static, bob_ident, bob_iv) = alice_and_bob_session_request();

        // Симулируем, что "сейчас" — далеко в будущем (день спустя).
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400;

        let info = bob
            .process_session_request(&wire, &bob_ident, &bob_iv, &bob_static, 2, far_future)
            .unwrap();
        assert!(info.clock_skew, "skew of 1 day must be detected");
    }

    #[test]
    fn is_clock_skew_exceeded_boundaries() {
        // В тесте `now_s` — u64, а `ts_a` — u32. Для читаемости
        // держим `skew` уже как u32; в реальном коде это u64-константа,
        // но её значение (60) точно влезает в u32.
        let skew = u32::try_from(NTCP2_CLOCK_SKEW_SECS).expect("60 fits u32");

        // Точно в пределах skew — не сработало.
        assert!(!is_clock_skew_exceeded(1000, u64::from(1000 + skew)));
        assert!(!is_clock_skew_exceeded(1000 + skew, 1000));
        // На секунду за пределами — сработало.
        assert!(is_clock_skew_exceeded(1000, u64::from(1000 + skew + 1)));
        assert!(is_clock_skew_exceeded(1000 + skew + 1, 1000));
        // Точное совпадение — не сработало.
        assert!(!is_clock_skew_exceeded(42, 42));
    }

    // ---- SessionCreated -------------------------------------------------

    /// Хелпер: Alice создала `SessionRequest`, Bob его принял — обе
    /// стороны готовы к `SessionCreated`. Возвращает `(alice, bob, bob_static)`.
    fn after_session_request() -> (Ntcp2Establisher, Ntcp2Establisher, I2PX25519Keys) {
        let bob_static = I2PX25519Keys::generate();
        let bob_ident_hash = [0x42u8; 32];
        let bob_iv = [0x37u8; 16];

        let mut alice = Ntcp2Establisher::new();
        alice.remote_static_pub = *bob_static.public_key();
        alice.remote_ident_hash = bob_ident_hash;
        alice.iv = bob_iv;

        let mut bob = Ntcp2Establisher::new();
        bob.iv = bob_iv;

        let fake_ri = vec![0xAAu8; 100];
        let mut rng = StdRng::seed_from_u64(7);
        let wire = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();

        let now_s = 1_700_000_000;
        bob.process_session_request(&wire, &bob_ident_hash, &bob_iv, &bob_static, 2, now_s)
            .unwrap();

        (alice, bob, bob_static)
    }

    #[test]
    fn session_created_roundtrip() {
        let (mut alice, mut bob, _) = after_session_request();

        let bob_ident_hash = [0x42u8; 32];
        let now_s = 1_700_000_100;
        let mut rng = StdRng::seed_from_u64(8);
        let wire = bob
            .create_session_created(&bob_ident_hash, 2, now_s, &mut rng)
            .unwrap();

        assert!(wire.len() >= 64);
        assert!(wire.len() <= 64 + 223);

        let bob_y = *bob.ephemeral.public_key();
        let info = alice.process_session_created(&wire, now_s).unwrap();
        assert_eq!(info.remote_ephemeral_pub, bob_y);
        assert!(!info.clock_skew);
    }

    #[test]
    fn session_created_noise_state_syncs() {
        let (mut alice, mut bob, _) = after_session_request();

        let bob_ident_hash = [0x42u8; 32];
        let now_s = 1_700_000_100;
        let mut rng = StdRng::seed_from_u64(9);
        let wire = bob
            .create_session_created(&bob_ident_hash, 2, now_s, &mut rng)
            .unwrap();
        let _ = alice.process_session_created(&wire, now_s).unwrap();

        // После SessionCreated h и ck должны совпадать — иначе
        // SessionConfirmed не расшифруется.
        assert_eq!(
            alice.noise.h, bob.noise.h,
            "h mismatch after SessionCreated"
        );
        assert_eq!(
            alice.noise.ck, bob.noise.ck,
            "ck mismatch after SessionCreated"
        );
    }

    #[test]
    fn session_created_iv_advances_on_both_sides() {
        let (mut alice, mut bob, _) = after_session_request();
        let alice_iv_before = alice.iv;
        let bob_iv_before = bob.iv;

        let bob_ident_hash = [0x42u8; 32];
        let now_s = 1_700_000_100;
        let mut rng = StdRng::seed_from_u64(10);
        let wire = bob
            .create_session_created(&bob_ident_hash, 2, now_s, &mut rng)
            .unwrap();
        let _ = alice.process_session_created(&wire, now_s).unwrap();

        // У Bob'а IV обновился при шифровании Y (это IV для SessionConfirmed part1).
        assert_ne!(bob.iv, bob_iv_before);
        // У Alice — при расшифровке Y, к тому же значению.
        assert_eq!(alice.iv, bob.iv, "IV must match on both sides");
        // И оба отличаются от IV до SessionCreated.
        assert_ne!(alice.iv, alice_iv_before);
    }

    #[test]
    fn session_created_detects_clock_skew() {
        let (mut alice, mut bob, _) = after_session_request();

        let bob_ident_hash = [0x42u8; 32];
        let bob_ts = 1_700_000_100;
        let mut rng = StdRng::seed_from_u64(11);
        let wire = bob
            .create_session_created(&bob_ident_hash, 2, bob_ts, &mut rng)
            .unwrap();

        // Alice считает, что сейчас сильно позже.
        let alice_now = bob_ts + 86400;
        let info = alice.process_session_created(&wire, alice_now).unwrap();
        assert!(info.clock_skew);
        assert_eq!(info.ts_b, u32::try_from(bob_ts).unwrap());
    }

    #[test]
    fn session_created_short_wire_rejected() {
        let (mut alice, _, _) = after_session_request();
        let r = alice.process_session_created(&[0u8; 30], 0);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn session_created_wrong_ident_hash_fails() {
        let (mut alice, mut bob, _) = after_session_request();

        // Bob шифрует своим настоящим ident hash.
        let bob_ident_hash = [0x42u8; 32];
        let now_s = 1_700_000_100;
        let mut rng = StdRng::seed_from_u64(12);
        let wire = bob
            .create_session_created(&bob_ident_hash, 2, now_s, &mut rng)
            .unwrap();

        // Alice думает, что у Bob'а другой ident hash — Y расшифруется
        // в мусор, старший бит может быть установлен или DH упадёт.
        alice.remote_ident_hash = [0x99u8; 32];
        let r = alice.process_session_created(&wire, now_s);
        assert!(r.is_err(), "wrong ident hash must fail");
    }

    /// Опции `SessionCreated`: padLen и tsB должны стоять на тех же
    /// смещениях, что в i2pd (`options[2..4]` и `options[10..14]`).
    /// Проверяем через round-trip — если сместим, тест сломается.
    #[test]
    fn session_created_options_layout() {
        let (mut alice, mut bob, _) = after_session_request();

        let bob_ident_hash = [0x42u8; 32];
        let bob_ts = 1_700_000_500;
        let mut rng = StdRng::seed_from_u64(13);
        let wire = bob
            .create_session_created(&bob_ident_hash, 2, bob_ts, &mut rng)
            .unwrap();

        let info = alice.process_session_created(&wire, bob_ts).unwrap();
        assert_eq!(info.ts_b, u32::try_from(bob_ts).unwrap());
        // padding_len — что-то валидное.
        assert!(info.padding_len <= NTCP2_MAX_HANDSHAKE_PADDING_LEN);
    }

    // ---- SessionConfirmed -----------------------------------------------

    /// Хелпер: Alice и Bob прошли KDF1, KDF2 (у Alice — через `SessionCreated`).
    /// У Alice заполнен `m3p2_block`; обе стороны могут делать KDF3.
    fn after_session_created() -> (
        Ntcp2Establisher,
        Ntcp2Establisher,
        I2PX25519Keys,
        I2PX25519Keys,
    ) {
        let alice_static = I2PX25519Keys::generate();
        let bob_static = I2PX25519Keys::generate();
        let bob_ident_hash = [0x42u8; 32];
        let bob_iv = [0x37u8; 16];

        let mut alice = Ntcp2Establisher::new();
        alice.remote_static_pub = *bob_static.public_key();
        alice.remote_ident_hash = bob_ident_hash;
        alice.iv = bob_iv;

        let mut bob = Ntcp2Establisher::new();
        bob.iv = bob_iv;

        // SessionRequest → Bob.
        let fake_ri = vec![0xAAu8; 100];
        let mut rng = StdRng::seed_from_u64(20);
        let req = alice.create_session_request(&fake_ri, 2, &mut rng).unwrap();
        let now_s = 1_700_000_000;
        bob.process_session_request(&req, &bob_ident_hash, &bob_iv, &bob_static, 2, now_s)
            .unwrap();

        // SessionCreated → Alice.
        let mut rng = StdRng::seed_from_u64(21);
        let created = bob
            .create_session_created(&bob_ident_hash, 2, now_s, &mut rng)
            .unwrap();
        alice.process_session_created(&created, now_s).unwrap();

        (alice, bob, alice_static, bob_static)
    }

    #[test]
    fn session_confirmed_roundtrip() {
        let (mut alice, mut bob, alice_static, _bob_static) = after_session_created();

        let wire = alice.create_session_confirmed(&alice_static).unwrap();
        // 48 (part1) + m3p2_len (part2 с MAC).
        assert_eq!(wire.len(), 48 + usize::from(alice.m3p2_len()));

        let info = bob.process_session_confirmed(&wire).unwrap();
        // Static pub Alice'а совпал.
        assert_eq!(info.remote_static_pub, *alice_static.public_key());
        // RouterInfo содержит тестовые байты.
        assert_eq!(info.remote_router_info.len(), 100);
        assert!(info.remote_router_info.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn session_confirmed_noise_state_finalized() {
        let (mut alice, mut bob, alice_static, _) = after_session_created();

        let wire = alice.create_session_confirmed(&alice_static).unwrap();
        let _ = bob.process_session_confirmed(&wire).unwrap();

        // После SessionConfirmed h и ck совпадают — можно выводить data phase.
        assert_eq!(
            alice.noise.h, bob.noise.h,
            "h mismatch after SessionConfirmed"
        );
        assert_eq!(
            alice.noise.ck, bob.noise.ck,
            "ck mismatch after SessionConfirmed"
        );
    }

    #[test]
    fn session_confirmed_data_phase_derives_symmetric_keys() {
        let (mut alice, mut bob, alice_static, _) = after_session_created();

        let wire = alice.create_session_confirmed(&alice_static).unwrap();
        let _ = bob.process_session_confirmed(&wire).unwrap();

        let alice_dp = alice.derive_data_phase(true);
        let bob_dp = bob.derive_data_phase(false);

        // Ключи зеркальны — можно обмениваться фреймами.
        assert_eq!(alice_dp.send_key, bob_dp.receive_key);
        assert_eq!(alice_dp.receive_key, bob_dp.send_key);
    }

    #[test]
    fn session_confirmed_short_wire_rejected() {
        let (mut alice, mut bob, alice_static, _) = after_session_created();
        let wire = alice.create_session_confirmed(&alice_static).unwrap();

        // Обрезаем — AEAD должен упасть или длины не хватит.
        let r = bob.process_session_confirmed(&wire[..40]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn session_confirmed_tampered_part1_fails() {
        let (mut alice, mut bob, alice_static, _) = after_session_created();
        let mut wire = alice.create_session_confirmed(&alice_static).unwrap();

        // Портим байт в part1.
        wire[10] ^= 0xFF;
        let r = bob.process_session_confirmed(&wire);
        assert!(r.is_err(), "tampered part1 must fail AEAD");
    }

    #[test]
    fn session_confirmed_tampered_part2_fails() {
        let (mut alice, mut bob, alice_static, _) = after_session_created();
        let mut wire = alice.create_session_confirmed(&alice_static).unwrap();

        // Портим байт в part2.
        let tampered_idx = 60;
        wire[tampered_idx] ^= 0xFF;
        let r = bob.process_session_confirmed(&wire);
        assert!(r.is_err(), "tampered part2 must fail AEAD");
    }

    #[test]
    fn session_confirmed_without_session_request_fails() {
        let alice_static = I2PX25519Keys::generate();
        let mut alice = Ntcp2Establisher::new();
        // m3p2_block пуст — Alice не создавала SessionRequest.
        let r = alice.create_session_confirmed(&alice_static);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn session_confirmed_wire_layout() {
        let (mut alice, _, alice_static, _) = after_session_created();
        let m3p2_len = usize::from(alice.m3p2_len());

        let wire = alice.create_session_confirmed(&alice_static).unwrap();

        // part1 — 48 байт, далее ровно m3p2_len.
        assert_eq!(wire.len(), 48 + m3p2_len);
    }

    // ---- Ntcp2Block сериализация ----------------------------------------

    #[test]
    fn block_roundtrip_datetime() {
        let b = Ntcp2Block::DateTime { ts: 1_700_000_000 };
        let bytes = b.to_bytes().unwrap();
        assert_eq!(bytes, [0x00, 0x00, 0x04, 0x65, 0x53, 0xF1, 0x00]);
        let (back, consumed) = Ntcp2Block::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(back, b);
    }

    #[test]
    fn block_roundtrip_router_info() {
        let b = Ntcp2Block::RouterInfo {
            flag: 0x01,
            ri_bytes: vec![0xAA; 50],
        };
        let bytes = b.to_bytes().unwrap();
        assert_eq!(bytes[0], Ntcp2BlockType::RouterInfo.as_u8());
        assert_eq!(&bytes[1..3], &51u16.to_be_bytes());
        let (back, _) = Ntcp2Block::from_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn block_roundtrip_i2np() {
        let b = Ntcp2Block::I2npMessage(vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        let bytes = b.to_bytes().unwrap();
        let (back, _) = Ntcp2Block::from_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn block_roundtrip_termination() {
        let b = Ntcp2Block::Termination {
            seqn: 0x0102_0304_0506_0708,
            reason: Ntcp2TerminationReason::IdleTimeout,
        };
        let bytes = b.to_bytes().unwrap();
        assert_eq!(bytes.len(), 12); // 3 + 9
        let (back, _) = Ntcp2Block::from_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn block_roundtrip_padding() {
        let b = Ntcp2Block::Padding(13);
        let bytes = b.to_bytes().unwrap();
        assert_eq!(bytes.len(), 16); // 3 + 13
        let (back, _) = Ntcp2Block::from_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn block_roundtrip_options() {
        let b = Ntcp2Block::Options(vec![1, 2, 3]);
        let bytes = b.to_bytes().unwrap();
        let (back, _) = Ntcp2Block::from_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn parse_ntcp2_blocks_sequence() {
        let blocks = vec![
            Ntcp2Block::DateTime { ts: 42 },
            Ntcp2Block::I2npMessage(vec![0xAA, 0xBB]),
            Ntcp2Block::Padding(5),
        ];
        let bytes = serialize_ntcp2_blocks(&blocks).unwrap();
        let parsed = parse_ntcp2_blocks(&bytes).unwrap();
        assert_eq!(parsed, blocks);
    }

    #[test]
    fn parse_ntcp2_blocks_truncated_header_fails() {
        // 2 байта — не хватает на заголовок блока (3 байта).
        let r = parse_ntcp2_blocks(&[0x00, 0x00]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn parse_ntcp2_blocks_truncated_i2np_fails() {
        // I2NP с size=10, но тела нет.
        let bytes = [Ntcp2BlockType::I2npMessage.as_u8(), 0x00, 0x0A];
        let r = parse_ntcp2_blocks(&bytes);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn parse_ntcp2_blocks_padding_truncated_is_ok() {
        // Padding с size=100, но в буфере только 5 байт тела.
        // i2pd позволяет padding «съесть» хвост фрейма.
        let mut bytes = vec![Ntcp2BlockType::Padding.as_u8(), 0x00, 0x64];
        bytes.extend_from_slice(&[0u8; 5]);
        let parsed = parse_ntcp2_blocks(&bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], Ntcp2Block::Padding(5));
    }

    // ---- Ntcp2DataPhase: фрейминг ---------------------------------------

    fn dp_pair() -> (Ntcp2DataPhase, Ntcp2DataPhase) {
        let ck = [0xAAu8; 32];
        let h = [0xBBu8; 32];
        (
            Ntcp2DataPhase::derive(&ck, &h, true),
            Ntcp2DataPhase::derive(&ck, &h, false),
        )
    }

    #[test]
    fn frame_roundtrip_empty() {
        let (mut alice, mut bob) = dp_pair();
        let wire = alice.create_frame(&[]).unwrap();
        // 2 + 16 (MAC от пустого plaintext'а).
        assert_eq!(wire.len(), 2 + 16);
        let parsed = bob.parse_frame(&wire).unwrap();
        assert_eq!(parsed, Vec::<Ntcp2Block>::new());
    }

    #[test]
    fn frame_roundtrip_multiple_blocks() {
        let (mut alice, mut bob) = dp_pair();
        let blocks = vec![
            Ntcp2Block::DateTime { ts: 42 },
            Ntcp2Block::I2npMessage(vec![0xAA; 100]),
            Ntcp2Block::Padding(7),
        ];
        let wire = alice.create_frame(&blocks).unwrap();
        let parsed = bob.parse_frame(&wire).unwrap();
        assert_eq!(parsed, blocks);
    }

    #[test]
    fn frame_roundtrip_consecutive() {
        // Несколько фреймов подряд — IV rolling и seq работают.
        let (mut alice, mut bob) = dp_pair();
        for i in 0u32..10 {
            let blocks = vec![Ntcp2Block::DateTime { ts: i }];
            let wire = alice.create_frame(&blocks).unwrap();
            let parsed = bob.parse_frame(&wire).unwrap();
            assert_eq!(parsed, blocks, "iteration {i}");
        }
    }

    #[test]
    fn frame_read_then_decrypt_split_api() {
        // Тот же результат через read_frame_length + decrypt_frame.
        let (mut alice, mut bob) = dp_pair();
        let blocks = vec![Ntcp2Block::I2npMessage(vec![1, 2, 3])];
        let wire = alice.create_frame(&blocks).unwrap();

        let prefix = [wire[0], wire[1]];
        let frame_len = usize::from(bob.read_frame_length(prefix));
        assert_eq!(frame_len + 2, wire.len());
        let parsed = bob.decrypt_frame(&wire[2..]).unwrap();
        assert_eq!(parsed, blocks);
    }

    #[test]
    fn frame_tampered_fails() {
        let (mut alice, mut bob) = dp_pair();
        let mut wire = alice
            .create_frame(&[Ntcp2Block::I2npMessage(vec![0xAA; 10])])
            .unwrap();
        // Портим байт в ciphertext'е.
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;
        let r = bob.parse_frame(&wire);
        assert!(r.is_err(), "tampered frame must fail AEAD");
    }

    #[test]
    fn frame_short_wire_fails() {
        let (_, mut bob) = dp_pair();
        let r = bob.parse_frame(&[0x00]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn frame_too_large_fails() {
        // `Padding(70_000)` — тело блока больше `u16::MAX`,
        // `Ntcp2Block::to_bytes` вернёт `Malformed`.
        let (mut alice, _) = dp_pair();
        let big = vec![Ntcp2Block::Padding(70_000)];
        let r = alice.create_frame(&big);
        assert!(matches!(r, Err(I2PError::Malformed(_))));

        // А это — большая, но влезающая в блок длина; кадр упадёт
        // на проверке `frame_len + 2 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE`.
        let (mut alice, _) = dp_pair();
        let big = vec![Ntcp2Block::Padding(65_500)];
        let r = alice.create_frame(&big);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    // ---- NTCP2 session (tokio) ------------------------------------------

    /// Собирает `RouterInfo` с одним опубликованным NTCP2-адресом
    /// (127.0.0.1:12345, который не используется — адрес нужен только
    /// чтобы handshake'у было откуда брать `s` и `i`).
    fn make_ri_with_ntcp2(
        keys: &I2PPrivateKeys,
        ntcp2_static: &I2PX25519Keys,
        ntcp2_iv: [u8; 16],
    ) -> Vec<u8> {
        let mut static_bytes = [0u8; 32];
        static_bytes.copy_from_slice(ntcp2_static.public_key());

        let addr = I2PAddress::ntcp2_published(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12345,
            I2PTag::from_array(static_bytes),
            ntcp2_iv,
        );
        let body = RouterInfo::builder()
            .timestamp(1_700_000_000_000)
            .add_address(addr)
            .build();
        let full = FullRouterInfo::from_keys(keys, body).unwrap();
        full.to_buffer().unwrap()
    }

    /// Готовит все данные для handshake'а на одной стороне.
    struct Side {
        keys: I2PPrivateKeys,
        ntcp2_static: I2PX25519Keys,
        ntcp2_iv: [u8; 16],
        ri_bytes: Vec<u8>,
    }

    impl Side {
        fn new(iv_byte: u8) -> Self {
            let keys = I2PPrivateKeys::generate_default().unwrap();
            let ntcp2_static = I2PX25519Keys::generate();
            let ntcp2_iv = [iv_byte; 16];
            let ri_bytes = make_ri_with_ntcp2(&keys, &ntcp2_static, ntcp2_iv);
            Self {
                keys,
                ntcp2_static,
                ntcp2_iv,
                ri_bytes,
            }
        }

        fn ident_hash(&self) -> [u8; 32] {
            *self.keys.public().ident_hash().as_bytes()
        }

        fn config(&self) -> Ntcp2LocalConfig<'_> {
            Ntcp2LocalConfig {
                static_keys: &self.ntcp2_static,
                ident_hash: self.ident_hash(),
                iv: self.ntcp2_iv,
                ri_bytes: &self.ri_bytes,
                net_id: 2,
            }
        }
    }

    #[tokio::test]
    async fn tokio_full_handshake_and_i2np_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x11);
        let bob = Side::new(0x22);

        // Клонируем то, что Alice'у нужно до того, как `bob` уедет
        // в spawned-задачу.
        let bob_ri_bytes = bob.ri_bytes.clone();
        let bob_ident_hash = bob.ident_hash();

        // Bob принимает в фоне.
        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await.map(|s| (s, bob))
        });

        // Alice подключается.
        let alice_stream = TcpStream::connect(server_addr).await.unwrap();
        let alice_cfg = alice.config();
        let mut alice_session = Ntcp2Session::connect(alice_stream, &alice_cfg, &bob_ri_bytes)
            .await
            .expect("alice handshake");

        let (mut bob_session, _bob) = bob_task.await.unwrap().expect("bob handshake");

        assert!(alice_session.is_alice());
        assert!(!bob_session.is_alice());
        assert_eq!(
            alice_session.remote_ident_hash(),
            &bob_ident_hash,
            "alice must see bob's ident hash"
        );
        assert_eq!(
            bob_session.remote_ident_hash(),
            &alice.ident_hash(),
            "bob must see alice's ident hash"
        );

        // Alice → Bob.
        let m1 = I2npMsg::new(I2npMessageType::Data, vec![1, 2, 3, 4]);
        alice_session.send_i2np(&m1).await.unwrap();
        let got = bob_session.recv_i2np().await.unwrap();
        assert_eq!(got.message_type(), I2npMessageType::Data);
        assert_eq!(got.payload(), &[1, 2, 3, 4]);

        // Bob → Alice.
        let m2 = I2npMsg::new(I2npMessageType::DeliveryStatus, vec![9, 9]);
        bob_session.send_i2np(&m2).await.unwrap();
        let got = alice_session.recv_i2np().await.unwrap();
        assert_eq!(got.message_type(), I2npMessageType::DeliveryStatus);
        assert_eq!(got.payload(), &[9, 9]);

        // Несколько сообщений подряд.
        for i in 0u8..5 {
            let m = I2npMsg::new(I2npMessageType::Data, vec![i]);
            alice_session.send_i2np(&m).await.unwrap();
            let got = bob_session.recv_i2np().await.unwrap();
            assert_eq!(got.payload(), &[i]);
        }
    }

    #[tokio::test]
    async fn tokio_bob_sends_router_info_in_first_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x33);
        let bob = Side::new(0x44);
        let bob_ri_expected = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await.map(|s| (s, bob))
        });

        let alice_stream = TcpStream::connect(server_addr).await.unwrap();
        let alice_cfg = alice.config();
        let mut alice_session = Ntcp2Session::connect(alice_stream, &alice_cfg, &bob_ri_expected)
            .await
            .unwrap();

        let (mut bob_session, _bob) = bob_task.await.unwrap().unwrap();

        // Alice уже знает RI Bob'а — он был передан вызывающим.
        assert_eq!(
            alice_session.remote_router_info(),
            Some(bob_ri_expected.as_slice())
        );

        // Bob шлёт что-то — в первом фрейме уйдёт его RI.
        let m = I2npMsg::new(I2npMessageType::Data, vec![0xAB]);
        bob_session.send_i2np(&m).await.unwrap();

        // Alice принимает, попутно усваивает RI Bob'а.
        let _ = alice_session.recv_i2np().await.unwrap();
        assert_eq!(
            alice_session.remote_router_info(),
            Some(bob_ri_expected.as_slice()),
            "alice must have bob's RI after first frame"
        );
    }
}
