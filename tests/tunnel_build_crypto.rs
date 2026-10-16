#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sha2::{Digest, Sha256};
    use uu_i2p::crypto::{chacha20_counter1, init_noise_n_state};
    use uu_i2p::tunnel_build_crypto::*;
    use uu_i2p::tunnel_build_record::*;
    use uu_i2p::tunnel_config::TunnelConfig;
    use uu_i2p::{I2PError, I2PX25519Keys, IdentHash, NoiseSymmetricState, ShortTunnelBuildBody};

    // ---- эталонные векторы -------------------------------------------------
    //
    // Получены независимой реализацией на Python (`cryptography`), по
    // алгоритму i2pd: Noise_N_25519_ChaChaPoly_SHA256, HKDF-цепочка
    // SMTunnelReplyKey / SMTunnelLayerKey / TunnelLayerIVKey /
    // RGarlicKeyAndTag, ChaCha20 со счётчиком 1.
    //
    // Запрос: receive=0x11223344, next=0x55667788, next_ident=[0xAB;32],
    // request_time=0x01020304, expiration=600, send_msg_id=0xDEADBEEF,
    // пустые options. Флаги: gateway (0x80) или endpoint (0x40).

    const STATIC_PRIV: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const EPH_PRIV: &str = "65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384";
    const SPUB: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
    const EPUB: &str = "5714769d116bf76436ae74bc793d2c30ad1903c59ac5273805c7e2698b410c36";

    const GW_CT: &str = "d96c9b8de5c2e64f13d575983aa3b731ca892d65c8f4e792c7a61d981097bb2729a1534271c980af9957e3f6bbb9bc735466a907f1f5440eeaa0b4fa1b04dc95f240d86594e15d0dbd2dad49cdef2a1aa7d3e732d17e6819f6a4c4604aaad171ec396cbe175cbcdefe09a26f257fa2d39410835d2c990e234fd5e9993ce90c63b0bab6e3ec79a7ed84ee5dbd32a617cdac1dcc8f5ff62d778821e7909d76607f78df56a1db917a244927";
    const GW_H: &str = "db2633521457051e217572d3988035b2d8ca831d6021fe778216cba73b548004";
    const GW_REPLY: &str = "4698c621c6a54914975c388e67a5a7493b6bf63d9123afdd9948f58f65f12e07";
    const GW_LAYER: &str = "c282f1cb1fef75b5f91b824ccc219a740b4beb905c321d6fdfb7b468d3885b9d";
    const GW_IV: &str = "150bd2c24efb385c4010118e859d003d8615c164ec53e980e5a2371cbebef1e6";

    const EP_CT: &str = "d96c9b8de5c2e64f13d575983aa3b731ca892d65c8f4e792c7a61d981097bb2729a1534271c980af5957e3f6bbb9bc735466a907f1f5440eeaa0b4fa1b04dc95f240d86594e15d0dbd2dad49cdef2a1aa7d3e732d17e6819f6a4c4604aaad171ec396cbe175cbcdefe09a26f257fa2d39410835d2c990e234fd5e9993ce90c63b0bab6e3ec79a7ed84ee5dbd32a617cdac1dcc8f5ff62d7788219da3fe732e3f686a750469483f74bc92";
    const EP_H: &str = "2b1b14545ba8d08d9e49a2f594aa8e1b402dbd183082ddaa583a2035eaf0c0e8";
    const EP_REPLY: &str = "4698c621c6a54914975c388e67a5a7493b6bf63d9123afdd9948f58f65f12e07";
    const EP_LAYER: &str = "c282f1cb1fef75b5f91b824ccc219a740b4beb905c321d6fdfb7b468d3885b9d";
    const EP_IV: &str = "ad4f159faaeba359021bff13b4206b0a033aec2cf1d1e3392395dfbdc5e44b0a";
    const EP_GARLIC_KEY: &str = "3e3d814089155ae2a51d97eedd3503283b54897533514360365a7753a1b53621";
    const EP_GARLIC_TAG: &str = "28cfb198a13e2e33";

    // ответ хопа 3 (gateway-вариант ключей): options пустые, ret = 0
    const OWN_REPLY_IDX3: &str = "6b50d07d8a155b40561f0886c6aab64cfd315bfe828d48695b5f9b2c67a24eb4fe174c651c6cdcf3fc38fc44c225d889e93d0079b4e35cc360e0e3ec139e80009eefd22bbf8cf3312b40a88ba0aa33977cbc032544b218850bc92c5964d1c32cde6b7441dc7e17abc44e194bc83ff655d20433afccb06ffb578f1397d9a30e0f711df0589655aec046ea10ca9ee8f2f81ecd6d9cd0b0938b610d4a0a19015eab9fa1fff70e931130d847417490463cd9e42c1a675dcd38c571a02662271d10769b1e3697bf8eaa3d2b3e819169d63405c197d1eb9f5e9f745fa6";
    // ChaCha20(reply_key = GW_REPLY, nonce[4] = 5, счётчик 1) от записи
    // с байтами (i * 7 + 1) & 0xFF
    const OTHER_CT_IDX5: &str = "e8847b35452a0d7be7dc817285875a6256ba333eddf5cf60a83d71429382d9c9f96478d6de701bd16238e0c78c545c279af683de1dc33747163f2437eb53f44414e7b3039893bbef4c87cbcc7acc164b46ded5f989c3041602edb81f5fdf29753b1107b569bca85df54ddb3c36927b9b43b05602393a00956a0673d4bf7f06f23bb61324d70979570b2d3214b83a4881e3ea944b0f0195912b7323300bcc5d30351ad80f839903f6d3d70b95c22e44d150c05587d5a55bdb2e3d470263d7a9e5333bec45a38681eec6c362ffa953cb46eda918ae9018b0261720";
    // RFC 8439 §2.4.2 (счётчик 1)
    const RFC_CT: &str = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";

    fn unhex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        unhex(s).try_into().unwrap()
    }

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    fn sample_request(endpoint: bool) -> ShortBuildRequestRecord {
        ShortBuildRequestRecord {
            receive_tunnel: 0x1122_3344,
            next_tunnel: 0x5566_7788,
            next_ident: ident(0xAB),
            is_gateway: !endpoint,
            is_endpoint: endpoint,
            more_flags: [0, 0],
            layer_encryption_type: 0,
            request_time_minutes: 0x0102_0304,
            request_expiration_secs: 600,
            send_msg_id: 0xDEAD_BEEF,
            options: BuildOptions::new(),
        }
    }

    fn static_keys() -> I2PX25519Keys {
        I2PX25519Keys::from_private(&arr::<32>(STATIC_PRIV), None)
    }

    fn eph_keys() -> I2PX25519Keys {
        I2PX25519Keys::from_private(&arr::<32>(EPH_PRIV), None)
    }

    fn hop_ident() -> IdentHash {
        ident(0x77)
    }

    // ---- примитивы ---------------------------------------------------------

    #[test]
    fn chacha20_counter1_rfc8439_vector() {
        let mut key = [0u8; 32];
        for (i, k) in key.iter_mut().enumerate() {
            *k = u8::try_from(i).unwrap();
        }
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut buf = plaintext.to_vec();
        chacha20_counter1(&key, &nonce, &mut buf);
        assert_eq!(buf, unhex(RFC_CT));
        chacha20_counter1(&key, &nonce, &mut buf);
        assert_eq!(&buf[..], &plaintext[..]);
    }

    #[test]
    fn noise_n_init_state() {
        let pubkey = [0x5Au8; 32];
        let mut st = NoiseSymmetricState::new(&[0; 32], &[0; 32], &[0; 32]);
        init_noise_n_state(&mut st, &pubkey);
        let mut name = b"Noise_N_25519_ChaChaPoly_SHA256".to_vec();
        name.push(0);
        assert_eq!(&st.ck[..], &name[..]);
        let hh = Sha256::digest(&name);
        let mut input = hh.to_vec();
        input.extend_from_slice(&pubkey);
        assert_eq!(&st.h[..], &Sha256::digest(&input)[..]);
        assert_eq!(st.n, 0);
    }

    // ---- запрос: векторы ----------------------------------------------------

    #[test]
    fn static_and_ephemeral_public_keys_match_vectors() {
        assert_eq!(static_keys().public_key()[..], unhex(SPUB)[..]);
        assert_eq!(eph_keys().public_key()[..], unhex(EPUB)[..]);
    }

    #[test]
    fn encrypt_request_gateway_matches_vector() {
        let (rec, keys) = encrypt_short_request(
            &sample_request(false),
            &hop_ident(),
            static_keys().public_key(),
            &eph_keys(),
        )
        .unwrap();
        assert_eq!(rec.to_peer, [0x77; 16]);
        assert_eq!(rec.ephemeral_key[..], unhex(EPUB)[..]);
        assert_eq!(rec.ciphertext[..], unhex(GW_CT)[..]);
        assert_eq!(keys.h[..], unhex(GW_H)[..]);
        assert_eq!(keys.reply_key[..], unhex(GW_REPLY)[..]);
        assert_eq!(keys.layer_key[..], unhex(GW_LAYER)[..]);
        assert_eq!(keys.iv_key[..], unhex(GW_IV)[..]);
        assert!(keys.garlic.is_none());
    }

    #[test]
    fn encrypt_request_endpoint_matches_vector() {
        let (rec, keys) = encrypt_short_request(
            &sample_request(true),
            &hop_ident(),
            static_keys().public_key(),
            &eph_keys(),
        )
        .unwrap();
        assert_eq!(rec.ciphertext[..], unhex(EP_CT)[..]);
        assert_eq!(keys.h[..], unhex(EP_H)[..]);
        assert_eq!(keys.reply_key[..], unhex(EP_REPLY)[..]);
        assert_eq!(keys.layer_key[..], unhex(EP_LAYER)[..]);
        assert_eq!(keys.iv_key[..], unhex(EP_IV)[..]);
        let garlic = keys.garlic.as_ref().expect("endpoint has garlic keys");
        assert_eq!(garlic.key[..], unhex(EP_GARLIC_KEY)[..]);
        assert_eq!(garlic.tag[..], unhex(EP_GARLIC_TAG)[..]);
    }

    #[test]
    fn decrypt_request_matches_vector() {
        for endpoint in [false, true] {
            let (rec, keys) = encrypt_short_request(
                &sample_request(endpoint),
                &hop_ident(),
                static_keys().public_key(),
                &eph_keys(),
            )
            .unwrap();
            let (req, keys2) = decrypt_short_request(&rec, &static_keys()).unwrap();
            assert_eq!(req, sample_request(endpoint));
            assert_eq!(keys2, keys);
            assert_eq!(keys2.garlic.is_some(), endpoint);
        }
    }

    #[test]
    fn decrypt_request_from_vector_bytes() {
        let rec = EncryptedShortRecord {
            to_peer: [0x77; 16],
            ephemeral_key: arr(EPUB),
            ciphertext: arr(GW_CT),
        };
        let (req, keys) = decrypt_short_request(&rec, &static_keys()).unwrap();
        assert_eq!(req, sample_request(false));
        assert_eq!(keys.reply_key[..], unhex(GW_REPLY)[..]);
    }

    // ---- запрос: отказы -----------------------------------------------------

    fn good_record() -> EncryptedShortRecord {
        encrypt_short_request(
            &sample_request(false),
            &hop_ident(),
            static_keys().public_key(),
            &eph_keys(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn decrypt_rejects_flipped_ciphertext_bit() {
        for pos in [0usize, 77, 153, 154, 169] {
            let mut rec = good_record();
            rec.ciphertext[pos] ^= 0x01;
            assert!(
                matches!(
                    decrypt_short_request(&rec, &static_keys()),
                    Err(I2PError::Malformed(_))
                ),
                "byte {pos}"
            );
        }
    }

    #[test]
    fn decrypt_rejects_flipped_ephemeral_key() {
        let mut rec = good_record();
        rec.ephemeral_key[3] ^= 0x80;
        assert!(decrypt_short_request(&rec, &static_keys()).is_err());
    }

    #[test]
    fn decrypt_rejects_wrong_static_key() {
        let other = I2PX25519Keys::from_private(&[0x33; 32], None);
        assert!(decrypt_short_request(&good_record(), &other).is_err());
    }

    #[test]
    fn decrypt_rejects_zero_ephemeral_key() {
        let mut rec = good_record();
        rec.ephemeral_key = [0; 32];
        assert!(decrypt_short_request(&rec, &static_keys()).is_err());
    }

    #[test]
    fn encrypt_rejects_zero_hop_public_key() {
        let r = encrypt_short_request(&sample_request(false), &hop_ident(), &[0; 32], &eph_keys());
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn decrypt_rejects_non_aes_layer_encryption() {
        let mut req = sample_request(false);
        req.layer_encryption_type = 1;
        let (rec, _) =
            encrypt_short_request(&req, &hop_ident(), static_keys().public_key(), &eph_keys())
                .unwrap();
        assert!(matches!(
            decrypt_short_request(&rec, &static_keys()),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn encrypt_propagates_oversized_options() {
        let mut req = sample_request(false);
        req.options.insert("k", &"v".repeat(92));
        let r = encrypt_short_request(&req, &hop_ident(), static_keys().public_key(), &eph_keys());
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    // ---- ответ: векторы -----------------------------------------------------

    fn gw_keys() -> RecordKeys {
        encrypt_short_request(
            &sample_request(false),
            &hop_ident(),
            static_keys().public_key(),
            &eph_keys(),
        )
        .unwrap()
        .1
    }

    fn accept() -> ShortBuildResponseRecord {
        ShortBuildResponseRecord {
            options: BuildOptions::new(),
            ret: BuildRetCode::Accept,
        }
    }

    #[test]
    fn own_reply_record_matches_vector() {
        let rec = encrypt_reply_record(&gw_keys(), 3, &accept()).unwrap();
        assert_eq!(rec.to_bytes()[..], unhex(OWN_REPLY_IDX3)[..]);
    }

    #[test]
    fn own_reply_record_roundtrip_and_index_binding() {
        let keys = gw_keys();
        let mut options = BuildOptions::new();
        options.insert(OPTION_AVAILABLE_BANDWIDTH, "1000");
        let resp = ShortBuildResponseRecord {
            options,
            ret: BuildRetCode::Bandwidth,
        };
        let rec = encrypt_reply_record(&keys, 2, &resp).unwrap();
        assert_eq!(decrypt_reply_record(&keys, 2, &rec).unwrap(), resp);
        // nonce зависит от индекса записи
        assert!(decrypt_reply_record(&keys, 3, &rec).is_err());
        // AD — h: другие ключи не подойдут
        let other = encrypt_short_request(
            &sample_request(true),
            &hop_ident(),
            static_keys().public_key(),
            &eph_keys(),
        )
        .unwrap()
        .1;
        assert!(decrypt_reply_record(&other, 2, &rec).is_err());
    }

    #[test]
    fn reply_layer_matches_vector_and_is_involution() {
        let keys = gw_keys();
        let plain: Vec<u8> = (0..218u32)
            .map(|i| u8::try_from((i * 7 + 1) & 0xFF).unwrap())
            .collect();
        let mut rec = EncryptedShortRecord::from_bytes(&plain).unwrap();
        apply_reply_layer(&keys.reply_key, 5, &mut rec).unwrap();
        assert_eq!(rec.to_bytes()[..], unhex(OTHER_CT_IDX5)[..]);
        apply_reply_layer(&keys.reply_key, 5, &mut rec).unwrap();
        assert_eq!(rec.to_bytes()[..], plain[..]);
    }

    #[test]
    fn reply_layer_index_above_255_rejected() {
        let mut rec = EncryptedShortRecord::from_bytes(&[0u8; 218]).unwrap();
        assert!(apply_reply_layer(&[1; 32], 256, &mut rec).is_err());
    }

    // ---- RecordKeys ---------------------------------------------------------

    #[test]
    fn record_keys_debug_does_not_leak() {
        let s = format!("{:?}", gw_keys());
        assert!(s.contains("RecordKeys"));
        assert!(!s.contains("reply_key"));
        assert!(!s.contains(&GW_REPLY[..16]));
    }

    #[test]
    fn apply_to_copies_three_keys() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut cfg = TunnelConfig::inbound(&[ident(1)], ident(9), &mut rng).unwrap();
        let keys = gw_keys();
        keys.apply_to(&mut cfg.hops_mut()[0]);
        let hop = cfg.first_hop();
        assert_eq!(hop.reply_key, keys.reply_key);
        assert_eq!(hop.layer_key, keys.layer_key);
        assert_eq!(hop.iv_key, keys.iv_key);
    }

    #[test]
    fn request_for_hop_maps_fields() {
        let mut rng = StdRng::seed_from_u64(2);
        let cfg =
            TunnelConfig::outbound(&[ident(1), ident(2)], 0xABCD, ident(9), &mut rng).unwrap();
        let first = request_for_hop(&cfg.hops()[0], 123, 456);
        assert_eq!(first.receive_tunnel, cfg.hops()[0].tunnel_id);
        assert_eq!(first.next_tunnel, cfg.hops()[1].tunnel_id);
        assert_eq!(first.next_ident, ident(2));
        assert!(!first.is_gateway && !first.is_endpoint);
        assert_eq!(first.layer_encryption_type, 0);
        assert_eq!(first.request_time_minutes, 123);
        assert_eq!(
            first.request_expiration_secs,
            DEFAULT_REQUEST_EXPIRATION_SECS
        );
        assert_eq!(first.send_msg_id, 456);
        assert!(first.options.is_empty());
        let last = request_for_hop(&cfg.hops()[1], 123, 789);
        assert!(last.is_endpoint);
        assert_eq!(last.next_tunnel, 0xABCD);
        assert_eq!(last.next_ident, ident(9));
    }

    // ---- сквозной сценарий ---------------------------------------------------

    fn hop_static(n: usize) -> I2PX25519Keys {
        I2PX25519Keys::from_private(&[u8::try_from(n).unwrap() + 0x10; 32], None)
    }

    fn hop_eph(n: usize) -> I2PX25519Keys {
        I2PX25519Keys::from_private(&[u8::try_from(n).unwrap() + 0x80; 32], None)
    }

    fn pad_record(i: usize) -> EncryptedShortRecord {
        let bytes: Vec<u8> = (0..218)
            .map(|j| u8::try_from((i * 13 + j * 31 + 5) & 0xFF).unwrap())
            .collect();
        let mut rec = EncryptedShortRecord::from_bytes(&bytes).unwrap();
        rec.to_peer = [0xEE; 16]; // не принадлежит ни одному хопу
        rec
    }

    /// Строит сообщение, прогоняет его через хопы и разбирает ответ.
    /// `rets[k]` — что отвечает k-й хоп.
    fn simulate(
        cfg: &mut TunnelConfig,
        order: &[usize],
        num_records: usize,
        rets: &[BuildRetCode],
    ) -> (Vec<ShortBuildResponseRecord>, Vec<HopCrypto>) {
        let n = cfg.num_hops();
        cfg.assign_record_indices(order).unwrap();
        let mut records: Vec<EncryptedShortRecord> = (0..num_records).map(pad_record).collect();
        let mut hops = Vec::new();
        for k in 0..n {
            let hop = &cfg.hops()[k];
            let req = request_for_hop(hop, 29_000_000, 1000 + u32::try_from(k).unwrap());
            let (rec, keys) =
                encrypt_short_request(&req, &hop.ident, hop_static(k).public_key(), &hop_eph(k))
                    .unwrap();
            records[hop.record_index] = rec;
            hops.push(HopCrypto {
                keys,
                record_index: hop.record_index,
            });
        }
        pre_decrypt_records(&hops, &mut records).unwrap();

        // каждый хоп по очереди обрабатывает сообщение
        let mut expected = Vec::new();
        for k in 0..n {
            let hop = &cfg.hops()[k];
            let body = ShortTunnelBuildBody::new(records.clone()).unwrap();
            let (idx, rec) = body.find_record_for(&hop.ident).expect("record for hop");
            assert_eq!(idx, hop.record_index);
            let (req, keys) = decrypt_short_request(rec, &hop_static(k)).unwrap();
            assert_eq!(
                req,
                request_for_hop(hop, 29_000_000, 1000 + u32::try_from(k).unwrap())
            );
            assert_eq!(keys, hops[k].keys);
            let mut options = BuildOptions::new();
            if rets[k].is_accept() {
                options.insert(OPTION_AVAILABLE_BANDWIDTH, "512");
            }
            let resp = ShortBuildResponseRecord {
                options,
                ret: rets[k],
            };
            encrypt_reply_records(&keys, idx, &resp, &mut records).unwrap();
            expected.push(resp);
        }
        let got = decrypt_build_reply(&hops, &mut records).unwrap();
        assert_eq!(got, expected);
        (got, hops)
    }

    #[test]
    fn end_to_end_outbound_three_hops_eight_records() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut cfg = TunnelConfig::outbound(
            &[ident(1), ident(2), ident(3)],
            0x1234,
            ident(0xDD),
            &mut rng,
        )
        .unwrap();
        let (resp, hops) = simulate(&mut cfg, &[5, 0, 7], 8, &[BuildRetCode::Accept; 3]);
        assert!(resp.iter().all(|r| r.ret.is_accept()));
        assert_eq!(
            resp[1].options.get_u32(OPTION_AVAILABLE_BANDWIDTH),
            Some(512)
        );
        // garlic-ключи есть только у endpoint (последний хоп outbound)
        assert!(hops[0].keys.garlic.is_none());
        assert!(hops[1].keys.garlic.is_none());
        assert!(hops[2].keys.garlic.is_some());
    }

    #[test]
    fn end_to_end_inbound_four_hops_shuffled() {
        let mut rng = StdRng::seed_from_u64(8);
        let mut cfg = TunnelConfig::inbound(
            &[ident(1), ident(2), ident(3), ident(4)],
            ident(0xEE),
            &mut rng,
        )
        .unwrap();
        let (resp, hops) = simulate(&mut cfg, &[7, 6, 0, 3], 8, &[BuildRetCode::Accept; 4]);
        assert_eq!(resp.len(), 4);
        // inbound: никто не endpoint
        assert!(hops.iter().all(|h| h.keys.garlic.is_none()));
    }

    #[test]
    fn end_to_end_single_hop_and_minimum_records() {
        let mut rng = StdRng::seed_from_u64(9);
        let mut cfg = TunnelConfig::outbound(&[ident(1)], 5, ident(9), &mut rng).unwrap();
        let (resp, _) = simulate(&mut cfg, &[0], 1, &[BuildRetCode::Accept]);
        assert!(resp[0].ret.is_accept());
    }

    #[test]
    fn end_to_end_in_order_indices() {
        let mut rng = StdRng::seed_from_u64(10);
        let mut cfg =
            TunnelConfig::outbound(&[ident(1), ident(2), ident(3)], 1, ident(9), &mut rng).unwrap();
        let (resp, _) = simulate(&mut cfg, &[0, 1, 2], 3, &[BuildRetCode::Accept; 3]);
        assert_eq!(resp.len(), 3);
    }

    #[test]
    fn end_to_end_middle_hop_rejects() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut cfg =
            TunnelConfig::outbound(&[ident(1), ident(2), ident(3)], 1, ident(9), &mut rng).unwrap();
        let rets = [
            BuildRetCode::Accept,
            BuildRetCode::Bandwidth,
            BuildRetCode::Accept,
        ];
        let (resp, _) = simulate(&mut cfg, &[2, 4, 1], 8, &rets);
        assert!(resp[0].ret.is_accept());
        assert_eq!(resp[1].ret, BuildRetCode::Bandwidth);
        assert!(resp[2].ret.is_accept());
    }

    #[test]
    fn tampered_reply_fails() {
        let mut rng = StdRng::seed_from_u64(12);
        let mut cfg = TunnelConfig::outbound(&[ident(1), ident(2)], 1, ident(9), &mut rng).unwrap();
        cfg.assign_record_indices(&[1, 0]).unwrap();
        let mut records: Vec<EncryptedShortRecord> = (0..2).map(pad_record).collect();
        let mut hops = Vec::new();
        for k in 0..2 {
            let hop = &cfg.hops()[k];
            let req = request_for_hop(hop, 1, 1);
            let (rec, keys) =
                encrypt_short_request(&req, &hop.ident, hop_static(k).public_key(), &hop_eph(k))
                    .unwrap();
            records[hop.record_index] = rec;
            hops.push(HopCrypto {
                keys,
                record_index: hop.record_index,
            });
        }
        pre_decrypt_records(&hops, &mut records).unwrap();
        for k in 0..2 {
            let hop = &cfg.hops()[k];
            let body = ShortTunnelBuildBody::new(records.clone()).unwrap();
            let (idx, rec) = body.find_record_for(&hop.ident).unwrap();
            let (_, keys) = decrypt_short_request(rec, &hop_static(k)).unwrap();
            encrypt_reply_records(&keys, idx, &accept(), &mut records).unwrap();
        }
        records[0].ciphertext[10] ^= 0x01;
        assert!(decrypt_build_reply(&hops, &mut records).is_err());
    }

    // ---- индексы -------------------------------------------------------------

    fn two_hops() -> Vec<HopCrypto> {
        vec![
            HopCrypto {
                keys: gw_keys(),
                record_index: 0,
            },
            HopCrypto {
                keys: gw_keys(),
                record_index: 1,
            },
        ]
    }

    #[test]
    fn index_validation() {
        let mut records: Vec<EncryptedShortRecord> = (0..4).map(pad_record).collect();
        let mut hops = two_hops();
        hops[1].record_index = 0; // дубликат
        assert!(matches!(
            pre_decrypt_records(&hops, &mut records),
            Err(I2PError::Malformed(_))
        ));
        assert!(decrypt_build_reply(&hops, &mut records).is_err());
        hops[1].record_index = 4; // вне диапазона
        assert!(pre_decrypt_records(&hops, &mut records).is_err());
        assert!(decrypt_build_reply(&hops, &mut records).is_err());
    }

    #[test]
    fn encrypt_reply_records_rejects_bad_own_index() {
        let mut records: Vec<EncryptedShortRecord> = (0..3).map(pad_record).collect();
        let r = encrypt_reply_records(&gw_keys(), 3, &accept(), &mut records);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn encrypt_reply_records_leaves_length_and_touches_all() {
        let keys = gw_keys();
        let before: Vec<EncryptedShortRecord> = (0..4).map(pad_record).collect();
        let mut after = before.clone();
        encrypt_reply_records(&keys, 2, &accept(), &mut after).unwrap();
        assert_eq!(after.len(), 4);
        for j in 0..4 {
            assert_ne!(after[j], before[j], "record {j} unchanged");
        }
        // чужие записи — обратимый слой
        for j in [0usize, 1, 3] {
            let mut r = after[j].clone();
            apply_reply_layer(&keys.reply_key, j, &mut r).unwrap();
            assert_eq!(r, before[j]);
        }
    }
}
