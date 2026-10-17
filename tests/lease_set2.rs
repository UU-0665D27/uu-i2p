#[cfg(test)]
mod tests {
    use uu_i2p::{
        CryptoKeyType, I2PTag, IdentHash, KeySection, LEASESET2_FLAG_OFFLINE_KEYS,
        LEASESET2_FLAG_PUBLISHED_ENCRYPTED, LEASESET2_FLAG_UNPUBLISHED_LEASESET, Lease, LeaseSet2,
        MAX_NUM_LEASES, NETDB_STORE_TYPE_ENCRYPTED_LEASESET2, NETDB_STORE_TYPE_META_LEASESET2,
        NETDB_STORE_TYPE_STANDARD_LEASESET2, Property, ed25519::I2PSigner, error::I2PError,
        router_info::param,
    };

    // ---- helpers --------------------------------------------------------

    /// `EdDSA + ECIES-X25519`: 391 байт, cert=[5,0,4], ext=[0,7,0,4].
    /// `signing_pub_len=32`, `sig_len=64`.
    ///
    /// Значимые байты certificate и extended явно выставляются
    /// ПОСЛЕ fill-цикла.
    fn eddsa_identity_bytes() -> Vec<u8> {
        let mut buf = vec![0xAB_u8; 391];
        buf[384] = 5;
        buf[385] = 0;
        buf[386] = 4;
        buf[387] = 0;
        buf[388] = 7;
        buf[389] = 0;
        buf[390] = 4;
        buf
    }

    fn lease(n: u8) -> Lease {
        Lease::new(
            IdentHash::from_array([n; 32]),
            u32::from(n),
            1_700_000_000_000,
        )
    }

    fn key_section_x25519() -> KeySection {
        KeySection {
            key_type: CryptoKeyType::EciesX25519Aead,
            key: vec![0xEE; 32],
        }
    }

    /// Собирает синтетический LS2 type 3 в i2pd-порядке.
    ///
    /// Восемь аргументов — потому что каждый опциональный кусок
    /// (`properties`, `key_sections`, `leases`) настраивается в тестах
    /// по отдельности. Разбивать на struct — оверинжиниринг для
    /// тестового хелпера.
    #[allow(clippy::too_many_arguments)]
    fn build_ls2(
        identity: Vec<u8>,
        published: u32,
        expires: u16,
        flags: u16,
        properties: &[Property],
        key_sections: &[KeySection],
        leases: &[Lease],
        sig_len: usize,
    ) -> Vec<u8> {
        let mut out = identity;

        out.extend_from_slice(&published.to_be_bytes());
        out.extend_from_slice(&expires.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());

        let mut props_buf = Vec::new();
        for (k, v) in properties {
            props_buf.extend_from_slice(&param(k, v));
        }
        out.extend_from_slice(&u16::try_from(props_buf.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&props_buf);

        out.push(u8::try_from(key_sections.len()).unwrap());
        for s in key_sections {
            out.extend_from_slice(&s.key_type.as_u16().to_be_bytes());
            out.extend_from_slice(&u16::try_from(s.key.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&s.key);
        }

        out.push(u8::try_from(leases.len()).unwrap());
        for l in leases {
            out.extend_from_slice(&l.to_buffer_ls2());
        }

        out.extend(std::iter::repeat_n(0xFF_u8, sig_len));
        out
    }

    /// Подписываемые байты LS2: `store_type || body`.
    ///
    /// Store type (`0x03`) лежит в I2NP `DatabaseStore`, а не в теле,
    /// но подпись покрывает и его (Java I2P, i2pd).
    fn signing_bytes(body: &[u8]) -> Vec<u8> {
        let mut out = vec![NETDB_STORE_TYPE_STANDARD_LEASESET2];
        out.extend_from_slice(body);
        out
    }

    /// Пустой базовый LS2 для тестов.
    fn basic_ls2(leases: &[Lease]) -> Vec<u8> {
        build_ls2(
            eddsa_identity_bytes(),
            1_700_000_000,
            3600,
            0,
            &[],
            &[key_section_x25519()],
            leases,
            64,
        )
    }

    // ---- parse ---------------------------------------------------------

    #[test]
    fn parse_minimal() {
        let buf = basic_ls2(&[lease(0x11)]);
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert_eq!(ls.published_timestamp(), 1_700_000_000);
        assert_eq!(ls.expires(), 3600);
        assert_eq!(ls.expiration_time_ms(), 1_700_003_600_000);
        assert_eq!(ls.flags(), 0);
        assert!(!ls.is_unpublished());
        assert!(!ls.is_published_encrypted());
        assert_eq!(ls.key_sections().len(), 1);
        assert_eq!(ls.leases().len(), 1);
        assert_eq!(ls.leases()[0].tunnel_id, 0x11);
        assert_eq!(ls.signature().len(), 64);
    }

    #[test]
    fn parse_with_two_key_sections() {
        let ks = vec![
            KeySection {
                key_type: CryptoKeyType::EciesMlKem768X25519Aead,
                key: vec![0xAA; 32],
            },
            KeySection {
                key_type: CryptoKeyType::EciesX25519Aead,
                key: vec![0xBB; 32],
            },
        ];
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            0,
            &[],
            &ks,
            &[lease(1)],
            64,
        );
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert_eq!(ls.key_sections().len(), 2);
        assert_eq!(
            ls.key_sections()[0].key_type,
            CryptoKeyType::EciesMlKem768X25519Aead
        );
        assert_eq!(
            ls.key_sections()[1].key_type,
            CryptoKeyType::EciesX25519Aead
        );
        assert_eq!(
            ls.encryption_key().unwrap().key_type,
            CryptoKeyType::EciesMlKem768X25519Aead
        );
    }

    #[test]
    fn parse_with_properties() {
        let props = vec![
            (b"i2p.streaming.maxWindowSize".to_vec(), b"512".to_vec()),
            (b"caps".to_vec(), b"OR".to_vec()),
        ];
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            0,
            &props,
            &[key_section_x25519()],
            &[lease(1)],
            64,
        );
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert_eq!(ls.properties().len(), 2);
        assert_eq!(
            ls.get_property(b"i2p.streaming.maxWindowSize"),
            Some(&b"512"[..])
        );
        assert_eq!(ls.get_property(b"caps"), Some(&b"OR"[..]));
        assert_eq!(ls.get_property(b"missing"), None);
    }

    #[test]
    fn parse_unpublished_flag() {
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            LEASESET2_FLAG_UNPUBLISHED_LEASESET,
            &[],
            &[key_section_x25519()],
            &[lease(1)],
            64,
        );
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert!(ls.is_unpublished());
        assert!(!ls.is_published_encrypted());
    }

    #[test]
    fn parse_published_encrypted_flag() {
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            LEASESET2_FLAG_PUBLISHED_ENCRYPTED,
            &[],
            &[key_section_x25519()],
            &[lease(1)],
            64,
        );
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert!(ls.is_published_encrypted());
        assert!(!ls.is_unpublished());
    }

    #[test]
    fn parse_max_leases() {
        let leases: Vec<Lease> = (1..=MAX_NUM_LEASES).map(lease).collect();
        let buf = basic_ls2(&leases);
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert_eq!(ls.leases().len(), usize::from(MAX_NUM_LEASES));
    }

    // ---- round-trip ----------------------------------------------------

    fn roundtrip(orig: &LeaseSet2) {
        let bytes = orig.to_buffer().expect("serialize");
        let back = LeaseSet2::from_buffer(&bytes).expect("parse");
        assert_eq!(&back, orig, "leaseset2 round-trip mismatch");
    }

    #[test]
    fn roundtrip_minimal() {
        let buf = basic_ls2(&[lease(0xAA)]);
        roundtrip(&LeaseSet2::from_buffer(&buf).unwrap());
    }

    #[test]
    fn roundtrip_two_key_sections() {
        let ks = vec![
            KeySection {
                key_type: CryptoKeyType::EciesMlKem768X25519Aead,
                key: vec![0xAA; 32],
            },
            KeySection {
                key_type: CryptoKeyType::EciesX25519Aead,
                key: vec![0xBB; 32],
            },
        ];
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            0,
            &[],
            &ks,
            &[lease(1)],
            64,
        );
        roundtrip(&LeaseSet2::from_buffer(&buf).unwrap());
    }

    #[test]
    fn roundtrip_with_properties() {
        let props = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
        ];
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            0,
            &props,
            &[key_section_x25519()],
            &[lease(1), lease(2)],
            64,
        );
        roundtrip(&LeaseSet2::from_buffer(&buf).unwrap());
    }

    #[test]
    fn roundtrip_max_leases() {
        let leases: Vec<Lease> = (1..=MAX_NUM_LEASES).map(lease).collect();
        let buf = basic_ls2(&leases);
        roundtrip(&LeaseSet2::from_buffer(&buf).unwrap());
    }

    #[test]
    fn roundtrip_unpublished() {
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            LEASESET2_FLAG_UNPUBLISHED_LEASESET,
            &[],
            &[key_section_x25519()],
            &[lease(1)],
            64,
        );
        roundtrip(&LeaseSet2::from_buffer(&buf).unwrap());
    }

    #[test]
    fn to_buffer_byte_perfect_for_synthetic() {
        let buf = basic_ls2(&[lease(1), lease(2)]);
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        let out = ls.to_buffer().unwrap();
        assert_eq!(out, buf, "byte-perfect failed");
    }

    // ---- errors --------------------------------------------------------

    #[test]
    fn empty_buffer_is_invalid() {
        let r = LeaseSet2::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn truncated_published_is_invalid() {
        let identity = eddsa_identity_bytes();
        let mut buf = identity;
        buf.extend_from_slice(&[0u8; 3]); // published должен быть 4
        let r = LeaseSet2::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn zero_leases_is_malformed() {
        let mut buf = eddsa_identity_bytes();
        buf.extend_from_slice(&[0u8; 4]); // published
        buf.extend_from_slice(&[0u8; 2]); // expires
        buf.extend_from_slice(&[0u8; 2]); // flags
        buf.extend_from_slice(&[0u8; 2]); // props len
        buf.push(0); // num_keys
        buf.push(0); // num_leases = 0
        let r = LeaseSet2::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn too_many_leases_is_malformed() {
        let mut buf = eddsa_identity_bytes();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.push(0);
        buf.push(MAX_NUM_LEASES + 1);
        let r = LeaseSet2::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn offline_keys_flag_is_unsupported() {
        let buf = build_ls2(
            eddsa_identity_bytes(),
            100,
            60,
            LEASESET2_FLAG_OFFLINE_KEYS,
            &[],
            &[key_section_x25519()],
            &[lease(1)],
            64,
        );
        let r = LeaseSet2::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    #[test]
    fn unknown_crypto_key_type_is_error() {
        let mut buf = eddsa_identity_bytes();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.push(1); // num_keys
        buf.extend_from_slice(&[0xFF, 0xFF]); // unknown key type
        buf.extend_from_slice(&[0, 32]); // 32-byte key
        buf.extend(std::iter::repeat_n(0u8, 32));
        let r = LeaseSet2::from_buffer(&buf);
        assert_eq!(r, Err(I2PError::UnknownCryptoKeyType(0xFFFF)));
    }

    #[test]
    fn truncated_key_is_invalid() {
        let mut buf = eddsa_identity_bytes();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.extend_from_slice(&[0u8; 2]);
        buf.push(1); // num_keys
        buf.extend_from_slice(&0x0004u16.to_be_bytes()); // ECIES-X25519
        buf.extend_from_slice(&32u16.to_be_bytes()); // объявлено 32
        buf.extend(std::iter::repeat_n(0u8, 16)); // но дано 16
        let r = LeaseSet2::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn malformed_properties_is_error() {
        // properties size = 3, но внутри нет '=' и ';'
        let mut buf = eddsa_identity_bytes();
        buf.extend_from_slice(&[0u8; 4]); // published
        buf.extend_from_slice(&[0u8; 2]); // expires
        buf.extend_from_slice(&[0u8; 2]); // flags
        buf.extend_from_slice(&3u16.to_be_bytes()); // props size
        buf.extend_from_slice(&[1, b'a', b'X']); // кривой param
        let r = LeaseSet2::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut buf = basic_ls2(&[lease(1)]);
        buf.extend_from_slice(&[0xDE, 0xAD]);
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert_eq!(ls.leases().len(), 1);
    }

    // ---- misc ----------------------------------------------------------

    #[test]
    fn netdb_store_type_constants() {
        assert_eq!(NETDB_STORE_TYPE_STANDARD_LEASESET2, 3);
        assert_eq!(NETDB_STORE_TYPE_ENCRYPTED_LEASESET2, 5);
        assert_eq!(NETDB_STORE_TYPE_META_LEASESET2, 7);
    }

    #[test]
    fn flag_constants() {
        assert_eq!(LEASESET2_FLAG_OFFLINE_KEYS, 0x0001);
        assert_eq!(LEASESET2_FLAG_UNPUBLISHED_LEASESET, 0x0002);
        assert_eq!(LEASESET2_FLAG_PUBLISHED_ENCRYPTED, 0x0004);
    }

    #[test]
    fn ident_hash_matches_identity() {
        let buf = basic_ls2(&[lease(1)]);
        let ls = LeaseSet2::from_buffer(&buf).unwrap();
        assert_eq!(ls.ident_hash(), ls.identity().ident_hash());
    }

    #[test]
    fn tag32_imported_for_tests() {
        let t = I2PTag::<32>::from_array([1u8; 32]);
        assert!(!t.is_zero());
    }
    /// Собирает identity с EdDSA+ECIES-X25519 из настоящего
    /// Ed25519-ключа. Используется для тестов верификации подписи.
    ///
    /// Раскладка: [0..256] = ECIES-X25519 public key (только первые
    /// 32 байта значащие, остальное padding), [256..384] = Ed25519
    /// public key (в самом конце — последние 32 байта), [384..387] =
    /// cert=[5,0,4], [387..391] = ext=[0,7,0,4].
    fn identity_from_ed25519(signer: &I2PSigner) -> Vec<u8> {
        let mut buf = vec![0u8; 391];

        // encryption key: первые 32 байта — рандом (не важно для
        // теста подписи), остальное нули
        for (i, b) in buf[..32].iter_mut().enumerate() {
            *b = u8::try_from((i * 7) & 0xff).expect("fits");
        }

        // signing key: Ed25519 public key в самом конце 128-байтового
        // блока, то есть в buf[384 - 32..384]
        let pub_key = signer.public_key();
        buf[384 - 32..384].copy_from_slice(&pub_key);

        // certificate
        buf[384] = 5;
        buf[385] = 0;
        buf[386] = 4;
        // extended: signing type 7, crypto type 4
        buf[387] = 0;
        buf[388] = 7;
        buf[389] = 0;
        buf[390] = 4;

        buf
    }
    #[test]
    fn lease_set2_verify_ed25519() {
        let signer = I2PSigner::generate();
        let id_bytes = identity_from_ed25519(&signer);

        // Собираем signing_data-часть LS2 (без хвостовой signature)
        let mut signing_data = id_bytes;
        signing_data.extend_from_slice(&100u32.to_be_bytes()); // published
        signing_data.extend_from_slice(&3600u16.to_be_bytes()); // expires
        signing_data.extend_from_slice(&0u16.to_be_bytes()); // flags
        signing_data.extend_from_slice(&0u16.to_be_bytes()); // props size
        signing_data.push(1); // num_keys
        signing_data.extend_from_slice(&0x0004u16.to_be_bytes()); // ECIES-X25519
        signing_data.extend_from_slice(&32u16.to_be_bytes()); // key len
        signing_data.extend(std::iter::repeat_n(0xEE_u8, 32)); // key
        signing_data.push(1); // num_leases
        signing_data.extend_from_slice(
            &Lease::new(IdentHash::from_array([0x11; 32]), 42, 1_700_000_000_000).to_buffer_ls2(),
        );

        let signature = signer.sign(&signing_bytes(&signing_data));
        let mut full_bytes = signing_data;
        full_bytes.extend_from_slice(&signature);

        let ls = LeaseSet2::from_buffer(&full_bytes).unwrap();
        ls.verify(&full_bytes).expect("signature must verify");
    }

    #[test]
    fn lease_set2_verify_fails_on_tampered_published_timestamp() {
        let signer = I2PSigner::generate();
        let id_bytes = identity_from_ed25519(&signer);

        let mut signing_data = id_bytes.clone();
        signing_data.extend_from_slice(&100u32.to_be_bytes());
        signing_data.extend_from_slice(&3600u16.to_be_bytes());
        signing_data.extend_from_slice(&0u16.to_be_bytes());
        signing_data.extend_from_slice(&0u16.to_be_bytes());
        signing_data.push(1);
        signing_data.extend_from_slice(&0x0004u16.to_be_bytes());
        signing_data.extend_from_slice(&32u16.to_be_bytes());
        signing_data.extend(std::iter::repeat_n(0xEE_u8, 32));
        signing_data.push(1);
        signing_data.extend_from_slice(
            &Lease::new(IdentHash::from_array([0x11; 32]), 42, 1_700_000_000_000).to_buffer_ls2(),
        );

        let signature = signer.sign(&signing_bytes(&signing_data));
        let mut tampered = signing_data;
        let pub_offset = id_bytes.len();
        tampered[pub_offset] ^= 0xFF; // портим первый байт published
        let mut full_bytes = tampered;
        full_bytes.extend_from_slice(&signature);

        let ls = LeaseSet2::from_buffer(&full_bytes).unwrap();
        ls.verify(&full_bytes)
            .expect_err("tampered signature must fail");
    }
    // ---- from_keys ------------------------------------------------------

    use uu_i2p::private_keys::I2PPrivateKeys;

    /// Подпись LS2 покрывает ведущий store type (`0x03`), а не только
    /// тело: иначе i2pd/Java I2P отвергнут LS2
    /// (`LeaseSet.cpp:969`, `LeaseSet2.sign`: «sigs cover the type byte»).
    #[test]
    fn signature_covers_store_type() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ls = LeaseSet2::from_keys(&keys, 100, 60, vec![lease(1)]).unwrap();
        let body = ls.to_buffer().unwrap();
        ls.verify(&body).expect("valid signature");

        // Подпись только над телом (как было бы «по LS1») не должна
        // приниматься.
        let sig_len = ls.identity().signature_len().unwrap();
        let unsigned = &body[..body.len() - sig_len];
        let wrong_sig = keys.sign(unsigned).unwrap();
        let mut wrong = unsigned.to_vec();
        wrong.extend_from_slice(&wrong_sig);
        assert!(
            ls.verify(&wrong).is_err(),
            "signature over body without store type must be rejected"
        );
    }

    #[test]
    fn from_keys_roundtrip_and_verify() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let leases = vec![
            Lease::new(IdentHash::from_array([0x11; 32]), 42, 1_700_000_000_000),
            Lease::new(IdentHash::from_array([0x22; 32]), 43, 1_700_000_100_000),
        ];

        let ls = LeaseSet2::from_keys(&keys, 1_700_000_000, 3600, leases).unwrap();

        assert_eq!(ls.identity(), keys.public());
        assert_eq!(ls.published_timestamp(), 1_700_000_000);
        assert_eq!(ls.expires(), 3600);
        assert_eq!(ls.flags(), 0);
        assert_eq!(ls.key_sections().len(), 1);
        assert_eq!(
            ls.key_sections()[0].key_type,
            uu_i2p::signature::CryptoKeyType::EciesX25519Aead
        );
        assert_eq!(ls.key_sections()[0].key.len(), 32);

        let wire = ls.to_buffer().unwrap();
        let back = LeaseSet2::from_buffer(&wire).unwrap();
        assert_eq!(back, ls);
        back.verify(&wire).expect("signature must verify");
    }

    #[test]
    fn from_keys_deterministic_signature() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let leases = vec![Lease::new(
            IdentHash::from_array([0x11; 32]),
            42,
            1_700_000_000_000,
        )];

        let a = LeaseSet2::from_keys(&keys, 100, 60, leases.clone()).unwrap();
        let b = LeaseSet2::from_keys(&keys, 100, 60, leases).unwrap();
        assert_eq!(a.to_buffer().unwrap(), b.to_buffer().unwrap());
    }

    #[test]
    fn from_keys_tamper_detected() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let leases = vec![Lease::new(
            IdentHash::from_array([0x11; 32]),
            42,
            1_700_000_000_000,
        )];
        let ls = LeaseSet2::from_keys(&keys, 100, 60, leases).unwrap();

        let mut wire = ls.to_buffer().unwrap();
        // Портим published_timestamp (первый байт после identity)
        let pub_offset = ls.identity().full_len();
        wire[pub_offset] ^= 0xFF;

        let back = LeaseSet2::from_buffer(&wire).unwrap();
        assert!(back.verify(&wire).is_err());
    }

    #[test]
    fn from_keys_max_leases() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let leases: Vec<Lease> = (1..=MAX_NUM_LEASES)
            .map(|n| {
                Lease::new(
                    IdentHash::from_array([n; 32]),
                    u32::from(n),
                    1_700_000_000_000,
                )
            })
            .collect();
        let ls = LeaseSet2::from_keys(&keys, 100, 60, leases).unwrap();
        let wire = ls.to_buffer().unwrap();
        let back = LeaseSet2::from_buffer(&wire).unwrap();
        back.verify(&wire).unwrap();
        assert_eq!(back.leases().len(), usize::from(MAX_NUM_LEASES));
    }
    // ---- LeaseSet2Builder ----------------------------------------------

    #[test]
    fn builder_minimal_auto_key_section() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let lease = lease(1);
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .add_lease(lease)
            .build(&keys)
            .unwrap();

        assert_eq!(ls.published_timestamp(), 100);
        assert_eq!(ls.expires(), 60);
        assert_eq!(ls.flags(), 0);
        assert_eq!(ls.key_sections().len(), 1);
        assert_eq!(
            ls.key_sections()[0].key_type,
            uu_i2p::signature::CryptoKeyType::EciesX25519Aead
        );
        assert_eq!(ls.leases().len(), 1);
        ls.verify(&ls.to_buffer().unwrap()).unwrap();
    }

    #[test]
    fn builder_unpublished() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .unpublished()
            .add_lease(lease(1))
            .build(&keys)
            .unwrap();
        assert!(ls.is_unpublished());
        assert!(!ls.is_published_encrypted());
        assert_eq!(
            ls.flags() & LEASESET2_FLAG_UNPUBLISHED_LEASESET,
            LEASESET2_FLAG_UNPUBLISHED_LEASESET
        );
    }

    #[test]
    fn builder_published_encrypted() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .published_encrypted()
            .add_lease(lease(1))
            .build(&keys)
            .unwrap();
        assert!(ls.is_published_encrypted());
        assert!(!ls.is_unpublished());
    }

    #[test]
    fn builder_with_properties() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .add_property(b"i2p.streaming.maxWindowSize", b"512")
            .add_property(b"caps", b"OR")
            .add_lease(lease(1))
            .build(&keys)
            .unwrap();
        assert_eq!(ls.properties().len(), 2);
        assert_eq!(
            ls.get_property(b"i2p.streaming.maxWindowSize"),
            Some(&b"512"[..])
        );
    }

    #[test]
    fn builder_set_property_replaces() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .add_property(b"x", b"old")
            .set_property(b"x", b"new")
            .add_lease(lease(1))
            .build(&keys)
            .unwrap();
        assert_eq!(ls.get_property(b"x"), Some(&b"new"[..]));
        assert_eq!(ls.properties().iter().filter(|(k, _)| k == b"x").count(), 1);
    }

    #[test]
    fn builder_multiple_key_sections() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ks = KeySection {
            key_type: uu_i2p::signature::CryptoKeyType::EciesMlKem768X25519Aead,
            key: vec![0xAA; 32],
        };
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .add_key_section(ks)
            .add_lease(lease(1))
            .build(&keys)
            .unwrap();
        // Автоматическая секция не добавилась, потому что мы задали одну
        assert_eq!(ls.key_sections().len(), 1);
        assert_eq!(
            ls.key_sections()[0].key_type,
            uu_i2p::signature::CryptoKeyType::EciesMlKem768X25519Aead
        );
    }

    #[test]
    fn builder_two_key_sections() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .add_key_section(KeySection {
                key_type: uu_i2p::signature::CryptoKeyType::EciesMlKem768X25519Aead,
                key: vec![0xAA; 32],
            })
            .add_key_section(KeySection {
                key_type: uu_i2p::signature::CryptoKeyType::EciesX25519Aead,
                key: vec![0xBB; 32],
            })
            .add_lease(lease(1))
            .build(&keys)
            .unwrap();
        assert_eq!(ls.key_sections().len(), 2);
    }

    #[test]
    fn builder_rejects_offline_keys_flag() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let r = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .flags(LEASESET2_FLAG_OFFLINE_KEYS)
            .add_lease(lease(1))
            .build(&keys);
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    #[test]
    fn builder_max_leases_roundtrip() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let leases: Vec<Lease> = (1..=MAX_NUM_LEASES).map(lease).collect();
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .leases(leases)
            .build(&keys)
            .unwrap();
        assert_eq!(ls.leases().len(), usize::from(MAX_NUM_LEASES));
        let wire = ls.to_buffer().unwrap();
        let back = LeaseSet2::from_buffer(&wire).unwrap();
        back.verify(&wire).unwrap();
    }

    #[test]
    fn builder_matches_from_keys_when_defaults() {
        // Если builder без явных flags/properties/key_sections, он
        // должен давать ровно тот же LS2, что from_keys.
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let leases = vec![lease(1), lease(2)];

        let via_builder = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .leases(leases.clone())
            .build(&keys)
            .unwrap();
        let via_from_keys = LeaseSet2::from_keys(&keys, 100, 60, leases).unwrap();

        assert_eq!(via_builder, via_from_keys);
        assert_eq!(
            via_builder.to_buffer().unwrap(),
            via_from_keys.to_buffer().unwrap()
        );
    }

    #[test]
    fn builder_tamper_detected_after_build() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ls = LeaseSet2::builder()
            .published_timestamp(100)
            .expires(60)
            .add_property(b"key", b"value")
            .add_lease(lease(1))
            .build(&keys)
            .unwrap();

        let mut wire = ls.to_buffer().unwrap();
        // Портим published_timestamp (первый байт после identity) —
        // фиксированной длины поле, парсер его прочитает без сбоев,
        // но подпись не сойдётся.
        let ts_offset = ls.identity().full_len();
        wire[ts_offset] ^= 0xFF;

        let back = LeaseSet2::from_buffer(&wire).unwrap();
        assert!(back.verify(&wire).is_err());
    }
}
