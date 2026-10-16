#[cfg(test)]
mod tests {
    use uu_i2p::{
        ENCRYPTION_KEY_SIZE, I2PTag, IdentHash, LEASE_SIZE, Lease, LeaseSet, MAX_NUM_LEASES,
        NETDB_STORE_TYPE_LEASESET, ed25519::I2PSigner, error::I2PError,
    };

    // ---- helpers --------------------------------------------------------

    /// DSA-SHA1 identity: 387 байт, cert=[0,0,0].
    /// `signing_pub_len=128`, `sig_len=40`.
    ///
    /// `certificate[384..387]` остаётся `[0, 0, 0]` — иначе
    /// `IdentityEx::from_buffer` решит, что это extended-формат
    /// (`cert_type` = KEY) и полезет читать несуществующий extension.
    fn dsa_identity_bytes() -> Vec<u8> {
        let mut buf = vec![0xCD_u8; 387];
        buf[384] = 0;
        buf[385] = 0;
        buf[386] = 0;
        buf
    }

    /// `EdDSA` + ECIES-X25519: 391 байт, cert=[5,0,4], ext=[0,7,0,4].
    /// `signing_pub_len=32`, `sig_len=64`.
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

    /// Собирает полный `LeaseSet` type 1.
    fn build_leaseset(identity: Vec<u8>, leases: &[Lease], sig_len: usize) -> Vec<u8> {
        let mut out = identity;
        out.extend(std::iter::repeat_n(0xEE_u8, ENCRYPTION_KEY_SIZE));
        // signing_key: для DSA — 128, для EdDSA — 32. Определим по cert.
        let sig_pub_len = if out[384] == 0 { 128 } else { 32 };
        out.extend(std::iter::repeat_n(0u8, sig_pub_len));
        out.push(u8::try_from(leases.len()).expect("test leases count fits u8"));
        for l in leases {
            out.extend_from_slice(&l.to_buffer_ls1());
        }
        out.extend(std::iter::repeat_n(0xFF_u8, sig_len));
        out
    }

    // ---- parse / fields -------------------------------------------------

    #[test]
    fn parse_eddsa_one_lease() {
        let buf = build_leaseset(eddsa_identity_bytes(), &[lease(0x11)], 64);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        assert_eq!(ls.leases().len(), 1);
        assert_eq!(ls.leases()[0].tunnel_id, 0x11);
        assert_eq!(ls.signature().len(), 64);
        assert!(ls.signature().iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn parse_eddsa_four_leases() {
        let leases = [lease(1), lease(2), lease(3), lease(4)];
        let buf = build_leaseset(eddsa_identity_bytes(), &leases, 64);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        assert_eq!(ls.leases().len(), 4);
        for (i, l) in ls.leases().iter().enumerate() {
            assert_eq!(l.tunnel_id, u32::try_from(i + 1).unwrap());
        }
    }

    #[test]
    fn parse_dsa_one_lease() {
        let buf = build_leaseset(dsa_identity_bytes(), &[lease(0x22)], 40);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        assert_eq!(ls.leases().len(), 1);
        assert_eq!(ls.signature().len(), 40);
        // DSA → ElGamal → 256 байт encryption key
        assert_eq!(ls.encryption_key().unwrap().len(), 256);
    }

    #[test]
    fn parse_eddsa_encryption_key_is_32_bytes() {
        let buf = build_leaseset(eddsa_identity_bytes(), &[lease(1)], 64);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        assert_eq!(ls.encryption_key().unwrap().len(), 32);
        assert_eq!(ls.encryption_key_full().len(), 256);
    }

    #[test]
    fn ident_hash_matches_identity() {
        let buf = build_leaseset(eddsa_identity_bytes(), &[lease(1)], 64);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        assert_eq!(ls.ident_hash(), ls.identity().ident_hash());
    }

    // ---- round-trip -----------------------------------------------------

    fn roundtrip(orig: &LeaseSet) {
        let bytes = orig.to_buffer().expect("serialize");
        let back = LeaseSet::from_buffer(&bytes).expect("parse");
        assert_eq!(&back, orig, "leaseset round-trip mismatch");
    }

    #[test]
    fn roundtrip_eddsa_one_lease() {
        let buf = build_leaseset(eddsa_identity_bytes(), &[lease(0xAA)], 64);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        roundtrip(&ls);
    }

    #[test]
    fn roundtrip_eddsa_max_leases() {
        let leases: Vec<Lease> = (1..=MAX_NUM_LEASES).map(lease).collect();
        let buf = build_leaseset(eddsa_identity_bytes(), &leases, 64);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        assert_eq!(ls.leases().len(), usize::from(MAX_NUM_LEASES));
        roundtrip(&ls);
    }

    #[test]
    fn roundtrip_dsa() {
        let buf = build_leaseset(dsa_identity_bytes(), &[lease(0x33), lease(0x44)], 40);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        roundtrip(&ls);
    }

    #[test]
    fn to_buffer_byte_perfect_for_synthetic() {
        let buf = build_leaseset(eddsa_identity_bytes(), &[lease(1), lease(2)], 64);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        let out = ls.to_buffer().unwrap();
        assert_eq!(out, buf, "byte-perfect failed");
    }

    // ---- errors ---------------------------------------------------------

    #[test]
    fn empty_buffer_is_invalid() {
        let r = LeaseSet::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn truncated_after_identity_is_invalid() {
        let identity = eddsa_identity_bytes();
        let r = LeaseSet::from_buffer(&identity);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn truncated_encryption_key_is_invalid() {
        let mut buf = eddsa_identity_bytes();
        buf.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE - 1));
        let r = LeaseSet::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn zero_leases_is_malformed() {
        let mut buf = eddsa_identity_bytes();
        buf.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE + 32));
        buf.push(0); // num_leases = 0
        let r = LeaseSet::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn too_many_leases_is_malformed() {
        let mut buf = eddsa_identity_bytes();
        buf.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE + 32));
        buf.push(MAX_NUM_LEASES + 1); // 17
        let r = LeaseSet::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn truncated_leases_is_invalid() {
        let mut buf = eddsa_identity_bytes();
        buf.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE + 32));
        buf.push(2); // объявлено 2 lease
        // но даём только 1
        buf.extend(std::iter::repeat_n(0u8, LEASE_SIZE));
        let r = LeaseSet::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn truncated_signature_is_invalid() {
        let mut buf = eddsa_identity_bytes();
        buf.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE + 32));
        buf.push(1);
        buf.extend(std::iter::repeat_n(0u8, LEASE_SIZE));
        // нет signature — должно быть 64 байта
        let r = LeaseSet::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut buf = build_leaseset(eddsa_identity_bytes(), &[lease(1)], 64);
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let ls = LeaseSet::from_buffer(&buf).unwrap();
        assert_eq!(ls.leases().len(), 1);
    }

    // ---- header / encryption key fields --------------------------------

    #[test]
    fn encryption_key_preserved_as_is() {
        let mut buf = eddsa_identity_bytes();
        for i in 0..ENCRYPTION_KEY_SIZE {
            buf.push(u8::try_from(i & 0xff).expect("fits"));
        }
        buf.extend(std::iter::repeat_n(0u8, 32));
        buf.push(1);
        buf.extend(std::iter::repeat_n(0u8, LEASE_SIZE));
        buf.extend(std::iter::repeat_n(0u8, 64));

        let ls = LeaseSet::from_buffer(&buf).unwrap();
        let ek = ls.encryption_key_full();
        for (i, &b) in ek.iter().enumerate() {
            assert_eq!(b, u8::try_from(i & 0xff).unwrap());
        }
    }

    #[test]
    fn signing_key_field_is_zeros_in_serialized() {
        // даже если вход имел что-то другое в signing_key,
        // writer пишет нули
        let mut buf = eddsa_identity_bytes();
        buf.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE));
        buf.extend(std::iter::repeat_n(0xFF_u8, 32)); // нестандартный signing_key
        buf.push(1);
        buf.extend_from_slice(&Lease::new(IdentHash::from_array([1; 32]), 1, 0).to_buffer_ls1());
        buf.extend(std::iter::repeat_n(0u8, 64));

        let ls = LeaseSet::from_buffer(&buf).unwrap();
        let out = ls.to_buffer().unwrap();
        // out и buf отличаются только в signing_key: buf — 0xFF, out — 0
        let sk_offset = eddsa_identity_bytes().len() + ENCRYPTION_KEY_SIZE;
        assert!(buf[sk_offset..sk_offset + 32].iter().all(|&b| b == 0xFF));
        assert!(out[sk_offset..sk_offset + 32].iter().all(|&b| b == 0));
    }

    #[test]
    fn store_type_constant() {
        assert_eq!(NETDB_STORE_TYPE_LEASESET, 1);
    }

    #[test]
    fn tag_type_accessible_in_tests() {
        // просто проверяем что Tag<32> импортируется в тестах и работает
        let t = I2PTag::<32>::from_array([0u8; 32]);
        assert!(t.is_zero());
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
    fn lease_set_verify_ed25519() {
        let signer = uu_i2p::ed25519::I2PSigner::generate();
        let id_bytes = identity_from_ed25519(&signer);

        // Собираем signing_data-часть: identity + ek + signing_key(нули) + num + leases
        let mut signing_data = id_bytes;
        signing_data.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE));
        signing_data.extend(std::iter::repeat_n(0u8, 32)); // signing_key (redundant)
        signing_data.push(1); // num_leases
        signing_data.extend_from_slice(
            &Lease::new(IdentHash::from_array([0x11; 32]), 42, 1_700_000_000_000).to_buffer_ls1(),
        );

        let signature = signer.sign(&signing_data);
        let mut full_bytes = signing_data;
        full_bytes.extend_from_slice(&signature);

        let ls = LeaseSet::from_buffer(&full_bytes).unwrap();
        ls.verify(&full_bytes).expect("signature must verify");
    }

    #[test]
    fn lease_set_verify_fails_on_tampered_leases() {
        let signer = uu_i2p::ed25519::I2PSigner::generate();
        let id_bytes = identity_from_ed25519(&signer);

        let mut signing_data = id_bytes.clone();
        signing_data.extend(std::iter::repeat_n(0u8, ENCRYPTION_KEY_SIZE));
        signing_data.extend(std::iter::repeat_n(0u8, 32));
        signing_data.push(1);
        signing_data.extend_from_slice(
            &Lease::new(IdentHash::from_array([0x11; 32]), 42, 1_700_000_000_000).to_buffer_ls1(),
        );

        let signature = signer.sign(&signing_data);
        // Портим tunnel_id в lease (offset: identity.len + 256 + 32 + 1 + 32)
        let mut tampered = signing_data;
        let lease_id_offset = id_bytes.len() + ENCRYPTION_KEY_SIZE + 32 + 1 + 32;
        tampered[lease_id_offset] ^= 0xFF;
        let mut full_bytes = tampered;
        full_bytes.extend_from_slice(&signature);

        let ls = LeaseSet::from_buffer(&full_bytes).unwrap();
        ls.verify(&full_bytes)
            .expect_err("tampered signature must fail");
    }
    // ---- from_keys ------------------------------------------------------

    use uu_i2p::private_keys::I2PPrivateKeys;

    #[test]
    fn from_keys_roundtrip_and_verify() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let leases = vec![
            Lease::new(IdentHash::from_array([0x11; 32]), 42, 1_700_000_000_000),
            Lease::new(IdentHash::from_array([0x22; 32]), 43, 1_700_000_100_000),
        ];

        let ls = LeaseSet::from_keys(&keys, leases).unwrap();

        // identity совпадает с keys
        assert_eq!(ls.identity(), keys.public());
        // encryption key = 32 байта X25519 + 224 нуля
        assert_eq!(
            ls.encryption_key_full()[..32],
            keys.public().encryption_public_key().unwrap()[..]
        );
        assert!(ls.encryption_key_full()[32..].iter().all(|&b| b == 0));

        // Round-trip через wire
        let wire = ls.to_buffer().unwrap();
        let back = LeaseSet::from_buffer(&wire).unwrap();
        assert_eq!(back, ls);

        // Верификация
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

        let a = LeaseSet::from_keys(&keys, leases.clone()).unwrap();
        let b = LeaseSet::from_keys(&keys, leases).unwrap();
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
        let ls = LeaseSet::from_keys(&keys, leases).unwrap();

        let mut wire = ls.to_buffer().unwrap();
        // Портим tunnel_id у lease
        let lease_id_offset = ls.identity().full_len() + ENCRYPTION_KEY_SIZE + 32 + 1 + 32;
        wire[lease_id_offset] ^= 0xFF;

        let back = LeaseSet::from_buffer(&wire).unwrap();
        assert!(back.verify(&wire).is_err());
    }

    #[test]
    fn from_keys_max_leases_roundtrip() {
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
        let ls = LeaseSet::from_keys(&keys, leases).unwrap();
        let wire = ls.to_buffer().unwrap();
        let back = LeaseSet::from_buffer(&wire).unwrap();
        back.verify(&wire).unwrap();
        assert_eq!(back.leases().len(), usize::from(MAX_NUM_LEASES));
    }
}
