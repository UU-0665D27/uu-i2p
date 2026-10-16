#[cfg(test)]
mod tests {
    use uu_i2p::{
        CryptoKeyType, I2PError, I2PHash, IdentHash, SigningKeyType,
        identity::{
            CERTIFICATE_TYPE_NULL, DEFAULT_IDENTITY_SIZE, Identity, IdentityEx,
            MAX_EXTENDED_BUFFER_SIZE,
        },
    };

    // ---- helpers --------------------------------------------------------

    /// Identity с DSA-SHA1: certificate = [0, 0, 0].
    fn dsa_bytes() -> [u8; 387] {
        let mut buf = [0u8; 387];
        for (i, b) in buf.iter_mut().enumerate().take(256) {
            *b = u8::try_from(i & 0xff).expect("i & 0xff fits u8");
        }
        for b in &mut buf[256..384] {
            *b = 0xAA;
        }
        buf
    }

    /// `EdDSA` + ECIES-X25519: extension = [0, 7, 0, 4].
    fn eddsa_ecies_bytes() -> [u8; 391] {
        let mut buf = [0u8; 391];
        for b in &mut buf[0..256] {
            *b = 0xFF;
        }
        for b in &mut buf[256..384] {
            *b = 0xBB;
        }
        buf[384] = 5;
        buf[385] = 0;
        buf[386] = 4;
        buf[387] = 0;
        buf[388] = 7;
        buf[389] = 0;
        buf[390] = 4;
        buf
    }

    /// ECDSA-P521 + ECIES-X25519: extension = [0, 3, 0, 4, DE, AD, BE, EF].
    fn ecdsa_p521_bytes() -> [u8; 395] {
        let mut buf = [0u8; 395];
        for b in &mut buf[0..384] {
            *b = 0xCC;
        }
        buf[384] = 5;
        buf[385] = 0;
        buf[386] = 8;
        buf[387] = 0;
        buf[388] = 3;
        buf[389] = 0;
        buf[390] = 4;
        buf[391] = 0xDE;
        buf[392] = 0xAD;
        buf[393] = 0xBE;
        buf[394] = 0xEF;
        buf
    }

    // ---- Identity -------------------------------------------------------

    #[test]
    fn identity_size_const() {
        assert_eq!(Identity::SIZE, 387);
        assert_eq!(DEFAULT_IDENTITY_SIZE, 387);
        assert_eq!(MAX_EXTENDED_BUFFER_SIZE, 8);
    }

    #[test]
    fn dsa_roundtrip() {
        let buf = dsa_bytes();
        let id = Identity::from_buffer(&buf).unwrap();
        assert!(id.is_legacy_dsa());
        assert_eq!(id.certificate_type(), CERTIFICATE_TYPE_NULL);
        assert_eq!(id.extended_len(), 0);
        assert_eq!(id.to_array(), buf);
    }

    #[test]
    fn identity_from_buffer_too_short() {
        let r = Identity::from_buffer(&[0u8; 386]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 387,
                got: 386
            })
        );
    }

    #[test]
    fn identity_hash_is_sha256_of_387() {
        let buf = dsa_bytes();
        let id = Identity::from_buffer(&buf).unwrap();
        let expected: IdentHash = I2PHash::of(&buf).into();
        assert_eq!(id.hash(), expected);
    }

    #[test]
    fn identity_debug_includes_hash() {
        let buf = dsa_bytes();
        let id = Identity::from_buffer(&buf).unwrap();
        let s = format!("{id:?}");
        assert!(s.contains(&id.hash().to_base64()));
    }

    // ---- IdentityEx: DSA -------------------------------------------------

    #[test]
    fn dsa_identity_ex_is_equivalent() {
        let buf = dsa_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        assert!(id.is_legacy_dsa());
        assert_eq!(id.full_len(), 387);
        assert_eq!(id.signing_key_type().unwrap(), SigningKeyType::DsaSha1);
        assert_eq!(id.crypto_key_type().unwrap(), CryptoKeyType::ElGamal);
        assert_eq!(id.signing_public_key_len().unwrap(), 128);
        assert_eq!(id.signature_len().unwrap(), 40);
        assert_eq!(*id.ident_hash(), id.standard().hash());
    }

    #[test]
    fn dsa_signing_public_key_is_full_128() {
        let buf = dsa_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        let key = id.signing_public_key().unwrap();
        assert_eq!(key.len(), 128);
        assert_eq!(key, &[0xAAu8; 128][..]);
        assert_eq!(id.signing_public_key_buf().unwrap(), &[0xAAu8; 128][..]);
    }

    // ---- IdentityEx: EdDSA + ECIES-X25519 -------------------------------

    #[test]
    fn eddsa_ecies_roundtrip() {
        let buf = eddsa_ecies_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        assert!(!id.is_legacy_dsa());
        assert_eq!(id.full_len(), 391);
        assert_eq!(
            id.signing_key_type().unwrap(),
            SigningKeyType::EdDsaSha512Ed25519
        );
        assert_eq!(
            id.crypto_key_type().unwrap(),
            CryptoKeyType::EciesX25519Aead
        );
    }

    #[test]
    fn eddsa_signing_public_key_is_last_32() {
        let buf = eddsa_ecies_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        assert_eq!(id.signing_public_key_len().unwrap(), 32);
        let key = id.signing_public_key().unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key, &[0xBBu8; 32][..]);
    }

    #[test]
    fn eddsa_encryption_public_key_is_first_32() {
        let buf = eddsa_ecies_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        let key = id.encryption_public_key().unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key, &[0xFFu8; 32][..]);
        assert_eq!(id.encryption_public_key_full().len(), 256);
    }

    #[test]
    fn eddsa_hash_differs_from_dsa_hash() {
        let dsa = IdentityEx::from_buffer(&dsa_bytes()).unwrap();
        let eddsa = IdentityEx::from_buffer(&eddsa_ecies_bytes()).unwrap();
        assert_ne!(dsa.ident_hash(), eddsa.ident_hash());
    }

    #[test]
    fn identity_ex_to_buffer_roundtrip() {
        let buf = eddsa_ecies_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        let mut out = [0u8; 391];
        assert_eq!(id.to_buffer(&mut out).unwrap(), 391);
        assert_eq!(out, buf);
        let back = IdentityEx::from_buffer(&out).unwrap();
        assert_eq!(back, id);
    }

    // ---- IdentityEx: P521 (excess в extended) ---------------------------

    #[test]
    fn p521_full_len_is_395() {
        let buf = ecdsa_p521_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        assert_eq!(id.full_len(), 395);
        assert_eq!(
            id.signing_key_type().unwrap(),
            SigningKeyType::EcdsaSha512P521
        );
    }

    #[test]
    fn p521_signing_public_key_concatenates() {
        let buf = ecdsa_p521_bytes();
        let id = IdentityEx::from_buffer(&buf).unwrap();
        assert_eq!(id.signing_public_key_len().unwrap(), 132);
        let key = id.signing_public_key().unwrap();
        assert_eq!(key.len(), 132);
        assert_eq!(&key[..128], &[0xCCu8; 128][..]);
        assert_eq!(&key[128..], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(id.signing_public_key_buf().is_none());
    }

    // ---- ошибки ---------------------------------------------------------

    #[test]
    fn non_key_certificate_with_nonzero_len_is_error() {
        let mut buf = dsa_bytes();
        buf[384] = 3;
        buf[385] = 0;
        buf[386] = 4;
        let r = IdentityEx::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn key_certificate_with_len_too_short_is_error() {
        let mut buf = dsa_bytes();
        buf[384] = 5;
        buf[385] = 0;
        buf[386] = 2;
        let mut full = buf.to_vec();
        full.extend_from_slice(&[0u8, 7]);
        let r = IdentityEx::from_buffer(&full);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn key_certificate_buffer_too_short_is_error() {
        let mut buf = dsa_bytes();
        buf[384] = 5;
        buf[385] = 0;
        buf[386] = 4;
        let r = IdentityEx::from_buffer(&buf);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 391,
                got: 387
            })
        );
    }

    #[test]
    fn unknown_signing_key_type_is_error() {
        let mut buf = eddsa_ecies_bytes();
        buf[387] = 0xff;
        buf[388] = 0xff;
        let id = IdentityEx::from_buffer(&buf).unwrap();
        let r = id.signing_key_type();
        assert_eq!(r, Err(I2PError::UnknownSigningKeyType(0xFFFF)));
    }

    #[test]
    fn unknown_crypto_key_type_is_error() {
        let mut buf = eddsa_ecies_bytes();
        buf[389] = 0xff;
        buf[390] = 0xff;
        let id = IdentityEx::from_buffer(&buf).unwrap();
        assert_eq!(
            id.signing_key_type().unwrap(),
            SigningKeyType::EdDsaSha512Ed25519
        );
        let r = id.crypto_key_type();
        assert_eq!(r, Err(I2PError::UnknownCryptoKeyType(0xFFFF)));
    }

    // ---- Buffer contracts ----------------------------------------------

    #[test]
    fn identity_to_buffer_too_short_is_error() {
        let id = Identity::from_buffer(&dsa_bytes()).unwrap();
        let mut small = [0u8; 100];
        let r = id.to_buffer(&mut small);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 387,
                got: 100
            })
        );
    }

    #[test]
    fn identity_ex_to_buffer_too_short_is_error() {
        let id = IdentityEx::from_buffer(&eddsa_ecies_bytes()).unwrap();
        let mut small = [0u8; 100];
        let r = id.to_buffer(&mut small);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 391,
                got: 100
            })
        );
    }
    #[test]
    fn new_from_raw_keys_roundtrips() {
        let public_key = [0x11u8; 32];
        let signing_key = [0x22u8; 32];
        let id = IdentityEx::new(
            &public_key,
            &signing_key,
            SigningKeyType::EdDsaSha512Ed25519,
            CryptoKeyType::EciesX25519Aead,
        )
        .unwrap();

        assert_eq!(id.full_len(), 391);
        assert_eq!(
            id.signing_key_type().unwrap(),
            SigningKeyType::EdDsaSha512Ed25519
        );
        assert_eq!(
            id.crypto_key_type().unwrap(),
            CryptoKeyType::EciesX25519Aead
        );

        // Public key сохранён как ожидается
        assert_eq!(id.encryption_public_key().unwrap(), &public_key[..]);
        assert_eq!(id.signing_public_key().unwrap(), &signing_key[..]);
    }

    #[test]
    fn new_then_to_buffer_then_from_buffer() {
        let public_key = [0xAAu8; 32];
        let signing_key = [0xBBu8; 32];
        let id = IdentityEx::new(
            &public_key,
            &signing_key,
            SigningKeyType::EdDsaSha512Ed25519,
            CryptoKeyType::EciesX25519Aead,
        )
        .unwrap();

        let mut buf = vec![0u8; id.full_len()];
        id.to_buffer(&mut buf).unwrap();
        let back = IdentityEx::from_buffer(&buf).unwrap();
        assert_eq!(back, id);
        assert_eq!(back.ident_hash(), id.ident_hash());
    }

    #[test]
    fn new_rejects_dsa() {
        let r = IdentityEx::new(
            &[0u8; 32],
            &[0u8; 128],
            SigningKeyType::DsaSha1,
            CryptoKeyType::EciesX25519Aead,
        );
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    #[test]
    fn new_rejects_p521() {
        let r = IdentityEx::new(
            &[0u8; 32],
            &[0u8; 132],
            SigningKeyType::EcdsaSha512P521,
            CryptoKeyType::EciesX25519Aead,
        );
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    #[test]
    fn new_rejects_short_keys() {
        let r = IdentityEx::new(
            &[0u8; 16],
            &[0u8; 32],
            SigningKeyType::EdDsaSha512Ed25519,
            CryptoKeyType::EciesX25519Aead,
        );
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }
}
