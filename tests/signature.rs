#[cfg(test)]
mod tests {
    use uu_i2p::{CryptoKeyType, I2PError, SigningKeyType};

    // ---- SigningKeyType -------------------------------------------------

    #[test]
    fn signing_all_roundtrip() {
        for t in SigningKeyType::ALL {
            let v = t.as_u16();
            let back = SigningKeyType::from_u16(v).unwrap();
            assert_eq!(back, t, "type {t:?} -> {v} -> {back:?}");
        }
    }

    #[test]
    fn signing_values_match_spec() {
        assert_eq!(SigningKeyType::DsaSha1.as_u16(), 0);
        assert_eq!(SigningKeyType::EcdsaSha256P256.as_u16(), 1);
        assert_eq!(SigningKeyType::EcdsaSha384P384.as_u16(), 2);
        assert_eq!(SigningKeyType::EcdsaSha512P521.as_u16(), 3);
        assert_eq!(SigningKeyType::RsaSha256_2048.as_u16(), 4);
        assert_eq!(SigningKeyType::RsaSha384_3072.as_u16(), 5);
        assert_eq!(SigningKeyType::RsaSha512_4096.as_u16(), 6);
        assert_eq!(SigningKeyType::EdDsaSha512Ed25519.as_u16(), 7);
        assert_eq!(SigningKeyType::EdDsaSha512Ed25519Ph.as_u16(), 8);
        assert_eq!(SigningKeyType::GostR3410CryptoProA.as_u16(), 9);
        assert_eq!(SigningKeyType::GostR3410Tc26A512.as_u16(), 10);
        assert_eq!(SigningKeyType::RedDsaSha512Ed25519.as_u16(), 11);
    }

    #[test]
    fn signing_unknown_returns_error() {
        for v in [12u16, 13, 100, 255, u16::MAX] {
            let r = SigningKeyType::from_u16(v);
            assert_eq!(
                r,
                Err(I2PError::UnknownSigningKeyType(v)),
                "unexpectedly OK for {v}"
            );
        }
    }

    #[test]
    fn signing_is_legacy_dsa() {
        assert!(SigningKeyType::DsaSha1.is_legacy_dsa());
        for t in SigningKeyType::ALL {
            if t != SigningKeyType::DsaSha1 {
                assert!(!t.is_legacy_dsa(), "{t:?} unexpectedly legacy");
            }
        }
    }

    #[test]
    fn signing_is_rsa() {
        assert!(SigningKeyType::RsaSha256_2048.is_rsa());
        assert!(SigningKeyType::RsaSha384_3072.is_rsa());
        assert!(SigningKeyType::RsaSha512_4096.is_rsa());
        assert!(!SigningKeyType::EdDsaSha512Ed25519.is_rsa());
        assert!(!SigningKeyType::DsaSha1.is_rsa());
    }

    #[test]
    fn signing_is_blindable() {
        assert!(SigningKeyType::EdDsaSha512Ed25519.is_blindable());
        assert!(SigningKeyType::RedDsaSha512Ed25519.is_blindable());
        assert!(!SigningKeyType::DsaSha1.is_blindable());
        assert!(!SigningKeyType::EcdsaSha256P256.is_blindable());
        assert!(!SigningKeyType::RsaSha256_2048.is_blindable());
    }

    #[test]
    fn signing_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in SigningKeyType::ALL {
            assert!(seen.insert(t.name()), "duplicate name: {}", t.name());
        }
    }

    #[test]
    fn signing_display_matches_name() {
        for t in SigningKeyType::ALL {
            assert_eq!(format!("{t}"), t.name());
        }
    }

    // ---- CryptoKeyType --------------------------------------------------

    #[test]
    fn crypto_all_roundtrip() {
        for t in CryptoKeyType::ALL {
            let v = t.as_u16();
            let back = CryptoKeyType::from_u16(v).unwrap();
            assert_eq!(back, t, "type {t:?} -> {v} -> {back:?}");
        }
    }

    #[test]
    fn crypto_values_match_spec() {
        assert_eq!(CryptoKeyType::ElGamal.as_u16(), 0);
        assert_eq!(CryptoKeyType::EciesP256Sha256Aes256Cbc.as_u16(), 1);
        assert_eq!(CryptoKeyType::EciesX25519Aead.as_u16(), 4);
        assert_eq!(CryptoKeyType::EciesMlKem512X25519Aead.as_u16(), 5);
        assert_eq!(CryptoKeyType::EciesMlKem768X25519Aead.as_u16(), 6);
        assert_eq!(CryptoKeyType::EciesMlKem1024X25519Aead.as_u16(), 7);
    }

    #[test]
    fn crypto_unknown_returns_error() {
        // 2 и 3 не используются, 8.. тоже
        for v in [2u16, 3, 8, 9, 100, u16::MAX] {
            let r = CryptoKeyType::from_u16(v);
            assert_eq!(
                r,
                Err(I2PError::UnknownCryptoKeyType(v)),
                "unexpectedly OK for {v}"
            );
        }
    }

    #[test]
    fn crypto_supports_ratchets() {
        assert!(!CryptoKeyType::ElGamal.supports_ratchets());
        assert!(!CryptoKeyType::EciesP256Sha256Aes256Cbc.supports_ratchets());
        assert!(CryptoKeyType::EciesX25519Aead.supports_ratchets());
        assert!(CryptoKeyType::EciesMlKem512X25519Aead.supports_ratchets());
        assert!(CryptoKeyType::EciesMlKem768X25519Aead.supports_ratchets());
        assert!(CryptoKeyType::EciesMlKem1024X25519Aead.supports_ratchets());
    }

    #[test]
    fn crypto_is_post_quantum() {
        assert!(!CryptoKeyType::ElGamal.is_post_quantum());
        assert!(!CryptoKeyType::EciesX25519Aead.is_post_quantum());
        assert!(CryptoKeyType::EciesMlKem512X25519Aead.is_post_quantum());
        assert!(CryptoKeyType::EciesMlKem768X25519Aead.is_post_quantum());
        assert!(CryptoKeyType::EciesMlKem1024X25519Aead.is_post_quantum());
    }

    #[test]
    fn crypto_ml_kem_level() {
        assert_eq!(CryptoKeyType::ElGamal.ml_kem_level(), None);
        assert_eq!(CryptoKeyType::EciesX25519Aead.ml_kem_level(), None);
        assert_eq!(
            CryptoKeyType::EciesMlKem512X25519Aead.ml_kem_level(),
            Some(512)
        );
        assert_eq!(
            CryptoKeyType::EciesMlKem768X25519Aead.ml_kem_level(),
            Some(768)
        );
        assert_eq!(
            CryptoKeyType::EciesMlKem1024X25519Aead.ml_kem_level(),
            Some(1024)
        );
    }

    #[test]
    fn crypto_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in CryptoKeyType::ALL {
            assert!(seen.insert(t.name()), "duplicate name: {}", t.name());
        }
    }

    #[test]
    fn crypto_display_matches_name() {
        for t in CryptoKeyType::ALL {
            assert_eq!(format!("{t}"), t.name());
        }
    }
}
