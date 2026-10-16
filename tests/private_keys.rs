#[cfg(test)]
mod tests {
    use uu_i2p::{CryptoKeyType, I2PError, I2PPrivateKeys, SigningKeyType};

    // ---- generate ------------------------------------------------------

    #[test]
    fn generate_default_works() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        assert_eq!(
            keys.public().signing_key_type().unwrap(),
            SigningKeyType::EdDsaSha512Ed25519
        );
        assert_eq!(
            keys.public().crypto_key_type().unwrap(),
            CryptoKeyType::EciesX25519Aead
        );
        assert_eq!(keys.crypto_private().len(), 32);
        assert_eq!(keys.signing_private().len(), 32);
        assert_eq!(keys.signature_len().unwrap(), 64);
    }

    #[test]
    fn generate_rejects_dsa() {
        let r = I2PPrivateKeys::generate(SigningKeyType::DsaSha1, CryptoKeyType::EciesX25519Aead);
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    #[test]
    fn generate_rejects_elgamal() {
        let r =
            I2PPrivateKeys::generate(SigningKeyType::EdDsaSha512Ed25519, CryptoKeyType::ElGamal);
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    // ---- sign ----------------------------------------------------------

    #[test]
    fn sign_then_verify() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let msg = b"hello, private keys";
        let sig = keys.sign(msg).unwrap();
        assert_eq!(sig.len(), 64);

        // Проверяем через identity — как будто получили сообщение
        keys.public().verify(msg, &sig).unwrap();
    }

    #[test]
    fn sign_tampered_message_fails_verification() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let sig = keys.sign(b"original").unwrap();
        assert!(keys.public().verify(b"tampered", &sig).is_err());
    }

    // ---- serialization -------------------------------------------------

    #[test]
    fn buffer_roundtrip() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let buf = keys.to_buffer().unwrap();
        // identity (391) + crypto_priv (32) + signing_priv (32) = 455
        assert_eq!(buf.len(), 391 + 32 + 32);

        let back = I2PPrivateKeys::from_buffer(&buf).unwrap();
        assert_eq!(back.public(), keys.public());
        assert_eq!(back.crypto_private(), keys.crypto_private());
        assert_eq!(back.signing_private(), keys.signing_private());
    }

    #[test]
    fn buffer_roundtrip_preserves_sign() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let buf = keys.to_buffer().unwrap();
        let back = I2PPrivateKeys::from_buffer(&buf).unwrap();

        let msg = b"same message, same signature";
        let sig1 = keys.sign(msg).unwrap();
        let sig2 = back.sign(msg).unwrap();
        // Ed25519 deterministic — подписи должны совпасть 1:1
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn from_buffer_too_short() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let buf = keys.to_buffer().unwrap();
        let r = I2PPrivateKeys::from_buffer(&buf[..buf.len() - 1]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn from_buffer_unsupported_types() {
        // Синтетический identity DSA + ElGamal (cert=[0,0,0])
        let buf = vec![0u8; 387 + 32 + 32];
        let r = I2PPrivateKeys::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    // ---- multi-key uniqueness ------------------------------------------

    #[test]
    fn generate_produces_unique_identities() {
        let k1 = I2PPrivateKeys::generate_default().unwrap();
        let k2 = I2PPrivateKeys::generate_default().unwrap();
        assert_ne!(k1.public().ident_hash(), k2.public().ident_hash());
    }

    // ---- integration: signed data + verify через identity -------------------

    #[test]
    fn full_signed_data_roundtrip() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let data = b"some important payload that we sign";

        // Подписываем
        let signature = keys.sign(data).unwrap();

        // Сериализуем ключи, загружаем обратно, верифицируем
        let serialized = keys.to_buffer().unwrap();
        let loaded = I2PPrivateKeys::from_buffer(&serialized).unwrap();
        loaded.public().verify(data, &signature).unwrap();
    }
}
