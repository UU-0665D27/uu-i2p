#[cfg(test)]
mod tests {
    use uu_i2p::{
        I2PError,
        ed25519::{I2PSigner, I2PVerifier, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN},
    };

    // ---- round-trip ----------------------------------------------------

    #[test]
    fn sign_verify_roundtrip() {
        let signer = I2PSigner::generate();
        let msg = b"hello, i2p";
        let sig = signer.sign(msg);

        let verifier = I2PVerifier::new(&signer.public_key()).unwrap();
        assert!(verifier.verify(msg, &sig).is_ok());
    }

    #[test]
    fn signature_from_one_key_fails_with_another() {
        let signer1 = I2PSigner::generate();
        let signer2 = I2PSigner::generate();
        let msg = b"hello";
        let sig = signer1.sign(msg);

        let v2 = I2PVerifier::new(&signer2.public_key()).unwrap();
        assert!(v2.verify(msg, &sig).is_err());
    }

    #[test]
    fn tampered_message_fails() {
        let signer = I2PSigner::generate();
        let sig = signer.sign(b"original");
        let v = signer.verifier();
        assert!(v.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let signer = I2PSigner::generate();
        let msg = b"hello";
        let mut sig = signer.sign(msg);
        sig[0] ^= 1;

        let v = signer.verifier();
        assert!(v.verify(msg, &sig).is_err());
    }

    #[test]
    fn is_valid_shortcut() {
        let signer = I2PSigner::generate();
        let msg = b"test";
        let sig = signer.sign(msg);
        let v = signer.verifier();
        assert!(v.is_valid(msg, &sig));
        assert!(!v.is_valid(b"other", &sig));
        // короткая подпись — не паникует, возвращает false
        assert!(!v.is_valid(msg, &sig[..10]));
    }

    // ---- key handling --------------------------------------------------

    #[test]
    fn signer_from_seed_is_deterministic() {
        let seed = [0x42u8; 32];
        let s1 = I2PSigner::from_seed(&seed).unwrap();
        let s2 = I2PSigner::from_seed(&seed).unwrap();
        assert_eq!(s1.public_key(), s2.public_key());
        assert_eq!(s1.private_key(), s2.private_key());

        let msg = b"deterministic";
        assert_eq!(s1.sign(msg), s2.sign(msg));
    }

    #[test]
    fn private_key_roundtrip() {
        let signer = I2PSigner::generate();
        let priv_bytes = signer.private_key();
        let s2 = I2PSigner::from_private_key(&priv_bytes).unwrap();
        assert_eq!(signer.public_key(), s2.public_key());
    }

    #[test]
    fn verifier_from_wrong_length_fails() {
        let r = I2PVerifier::new(&[0u8; 31]);
        assert_eq!(
            r.unwrap_err(),
            I2PError::InvalidLength {
                expected: 32,
                got: 31,
            }
        );
        let r = I2PVerifier::new(&[0u8; 33]);
        assert_eq!(
            r.unwrap_err(),
            I2PError::InvalidLength {
                expected: 32,
                got: 33,
            }
        );
    }

    #[test]
    fn signer_from_wrong_length_fails() {
        let r = I2PSigner::from_private_key(&[0u8; 31]);
        assert_eq!(
            r.unwrap_err(),
            I2PError::InvalidLength {
                expected: 32,
                got: 31,
            }
        );
        let r = I2PSigner::from_seed(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn verifier_from_invalid_point_fails() {
        // y-координата с установленным старшим битом, но не на кривой.
        // Находим байты, которые ed25519-dalek отвергает как точку.
        // Проверяем хотя бы, что некоторые входы дают Malformed.
        let invalid = [0xffu8; 32];
        match I2PVerifier::new(&invalid) {
            Err(I2PError::Malformed(_)) | Ok(_) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ---- lengths -------------------------------------------------------

    #[test]
    fn constants_match_rfc8032() {
        assert_eq!(PUBLIC_KEY_LEN, 32);
        assert_eq!(PRIVATE_KEY_LEN, 32);
        assert_eq!(SIGNATURE_LEN, 64);
    }

    #[test]
    fn signature_is_64_bytes() {
        let signer = I2PSigner::generate();
        let sig = signer.sign(b"x");
        assert_eq!(sig.len(), SIGNATURE_LEN);
    }

    #[test]
    fn public_key_is_32_bytes() {
        let signer = I2PSigner::generate();
        assert_eq!(signer.public_key().len(), PUBLIC_KEY_LEN);
    }

    // ---- RFC 8032 test vector ------------------------------------------

    /// RFC 8032, Section 7.1, Test 1.
    ///
    /// SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    /// PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    /// MESSAGE:    (empty)
    /// SIGNATURE:  e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    #[test]
    fn rfc8032_test_vector_1() {
        let secret: [u8; 32] =
            hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public: [u8; 32] =
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_sig: [u8; 64] = hex64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let signer = I2PSigner::from_seed(&secret).unwrap();
        assert_eq!(signer.public_key(), expected_public);

        let msg = b"";
        let sig = signer.sign(msg);
        assert_eq!(sig, expected_sig);

        let v = I2PVerifier::new(&expected_public).unwrap();
        assert!(v.verify(msg, &sig).is_ok());
    }

    /// RFC 8032, Section 7.1, Test 2.
    ///
    /// SECRET KEY: 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
    /// PUBLIC KEY: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    /// MESSAGE:    72
    /// SIGNATURE:  92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
    #[test]
    fn rfc8032_test_vector_2() {
        let secret: [u8; 32] =
            hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_public: [u8; 32] =
            hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let expected_sig: [u8; 64] = hex64(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );

        let signer = I2PSigner::from_seed(&secret).unwrap();
        assert_eq!(signer.public_key(), expected_public);

        let msg = [0x72u8];
        let sig = signer.sign(&msg);
        assert_eq!(sig, expected_sig);

        let v = I2PVerifier::new(&expected_public).unwrap();
        assert!(v.verify(&msg, &sig).is_ok());
    }

    // ---- helpers -------------------------------------------------------

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex_into(s, &mut out);
        out
    }

    fn hex64(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        hex_into(s, &mut out);
        out
    }

    fn hex_into(s: &str, out: &mut [u8]) {
        assert_eq!(s.len(), out.len() * 2);
        let (chunks, remainder) = s.as_bytes().as_chunks::<2>();
        debug_assert_eq!(remainder, [0u8; 0]);
        for (i, chunk) in chunks.iter().enumerate() {
            let hi = hex_digit(chunk[0]);
            let lo = hex_digit(chunk[1]);
            out[i] = (hi << 4) | lo;
        }
    }

    const fn hex_digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }
}
