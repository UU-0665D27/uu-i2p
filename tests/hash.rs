#[cfg(test)]
mod tests {
    use uu_i2p::{
        I2PHash, I2PTag,
        error::{I2PError, Result},
    };

    #[test]
    fn len_const() {
        assert_eq!(I2PHash::LEN, 32);
    }

    #[test]
    fn sha256_empty() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = I2PHash::of(b"");
        assert_eq!(
            h.to_base64(),
            // I2P base64 от этих байтов:
            "47DEQpj8HBSa-~TImW-5JCeuQeRkm5NMpJWZG3hSuFU="
        );
    }

    #[test]
    fn sha256_abc() {
        // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = I2PHash::of(b"abc");
        let expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex_encode(h.as_bytes()), expected_hex);
    }

    #[test]
    fn sha256_quick_brown_fox() {
        // SHA256("The quick brown fox jumps over the lazy dog")
        let h = I2PHash::of(b"The quick brown fox jumps over the lazy dog");
        let expected_hex = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
        assert_eq!(hex_encode(h.as_bytes()), expected_hex);
    }

    #[test]
    fn of_concat_equals_streaming() {
        // Hash::of_concat([a, b]) == Hash::of(a ++ b)
        let a = b"hello, ";
        let b = b"i2p!";
        let mut joined = Vec::new();
        joined.extend_from_slice(a);
        joined.extend_from_slice(b);
        assert_eq!(I2PHash::of_concat(&[a, b]), I2PHash::of(&joined));
    }

    #[test]
    fn of_concat_empty() {
        // Пустой список частей == хеш пустого ввода
        assert_eq!(I2PHash::of_concat(&[]), I2PHash::of(b""));
    }

    #[test]
    fn of_concat_single() {
        assert_eq!(I2PHash::of_concat(&[b"abc"]), I2PHash::of(b"abc"));
    }

    #[test]
    fn is_zero_true() {
        assert!(I2PHash::from([0u8; 32]).is_zero());
    }

    #[test]
    fn is_zero_false() {
        assert!(!I2PHash::of(b"").is_zero());
    }

    #[test]
    fn base32_roundtrip() {
        let h = I2PHash::of(b"hello");
        assert_eq!(I2PHash::from_base32(&h.to_base32()).unwrap(), h);
    }

    #[test]
    fn base64_roundtrip() {
        let h = I2PHash::of(b"hello");
        assert_eq!(I2PHash::from_base64(&h.to_base64()).unwrap(), h);
    }

    #[test]
    fn debug_and_display_use_base64() {
        let h = I2PHash::of(b"");
        let b64 = h.to_base64();
        assert_eq!(format!("{h:?}"), format!("Hash({b64})"));
        assert_eq!(format!("{h}"), b64);
    }

    #[test]
    fn as_ref_is_slice() {
        let h = I2PHash::of(b"x");
        let s: &[u8] = h.as_ref();
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn try_from_wrong_length() {
        let r: Result<I2PHash> = (&[0u8; 31][..]).try_into();
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 32,
                got: 31
            })
        );
    }

    #[test]
    fn from_array_roundtrip() {
        let arr = [7u8; 32];
        let h = I2PHash::from(arr);
        let back: [u8; 32] = h.into();
        assert_eq!(back, arr);
    }

    #[test]
    fn tag32_to_hash_and_back() {
        let t = I2PTag::<32>::from_array([1u8; 32]);
        let h: I2PHash = t.into();
        let t2: I2PTag<32> = h.into();
        assert_eq!(t, t2);
    }

    #[test]
    fn hash_as_ident_hash_like_in_i2pd() {
        // Типичный паттерн: хеш от identity = IdentHash
        let identity_bytes = b"some identity";
        let h = I2PHash::of(identity_bytes);
        let ident: I2PTag<32> = h.into();
        // и обратно
        let h2: I2PHash = ident.into();
        assert_eq!(h, h2);
    }

    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").expect("writing to String never fails");
        }
        s
    }
}
