#[cfg(test)]
mod tests {
    use uu_i2p::I2PAesKey;
    use uu_i2p::IdentHash;
    use uu_i2p::SessionTag;
    use uu_i2p::VERSION;
    use uu_i2p::base32;
    use uu_i2p::base64;

    #[test]
    fn version_is_present() {
        assert_ne!(VERSION, "");
    }

    #[test]
    fn aliases_have_expected_size() {
        assert_eq!(IdentHash::LEN, 32);
        assert_eq!(I2PAesKey::LEN, 32);
        assert_eq!(SessionTag::LEN, 32);
    }

    #[test]
    fn ident_hash_b64_b32_roundtrip_100x() {
        let mut rng = rand::thread_rng();
        for i in 0..100 {
            let h = IdentHash::random(&mut rng);
            assert_eq!(
                IdentHash::from_base64(&h.to_base64()).unwrap(),
                h,
                "b64 iter {i}"
            );
            assert_eq!(
                IdentHash::from_base32(&h.to_base32()).unwrap(),
                h,
                "b32 iter {i}"
            );
        }
    }

    #[test]
    fn one_hundred_random_idents_are_unique() {
        let mut rng = rand::thread_rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            assert!(
                seen.insert(IdentHash::random(&mut rng)),
                "collision in 100 random 256-bit idents"
            );
        }
    }

    #[test]
    fn i2p_b64_alphabet_is_used() {
        // 62 = '-', 63 = '~' — I2P-специфика
        let bytes = [0xff_u8, 0xff, 0xff];
        assert_eq!(base64::encode_no_pad(&bytes), "~~~~");
    }

    #[test]
    fn i2p_b32_alphabet_is_used() {
        // lowercase, без padding
        assert_eq!(base32::encode(b"foobar"), "mzxw6ytboi");
        assert!(!base32::encode(b"foobar").contains('='));
    }
}
