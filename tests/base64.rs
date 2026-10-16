mod tests {
    use uu_i2p::{
        base64::{decode, decode_to, encode, encode_no_pad},
        error::{I2PError, Result},
    };

    #[test]
    fn empty() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode_no_pad(&[]), "");
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn i2p_alphabet() {
        // 0xff 0xff 0xff -> 111111 111111 111111 111111 -> '~' x4
        assert_eq!(encode_no_pad(&[0xff, 0xff, 0xff]), "~~~~");
        // 0x00 0x00 0x00 -> 'A' x4
        assert_eq!(encode_no_pad(&[0x00, 0x00, 0x00]), "AAAA");
    }

    #[test]
    fn roundtrip_all_lengths() {
        for len in 0..64_u8 {
            let data: Vec<u8> = (0..len)
                .map(|i| i.wrapping_mul(41).wrapping_add(7))
                .collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data, "padded len={len}");
            assert_eq!(
                decode(&encode_no_pad(&data)).unwrap(),
                data,
                "no-pad len={len}"
            );
        }
    }

    #[test]
    fn accepts_both_padded_and_unpadded() {
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm8").unwrap(), b"fo");
    }

    #[test]
    fn invalid_char_plus_slash() {
        // стандартный RFC 4648 алфавит — это ошибка для I2P
        assert!(matches!(decode("Z+"), Err(I2PError::InvalidBase64(b'+'))));
        assert!(matches!(decode("Z/"), Err(I2PError::InvalidBase64(b'/'))));
    }

    #[test]
    fn non_canonical_tail() {
        // "ZA" = 2 символа = 12 бит: 8 значащих + 4 нулевых → ок
        assert!(decode("ZA").is_ok());
        // "Zh" = 2 символа = 12 бит: хвост 0001 — значащий → ошибка
        assert!(matches!(decode("Zh"), Err(I2PError::NonCanonical)));
    }

    #[test]
    fn decode_to_length_ok() {
        let bytes = decode_to::<3>("Zm9v").unwrap();
        assert_eq!(&bytes, b"foo");
    }

    #[test]
    fn decode_to_length_err() {
        let r: Result<[u8; 4]> = decode_to("Zm9v");
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 4,
                got: 3
            })
        );
    }
}
