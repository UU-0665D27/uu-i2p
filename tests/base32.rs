#[cfg(test)]
mod tests {
    use uu_i2p::{
        base32::{decode, decode_to, encode},
        error::{I2PError, Result},
    };

    #[test]
    fn empty() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn known_vectors() {
        // RFC 4648 test vectors, lowercase без padding
        assert_eq!(encode(b"f"), "my");
        assert_eq!(encode(b"fo"), "mzxq");
        assert_eq!(encode(b"foo"), "mzxw6");
        assert_eq!(encode(b"foob"), "mzxw6yq");
        assert_eq!(encode(b"fooba"), "mzxw6ytb");
        assert_eq!(encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn roundtrip_all_lengths() {
        for len in 0..64_u8 {
            let data: Vec<u8> = (0..len)
                .map(|i| i.wrapping_mul(37).wrapping_add(13))
                .collect();
            let enc = encode(&data);
            let dec = decode(&enc).unwrap();
            assert_eq!(dec, data, "len={len}");
        }
    }

    #[test]
    fn invalid_char_lowercase() {
        assert!(matches!(decode("MZXW6"), Err(I2PError::InvalidBase32(b'M'))));
    }

    #[test]
    fn invalid_char_digit() {
        assert!(matches!(decode("m1"), Err(I2PError::InvalidBase32(b'1'))));
        assert!(matches!(decode("m8"), Err(I2PError::InvalidBase32(b'8'))));
    }

    #[test]
    fn invalid_char_empty_ok() {
        // пустая строка валидна
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn non_canonical_tail() {
        // "ma" = 2 символа = 10 бит: 8 значащих + 2 нулевых → ок
        assert!(decode("ma").is_ok());
        // "mz" = 2 символа = 10 бит: хвост 01 — значащий → ошибка
        assert!(matches!(decode("mz"), Err(I2PError::NonCanonical)));
    }

    #[test]
    fn decode_to_length_ok() {
        let bytes = decode_to::<3>("mzxw6").unwrap();
        assert_eq!(&bytes, b"foo");
    }

    #[test]
    fn decode_to_length_err() {
        let r: Result<[u8; 4]> = decode_to("mzxw6");
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 4,
                got: 3
            })
        );
    }
}
