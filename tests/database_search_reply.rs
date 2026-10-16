#[cfg(test)]
mod tests {
    use uu_i2p::{
        DatabaseSearchReply, I2PError, IdentHash,
        database_search_reply::DATABASE_SEARCH_REPLY_HEADER_SIZE,
    };

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    // ---- round-trips ---------------------------------------------------

    #[test]
    fn roundtrip_empty_hashes() {
        let r = DatabaseSearchReply::new(ident(1), vec![]);
        let buf = r.to_buffer().unwrap();
        assert_eq!(buf.len(), DATABASE_SEARCH_REPLY_HEADER_SIZE);
        let back = DatabaseSearchReply::from_buffer(&buf).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn roundtrip_one_hash() {
        let r = DatabaseSearchReply::new(ident(0xAA), vec![ident(0x11)]);
        let buf = r.to_buffer().unwrap();
        let back = DatabaseSearchReply::from_buffer(&buf).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn roundtrip_three_hashes() {
        let r = DatabaseSearchReply::new(ident(0xAA), vec![ident(0x11), ident(0x22), ident(0x33)]);
        let buf = r.to_buffer().unwrap();
        let back = DatabaseSearchReply::from_buffer(&buf).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn roundtrip_with_from() {
        let r = DatabaseSearchReply::with_from(
            ident(0xAA),
            vec![ident(0x11), ident(0x22)],
            ident(0xBB),
        );
        let buf = r.to_buffer().unwrap();
        // key + num + 2*32 + from(32)
        assert_eq!(buf.len(), DATABASE_SEARCH_REPLY_HEADER_SIZE + 2 * 32 + 32);
        let back = DatabaseSearchReply::from_buffer(&buf).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn roundtrip_max_hashes() {
        let hashes: Vec<IdentHash> = (0u8..255).map(ident).collect();
        let r = DatabaseSearchReply::new(ident(1), hashes);
        let buf = r.to_buffer().unwrap();
        let back = DatabaseSearchReply::from_buffer(&buf).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.peer_hashes.len(), 255);
    }

    // ---- trailing bytes ------------------------------------------------

    #[test]
    fn trailing_bytes_ignored() {
        let r = DatabaseSearchReply::new(ident(1), vec![ident(0x11)]);
        let mut buf = r.to_buffer().unwrap();
        buf.extend_from_slice(b"--- garbage ---");
        let back = DatabaseSearchReply::from_buffer(&buf).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn partial_from_ignored() {
        // только 16 байт из from — недостаточно, значит None
        let buf = vec![0u8; DATABASE_SEARCH_REPLY_HEADER_SIZE + 16];
        let back = DatabaseSearchReply::from_buffer(&buf).unwrap();
        assert_eq!(back.from, None);
    }

    // ---- errors -------------------------------------------------------

    #[test]
    fn empty_buffer_invalid() {
        let r = DatabaseSearchReply::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn short_header_invalid() {
        let r = DatabaseSearchReply::from_buffer(&[0u8; DATABASE_SEARCH_REPLY_HEADER_SIZE - 1]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn declared_num_exceeds_buffer() {
        let mut buf = vec![0u8; DATABASE_SEARCH_REPLY_HEADER_SIZE];
        buf[32] = 3; // num = 3
        // но нет hashes
        let r = DatabaseSearchReply::from_buffer(&buf);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: DATABASE_SEARCH_REPLY_HEADER_SIZE + 3 * 32,
                got: DATABASE_SEARCH_REPLY_HEADER_SIZE,
            })
        );
    }

    // ---- byte-perfect -------------------------------------------------

    #[test]
    fn to_buffer_stable() {
        let r = DatabaseSearchReply::with_from(ident(0xAA), vec![ident(0x11)], ident(0xBB));
        assert_eq!(r.to_buffer().unwrap(), r.to_buffer().unwrap());
    }

    #[test]
    fn matches_i2pd_layout() {
        // i2pd пишет: key(32) || num(1) || hashes(num*32) || from(32)
        let r = DatabaseSearchReply::with_from(
            ident(0x01),
            vec![ident(0x02), ident(0x03)],
            ident(0x04),
        );
        let buf = r.to_buffer().unwrap();
        assert_eq!(&buf[0..32], &[0x01; 32]);
        assert_eq!(buf[32], 2);
        assert_eq!(&buf[33..65], &[0x02; 32]);
        assert_eq!(&buf[65..97], &[0x03; 32]);
        assert_eq!(&buf[97..129], &[0x04; 32]);
    }

    #[test]
    fn header_size_constant() {
        assert_eq!(DATABASE_SEARCH_REPLY_HEADER_SIZE, 33);
        assert_eq!(DATABASE_SEARCH_REPLY_HEADER_SIZE, 32 + 1);
    }
}
