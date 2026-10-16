#[cfg(test)]
mod tests {
    use uu_i2p::{
        DatabaseLookup, ECIES_TAG_LEN, ELGAMAL_TAG_LEN, EncryptedReply, I2PError, IdentHash,
        LOOKUP_FLAG_DELIVERY, LOOKUP_FLAG_ECIES, LOOKUP_FLAG_ENCRYPTION, LookupType,
        database_lookup::DATABASE_LOOKUP_HEADER_SIZE, endian::write_u16_be,
    };

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    // ---- lookup type --------------------------------------------------

    #[test]
    fn lookup_type_flags_roundtrip() {
        for t in [
            LookupType::Normal,
            LookupType::LeaseSet,
            LookupType::RouterInfo,
            LookupType::Exploratory,
        ] {
            let bits = t.as_flags_bits();
            assert_eq!(LookupType::from_flags_bits(bits), t);
        }
    }

    #[test]
    fn lookup_type_flag_values() {
        assert_eq!(LookupType::Normal.as_flags_bits(), 0);
        assert_eq!(LookupType::LeaseSet.as_flags_bits(), 4);
        assert_eq!(LookupType::RouterInfo.as_flags_bits(), 8);
        assert_eq!(LookupType::Exploratory.as_flags_bits(), 12);
    }

    #[test]
    fn lookup_type_ignores_other_bits() {
        // биты 0-1 и 4-7 не должны влиять на тип
        assert_eq!(
            LookupType::from_flags_bits(0x08 | 0x01),
            LookupType::RouterInfo
        );
        assert_eq!(
            LookupType::from_flags_bits(0x04 | 0xF2),
            LookupType::LeaseSet
        );
    }

    // ---- basic round-trips ---------------------------------------------

    #[test]
    fn roundtrip_minimal_router_info() {
        let l = DatabaseLookup::new_router_info(ident(1), ident(2), None, vec![]);
        let buf = l.to_buffer().unwrap();
        let back = DatabaseLookup::from_buffer(&buf).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn roundtrip_with_reply_tunnel() {
        let l =
            DatabaseLookup::new_router_info(ident(0xAA), ident(0xBB), Some(0xDEAD_BEEF), vec![]);
        let buf = l.to_buffer().unwrap();
        let back = DatabaseLookup::from_buffer(&buf).unwrap();
        assert_eq!(back.reply_tunnel_id, Some(0xDEAD_BEEF));
    }

    #[test]
    fn roundtrip_exploratory() {
        let l = DatabaseLookup::new_exploratory(ident(1), ident(2), None, vec![]);
        let buf = l.to_buffer().unwrap();
        let back = DatabaseLookup::from_buffer(&buf).unwrap();
        assert_eq!(back.lookup_type, LookupType::Exploratory);
    }

    #[test]
    fn roundtrip_with_excluded() {
        let excluded = vec![ident(0x11), ident(0x22), ident(0x33)];
        let l = DatabaseLookup::new_router_info(ident(1), ident(2), None, excluded);
        let buf = l.to_buffer().unwrap();
        let back = DatabaseLookup::from_buffer(&buf).unwrap();
        assert_eq!(back.excluded.len(), 3);
        assert_eq!(back.excluded[0], ident(0x11));
        assert_eq!(back.excluded[2], ident(0x33));
    }

    // ---- encryption ---------------------------------------------------

    #[test]
    fn roundtrip_ecies_encrypted_reply() {
        let mut l = DatabaseLookup::new_router_info(ident(1), ident(2), Some(42), vec![]);
        l.encrypted_reply = Some(EncryptedReply {
            session_key: [0x77u8; 32],
            tags: vec![vec![0u8; ECIES_TAG_LEN], vec![1u8; ECIES_TAG_LEN]],
        });
        let buf = l.to_buffer().unwrap();
        let back = DatabaseLookup::from_buffer(&buf).unwrap();
        assert_eq!(back, l);

        // Проверяем, что флаг ECIES действительно выставлен
        let flags = buf[64];
        assert!(flags & LOOKUP_FLAG_ECIES != 0);
        assert!(flags & LOOKUP_FLAG_ENCRYPTION != 0);
    }

    #[test]
    fn roundtrip_elgamal_encrypted_reply() {
        let mut l = DatabaseLookup::new_router_info(ident(1), ident(2), Some(42), vec![]);
        l.encrypted_reply = Some(EncryptedReply {
            session_key: [0x88u8; 32],
            tags: vec![vec![0u8; ELGAMAL_TAG_LEN]],
        });
        let buf = l.to_buffer().unwrap();
        let back = DatabaseLookup::from_buffer(&buf).unwrap();
        assert_eq!(back, l);

        let flags = buf[64];
        assert_eq!(flags & LOOKUP_FLAG_ECIES, 0);
        assert_ne!(flags & LOOKUP_FLAG_ENCRYPTION, 0);
    }

    // ---- errors -------------------------------------------------------

    #[test]
    fn empty_buffer_invalid() {
        let r = DatabaseLookup::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn short_header_invalid() {
        let r = DatabaseLookup::from_buffer(&[0u8; DATABASE_LOOKUP_HEADER_SIZE - 1]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn delivery_flag_without_tunnel_id_fails() {
        let mut buf = vec![0u8; DATABASE_LOOKUP_HEADER_SIZE];
        buf[64] = LOOKUP_FLAG_DELIVERY; // flag set
        // нет 4 байт tunnel_id
        let r = DatabaseLookup::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn too_many_excluded_in_buffer_fails() {
        let mut buf = vec![0u8; DATABASE_LOOKUP_HEADER_SIZE + 2];
        write_u16_be(&mut buf[DATABASE_LOOKUP_HEADER_SIZE..], 1000);
        let r = DatabaseLookup::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn encryption_flag_without_session_key_fails() {
        let mut buf = vec![0u8; DATABASE_LOOKUP_HEADER_SIZE];
        buf[64] = LOOKUP_FLAG_ECIES | LOOKUP_FLAG_ENCRYPTION;
        // нет session_key + num_tags
        let r = DatabaseLookup::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn wrong_tag_len_in_to_buffer_fails() {
        let mut l = DatabaseLookup::new_router_info(ident(1), ident(2), None, vec![]);
        l.encrypted_reply = Some(EncryptedReply {
            session_key: [0u8; 32],
            tags: vec![vec![0u8; 16]], // 16 байт — не 8 и не 32
        });
        // Writer посмотрит на первый тег: 16 ≠ 8, значит решит ElGamal.
        // 16 ≠ 32 → Malformed.
        let r = l.to_buffer();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    // ---- byte-perfect --------------------------------------------------

    #[test]
    fn to_buffer_is_stable() {
        let l = DatabaseLookup::new_router_info(ident(1), ident(2), Some(42), vec![ident(3)]);
        let b1 = l.to_buffer().unwrap();
        let b2 = l.to_buffer().unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn flags_layout_matches_spec() {
        // Пример из i2pd CreateRouterInfoDatabaseLookupMsg:
        // exploratory flag = 0x0C | (DELIVERY = 0x01) = 0x0D
        let l = DatabaseLookup::new_exploratory(ident(1), ident(2), Some(0), vec![]);
        let buf = l.to_buffer().unwrap();
        assert_eq!(buf[64], 0x0C | 0x01);

        let l2 = DatabaseLookup::new_router_info(ident(1), ident(2), None, vec![]);
        let buf2 = l2.to_buffer().unwrap();
        assert_eq!(buf2[64], 0x08);
    }
}
