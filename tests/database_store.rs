#[cfg(test)]
mod tests {
    use uu_i2p::{
        DatabaseStore, I2PError, IdentHash, ReplyInstruction, StoreType,
        database_store::{
            DATABASE_STORE_HEADER_SIZE, STORE_TYPE_ENCRYPTED_LEASESET2, STORE_TYPE_LEASESET,
            STORE_TYPE_META_LEASESET2, STORE_TYPE_ROUTER_INFO, STORE_TYPE_STANDARD_LEASESET2,
        },
    };

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    // ---- store_type ----------------------------------------------------

    #[test]
    fn store_type_roundtrip() {
        for v in [
            StoreType::RouterInfo,
            StoreType::LeaseSet,
            StoreType::LeaseSet2,
            StoreType::EncryptedLeaseSet2,
            StoreType::MetaLeaseSet2,
        ] {
            assert_eq!(StoreType::from_u8(v.as_u8()), v);
        }
    }

    #[test]
    fn store_type_unknown_preserved() {
        let t = StoreType::from_u8(0x42);
        assert_eq!(t, StoreType::Unknown(0x42));
        assert_eq!(t.as_u8(), 0x42);
    }

    #[test]
    fn store_type_constants_match_spec() {
        assert_eq!(STORE_TYPE_ROUTER_INFO, 0);
        assert_eq!(STORE_TYPE_LEASESET, 1);
        assert_eq!(STORE_TYPE_STANDARD_LEASESET2, 3);
        assert_eq!(STORE_TYPE_ENCRYPTED_LEASESET2, 5);
        assert_eq!(STORE_TYPE_META_LEASESET2, 7);
    }

    // ---- RouterInfo ----------------------------------------------------

    #[test]
    fn router_info_roundtrip_no_reply() {
        let ri_bytes: Vec<u8> = (0..500).map(|i| u8::try_from(i & 0xff).unwrap()).collect();
        let ds = DatabaseStore::new_router_info(ident(0x11), &ri_bytes, 0, None).unwrap();
        assert_eq!(ds.store_type, StoreType::RouterInfo);
        assert_eq!(ds.reply_token, 0);
        assert!(ds.reply_instruction.is_none());

        let bytes = ds.to_buffer().unwrap();
        let back = DatabaseStore::from_buffer(&bytes).unwrap();
        assert_eq!(back.key, ds.key);
        assert_eq!(back.store_type, ds.store_type);
        assert_eq!(back.reply_token, ds.reply_token);
        assert_eq!(back.reply_instruction, ds.reply_instruction);
        assert_eq!(back.payload_decoded().unwrap(), ri_bytes);
    }

    #[test]
    fn router_info_roundtrip_with_reply() {
        let ri_bytes = b"fake router info".to_vec();
        let instr = ReplyInstruction {
            tunnel_id: 0xDEAD_BEEF,
            gateway: ident(0x22),
        };
        let ds = DatabaseStore::new_router_info(ident(0x33), &ri_bytes, 0x1122_3344, Some(instr))
            .unwrap();

        let bytes = ds.to_buffer().unwrap();
        let back = DatabaseStore::from_buffer(&bytes).unwrap();
        assert_eq!(back.reply_token, 0x1122_3344);
        assert_eq!(back.reply_instruction, Some(instr));
        assert_eq!(back.payload_decoded().unwrap(), ri_bytes);
    }

    #[test]
    fn router_info_empty_payload() {
        let ds = DatabaseStore::new_router_info(ident(1), &[], 0, None).unwrap();
        let bytes = ds.to_buffer().unwrap();
        let back = DatabaseStore::from_buffer(&bytes).unwrap();
        assert_eq!(back.payload_decoded().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn router_info_large_payload_roundtrip() {
        // ~3 KB, как максимум RouterInfo
        let ri_bytes: Vec<u8> = (0..3072).map(|i| u8::try_from(i & 0xff).unwrap()).collect();
        let ds = DatabaseStore::new_router_info(ident(1), &ri_bytes, 0, None).unwrap();
        let bytes = ds.to_buffer().unwrap();
        let back = DatabaseStore::from_buffer(&bytes).unwrap();
        assert_eq!(back.payload_decoded().unwrap(), ri_bytes);
    }

    #[test]
    fn router_info_with_token_without_instruction_fails() {
        let r = DatabaseStore::new_router_info(ident(1), b"x", 0x42, None);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    // ---- LeaseSet ------------------------------------------------------

    #[test]
    fn lease_set_roundtrip() {
        let ls_bytes = b"fake leaseset bytes".to_vec();
        let ds = DatabaseStore::new_lease_set(ident(0xAA), ls_bytes.clone());
        assert_eq!(ds.store_type, StoreType::LeaseSet);

        let bytes = ds.to_buffer().unwrap();
        let back = DatabaseStore::from_buffer(&bytes).unwrap();
        assert_eq!(back.key, ident(0xAA));
        assert_eq!(back.store_type, StoreType::LeaseSet);
        assert_eq!(back.reply_token, 0);
        assert_eq!(back.reply_instruction, None);
        // Для LS payload не сжимается
        assert_eq!(back.payload_raw(), &ls_bytes[..]);
        assert_eq!(back.payload_decoded().unwrap(), ls_bytes);
    }

    #[test]
    fn lease_set2_roundtrip() {
        let ls_bytes = b"fake leaseset2".to_vec();
        let ds = DatabaseStore::new_lease_set2(ident(0xBB), ls_bytes.clone());
        let bytes = ds.to_buffer().unwrap();
        let back = DatabaseStore::from_buffer(&bytes).unwrap();
        assert_eq!(back.store_type, StoreType::LeaseSet2);
        assert_eq!(back.payload_raw(), &ls_bytes[..]);
    }

    // ---- errors -------------------------------------------------------

    #[test]
    fn empty_buffer_invalid() {
        let r = DatabaseStore::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn too_short_for_reply_instruction() {
        let mut buf = vec![0u8; DATABASE_STORE_HEADER_SIZE];
        // reply_token = 1 (не 0)
        buf[33..37].copy_from_slice(&1u32.to_be_bytes());
        // но нет reply_instruction
        let r = DatabaseStore::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn router_info_gzip_len_too_big() {
        let mut buf = vec![0u8; DATABASE_STORE_HEADER_SIZE];
        // store_type = 0
        buf[32] = 0;
        // gzip_len = 0xFFFF, но payload пустой
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes());
        let r = DatabaseStore::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    // ---- byte-perfect --------------------------------------------------

    #[test]
    fn router_info_to_buffer_is_stable() {
        // to_buffer должен возвращать одинаковые байты при
        // повторных вызовах для одного и того же struct'а.
        let ri_bytes = b"stable input".to_vec();
        let ds = DatabaseStore::new_router_info(ident(1), &ri_bytes, 0, None).unwrap();
        let b1 = ds.to_buffer().unwrap();
        let b2 = ds.to_buffer().unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn reparse_reserialize_is_stable() {
        // parse(to_buffer(parse(buf))) == parse(buf) — semantic
        let ri_bytes: Vec<u8> = (0..100).map(|i| u8::try_from(i).unwrap()).collect();
        let ds = DatabaseStore::new_router_info(ident(0x55), &ri_bytes, 0, None).unwrap();
        let buf1 = ds.to_buffer().unwrap();
        let ds2 = DatabaseStore::from_buffer(&buf1).unwrap();
        let buf2 = ds2.to_buffer().unwrap();
        // payload одинаковый, но не обязательно тот же gzip — flate2
        // может выдавать разный stream для одинаковых входов в
        // зависимости от уровня сжатия. Но при одинаковом уровне
        // (Compression::default()) — детерминирован.
        let ds3 = DatabaseStore::from_buffer(&buf2).unwrap();
        assert_eq!(ds2.payload_raw(), ds3.payload_raw());
    }
}
