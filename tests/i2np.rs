#[cfg(test)]
mod tests {
    use uu_i2p::{
        I2PError, I2npHeader, I2npMessageType,
        i2np::{
            I2NP_HEADER_CHKS_OFFSET, I2NP_HEADER_EXPIRATION_OFFSET, I2NP_HEADER_MSGID_OFFSET,
            I2NP_HEADER_SIZE, I2NP_HEADER_SIZE_OFFSET, I2NP_HEADER_TYPEID_OFFSET,
            I2NP_MESSAGE_CLOCK_SKEW_MS, I2NP_MESSAGE_EXPIRATION_TIMEOUT_MS,
        },
    };

    // ---- enum -----------------------------------------------------------

    #[test]
    fn message_type_roundtrip_all_variants() {
        let all = [
            I2npMessageType::DatabaseStore,
            I2npMessageType::DatabaseLookup,
            I2npMessageType::DatabaseSearchReply,
            I2npMessageType::DeliveryStatus,
            I2npMessageType::Garlic,
            I2npMessageType::TunnelData,
            I2npMessageType::TunnelGateway,
            I2npMessageType::Data,
            I2npMessageType::TunnelBuild,
            I2npMessageType::TunnelBuildReply,
            I2npMessageType::VariableTunnelBuild,
            I2npMessageType::VariableTunnelBuildReply,
            I2npMessageType::ShortTunnelBuild,
            I2npMessageType::ShortTunnelBuildReply,
            I2npMessageType::TunnelTest,
        ];
        for t in all {
            let v = t.as_u8();
            let back = I2npMessageType::from_u8(v).unwrap();
            assert_eq!(back, t, "type {t:?} -> {v} -> {back:?}");
        }
    }

    #[test]
    fn message_type_known_values_match_spec() {
        // Сверяем с I2NPProtocol.h
        assert_eq!(I2npMessageType::DatabaseStore.as_u8(), 1);
        assert_eq!(I2npMessageType::DatabaseLookup.as_u8(), 2);
        assert_eq!(I2npMessageType::DatabaseSearchReply.as_u8(), 3);
        assert_eq!(I2npMessageType::DeliveryStatus.as_u8(), 10);
        assert_eq!(I2npMessageType::Garlic.as_u8(), 11);
        assert_eq!(I2npMessageType::TunnelData.as_u8(), 18);
        assert_eq!(I2npMessageType::TunnelGateway.as_u8(), 19);
        assert_eq!(I2npMessageType::Data.as_u8(), 20);
        assert_eq!(I2npMessageType::VariableTunnelBuild.as_u8(), 23);
        assert_eq!(I2npMessageType::ShortTunnelBuild.as_u8(), 25);
        assert_eq!(I2npMessageType::TunnelTest.as_u8(), 231);
    }

    #[test]
    fn message_type_unknown_returns_error() {
        for v in [0u8, 4, 5, 9, 12, 17, 27, 100, 200, 255] {
            let r = I2npMessageType::from_u8(v);
            assert_eq!(
                r,
                Err(I2PError::UnknownI2npType(v)),
                "unexpectedly OK for {v}"
            );
        }
    }

    #[test]
    fn message_type_name_is_unique() {
        // Проверяем, что name() возвращает разные строки для разных типов
        // (может быть полезно, чтобы не было опечаток).
        let names = [
            I2npMessageType::DatabaseStore.name(),
            I2npMessageType::DatabaseLookup.name(),
            I2npMessageType::DatabaseSearchReply.name(),
            I2npMessageType::DeliveryStatus.name(),
            I2npMessageType::Garlic.name(),
            I2npMessageType::TunnelData.name(),
            I2npMessageType::TunnelGateway.name(),
            I2npMessageType::Data.name(),
            I2npMessageType::TunnelTest.name(),
        ];
        let mut seen = std::collections::HashSet::new();
        for n in names {
            assert!(seen.insert(n), "duplicate name: {n}");
        }
    }

    #[test]
    fn message_type_display_matches_name() {
        for t in [I2npMessageType::Garlic, I2npMessageType::TunnelData] {
            assert_eq!(format!("{t}"), t.name());
        }
    }

    // ---- header layout --------------------------------------------------

    #[test]
    fn header_size_is_16() {
        assert_eq!(I2NP_HEADER_SIZE, 16);
        assert_eq!(I2npHeader::SIZE, 16);
    }

    #[test]
    fn header_offsets_match_spec() {
        assert_eq!(I2NP_HEADER_TYPEID_OFFSET, 0);
        assert_eq!(I2NP_HEADER_MSGID_OFFSET, 1);
        assert_eq!(I2NP_HEADER_EXPIRATION_OFFSET, 5);
        assert_eq!(I2NP_HEADER_SIZE_OFFSET, 13);
        assert_eq!(I2NP_HEADER_CHKS_OFFSET, 15);
    }

    #[test]
    fn header_serialize_parse_roundtrip() {
        let h = I2npHeader {
            message_type: I2npMessageType::DatabaseStore,
            msg_id: 0xdead_beef,
            expiration_ms: 1_700_000_000_000,
            size: 1024,
            checksum: Some(0xab),
        };
        let mut buf = [0u8; I2NP_HEADER_SIZE];
        h.serialize(&mut buf).unwrap();
        let back = I2npHeader::parse(&buf).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn header_serialize_golden() {
        let h = I2npHeader {
            message_type: I2npMessageType::TunnelData, // 18 = 0x12
            msg_id: 0x1122_3344,
            expiration_ms: 0x0102_0304_0506_0708,
            size: 0xabcd,
            checksum: Some(0x99),
        };
        let mut buf = [0u8; I2NP_HEADER_SIZE];
        h.serialize(&mut buf).unwrap();
        assert_eq!(
            buf,
            [
                0x12, // typeID
                0x11, 0x22, 0x33, 0x44, // msgID
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // expiration
                0xab, 0xcd, // size
                0x99, // chks
            ]
        );
    }

    #[test]
    fn header_parse_golden() {
        let buf = [
            0x01, // DatabaseStore
            0xde, 0xad, 0xbe, 0xef, // msgID
            0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x00, // expiration
            0x04, 0x00, // size = 1024
            0x7f, // chks
        ];
        let h = I2npHeader::parse(&buf).unwrap();
        assert_eq!(h.message_type, I2npMessageType::DatabaseStore);
        assert_eq!(h.msg_id, 0xdead_beef);
        assert_eq!(h.expiration_ms, 0x0000_0190_0000_0000);
        assert_eq!(h.size, 1024);
        assert_eq!(h.checksum, Some(0x7f));
    }

    #[test]
    fn header_parse_checksum_zero_means_none() {
        let buf = [
            0x01, // DatabaseStore
            0, 0, 0, 0, // msgID
            0, 0, 0, 0, 0, 0, 0, 0, // expiration
            0, 0, // size
            0, // chks = 0
        ];
        let h = I2npHeader::parse(&buf).unwrap();
        assert_eq!(h.checksum, None);
    }

    #[test]
    fn header_parse_too_short() {
        let r = I2npHeader::parse(&[0u8; 15]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 16,
                got: 15
            })
        );
    }

    #[test]
    fn header_parse_unknown_type() {
        let mut buf = [0u8; I2NP_HEADER_SIZE];
        buf[0] = 0xff;
        let r = I2npHeader::parse(&buf);
        assert_eq!(r, Err(I2PError::UnknownI2npType(0xff)));
    }

    #[test]
    fn header_serialize_too_short() {
        let h = I2npHeader {
            message_type: I2npMessageType::Data,
            msg_id: 1,
            expiration_ms: 0,
            size: 0,
            checksum: None,
        };
        let mut buf = [0u8; 15];
        let r = h.serialize(&mut buf);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 16,
                got: 15
            })
        );
    }

    // ---- expiration -----------------------------------------------------

    #[test]
    fn is_expired_false_when_fresh() {
        let h = I2npHeader::new(I2npMessageType::Data, 1, 0);
        let now = h.expiration_ms;
        assert!(!h.is_expired(now));
        assert!(!h.is_expired(now - 1));
        assert!(!h.is_expired(now - I2NP_MESSAGE_EXPIRATION_TIMEOUT_MS));
    }

    #[test]
    fn is_expired_true_when_past_timeout() {
        let h = I2npHeader::new(I2npMessageType::Data, 1, 0);
        // expiration + clock_skew + 1
        let now = h.expiration_ms + I2NP_MESSAGE_CLOCK_SKEW_MS + 1;
        assert!(h.is_expired(now));
    }

    #[test]
    fn is_expired_true_when_too_far_future() {
        let h = I2npHeader::new(I2npMessageType::Data, 1, 0);
        // expiration - 3*clock_skew - 1
        let now = h.expiration_ms - 3 * I2NP_MESSAGE_CLOCK_SKEW_MS - 1;
        assert!(h.is_expired(now));
    }

    #[test]
    fn is_expired_handles_underflow() {
        // expiration_ms близко к 0, now_ms=0 — не должно паниковать
        let h = I2npHeader {
            message_type: I2npMessageType::Data,
            msg_id: 0,
            expiration_ms: 100,
            size: 0,
            checksum: None,
        };
        assert!(!h.is_expired(0));
    }

    // ---- total_len ------------------------------------------------------

    #[test]
    fn total_len_is_header_plus_payload() {
        let h = I2npHeader {
            message_type: I2npMessageType::Data,
            msg_id: 0,
            expiration_ms: 0,
            size: 100,
            checksum: None,
        };
        assert_eq!(h.total_len(), 116);
    }

    // ---- new() ----------------------------------------------------------

    #[test]
    fn new_sets_expiration_in_future() {
        let h = I2npHeader::new(I2npMessageType::Garlic, 0x42, 10);
        assert_eq!(h.message_type, I2npMessageType::Garlic);
        assert_eq!(h.msg_id, 0x42);
        assert_eq!(h.size, 10);
        assert_eq!(h.checksum, None);
        // expiration должен быть в будущем относительно "сейчас"
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let now = u64::try_from(now_ms).expect("milliseconds since epoch fit in u64");
        assert!(h.expiration_ms > now);
    }
}
