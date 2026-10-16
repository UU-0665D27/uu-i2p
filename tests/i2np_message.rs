#[cfg(test)]
mod tests {
    use uu_i2p::{
        DatabaseLookup, I2PHash, I2npBody, I2npHeader, I2npMessage, I2npMessageType, IdentHash,
        database_lookup::LookupType,
        database_search_reply::DatabaseSearchReply,
        database_store::{DatabaseStore, ReplyInstruction, StoreType},
        delivery_status::DeliveryStatus,
        endian::{read_u16_be, write_u16_be},
        error::I2PError,
        i2np::I2NP_HEADER_SIZE,
    };

    fn sample_payload(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from(i & 0xff).expect("fits"))
            .collect()
    }

    // ---- construction --------------------------------------------------

    #[test]
    fn new_sets_header_fields() {
        let payload = b"hello".to_vec();
        let msg = I2npMessage::new(I2npMessageType::Data, payload.clone());
        assert_eq!(msg.message_type(), I2npMessageType::Data);
        assert_eq!(msg.payload(), &payload[..]);
        assert_eq!(msg.header().size, 5);
        assert!(msg.header().checksum.is_none());
        // expiration в будущем
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        assert!(msg.expiration_ms() > u64::try_from(now_ms).unwrap());
    }

    #[test]
    fn new_random_msg_id() {
        let a = I2npMessage::new(I2npMessageType::Data, vec![]);
        let b = I2npMessage::new(I2npMessageType::Data, vec![]);
        // 2^32 msg_id space, коллизия крайне маловероятна
        assert_ne!(a.msg_id(), b.msg_id());
    }

    // ---- round-trip ----------------------------------------------------

    #[test]
    fn roundtrip_no_checksum() {
        let payload = sample_payload(100);
        let msg = I2npMessage::new(I2npMessageType::DatabaseStore, payload);
        let buf = msg.to_buffer().unwrap();
        assert_eq!(buf.len(), I2NP_HEADER_SIZE + 100);

        let back = I2npMessage::from_buffer(&buf).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn roundtrip_with_checksum() {
        let payload = sample_payload(50);
        let mut msg = I2npMessage::new(I2npMessageType::Garlic, payload);
        msg.enable_checksum();
        assert!(msg.header().checksum.is_some());

        let buf = msg.to_buffer().unwrap();
        let back = I2npMessage::from_buffer(&buf).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let msg = I2npMessage::new(I2npMessageType::DeliveryStatus, vec![]);
        let buf = msg.to_buffer().unwrap();
        assert_eq!(buf.len(), I2NP_HEADER_SIZE);
        let back = I2npMessage::from_buffer(&buf).unwrap();
        assert_eq!(back, msg);
        assert_eq!(back.payload().len(), 0);
    }

    #[test]
    fn roundtrip_max_payload() {
        // payload ровно u16::MAX байт (максимум по формату)
        let payload = sample_payload(usize::from(u16::MAX));
        let msg = I2npMessage::with_header(
            I2npHeader {
                message_type: I2npMessageType::TunnelData,
                msg_id: 0,
                expiration_ms: 0,
                size: u16::MAX,
                checksum: None,
            },
            payload.clone(),
        );
        let buf = msg.to_buffer().unwrap();
        let back = I2npMessage::from_buffer(&buf).unwrap();
        assert_eq!(back.payload().len(), payload.len());
    }

    #[test]
    fn trailing_bytes_ignored() {
        let msg = I2npMessage::new(I2npMessageType::Data, b"payload".to_vec());
        let mut buf = msg.to_buffer().unwrap();
        buf.extend_from_slice(b"--- trailing garbage ---");
        let back = I2npMessage::from_buffer(&buf).unwrap();
        assert_eq!(back, msg);
    }

    // ---- checksum ------------------------------------------------------

    #[test]
    fn checksum_value_is_first_byte_of_sha256() {
        let payload = b"test";
        let msg = I2npMessage::new(I2npMessageType::Data, payload.to_vec());
        let expected = I2PHash::of(payload).as_bytes()[0];
        let mut msg = msg;
        msg.enable_checksum();
        assert_eq!(msg.header().checksum, Some(expected));
    }

    #[test]
    fn checksum_mismatch_fails_on_parse() {
        let payload = b"data".to_vec();
        let mut msg = I2npMessage::new(I2npMessageType::Data, payload);
        msg.enable_checksum();
        let mut buf = msg.to_buffer().unwrap();
        // Портим payload — checksum не сойдётся
        buf[I2NP_HEADER_SIZE] ^= 0xFF;
        let r = I2npMessage::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn no_checksum_means_no_validation() {
        let mut msg = I2npMessage::new(I2npMessageType::Data, b"data".to_vec());
        msg.disable_checksum();
        let mut buf = msg.to_buffer().unwrap();
        // Портим payload — теперь проверки нет, всё парсится
        buf[I2NP_HEADER_SIZE] ^= 0xFF;
        let back = I2npMessage::from_buffer(&buf).unwrap();
        assert_ne!(back.payload(), &b"data"[..]);
    }

    // ---- errors -------------------------------------------------------

    #[test]
    fn empty_buffer_invalid() {
        let r = I2npMessage::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn short_header_invalid() {
        let r = I2npMessage::from_buffer(&[0u8; 15]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn declared_size_exceeds_buffer() {
        let mut buf = [0u8; I2NP_HEADER_SIZE];
        // typeID = Data
        buf[0] = I2npMessageType::Data.as_u8();
        // size = 100, но payload пустой
        write_u16_be(&mut buf[13..], 100);
        let r = I2npMessage::from_buffer(&buf);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: I2NP_HEADER_SIZE + 100,
                got: I2NP_HEADER_SIZE,
            })
        );
    }

    // ---- accessors -----------------------------------------------------

    #[test]
    fn accessors_match_header() {
        let msg = I2npMessage::new(I2npMessageType::TunnelGateway, b"x".to_vec());
        assert_eq!(msg.message_type(), msg.header().message_type);
        assert_eq!(msg.msg_id(), msg.header().msg_id);
        assert_eq!(msg.expiration_ms(), msg.header().expiration_ms);
    }

    #[test]
    fn total_len_is_header_plus_payload() {
        let msg = I2npMessage::new(I2npMessageType::Data, vec![0u8; 100]);
        assert_eq!(msg.total_len(), I2NP_HEADER_SIZE + 100);
    }

    #[test]
    fn is_expired_uses_header() {
        let header = I2npHeader {
            message_type: I2npMessageType::Data,
            msg_id: 0,
            expiration_ms: 1000,
            size: 0,
            checksum: None,
        };
        let msg = I2npMessage::with_header(header, vec![]);
        assert!(!msg.is_expired(500));
        // истёк после expiration + clock skew (60 сек)
        assert!(msg.is_expired(1000 + 60_000 + 1));
    }

    // ---- to_buffer syncs size ------------------------------------------

    #[test]
    fn to_buffer_overrides_header_size() {
        // Искусственно рассинхронизируем size и payload.
        let header = I2npHeader {
            message_type: I2npMessageType::Data,
            msg_id: 1,
            expiration_ms: 0,
            size: 999, // наврали
            checksum: None,
        };
        let msg = I2npMessage::with_header(header, vec![0u8; 10]);
        let buf = msg.to_buffer().unwrap();
        // В wire должен быть записан правильный size = 10
        assert_eq!(read_u16_be(&buf[13..]), 10);
    }

    #[test]
    fn from_buffer_reads_size_from_wire() {
        let payload = sample_payload(42);
        let msg = I2npMessage::new(I2npMessageType::Data, payload);
        let buf = msg.to_buffer().unwrap();
        let back = I2npMessage::from_buffer(&buf).unwrap();
        assert_eq!(back.header().size, 42);
    }
    // ---- I2npBody ------------------------------------------------------

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    #[test]
    fn body_database_store_roundtrip() {
        // Через I2npBody
        let ri_bytes = vec![0xAB_u8; 100];
        let ds = DatabaseStore::new_router_info(ident(0x11), &ri_bytes, 0, None).unwrap();
        let body = I2npBody::DatabaseStore(ds.clone());
        assert_eq!(body.message_type(), I2npMessageType::DatabaseStore);

        // Оборачиваем в I2NP и обратно
        let msg = I2npMessage::from_body(body).unwrap();
        let parsed = msg.parse_body().unwrap();
        assert_eq!(parsed, I2npBody::DatabaseStore(ds));
    }

    #[test]
    fn body_database_lookup_roundtrip() {
        let dl = DatabaseLookup::new_router_info(ident(1), ident(2), Some(42), vec![ident(3)]);
        let body = I2npBody::DatabaseLookup(dl.clone());
        assert_eq!(body.message_type(), I2npMessageType::DatabaseLookup);

        let msg = I2npMessage::from_body(body).unwrap();
        let parsed = msg.parse_body().unwrap();
        assert_eq!(parsed, I2npBody::DatabaseLookup(dl));
    }

    #[test]
    fn body_raw_preserves_unknown_type() {
        // TunnelData (type 18) — нет typed-парсера
        let payload = vec![0x01_u8, 0x02, 0x03];
        let msg = I2npMessage::new(I2npMessageType::TunnelData, payload.clone());
        let body = msg.parse_body().unwrap();
        match body {
            I2npBody::Raw {
                type_id,
                payload: p,
            } => {
                assert_eq!(type_id, I2npMessageType::TunnelData);
                assert_eq!(p, payload);
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn body_raw_roundtrip() {
        let payload = vec![0xAA_u8; 50];
        let body = I2npBody::Raw {
            type_id: I2npMessageType::TunnelBuild,
            payload: payload.clone(),
        };
        let msg = I2npMessage::from_body(body.clone()).unwrap();
        assert_eq!(msg.message_type(), I2npMessageType::TunnelBuild);
        assert_eq!(msg.payload(), &payload[..]);

        let back = msg.parse_body().unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn parse_body_database_store_malformed_fails() {
        // DatabaseStore требует минимум DATABASE_STORE_HEADER_SIZE
        // байт payload'а
        let msg = I2npMessage::new(I2npMessageType::DatabaseStore, vec![0u8; 10]);
        assert!(msg.parse_body().is_err());
    }

    #[test]
    fn parse_body_database_lookup_malformed_fails() {
        let msg = I2npMessage::new(I2npMessageType::DatabaseLookup, vec![0u8; 10]);
        assert!(msg.parse_body().is_err());
    }

    #[test]
    fn body_message_type_for_all_variants() {
        let ds = DatabaseStore::new_lease_set(ident(1), vec![0xAA; 10]);
        let dl = DatabaseLookup::new_router_info(ident(1), ident(2), None, vec![]);
        assert_eq!(
            I2npBody::DatabaseStore(ds).message_type(),
            I2npMessageType::DatabaseStore
        );
        assert_eq!(
            I2npBody::DatabaseLookup(dl).message_type(),
            I2npMessageType::DatabaseLookup
        );
        assert_eq!(
            I2npBody::Raw {
                type_id: I2npMessageType::DeliveryStatus,
                payload: vec![]
            }
            .message_type(),
            I2npMessageType::DeliveryStatus
        );
    }

    #[test]
    fn body_lookup_type_field_survives_roundtrip() {
        let dl = DatabaseLookup::new_exploratory(ident(1), ident(2), None, vec![]);
        let body = I2npBody::DatabaseLookup(dl);
        let wire = I2npMessage::from_body(body).unwrap().to_buffer().unwrap();
        let msg = I2npMessage::from_buffer(&wire).unwrap();
        match msg.parse_body().unwrap() {
            I2npBody::DatabaseLookup(b) => {
                assert_eq!(b.lookup_type, LookupType::Exploratory);
            }
            other => panic!("expected DatabaseLookup, got {other:?}"),
        }
    }

    #[test]
    fn body_store_type_field_survives_roundtrip() {
        let ds = DatabaseStore::new_lease_set2(ident(1), vec![0xBB; 20]);
        let body = I2npBody::DatabaseStore(ds);
        let wire = I2npMessage::from_body(body).unwrap().to_buffer().unwrap();
        let msg = I2npMessage::from_buffer(&wire).unwrap();
        match msg.parse_body().unwrap() {
            I2npBody::DatabaseStore(b) => {
                assert_eq!(b.store_type, StoreType::LeaseSet2);
            }
            other => panic!("expected DatabaseStore, got {other:?}"),
        }
    }

    #[test]
    fn body_full_pipeline_preserves_byte_identical_payload() {
        // Проверяем, что полный цикл
        //   body -> I2NP -> wire -> I2NP -> body
        // не портит payload. Это критично: любой I2NP-диспатчер,
        // который потом будет обрабатывать сообщения, не должен
        // незаметно портить данные.
        let original = DatabaseLookup::new_router_info(
            ident(1),
            ident(2),
            Some(0xDEAD),
            vec![ident(3), ident(4)],
        );
        let body1 = I2npBody::DatabaseLookup(original.clone());

        // body -> I2NP -> wire
        let msg1 = I2npMessage::from_body(body1.clone()).unwrap();
        let wire = msg1.to_buffer().unwrap();

        // wire -> I2NP -> body
        let msg2 = I2npMessage::from_buffer(&wire).unwrap();
        let body2 = msg2.parse_body().unwrap();

        assert_eq!(body1, body2);
        if let I2npBody::DatabaseLookup(b) = body2 {
            assert_eq!(b, original);
        }
    }
    #[test]
    fn body_database_search_reply_roundtrip() {
        let r = DatabaseSearchReply::with_from(
            ident(0xAA),
            vec![ident(0x11), ident(0x22)],
            ident(0xBB),
        );
        let body = I2npBody::DatabaseSearchReply(r.clone());
        assert_eq!(body.message_type(), I2npMessageType::DatabaseSearchReply);

        let msg = I2npMessage::from_body(body).unwrap();
        let parsed = msg.parse_body().unwrap();
        assert_eq!(parsed, I2npBody::DatabaseSearchReply(r));
    }

    #[test]
    fn parse_body_database_search_reply_malformed_fails() {
        let msg = I2npMessage::new(I2npMessageType::DatabaseSearchReply, vec![0u8; 10]);
        assert!(msg.parse_body().is_err());
    }
    #[test]
    fn body_delivery_status_roundtrip() {
        let ds = DeliveryStatus::new(0xDEAD_BEEF, 1_700_000_000_000);
        let body = I2npBody::DeliveryStatus(ds);
        assert_eq!(body.message_type(), I2npMessageType::DeliveryStatus);

        let msg = I2npMessage::from_body(body).unwrap();
        let parsed = msg.parse_body().unwrap();
        assert_eq!(parsed, I2npBody::DeliveryStatus(ds));
    }

    #[test]
    fn parse_body_delivery_status_malformed_fails() {
        let msg = I2npMessage::new(I2npMessageType::DeliveryStatus, vec![0u8; 5]);
        assert!(msg.parse_body().is_err());
    }

    /// Мини-сценарий публикации: собрали `DatabaseStore` с `reply_token`,
    /// отправили, получили `DeliveryStatus` — `msg_id` совпадает.
    #[test]
    fn publish_then_delivery_status_scenario() {
        // 1. Собираем DatabaseStore с reply_token и reply_instruction.
        // reply_token != 0 требует reply_instruction — это правило
        // формата, не наша выдумка.
        let reply_token = 0xCAFE_BABE;
        let reply_instr = ReplyInstruction {
            tunnel_id: 0xDEAD_BEEF,
            gateway: ident(0x22),
        };
        let ds =
            DatabaseStore::new_router_info(ident(0x11), b"fake RI", reply_token, Some(reply_instr))
                .unwrap();
        let msg = I2npMessage::from_body(I2npBody::DatabaseStore(ds)).unwrap();
        // I2NP msg_id — свой, не связан с reply_token (это разные вещи)
        assert_ne!(msg.msg_id(), reply_token, "I2NP msg_id != reply_token");

        // 2. Получатель шлёт DeliveryStatus с нашим reply_token
        let status = DeliveryStatus::now(reply_token);
        let status_msg = I2npMessage::from_body(I2npBody::DeliveryStatus(status)).unwrap();

        // 3. Мы получаем — распаковываем и проверяем, что msg_id наш
        let wire = status_msg.to_buffer().unwrap();
        let received = I2npMessage::from_buffer(&wire).unwrap();
        match received.parse_body().unwrap() {
            I2npBody::DeliveryStatus(s) => assert_eq!(s.msg_id, reply_token),
            other => panic!("expected DeliveryStatus, got {other:?}"),
        }
    }

    // ---- NTCP2 short header ---------------------------------------------

    #[test]
    fn to_ntcp2_bytes_layout() {
        let header = I2npHeader {
            message_type: I2npMessageType::Data,
            msg_id: 0x1122_3344,
            expiration_ms: 1_700_000_000_000,
            size: 3,
            checksum: Some(0xAA),
        };
        let msg = I2npMessage::with_header(header, vec![1, 2, 3]);
        let buf = msg.to_ntcp2_bytes();

        // typeid + msgid + expiration(secs) + payload = 9 + 3.
        assert_eq!(buf.len(), 12);
        assert_eq!(buf[0], I2npMessageType::Data.as_u8());
        assert_eq!(&buf[1..5], &[0x11, 0x22, 0x33, 0x44]);
        // 1_700_000_000 in BE u32.
        assert_eq!(&buf[5..9], &1_700_000_000u32.to_be_bytes());
        assert_eq!(&buf[9..], &[1, 2, 3]);
    }

    #[test]
    fn ntcp2_bytes_roundtrip() {
        let header = I2npHeader {
            message_type: I2npMessageType::Garlic,
            msg_id: 42,
            expiration_ms: 1_700_000_000_000,
            size: 5,
            checksum: None,
        };
        let msg = I2npMessage::with_header(header, vec![0xAA; 5]);

        let bytes = msg.to_ntcp2_bytes();
        let back = I2npMessage::from_ntcp2_bytes(&bytes).unwrap();

        // expiration округлилось до секунд — точное значение 1_700_000_000_000.
        assert_eq!(back.header().message_type, I2npMessageType::Garlic);
        assert_eq!(back.msg_id(), 42);
        assert_eq!(back.expiration_ms(), 1_700_000_000_000);
        assert_eq!(back.payload(), &[0xAA; 5]);
        // Checksum в коротком формате отсутствует.
        assert_eq!(back.header().checksum, None);
    }

    #[test]
    fn ntcp2_bytes_sub_second_expiration_truncated() {
        let header = I2npHeader {
            message_type: I2npMessageType::Data,
            msg_id: 1,
            expiration_ms: 1_700_000_000_999,
            size: 0,
            checksum: None,
        };
        let msg = I2npMessage::with_header(header, vec![]);
        let back = I2npMessage::from_ntcp2_bytes(&msg.to_ntcp2_bytes()).unwrap();
        assert_eq!(back.expiration_ms(), 1_700_000_000_000);
    }

    #[test]
    fn from_ntcp2_bytes_too_short() {
        let r = I2npMessage::from_ntcp2_bytes(&[0u8; 8]);
        assert!(matches!(
            r,
            Err(I2PError::InvalidLength {
                expected: 9,
                got: 8
            })
        ));
    }

    #[test]
    fn from_ntcp2_bytes_unknown_type() {
        let mut buf = [0u8; 9];
        buf[0] = 0xFF;
        let r = I2npMessage::from_ntcp2_bytes(&buf);
        assert_eq!(r, Err(I2PError::UnknownI2npType(0xFF)));
    }
}
