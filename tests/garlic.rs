#[cfg(test)]
mod tests {
    use uu_i2p::{
        Delivery, GarlicClove, I2PError, IdentHash, i2np::I2npMessageType,
        i2np_message::I2npMessage, parse_garlic_payload, serialize_garlic_payload,
    };

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    fn make_msg(type_id: I2npMessageType, payload: &[u8]) -> I2npMessage {
        I2npMessage::new(type_id, payload.to_vec())
    }

    // ---- Delivery -----------------------------------------------------

    #[test]
    fn delivery_flags_match_spec() {
        assert_eq!(Delivery::Local.flag(), 0x00);
        assert_eq!(Delivery::Destination(ident(1)).flag(), 0x20);
        assert_eq!(
            Delivery::Tunnel {
                gateway: ident(1),
                tunnel_id: 0
            }
            .flag(),
            0x40
        );
        assert_eq!(Delivery::Router(ident(1)).flag(), 0x60);
    }

    #[test]
    fn delivery_suffix_len() {
        assert_eq!(Delivery::Local.suffix_len(), 0);
        assert_eq!(Delivery::Destination(ident(1)).suffix_len(), 32);
        assert_eq!(Delivery::Router(ident(1)).suffix_len(), 32);
        assert_eq!(
            Delivery::Tunnel {
                gateway: ident(1),
                tunnel_id: 0
            }
            .suffix_len(),
            36
        );
    }

    // ---- round-trips --------------------------------------------------

    fn roundtrip_clove(clove: &GarlicClove) {
        let bytes = clove.to_buffer().unwrap();
        let (parsed, consumed) = GarlicClove::from_buffer(&bytes).unwrap();
        assert_eq!(consumed, bytes.len(), "must consume whole buffer");
        assert_eq!(&parsed, clove);
    }

    #[test]
    fn roundtrip_local_delivery() {
        let msg = make_msg(I2npMessageType::DeliveryStatus, b"x");
        roundtrip_clove(&GarlicClove::new(
            Delivery::Local,
            msg,
            0xDEAD_BEEF,
            1_700_000_000_000,
        ));
    }

    #[test]
    fn roundtrip_destination_delivery() {
        let msg = make_msg(I2npMessageType::Data, b"hi");
        roundtrip_clove(&GarlicClove::new(
            Delivery::Destination(ident(0x11)),
            msg,
            1,
            2,
        ));
    }

    #[test]
    fn roundtrip_tunnel_delivery() {
        let msg = make_msg(I2npMessageType::DatabaseStore, b"");
        roundtrip_clove(&GarlicClove::new(
            Delivery::Tunnel {
                gateway: ident(0x22),
                tunnel_id: 0xCAFE_BABE,
            },
            msg,
            42,
            100_000,
        ));
    }

    #[test]
    fn roundtrip_router_delivery() {
        let msg = make_msg(I2npMessageType::Garlic, b"nested");
        roundtrip_clove(&GarlicClove::new(Delivery::Router(ident(0x33)), msg, 7, 8));
    }

    #[test]
    fn payload_roundtrip_multiple_cloves() {
        let cloves = vec![
            GarlicClove::new(
                Delivery::Local,
                make_msg(I2npMessageType::DeliveryStatus, b"a"),
                1,
                100,
            ),
            GarlicClove::new(
                Delivery::Destination(ident(0x11)),
                make_msg(I2npMessageType::Data, b"bb"),
                2,
                200,
            ),
            GarlicClove::new(
                Delivery::Tunnel {
                    gateway: ident(0x22),
                    tunnel_id: 5,
                },
                make_msg(I2npMessageType::DatabaseLookup, b"ccc"),
                3,
                300,
            ),
        ];
        let wire = serialize_garlic_payload(&cloves).unwrap();
        let parsed = parse_garlic_payload(&wire).unwrap();
        assert_eq!(parsed, cloves);
    }

    #[test]
    fn payload_empty() {
        let wire = serialize_garlic_payload(&[]).unwrap();
        assert_eq!(wire, [0u8]);
        let parsed = parse_garlic_payload(&wire).unwrap();
        assert!(parsed.is_empty(), "expected no cloves");
    }

    #[test]
    fn payload_255_cloves_max() {
        let cloves: Vec<GarlicClove> = (0..255)
            .map(|i| {
                GarlicClove::new(
                    Delivery::Local,
                    make_msg(I2npMessageType::DeliveryStatus, &[i]),
                    u32::from(i),
                    u64::from(i) * 1000,
                )
            })
            .collect();
        let wire = serialize_garlic_payload(&cloves).unwrap();
        let parsed = parse_garlic_payload(&wire).unwrap();
        assert_eq!(parsed.len(), 255);
    }

    // ---- errors -------------------------------------------------------

    #[test]
    fn parse_empty_payload_fails() {
        let r = parse_garlic_payload(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn parse_clove_empty_fails() {
        let r = GarlicClove::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn encrypted_clove_bit_is_unsupported() {
        let mut buf = vec![0x80]; // bit 7 set
        buf.extend_from_slice(&[0u8; 100]);
        let r = GarlicClove::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::Unsupported(_))));
    }

    #[test]
    fn truncated_destination_delivery_fails() {
        let mut buf = vec![0x20]; // delivery=destination
        buf.extend_from_slice(&[0u8; 16]); // только 16 из 32
        let r = GarlicClove::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn truncated_tunnel_delivery_fails() {
        let mut buf = vec![0x40]; // delivery=tunnel
        buf.extend_from_slice(&[0u8; 20]); // только 20 из 36
        let r = GarlicClove::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn too_many_cloves_fails() {
        let cloves = vec![
            GarlicClove::new(
                Delivery::Local,
                make_msg(I2npMessageType::DeliveryStatus, b""),
                0,
                0,
            );
            256
        ];
        let r = serialize_garlic_payload(&cloves);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    // ---- parse_bytes golden --------------------------------------------

    #[test]
    fn local_clove_golden_bytes() {
        // Собираем вручную по формату:
        // flag=0x00 | msg(I2NP DeliveryStatus 12 байт) | clove_id(4) | exp(8) | cert(3)
        let msg = make_msg(I2npMessageType::DeliveryStatus, &[0u8; 12]);
        let clove = GarlicClove::new(Delivery::Local, msg, 0xAABB_CCDD, 1);
        let bytes = clove.to_buffer().unwrap();
        // flag(1) + I2NP(16 header + 12 payload = 28) + 4 + 8 + 3 = 44
        assert_eq!(bytes.len(), 44);
        assert_eq!(bytes[0], 0x00); // flag Local
        // CloveID и expiration ищем с конца:
        let n = bytes.len();
        assert_eq!(&bytes[n - 15..n - 11], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&bytes[n - 11..n - 3], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&bytes[n - 3..], &[0, 0, 0]);
    }

    #[test]
    fn parse_bytes_from_i2pd_layout() {
        // i2pd пишет: flag | [delivery suffix] | I2NP | clove_id(4) | exp(8) | cert(3)
        // Мы прочитаем в обратном порядке и получим всё.
        let mut buf = Vec::new();
        buf.push(0x20); // destination
        buf.extend_from_slice(&[0x11u8; 32]); // ident
        // I2NP: typeID=Data(20), msgID, expiration, size
        let inner = make_msg(I2npMessageType::Data, b"hello");
        buf.extend_from_slice(&inner.to_buffer().unwrap());
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // clove_id
        buf.extend_from_slice(&[0u8; 8]); // expiration
        buf.extend_from_slice(&[0u8, 0u8, 0u8]); // cert

        let (clove, consumed) = GarlicClove::from_buffer(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(clove.delivery, Delivery::Destination(ident(0x11)));
        assert_eq!(clove.message.message_type(), I2npMessageType::Data);
        assert_eq!(clove.message.payload(), b"hello");
        assert_eq!(clove.clove_id, 0xDEAD_BEEF);
        assert_eq!(clove.expiration_ms, 0);
        assert_eq!(clove.certificate, [0, 0, 0]);
    }
}
