#[cfg(test)]
mod tests {
    use uu_i2p::tunnel_build_record::*;
    use uu_i2p::{I2PError, IdentHash};

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    fn sample_request() -> ShortBuildRequestRecord {
        ShortBuildRequestRecord {
            receive_tunnel: 0x1122_3344,
            next_tunnel: 0x5566_7788,
            next_ident: ident(0xAB),
            is_gateway: true,
            is_endpoint: false,
            more_flags: [0, 0],
            layer_encryption_type: 0,
            request_time_minutes: 0x0102_0304,
            request_expiration_secs: DEFAULT_REQUEST_EXPIRATION_SECS,
            send_msg_id: 0xDEAD_BEEF,
            options: BuildOptions::new(),
        }
    }

    // ---- constants ------------------------------------------------------

    #[test]
    fn constants_are_consistent() {
        assert_eq!(SHORT_TUNNEL_BUILD_RECORD_SIZE, 218);
        assert_eq!(
            SHORT_TUNNEL_BUILD_RECORD_SIZE,
            BUILD_RECORD_TO_PEER_SIZE
                + SHORT_REQUEST_RECORD_EPHEMERAL_SIZE
                + SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE
        );
        assert_eq!(SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE, 154);
        assert_eq!(SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE, 170);
        assert_eq!(SHORT_RESPONSE_PLAINTEXT_SIZE, 202);
        assert_eq!(
            SHORT_RESPONSE_RECORD_RET_OFFSET + 1,
            SHORT_RESPONSE_PLAINTEXT_SIZE
        );
        assert_eq!(NUM_TUNNEL_BUILD_RECORDS, 8);
    }

    #[test]
    fn request_offsets_chain() {
        assert_eq!(SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET, 4);
        assert_eq!(SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, 8);
        assert_eq!(SHORT_REQUEST_RECORD_FLAG_OFFSET, 8 + 32);
        assert_eq!(SHORT_REQUEST_RECORD_MORE_FLAGS_OFFSET, 41);
        assert_eq!(SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE, 43);
        assert_eq!(SHORT_REQUEST_RECORD_REQUEST_TIME_OFFSET, 44);
        assert_eq!(SHORT_REQUEST_RECORD_REQUEST_EXPIRATION_OFFSET, 48);
        assert_eq!(SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET, 52);
        assert_eq!(SHORT_REQUEST_RECORD_TUNNEL_BUILD_OPTIONS_OFFSET, 56);
    }

    // ---- request clear text --------------------------------------------

    #[test]
    fn request_golden_bytes() {
        let buf = sample_request().to_clear_text().unwrap();
        assert_eq!(buf.len(), 154);
        assert_eq!(&buf[0..4], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&buf[4..8], &[0x55, 0x66, 0x77, 0x88]);
        assert_eq!(&buf[8..40], &[0xAB; 32]);
        assert_eq!(buf[40], 0x80); // gateway
        assert_eq!(&buf[41..43], &[0, 0]);
        assert_eq!(buf[43], 0);
        assert_eq!(&buf[44..48], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&buf[48..52], &[0x00, 0x00, 0x02, 0x58]); // 600
        assert_eq!(&buf[52..56], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&buf[56..58], &[0x00, 0x00]); // empty mapping
        assert!(buf[58..].iter().all(|&b| b == 0));
    }

    #[test]
    fn request_roundtrip() {
        let mut rec = sample_request();
        rec.is_endpoint = true;
        rec.more_flags = [0x12, 0x34];
        rec.layer_encryption_type = 7;
        rec.options.insert(OPTION_MINIMUM_BANDWIDTH, "64");
        rec.options.insert(OPTION_REQUESTED_BANDWIDTH, "512");
        let buf = rec.to_clear_text().unwrap();
        let back = ShortBuildRequestRecord::from_clear_text(&buf).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn flags_combinations() {
        for (gw, ep, byte) in [
            (false, false, 0x00),
            (true, false, 0x80),
            (false, true, 0x40),
            (true, true, 0xC0),
        ] {
            let mut rec = sample_request();
            rec.is_gateway = gw;
            rec.is_endpoint = ep;
            assert_eq!(rec.flags_byte(), byte);
            let buf = rec.to_clear_text().unwrap();
            let back = ShortBuildRequestRecord::from_clear_text(&buf).unwrap();
            assert_eq!(back.is_gateway, gw);
            assert_eq!(back.is_endpoint, ep);
        }
    }

    #[test]
    fn request_wrong_length() {
        for len in [0usize, 153, 155] {
            let r = ShortBuildRequestRecord::from_clear_text(&vec![0u8; len]);
            assert_eq!(
                r,
                Err(I2PError::InvalidLength {
                    expected: 154,
                    got: len
                })
            );
        }
    }

    #[test]
    fn request_options_bandwidth_values() {
        let mut rec = sample_request();
        rec.options.insert(OPTION_MINIMUM_BANDWIDTH, "100");
        let buf = rec.to_clear_text().unwrap();
        let back = ShortBuildRequestRecord::from_clear_text(&buf).unwrap();
        assert_eq!(back.options.get_u32(OPTION_MINIMUM_BANDWIDTH), Some(100));
        assert_eq!(back.options.get_u32(OPTION_REQUESTED_BANDWIDTH), None);
    }

    #[test]
    fn request_options_exact_capacity() {
        // область options: 154 - 56 = 98 байт, включая 2 байта размера.
        let mut rec = sample_request();
        rec.options.insert("k", &"v".repeat(91)); // 2 + (1+1+1+1+91+1) = 98
        assert_eq!(rec.options.wire_size(), 98);
        let buf = rec.to_clear_text().unwrap();
        let back = ShortBuildRequestRecord::from_clear_text(&buf).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn request_options_overflow_is_error() {
        let mut rec = sample_request();
        rec.options.insert("k", &"v".repeat(92)); // 99 байт
        assert!(matches!(rec.to_clear_text(), Err(I2PError::Malformed(_))));
    }

    // ---- response plaintext ---------------------------------------------

    #[test]
    fn response_golden_with_bandwidth() {
        let mut options = BuildOptions::new();
        options.insert(OPTION_AVAILABLE_BANDWIDTH, "1000");
        let rec = ShortBuildResponseRecord {
            options,
            ret: BuildRetCode::Accept,
        };
        let buf = rec.to_plaintext().unwrap();
        assert_eq!(buf.len(), 202);
        // size=9 | 01 'b' '=' 04 "1000" ';'
        assert_eq!(
            &buf[..11],
            &[
                0x00, 0x09, 0x01, b'b', b'=', 0x04, b'1', b'0', b'0', b'0', b';'
            ]
        );
        assert!(buf[11..201].iter().all(|&b| b == 0));
        assert_eq!(buf[201], 0);
    }

    #[test]
    fn response_roundtrip_reject() {
        let rec = ShortBuildResponseRecord {
            options: BuildOptions::new(),
            ret: BuildRetCode::Bandwidth,
        };
        let buf = rec.to_plaintext().unwrap();
        assert_eq!(buf[201], 30);
        let back = ShortBuildResponseRecord::from_plaintext(&buf).unwrap();
        assert_eq!(back, rec);
        assert!(!back.ret.is_accept());
    }

    #[test]
    fn response_wrong_length() {
        let r = ShortBuildResponseRecord::from_plaintext(&[0u8; 218]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 202,
                got: 218
            })
        );
    }

    #[test]
    fn response_options_cannot_overwrite_ret() {
        let mut options = BuildOptions::new();
        options.insert("k", &"v".repeat(200)); // не влезает в 201 байт
        let rec = ShortBuildResponseRecord {
            options,
            ret: BuildRetCode::Accept,
        };
        assert!(matches!(rec.to_plaintext(), Err(I2PError::Malformed(_))));
    }

    #[test]
    fn ret_code_mapping() {
        assert_eq!(BuildRetCode::from_u8(0), BuildRetCode::Accept);
        assert_eq!(BuildRetCode::from_u8(30), BuildRetCode::Bandwidth);
        assert_eq!(BuildRetCode::from_u8(50), BuildRetCode::Other(50));
        for v in 0..=255u8 {
            assert_eq!(BuildRetCode::from_u8(v).to_u8(), v);
        }
        assert!(BuildRetCode::Accept.is_accept());
        assert!(!BuildRetCode::Other(1).is_accept());
    }

    // ---- BuildOptions parsing -------------------------------------------

    #[test]
    fn options_parse_ignores_trailing_padding() {
        let buf = [0x00, 0x06, 0x01, b'a', b'=', 0x01, b'b', b';', 0, 0, 0, 0];
        // size=6: 01 a = 01 b ;
        let o = BuildOptions::parse(&buf).unwrap();
        assert_eq!(o.get("a"), Some("b"));
        assert_eq!(o.len(), 1);
    }

    #[test]
    fn options_parse_errors() {
        // нет префикса
        assert!(matches!(
            BuildOptions::parse(&[0]),
            Err(I2PError::InvalidLength { .. })
        ));
        // размер больше буфера
        assert!(matches!(
            BuildOptions::parse(&[0x00, 0x05, 0x00]),
            Err(I2PError::Malformed(_))
        ));
        // нет '='
        assert!(matches!(
            BuildOptions::parse(&[0x00, 0x06, 0x01, b'a', b'-', 0x01, b'b', b';']),
            Err(I2PError::Malformed(_))
        ));
        // нет ';'
        assert!(matches!(
            BuildOptions::parse(&[0x00, 0x06, 0x01, b'a', b'=', 0x01, b'b', b'x']),
            Err(I2PError::Malformed(_))
        ));
        // обрезанная строка
        assert!(matches!(
            BuildOptions::parse(&[0x00, 0x03, 0x05, b'a', b'b']),
            Err(I2PError::Malformed(_))
        ));
        // дубликат ключа
        let dup = [
            0x00, 0x0C, 0x01, b'a', b'=', 0x01, b'1', b';', 0x01, b'a', b'=', 0x01, b'2', b';',
        ];
        assert!(matches!(
            BuildOptions::parse(&dup),
            Err(I2PError::Malformed(_))
        ));
        // не UTF-8
        assert!(matches!(
            BuildOptions::parse(&[0x00, 0x06, 0x01, 0xFF, b'=', 0x01, b'b', b';']),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn options_write_sorted_by_key() {
        let mut o = BuildOptions::new();
        o.insert("r", "2");
        o.insert("m", "1");
        let mut buf = [0u8; 32];
        let n = o.write_into(&mut buf).unwrap();
        assert_eq!(n, o.wire_size());
        assert_eq!(buf[3], b'm'); // 'm' < 'r', как в std::map
    }

    #[test]
    fn options_string_longer_than_255_rejected() {
        let mut o = BuildOptions::new();
        o.insert("k", &"v".repeat(256));
        let mut buf = [0u8; 400];
        assert!(matches!(
            o.write_into(&mut buf),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn options_insert_replaces() {
        let mut o = BuildOptions::new();
        o.insert("a", "1");
        o.insert("a", "2");
        assert_eq!(o.len(), 1);
        assert_eq!(o.get("a"), Some("2"));
        assert!(!o.is_empty());
    }

    // ---- encrypted record -----------------------------------------------

    #[test]
    fn encrypted_record_layout() {
        let mut raw = [0u8; 218];
        raw[..16].fill(0x01);
        raw[16..48].fill(0x02);
        raw[48..].fill(0x03);
        let rec = EncryptedShortRecord::from_bytes(&raw).unwrap();
        assert_eq!(rec.to_peer, [0x01; 16]);
        assert_eq!(rec.ephemeral_key, [0x02; 32]);
        assert_eq!(rec.ciphertext, [0x03; 170]);
        assert_eq!(rec.to_bytes(), raw);
    }

    #[test]
    fn encrypted_record_wrong_length() {
        let r = EncryptedShortRecord::from_bytes(&[0u8; 217]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 218,
                got: 217
            })
        );
    }

    #[test]
    fn encrypted_record_is_for() {
        let id = ident(0x42);
        let rec = EncryptedShortRecord {
            to_peer: [0x42; 16],
            ephemeral_key: [0; 32],
            ciphertext: [0; 170],
        };
        assert!(rec.is_for(&id));
        assert!(!rec.is_for(&ident(0x43)));
    }
}
