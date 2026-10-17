#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use uu_i2p::{
        error::I2PError,
        ssu2_block::{
            AddressBlock, Blocks, DateTimeBlock, FirstFragmentBlock, FirstPacketNumberBlock,
            FollowOnFragmentBlock, I2npBlock, NewTokenBlock, OptionsBlock, PaddingBlock,
            PathChallengeBlock, PathResponseBlock, PeerTestBlock, RawBlock, RelayIntroBlock,
            RelayRequestBlock, RelayResponseBlock, RelayTagBlock, RelayTagRequestBlock,
            RouterInfoBlock, SSU2_BLOCK_HEADER_SIZE, SSU2_ROUTER_INFO_FLAG_FLOOD,
            SSU2_ROUTER_INFO_FLAG_GZIP, Ssu2Block, Ssu2BlockType, Ssu2PeerTestCode,
            Ssu2RelayResponseCode, Ssu2TerminationReason, TerminationBlock, follow_on_frag_byte,
            write_block, write_raw_block,
        },
    };

    // ---- hex helper -----------------------------------------------------

    const fn hex_digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2, "hex string length mismatch");
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = (hex_digit(s.as_bytes()[2 * i]) << 4) | hex_digit(s.as_bytes()[2 * i + 1]);
        }
        out
    }

    /// Собирает блок как сырые байты (для удобства в тестах).
    fn framed(block_type: Ssu2BlockType, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_block(&mut out, block_type, body).unwrap();
        out
    }

    // ---- типы блоков ----------------------------------------------------

    #[test]
    fn block_type_values() {
        assert_eq!(Ssu2BlockType::DateTime.as_u8(), 0);
        assert_eq!(Ssu2BlockType::I2npMessage.as_u8(), 3);
        assert_eq!(Ssu2BlockType::Termination.as_u8(), 6);
        assert_eq!(Ssu2BlockType::Ack.as_u8(), 12);
        assert_eq!(Ssu2BlockType::Address.as_u8(), 13);
        assert_eq!(Ssu2BlockType::RelayTagRequest.as_u8(), 15);
        assert_eq!(Ssu2BlockType::Congestion.as_u8(), 21);
        assert_eq!(Ssu2BlockType::Padding.as_u8(), 254);
    }

    #[test]
    fn block_type_roundtrip_registered() {
        let registered = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 254,
        ];
        for v in registered {
            let t = Ssu2BlockType::from_u8(v).expect("registered type");
            assert_eq!(t.as_u8(), v);
        }
    }

    #[test]
    fn block_type_unknown_is_none() {
        for v in [14u8, 22, 100, 223, 253, 255] {
            assert!(Ssu2BlockType::from_u8(v).is_none(), "type {v}");
        }
    }

    #[test]
    fn block_type_names_unique() {
        let registered = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 254,
        ];
        let mut seen = std::collections::HashSet::new();
        for v in registered {
            let t = Ssu2BlockType::from_u8(v).unwrap();
            assert!(seen.insert(t.name()), "duplicate name {}", t.name());
            assert_eq!(format!("{t}"), t.name());
        }
    }

    // ---- фрейминг -------------------------------------------------------

    #[test]
    fn write_block_layout_golden() {
        let mut out = Vec::new();
        write_block(&mut out, Ssu2BlockType::DateTime, &[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(out, hex::<7>("00000401020304"));
    }

    #[test]
    fn write_block_rejects_oversized_body() {
        let mut out = Vec::new();
        let big = vec![0u8; 0x1_0000];
        assert!(matches!(
            write_block(&mut out, Ssu2BlockType::Padding, &big),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn blocks_empty_payload() {
        let mut it = Blocks::new(&[]);
        assert!(it.next().is_none());
    }

    #[test]
    fn blocks_iterate_several() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&framed(Ssu2BlockType::DateTime, &[0xAA, 0xBB, 0xCC, 0xDD]));
        payload.extend_from_slice(&framed(Ssu2BlockType::Padding, &[0, 0, 0]));

        let collected: Vec<RawBlock<'_>> = Blocks::new(&payload).map(Result::unwrap).collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].kind(), Some(Ssu2BlockType::DateTime));
        assert_eq!(collected[0].body, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(collected[1].kind(), Some(Ssu2BlockType::Padding));
        assert_eq!(collected[1].body, &[0, 0, 0]);
    }

    #[test]
    fn blocks_unknown_type_passes_through() {
        let mut payload = Vec::new();
        write_raw_block(&mut payload, 200, b"xyz").unwrap();
        let block = Blocks::new(&payload).next().unwrap().unwrap();
        assert_eq!(block.block_type, 200);
        assert_eq!(block.kind(), None);
        assert_eq!(block.body, b"xyz");
    }

    #[test]
    fn blocks_rejects_truncated_header() {
        let payload = [0x00u8, 0x00];
        let mut it = Blocks::new(&payload);
        assert_eq!(
            it.next().unwrap(),
            Err(I2PError::InvalidLength {
                expected: SSU2_BLOCK_HEADER_SIZE,
                got: 2
            })
        );
        // После ошибки итератор завершается.
        assert!(it.next().is_none());
    }

    #[test]
    fn blocks_rejects_body_overrun() {
        // Заголовок обещает 16 байт тела, но их нет.
        let payload = [0x00u8, 0x00, 0x10];
        let mut it = Blocks::new(&payload);
        assert_eq!(
            it.next().unwrap(),
            Err(I2PError::InvalidLength {
                expected: 19,
                got: 3
            })
        );
        assert!(it.next().is_none());
    }

    #[test]
    fn blocks_rejects_trailing_bytes() {
        let mut payload = framed(Ssu2BlockType::Padding, &[0, 0, 0]);
        payload.push(0xFF); // «висячий» байт
        let mut it = Blocks::new(&payload);
        assert!(it.next().unwrap().is_ok());
        assert!(matches!(
            it.next().unwrap(),
            Err(I2PError::InvalidLength { .. })
        ));
    }

    #[test]
    fn blocks_full_payload_golden() {
        let mut payload = Vec::new();
        DateTimeBlock {
            timestamp: 0x0102_0304,
        }
        .write(&mut payload)
        .unwrap();
        RelayTagBlock {
            relay_tag: 0xAABB_CCDD,
        }
        .write(&mut payload)
        .unwrap();
        PaddingBlock { data: &[0, 0, 0] }
            .write(&mut payload)
            .unwrap();

        assert_eq!(
            payload,
            hex::<20>("00000401020304100004aabbccddfe0003000000")
        );
    }

    #[test]
    fn raw_block_parses_typed() {
        let payload = framed(Ssu2BlockType::DateTime, &[0x00, 0x00, 0x00, 0x2A]);
        let raw = Blocks::new(&payload).next().unwrap().unwrap();
        let dt: DateTimeBlock = raw.parse().unwrap();
        assert_eq!(dt.timestamp, 42);
    }

    // ---- DateTime -------------------------------------------------------

    #[test]
    fn datetime_roundtrip() {
        let b = DateTimeBlock {
            timestamp: 0xDEAD_BEEF,
        };
        assert_eq!(b.to_body(), hex::<4>("deadbeef"));
        assert_eq!(DateTimeBlock::parse(&b.to_body()).unwrap(), b);
        assert_eq!(DateTimeBlock::TYPE, Ssu2BlockType::DateTime);
    }

    #[test]
    fn datetime_too_short() {
        assert!(matches!(
            DateTimeBlock::parse(&[0, 0, 0]),
            Err(I2PError::InvalidLength {
                expected: 4,
                got: 3
            })
        ));
    }

    // ---- Options --------------------------------------------------------

    #[test]
    fn options_roundtrip_and_layout() {
        let b = OptionsBlock {
            tmin: 1,
            tmax: 2,
            rmin: 3,
            rmax: 4,
            tdmy: 0x0506,
            rdmy: 0x0708,
            tdelay: 0x090A,
            rdelay: 0x0B0C,
            more: vec![0xAA, 0xBB],
        };
        assert_eq!(b.to_body(), hex::<14>("0102030405060708090a0b0caabb"));
        assert_eq!(OptionsBlock::parse(&b.to_body()).unwrap(), b);
    }

    #[test]
    fn options_too_short() {
        assert!(matches!(
            OptionsBlock::parse(&[0u8; 11]),
            Err(I2PError::InvalidLength {
                expected: 12,
                got: 11
            })
        ));
    }

    // ---- RouterInfo -----------------------------------------------------

    #[test]
    fn router_info_roundtrip_and_accessors() {
        let body = framed(Ssu2BlockType::RouterInfo, &[0x03, 0x01, 0xDE, 0xAD]);
        let raw = Blocks::new(&body).next().unwrap().unwrap();
        let b: RouterInfoBlock<'_> = raw.parse().unwrap();
        assert_eq!(
            b.flags,
            SSU2_ROUTER_INFO_FLAG_FLOOD | SSU2_ROUTER_INFO_FLAG_GZIP
        );
        assert!(b.flood_requested());
        assert!(b.gzip_compressed());
        assert_eq!(b.fragment_number(), 0);
        assert_eq!(b.num_fragments(), 1);
        assert_eq!(b.router_info, &[0xDE, 0xAD]);
        assert_eq!(b.to_body(), vec![0x03, 0x01, 0xDE, 0xAD]);
    }

    #[test]
    fn router_info_too_short() {
        assert!(matches!(
            RouterInfoBlock::parse(&[0x00]),
            Err(I2PError::InvalidLength {
                expected: 2,
                got: 1
            })
        ));
    }

    // ---- I2NP / фрагменты ----------------------------------------------

    /// 9-байтовый NTCP2-заголовок: type=20 (`Data`), msgid, exp + payload.
    fn i2np_body(msg_id: u32, exp: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(20); // I2npMessageType::Data
        body.extend_from_slice(&msg_id.to_be_bytes());
        body.extend_from_slice(&exp.to_be_bytes());
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn i2np_roundtrip() {
        let body = i2np_body(0x1122_3344, 5, b"hello");
        let b = I2npBlock::parse(&body).unwrap();
        assert_eq!(b.0.msg_id(), 0x1122_3344);
        assert_eq!(b.0.payload(), b"hello");
        assert_eq!(b.to_body(), body);
        assert_eq!(I2npBlock::TYPE, Ssu2BlockType::I2npMessage);
    }

    #[test]
    fn i2np_too_short() {
        assert!(matches!(
            I2npBlock::parse(&[0u8; 8]),
            Err(I2PError::InvalidLength {
                expected: 9,
                got: 8
            })
        ));
    }

    #[test]
    fn first_fragment_roundtrip() {
        let body = i2np_body(0x0102_0304, 7, b"part");
        let b = FirstFragmentBlock::parse(&body).unwrap();
        assert_eq!(b.0.payload(), b"part");
        assert_eq!(b.to_body(), body);
        assert_eq!(FirstFragmentBlock::TYPE, Ssu2BlockType::FirstFragment);
    }

    #[test]
    fn first_fragment_requires_nonempty_part() {
        // Ровно 9 байт заголовка без части сообщения — невалидно.
        let body = i2np_body(1, 1, b"");
        assert!(matches!(
            FirstFragmentBlock::parse(&body),
            Err(I2PError::InvalidLength { expected: 10, .. })
        ));
    }

    #[test]
    fn follow_on_fragment_roundtrip_and_accessors() {
        let frag = follow_on_frag_byte(5, true);
        assert_eq!(frag, (5 << 1) | 1);

        let mut body = Vec::new();
        body.push(frag);
        body.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
        body.extend_from_slice(b"more");
        let b = FollowOnFragmentBlock::parse(&body).unwrap();
        assert_eq!(b.fragment_number(), 5);
        assert!(b.is_last());
        assert_eq!(b.msg_id, 0xCAFE_BABE);
        assert_eq!(b.data, b"more");
        assert_eq!(b.to_body(), body);
    }

    #[test]
    fn follow_on_fragment_too_short() {
        assert!(matches!(
            FollowOnFragmentBlock::parse(&[0u8; 4]),
            Err(I2PError::InvalidLength {
                expected: 5,
                got: 4
            })
        ));
    }

    // ---- Termination ----------------------------------------------------

    #[test]
    fn termination_roundtrip_and_reason() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0000_0000_0000_0042u64.to_be_bytes());
        body.push(Ssu2TerminationReason::ClockSkew.as_u8());
        body.extend_from_slice(b"details");
        let b = TerminationBlock::parse(&body).unwrap();
        assert_eq!(b.valid_packets, 0x42);
        assert_eq!(b.reason, 7);
        assert_eq!(b.reason_kind(), Some(Ssu2TerminationReason::ClockSkew));
        assert_eq!(b.additional, b"details");
        assert_eq!(b.to_body(), body);
    }

    #[test]
    fn termination_unknown_reason_tolerated() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_be_bytes());
        body.push(99);
        let b = TerminationBlock::parse(&body).unwrap();
        assert_eq!(b.reason_kind(), None);
    }

    #[test]
    fn termination_too_short() {
        assert!(matches!(
            TerminationBlock::parse(&[0u8; 8]),
            Err(I2PError::InvalidLength {
                expected: 9,
                got: 8
            })
        ));
    }

    #[test]
    fn termination_reason_roundtrip_all() {
        for v in 0u8..=22 {
            let r = Ssu2TerminationReason::from_u8(v).unwrap();
            assert_eq!(r.as_u8(), v);
            assert_ne!(r.name(), "");
            assert_eq!(format!("{r}"), r.name());
        }
        assert!(Ssu2TerminationReason::from_u8(23).is_none());
    }

    // ---- Address --------------------------------------------------------

    #[test]
    fn address_ipv4_roundtrip() {
        let b = AddressBlock {
            port: 0x1234,
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let body = b.to_body();
        assert_eq!(body.len(), 6);
        assert_eq!(body, vec![0x12, 0x34, 10, 0, 0, 1]);
        assert_eq!(AddressBlock::parse(&body).unwrap(), b);
    }

    #[test]
    fn address_ipv6_roundtrip() {
        let ip = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let b = AddressBlock {
            port: 0xABCD,
            ip: IpAddr::V6(ip),
        };
        let body = b.to_body();
        assert_eq!(body.len(), 18);
        assert_eq!(AddressBlock::parse(&body).unwrap(), b);
    }

    #[test]
    fn address_bad_length() {
        assert!(matches!(
            AddressBlock::parse(&[0u8; 7]),
            Err(I2PError::Malformed(_))
        ));
    }

    // ---- фиксированные блоки -------------------------------------------

    #[test]
    fn relay_tag_request_must_be_empty() {
        assert_eq!(
            RelayTagRequestBlock::parse(&[]).unwrap(),
            RelayTagRequestBlock
        );
        assert!(matches!(
            RelayTagRequestBlock::parse(&[0u8]),
            Err(I2PError::Malformed(_))
        ));
        let mut out = Vec::new();
        RelayTagRequestBlock.write(&mut out).unwrap();
        assert_eq!(out, hex::<3>("0f0000"));
    }

    #[test]
    fn relay_tag_roundtrip() {
        let b = RelayTagBlock {
            relay_tag: 0x0102_0304,
        };
        assert_eq!(b.to_body(), hex::<4>("01020304"));
        assert_eq!(RelayTagBlock::parse(&b.to_body()).unwrap(), b);
        assert!(matches!(
            RelayTagBlock::parse(&[0u8; 3]),
            Err(I2PError::InvalidLength { expected: 4, .. })
        ));
    }

    #[test]
    fn new_token_roundtrip() {
        let b = NewTokenBlock {
            expires: 0x1122_3344,
            token: 0x0102_0304_0506_0708,
        };
        assert_eq!(b.to_body(), hex::<12>("112233440102030405060708"));
        assert_eq!(NewTokenBlock::parse(&b.to_body()).unwrap(), b);
        assert!(matches!(
            NewTokenBlock::parse(&[0u8; 11]),
            Err(I2PError::InvalidLength {
                expected: 12,
                got: 11
            })
        ));
    }

    #[test]
    fn path_challenge_and_response_roundtrip() {
        let data = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let c = PathChallengeBlock { data: &data };
        assert_eq!(c.to_body(), data.to_vec());
        assert_eq!(PathChallengeBlock::parse(&data).unwrap(), c);

        let r = PathResponseBlock { data: &data };
        assert_eq!(r.to_body(), data.to_vec());
        assert_eq!(PathResponseBlock::parse(&data).unwrap(), r);
    }

    #[test]
    fn first_packet_number_roundtrip() {
        let b = FirstPacketNumberBlock {
            first_packet_number: 0x0000_0007,
        };
        assert_eq!(b.to_body(), hex::<4>("00000007"));
        assert_eq!(FirstPacketNumberBlock::parse(&b.to_body()).unwrap(), b);
        assert!(matches!(
            FirstPacketNumberBlock::parse(&[0u8; 3]),
            Err(I2PError::InvalidLength { expected: 4, .. })
        ));
    }

    #[test]
    fn padding_roundtrip() {
        let data = [0u8; 8];
        let b = PaddingBlock { data: &data };
        assert_eq!(b.to_body(), data.to_vec());
        assert_eq!(PaddingBlock::parse(&data).unwrap(), b);
    }

    // ---- RelayRequest ---------------------------------------------------

    fn relay_request_body(signature: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0); // flag
        body.extend_from_slice(&0x1122_3344u32.to_be_bytes());
        body.extend_from_slice(&0x5566_7788u32.to_be_bytes());
        body.extend_from_slice(&0x99AA_BBCCu32.to_be_bytes());
        body.push(2); // ver
        body.push(6); // asz
        body.push(0x12); // port
        body.push(0x34);
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.extend_from_slice(signature);
        body
    }

    #[test]
    fn relay_request_roundtrip_and_layout() {
        let signature = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let body = relay_request_body(&signature);
        assert_eq!(body.len(), 25);
        let b = RelayRequestBlock::parse(&body).unwrap();
        assert_eq!(b.flag, 0);
        assert_eq!(b.nonce, 0x1122_3344);
        assert_eq!(b.relay_tag, 0x5566_7788);
        assert_eq!(b.timestamp, 0x99AA_BBCC);
        assert_eq!(b.version, 2);
        assert_eq!(b.endpoint.port, 0x1234);
        assert_eq!(b.endpoint.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(b.signature, &signature);
        assert_eq!(b.to_body(), body);
        assert_eq!(RelayRequestBlock::TYPE, Ssu2BlockType::RelayRequest);

        // Проводная сборка/разбор через Blocks.
        let mut framed = Vec::new();
        b.write(&mut framed).unwrap();
        let raw = Blocks::new(&framed).next().unwrap().unwrap();
        assert_eq!(raw.kind(), Some(Ssu2BlockType::RelayRequest));
        let parsed: RelayRequestBlock<'_> = raw.parse().unwrap();
        assert_eq!(parsed, b);
    }

    #[test]
    fn relay_request_ipv6_roundtrip() {
        let endpoint = AddressBlock {
            port: 0x00FF,
            ip: IpAddr::V6("2001:db8::5".parse::<Ipv6Addr>().unwrap()),
        };
        let b = RelayRequestBlock {
            flag: 0,
            nonce: 1,
            relay_tag: 2,
            timestamp: 3,
            version: 2,
            endpoint,
            signature: &[],
        };
        let body = b.to_body();
        assert_eq!(body.len(), 15 + 18);
        assert_eq!(RelayRequestBlock::parse(&body).unwrap(), b);
    }

    #[test]
    fn relay_request_rejects_bad_endpoint_size() {
        let mut body = relay_request_body(&[]);
        body[14] = 5; // asz
        assert!(matches!(
            RelayRequestBlock::parse(&body),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn relay_request_too_short() {
        assert!(matches!(
            RelayRequestBlock::parse(&[0u8; 14]),
            Err(I2PError::InvalidLength {
                expected: 15,
                got: 14
            })
        ));
        // asz=6, но endpoint обрезан.
        let body = relay_request_body(&[]);
        assert!(matches!(
            RelayRequestBlock::parse(&body[..20]),
            Err(I2PError::InvalidLength {
                expected: 21,
                got: 20
            })
        ));
    }

    // ---- RelayResponse --------------------------------------------------

    #[test]
    fn relay_response_accept_with_endpoint() {
        // Подпись + 8-байтовый токен (code == Accept).
        let sig_and_token = hex::<12>("112233440102030405060708");
        let mut body = Vec::new();
        body.push(0); // flag
        body.push(Ssu2RelayResponseCode::Accept.as_u8());
        body.extend_from_slice(&0x0A0B_0C0Du32.to_be_bytes());
        body.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        body.push(2); // ver
        body.push(6); // csz
        body.push(0xAB); // port
        body.push(0xCD);
        body.extend_from_slice(&[1, 2, 3, 4]);
        body.extend_from_slice(&sig_and_token);

        let b = RelayResponseBlock::parse(&body).unwrap();
        assert_eq!(b.code, 0);
        assert_eq!(b.code_kind(), Some(Ssu2RelayResponseCode::Accept));
        assert_eq!(b.nonce, 0x0A0B_0C0D);
        assert_eq!(b.timestamp, 0x0102_0304);
        assert_eq!(b.version, 2);
        assert_eq!(b.endpoint.unwrap().port, 0xABCD);
        assert_eq!(b.signature, &sig_and_token);
        assert_eq!(b.to_body(), body);
        assert_eq!(RelayResponseBlock::TYPE, Ssu2BlockType::RelayResponse);
    }

    #[test]
    fn relay_response_reject_has_no_endpoint() {
        let b = RelayResponseBlock {
            flag: 0,
            code: Ssu2RelayResponseCode::BobRelayTagNotFound.as_u8(),
            nonce: 7,
            timestamp: 8,
            version: 2,
            endpoint: None,
            signature: &[0xAA; 64],
        };
        let body = b.to_body();
        assert_eq!(body.len(), 12 + 64);
        assert_eq!(body[11], 0); // csz
        let parsed = RelayResponseBlock::parse(&body).unwrap();
        assert_eq!(
            parsed.code_kind(),
            Some(Ssu2RelayResponseCode::BobRelayTagNotFound)
        );
        assert_eq!(parsed.endpoint, None);
        assert_eq!(parsed, b);
    }

    #[test]
    fn relay_response_rejects_bad_csz_and_too_short() {
        assert!(matches!(
            RelayResponseBlock::parse(&[0u8; 11]),
            Err(I2PError::InvalidLength {
                expected: 12,
                got: 11
            })
        ));
        let mut body = vec![0u8; 12];
        body[11] = 5; // csz
        assert!(matches!(
            RelayResponseBlock::parse(&body),
            Err(I2PError::Malformed(_))
        ));
    }

    // ---- RelayIntro -----------------------------------------------------

    #[test]
    fn relay_intro_roundtrip_and_layout() {
        let alice_hash = [0x42u8; 32];
        let signature = [0x01u8, 0x02, 0x03];
        let b = RelayIntroBlock {
            flag: 0,
            alice_hash,
            nonce: 0x0102_0304,
            relay_tag: 0x0506_0708,
            timestamp: 0x090A_0B0C,
            version: 2,
            endpoint: AddressBlock {
                port: 0x0D0E,
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            },
            signature: &signature,
        };
        let body = b.to_body();
        assert_eq!(body.len(), 47 + 6 + 3);
        assert_eq!(body[46], 6); // asz
        assert_eq!(RelayIntroBlock::parse(&body).unwrap(), b);
        assert_eq!(RelayIntroBlock::TYPE, Ssu2BlockType::RelayIntro);
    }

    #[test]
    fn relay_intro_too_short_and_bad_endpoint() {
        assert!(matches!(
            RelayIntroBlock::parse(&[0u8; 46]),
            Err(I2PError::InvalidLength {
                expected: 47,
                got: 46
            })
        ));
        let mut body = vec![0u8; 47];
        body[46] = 5; // asz
        assert!(matches!(
            RelayIntroBlock::parse(&body),
            Err(I2PError::Malformed(_))
        ));
    }

    // ---- PeerTest -------------------------------------------------------

    #[test]
    fn peer_test_msg1_without_hash_roundtrip() {
        let data = [2u8, 0, 0, 0, 1, 0, 0, 0, 0, 0];
        let mut body = vec![1u8, 0, 0];
        body.extend_from_slice(&data);
        let b = PeerTestBlock::parse(&body).unwrap();
        assert_eq!(b.msg, 1);
        assert_eq!(b.code, 0);
        assert_eq!(b.code_kind(), Some(Ssu2PeerTestCode::Accept));
        assert_eq!(b.flag, 0);
        assert_eq!(b.router_hash, None);
        assert_eq!(b.data, &data);
        assert_eq!(b.to_body(), body);
        assert_eq!(PeerTestBlock::TYPE, Ssu2BlockType::PeerTest);
    }

    #[test]
    fn peer_test_msg2_with_hash_roundtrip() {
        let hash = [0x99u8; 32];
        let data = [0u8; 6];
        let mut body = vec![2u8, 0, 0];
        body.extend_from_slice(&hash);
        body.extend_from_slice(&data);
        let b = PeerTestBlock::parse(&body).unwrap();
        assert_eq!(b.msg, 2);
        assert_eq!(b.router_hash, Some(hash));
        assert_eq!(b.data, &data);
        assert_eq!(b.to_body(), body);
        assert!(PeerTestBlock::has_router_hash(2));
        assert!(PeerTestBlock::has_router_hash(4));
        assert!(!PeerTestBlock::has_router_hash(1));
        assert!(!PeerTestBlock::has_router_hash(3));
    }

    #[test]
    fn peer_test_too_short() {
        assert!(matches!(
            PeerTestBlock::parse(&[1u8, 0]),
            Err(I2PError::InvalidLength {
                expected: 3,
                got: 2
            })
        ));
        // msg=1 требует 3 + 5 = 8 байт подписанных данных.
        assert!(matches!(
            PeerTestBlock::parse(&[1u8, 0, 0, 0, 0, 0, 0]),
            Err(I2PError::InvalidLength {
                expected: 8,
                got: 7
            })
        ));
        // msg=2 требует хеш: 35 + 5 = 40.
        assert!(matches!(
            PeerTestBlock::parse(&[2u8, 0, 0]),
            Err(I2PError::InvalidLength {
                expected: 40,
                got: 3
            })
        ));
    }

    // ---- коды ----------------------------------------------------------

    #[test]
    fn relay_response_code_roundtrip_all() {
        let known = [0u8, 5, 65, 67, 70];
        for v in known {
            let c = Ssu2RelayResponseCode::from_u8(v).unwrap();
            assert_eq!(c.as_u8(), v);
            assert_ne!(c.name(), "");
            assert_eq!(format!("{c}"), c.name());
        }
        for v in [1u8, 6, 64, 66, 71, 255] {
            assert!(Ssu2RelayResponseCode::from_u8(v).is_none(), "code {v}");
        }
    }

    #[test]
    fn peer_test_code_roundtrip_all() {
        let known = [0u8, 1, 2, 3, 4, 64, 65, 66, 67, 68, 69, 70, 128];
        for v in known {
            let c = Ssu2PeerTestCode::from_u8(v).unwrap();
            assert_eq!(c.as_u8(), v);
            assert_ne!(c.name(), "");
            assert_eq!(format!("{c}"), c.name());
        }
        for v in [5u8, 63, 71, 127, 129, 255] {
            assert!(Ssu2PeerTestCode::from_u8(v).is_none(), "code {v}");
        }
    }
}
