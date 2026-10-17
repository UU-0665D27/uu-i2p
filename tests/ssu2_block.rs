#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use uu_i2p::{
        error::I2PError,
        ssu2_block::{
            follow_on_frag_byte, write_block, write_raw_block, AddressBlock, Blocks, DateTimeBlock,
            FirstFragmentBlock, FirstPacketNumberBlock, FollowOnFragmentBlock, I2npBlock,
            NewTokenBlock, OptionsBlock, PaddingBlock, PathChallengeBlock, PathResponseBlock,
            RawBlock, RelayTagBlock, RelayTagRequestBlock, RouterInfoBlock, Ssu2Block,
            Ssu2BlockType, Ssu2TerminationReason, TerminationBlock, SSU2_BLOCK_HEADER_SIZE,
            SSU2_ROUTER_INFO_FLAG_FLOOD, SSU2_ROUTER_INFO_FLAG_GZIP,
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
}
