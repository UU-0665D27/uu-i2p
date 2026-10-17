#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};
    use uu_i2p::{
        error::I2PError,
        ssu2_header::{
            header_mask, obfuscate_cover_header, obfuscate_extended_header, obfuscate_header,
            ConnectionId, LongHeader, ShortHeader, Ssu2MessageType,
            SSU2_FLAG_IMMEDIATE_ACK_REQUESTED, SSU2_MAX_PACKET_SIZE_IPV4,
            SSU2_MAX_PACKET_SIZE_IPV6, SSU2_MIN_PACKET_SIZE, SSU2_VERSION,
        },
    };

    // ---- hex helpers ----------------------------------------------------

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

    // ---- golden vectors (независимо сгенерированы Python `cryptography`) ----

    const K_H1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const K_H2: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

    /// Пакет `Data`/`SessionConfirmed`-типа: только cover-обфускация.
    const COVER_PLAIN: &str =
        "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d14";
    const COVER_OBFUSC: &str =
        "95b551d6b46b2a6d2c8ea073913c9e84737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d14";

    /// `SessionRequest`-пакет (88 байт, минимум спеки): cover + extended.
    const SR_PLAIN: &str = concat!(
        "303b46515c67727d88939ea9b4bfcad5e0ebf6010c17222d38434e59646f7a85",
        "909ba6b1bcc7d2dde8f3fe09141f2a35404b56616c77828d98a3aeb9c4cfdae5",
        "f0fb06111c27323d48535e69747f8a95a0abb6c1ccd7e2ed",
    );
    const SR_OBFUSC: &str = concat!(
        "8221821c9dd9432da9e0964aa5bed31df853b430a1f184fc2b221238cb2c34a2",
        "682a55445d6a8981040b021b3e2a5f6932435e0cbd99bed00522f69da0c1dad9",
        "f0fb06111c27323d48535e69747f8a95a0abb6c1ccd7e2ed",
    );

    // ---- константы ------------------------------------------------------

    #[test]
    fn constants_match_spec() {
        assert_eq!(SSU2_VERSION, 2);
        assert_eq!(SSU2_MIN_PACKET_SIZE, 40);
        assert_eq!(SSU2_MAX_PACKET_SIZE_IPV4, 1472);
        assert_eq!(SSU2_MAX_PACKET_SIZE_IPV6, 1452);
        assert_eq!(SSU2_FLAG_IMMEDIATE_ACK_REQUESTED, 0x01);
    }

    // ---- Ssu2MessageType ------------------------------------------------

    #[test]
    fn message_type_roundtrip_all_variants() {
        let all = [
            Ssu2MessageType::SessionRequest,
            Ssu2MessageType::SessionCreated,
            Ssu2MessageType::SessionConfirmed,
            Ssu2MessageType::Data,
            Ssu2MessageType::PeerTest,
            Ssu2MessageType::Retry,
            Ssu2MessageType::TokenRequest,
            Ssu2MessageType::HolePunch,
        ];
        for t in all {
            assert_eq!(Ssu2MessageType::from_u8(t.as_u8()).unwrap(), t);
        }
    }

    #[test]
    fn message_type_values_match_spec() {
        assert_eq!(Ssu2MessageType::SessionRequest.as_u8(), 0);
        assert_eq!(Ssu2MessageType::SessionCreated.as_u8(), 1);
        assert_eq!(Ssu2MessageType::SessionConfirmed.as_u8(), 2);
        assert_eq!(Ssu2MessageType::Data.as_u8(), 6);
        assert_eq!(Ssu2MessageType::PeerTest.as_u8(), 7);
        assert_eq!(Ssu2MessageType::Retry.as_u8(), 9);
        assert_eq!(Ssu2MessageType::TokenRequest.as_u8(), 10);
        assert_eq!(Ssu2MessageType::HolePunch.as_u8(), 11);
    }

    #[test]
    fn message_type_unknown_returns_error() {
        for v in [3u8, 4, 5, 8, 12, 13, 50, 255] {
            assert_eq!(
                Ssu2MessageType::from_u8(v),
                Err(I2PError::UnknownSsu2MessageType(v))
            );
        }
    }

    #[test]
    fn message_type_names_are_unique() {
        let all = [
            Ssu2MessageType::SessionRequest,
            Ssu2MessageType::SessionCreated,
            Ssu2MessageType::SessionConfirmed,
            Ssu2MessageType::Data,
            Ssu2MessageType::PeerTest,
            Ssu2MessageType::Retry,
            Ssu2MessageType::TokenRequest,
            Ssu2MessageType::HolePunch,
        ];
        let mut seen = std::collections::HashSet::new();
        for t in all {
            assert!(seen.insert(t.name()), "duplicate name: {}", t.name());
        }
    }

    #[test]
    fn message_type_display_matches_name() {
        for t in [Ssu2MessageType::Data, Ssu2MessageType::TokenRequest] {
            assert_eq!(format!("{t}"), t.name());
        }
    }

    #[test]
    fn message_type_header_shape() {
        // (тип, длинный?, эфемерный?, header_len, extended_len)
        let cases = [
            (Ssu2MessageType::SessionRequest, true, true, 32, 48),
            (Ssu2MessageType::SessionCreated, true, true, 32, 48),
            (Ssu2MessageType::SessionConfirmed, false, false, 16, 0),
            (Ssu2MessageType::Data, false, false, 16, 0),
            (Ssu2MessageType::PeerTest, true, false, 32, 16),
            (Ssu2MessageType::Retry, true, false, 32, 16),
            (Ssu2MessageType::TokenRequest, true, false, 32, 16),
            (Ssu2MessageType::HolePunch, true, false, 32, 16),
        ];
        for (t, long, eph, hlen, ext) in cases {
            assert_eq!(t.is_long_header(), long, "{t} is_long_header");
            assert_eq!(t.has_ephemeral_key(), eph, "{t} has_ephemeral_key");
            assert_eq!(t.header_len(), hlen, "{t} header_len");
            assert_eq!(t.extended_header_len(), ext, "{t} extended_header_len");
        }
    }

    // ---- ConnectionId ---------------------------------------------------

    #[test]
    fn connection_id_u64_roundtrip() {
        let v = 0x1122_3344_5566_7788_u64;
        let c = ConnectionId::from_u64(v);
        assert_eq!(c.to_u64(), v);
        assert_eq!(c.as_bytes(), &v.to_be_bytes());
    }

    #[test]
    fn connection_id_inverse_is_involution() {
        let c = ConnectionId::from_u64(0x0123_4567_89ab_cdef);
        assert_eq!(c.inverse().inverse(), c);
        assert_eq!(
            c.inverse().as_bytes(),
            &[0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
        );
    }

    #[test]
    fn connection_id_relay_nonce_pair_matches_spec() {
        // ((nonce << 32) | nonce) BE, source = ~dest.
        let (dest, source) = ConnectionId::relay_nonce_pair(0xDEAD_BEEF);
        assert_eq!(
            dest.as_bytes(),
            &[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            source.as_bytes(),
            &[0x21, 0x52, 0x41, 0x10, 0x21, 0x52, 0x41, 0x10]
        );
        assert_eq!(source, dest.inverse());
    }

    #[test]
    fn connection_id_random_is_seeded() {
        let mut a = StdRng::seed_from_u64(42);
        let mut b = StdRng::seed_from_u64(42);
        assert_eq!(ConnectionId::random(&mut a), ConnectionId::random(&mut b));
    }

    // ---- LongHeader -----------------------------------------------------

    #[test]
    fn long_header_roundtrip_and_layout() {
        let h = LongHeader {
            dest_conn_id: ConnectionId::from_u64(0x1122_3344_5566_7788),
            packet_num: 0xdead_beef,
            msg_type: Ssu2MessageType::SessionRequest,
            version: SSU2_VERSION,
            net_id: 2,
            flag: 0,
            source_conn_id: ConnectionId::from_u64(0x8877_6655_4433_2211),
            token: 0x0123_4567_89ab_cdef,
        };
        let bytes = h.to_bytes();
        assert_eq!(
            bytes,
            hex::<32>("1122334455667788deadbeef0002020088776655443322110123456789abcdef")
        );
        assert_eq!(LongHeader::parse(&bytes).unwrap(), h);
    }

    #[test]
    fn long_header_parse_too_short() {
        let buf = [0u8; 31];
        assert_eq!(
            LongHeader::parse(&buf),
            Err(I2PError::InvalidLength {
                expected: 32,
                got: 31
            })
        );
    }

    #[test]
    fn long_header_parse_rejects_short_type() {
        let mut buf = [0u8; 32];
        buf[12] = Ssu2MessageType::Data.as_u8();
        assert!(matches!(
            LongHeader::parse(&buf),
            Err(I2PError::Malformed(_))
        ));
    }

    // ---- ShortHeader ----------------------------------------------------

    #[test]
    fn short_header_roundtrip() {
        let h = ShortHeader {
            dest_conn_id: ConnectionId::from_u64(0x0102_0304_0506_0708),
            packet_num: 7,
            msg_type: Ssu2MessageType::Data,
            flags: [0x01, 0x00, 0x00],
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes, hex::<16>("01020304050607080000000706010000"));
        assert_eq!(ShortHeader::parse(&bytes).unwrap(), h);
    }

    #[test]
    fn short_header_frag_accessors() {
        let mut h = ShortHeader {
            dest_conn_id: ConnectionId::from_u64(0),
            packet_num: 0,
            msg_type: Ssu2MessageType::SessionConfirmed,
            flags: [0, 0, 0],
        };
        h.set_frag(3, 5);
        assert_eq!(h.flags[0], 0x35);
        assert_eq!(h.frag_number(), 3);
        assert_eq!(h.num_fragments(), 5);
    }

    #[test]
    fn short_header_immediate_ack_accessor() {
        let mut h = ShortHeader {
            dest_conn_id: ConnectionId::from_u64(0),
            packet_num: 0,
            msg_type: Ssu2MessageType::Data,
            flags: [0, 0, 0],
        };
        assert!(!h.immediate_ack_requested());
        h.set_immediate_ack_requested(true);
        assert!(h.immediate_ack_requested());
        assert_eq!(h.flags[0], SSU2_FLAG_IMMEDIATE_ACK_REQUESTED);
        h.set_immediate_ack_requested(false);
        assert!(!h.immediate_ack_requested());
    }

    #[test]
    fn short_header_parse_too_short() {
        let buf = [0u8; 15];
        assert_eq!(
            ShortHeader::parse(&buf),
            Err(I2PError::InvalidLength {
                expected: 16,
                got: 15
            })
        );
    }

    #[test]
    fn short_header_parse_rejects_long_type() {
        let mut buf = [0u8; 16];
        buf[12] = Ssu2MessageType::Retry.as_u8();
        assert!(matches!(
            ShortHeader::parse(&buf),
            Err(I2PError::Malformed(_))
        ));
    }

    // ---- header_mask ----------------------------------------------------

    #[test]
    fn header_mask_matches_golden() {
        let key = hex::<32>(K_H1);
        let iv = hex::<12>("101112131415161718191a1b");
        assert_eq!(header_mask(&key, &iv), hex::<8>("5eca45070619c669"));
    }

    // ---- cover-обфускация ----------------------------------------------

    #[test]
    fn cover_header_matches_golden() {
        let k1 = hex::<32>(K_H1);
        let k2 = hex::<32>(K_H2);
        let mut pkt = hex::<40>(COVER_PLAIN);
        obfuscate_cover_header(&k1, &k2, &mut pkt).unwrap();
        assert_eq!(pkt, hex::<40>(COVER_OBFUSC));
    }

    #[test]
    fn cover_header_is_involution() {
        let k1 = hex::<32>(K_H1);
        let k2 = hex::<32>(K_H2);
        let plain = hex::<40>(COVER_PLAIN);
        let mut pkt = plain;
        obfuscate_cover_header(&k1, &k2, &mut pkt).unwrap();
        assert_ne!(pkt, plain);
        obfuscate_cover_header(&k1, &k2, &mut pkt).unwrap();
        assert_eq!(pkt, plain);
    }

    #[test]
    fn cover_header_too_short() {
        let k1 = hex::<32>(K_H1);
        let k2 = hex::<32>(K_H2);
        let mut buf = [0u8; 39];
        assert_eq!(
            obfuscate_cover_header(&k1, &k2, &mut buf),
            Err(I2PError::InvalidLength {
                expected: SSU2_MIN_PACKET_SIZE,
                got: 39
            })
        );
    }

    // ---- extended-обфускация -------------------------------------------

    #[test]
    fn extended_header_48_matches_golden() {
        let key = hex::<32>(K_H2);
        let mut buf = hex::<48>(concat!(
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
        ));
        let plain = buf;
        obfuscate_extended_header(&key, &mut buf);
        assert_eq!(
            buf,
            hex::<48>(concat!(
                "26bf942140f401e97db4befe59f254c55af6a254a1970151cea17133eb580382",
                "05d3932a52c2f5528806e4e5665c2814",
            ))
        );
        obfuscate_extended_header(&key, &mut buf);
        assert_eq!(buf, plain);
    }

    #[test]
    fn extended_header_16_matches_golden() {
        let key = hex::<32>(K_H2);
        let mut buf = hex::<16>("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        obfuscate_extended_header(&key, &mut buf);
        assert_eq!(buf, hex::<16>("46dff441209461891dd4de9e399234a5"));
    }

    // ---- композитная обфускация ----------------------------------------

    #[test]
    fn header_full_matches_golden() {
        let k1 = hex::<32>(K_H1);
        let mut pkt = hex::<88>(SR_PLAIN);
        obfuscate_header(Ssu2MessageType::SessionRequest, &k1, &k1, &mut pkt).unwrap();
        assert_eq!(pkt, hex::<88>(SR_OBFUSC));
    }

    #[test]
    fn header_full_is_involution() {
        let k1 = hex::<32>(K_H1);
        let plain = hex::<88>(SR_PLAIN);
        let mut pkt = plain;
        obfuscate_header(Ssu2MessageType::SessionRequest, &k1, &k1, &mut pkt).unwrap();
        assert_ne!(pkt, plain);
        obfuscate_header(Ssu2MessageType::SessionRequest, &k1, &k1, &mut pkt).unwrap();
        assert_eq!(pkt, plain);
    }

    #[test]
    fn header_full_data_is_cover_only() {
        let k1 = hex::<32>(K_H1);
        let k2 = hex::<32>(K_H2);
        let plain = hex::<40>(COVER_PLAIN);

        let mut via_full = plain;
        obfuscate_header(Ssu2MessageType::Data, &k1, &k2, &mut via_full).unwrap();

        let mut via_cover = plain;
        obfuscate_cover_header(&k1, &k2, &mut via_cover).unwrap();

        assert_eq!(via_full, via_cover);
    }

    #[test]
    fn header_full_rejects_short_extended() {
        // SessionRequest: 40 (min cover) + 48 (extended) = 88.
        let k1 = hex::<32>(K_H1);
        let mut buf = [0u8; 40];
        assert_eq!(
            obfuscate_header(Ssu2MessageType::SessionRequest, &k1, &k1, &mut buf),
            Err(I2PError::InvalidLength {
                expected: 88,
                got: 40
            })
        );
    }

    #[test]
    fn header_full_rejects_short_cover() {
        let k1 = hex::<32>(K_H1);
        let mut buf = [0u8; 30];
        assert_eq!(
            obfuscate_header(Ssu2MessageType::Data, &k1, &k1, &mut buf),
            Err(I2PError::InvalidLength {
                expected: SSU2_MIN_PACKET_SIZE,
                got: 30
            })
        );
    }
}
