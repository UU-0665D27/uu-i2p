#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use uu_i2p::{
        Congestion, I2PAddress, I2PPrivateKeys, I2PTag, IdentHash, Introducer, RouterInfo,
        RouterInfoCaps,
        base64::{self, encode},
        database_store::DatabaseStore,
        ed25519::I2PSigner,
        error::I2PError,
        extract_param, extract_string,
        router_info::{
            FullRouterInfo, Reader, lp, param, parse_address, ri_caps, serialize_address,
        },
        router_info_address,
    };

    // ---- helpers --------------------------------------------------------

    fn zero_b64(n: usize) -> String {
        encode(&vec![0u8; n])
    }

    /// Собирает опубликованный NTCP2-адрес в i2pd-каноническом порядке
    /// (`host, i, port, s, v` — см. `LocalRouterInfo::WriteToStream`).
    fn ntcp2_addr_published(host: &str, port: u16) -> Vec<u8> {
        let mut props = Vec::new();
        props.extend(param(b"host", host.as_bytes()));
        props.extend(param(b"i", zero_b64(16).as_bytes()));
        props.extend(param(b"port", port.to_string().as_bytes()));
        props.extend(param(b"s", zero_b64(32).as_bytes()));
        props.extend(param(b"v", b"2"));

        let mut addr = vec![router_info_address::cost::NTCP2_PUBLISHED];
        addr.extend_from_slice(&0u64.to_be_bytes()); // date
        addr.extend_from_slice(&lp(b"NTCP2"));
        addr.extend_from_slice(&u16::try_from(props.len()).unwrap().to_be_bytes());
        addr.extend_from_slice(&props);
        addr
    }

    /// Собирает RI body с одним адресом и данными props.
    fn build_body(timestamp: u64, addresses: &[Vec<u8>], props: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.push(u8::try_from(addresses.len()).unwrap());
        for a in addresses {
            body.extend_from_slice(a);
        }
        body.push(0); // numPeers
        let mut props_bytes = Vec::new();
        for p in props {
            props_bytes.extend_from_slice(p);
        }
        body.extend_from_slice(&u16::try_from(props_bytes.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&props_bytes);
        body
    }

    // ---- extract_string -------------------------------------------------

    #[test]
    fn extract_string_ok() {
        let buf = [3u8, b'a', b'b', b'c', 0xff];
        let (s, n) = extract_string(&buf).unwrap();
        assert_eq!(s, b"abc");
        assert_eq!(n, 4);
    }

    #[test]
    fn extract_string_empty() {
        let buf = [0u8, 0xff];
        let (s, n) = extract_string(&buf).unwrap();
        assert_eq!(s, b"");
        assert_eq!(n, 1);
    }

    #[test]
    fn extract_string_empty_buffer_is_error() {
        let r = extract_string(&[]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn extract_string_too_short_is_error() {
        let buf = [5u8, b'a', b'b'];
        let r = extract_string(&buf);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 6,
                got: 3
            })
        );
    }

    // ---- extract_param --------------------------------------------------

    #[test]
    fn extract_param_ok() {
        let buf = [1u8, b'k', b'=', 1, b'v', b';', 0xaa];
        let (k, v, n) = extract_param(&buf).unwrap();
        assert_eq!(k, b"k");
        assert_eq!(v, b"v");
        assert_eq!(n, 6);
    }

    #[test]
    fn extract_param_missing_eq_is_error() {
        let buf = [1u8, b'k', b'X'];
        let r = extract_param(&buf);
        assert_eq!(r, Err(I2PError::Malformed("expected '=' after param key")));
    }

    #[test]
    fn extract_param_missing_semi_is_error() {
        let buf = [1u8, b'k', b'=', 1, b'v', b'X'];
        let r = extract_param(&buf);
        assert_eq!(
            r,
            Err(I2PError::Malformed("expected ';' after param value"))
        );
    }

    // ---- parse_address --------------------------------------------------

    #[test]
    fn parse_ntcp2_published_golden() {
        let addr_bytes = ntcp2_addr_published("1.2.3.4", 1234);
        let mut r = Reader::new(&addr_bytes);
        let addr = parse_address(&mut r).unwrap().expect("valid address");
        assert!(addr.is_ntcp2());
        assert!(addr.is_v4());
        assert_eq!(addr.port, 1234);
        assert_eq!(addr.host, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert!(addr.published);
        assert_eq!(addr.v, 2);
        assert!(addr.ssu.is_none());
        // Reader продвинулся на всю длину адреса
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn parse_ntcp2_without_host_is_not_published() {
        let mut props = Vec::new();
        props.extend(param(b"caps", b"4"));
        props.extend(param(b"s", zero_b64(32).as_bytes()));
        props.extend(param(b"i", zero_b64(16).as_bytes()));
        let mut addr_bytes = vec![0u8];
        addr_bytes.extend_from_slice(&0u64.to_be_bytes());
        addr_bytes.extend_from_slice(&lp(b"NTCP2"));
        addr_bytes.extend_from_slice(&u16::try_from(props.len()).unwrap().to_be_bytes());
        addr_bytes.extend_from_slice(&props);

        let mut r = Reader::new(&addr_bytes);
        let addr = parse_address(&mut r).unwrap().expect("valid address");
        assert!(addr.is_ntcp2());
        assert!(!addr.published);
        assert!(addr.is_v4()); // caps = '4'
    }

    #[test]
    fn parse_ssu2_with_introducer_golden() {
        // Хэш introducer'а — не нулевой, чтобы пройти проверку `i_h.is_zero()`.
        let intro_hash_bytes = [0x42u8; 32];
        let intro_hash_b64 = base64::encode(&intro_hash_bytes);

        let mut props = Vec::new();
        props.extend(param(b"host", b"192.0.2.1"));
        props.extend(param(b"port", b"5000"));
        props.extend(param(b"s", zero_b64(32).as_bytes()));
        props.extend(param(b"i", zero_b64(32).as_bytes()));
        props.extend(param(b"v", b"2"));
        props.extend(param(b"caps", b"BC"));
        props.extend(param(b"ih0", intro_hash_b64.as_bytes()));
        props.extend(param(b"itag0", b"1234"));
        props.extend(param(b"iexp0", b"2000000000"));
        props.extend(param(b"mtu", b"1450"));

        let mut addr_bytes = vec![0u8];
        addr_bytes.extend_from_slice(&0u64.to_be_bytes());
        addr_bytes.extend_from_slice(&lp(b"SSU2"));
        addr_bytes.extend_from_slice(&u16::try_from(props.len()).unwrap().to_be_bytes());
        addr_bytes.extend_from_slice(&props);

        let mut r = Reader::new(&addr_bytes);
        let addr = parse_address(&mut r).unwrap().expect("valid address");
        assert!(addr.is_ssu2());
        assert!(addr.is_v4());
        assert!(addr.published);
        assert!(addr.is_peer_testing());
        assert!(addr.is_introducer());
        assert!(addr.uses_introducer());

        let ssu = addr.ssu.as_ref().expect("ssu ext");
        assert_eq!(ssu.mtu, 1450);
        assert_eq!(ssu.introducers.len(), 1);

        let intro = &ssu.introducers[0];
        assert_eq!(intro.i_tag, 1234);
        assert_eq!(intro.i_exp, 2_000_000_000);
        assert_eq!(intro.i_h.as_bytes(), &intro_hash_bytes);
        // Всё на месте → introducer валиден на момент 1_000_000.
        assert!(intro.is_valid(1_000_000));
    }

    #[test]
    fn parse_address_unknown_transport_skipped() {
        let mut addr_bytes = vec![0u8];
        addr_bytes.extend_from_slice(&0u64.to_be_bytes());
        addr_bytes.extend_from_slice(&lp(b"XYZW"));
        addr_bytes.extend_from_slice(&0u16.to_be_bytes()); // no props

        let mut r = Reader::new(&addr_bytes);
        let addr = parse_address(&mut r).unwrap();
        assert!(addr.is_none());
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn parse_address_invalid_s_is_skipped() {
        let mut props = Vec::new();
        props.extend(param(b"host", b"1.2.3.4"));
        props.extend(param(b"port", b"1234"));
        props.extend(param(b"s", b"not-a-key"));
        props.extend(param(b"i", zero_b64(16).as_bytes()));
        props.extend(param(b"v", b"2"));

        let mut addr_bytes = vec![0u8];
        addr_bytes.extend_from_slice(&0u64.to_be_bytes());
        addr_bytes.extend_from_slice(&lp(b"NTCP2"));
        addr_bytes.extend_from_slice(&u16::try_from(props.len()).unwrap().to_be_bytes());
        addr_bytes.extend_from_slice(&props);

        let mut r = Reader::new(&addr_bytes);
        assert!(parse_address(&mut r).unwrap().is_none());
    }

    #[test]
    fn parse_address_invalid_v_is_skipped() {
        let mut props = Vec::new();
        props.extend(param(b"host", b"1.2.3.4"));
        props.extend(param(b"port", b"1234"));
        props.extend(param(b"s", zero_b64(32).as_bytes()));
        props.extend(param(b"i", zero_b64(32).as_bytes()));
        props.extend(param(b"v", b"3")); // для SSU2 не годится

        let mut addr_bytes = vec![0u8];
        addr_bytes.extend_from_slice(&0u64.to_be_bytes());
        addr_bytes.extend_from_slice(&lp(b"SSU2"));
        addr_bytes.extend_from_slice(&u16::try_from(props.len()).unwrap().to_be_bytes());
        addr_bytes.extend_from_slice(&props);

        let mut r = Reader::new(&addr_bytes);
        assert!(parse_address(&mut r).unwrap().is_none());
    }
    /// В реальных RI встречается `pq=4,3` (multi-value, пока не поддержано).
    /// Адрес должен парситься, v остаётся 2. i2pd ведёт себя так же.
    #[test]
    fn parse_ssu2_with_multivalue_pq_is_kept() {
        let mut props = Vec::new();
        props.extend(param(b"host", b"92.29.142.247"));
        props.extend(param(b"port", b"17380"));
        props.extend(param(b"s", zero_b64(32).as_bytes()));
        props.extend(param(b"i", zero_b64(32).as_bytes()));
        props.extend(param(b"v", b"2"));
        props.extend(param(b"caps", b"BC"));
        props.extend(param(b"pq", b"4,3")); // вот оно

        let mut addr_bytes = vec![0u8];
        addr_bytes.extend_from_slice(&0u64.to_be_bytes());
        addr_bytes.extend_from_slice(&lp(b"SSU2"));
        addr_bytes.extend_from_slice(&u16::try_from(props.len()).unwrap().to_be_bytes());
        addr_bytes.extend_from_slice(&props);

        let mut r = Reader::new(&addr_bytes);
        let addr = parse_address(&mut r).unwrap().expect("SSU2 must be kept");
        assert!(addr.is_ssu2());
        assert_eq!(addr.v, 2, "multi-value pq must not bump v");
        assert_eq!(addr.port, 17380);
        assert!(addr.published);
        assert!(addr.is_peer_testing());
        assert!(addr.is_introducer());
    }

    /// Single-byte `pq=4` работает как раньше.
    #[test]
    fn parse_ntcp2_with_single_byte_pq_bumps_v() {
        let mut props = Vec::new();
        props.extend(param(b"host", b"1.2.3.4"));
        props.extend(param(b"port", b"1234"));
        props.extend(param(b"s", zero_b64(32).as_bytes()));
        props.extend(param(b"i", zero_b64(16).as_bytes()));
        props.extend(param(b"v", b"2"));
        props.extend(param(b"pq", b"4"));

        let mut addr_bytes = vec![0u8];
        addr_bytes.extend_from_slice(&0u64.to_be_bytes());
        addr_bytes.extend_from_slice(&lp(b"NTCP2"));
        addr_bytes.extend_from_slice(&u16::try_from(props.len()).unwrap().to_be_bytes());
        addr_bytes.extend_from_slice(&props);

        let mut r = Reader::new(&addr_bytes);
        let addr = parse_address(&mut r).unwrap().expect("NTCP2 must be valid");
        assert_eq!(addr.v, 4);
    }

    // ---- parse_body -----------------------------------------------------

    #[test]
    fn parse_body_minimal() {
        let body = build_body(1_700_000_000_000, &[], &[]);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.timestamp, 1_700_000_000_000);
        assert!(ri.addresses.is_empty(), "addresses must be empty");
        assert!(ri.peers.is_empty(), "peers must be empty");
        assert!(ri.properties.is_empty(), "properties must be empty");
        assert!(!ri.is_floodfill());
        assert_eq!(ri.version, None);
        assert_eq!(ri.net_id, None);
    }

    #[test]
    fn parse_body_with_ntcp2_address() {
        let addr = ntcp2_addr_published("10.0.0.1", 1234);
        let body = build_body(1, &[addr], &[]);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.addresses.len(), 1);
        let a = &ri.addresses[0];
        assert!(a.is_ntcp2());
        assert_eq!(a.port, 1234);
    }

    #[test]
    fn parse_body_with_caps() {
        let props = vec![param(b"caps", b"fORP46")];
        let body = build_body(1, &[], &props);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert!(ri.caps.is_floodfill());
        assert!(ri.caps.is_high_bandwidth());
        assert!(ri.caps.is_extra_bandwidth());
        assert!(ri.caps.is_reachable());
        assert!(ri.caps.supports_v4());
        assert!(ri.caps.supports_v6());
        assert_eq!(ri.caps.bandwidth_cap, Some(b'P'));
    }

    #[test]
    fn parse_body_with_version_and_netid() {
        let props = vec![param(b"router.version", b"0.9.64"), param(b"netId", b"2")];
        let body = build_body(1, &[], &props);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.version, Some(964));
        assert_eq!(ri.net_id, Some(2));
    }

    #[test]
    fn parse_body_version_with_dots_is_concatenated() {
        // i2pd считает все цифры: "0.9.100" → 9100
        let props = vec![param(b"router.version", b"0.9.100")];
        let body = build_body(1, &[], &props);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.version, Some(9100));
    }

    #[test]
    fn parse_body_with_peer_hashes() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u64.to_be_bytes());
        body.push(0); // no addresses
        body.push(2); // 2 peers
        body.extend_from_slice(&[0xAA; 32]);
        body.extend_from_slice(&[0xBB; 32]);
        body.extend_from_slice(&0u16.to_be_bytes()); // no props
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.peers.len(), 2);
        assert_eq!(ri.peers[0].as_bytes(), &[0xAA; 32]);
        assert_eq!(ri.peers[1].as_bytes(), &[0xBB; 32]);
    }

    #[test]
    fn parse_body_ignores_trailing_bytes() {
        // После properties идут "signature" байты — должны игнорироваться.
        let mut body = build_body(1, &[], &[]);
        body.extend_from_slice(&[0xde; 64]); // "signature"
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.timestamp, 1);
    }

    #[test]
    fn parse_body_truncated_is_error() {
        let r = RouterInfo::parse_body(&[0u8; 4]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    // ---- ri_caps --------------------------------------------------------

    #[test]
    fn ri_caps_parse_empty() {
        let c = RouterInfoCaps::parse(b"");
        assert_eq!(c.bits, 0);
        assert_eq!(c.bandwidth_cap, None);
        assert_eq!(c.congestion, Congestion::Low);
    }

    #[test]
    fn ri_caps_bandwidth_letters() {
        for (c, expected_bits) in [
            (b'K', 0u8),
            (b'L', 0),
            (b'M', 0),
            (b'N', 0),
            (b'O', ri_caps::HIGH_BANDWIDTH),
            (b'P', ri_caps::HIGH_BANDWIDTH | ri_caps::EXTRA_BANDWIDTH),
            (b'X', ri_caps::HIGH_BANDWIDTH | ri_caps::EXTRA_BANDWIDTH),
        ] {
            let cap = RouterInfoCaps::parse(&[c]);
            assert_eq!(cap.bandwidth_cap, Some(c), "letter {c:?}");
            assert_eq!(cap.bits, expected_bits, "letter {c:?}");
        }
    }

    #[test]
    fn ri_caps_congestion_last_wins() {
        let c = RouterInfoCaps::parse(b"DEG");
        assert_eq!(c.congestion, Congestion::RejectAll);
        let c = RouterInfoCaps::parse(b"ED");
        assert_eq!(c.congestion, Congestion::Medium);
    }

    #[test]
    fn ri_caps_unknown_ignored() {
        let c = RouterInfoCaps::parse(b"fZzZ");
        assert!(c.is_floodfill());
        assert!(!c.is_high_bandwidth());
    }

    // ---- accessors ------------------------------------------------------

    #[test]
    fn get_property_finds_and_misses() {
        let props = vec![param(b"a", b"1"), param(b"b", b"2")];
        let body = build_body(1, &[], &props);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.get_property(b"a"), Some(&b"1"[..]));
        assert_eq!(ri.get_property_str("b"), Some(&b"2"[..]));
        assert_eq!(ri.get_property(b"missing"), None);
    }

    #[test]
    fn get_property_uses_last_when_duplicated() {
        let props = vec![param(b"x", b"first"), param(b"x", b"second")];
        let body = build_body(1, &[], &props);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.get_property(b"x"), Some(&b"second"[..]));
    }

    #[test]
    fn address_accessors_pick_right_transport() {
        let ntcp2 = ntcp2_addr_published("1.2.3.4", 1111);
        // SSU2 v6
        let mut ssu2_props = Vec::new();
        ssu2_props.extend(param(b"host", b"2001:db8::1"));
        ssu2_props.extend(param(b"port", b"2222"));
        ssu2_props.extend(param(b"s", zero_b64(32).as_bytes()));
        ssu2_props.extend(param(b"i", zero_b64(32).as_bytes()));
        ssu2_props.extend(param(b"v", b"2"));
        let mut ssu2 = vec![0u8];
        ssu2.extend_from_slice(&0u64.to_be_bytes());
        ssu2.extend_from_slice(&lp(b"SSU2"));
        ssu2.extend_from_slice(&u16::try_from(ssu2_props.len()).unwrap().to_be_bytes());
        ssu2.extend_from_slice(&ssu2_props);

        let body = build_body(1, &[ntcp2, ssu2], &[]);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert!(ri.ntcp2_v4_address().is_some());
        assert!(ri.ntcp2_v6_address().is_none());
        assert!(ri.ssu2_v4_address().is_none());
        assert!(ri.ssu2_v6_address().is_some());
    }

    // ---- FullRouterInfo -------------------------------------------------

    /// Собирает полный буфер: identity + body + signature.
    fn build_full(dsa: bool) -> Vec<u8> {
        let mut id = if dsa { vec![0u8; 387] } else { vec![0u8; 391] };

        // Заполняем всё, кроме certificate (первые 384 байта).
        // Для DSA байты 384..387 = [0, 0, 0] и так.
        for (i, b) in id.iter_mut().enumerate().take(384) {
            *b = u8::try_from(i & 0xff).expect("i & 0xff fits u8");
        }

        if !dsa {
            // EdDSA + ECIES-X25519: certificate = [5, 0, 4], ext = [0, 7, 0, 4]
            id[384] = 5;
            id[385] = 0;
            id[386] = 4;
            id[387] = 0;
            id[388] = 7;
            id[389] = 0;
            id[390] = 4;
        }
        // для DSA certificate остался [0, 0, 0] из vec![0u8; 387]

        let body = build_body(42, &[], &[]);
        let sig_len = if dsa { 40 } else { 64 };
        let mut full = id;
        full.extend_from_slice(&body);
        full.extend(std::iter::repeat_n(0xAB, sig_len));
        full
    }

    #[test]
    fn full_roundtrip_dsa() {
        let buf = build_full(true);
        let full = FullRouterInfo::from_buffer(&buf).unwrap();
        assert_eq!(full.body().timestamp, 42);
        assert_eq!(full.signature().len(), 40);
        assert!(full.signature().iter().all(|&b| b == 0xAB));
        assert_eq!(full.identity().full_len(), 387);
    }

    #[test]
    fn full_roundtrip_eddsa() {
        let buf = build_full(false);
        let full = FullRouterInfo::from_buffer(&buf).unwrap();
        assert_eq!(full.body().timestamp, 42);
        assert_eq!(full.signature().len(), 64);
        assert_eq!(full.identity().full_len(), 391);
    }

    #[test]
    fn full_hash_matches_identity_hash() {
        let buf = build_full(false);
        let full = FullRouterInfo::from_buffer(&buf).unwrap();
        assert_eq!(full.ident_hash(), full.identity().ident_hash());
    }

    #[test]
    fn full_too_short_for_signature() {
        let mut buf = build_full(false);
        buf.truncate(buf.len() - 1); // не хватает одного байта signature
        let r = FullRouterInfo::from_buffer(&buf);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn full_too_short_for_identity() {
        let r = FullRouterInfo::from_buffer(&[0u8; 100]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn full_body_with_addresses_roundtrip() {
        let mut id = vec![0u8; 391];
        id[384] = 5;
        id[386] = 4;
        id[388] = 7;
        id[390] = 4;

        let addr = ntcp2_addr_published("1.2.3.4", 1234);
        let body = build_body(99, &[addr], &[param(b"caps", b"fR")]);

        let mut full_bytes = id;
        full_bytes.extend_from_slice(&body);
        full_bytes.extend(std::iter::repeat_n(0u8, 64));

        let full = FullRouterInfo::from_buffer(&full_bytes).unwrap();
        assert_eq!(full.body().addresses.len(), 1);
        assert_eq!(full.body().addresses[0].port, 1234);
        assert!(full.body().is_floodfill());
    } // ---- serialize_address: round-trip --------------------------------

    fn roundtrip_addr(orig: &I2PAddress) {
        let bytes = serialize_address(orig);
        let mut r = Reader::new(&bytes);
        let parsed = parse_address(&mut r).unwrap().expect("valid address");
        assert_eq!(r.remaining(), 0, "Reader must consume whole buffer");
        assert_eq!(&parsed, orig, "round-trip mismatch");
    }

    #[test]
    fn roundtrip_ntcp2_published() {
        roundtrip_addr(&I2PAddress::ntcp2_published(
            "1.2.3.4".parse().unwrap(),
            1234,
            I2PTag::from_array([0x11; 32]),
            [0x22; 16],
        ));
    }

    #[test]
    fn roundtrip_ntcp2_unpublished_v4() {
        roundtrip_addr(&I2PAddress::ntcp2_unpublished(
            0,
            I2PTag::from_array([0x33; 32]),
            [0x44; 16],
            true,
            false,
        ));
    }

    #[test]
    fn roundtrip_ntcp2_unpublished_v4_v6() {
        roundtrip_addr(&I2PAddress::ntcp2_unpublished(
            0,
            I2PTag::from_array([0x33; 32]),
            [0x44; 16],
            true,
            true,
        ));
    }

    #[test]
    fn roundtrip_ssu2_published() {
        roundtrip_addr(&I2PAddress::ssu2_published(
            "10.0.0.1".parse().unwrap(),
            5000,
            I2PTag::from_array([0x55; 32]),
            I2PTag::from_array([0x66; 32]),
        ));
    }

    #[test]
    fn roundtrip_ssu2_unpublished() {
        // Порт для unpublished-адресов НЕ сохраняется (i2pd пишет port
        // только для published; на read-back получаем 0). Это
        // ожидаемое поведение, а не баг writer'а.
        roundtrip_addr(&I2PAddress::ssu2_unpublished(
            0,
            I2PTag::from_array([0x55; 32]),
            I2PTag::from_array([0x66; 32]),
            true,
            false,
        ));
    }

    #[test]
    fn roundtrip_ssu2_with_introducer() {
        let mut addr = I2PAddress::ssu2_unpublished(
            0,
            I2PTag::from_array([0x55; 32]),
            I2PTag::from_array([0x66; 32]),
            true,
            false,
        );
        let mut intro_hash = [0u8; 32];
        intro_hash[0] = 0x77;
        addr.ssu
            .as_mut()
            .expect("ssu ext")
            .introducers
            .push(Introducer::new(
                IdentHash::from_array(intro_hash),
                0xDEAD_BEEF,
                2_000_000_000,
            ));
        roundtrip_addr(&addr);
    }

    #[test]
    fn roundtrip_ssu2_with_mtu() {
        let mut addr = I2PAddress::ssu2_published(
            "10.0.0.1".parse().unwrap(),
            5000,
            I2PTag::from_array([0x55; 32]),
            I2PTag::from_array([0x66; 32]),
        );
        addr.ssu.as_mut().expect("ssu ext").mtu = 1450;
        roundtrip_addr(&addr);
    }

    #[test]
    fn roundtrip_ntcp2_with_pq() {
        let mut addr = I2PAddress::ntcp2_published(
            "1.2.3.4".parse().unwrap(),
            1234,
            I2PTag::from_array([0x11; 32]),
            [0x22; 16],
        );
        addr.v = 4;
        roundtrip_addr(&addr);
    }

    /// Round-trip адресов на всех реальных `routerInfo-*.dat` из
    /// `tests/`. Cargo выставляет `CARGO_MANIFEST_DIR` при запуске
    /// тестов, поэтому путь строим от него.
    ///
    /// Файлы подкладываются вручную (в репо не коммитятся, потому что
    /// они меняются каждый день). Если файлов нет — тест падает с
    /// понятным сообщением, чтобы не пропустить smoke-проверку.
    #[test]
    fn roundtrip_addresses_from_real_files() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {}", dir.display(), e));

        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.expect("read dir entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("routerInfo-") && name.ends_with(".dat") {
                files.push(entry.path());
            }
        }
        files.sort();

        assert!(
            !files.is_empty(),
            "no routerInfo-*.dat found in {} — put a real file there",
            dir.display()
        );

        for path in &files {
            let name = path.file_name().unwrap().to_string_lossy();
            let buf = std::fs::read(path).unwrap_or_else(|e| panic!("read {name}: {e}"));
            let full =
                FullRouterInfo::from_buffer(&buf).unwrap_or_else(|e| panic!("parse {name}: {e}"));

            assert!(
                !full.body().addresses.is_empty(),
                "{name}: parsed 0 addresses — parser likely dropped something"
            );

            for addr in &full.body().addresses {
                let bytes = serialize_address(addr);
                let mut r = Reader::new(&bytes);
                let parsed = parse_address(&mut r)
                    .unwrap_or_else(|e| panic!("{name}: parse serialized: {e}"))
                    .expect("valid address");
                assert_eq!(
                    &parsed, addr,
                    "{}: round-trip mismatch for {:?}",
                    name, addr.transport_style
                );
                assert_eq!(r.remaining(), 0, "{name}: trailing bytes");
            }

            eprintln!(
                "round-trip OK: {} ({} addresses)",
                name,
                full.body().addresses.len()
            );
        }
    } // ---- serialize_body: semantic round-trip --------------------------

    fn semantic_body_roundtrip(orig: &RouterInfo) {
        let bytes = orig.serialize_body().expect("serialize");
        let parsed = RouterInfo::parse_body(&bytes).expect("parse");
        assert_eq!(&parsed, orig, "body round-trip mismatch");
    }

    #[test]
    fn body_roundtrip_minimal() {
        let body = build_body(1_700_000_000_000, &[], &[]);
        let ri = RouterInfo::parse_body(&body).unwrap();
        semantic_body_roundtrip(&ri);
    }

    #[test]
    fn body_roundtrip_with_addresses() {
        let addr1 = ntcp2_addr_published("1.2.3.4", 1234);
        let addr2 = ntcp2_addr_published("5.6.7.8", 5678);
        let body = build_body(42, &[addr1, addr2], &[]);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.addresses.len(), 2);
        semantic_body_roundtrip(&ri);
    }

    #[test]
    fn body_roundtrip_with_properties() {
        let props = vec![
            param(b"caps", b"fOR"),
            param(b"netId", b"2"),
            param(b"router.version", b"0.9.64"),
            param(b"family", b"myfamily"),
        ];
        let body = build_body(1, &[], &props);
        let ri = RouterInfo::parse_body(&body).unwrap();
        assert_eq!(ri.properties.len(), 4);
        semantic_body_roundtrip(&ri);
    }

    #[test]
    fn body_roundtrip_with_peers() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u64.to_be_bytes());
        body.push(0); // no addresses
        body.push(3); // 3 peers
        body.extend_from_slice(&[0xAA; 32]);
        body.extend_from_slice(&[0xBB; 32]);
        body.extend_from_slice(&[0xCC; 32]);
        body.extend_from_slice(&0u16.to_be_bytes());
        let ri = RouterInfo::parse_body(&body).unwrap();
        semantic_body_roundtrip(&ri);
    }

    /// Byte-perfect round-trip: наш writer должен воспроизвести
    /// входной буфер посимвольно, если все поля поддерживаются.
    #[test]
    fn body_byte_perfect_for_synthetic() {
        let addr = ntcp2_addr_published("10.0.0.1", 1234);
        let props = vec![
            param(b"caps", b"OR"),
            param(b"netId", b"2"),
            param(b"router.version", b"0.9.70"),
        ];
        let body = build_body(99, &[addr], &props);

        let ri = RouterInfo::parse_body(&body).unwrap();
        let bytes = ri.serialize_body().unwrap();
        assert_eq!(bytes, body, "byte-perfect round-trip failed");
    } // ---- FullRouterInfo: semantic + byte-perfect -----------------------

    #[test]
    fn full_router_info_semantic_roundtrip_dsa() {
        let buf = build_full(true);
        let ri = FullRouterInfo::from_buffer(&buf).unwrap();
        let bytes = ri.to_buffer().unwrap();
        let ri2 = FullRouterInfo::from_buffer(&bytes).unwrap();
        assert_eq!(ri, ri2);
    }

    #[test]
    fn full_router_info_semantic_roundtrip_eddsa() {
        let buf = build_full(false);
        let ri = FullRouterInfo::from_buffer(&buf).unwrap();
        let bytes = ri.to_buffer().unwrap();
        let ri2 = FullRouterInfo::from_buffer(&bytes).unwrap();
        assert_eq!(ri, ri2);
    }

    #[test]
    fn full_router_info_byte_perfect_for_synthetic() {
        // Наш `build_full` создаёт identity + body + signature.
        // Ничего нестандартного там нет, так что writer должен
        // воспроизвести байты 1:1.
        let buf = build_full(false);
        let ri = FullRouterInfo::from_buffer(&buf).unwrap();
        let bytes = ri.to_buffer().unwrap();
        assert_eq!(bytes, buf, "byte-perfect round-trip failed");
    }
    /// Полный semantic round-trip `FullRouterInfo` на всех реальных
    /// `routerInfo-*.dat` из `tests/`.
    ///
    /// Byte-perfect НЕ проверяем: файлы могут содержать поля, которые
    /// мы не храним (например multi-value `pq=4,3` у SSU2), так что
    /// байт-в-байт не сойдётся. Но семантически всё должно
    /// восстановиться.
    #[test]
    fn full_router_info_semantic_roundtrip_real_files() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));

        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.expect("read dir entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("routerInfo-") && name.ends_with(".dat") {
                files.push(entry.path());
            }
        }
        files.sort();

        assert!(
            !files.is_empty(),
            "no routerInfo-*.dat found in {}",
            dir.display()
        );

        for path in &files {
            let name = path.file_name().unwrap().to_string_lossy();
            let buf = std::fs::read(path).unwrap_or_else(|e| panic!("read {name}: {e}"));

            let orig =
                FullRouterInfo::from_buffer(&buf).unwrap_or_else(|e| panic!("parse {name}: {e}"));

            let reserialized = orig
                .to_buffer()
                .unwrap_or_else(|e| panic!("serialize {name}: {e}"));

            let back = FullRouterInfo::from_buffer(&reserialized)
                .unwrap_or_else(|e| panic!("re-parse {name}: {e}"));

            assert_eq!(back, orig, "{name}: semantic round-trip mismatch");

            // Вот оно — подпись проверяется настоящим Ed25519 над
            // **исходными** байтами файла (не над нашей ре-сериализацией).
            orig.verify(&buf)
                .unwrap_or_else(|e| panic!("{name}: signature verification failed: {e}"));

            // Логируем byte-perfect статус — интересно, но не критично.
            let byte_perfect = reserialized == buf;
            eprintln!(
                "{name}: semantic round-trip OK ({} addresses), byte-perfect: {}",
                orig.body().addresses.len(),
                if byte_perfect { "yes" } else { "no" }
            );
        }
    }
    /// Собирает identity с EdDSA+ECIES-X25519 из настоящего
    /// Ed25519-ключа. Используется для тестов верификации подписи.
    ///
    /// Раскладка: [0..256] = ECIES-X25519 public key (только первые
    /// 32 байта значащие, остальное padding), [256..384] = Ed25519
    /// public key (в самом конце — последние 32 байта), [384..387] =
    /// cert=[5,0,4], [387..391] = ext=[0,7,0,4].
    fn identity_from_ed25519(signer: &I2PSigner) -> Vec<u8> {
        let mut buf = vec![0u8; 391];

        // encryption key: первые 32 байта — рандом (не важно для
        // теста подписи), остальное нули
        for (i, b) in buf[..32].iter_mut().enumerate() {
            *b = u8::try_from((i * 7) & 0xff).expect("fits");
        }

        // signing key: Ed25519 public key в самом конце 128-байтового
        // блока, то есть в buf[384 - 32..384]
        let pub_key = signer.public_key();
        buf[384 - 32..384].copy_from_slice(&pub_key);

        // certificate
        buf[384] = 5;
        buf[385] = 0;
        buf[386] = 4;
        // extended: signing type 7, crypto type 4
        buf[387] = 0;
        buf[388] = 7;
        buf[389] = 0;
        buf[390] = 4;

        buf
    }
    #[test]
    fn full_router_info_verify_ed25519() {
        let signer = I2PSigner::generate();
        let id_bytes = identity_from_ed25519(&signer);
        let body = build_body(1, &[], &[]);

        // Собираем signing_data-часть и подписываем её
        let mut signing_data = id_bytes;
        signing_data.extend_from_slice(&body);
        let signature = signer.sign(&signing_data);

        // Полный буфер = signed || signature
        let mut full_bytes = signing_data;
        full_bytes.extend_from_slice(&signature);

        let ri = FullRouterInfo::from_buffer(&full_bytes).unwrap();
        ri.verify(&full_bytes).expect("signature must verify");
    }

    #[test]
    fn full_router_info_verify_fails_on_tampered_body() {
        let signer = I2PSigner::generate();
        let id_bytes = identity_from_ed25519(&signer);
        let body = build_body(1, &[], &[]);

        let mut signing_data = id_bytes;
        signing_data.extend_from_slice(&body);
        let signature = signer.sign(&signing_data);

        // Портим timestamp в body, но оставляем старую подпись
        let mut tampered = signing_data;
        tampered[391] ^= 0xFF; // первый байт timestamp
        let mut full_bytes = tampered;
        full_bytes.extend_from_slice(&signature);

        let ri = FullRouterInfo::from_buffer(&full_bytes).unwrap();
        ri.verify(&full_bytes)
            .expect_err("tampered signature must fail");
    }
    #[test]
    fn real_router_info_through_database_store() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let entries = std::fs::read_dir(&dir).expect("read tests/");
        let mut found = false;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("routerInfo-") || !name.ends_with(".dat") {
                continue;
            }
            found = true;
            let buf = std::fs::read(entry.path()).expect("read");
            let ri = FullRouterInfo::from_buffer(&buf).expect("parse");

            // Оборачиваем в DatabaseStore
            let ds = DatabaseStore::new_router_info(*ri.ident_hash(), &buf, 0, None)
                .expect("wrap in DatabaseStore");
            let wire = ds.to_buffer().expect("serialize DatabaseStore");

            // Парсим обратно
            let ds2 = DatabaseStore::from_buffer(&wire).expect("parse DatabaseStore");
            assert_eq!(ds2.key, *ri.ident_hash());

            // Достаём RI и сверяем с исходным
            let ri_bytes = ds2.payload_decoded().expect("decompress");
            assert_eq!(
                ri_bytes, buf,
                "{name}: RI bytes through DatabaseStore mismatch"
            );

            // И верифицируем подпись — она должна сойтись, потому
            // что payload — те же самые байты.
            let ri2 = FullRouterInfo::from_buffer(&ri_bytes).expect("re-parse RI");
            ri2.verify(&ri_bytes).expect("signature must verify");
        }
        assert!(found, "no routerInfo-*.dat found in tests/");
    } // ---- FullRouterInfo::from_keys --------------------------------------

    /// Строит `RouterInfo` body из пустого минимального набора.
    fn body_from_bytes(ts: u64) -> RouterInfo {
        let bytes = build_body(ts, &[], &[]);
        RouterInfo::parse_body(&bytes).unwrap()
    }

    #[test]
    fn from_keys_then_verify() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body = body_from_bytes(1_700_000_000_000);
        let ri = FullRouterInfo::from_keys(&keys, body.clone()).unwrap();

        // identity из ключей, body как передан
        assert_eq!(ri.identity(), keys.public());
        assert_eq!(ri.body(), &body);
        assert_eq!(ri.signature().len(), 64);

        // Round-trip через wire + verify над исходными байтами
        let buf = ri.to_buffer().unwrap();
        let back = FullRouterInfo::from_buffer(&buf).unwrap();
        assert_eq!(back, ri);
        back.verify(&buf).expect("signature must verify");
    }

    #[test]
    fn from_keys_deterministic_signature() {
        // Ed25519 детерминирован — одна и та же пара ключей и тело
        // должны давать побайтово одинаковый RI.
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body = body_from_bytes(1_700_000_000_000);

        let a = FullRouterInfo::from_keys(&keys, body.clone()).unwrap();
        let b = FullRouterInfo::from_keys(&keys, body).unwrap();

        assert_eq!(a.signature(), b.signature());
        assert_eq!(a.to_buffer().unwrap(), b.to_buffer().unwrap());
    }

    #[test]
    fn from_keys_tamper_detected() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body = body_from_bytes(42);
        let ri = FullRouterInfo::from_keys(&keys, body).unwrap();

        let mut buf = ri.to_buffer().unwrap();
        // Портим байт в теле (после identity, до signature).
        let body_start = ri.identity().full_len();
        buf[body_start] ^= 0xFF;

        let parsed = FullRouterInfo::from_buffer(&buf).unwrap();
        assert!(parsed.verify(&buf).is_err());
    }

    #[test]
    fn from_keys_with_address_and_properties() {
        // Нетривиальный body: адрес + properties. Проверяем, что
        // подпись над сериализованным видом, а не над «логической»
        // структурой — round-trip через wire должен остаться валидным.
        let keys = I2PPrivateKeys::generate_default().unwrap();

        let addr = ntcp2_addr_published("1.2.3.4", 1234);
        let props = vec![param(b"caps", b"OR"), param(b"netId", b"2")];
        let bytes = build_body(99, &[addr], &props);
        let body = RouterInfo::parse_body(&bytes).unwrap();

        let ri = FullRouterInfo::from_keys(&keys, body).unwrap();
        let wire = ri.to_buffer().unwrap();

        let back = FullRouterInfo::from_buffer(&wire).unwrap();
        back.verify(&wire).expect("signature must verify");
        assert_eq!(back.body().addresses.len(), 1);
        assert!(back.body().caps.is_high_bandwidth());
        assert!(back.body().caps.is_reachable());
    }

    #[test]
    fn from_keys_different_keys_different_identity() {
        let keys1 = I2PPrivateKeys::generate_default().unwrap();
        let keys2 = I2PPrivateKeys::generate_default().unwrap();
        let body = body_from_bytes(1);

        let ri1 = FullRouterInfo::from_keys(&keys1, body.clone()).unwrap();
        let ri2 = FullRouterInfo::from_keys(&keys2, body).unwrap();

        assert_ne!(ri1.ident_hash(), ri2.ident_hash());
        assert_ne!(ri1.signature(), ri2.signature());
    }

    // ---- RouterInfoBuilder ----------------------------------------------

    #[test]
    fn builder_empty() {
        let ri = RouterInfo::builder().build();
        assert_eq!(ri.timestamp, 0);
        assert!(ri.addresses.is_empty(), "addresses empty");
        assert!(ri.peers.is_empty(), "peers empty");
        assert!(ri.properties.is_empty(), "properties empty");
        assert_eq!(ri.version, None);
        assert_eq!(ri.net_id, None);
        assert!(!ri.is_floodfill());
        assert!(!ri.is_high_bandwidth());
    }

    #[test]
    fn builder_timestamp() {
        let ri = RouterInfo::builder().timestamp(12345).build();
        assert_eq!(ri.timestamp, 12345);
    }

    #[test]
    fn builder_with_address() {
        let addr = I2PAddress::ntcp2_published(
            "1.2.3.4".parse().unwrap(),
            1234,
            I2PTag::from_array([0x11; 32]),
            [0x22; 16],
        );
        let ri = RouterInfo::builder().add_address(addr.clone()).build();
        assert_eq!(ri.addresses.len(), 1);
        assert_eq!(ri.addresses[0], addr);
    }

    #[test]
    fn builder_with_peer() {
        let h = IdentHash::from_array([0xAA; 32]);
        let ri = RouterInfo::builder().add_peer(h).build();
        assert_eq!(ri.peers.len(), 1);
        assert_eq!(ri.peers[0], h);
    }

    #[test]
    fn builder_caps_writes_property() {
        let ri = RouterInfo::builder()
            .caps(RouterInfoCaps::parse(b"OR"))
            .build();
        assert_eq!(ri.get_property_str("caps"), Some(&b"OR"[..]));
        assert!(ri.caps.is_high_bandwidth());
        assert!(ri.caps.is_reachable());
    }

    #[test]
    fn builder_default_caps_does_not_write_property() {
        let ri = RouterInfo::builder()
            .caps(RouterInfoCaps::default())
            .build();
        assert_eq!(ri.get_property_str("caps"), None);
    }

    #[test]
    fn builder_version_writes_property() {
        let ri = RouterInfo::builder().version(970).build();
        assert_eq!(ri.get_property_str("router.version"), Some(&b"970"[..]));
        assert_eq!(ri.version, Some(970));
    }

    #[test]
    fn builder_net_id_writes_property() {
        let ri = RouterInfo::builder().net_id(2).build();
        assert_eq!(ri.get_property_str("netId"), Some(&b"2"[..]));
        assert_eq!(ri.net_id, Some(2));
    }

    #[test]
    fn builder_caps_replaces_existing_property() {
        // add_property добавляет "caps", set_property (используется
        // в caps()) — заменяет.
        let ri = RouterInfo::builder()
            .add_property(b"caps", b"K")
            .caps(RouterInfoCaps::parse(b"OR"))
            .build();
        let all_caps: Vec<_> = ri.properties.iter().filter(|(k, _)| k == b"caps").collect();
        assert_eq!(all_caps.len(), 1);
        assert_eq!(all_caps[0].1, b"OR");
    }

    #[test]
    fn builder_add_property_allows_duplicates() {
        let ri = RouterInfo::builder()
            .add_property(b"x", b"1")
            .add_property(b"x", b"2")
            .build();
        assert_eq!(ri.properties.iter().filter(|(k, _)| k == b"x").count(), 2);
        // get_property → последний (использует .rev().find())
        assert_eq!(ri.get_property_str("x"), Some(&b"2"[..]));
    }

    #[test]
    fn builder_roundtrip_through_wire() {
        let addr = I2PAddress::ntcp2_published(
            "1.2.3.4".parse().unwrap(),
            1234,
            I2PTag::from_array([0x11; 32]),
            [0x22; 16],
        );
        let ri = RouterInfo::builder()
            .timestamp(1_700_000_000_000)
            .add_address(addr)
            .caps(RouterInfoCaps::parse(b"OR"))
            .version(970)
            .net_id(2)
            .add_property(b"family", b"myfamily")
            .build();

        let bytes = ri.serialize_body().unwrap();
        let back = RouterInfo::parse_body(&bytes).unwrap();

        // struct равенство — семантический round-trip
        assert_eq!(back, ri);
    }

    #[test]
    fn builder_byte_perfect_matches_manual() {
        // Сравниваем буфер, собранный через builder и через build_body
        // (ручную сборку). Порядок вызовов builder'а = порядку
        // properties в build_body.
        let addr = ntcp2_addr_published("10.0.0.1", 1234);
        let manual = build_body(
            99,
            &[addr],
            &[
                param(b"caps", b"OR"),
                param(b"netId", b"2"),
                param(b"router.version", b"970"),
            ],
        );
        let addr = I2PAddress::ntcp2_published(
            "10.0.0.1".parse().unwrap(),
            1234,
            I2PTag::from_array([0u8; 32]),
            [0u8; 16],
        );
        let from_builder = RouterInfo::builder()
            .timestamp(99)
            .add_address(addr)
            .add_property(b"caps", b"OR")
            .add_property(b"netId", b"2")
            .add_property(b"router.version", b"970")
            .build()
            .serialize_body()
            .unwrap();

        assert_eq!(from_builder, manual, "byte-perfect mismatch");
    }

    #[test]
    fn builder_then_full_router_info_from_keys() {
        // Интеграция: builder + from_keys + verify

        use uu_i2p::private_keys::I2PPrivateKeys;
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body = RouterInfo::builder()
            .timestamp(1_700_000_000_000)
            .caps(RouterInfoCaps::parse(b"OR"))
            .version(970)
            .net_id(2)
            .build();

        let ri = FullRouterInfo::from_keys(&keys, body).unwrap();
        let wire = ri.to_buffer().unwrap();
        let parsed = FullRouterInfo::from_buffer(&wire).unwrap();

        assert_eq!(parsed, ri);
        parsed.verify(&wire).expect("signature must verify");
    }
    // ---- RouterInfo::is_newer_than (body vs body) -----------------------

    #[test]
    fn body_is_newer_than_compares_timestamps() {
        let a = RouterInfo::parse_body(&build_body(1000, &[], &[])).unwrap();
        let b = RouterInfo::parse_body(&build_body(2000, &[], &[])).unwrap();
        let c = RouterInfo::parse_body(&build_body(500, &[], &[])).unwrap();
        let d = RouterInfo::parse_body(&build_body(1000, &[], &[])).unwrap();

        assert!(a.is_newer_than(&b));
        assert!(!a.is_newer_than(&c));
        assert!(!a.is_newer_than(&d), "equal timestamps — not newer");
        assert!(!a.is_newer_than(&a));
    }

    // ---- FullRouterInfo::update_verified --------------------------------

    #[test]
    fn full_update_verified_accepts_newer() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ri1 = FullRouterInfo::from_keys(&keys, body_from_bytes(1000)).unwrap();
        let ri2 = FullRouterInfo::from_keys(&keys, body_from_bytes(2000)).unwrap();

        let mut current = ri1;
        let wire2 = ri2.to_buffer().unwrap();
        assert!(current.update_verified(&wire2).unwrap());
        assert_eq!(current.body().timestamp, 2000);

        // Повторный — не обновит (равный timestamp)
        assert!(!current.update_verified(&wire2).unwrap());
    }

    #[test]
    fn full_update_verified_rejects_older() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ri_new = FullRouterInfo::from_keys(&keys, body_from_bytes(2000)).unwrap();
        let ri_old = FullRouterInfo::from_keys(&keys, body_from_bytes(1000)).unwrap();

        let mut current = ri_new;
        let wire_old = ri_old.to_buffer().unwrap();
        assert!(!current.update_verified(&wire_old).unwrap());
        assert_eq!(current.body().timestamp, 2000);
    }

    #[test]
    fn full_update_verified_rejects_bad_signature() {
        let keys1 = I2PPrivateKeys::generate_default().unwrap();
        let keys2 = I2PPrivateKeys::generate_default().unwrap();

        let ri1 = FullRouterInfo::from_keys(&keys1, body_from_bytes(1000)).unwrap();
        let ri2_wrong_key = FullRouterInfo::from_keys(&keys2, body_from_bytes(2000)).unwrap();

        let mut current = ri1;
        let wire = ri2_wrong_key.to_buffer().unwrap();

        // Подпись от keys2 — не сходится с identity от keys1
        let r = current.update_verified(&wire);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
        assert_eq!(current.body().timestamp, 1000, "body unchanged on error");
    }

    #[test]
    fn full_update_verified_replaces_full_body() {
        let keys = I2PPrivateKeys::generate_default().unwrap();

        let ri1 = FullRouterInfo::from_keys(&keys, body_from_bytes(1000)).unwrap();

        let addr = I2PAddress::ntcp2_published(
            "1.2.3.4".parse().unwrap(),
            1234,
            I2PTag::from_array([0x11; 32]),
            [0x22; 16],
        );
        let body2 = RouterInfo::builder()
            .timestamp(2000)
            .add_address(addr)
            .caps(RouterInfoCaps::parse(b"OR"))
            .build();
        let ri2 = FullRouterInfo::from_keys(&keys, body2).unwrap();

        let mut current = ri1;
        let wire2 = ri2.to_buffer().unwrap();
        assert!(current.update_verified(&wire2).unwrap());
        assert_eq!(current.body().timestamp, 2000);
        assert_eq!(current.body().addresses.len(), 1);
        assert!(current.body().caps.is_reachable());
    }

    #[test]
    fn full_is_newer_than_wire() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let ri1 = FullRouterInfo::from_keys(&keys, body_from_bytes(1000)).unwrap();
        let ri2 = FullRouterInfo::from_keys(&keys, body_from_bytes(2000)).unwrap();

        let wire2 = ri2.to_buffer().unwrap();
        assert!(ri1.is_newer_than(&wire2).unwrap());
        assert!(!ri2.is_newer_than(&wire2).unwrap());
    }
}
