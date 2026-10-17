#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sha2::{Digest, Sha256};
    use uu_i2p::tunnel_fragments::*;
    use uu_i2p::tunnel_messages::TunnelDataBody;
    use uu_i2p::{I2PError, IdentHash};

    fn rng() -> StdRng {
        StdRng::seed_from_u64(99)
    }

    fn hash(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    fn sha4(payload: &[u8], iv: &[u8; 16]) -> [u8; 4] {
        let mut h = Sha256::new();
        h.update(payload);
        h.update(iv);
        let d = h.finalize();
        [d[0], d[1], d[2], d[3]]
    }

    /// Собирает tunnel-сообщение из готового payload с фиксированным padding.
    fn make_plain(payload: &[u8], iv: [u8; 16]) -> TunnelDataBody {
        assert!(payload.len() <= TUNNEL_DATA_MAX_PAYLOAD_SIZE);
        let start = 1008 - payload.len();
        let mut enc = Box::new([0x55u8; 1008]);
        enc[start - 1] = 0;
        enc[start..].copy_from_slice(payload);
        enc[..4].copy_from_slice(&sha4(payload, &iv));
        TunnelDataBody {
            tunnel_id: 0,
            iv,
            encrypted: enc,
        }
    }

    fn parse_ok(payload: &[u8]) -> Vec<Fragment> {
        let parsed = parse_tunnel_message(&make_plain(payload, [7; 16])).unwrap();
        assert_eq!(parsed.error, None);
        parsed.fragments
    }

    // ---- константы и Delivery -------------------------------------------------

    #[test]
    fn constants() {
        assert_eq!(TUNNEL_DATA_MAX_PAYLOAD_SIZE, 1008 - 4 - 1);
        assert_eq!(FOLLOW_ON_HEADER_SIZE, 7);
        assert_eq!(MAX_FRAGMENT_NUMBER, 63);
    }

    #[test]
    fn delivery_helpers() {
        let local = Delivery::Local;
        let tunnel = Delivery::Tunnel {
            tunnel_id: 0x0102_0304,
            hash: hash(9),
        };
        let router = Delivery::Router { hash: hash(8) };
        assert_eq!(
            [local.type_bits(), tunnel.type_bits(), router.type_bits()],
            [0, 1, 2]
        );
        assert_eq!(
            [
                local.instructions_len(),
                tunnel.instructions_len(),
                router.instructions_len()
            ],
            [1, 37, 33]
        );
        let mut out = Vec::new();
        local.write_instructions(&mut out);
        assert_eq!(out, vec![0x00]);
        out.clear();
        tunnel.write_instructions(&mut out);
        assert_eq!(out.len(), 37);
        assert_eq!(&out[..5], &[0x20, 1, 2, 3, 4]);
        assert_eq!(&out[5..], &[9u8; 32]);
        out.clear();
        router.write_instructions(&mut out);
        assert_eq!(out[0], 0x40);
        assert_eq!(&out[1..], &[8u8; 32]);
    }

    // ---- build_plain_tunnel_message -------------------------------------------

    #[test]
    fn plain_message_layout() {
        let payload = [1u8, 2, 3];
        let m = build_plain_tunnel_message(&payload, &mut rng()).unwrap();
        assert_eq!(m.tunnel_id, 0);
        let start = 1008 - 3;
        assert_eq!(&m.encrypted[start..], &payload);
        assert_eq!(m.encrypted[start - 1], 0);
        // padding — только ненулевые байты
        assert!(m.encrypted[4..start - 1].iter().all(|&b| b != 0));
        assert_eq!(start - 1 - 4, 1000);
        assert_eq!(m.encrypted[..4], sha4(&payload, &m.iv));
    }

    #[test]
    fn plain_message_extremes() {
        // максимум: без padding
        let big = vec![0xABu8; TUNNEL_DATA_MAX_PAYLOAD_SIZE];
        let m = build_plain_tunnel_message(&big, &mut rng()).unwrap();
        assert_eq!(m.encrypted[4], 0);
        assert_eq!(&m.encrypted[5..], &big[..]);
        // пустой payload
        let m = build_plain_tunnel_message(&[], &mut rng()).unwrap();
        assert_eq!(m.encrypted[1007], 0);
        assert!(m.encrypted[4..1007].iter().all(|&b| b != 0));
        // слишком длинный
        let too_big = vec![0u8; TUNNEL_DATA_MAX_PAYLOAD_SIZE + 1];
        assert!(matches!(
            build_plain_tunnel_message(&too_big, &mut rng()),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn plain_message_is_random_but_deterministic_per_seed() {
        let a = build_plain_tunnel_message(&[1, 2], &mut StdRng::seed_from_u64(1)).unwrap();
        let b = build_plain_tunnel_message(&[1, 2], &mut StdRng::seed_from_u64(1)).unwrap();
        let c = build_plain_tunnel_message(&[1, 2], &mut StdRng::seed_from_u64(2)).unwrap();
        assert_eq!(a, b);
        assert_ne!(a.iv, c.iv);
        assert_ne!(a.encrypted[..], c.encrypted[..]);
    }

    #[test]
    fn built_message_parses_back() {
        let mut payload = vec![0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let m = build_plain_tunnel_message(&payload, &mut rng()).unwrap();
        let parsed = parse_tunnel_message(&m).unwrap();
        assert_eq!(parsed.error, None);
        assert_eq!(parsed.fragments.len(), 1);
        assert_eq!(parsed.fragments[0].data, payload.split_off(3));
    }

    // ---- разбор: виды фрагментов -------------------------------------------------

    #[test]
    fn parse_local_single() {
        let f = parse_ok(&[0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(
            f,
            vec![Fragment {
                kind: FragmentKind::First {
                    delivery: Delivery::Local,
                    msg_id: None
                },
                data: vec![0xAA, 0xBB],
            }]
        );
    }

    #[test]
    fn parse_tunnel_and_router_delivery() {
        let mut p = vec![0x20, 0x00, 0x00, 0x00, 0x2A];
        p.extend_from_slice(&[0x11; 32]);
        p.extend_from_slice(&[0x00, 0x01, 0xFE]);
        p.push(0x40);
        p.extend_from_slice(&[0x22; 32]);
        p.extend_from_slice(&[0x00, 0x02, 0x01, 0x02]);
        let f = parse_ok(&p);
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0].kind,
            FragmentKind::First {
                delivery: Delivery::Tunnel {
                    tunnel_id: 42,
                    hash: hash(0x11)
                },
                msg_id: None
            }
        );
        assert_eq!(f[0].data, vec![0xFE]);
        assert_eq!(
            f[1].kind,
            FragmentKind::First {
                delivery: Delivery::Router { hash: hash(0x22) },
                msg_id: None
            }
        );
        assert_eq!(f[1].data, vec![1, 2]);
    }

    #[test]
    fn parse_fragmented_first_and_follow_on() {
        let mut p = vec![0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02, 0x01, 0x02];
        // follow-on: номер 2, последний
        p.extend_from_slice(&[
            0x80 | (2 << 1) | 1,
            0xDE,
            0xAD,
            0xBE,
            0xEF,
            0x00,
            0x01,
            0x09,
        ]);
        let f = parse_ok(&p);
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0].kind,
            FragmentKind::First {
                delivery: Delivery::Local,
                msg_id: Some(0xDEAD_BEEF)
            }
        );
        assert_eq!(
            f[1].kind,
            FragmentKind::FollowOn {
                msg_id: 0xDEAD_BEEF,
                fragment_num: 2,
                is_last: true
            }
        );
        assert_eq!(f[1].data, vec![9]);
    }

    #[test]
    fn follow_on_flag_decoding() {
        for (num, last) in [(1u8, false), (1, true), (63, false), (63, true), (17, true)] {
            let flag = 0x80 | (num << 1) | u8::from(last);
            let f = parse_ok(&[flag, 0, 0, 0, 5, 0, 0]);
            assert_eq!(
                f[0].kind,
                FragmentKind::FollowOn {
                    msg_id: 5,
                    fragment_num: num,
                    is_last: last
                }
            );
            assert_eq!(f[0].data, [] as [u8; 0]);
        }
    }

    #[test]
    fn parse_many_fragments_in_order() {
        let mut p = Vec::new();
        for i in 0..5u8 {
            p.extend_from_slice(&[0x00, 0x00, 0x01, i]);
        }
        let f = parse_ok(&p);
        let data: Vec<u8> = f.iter().map(|x| x.data[0]).collect();
        assert_eq!(data, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn delay_bit_is_ignored_like_i2pd() {
        let f = parse_ok(&[0x10, 0x00, 0x01, 0xAA]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].data, vec![0xAA]);
    }

    #[test]
    fn empty_payload_has_no_fragments() {
        assert_eq!(parse_ok(&[]), [] as [uu_i2p::tunnel_fragments::Fragment; 0]);
    }

    // ---- разбор: ошибки ----------------------------------------------------------

    #[test]
    fn checksum_mismatch_rejected() {
        let mut m = make_plain(&[0x00, 0x00, 0x01, 0xAA], [3; 16]);
        m.encrypted[1007] ^= 0x01; // портим payload
        assert!(matches!(
            parse_tunnel_message(&m),
            Err(I2PError::Malformed(_))
        ));
        let mut m = make_plain(&[0x00, 0x00, 0x01, 0xAA], [3; 16]);
        m.iv[0] ^= 0x01; // IV входит в контрольную сумму
        assert!(parse_tunnel_message(&m).is_err());
        let mut m = make_plain(&[0x00, 0x00, 0x01, 0xAA], [3; 16]);
        m.encrypted[0] ^= 0x01;
        assert!(parse_tunnel_message(&m).is_err());
    }

    #[test]
    fn missing_zero_separator_rejected() {
        let m = TunnelDataBody {
            tunnel_id: 0,
            iv: [1; 16],
            encrypted: Box::new([0xFF; 1008]),
        };
        assert!(matches!(
            parse_tunnel_message(&m),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn size_exceeding_message_keeps_previous_fragments() {
        let mut p = vec![0x00, 0x00, 0x01, 0xAA];
        p.extend_from_slice(&[0x00, 0xFF, 0xFF, 0x01]); // size 65535, данных нет
        let parsed = parse_tunnel_message(&make_plain(&p, [1; 16])).unwrap();
        assert_eq!(parsed.fragments.len(), 1);
        assert_eq!(parsed.fragments[0].data, vec![0xAA]);
        assert!(matches!(parsed.error, Some(I2PError::Malformed(_))));
    }

    #[test]
    fn unknown_delivery_type_stops_parsing() {
        let mut p = vec![0x00, 0x00, 0x01, 0xAA];
        p.extend_from_slice(&[0x60, 0x00, 0x01, 0xBB]); // тип 3
        p.extend_from_slice(&[0x00, 0x00, 0x01, 0xCC]);
        let parsed = parse_tunnel_message(&make_plain(&p, [1; 16])).unwrap();
        assert_eq!(parsed.fragments.len(), 1);
        assert!(parsed.error.is_some());
    }

    #[test]
    fn truncated_headers_are_errors() {
        // tunnel delivery, hash обрезан
        let mut p = vec![0x20, 0, 0, 0, 1];
        p.extend_from_slice(&[0u8; 10]);
        let parsed = parse_tunnel_message(&make_plain(&p, [1; 16])).unwrap();
        assert!(parsed.fragments.is_empty() && parsed.error.is_some());
        // follow-on без msg_id
        let parsed = parse_tunnel_message(&make_plain(&[0x82, 0, 0], [1; 16])).unwrap();
        assert!(parsed.fragments.is_empty() && parsed.error.is_some());
        // нет размера
        let parsed = parse_tunnel_message(&make_plain(&[0x00, 0x00], [1; 16])).unwrap();
        assert!(parsed.fragments.is_empty() && parsed.error.is_some());
        // fragmented без msg_id
        let parsed = parse_tunnel_message(&make_plain(&[0x08, 0, 0], [1; 16])).unwrap();
        assert!(parsed.fragments.is_empty() && parsed.error.is_some());
    }
}
