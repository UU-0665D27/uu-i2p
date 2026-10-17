#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use uu_i2p::tunnel_build_crypto::{
        decrypt_short_request, encrypt_reply_records, request_for_hop,
    };
    use uu_i2p::tunnel_build_message::*;
    use uu_i2p::tunnel_build_record::*;
    use uu_i2p::tunnel_config::TunnelConfig;
    use uu_i2p::{I2PError, I2PX25519Keys, I2npBody, I2npMessage, IdentHash, ShortTunnelBuildBody};

    const TIME: u32 = 29_000_000;
    const REPLY_MSG_ID: u32 = 0xCAFE_F00D;

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    fn our() -> IdentHash {
        ident(0xEE)
    }

    fn peers(n: usize) -> Vec<IdentHash> {
        (1..=n).map(|k| ident(u8::try_from(k).unwrap())).collect()
    }

    fn statics(n: usize) -> Vec<I2PX25519Keys> {
        (0..n)
            .map(|k| I2PX25519Keys::from_private(&[u8::try_from(k).unwrap() + 0x10; 32], None))
            .collect()
    }

    fn publics(keys: &[I2PX25519Keys]) -> Vec<[u8; 32]> {
        keys.iter().map(|k| *k.public_key()).collect()
    }

    fn outbound(n: usize, seed: u64) -> TunnelConfig {
        let mut rng = StdRng::seed_from_u64(seed);
        TunnelConfig::outbound(&peers(n), 0x1234, ident(0xDD), &mut rng).unwrap()
    }

    fn inbound(n: usize, seed: u64) -> TunnelConfig {
        let mut rng = StdRng::seed_from_u64(seed);
        TunnelConfig::inbound(&peers(n), our(), &mut rng).unwrap()
    }

    fn build(cfg: &mut TunnelConfig, seed: u64) -> ShortBuildRequest {
        let st = statics(cfg.num_hops());
        let mut rng = StdRng::seed_from_u64(seed);
        build_short_tunnel_request(cfg, &publics(&st), &our(), REPLY_MSG_ID, TIME, &mut rng)
            .unwrap()
    }

    /// Прогоняет сообщение через хопы. Возвращает расшифрованные
    /// запросы и ответы по порядку хопов.
    fn run_hops(
        built: &mut ShortBuildRequest,
        cfg: &TunnelConfig,
        rets: &[BuildRetCode],
    ) -> (Vec<ShortBuildRequestRecord>, Vec<ShortBuildResponseRecord>) {
        let st = statics(cfg.num_hops());
        let mut requests = Vec::new();
        let mut responses = Vec::new();
        for k in 0..cfg.num_hops() {
            let hop = &cfg.hops()[k];
            let snapshot = built.body.clone();
            let (idx, rec) = snapshot
                .find_record_for(&hop.ident)
                .expect("record for hop");
            assert_eq!(idx, hop.record_index);
            let (req, keys) = decrypt_short_request(rec, &st[k]).unwrap();
            assert_eq!(req, request_for_hop(hop, TIME, req.send_msg_id));
            assert_eq!(keys, built.hops[k].keys);
            let mut options = BuildOptions::new();
            if rets[k].is_accept() {
                options.insert(OPTION_AVAILABLE_BANDWIDTH, "512");
            }
            let resp = ShortBuildResponseRecord {
                options,
                ret: rets[k],
            };
            encrypt_reply_records(&keys, idx, &resp, &mut built.body.records).unwrap();
            requests.push(req);
            responses.push(resp);
        }
        (requests, responses)
    }

    // ---- раскладка записей ------------------------------------------------

    #[test]
    fn standard_num_records_constant() {
        assert_eq!(STANDARD_NUM_RECORDS, 4);
    }

    #[test]
    fn record_counts_for_all_hop_numbers() {
        for n in 1..=8usize {
            // outbound: phony нет
            let mut cfg = outbound(n, 1);
            let built = build(&mut cfg, 2);
            let expected = if n <= 4 { 4 } else { 8 };
            assert_eq!(built.body.records.len(), expected, "outbound {n}");
            assert_eq!(built.hops.len(), n);

            // inbound: phony, если хопов меньше 8
            let mut cfg = inbound(n, 1);
            let built = build(&mut cfg, 2);
            let total = if n < 8 { n + 1 } else { n };
            let expected = if total <= 4 { 4 } else { 8 };
            assert_eq!(built.body.records.len(), expected, "inbound {n}");
            assert_eq!(built.hops.len(), n);
        }
    }

    #[test]
    fn indices_are_unique_and_in_range() {
        for seed in 0..20 {
            let mut cfg = outbound(3, 5);
            let built = build(&mut cfg, seed);
            let mut seen = [false; 8];
            for hop in &built.hops {
                assert!(hop.record_index < built.body.records.len());
                assert!(!seen[hop.record_index]);
                seen[hop.record_index] = true;
            }
            // индексы в конфиге совпадают с HopCrypto
            for (h, c) in cfg.hops().iter().zip(&built.hops) {
                assert_eq!(h.record_index, c.record_index);
            }
        }
    }

    #[test]
    fn indices_are_shuffled_across_seeds() {
        let mut firsts = std::collections::BTreeSet::new();
        for seed in 0..40 {
            let mut cfg = outbound(2, 5);
            let built = build(&mut cfg, seed);
            firsts.insert(built.hops[0].record_index);
        }
        assert!(
            firsts.len() > 1,
            "первый хоп всегда в одном слоте: {firsts:?}"
        );
    }

    #[test]
    fn hop_keys_are_applied_to_config_and_distinct() {
        let mut cfg = inbound(3, 3);
        let built = build(&mut cfg, 4);
        for (hop, crypto) in cfg.hops().iter().zip(&built.hops) {
            assert_eq!(hop.reply_key, crypto.keys.reply_key);
            assert_eq!(hop.layer_key, crypto.keys.layer_key);
            assert_eq!(hop.iv_key, crypto.keys.iv_key);
            assert_ne!(hop.layer_key, [0; 32]);
        }
        let k = &built.hops;
        assert_ne!(k[0].keys.reply_key, k[1].keys.reply_key);
        assert_ne!(k[1].keys.reply_key, k[2].keys.reply_key);
        assert_ne!(k[0].keys.layer_key, k[2].keys.layer_key);
    }

    // ---- сквозные сценарии --------------------------------------------------

    #[test]
    fn end_to_end_outbound_three_hops() {
        let mut cfg = outbound(3, 10);
        let mut built = build(&mut cfg, 11);
        let (_, expected) = run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 3]);
        let hops = built.hops.clone();
        let result = process_short_build_reply(&mut built.body, &hops).unwrap();
        assert_eq!(result.responses, expected);
        assert!(result.is_established());
        assert_eq!(result.first_rejection(), None);
        for k in 0..3 {
            assert_eq!(result.available_bandwidth(k), Some(512));
        }
        // garlic-ключи только у endpoint
        assert!(hops[0].keys.garlic.is_none());
        assert!(hops[2].keys.garlic.is_some());
    }

    #[test]
    fn end_to_end_inbound_phony_record_is_restored() {
        let mut cfg = inbound(3, 12);
        let mut built = build(&mut cfg, 13);
        assert_eq!(built.body.records.len(), 4);
        run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 3]);

        // единственный слот без настоящего хопа — phony; пройдя все
        // хопы, он снова выглядит как запись «для нас»
        let real: Vec<usize> = built.hops.iter().map(|h| h.record_index).collect();
        let phony: Vec<usize> = (0..4).filter(|i| !real.contains(i)).collect();
        assert_eq!(phony.len(), 1);
        assert_eq!(built.body.records[phony[0]].to_peer, [0xEE; 16]);

        let hops = built.hops.clone();
        let result = process_short_build_reply(&mut built.body, &hops).unwrap();
        assert!(result.is_established());
        // inbound: endpoint-хопа нет, garlic-ключей тоже
        assert!(hops.iter().all(|h| h.keys.garlic.is_none()));
    }

    #[test]
    fn end_to_end_inbound_four_hops_uses_eight_records() {
        let mut cfg = inbound(4, 14);
        let mut built = build(&mut cfg, 15);
        assert_eq!(built.body.records.len(), 8);
        run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 4]);
        let hops = built.hops.clone();
        let result = process_short_build_reply(&mut built.body, &hops).unwrap();
        assert!(result.is_established());
        assert_eq!(result.responses.len(), 4);
    }

    #[test]
    fn end_to_end_eight_hops_both_directions() {
        for is_inbound in [false, true] {
            let mut cfg = if is_inbound {
                inbound(8, 16)
            } else {
                outbound(8, 16)
            };
            let mut built = build(&mut cfg, 17);
            assert_eq!(built.body.records.len(), 8);
            run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 8]);
            let hops = built.hops.clone();
            let result = process_short_build_reply(&mut built.body, &hops).unwrap();
            assert!(result.is_established());
        }
    }

    #[test]
    fn end_to_end_single_hop() {
        let mut cfg = outbound(1, 18);
        let mut built = build(&mut cfg, 19);
        run_hops(&mut built, &cfg, &[BuildRetCode::Accept]);
        let hops = built.hops.clone();
        assert!(
            process_short_build_reply(&mut built.body, &hops)
                .unwrap()
                .is_established()
        );
    }

    #[test]
    fn rejection_is_reported_with_hop_number() {
        let mut cfg = outbound(3, 20);
        let mut built = build(&mut cfg, 21);
        let rets = [
            BuildRetCode::Accept,
            BuildRetCode::Bandwidth,
            BuildRetCode::Accept,
        ];
        run_hops(&mut built, &cfg, &rets);
        let hops = built.hops.clone();
        let result = process_short_build_reply(&mut built.body, &hops).unwrap();
        assert!(!result.is_established());
        assert_eq!(result.first_rejection(), Some((1, BuildRetCode::Bandwidth)));
        assert_eq!(result.available_bandwidth(0), Some(512));
        assert_eq!(result.available_bandwidth(1), None);
    }

    #[test]
    fn last_hop_gets_reply_msg_id_others_are_random() {
        let mut cfg = outbound(3, 22);
        let mut built = build(&mut cfg, 23);
        let (requests, _) = run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 3]);
        assert_eq!(requests[2].send_msg_id, REPLY_MSG_ID);
        assert_ne!(requests[0].send_msg_id, requests[1].send_msg_id);
    }

    #[test]
    fn requests_carry_time_and_default_expiration() {
        let mut cfg = outbound(2, 24);
        let mut built = build(&mut cfg, 25);
        let (requests, _) = run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 2]);
        for req in &requests {
            assert_eq!(req.request_time_minutes, TIME);
            assert_eq!(req.request_expiration_secs, DEFAULT_REQUEST_EXPIRATION_SECS);
            assert!(req.options.is_empty());
        }
        assert!(requests[1].is_endpoint);
    }

    // ---- детерминизм и wire --------------------------------------------------

    #[test]
    fn same_seed_same_message_different_seed_differs() {
        let a = build(&mut outbound(3, 30), 31).body.to_buffer().unwrap();
        let b = build(&mut outbound(3, 30), 31).body.to_buffer().unwrap();
        let c = build(&mut outbound(3, 30), 32).body.to_buffer().unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 1 + 4 * 218);
    }

    #[test]
    fn message_survives_i2np_wire() {
        let mut cfg = outbound(3, 40);
        let built = build(&mut cfg, 41);
        let msg = I2npMessage::from_body(I2npBody::ShortTunnelBuild(built.body.clone())).unwrap();
        let wire = msg.to_buffer().unwrap();
        let parsed = I2npMessage::from_buffer(&wire)
            .unwrap()
            .parse_body()
            .unwrap();
        assert_eq!(parsed, I2npBody::ShortTunnelBuild(built.body));
    }

    // ---- ошибки ---------------------------------------------------------------

    #[test]
    fn wrong_number_of_public_keys_rejected() {
        let mut cfg = outbound(3, 50);
        let st = statics(2);
        let mut rng = StdRng::seed_from_u64(1);
        let r = build_short_tunnel_request(
            &mut cfg,
            &publics(&st),
            &our(),
            REPLY_MSG_ID,
            TIME,
            &mut rng,
        );
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn zero_hop_public_key_rejected() {
        let mut cfg = outbound(2, 51);
        let mut pubs = publics(&statics(2));
        pubs[1] = [0; 32];
        let mut rng = StdRng::seed_from_u64(1);
        let r = build_short_tunnel_request(&mut cfg, &pubs, &our(), REPLY_MSG_ID, TIME, &mut rng);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn tampered_reply_is_rejected() {
        let mut cfg = outbound(3, 52);
        let mut built = build(&mut cfg, 53);
        run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 3]);
        let hops = built.hops.clone();
        let idx = hops[1].record_index;
        built.body.records[idx].ciphertext[20] ^= 0x01;
        assert!(process_short_build_reply(&mut built.body, &hops).is_err());
    }

    #[test]
    fn reply_with_too_few_records_is_rejected() {
        let mut cfg = outbound(3, 54);
        let mut built = build(&mut cfg, 55);
        run_hops(&mut built, &cfg, &[BuildRetCode::Accept; 3]);
        let hops = built.hops.clone();
        let mut short = ShortTunnelBuildBody::new(vec![built.body.records[0].clone()]).unwrap();
        let r = process_short_build_reply(&mut short, &hops);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn unprocessed_request_is_not_a_valid_reply() {
        // если сообщение вернулось, не пройдя хопы, AEAD не сойдётся
        let mut cfg = outbound(2, 56);
        let mut built = build(&mut cfg, 57);
        let hops = built.hops.clone();
        assert!(process_short_build_reply(&mut built.body, &hops).is_err());
    }

    // ---- BuildReplyResult -------------------------------------------------------

    #[test]
    fn reply_result_helpers() {
        let mut opts = BuildOptions::new();
        opts.insert(OPTION_AVAILABLE_BANDWIDTH, "300");
        let result = BuildReplyResult {
            responses: vec![
                ShortBuildResponseRecord {
                    options: opts,
                    ret: BuildRetCode::Accept,
                },
                ShortBuildResponseRecord {
                    options: BuildOptions::new(),
                    ret: BuildRetCode::Other(50),
                },
            ],
        };
        assert!(!result.is_established());
        assert_eq!(result.first_rejection(), Some((1, BuildRetCode::Other(50))));
        assert_eq!(result.available_bandwidth(0), Some(300));
        assert_eq!(result.available_bandwidth(1), None);
        assert_eq!(result.available_bandwidth(2), None);

        let empty = BuildReplyResult { responses: vec![] };
        assert!(empty.is_established()); // vacuous: проверяет вызывающий
        assert_eq!(empty.first_rejection(), None);
    }
}
