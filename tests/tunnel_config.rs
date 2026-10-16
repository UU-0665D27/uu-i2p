#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rand::{Error, RngCore};
    use uu_i2p::tunnel_build_record::NUM_TUNNEL_BUILD_RECORDS;
    use uu_i2p::tunnel_config::{TunnelConfig, TunnelHopConfig};
    use uu_i2p::{I2PError, IdentHash};

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    /// ГСЧ, всегда возвращающий нули.
    struct ZeroRng;

    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            dest.fill(0);
            Ok(())
        }
    }

    // ---- hop ------------------------------------------------------------

    #[test]
    fn new_hop_defaults() {
        let hop = TunnelHopConfig::new(ident(1), &mut rng());
        assert_eq!(hop.ident, ident(1));
        assert_ne!(hop.tunnel_id, 0);
        assert_eq!(hop.next_tunnel_id, 0);
        assert!(hop.is_gateway);
        assert!(hop.is_endpoint);
        assert_eq!(hop.record_index, 0);
        assert_eq!(hop.layer_key, [0; 32]);
    }

    #[test]
    fn zero_tunnel_id_replaced_with_one() {
        let hop = TunnelHopConfig::new(ident(1), &mut ZeroRng);
        assert_eq!(hop.tunnel_id, 1);
        let mut hop = hop;
        hop.set_next_ident(ident(2), &mut ZeroRng);
        assert_eq!(hop.next_tunnel_id, 1);
    }

    #[test]
    fn set_next_ident_clears_endpoint() {
        let mut hop = TunnelHopConfig::new(ident(1), &mut rng());
        hop.set_next_ident(ident(9), &mut rng());
        assert_eq!(hop.next_ident, ident(9));
        assert!(!hop.is_endpoint);
        assert_ne!(hop.next_tunnel_id, 0);
    }

    #[test]
    fn set_reply_hop_sets_endpoint() {
        let mut hop = TunnelHopConfig::new(ident(1), &mut rng());
        hop.is_endpoint = false;
        hop.set_reply_hop(0xABCD, ident(7));
        assert_eq!(hop.next_ident, ident(7));
        assert_eq!(hop.next_tunnel_id, 0xABCD);
        assert!(hop.is_endpoint);
    }

    // ---- inbound --------------------------------------------------------

    #[test]
    fn inbound_three_hops() {
        let peers = [ident(1), ident(2), ident(3)];
        let cfg = TunnelConfig::inbound(&peers, ident(0xEE), &mut rng()).unwrap();
        let h = cfg.hops();
        assert_eq!(cfg.num_hops(), 3);
        assert!(cfg.is_inbound());

        assert!(h[0].is_gateway && !h[1].is_gateway && !h[2].is_gateway);
        assert!(!h[0].is_endpoint && !h[1].is_endpoint && !h[2].is_endpoint);

        assert_eq!(h[0].next_ident, ident(2));
        assert_eq!(h[0].next_tunnel_id, h[1].tunnel_id);
        assert_eq!(h[1].next_ident, ident(3));
        assert_eq!(h[1].next_tunnel_id, h[2].tunnel_id);
        assert_eq!(h[2].next_ident, ident(0xEE));
        assert_ne!(h[2].next_tunnel_id, 0);
    }

    #[test]
    fn inbound_accessors() {
        let peers = [ident(1), ident(2)];
        let cfg = TunnelConfig::inbound(&peers, ident(0xEE), &mut rng()).unwrap();
        assert_eq!(cfg.tunnel_id(), cfg.last_hop().next_tunnel_id);
        assert_eq!(cfg.first_hop_tunnel_id(), cfg.first_hop().tunnel_id);
        assert_eq!(cfg.next_ident_hash(), &ident(1));
        assert_eq!(cfg.last_ident_hash(), &ident(2));
        assert_eq!(cfg.peers(), peers.to_vec());
    }

    #[test]
    fn inbound_single_hop() {
        let cfg = TunnelConfig::inbound(&[ident(1)], ident(0xEE), &mut rng()).unwrap();
        let hop = cfg.first_hop();
        assert!(hop.is_gateway);
        assert!(!hop.is_endpoint);
        assert_eq!(hop.next_ident, ident(0xEE));
    }

    // ---- outbound -------------------------------------------------------

    #[test]
    fn outbound_three_hops() {
        let peers = [ident(1), ident(2), ident(3)];
        let cfg = TunnelConfig::outbound(&peers, 0x1234, ident(0xDD), &mut rng()).unwrap();
        let h = cfg.hops();
        assert!(!cfg.is_inbound());

        assert!(!h[0].is_gateway && !h[1].is_gateway && !h[2].is_gateway);
        assert!(!h[0].is_endpoint && !h[1].is_endpoint && h[2].is_endpoint);

        assert_eq!(h[0].next_ident, ident(2));
        assert_eq!(h[0].next_tunnel_id, h[1].tunnel_id);
        assert_eq!(h[2].next_ident, ident(0xDD));
        assert_eq!(h[2].next_tunnel_id, 0x1234);
    }

    #[test]
    fn outbound_tunnel_id_is_first_hop() {
        let cfg = TunnelConfig::outbound(&[ident(1), ident(2)], 5, ident(9), &mut rng()).unwrap();
        assert_eq!(cfg.tunnel_id(), cfg.first_hop().tunnel_id);
    }

    #[test]
    fn outbound_single_hop_is_endpoint_not_gateway() {
        let cfg = TunnelConfig::outbound(&[ident(1)], 5, ident(9), &mut rng()).unwrap();
        let hop = cfg.first_hop();
        assert!(!hop.is_gateway);
        assert!(hop.is_endpoint);
    }

    // ---- ошибки ---------------------------------------------------------

    #[test]
    fn empty_peers_rejected() {
        let r = TunnelConfig::inbound(&[], ident(1), &mut rng());
        assert!(matches!(r, Err(I2PError::Malformed(_))));
        let r = TunnelConfig::outbound(&[], 1, ident(1), &mut rng());
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn too_many_hops_rejected() {
        let peers: Vec<IdentHash> = (0..=u8::try_from(NUM_TUNNEL_BUILD_RECORDS).unwrap())
            .map(ident)
            .collect();
        assert_eq!(peers.len(), NUM_TUNNEL_BUILD_RECORDS + 1);
        let r = TunnelConfig::inbound(&peers, ident(0xEE), &mut rng());
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn max_hops_accepted() {
        let peers: Vec<IdentHash> = (1..=u8::try_from(NUM_TUNNEL_BUILD_RECORDS).unwrap())
            .map(ident)
            .collect();
        let cfg = TunnelConfig::inbound(&peers, ident(0xEE), &mut rng()).unwrap();
        assert_eq!(cfg.num_hops(), NUM_TUNNEL_BUILD_RECORDS);
    }

    #[test]
    fn all_tunnel_ids_nonzero_even_with_zero_rng() {
        let peers = [ident(1), ident(2), ident(3)];
        let cfg = TunnelConfig::inbound(&peers, ident(0xEE), &mut ZeroRng).unwrap();
        assert!(cfg.hops().iter().all(|h| h.tunnel_id != 0));
        assert_ne!(cfg.tunnel_id(), 0);
    }

    // ---- record indices -------------------------------------------------

    #[test]
    fn assign_record_indices_ok() {
        let mut cfg =
            TunnelConfig::inbound(&[ident(1), ident(2), ident(3)], ident(9), &mut rng()).unwrap();
        cfg.assign_record_indices(&[5, 0, 7]).unwrap();
        let idx: Vec<usize> = cfg.hops().iter().map(|h| h.record_index).collect();
        assert_eq!(idx, vec![5, 0, 7]);
    }

    #[test]
    fn assign_record_indices_errors_keep_config() {
        let mut cfg = TunnelConfig::inbound(&[ident(1), ident(2)], ident(9), &mut rng()).unwrap();
        let before = cfg.clone();
        assert!(cfg.assign_record_indices(&[0]).is_err()); // не то количество
        assert!(cfg.assign_record_indices(&[0, 0]).is_err()); // дубликат
        assert!(cfg.assign_record_indices(&[0, 8]).is_err()); // вне диапазона
        assert_eq!(cfg, before);
    }

    #[test]
    fn hops_mut_allows_key_fill() {
        let mut cfg = TunnelConfig::inbound(&[ident(1)], ident(9), &mut rng()).unwrap();
        cfg.hops_mut()[0].layer_key = [0x11; 32];
        assert_eq!(cfg.first_hop().layer_key, [0x11; 32]);
    }
}
