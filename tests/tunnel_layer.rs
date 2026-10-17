#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sha2::{Digest, Sha256};
    use uu_i2p::tunnel_config::TunnelConfig;
    use uu_i2p::tunnel_layer::*;
    use uu_i2p::tunnel_messages::TunnelDataBody;
    use uu_i2p::{Aes256Ecb, I2PError, IdentHash};

    // ---- эталонные векторы -------------------------------------------------
    //
    // Получены независимой реализацией на Python (`cryptography`):
    // AES-256-ECB для IV и AES-256-CBC для данных, как в
    // `TunnelEncryption::Encrypt` из i2pd.
    //
    // layer_key[i] = (i * 5 + 1) & 0xFF, iv_key[i] = (i * 9 + 3) & 0xFF,
    // input[i] = (i * 3 + 7) & 0xFF для i в 0..1024.

    const FIPS_CT: &str = "8ea2b7ca516745bfeafc49904b496089";
    const OUT_FIRST32: &str = "66bec6af321a400e8a9a1ee1df8c8186a4ee1966d58599a1a425c78a297f1881";
    const OUT_SHA256: &str = "74830a3531fef18fba9a01667603ed3795c48ac25e944a878b81f4b267a54e39";
    const OUT_LAST16: &str = "ff332a66426517e9a08dbf49b2cb9c1c";

    // три хопа: layer_key = [0x20 + k; 32], iv_key = [0x40 + k; 32]
    const CHAIN3_SHA256: &str = "bca4cb76eeb3a073380b3765f53ef4e32f115955faaa3d773439257c3836311e";
    const OWNER3_SHA256: &str = "603998c203c5e70c347e20ceb53cfac37fcc4fb3b57dfe3bf32ebe279834d8ea";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn sha_bytes(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    fn pattern(mul: usize, add: usize, n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from((i * mul + add) & 0xFF).unwrap())
            .collect()
    }

    fn key32(mul: usize, add: usize) -> [u8; 32] {
        pattern(mul, add, 32).try_into().unwrap()
    }

    fn input() -> [u8; TUNNEL_LAYER_SIZE] {
        pattern(3, 7, 1024).try_into().unwrap()
    }

    fn layer_keys() -> ([u8; 32], [u8; 32]) {
        (key32(5, 1), key32(9, 3))
    }

    // ---- Aes256Ecb ---------------------------------------------------------

    #[test]
    fn ecb_fips197_vector() {
        let key: [u8; 32] = pattern(1, 0, 32).try_into().unwrap();
        let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        let ecb = Aes256Ecb::new(&key);
        let ct = ecb.encrypt_block(&pt);
        assert_eq!(ct[..], unhex(FIPS_CT)[..]);
        assert_eq!(ecb.decrypt_block(&ct), pt);
    }

    #[test]
    fn ecb_is_deterministic_per_block() {
        let ecb = Aes256Ecb::new(&[7; 32]);
        let a = ecb.encrypt_block(&[1; 16]);
        assert_eq!(a, ecb.encrypt_block(&[1; 16]));
        assert_ne!(a, ecb.encrypt_block(&[2; 16]));
        assert_ne!(a, Aes256Ecb::new(&[8; 32]).encrypt_block(&[1; 16]));
    }

    // ---- один слой ----------------------------------------------------------

    #[test]
    fn layer_size_constant() {
        assert_eq!(TUNNEL_LAYER_SIZE, 1024);
    }

    #[test]
    fn encrypt_matches_vector() {
        let (lk, ik) = layer_keys();
        let out = TunnelEncryption::new(&lk, &ik).encrypt(&input()).unwrap();
        assert_eq!(out[..32], unhex(OUT_FIRST32)[..]);
        assert_eq!(out[1008..], unhex(OUT_LAST16)[..]);
        assert_eq!(sha_bytes(&out), unhex(OUT_SHA256));
    }

    #[test]
    fn decrypt_inverts_vector() {
        let (lk, ik) = layer_keys();
        // шифртекст получаем нашим encrypt (он сверен с вектором выше)
        let enc = TunnelEncryption::new(&lk, &ik).encrypt(&input()).unwrap();
        let dec = TunnelDecryption::new(&lk, &ik).decrypt(&enc).unwrap();
        assert_eq!(dec, input());
    }

    #[test]
    fn iv_is_double_encrypted() {
        let (lk, ik) = layer_keys();
        let inp = input();
        let out = TunnelEncryption::new(&lk, &ik).encrypt(&inp).unwrap();
        let ecb = Aes256Ecb::new(&ik);
        let iv = ecb.encrypt_block(inp[..16].try_into().unwrap());
        assert_eq!(out[..16], ecb.encrypt_block(&iv)[..]);
        assert_ne!(out[..16], inp[..16]);
    }

    #[test]
    fn encrypt_changes_data_and_depends_on_keys() {
        let (lk, ik) = layer_keys();
        let a = TunnelEncryption::new(&lk, &ik).encrypt(&input()).unwrap();
        assert_ne!(a[16..], input()[16..]);
        let b = TunnelEncryption::new(&[1; 32], &ik)
            .encrypt(&input())
            .unwrap();
        let c = TunnelEncryption::new(&lk, &[1; 32])
            .encrypt(&input())
            .unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn wrong_keys_do_not_decrypt() {
        let (lk, ik) = layer_keys();
        let enc = TunnelEncryption::new(&lk, &ik).encrypt(&input()).unwrap();
        let dec = TunnelDecryption::new(&lk, &[9; 32]).decrypt(&enc).unwrap();
        assert_ne!(dec, input());
        // неверный layer_key: IV восстанавливается (iv_key верный), данные — нет
        let dec = TunnelDecryption::new(&[9; 32], &ik).decrypt(&enc).unwrap();
        assert_eq!(dec[..16], input()[..16]);
        assert_ne!(dec[16..], input()[16..]);
    }

    #[test]
    fn cbc_bit_flip_only_affects_two_blocks() {
        let (lk, ik) = layer_keys();
        let enc = TunnelEncryption::new(&lk, &ik).encrypt(&input()).unwrap();
        let dec = TunnelDecryption::new(&lk, &ik);
        let good = dec.decrypt(&enc).unwrap();
        // портим байт в 10-м блоке данных (блок 10 после IV)
        let block = 10usize;
        let mut bad = enc;
        bad[16 + block * 16 + 3] ^= 0x01;
        let got = dec.decrypt(&bad).unwrap();
        for b in 0..63usize {
            let range = 16 + b * 16..16 + (b + 1) * 16;
            if b == block || b == block + 1 {
                assert_ne!(got[range.clone()], good[range], "block {b} must change");
            } else {
                assert_eq!(got[range.clone()], good[range], "block {b} must stay");
            }
        }
        assert_eq!(got[..16], good[..16]);
    }

    #[test]
    fn iv_flip_corrupts_iv_and_first_block() {
        let (lk, ik) = layer_keys();
        let enc = TunnelEncryption::new(&lk, &ik).encrypt(&input()).unwrap();
        let dec = TunnelDecryption::new(&lk, &ik);
        let good = dec.decrypt(&enc).unwrap();
        let mut bad = enc;
        bad[0] ^= 0x01;
        let got = dec.decrypt(&bad).unwrap();
        assert_ne!(got[..16], good[..16]);
        assert_ne!(got[16..32], good[16..32]);
        assert_eq!(got[32..], good[32..]);
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let (lk, ik) = layer_keys();
        let s = format!(
            "{:?} {:?}",
            TunnelEncryption::new(&lk, &ik),
            TunnelDecryption::new(&lk, &ik)
        );
        assert!(s.contains("TunnelEncryption") && s.contains("TunnelDecryption"));
        assert!(!s.contains("layer_key"));
    }

    // ---- TunnelData ----------------------------------------------------------

    fn tunnel_data() -> TunnelDataBody {
        let inp = input();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&inp[..16]);
        let mut encrypted = Box::new([0u8; 1008]);
        encrypted.copy_from_slice(&inp[16..]);
        TunnelDataBody {
            tunnel_id: 0xAABB_CCDD,
            iv,
            encrypted,
        }
    }

    #[test]
    fn tunnel_data_wrappers_keep_tunnel_id_and_roundtrip() {
        let (lk, ik) = layer_keys();
        let msg = tunnel_data();
        let enc = TunnelEncryption::new(&lk, &ik)
            .encrypt_tunnel_data(&msg)
            .unwrap();
        assert_eq!(enc.tunnel_id, 0xAABB_CCDD);
        assert_ne!(enc.iv, msg.iv);
        // совпадает с «плоским» вариантом
        let flat = TunnelEncryption::new(&lk, &ik).encrypt(&input()).unwrap();
        assert_eq!(enc.iv[..], flat[..16]);
        assert_eq!(enc.encrypted[..], flat[16..]);
        let dec = TunnelDecryption::new(&lk, &ik)
            .decrypt_tunnel_data(&enc)
            .unwrap();
        assert_eq!(dec, msg);
    }

    // ---- цепочка владельца ----------------------------------------------------

    fn config_with_keys(
        inbound: bool,
        n: usize,
        seed: u64,
        keys: &[([u8; 32], [u8; 32])],
    ) -> TunnelConfig {
        let peers: Vec<IdentHash> = (1..=n)
            .map(|k| IdentHash::from_array([u8::try_from(k).unwrap(); 32]))
            .collect();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut cfg = if inbound {
            TunnelConfig::inbound(&peers, IdentHash::from_array([0xEE; 32]), &mut rng).unwrap()
        } else {
            TunnelConfig::outbound(&peers, 7, IdentHash::from_array([0xDD; 32]), &mut rng).unwrap()
        };
        for (hop, (lk, ik)) in cfg.hops_mut().iter_mut().zip(keys) {
            hop.layer_key = *lk;
            hop.iv_key = *ik;
        }
        cfg
    }

    fn vector_keys() -> Vec<([u8; 32], [u8; 32])> {
        (0..3u8).map(|k| ([0x20 + k; 32], [0x40 + k; 32])).collect()
    }

    #[test]
    fn inbound_chain_matches_vector() {
        let keys = vector_keys();
        let cfg = config_with_keys(true, 3, 1, &keys);
        // хопы шифруют по порядку
        let mut buf = input();
        for hop in cfg.hops() {
            buf = TunnelEncryption::new(&hop.layer_key, &hop.iv_key)
                .encrypt(&buf)
                .unwrap();
        }
        assert_eq!(sha_bytes(&buf), unhex(CHAIN3_SHA256));
        // владелец снимает слои от последнего к первому
        let chain = TunnelLayerChain::from_config(&cfg).unwrap();
        assert_eq!(chain.len(), 3);
        assert!(!chain.is_empty());
        assert_eq!(chain.decrypt(&buf).unwrap(), input());
    }

    #[test]
    fn outbound_chain_matches_vector() {
        let keys = vector_keys();
        let cfg = config_with_keys(false, 3, 2, &keys);
        let chain = TunnelLayerChain::from_config(&cfg).unwrap();
        let pre = chain.decrypt(&input()).unwrap();
        assert_eq!(sha_bytes(&pre), unhex(OWNER3_SHA256));
        // хопы шифруют по порядку — слои сокращаются
        let mut buf = pre;
        for hop in cfg.hops() {
            buf = TunnelEncryption::new(&hop.layer_key, &hop.iv_key)
                .encrypt(&buf)
                .unwrap();
        }
        assert_eq!(buf, input());
    }

    #[test]
    fn chains_roundtrip_for_all_hop_counts() {
        for n in 1..=8usize {
            let keys: Vec<([u8; 32], [u8; 32])> = (0..n)
                .map(|k| {
                    let k = u8::try_from(k).unwrap();
                    ([0x30 + k; 32], [0x60 + k; 32])
                })
                .collect();
            for inbound in [true, false] {
                let cfg = config_with_keys(inbound, n, 3, &keys);
                let chain = TunnelLayerChain::from_config(&cfg).unwrap();
                assert_eq!(chain.len(), n);
                let mut buf = input();
                if inbound {
                    for hop in cfg.hops() {
                        buf = TunnelEncryption::new(&hop.layer_key, &hop.iv_key)
                            .encrypt(&buf)
                            .unwrap();
                    }
                    assert_eq!(chain.decrypt(&buf).unwrap(), input(), "inbound {n}");
                } else {
                    buf = chain.decrypt(&buf).unwrap();
                    for hop in cfg.hops() {
                        buf = TunnelEncryption::new(&hop.layer_key, &hop.iv_key)
                            .encrypt(&buf)
                            .unwrap();
                    }
                    assert_eq!(buf, input(), "outbound {n}");
                }
            }
        }
    }

    #[test]
    fn chain_order_matters() {
        let keys = vector_keys();
        let cfg = config_with_keys(true, 3, 4, &keys);
        let mut buf = input();
        for hop in cfg.hops() {
            buf = TunnelEncryption::new(&hop.layer_key, &hop.iv_key)
                .encrypt(&buf)
                .unwrap();
        }
        // расшифровка от первого к последнему не восстанавливает данные
        let mut wrong = buf;
        for hop in cfg.hops() {
            wrong = TunnelDecryption::new(&hop.layer_key, &hop.iv_key)
                .decrypt(&wrong)
                .unwrap();
        }
        assert_ne!(wrong, input());
    }

    #[test]
    fn chain_tunnel_data_keeps_tunnel_id() {
        let keys = vector_keys();
        let cfg = config_with_keys(true, 3, 5, &keys);
        let mut msg = tunnel_data();
        for hop in cfg.hops() {
            msg = TunnelEncryption::new(&hop.layer_key, &hop.iv_key)
                .encrypt_tunnel_data(&msg)
                .unwrap();
        }
        let chain = TunnelLayerChain::from_config(&cfg).unwrap();
        let back = chain.decrypt_tunnel_data(&msg).unwrap();
        assert_eq!(back, tunnel_data());
    }

    #[test]
    fn chain_requires_keys_to_be_set() {
        let mut keys = vector_keys();
        // у второго хопа не выведены ключи
        keys[1] = ([0; 32], [0x41; 32]);
        let cfg = config_with_keys(true, 3, 6, &keys);
        assert!(matches!(
            TunnelLayerChain::from_config(&cfg),
            Err(I2PError::Malformed(_))
        ));
        keys[1] = ([0x21; 32], [0; 32]);
        let cfg = config_with_keys(true, 3, 6, &keys);
        assert!(TunnelLayerChain::from_config(&cfg).is_err());
    }

    #[test]
    fn default_chain_is_empty_identity() {
        let chain = TunnelLayerChain::default();
        assert!(chain.is_empty());
        assert_eq!(chain.decrypt(&input()).unwrap(), input());
    }
}
