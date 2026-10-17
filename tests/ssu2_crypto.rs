#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use uu_i2p::{
        ssu2_crypto::{
            aead_nonce, derive_data_phase_keys, init_noise_ssu2_state, sess_create_header_key,
            session_confirmed_header_key,
        },
        NoiseSymmetricState,
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

    // ---- golden vectors -------------------------------------------------
    //
    // Независимо сгенерированы Python `cryptography` (HKDF-SHA256) и
    // hashlib (SHA256).

    const CK: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    const SESS_CREATE_HK: &str = "554239989d0ca8482ba2aaee2a54c767942455cc6ce929d41ee09ed4c7ba53f8";
    const SESSION_CONF_HK: &str =
        "506c477666ee5466490f78242e383ce6f688621dece2b96b82346c1cb3ab55a4";

    const DATA_AB: &str = concat!(
        "51ec9db0209a3ac1bb2c636a7d827b2f1596c3d8ce71eecf0fab55d9345a80a8",
        "979ef18094fcc43a1a42368378dc6824e15f121ec94b3a564767a82950509974",
    );
    const DATA_BA: &str = concat!(
        "2ba79fc2b52b396016dcb9fba960a14694cc88c0660415718dcc6e82be03c602",
        "e8ec5a17087cfb8584463cdac2d3688f2546a15d21460a5fb5a837f803b4984b",
    );

    const NOISE_CK: &str = "b13722817423a8fdf42df2e60ed1edf41b93071db1ec24a367f784ec270d8132";
    const NOISE_HH: &str = "dc85e6af7b02650cf1f90d71fbc6d453a7cf6dbfbd525ea5b5791c47b35ebc33";
    const NOISE_PUB: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NOISE_H: &str = "db15dfc72c8a16e0bd4246a9a610b17910b59075cdcc08f078a847837d9693e6";

    // ---- header key KDFs ------------------------------------------------

    #[test]
    fn sess_create_header_key_matches_golden() {
        let ck = hex::<32>(CK);
        assert_eq!(sess_create_header_key(&ck), hex::<32>(SESS_CREATE_HK));
    }

    #[test]
    fn session_confirmed_header_key_matches_golden() {
        let ck = hex::<32>(CK);
        assert_eq!(
            session_confirmed_header_key(&ck),
            hex::<32>(SESSION_CONF_HK)
        );
    }

    #[test]
    fn header_keys_differ() {
        let ck = hex::<32>(CK);
        assert_ne!(
            sess_create_header_key(&ck),
            session_confirmed_header_key(&ck)
        );
    }

    // ---- data phase KDF -------------------------------------------------

    #[test]
    fn data_phase_keys_match_golden() {
        let ck = hex::<32>(CK);
        let keys = derive_data_phase_keys(&ck);

        let ab = hex::<64>(DATA_AB);
        let ba = hex::<64>(DATA_BA);

        assert_eq!(keys.ab.k_data, ab[..32]);
        assert_eq!(keys.ab.k_header_2, ab[32..]);
        assert_eq!(keys.ba.k_data, ba[..32]);
        assert_eq!(keys.ba.k_header_2, ba[32..]);
    }

    #[test]
    fn data_phase_keys_directions_differ() {
        let ck = hex::<32>(CK);
        let keys = derive_data_phase_keys(&ck);
        assert_ne!(keys.ab.k_data, keys.ba.k_data);
        assert_ne!(keys.ab.k_header_2, keys.ba.k_header_2);
        // k_data и k_header_2 одного направления тоже различаются.
        assert_ne!(keys.ab.k_data, keys.ab.k_header_2);
    }

    // ---- Noise init -----------------------------------------------------

    #[test]
    fn noise_init_matches_golden() {
        let pub_key = hex::<32>(NOISE_PUB);
        let mut state = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        init_noise_ssu2_state(&mut state, &pub_key);

        assert_eq!(state.ck, hex::<32>(NOISE_CK));
        assert_eq!(state.h, hex::<32>(NOISE_H));
        assert_eq!(state.k, [0u8; 32]);
        assert_eq!(state.n, 0);
    }

    #[test]
    fn noise_init_h_is_sha256_of_hh_and_pub() {
        let pub_key = hex::<32>(NOISE_PUB);
        let mut state = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        init_noise_ssu2_state(&mut state, &pub_key);

        let mut hasher = Sha256::new();
        hasher.update(hex::<32>(NOISE_HH));
        hasher.update(pub_key);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(state.h, expected);
    }

    // ---- AEAD nonce -----------------------------------------------------

    #[test]
    fn aead_nonce_layout() {
        assert_eq!(aead_nonce(0), [0u8; 12]);
        assert_eq!(aead_nonce(1), [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            aead_nonce(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn aead_nonce_matches_noise_state_nonce() {
        let mut state = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        for n in [0_u64, 1, 42, 0xdead_beef_cafe_babe] {
            state.n = n;
            assert_eq!(aead_nonce(n), state.nonce());
        }
    }
}
