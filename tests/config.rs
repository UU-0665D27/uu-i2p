#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use uu_i2p::{
        DEFAULT_NET_ID, DEFAULT_VERSION, I2PPrivateKeys, I2PX25519Keys, ListenEndpoint,
        RouterConfig, error::I2PError,
    };

    fn keys() -> I2PPrivateKeys {
        I2PPrivateKeys::generate_default().unwrap()
    }

    fn ntcp2() -> (I2PX25519Keys, [u8; 16]) {
        (I2PX25519Keys::generate(), [0x42u8; 16])
    }

    fn minimal_config() -> RouterConfig {
        let (static_key, iv) = ntcp2();
        RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_unpublished("127.0.0.1:2827".parse().unwrap())
            .build()
            .unwrap()
    }

    // ---- builder validation ---------------------------------------------

    #[test]
    fn missing_keys_fails() {
        let (static_key, iv) = ntcp2();
        let r = RouterConfig::builder()
            .ntcp2_keys(static_key, iv)
            .listen_unpublished("127.0.0.1:2827".parse().unwrap())
            .build();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn missing_ntcp2_keys_fails() {
        let r = RouterConfig::builder()
            .keys(keys())
            .listen_unpublished("127.0.0.1:2827".parse().unwrap())
            .build();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn missing_listen_fails() {
        let (static_key, iv) = ntcp2();
        let r = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .build();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn advertise_unspecified_fails() {
        let (static_key, iv) = ntcp2();
        let r = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_published(
                "0.0.0.0:2827".parse().unwrap(),
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            )
            .build();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn advertise_loopback_fails() {
        let (static_key, iv) = ntcp2();
        let r = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_published(
                "0.0.0.0:2827".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            )
            .build();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn advertise_multicast_fails() {
        let (static_key, iv) = ntcp2();
        let r = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_published(
                "0.0.0.0:2827".parse().unwrap(),
                "224.0.0.1".parse().unwrap(),
            )
            .build();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[test]
    fn advertise_port_zero_fails() {
        let (static_key, iv) = ntcp2();
        let r = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_published("0.0.0.0:0".parse().unwrap(), "1.2.3.4".parse().unwrap())
            .build();
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    // ---- defaults -------------------------------------------------------

    #[test]
    fn defaults_are_applied() {
        let cfg = minimal_config();
        assert_eq!(cfg.net_id(), DEFAULT_NET_ID);
        assert_eq!(cfg.version(), DEFAULT_VERSION);
        assert!(!cfg.is_floodfill());
        // Дефолтный caps печатается как "L".
        assert_eq!(cfg.caps().to_string(), "L");
    }

    #[test]
    fn version_and_net_id_override() {
        let (static_key, iv) = ntcp2();
        let cfg = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_unpublished("127.0.0.1:0".parse().unwrap())
            .version(1234)
            .net_id(42)
            .build()
            .unwrap();
        assert_eq!(cfg.version(), 1234);
        assert_eq!(cfg.net_id(), 42);
    }

    // ---- ListenEndpoint ------------------------------------------------

    #[test]
    fn auto_endpoint_unspecified_is_unpublished() {
        let ep = ListenEndpoint::auto("0.0.0.0:2827".parse().unwrap());
        assert!(ep.advertise.is_none());
    }

    #[test]
    fn auto_endpoint_specific_is_published() {
        let ep = ListenEndpoint::auto("1.2.3.4:2827".parse().unwrap());
        assert_eq!(ep.advertise, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn multiple_endpoints() {
        let (static_key, iv) = ntcp2();
        let cfg = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_unpublished("0.0.0.0:2827".parse().unwrap())
            .listen_published("0.0.0.0:2827".parse().unwrap(), "1.2.3.4".parse().unwrap())
            .listen_unpublished("[::]:2827".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(cfg.listen().len(), 3);
    }

    // ---- build_router_info ---------------------------------------------

    #[test]
    fn build_router_info_unpublished_has_no_published_address() {
        let cfg = minimal_config();
        let ri = cfg.build_router_info(1_700_000_000_000).unwrap();
        assert_eq!(ri.body().addresses.len(), 1);
        assert!(!ri.body().addresses[0].published);
        assert!(ri.body().addresses[0].host.is_unspecified());
    }

    #[test]
    fn build_router_info_published_has_ip() {
        let (static_key, iv) = ntcp2();
        let cfg = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_published("0.0.0.0:2827".parse().unwrap(), "1.2.3.4".parse().unwrap())
            .build()
            .unwrap();
        let ri = cfg.build_router_info(1_700_000_000_000).unwrap();
        assert_eq!(ri.body().addresses.len(), 1);
        let addr = &ri.body().addresses[0];
        assert!(addr.published);
        assert_eq!(addr.host, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port, 2827);
    }

    #[test]
    fn build_router_info_has_version_and_net_id() {
        let cfg = minimal_config();
        let ri = cfg.build_router_info(1_700_000_000_000).unwrap();
        assert_eq!(ri.body().version, Some(DEFAULT_VERSION));
        assert_eq!(ri.body().net_id, Some(i32::from(DEFAULT_NET_ID)));
    }

    #[test]
    fn build_router_info_floodfill_sets_caps() {
        let (static_key, iv) = ntcp2();
        let cfg = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_unpublished("127.0.0.1:0".parse().unwrap())
            .floodfill(true)
            .build()
            .unwrap();
        let ri = cfg.build_router_info(1_700_000_000_000).unwrap();
        assert!(ri.body().caps.is_floodfill());
    }

    #[test]
    fn build_router_info_signature_verifies() {
        let cfg = minimal_config();
        let ri = cfg.build_router_info(1_700_000_000_000).unwrap();
        let buf = ri.to_buffer().unwrap();
        ri.verify(&buf).unwrap();
        assert_eq!(ri.ident_hash(), cfg.keys().public().ident_hash());
    }

    #[test]
    fn build_router_info_multiple_addresses() {
        let (static_key, iv) = ntcp2();
        let cfg = RouterConfig::builder()
            .keys(keys())
            .ntcp2_keys(static_key, iv)
            .listen_published("0.0.0.0:2827".parse().unwrap(), "1.2.3.4".parse().unwrap())
            .listen_unpublished("[::]:2827".parse().unwrap())
            .build()
            .unwrap();
        let ri = cfg.build_router_info(1_700_000_000_000).unwrap();
        assert_eq!(ri.body().addresses.len(), 2);
    }

    // ---- Debug ---------------------------------------------------------

    #[test]
    fn debug_does_not_panic() {
        let cfg = minimal_config();
        let s = format!("{cfg:?}");
        assert!(s.contains("RouterConfig"));
        // Публичный ключ NTCP2 — не секрет, попадает в вывод.
        assert!(s.contains("ntcp2_public"));
    }
}
