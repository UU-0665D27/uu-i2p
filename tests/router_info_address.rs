#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use uu_i2p::router_info_address::*;
    use uu_i2p::*;

    fn key(n: u8) -> I2PTag<32> {
        I2PTag::from_array([n; 32])
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid IP literal in test")
    }

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    // ---- constructors ---------------------------------------------------

    #[test]
    fn ntcp2_published_basic() {
        let addr = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1234, key(1), [0xaa; 16]);
        assert_eq!(addr.transport_style, TransportStyle::Ntcp2);
        assert_eq!(addr.port, 1234);
        assert!(addr.is_ntcp2());
        assert!(!addr.is_ssu2());
        assert!(addr.is_published_ntcp2());
        assert!(addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(addr.v, 2);
        assert_eq!(addr.s, key(1));
        // первая половина i = IV, вторая — нули
        assert_eq!(&addr.i.as_bytes()[..16], &[0xaa; 16]);
        assert_eq!(&addr.i.as_bytes()[16..], &[0u8; 16]);
        assert!(addr.ssu.is_none());
    }

    #[test]
    fn ntcp2_unpublished_both_families() {
        let addr = I2PAddress::ntcp2_unpublished(0, key(1), [0; 16], true, true);
        assert!(!addr.published);
        assert!(addr.is_v4());
        assert!(addr.is_v6());
        assert!(!addr.is_published_ntcp2());
        assert_eq!(addr.caps, caps::V4 | caps::V6);
    }

    #[test]
    fn ntcp2_unpublished_v4_only() {
        let addr = I2PAddress::ntcp2_unpublished(0, key(1), [0; 16], true, false);
        assert!(addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(addr.caps, caps::V4);
    }

    #[test]
    fn ntcp2_unpublished_neither_family() {
        // вырожденный, но валидный: caps = 0
        let addr = I2PAddress::ntcp2_unpublished(0, key(1), [0; 16], false, false);
        assert!(!addr.is_v4());
        assert!(!addr.is_v6());
        assert_eq!(addr.caps, 0);
    }

    #[test]
    fn ssu2_published_has_bc_caps_and_ext() {
        let addr = I2PAddress::ssu2_published(ip("10.0.0.1"), 5000, key(2), key(3));
        assert!(addr.is_ssu2());
        assert!(!addr.is_ntcp2());
        assert!(addr.published);
        assert!(addr.ssu.is_some());
        assert!(addr.is_peer_testing());
        assert!(addr.is_introducer());
        assert_eq!(addr.caps, caps::SSU_TESTING | caps::SSU_INTRODUCER);
        // пока introducer'ов нет
        assert!(!addr.uses_introducer());
    }

    #[test]
    fn ssu2_unpublished_v4_only() {
        let addr = I2PAddress::ssu2_unpublished(5000, key(2), key(3), true, false);
        assert!(!addr.published);
        assert!(addr.is_v4());
        assert!(!addr.is_v6());
        assert!(!addr.is_peer_testing());
        assert!(!addr.is_introducer());
        // не reachable: ни published, ни introducer'ов
        assert!(!addr.is_reachable_ssu());
    }

    // ---- introducers ----------------------------------------------------

    #[test]
    fn introducer_is_valid_accepts_future_exp() {
        let i = Introducer::new(ident(1), 42, 1000);
        assert!(i.is_valid(0));
        assert!(i.is_valid(999));
    }

    #[test]
    fn introducer_is_valid_rejects_expired() {
        let i = Introducer::new(ident(1), 42, 1000);
        assert!(!i.is_valid(1000)); // exp не включителен
        assert!(!i.is_valid(1001));
    }

    #[test]
    fn introducer_is_valid_rejects_zero_tag() {
        let i = Introducer::new(ident(1), 0, 1000);
        assert!(!i.is_valid(500));
    }

    #[test]
    fn introducer_is_valid_rejects_zero_hash() {
        let i = Introducer::new(IdentHash::from_array([0u8; 32]), 42, 1000);
        assert!(!i.is_valid(500));
    }

    #[test]
    fn introducer_default_is_invalid() {
        let i = Introducer::default();
        assert!(!i.is_valid(0));
        assert!(!i.is_valid(u32::MAX));
    }

    #[test]
    fn uses_introducer_requires_nonempty() {
        let mut addr = I2PAddress::ssu2_published(ip("1.2.3.4"), 5000, key(2), key(3));
        assert!(!addr.uses_introducer());

        addr.ssu
            .as_mut()
            .expect("ssu ext")
            .introducers
            .push(Introducer::new(ident(1), 1, 1000));
        assert!(addr.uses_introducer());
    }

    #[test]
    fn is_reachable_ssu_with_introducer_even_if_not_published() {
        let mut addr = I2PAddress::ssu2_unpublished(5000, key(2), key(3), true, false);
        assert!(!addr.is_reachable_ssu()); // пока пусто

        addr.ssu
            .as_mut()
            .expect("ssu ext")
            .introducers
            .push(Introducer::new(ident(1), 1, 1000));
        assert!(addr.is_reachable_ssu()); // появился introducer
    }

    #[test]
    fn is_reachable_ssu_false_for_ntcp2() {
        let addr = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1234, key(1), [0; 16]);
        assert!(!addr.is_reachable_ssu());
    }

    // ---- subnet ---------------------------------------------------------

    #[test]
    fn same_subnet_v4_24_positive() {
        let a = I2PAddress::ntcp2_published(ip("10.0.0.1"), 1, key(1), [0; 16]);
        let b = I2PAddress::ntcp2_published(ip("10.0.0.2"), 2, key(2), [0; 16]);
        assert!(a.is_same_subnet(&b));
        assert!(b.is_same_subnet(&a));
    }

    #[test]
    fn same_subnet_v4_24_negative() {
        let a = I2PAddress::ntcp2_published(ip("10.0.0.1"), 1, key(1), [0; 16]);
        let c = I2PAddress::ntcp2_published(ip("10.0.1.1"), 3, key(3), [0; 16]);
        assert!(!a.is_same_subnet(&c));
    }

    #[test]
    fn same_subnet_v6_56_positive() {
        let a =
            I2PAddress::ntcp2_published("2001:db8:1:2:3:4:5:6".parse().unwrap(), 1, key(1), [0; 16]);
        let b =
            I2PAddress::ntcp2_published("2001:db8:1:2:3:4:5:7".parse().unwrap(), 2, key(2), [0; 16]);
        assert!(a.is_same_subnet(&b));
    }

    #[test]
    fn same_subnet_v6_56_negative() {
        let a =
            I2PAddress::ntcp2_published("2001:db8:1:2:3:4:5:6".parse().unwrap(), 1, key(1), [0; 16]);
        // отличие в сегменте 3 (байт 5), а он входит в /56
        let c =
            I2PAddress::ntcp2_published("2001:db8:2:0:0:0:0:0".parse().unwrap(), 3, key(3), [0; 16]);
        assert!(!a.is_same_subnet(&c));
    }
    #[test]
    fn same_subnet_unspecified_is_false() {
        let a = I2PAddress::ntcp2_unpublished(0, key(1), [0; 16], true, false);
        let b = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1, key(2), [0; 16]);
        assert!(!a.is_same_subnet(&b));
        assert!(!b.is_same_subnet(&a));
    }

    #[test]
    fn same_subnet_different_family_is_false() {
        let a = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1, key(1), [0; 16]);
        let b = I2PAddress::ntcp2_published(ip("::1"), 2, key(2), [0; 16]);
        assert!(!a.is_same_subnet(&b));
    }
    /// Граница /56 проходит ровно по байту 7: байт 6 ещё входит в префикс,
    /// байт 7 — уже нет.
    ///
    /// a = 2001:db8:1:2:3:4:5:6
    /// b = 2001:db8:1:3:...   ← отличие в байте 7 (второй байт сегмента 4)
    /// → одна /56-подсеть.
    #[test]
    fn same_subnet_v6_56_boundary_byte7_is_outside() {
        let a =
            I2PAddress::ntcp2_published("2001:db8:1:2:3:4:5:6".parse().unwrap(), 1, key(1), [0; 16]);
        let b =
            I2PAddress::ntcp2_published("2001:db8:1:3:0:0:0:0".parse().unwrap(), 2, key(2), [0; 16]);
        assert!(
            a.is_same_subnet(&b),
            "byte 7 is outside /56, addresses must be in the same subnet"
        );
    }

    /// Отличие в байте 6 (первый байт сегмента 4) — уже разные /56-подсети.
    ///
    /// a = 2001:db8:1:02xx:...
    /// c = 2001:db8:1:03xx:...   ← байт 6: 0x02 vs 0x03
    /// → разные /56.
    #[test]
    fn same_subnet_v6_56_boundary_byte6_is_inside() {
        let a = I2PAddress::ntcp2_published("2001:db8:1:0200::".parse().unwrap(), 1, key(1), [0; 16]);
        let c = I2PAddress::ntcp2_published("2001:db8:1:0300::".parse().unwrap(), 2, key(2), [0; 16]);
        assert!(
            !a.is_same_subnet(&c),
            "byte 6 is inside /56, addresses must be in different subnets"
        );
    }
    #[test]
    fn constructors_set_cost_per_i2pd() {
        let ntcp2_pub = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1234, key(1), [0; 16]);
        let ntcp2_unp = I2PAddress::ntcp2_unpublished(0, key(1), [0; 16], true, false);
        let ssu2_pub = I2PAddress::ssu2_published(ip("1.2.3.4"), 5000, key(2), key(3));
        let ssu2_unp = I2PAddress::ssu2_unpublished(0, key(2), key(3), true, false);
        assert_eq!(ntcp2_pub.cost(), cost::NTCP2_PUBLISHED);
        assert_eq!(ntcp2_unp.cost(), cost::NTCP2_NON_PUBLISHED);
        assert_eq!(ssu2_pub.cost(), cost::SSU2_DIRECT);
        assert_eq!(ssu2_unp.cost(), cost::SSU2_NON_PUBLISHED);
    }

    #[test]
    fn cost_constants_match_i2pd() {
        assert_eq!(cost::NTCP2_PUBLISHED, 3);
        assert_eq!(cost::NTCP2_NON_PUBLISHED, 14);
        assert_eq!(cost::SSU2_DIRECT, 8);
        assert_eq!(cost::SSU2_NON_PUBLISHED, 15);
    }
    // ---- caps -----------------------------------------------------------

    #[test]
    fn caps_parse_known_flags() {
        assert_eq!(caps::parse("4"), caps::V4);
        assert_eq!(caps::parse("6"), caps::V6);
        assert_eq!(caps::parse("BC"), caps::SSU_TESTING | caps::SSU_INTRODUCER);
        assert_eq!(caps::parse("46BC"), 0x0F);
        assert_eq!(caps::parse(""), 0);
    }

    #[test]
    fn caps_parse_unknown_ignored() {
        assert_eq!(caps::parse("X"), 0);
        assert_eq!(caps::parse("4X6"), caps::V4 | caps::V6);
    }

    #[test]
    fn caps_to_string_empty_for_zero() {
        assert_eq!(caps::to_string(0), "");
    }

    #[test]
    fn caps_to_string_roundtrip_all_masks() {
        // Все 16 возможных битовых комбинаций должны пережить roundtrip.
        for v in 0u8..16 {
            let s = caps::to_string(v);
            let back = caps::parse(&s);
            assert_eq!(back, v, "caps {v:#04x} -> {s:?} -> {back:#04x}");
        }
    }

    // ---- compatibility --------------------------------------------------

    #[test]
    fn is_compatible_with_same_family() {
        let a = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1, key(1), [0; 16]);
        assert!(a.is_compatible_with(&ip("5.6.7.8")));
        assert!(!a.is_compatible_with(&ip("::1")));
    }

    #[test]
    fn is_compatible_with_v6() {
        let a = I2PAddress::ntcp2_published(ip("::1"), 1, key(1), [0; 16]);
        assert!(a.is_compatible_with(&ip("2001:db8::1")));
        assert!(!a.is_compatible_with(&ip("10.0.0.1")));
    }

    #[test]
    fn is_compatible_with_unpublished_uses_caps() {
        let a = I2PAddress::ntcp2_unpublished(0, key(1), [0; 16], false, true);
        assert!(a.is_compatible_with(&ip("2001:db8::1")));
        assert!(!a.is_compatible_with(&ip("10.0.0.1")));
    }

    // ---- equality -------------------------------------------------------

    #[test]
    fn equality_compares_all_fields() {
        let a = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1, key(1), [0; 16]);
        let b = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1, key(1), [0; 16]);
        let c = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1, key(2), [0; 16]);
        let d = I2PAddress::ntcp2_published(ip("1.2.3.5"), 1, key(1), [0; 16]);
        assert_eq!(a, b);
        assert_ne!(a, c, "different s keys must not be equal");
        assert_ne!(a, d, "different hosts must not be equal");
    }

    #[test]
    fn equality_distinguishes_transports() {
        let a = I2PAddress::ntcp2_published(ip("1.2.3.4"), 1, key(1), [0; 16]);
        let b = I2PAddress::ssu2_published(ip("1.2.3.4"), 1, key(1), key(1));
        assert_ne!(a, b);
    }

    // ---- display --------------------------------------------------------

    #[test]
    fn transport_style_name() {
        assert_eq!(TransportStyle::Ntcp2.name(), "NTCP2");
        assert_eq!(TransportStyle::Ssu2.name(), "SSU2");
        assert_eq!(TransportStyle::Unknown.name(), "");
    }

    #[test]
    fn transport_style_display_matches_name() {
        for t in [
            TransportStyle::Unknown,
            TransportStyle::Ntcp2,
            TransportStyle::Ssu2,
        ] {
            assert_eq!(format!("{t}"), t.name());
        }
    }

    // ---- SsuExt ---------------------------------------------------------

    #[test]
    fn ssu_ext_new_is_empty() {
        let e = SsuExt::new();
        assert_eq!(e.mtu, 0);
        assert!(
            e.introducers.is_empty(),
            "SSU ext introducers must be empty"
        );
        assert_eq!(e, SsuExt::default());
    }
}
