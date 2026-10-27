#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use uu_i2p::{
        I2PAddress, I2PTag, IdentHash, NetDb,
        netdb::xor_distance,
        private_keys::I2PPrivateKeys,
        router_info::{FullRouterInfo, RouterInfo, RouterInfoCaps},
    };

    /// Собирает «достижимый по правилам i2pd» RI: опубликованный
    /// NTCP2-адрес, `netId` и `router.version`.
    ///
    /// Иначе `I2pdReachability` (дефолт [`NetDb`]) отбросил бы такой RI
    /// из выбора флудфиллов и ответов на `DatabaseLookup` — см.
    /// `RouterInfo.cpp:508`.
    fn make_ri(seed: u8, timestamp: u64, floodfill: bool) -> FullRouterInfo {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        // Идентичность разная из-за rand; `seed` нужен только чтобы у
        // вызывающего было чем различать RI в отладочном выводе.
        let _ = seed;

        let caps = if floodfill {
            RouterInfoCaps::parse(b"fR")
        } else {
            RouterInfoCaps::parse(b"R")
        };
        let body = RouterInfo::builder()
            .timestamp(timestamp)
            .caps(caps)
            .version(970)
            .net_id(2)
            .add_address(I2PAddress::ntcp2_published(
                "127.0.0.1".parse().unwrap(),
                9000,
                I2PTag::from_array([0x11; 32]),
                [0x22; 16],
            ))
            .build();
        FullRouterInfo::from_keys(&keys, body).unwrap()
    }

    /// RI без единого адреса — i2pd считает такой недостижимым.
    fn make_unreachable_ri(timestamp: u64, floodfill: bool) -> FullRouterInfo {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let caps = if floodfill {
            RouterInfoCaps::parse(b"fR")
        } else {
            RouterInfoCaps::parse(b"R")
        };
        let body = RouterInfo::builder()
            .timestamp(timestamp)
            .caps(caps)
            .version(970)
            .net_id(2)
            .build();
        FullRouterInfo::from_keys(&keys, body).unwrap()
    }

    fn ident(seed: u8) -> IdentHash {
        I2PTag::from_array([seed; 32])
    }

    // ---- базовые операции -----------------------------------------------

    #[test]
    fn empty_store() {
        let db = NetDb::new();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        assert!(!db.contains(&ident(1)));
        assert!(db.get(&ident(1)).is_none());
    }

    #[test]
    fn insert_and_get() {
        let mut db = NetDb::new();
        let ri = make_ri(1, 100, false);
        let h = *ri.ident_hash();

        assert!(db.insert(ri));
        assert_eq!(db.len(), 1);
        assert!(db.contains(&h));

        let got = db.get(&h).unwrap();
        assert_eq!(got.ident_hash(), &h);
    }

    #[test]
    fn insert_same_ri_twice_is_noop() {
        let mut db = NetDb::new();
        let ri = make_ri(1, 100, false);
        let h = *ri.ident_hash();

        assert!(db.insert(ri.clone()));
        assert!(!db.insert(ri));
        assert_eq!(db.len(), 1);
        assert_eq!(db.get(&h).unwrap().body().timestamp, 100);
    }

    #[test]
    fn insert_updates_when_newer() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body_old = RouterInfo::builder().timestamp(100).build();
        let body_new = RouterInfo::builder().timestamp(200).build();
        let ri_old = FullRouterInfo::from_keys(&keys, body_old).unwrap();
        let ri_new = FullRouterInfo::from_keys(&keys, body_new).unwrap();
        let h = *ri_old.ident_hash();

        let mut db = NetDb::new();
        assert!(db.insert(ri_old));
        assert!(db.insert(ri_new));
        assert_eq!(db.get(&h).unwrap().body().timestamp, 200);
    }

    #[test]
    fn insert_ignores_when_older() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body_old = RouterInfo::builder().timestamp(100).build();
        let body_new = RouterInfo::builder().timestamp(200).build();
        let ri_old = FullRouterInfo::from_keys(&keys, body_old).unwrap();
        let ri_new = FullRouterInfo::from_keys(&keys, body_new).unwrap();
        let h = *ri_old.ident_hash();

        let mut db = NetDb::new();
        assert!(db.insert(ri_new));
        assert!(!db.insert(ri_old));
        assert_eq!(db.get(&h).unwrap().body().timestamp, 200);
    }

    #[test]
    fn insert_ignores_when_equal_timestamp() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body1 = RouterInfo::builder().timestamp(100).build();
        let body2 = RouterInfo::builder().timestamp(100).build();
        let ri1 = FullRouterInfo::from_keys(&keys, body1).unwrap();
        let ri2 = FullRouterInfo::from_keys(&keys, body2).unwrap();

        let mut db = NetDb::new();
        assert!(db.insert(ri1));
        assert!(!db.insert(ri2), "equal timestamp must not replace");
    }

    #[test]
    fn remove_returns_ri() {
        let mut db = NetDb::new();
        let ri = make_ri(1, 100, false);
        let h = *ri.ident_hash();
        db.insert(ri);

        let removed = db.remove(&h).unwrap();
        assert_eq!(removed.ident_hash(), &h);
        assert!(db.is_empty());
        assert!(db.remove(&h).is_none());
    }

    #[test]
    fn clear_empties_store() {
        let mut db = NetDb::new();
        for s in 0..10 {
            db.insert(make_ri(s, 100, false));
        }
        assert_eq!(db.len(), 10);
        db.clear();
        assert!(db.is_empty());
    }

    // ---- floodfills -----------------------------------------------------

    #[test]
    fn floodfills_filters_by_caps() {
        let mut db = NetDb::new();
        db.insert(make_ri(1, 100, true));
        db.insert(make_ri(2, 100, false));
        db.insert(make_ri(3, 100, true));

        let floods: Vec<_> = db.floodfills().collect();
        assert_eq!(floods.len(), 2);
        for (_, ri) in &floods {
            assert!(ri.body().caps.is_floodfill());
        }
    }

    #[test]
    fn floodfills_empty_when_no_floodfill() {
        let mut db = NetDb::new();
        for s in 0..5 {
            db.insert(make_ri(s, 100, false));
        }
        assert_eq!(db.floodfills().count(), 0);
    }

    // ---- closest_to -----------------------------------------------------

    #[test]
    fn xor_distance_basic() {
        let a = I2PTag::from_array([0u8; 32]);
        let b = I2PTag::from_array([0u8; 32]);
        assert_eq!(xor_distance(&a, &b), [0u8; 32]);

        let mut c = [0u8; 32];
        c[0] = 0xFF;
        let c = I2PTag::from_array(c);
        let d = xor_distance(&a, &c);
        assert_eq!(d[0], 0xFF);
        assert!(d[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn xor_distance_is_symmetric() {
        let a = I2PTag::from_array([0x11; 32]);
        let b = I2PTag::from_array([0x22; 32]);
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn closest_to_returns_sorted_by_distance() {
        // Создаём фейковые RI с известными идентичностями — но
        // они генерируются случайно. Значит, проверяем свойство:
        // среди возвращённых `n` расстояние монотонно возрастает.
        let mut db = NetDb::new();
        for s in 0..20 {
            db.insert(make_ri(s, 100, false));
        }
        let target = ident(0x77);
        let closest = db.closest_to(&target, 5, |_| true);
        assert_eq!(closest.len(), 5);

        let distances: Vec<_> = closest
            .iter()
            .map(|ri| xor_distance(ri.ident_hash(), &target))
            .collect();
        for w in distances.windows(2) {
            assert!(w[0] <= w[1], "distances must be non-decreasing");
        }
    }

    #[test]
    fn closest_to_zero_returns_empty() {
        let mut db = NetDb::new();
        db.insert(make_ri(1, 100, false));
        let closest = db.closest_to(&ident(0), 0, |_| true);
        assert_eq!(closest.len(), 0);
    }

    #[test]
    fn closest_to_more_than_available() {
        let mut db = NetDb::new();
        db.insert(make_ri(1, 100, false));
        db.insert(make_ri(2, 100, false));
        let closest = db.closest_to(&ident(0), 10, |_| true);
        assert_eq!(closest.len(), 2);
    }

    #[test]
    fn closest_floodfills_only_floodfills() {
        let mut db = NetDb::new();
        for s in 0..10 {
            let is_flood = s % 3 == 0;
            db.insert(make_ri(s, 100, is_flood));
        }
        let floods = db.closest_floodfills(&ident(0), 5);
        assert!(floods.len() <= 5);
        for ri in &floods {
            assert!(ri.body().caps.is_floodfill());
        }
    }

    #[test]
    fn closest_floodfills_excluding_skips_excluded() {
        let mut db = NetDb::new();
        for s in 0..10 {
            db.insert(make_ri(s, 100, true));
        }
        let target = ident(0);
        let all = db.closest_floodfills(&target, 4);
        assert_eq!(all.len(), 4);

        let excluded: HashSet<IdentHash> = [*all[0].ident_hash(), *all[2].ident_hash()]
            .into_iter()
            .collect();
        let filtered = db.closest_floodfills_excluding(&target, 3, &excluded);

        // Исключённые не занимают место в результате: берутся следующие
        // по расстоянию, а не «n минус исключённые».
        assert_eq!(filtered.len(), 3);
        for ri in &filtered {
            assert!(!excluded.contains(ri.ident_hash()));
        }
        assert_eq!(*filtered[0].ident_hash(), *all[1].ident_hash());
        assert_eq!(*filtered[1].ident_hash(), *all[3].ident_hash());
    }

    #[test]
    fn closest_with_filter() {
        let mut db = NetDb::new();
        for s in 0..10 {
            let is_flood = s % 2 == 0;
            db.insert(make_ri(s, 100, is_flood));
        }
        // Фильтр «не floodfill» — берём только обычных.
        let non_floods = db.closest_to(&ident(0), 3, |ri| !ri.body().caps.is_floodfill());
        assert_eq!(non_floods.len(), 3);
        for ri in &non_floods {
            assert!(!ri.body().caps.is_floodfill());
        }
    }

    // ---- retain ---------------------------------------------------------

    #[test]
    fn retain_removes_by_predicate() {
        let mut db = NetDb::new();
        for s in 0..10 {
            db.insert(make_ri(s, u64::from(s) * 100, false));
        }
        // Оставляем только RI с timestamp > 500.
        db.retain(|_, ri| ri.body().timestamp > 500);
        assert!(db.len() < 10);
        for (_, ri) in db.iter() {
            assert!(ri.body().timestamp > 500);
        }
    }

    // ---- iter -----------------------------------------------------------

    #[test]
    fn iter_yields_all() {
        let mut db = NetDb::new();
        for s in 0..5 {
            db.insert(make_ri(s, 100, false));
        }
        let count = db.iter().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn iter_entries_match_get() {
        let mut db = NetDb::new();
        for s in 0..5 {
            db.insert(make_ri(s, 100, false));
        }
        for (h, ri) in db.iter() {
            assert_eq!(db.get(h).unwrap().ident_hash(), ri.ident_hash());
        }
    }

    // ---- достижимость ---------------------------------------------------

    #[test]
    fn reachable_ri_has_valid_addresses_and_transport_mask() {
        let ri = make_ri(1, 100, false);
        assert!(ri.has_valid_addresses());
        assert!(!ri.is_unreachable(2));
        assert_eq!(
            ri.body().reachable_transports().bits(),
            uu_i2p::CompatibleTransports::NTCP2_V4.bits()
        );
    }

    #[test]
    fn ri_without_addresses_is_unreachable() {
        let ri = make_unreachable_ri(100, true);
        assert!(!ri.has_valid_addresses());
        assert!(ri.is_unreachable(2));
    }

    #[test]
    fn foreign_net_id_is_unreachable() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body = RouterInfo::builder()
            .timestamp(100)
            .caps(RouterInfoCaps::parse(b"R"))
            .version(970)
            .net_id(42)
            .add_address(I2PAddress::ntcp2_published(
                "127.0.0.1".parse().unwrap(),
                9000,
                I2PTag::from_array([0x11; 32]),
                [0x22; 16],
            ))
            .build();
        let ri = FullRouterInfo::from_keys(&keys, body).unwrap();
        assert!(ri.is_unreachable(2));
        assert!(!ri.is_unreachable(42));
    }

    #[test]
    fn missing_router_version_is_unreachable() {
        let keys = I2PPrivateKeys::generate_default().unwrap();
        let body = RouterInfo::builder()
            .timestamp(100)
            .caps(RouterInfoCaps::parse(b"R"))
            .net_id(2)
            .add_address(I2PAddress::ntcp2_published(
                "127.0.0.1".parse().unwrap(),
                9000,
                I2PTag::from_array([0x11; 32]),
                [0x22; 16],
            ))
            .build();
        let ri = FullRouterInfo::from_keys(&keys, body).unwrap();
        assert!(ri.is_unreachable(2));
    }

    #[test]
    fn closest_routers_skips_unreachable() {
        let mut db = NetDb::new();
        db.insert(make_ri(1, 100, false));
        let bad = make_unreachable_ri(100, false);
        let bad_hash = *bad.ident_hash();
        db.insert(bad);

        assert_eq!(db.unreachable(&bad_hash), Some(true));
        let picked = db.closest_routers(&ident(0), 5);
        assert_eq!(picked.len(), 1);
        assert_ne!(*picked[0].ident_hash(), bad_hash);
    }

    #[test]
    fn closest_floodfills_skips_unreachable() {
        let mut db = NetDb::new();
        db.insert(make_ri(1, 100, true));
        db.insert(make_unreachable_ri(100, true));

        let floods = db.closest_floodfills(&ident(0), 5);
        assert_eq!(floods.len(), 1);
        assert!(floods[0].has_valid_addresses());
    }

    #[test]
    fn accept_all_reachability_keeps_synthetic_ris() {
        let mut db = NetDb::with_reachability(uu_i2p::AcceptAllReachability);
        db.insert(make_unreachable_ri(100, true));
        db.insert(make_unreachable_ri(100, false));

        assert_eq!(db.closest_routers(&ident(0), 5).len(), 2);
        assert_eq!(db.closest_floodfills(&ident(0), 5).len(), 1);
        for (h, _) in db.iter() {
            assert_eq!(db.unreachable(h), Some(false));
        }
    }

    #[test]
    fn net_db_for_foreign_network_rejects_default_ris() {
        let mut db = NetDb::with_net_id(42);
        db.insert(make_ri(1, 100, true));
        assert_eq!(db.closest_floodfills(&ident(0), 5).len(), 0);
    }
}
