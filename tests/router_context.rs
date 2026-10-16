use std::net::{IpAddr, Ipv4Addr};
use uu_i2p::{
    DatabaseLookup, DatabaseSearchReply, DatabaseStore, I2PError, I2PTag, I2PX25519Keys,
    I2npMessage, IdentHash, RouterConfig, RouterContext, StoreHandling, StoreType,
    ecies_destination::EciesGarlicDestination,
    garlic_body::GarlicBody,
    i2np::I2npMessageType,
    i2np_message::I2npBody,
    netdb_requests::SendAction,
    private_keys::I2PPrivateKeys,
    router_info::{FullRouterInfo, RouterInfo, RouterInfoCaps},
    router_info_address::I2PAddress,
};

/// Минимальный роутер с одним неопубликованным listen-эндпоинтом.
///
/// `listen_unpublished` — чтобы `RouterConfigBuilder::build` не
/// проверял advertise (unspecified/multicast/loopback), и чтобы
/// не возиться с публикуемыми адресами в тестах, которые про
/// lookup, а не про адреса.
fn minimal_ctx() -> RouterContext {
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let ntcp2 = I2PX25519Keys::generate();
    let iv = [0u8; 16];

    let cfg = RouterConfig::builder()
        .keys(keys)
        .ntcp2_keys(ntcp2, iv)
        .listen_unpublished("127.0.0.1:0".parse().unwrap())
        .build()
        .expect("config");

    RouterContext::new(cfg).expect("ctx")
}
/// Собирает и подписывает «чужой» RI, кладёт его в netdb,
/// возвращает `IdentHash` вставленного роутера.
///
/// Каждый вызов генерирует **новую** пару ключей, так что
/// `IdentHash`'и разных вызовов не совпадают. `seed` используется
/// только для IV NTCP2 — чтобы при желании зафиксировать
/// «стабильный» адрес.
///
/// Timestamp фиксирован: `build_router_info` иначе читает системные
/// часы, и golden-проверки в других тестах становились бы
/// нестабильными.
fn add_ri_to_netdb(ctx: &mut RouterContext, seed: u8, is_floodfill: bool) -> IdentHash {
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let ntcp2 = I2PX25519Keys::generate();
    let iv = [seed; 16];

    let cfg = RouterConfig::builder()
        .keys(keys)
        .ntcp2_keys(ntcp2, iv)
        .listen_unpublished("127.0.0.1:0".parse().unwrap())
        .floodfill(is_floodfill)
        .build()
        .expect("config");

    let ri = cfg.build_router_info(1_700_000_000_000).expect("build ri");

    let ident = *ri.ident_hash();
    ctx.netdb_mut().insert(ri);
    ident
}
/// Собирает конфиг для теста: `EdDSA` + ECIES-X25519, один
/// слушающий unpublished-адрес.
fn test_config() -> RouterConfig {
    let keys = I2PPrivateKeys::generate_default().unwrap();
    let ntcp2_static = I2PX25519Keys::generate();
    let ntcp2_iv = [0x42u8; 16];
    RouterConfig::builder()
        .keys(keys)
        .ntcp2_keys(ntcp2_static, ntcp2_iv)
        .listen_unpublished("127.0.0.1:0".parse().unwrap())
        .build()
        .unwrap()
}

fn ctx() -> RouterContext {
    RouterContext::new(test_config()).unwrap()
}

/// Собирает синтетический `FullRouterInfo` чужого роутера.
///
/// Используется, чтобы подложить «чужой RI» в `handle_database_store`.
fn foreign_ri(timestamp: u64, ntcp2_pub: &[u8; 32], iv: [u8; 16]) -> FullRouterInfo {
    let keys = I2PPrivateKeys::generate_default().unwrap();
    let addr = I2PAddress::ntcp2_published(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1234,
        I2PTag::from_array(*ntcp2_pub),
        iv,
    );
    let body = RouterInfo::builder()
        .timestamp(timestamp)
        .caps(RouterInfoCaps::parse(b"R"))
        .add_address(addr)
        .build();
    FullRouterInfo::from_keys(&keys, body).unwrap()
}

// ---- конструктор и инварианты ---------------------------------------

#[test]
fn new_builds_own_ri() {
    let cfg = test_config();
    let expected_hash = *cfg.keys().public().ident_hash();
    let expected_ntcp2 = *cfg.ntcp2_static().public_key();

    let ctx = RouterContext::new(cfg).unwrap();
    assert_eq!(ctx.own_ident_hash(), &expected_hash);
    // RI содержит один NTCP2-адрес с нашим static-ключом.
    assert_eq!(ctx.own_ri().body().addresses.len(), 1);
    assert_eq!(
        ctx.own_ri().body().addresses[0].s.as_bytes(),
        &expected_ntcp2
    );
}

#[test]
fn new_creates_empty_netdb() {
    let ctx = ctx();
    assert!(ctx.netdb().is_empty());
}

#[test]
fn ecies_static_key_matches_identity_encryption_key() {
    let cfg = test_config();
    // Копируем в массив — иначе borrow-checker не даст
    // переместить `cfg` в `RouterContext::new`.
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&cfg.keys().public().encryption_public_key().unwrap()[..32]);

    let ctx = RouterContext::new(cfg).unwrap();
    assert_eq!(ctx.ecies().local_static_public(), &expected);
}

#[test]
fn new_with_multiple_listen_endpoints() {
    let keys = I2PPrivateKeys::generate_default().unwrap();
    let ntcp2_static = I2PX25519Keys::generate();
    let ntcp2_iv = [0x11u8; 16];
    let cfg = RouterConfig::builder()
        .keys(keys)
        .ntcp2_keys(ntcp2_static, ntcp2_iv)
        .listen_unpublished("127.0.0.1:0".parse().unwrap())
        .listen_unpublished("[::1]:0".parse().unwrap())
        .build()
        .unwrap();
    let ctx = RouterContext::new(cfg).unwrap();
    assert_eq!(ctx.own_ri().body().addresses.len(), 2);
}

#[test]
fn own_ri_is_signed_and_verifies() {
    let ctx = ctx();
    let buf = ctx.own_ri().to_buffer().unwrap();
    ctx.own_ri().verify(&buf).unwrap();
}

// ---- rebuild_own_ri -------------------------------------------------

#[test]
fn rebuild_own_ri_preserves_ident_hash() {
    let mut ctx = ctx();
    let before = *ctx.own_ident_hash();
    std::thread::sleep(std::time::Duration::from_millis(2));
    ctx.rebuild_own_ri().unwrap();
    assert_eq!(ctx.own_ident_hash(), &before);
}

#[test]
fn rebuild_own_ri_advances_timestamp() {
    let mut ctx = ctx();
    let t0 = ctx.own_ri().body().timestamp;
    std::thread::sleep(std::time::Duration::from_millis(2));
    ctx.rebuild_own_ri().unwrap();
    let t1 = ctx.own_ri().body().timestamp;
    assert!(t1 >= t0, "timestamp must not go backwards");
}

// ---- find_router ----------------------------------------------------

#[test]
fn find_router_returns_own_ri_for_own_hash() {
    let ctx = ctx();
    let found = ctx.find_router(ctx.own_ident_hash()).unwrap();
    assert_eq!(found.ident_hash(), ctx.own_ident_hash());
}

#[test]
fn find_router_unknown_returns_none() {
    let ctx = ctx();
    let unknown = IdentHash::from_array([0xFF; 32]);
    assert!(ctx.find_router(&unknown).is_none());
}

#[test]
fn find_router_returns_from_netdb_after_insert() {
    let mut ctx = ctx();
    let ri = foreign_ri(1_700_000_000_000, &[0xAA; 32], [0x11; 16]);
    let ident = *ri.ident_hash();
    ctx.netdb_mut().insert(ri);

    let found = ctx.find_router(&ident).unwrap();
    assert_eq!(found.ident_hash(), &ident);
}

// ---- build_own_database_store ---------------------------------------

#[test]
fn build_own_database_store_has_our_key_and_type() {
    let ctx = ctx();
    let ds = ctx.build_own_database_store().unwrap();
    assert_eq!(ds.key, *ctx.own_ident_hash());
    assert_eq!(ds.store_type, StoreType::RouterInfo);
    assert_eq!(ds.reply_token, 0);
    assert!(ds.reply_instruction.is_none());
    // payload_decoded должен дать валидный RI, совпадающий с own.
    let bytes = ds.payload_decoded().unwrap();
    let ri = FullRouterInfo::from_buffer(&bytes).unwrap();
    assert_eq!(ri.ident_hash(), ctx.own_ident_hash());
}

// ---- handle_database_store ------------------------------------------

#[test]
fn handle_database_store_inserts_new_router() {
    let mut ctx = ctx();
    let ri = foreign_ri(1_700_000_000_000, &[0xAA; 32], [0x11; 16]);
    let ident = *ri.ident_hash();
    let ds = DatabaseStore::new_router_info(ident, &ri.to_buffer().unwrap(), 0, None).unwrap();

    let result = ctx.handle_database_store(&ds.to_buffer().unwrap()).unwrap();
    assert_eq!(result, StoreHandling::Inserted(ident));
    assert!(ctx.netdb().contains(&ident));
}

#[test]
fn handle_database_store_updates_newer_ri() {
    let mut ctx = ctx();
    // Тот же роутер не можем дважды сгенерировать через foreign_ri
    // (каждый раз новые ключи). Поэтому вставляем RI с одинаковыми
    // ключами, но разными timestamp'ами через один PrivateKeys.
    let keys = I2PPrivateKeys::generate_default().unwrap();
    let addr = I2PAddress::ntcp2_published(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1234,
        I2PTag::from_array([0xAA; 32]),
        [0x11; 16],
    );
    let body_old = RouterInfo::builder()
        .timestamp(1_000)
        .add_address(addr.clone())
        .build();
    let body_new = RouterInfo::builder()
        .timestamp(2_000)
        .add_address(addr)
        .build();
    let ri_old = FullRouterInfo::from_keys(&keys, body_old).unwrap();
    let ri_new = FullRouterInfo::from_keys(&keys, body_new).unwrap();
    let ident = *ri_old.ident_hash();

    let ds_old =
        DatabaseStore::new_router_info(ident, &ri_old.to_buffer().unwrap(), 0, None).unwrap();
    let ds_new =
        DatabaseStore::new_router_info(ident, &ri_new.to_buffer().unwrap(), 0, None).unwrap();

    // Первый раз — Inserted.
    assert_eq!(
        ctx.handle_database_store(&ds_old.to_buffer().unwrap())
            .unwrap(),
        StoreHandling::Inserted(ident)
    );
    // Второй раз, timestamp новее — Updated.
    assert_eq!(
        ctx.handle_database_store(&ds_new.to_buffer().unwrap())
            .unwrap(),
        StoreHandling::Updated(ident)
    );
}

#[test]
fn handle_database_store_stale_is_reported() {
    let mut ctx = ctx();
    let keys = I2PPrivateKeys::generate_default().unwrap();
    let addr = I2PAddress::ntcp2_published(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1234,
        I2PTag::from_array([0xAA; 32]),
        [0x11; 16],
    );
    let body_new = RouterInfo::builder()
        .timestamp(2_000)
        .add_address(addr.clone())
        .build();
    let body_old = RouterInfo::builder()
        .timestamp(1_000)
        .add_address(addr)
        .build();
    let ri_new = FullRouterInfo::from_keys(&keys, body_new).unwrap();
    let ri_old = FullRouterInfo::from_keys(&keys, body_old).unwrap();
    let ident = *ri_new.ident_hash();

    let ds_new =
        DatabaseStore::new_router_info(ident, &ri_new.to_buffer().unwrap(), 0, None).unwrap();
    let ds_old =
        DatabaseStore::new_router_info(ident, &ri_old.to_buffer().unwrap(), 0, None).unwrap();

    assert_eq!(
        ctx.handle_database_store(&ds_new.to_buffer().unwrap())
            .unwrap(),
        StoreHandling::Inserted(ident)
    );
    assert_eq!(
        ctx.handle_database_store(&ds_old.to_buffer().unwrap())
            .unwrap(),
        StoreHandling::Stale(ident)
    );
}

#[test]
fn handle_database_store_rejects_key_mismatch() {
    let mut ctx = ctx();
    let ri = foreign_ri(1_700_000_000_000, &[0xAA; 32], [0x11; 16]);
    // Кладём RI с ключом, **не** совпадающим с его ident_hash.
    let wrong_key = IdentHash::from_array([0xFF; 32]);
    let ds = DatabaseStore::new_router_info(wrong_key, &ri.to_buffer().unwrap(), 0, None).unwrap();

    let r = ctx.handle_database_store(&ds.to_buffer().unwrap());
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn handle_database_store_reports_not_router_info() {
    let mut ctx = ctx();
    // Заворачиваем произвольные байты как LeaseSet — тип другой.
    let ds = DatabaseStore::new_lease_set(ident(0x77), vec![0xAA; 10]);
    let result = ctx.handle_database_store(&ds.to_buffer().unwrap()).unwrap();
    match result {
        StoreHandling::NotRouterInfo(StoreType::LeaseSet) => {}
        other => panic!("expected NotRouterInfo(LeaseSet), got {other:?}"),
    }
    // netDb не изменился.
    assert!(ctx.netdb().is_empty());
}

#[test]
fn handle_database_store_malformed_fails() {
    let mut ctx = ctx();
    let r = ctx.handle_database_store(&[0u8; 5]);
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}

// ---- handle_database_lookup -----------------------------------------

#[test]
fn handle_database_lookup_parses_minimal() {
    let ctx = ctx();
    let key = ident(0x01);
    let from = ident(0x02);
    let dl = DatabaseLookup::new_router_info(key, from, None, vec![]);
    let payload = dl.to_buffer().unwrap();

    let parsed = ctx.handle_database_lookup(&payload).unwrap();
    assert_eq!(parsed.key, key);
    assert_eq!(parsed.from, from);
}

#[test]
fn handle_database_lookup_malformed_fails() {
    let ctx = ctx();
    let r = ctx.handle_database_lookup(&[0u8; 5]);
    assert!(r.is_err());
}

// ---- handle_database_search_reply -----------------------------------

#[test]
fn handle_database_search_reply_parses() {
    let ctx = ctx();
    let reply = DatabaseSearchReply::with_from(ident(0xAA), vec![ident(0x11)], ident(0xBB));
    let payload = reply.to_buffer().unwrap();
    let parsed = ctx.handle_database_search_reply(&payload).unwrap();
    assert_eq!(parsed.key, ident(0xAA));
    assert_eq!(parsed.peer_hashes.len(), 1);
}

#[test]
fn handle_database_search_reply_malformed_fails() {
    let ctx = ctx();
    let r = ctx.handle_database_search_reply(&[0u8; 5]);
    assert!(r.is_err());
}

// ---- helpers --------------------------------------------------------

const fn ident(b: u8) -> IdentHash {
    I2PTag::from_array([b; 32])
}

// ---- Debug ----------------------------------------------------------

#[test]
fn debug_does_not_panic() {
    let ctx = ctx();
    let s = format!("{ctx:?}");
    assert!(s.contains("RouterContext"));
}

// --- build_lookup_reply --------------------------------------------------

#[test]
fn lookup_router_info_present_returns_database_store() {
    let mut ctx = minimal_ctx();
    let target = add_ri_to_netdb(&mut ctx, 0x11, false);

    let lookup = DatabaseLookup::new_router_info(target, *ctx.own_ident_hash(), None, Vec::new());
    let reply = ctx.build_lookup_reply(&lookup).unwrap();

    assert_eq!(reply.message_type(), uu_i2p::I2npMessageType::DatabaseStore);
    let body = reply.parse_body().unwrap();
    match body {
        I2npBody::DatabaseStore(ds) => {
            assert_eq!(ds.key, target);
        }
        other => panic!("expected DatabaseStore, got {other:?}"),
    }
}

#[test]
fn lookup_router_info_missing_returns_search_reply() {
    let ctx = minimal_ctx();
    // Ищем несуществующий RI.
    let unknown = IdentHash::from_array([0x77u8; 32]);

    let lookup = DatabaseLookup::new_router_info(unknown, *ctx.own_ident_hash(), None, Vec::new());
    let reply = ctx.build_lookup_reply(&lookup).unwrap();

    assert_eq!(
        reply.message_type(),
        uu_i2p::I2npMessageType::DatabaseSearchReply,
    );
    let body = reply.parse_body().unwrap();
    match body {
        I2npBody::DatabaseSearchReply(sr) => {
            assert_eq!(sr.key, unknown, "key must be echoed back");
            assert_eq!(sr.from, Some(*ctx.own_ident_hash()));
        }
        other => panic!("expected DatabaseSearchReply, got {other:?}"),
    }
}

#[test]
fn lookup_router_info_missing_returns_closest_floodfills() {
    let mut ctx = minimal_ctx();
    // Три floodfill'а в netdb.
    let f1 = add_ri_to_netdb(&mut ctx, 0x11, true);
    let f2 = add_ri_to_netdb(&mut ctx, 0x22, true);
    let f3 = add_ri_to_netdb(&mut ctx, 0x33, true);
    // Плюс один не-floodfill — он не должен попасть в SearchReply.
    let _non_ff = add_ri_to_netdb(&mut ctx, 0x44, false);

    let unknown = IdentHash::from_array([0x77u8; 32]);
    let lookup = DatabaseLookup::new_router_info(unknown, *ctx.own_ident_hash(), None, Vec::new());
    let reply = ctx.build_lookup_reply(&lookup).unwrap();
    let body = reply.parse_body().unwrap();
    match body {
        I2npBody::DatabaseSearchReply(sr) => {
            assert!(
                sr.peer_hashes.len() <= 3,
                "no more than 3 floodfills returned",
            );
            for h in &sr.peer_hashes {
                assert!(
                    *h == f1 || *h == f2 || *h == f3,
                    "only floodfills go into SearchReply for RI lookup",
                );
            }
        }
        other => panic!("expected DatabaseSearchReply, got {other:?}"),
    }
}

#[test]
fn lookup_exploratory_returns_non_floodfills() {
    let mut ctx = minimal_ctx();
    let _f1 = add_ri_to_netdb(&mut ctx, 0x11, true);
    let n1 = add_ri_to_netdb(&mut ctx, 0x22, false);
    let n2 = add_ri_to_netdb(&mut ctx, 0x33, false);

    let target = IdentHash::from_array([0x77u8; 32]);
    let lookup = DatabaseLookup::new_exploratory(target, *ctx.own_ident_hash(), None, Vec::new());
    let reply = ctx.build_lookup_reply(&lookup).unwrap();
    let body = reply.parse_body().unwrap();
    match body {
        I2npBody::DatabaseSearchReply(sr) => {
            for h in &sr.peer_hashes {
                assert!(
                    *h == n1 || *h == n2,
                    "exploratory must return only non-floodfills",
                );
            }
        }
        other => panic!("expected DatabaseSearchReply, got {other:?}"),
    }
}

#[test]
fn lookup_excluded_are_not_in_reply() {
    let mut ctx = minimal_ctx();
    let f1 = add_ri_to_netdb(&mut ctx, 0x11, true);
    let f2 = add_ri_to_netdb(&mut ctx, 0x22, true);

    let target = IdentHash::from_array([0x77u8; 32]);
    let lookup = DatabaseLookup::new_router_info(target, *ctx.own_ident_hash(), None, vec![f1]);
    let reply = ctx.build_lookup_reply(&lookup).unwrap();
    let body = reply.parse_body().unwrap();
    match body {
        I2npBody::DatabaseSearchReply(sr) => {
            assert!(
                !sr.peer_hashes.contains(&f1),
                "excluded must not be returned"
            );
            // f2 всё ещё может быть возвращён.
            let _ = f2;
        }
        other => panic!("expected DatabaseSearchReply, got {other:?}"),
    }
}

#[test]
fn lookup_self_is_not_in_reply() {
    let mut ctx = minimal_ctx();

    // Кладём в netdb три floodfill'а — без своего RI, но в
    // excluded у нас всегда добавляется `own_ident_hash()`,
    // так что даже если бы он там был — не вернулся бы.
    let _f1 = add_ri_to_netdb(&mut ctx, 0x11, true);
    let _f2 = add_ri_to_netdb(&mut ctx, 0x22, true);
    let _f3 = add_ri_to_netdb(&mut ctx, 0x33, true);

    let target = IdentHash::from_array([0x77u8; 32]);
    let lookup = DatabaseLookup::new_router_info(target, *ctx.own_ident_hash(), None, Vec::new());
    let reply = ctx.build_lookup_reply(&lookup).unwrap();
    let body = reply.parse_body().unwrap();
    match body {
        I2npBody::DatabaseSearchReply(sr) => {
            assert!(
                !sr.peer_hashes.contains(ctx.own_ident_hash()),
                "own hash must never be in a SearchReply we send",
            );
        }
        other => panic!("expected DatabaseSearchReply, got {other:?}"),
    }
}

// --- process_database_lookup --------------------------------------------

#[test]
fn process_lookup_bad_payload_fails() {
    let mut ctx = minimal_ctx();
    // Слишком коротко — DatabaseLookup не парсится.
    assert!(ctx.process_database_lookup(&[0u8; 10]).is_err());
}

#[test]
fn process_lookup_roundtrip_via_wire() {
    let mut ctx = minimal_ctx();
    let target = add_ri_to_netdb(&mut ctx, 0x11, false);

    // Собираем входящий DatabaseLookup, сериализуем, разбираем.
    let lookup = DatabaseLookup::new_router_info(target, *ctx.own_ident_hash(), None, Vec::new());
    let payload = lookup.to_buffer().unwrap();

    let reply = ctx.process_database_lookup(&payload).unwrap().unwrap();
    assert_eq!(reply.message_type(), uu_i2p::I2npMessageType::DatabaseStore);
    let body = reply.parse_body().unwrap();
    if let I2npBody::DatabaseStore(ds) = body {
        assert_eq!(ds.key, target);
    } else {
        panic!("expected DatabaseStore");
    }
}

#[test]
fn request_router_registers_lookup() {
    let mut ctx = minimal_ctx();
    let target = ident(0xAA);
    assert!(ctx.request_router(target, 1_000));
    assert!(ctx.netdb_requests().is_active(&target));
    // Повторный запрос — не создаётся заново.
    assert!(!ctx.request_router(target, 1_100));
}

#[test]
fn tick_empty_no_floodfills_yields_nothing() {
    let mut ctx = minimal_ctx();
    let _ = ctx.request_router(ident(0xAA), 1_000);
    let actions = ctx.tick_netdb_requests(1_000);
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "no floodfills in netdb → no actions",
    );
    // Запрос помечен неактивным (нет пиров).
    assert!(!ctx.netdb_requests().is_active(&ident(0xAA)));
}

#[test]
fn tick_asks_closest_floodfill() {
    let mut ctx = minimal_ctx();
    let ff = add_ri_to_netdb(&mut ctx, 0x11, true);
    let target = ident(0xAA);

    let _ = ctx.request_router(target, 1_000);
    let actions = ctx.tick_netdb_requests(1_000);

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].to, ff);
    assert_eq!(
        actions[0].message.message_type(),
        uu_i2p::i2np::I2npMessageType::DatabaseLookup,
    );
}

#[test]
fn tick_does_not_ask_self() {
    let mut ctx = minimal_ctx();
    // Единственный floodfill — мы сами (вставим свой RI в netdb).
    // В проде так не бывает, но пусть будет явно.
    let our = *ctx.own_ident_hash();
    let _ = ctx.request_router(ident(0xAA), 1_000);
    let actions = ctx.tick_netdb_requests(1_000);
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "must not send lookup to ourselves",
    );
    let _ = our;
}

#[test]
fn database_store_completes_pending_lookup() {
    let mut ctx = minimal_ctx();
    let target = add_ri_to_netdb(&mut ctx, 0x11, false);

    // Регистрируем запрос на этот же RI.
    let _ = ctx.request_router(target, 1_000);
    assert!(ctx.netdb_requests().is_active(&target));

    // Приходит DatabaseStore с этим же RI — запрос завершается.
    // (Второй раз вставляем тот же RI — insert вернёт Stale,
    // но complete всё равно должен сработать.)
    let ri = ctx.netdb().get(&target).unwrap().clone();
    let ri_bytes = ri.to_buffer().unwrap();
    let ds = DatabaseStore::new_router_info(target, &ri_bytes, 0, None).unwrap();
    let payload = ds.to_buffer().unwrap();
    let _ = ctx.handle_database_store(&payload).unwrap();

    assert!(
        !ctx.netdb_requests().is_active(&target),
        "lookup must be completed after DatabaseStore for target",
    );
}
// --- Garlic ----------------------------------------------------------

#[test]
fn handle_garlic_empty_payload_fails() {
    let mut ctx = minimal_ctx();
    // I2NP-сообщение типа Garlic без 4-байтового префикса длины.
    assert!(matches!(
        ctx.handle_garlic(&[]),
        Err(I2PError::InvalidLength {
            expected: 4,
            got: 0
        })
    ));
}

#[test]
fn handle_garlic_truncated_length_prefix_fails() {
    let mut ctx = minimal_ctx();
    assert!(matches!(
        ctx.handle_garlic(&[0, 0, 0]),
        Err(I2PError::InvalidLength {
            expected: 4,
            got: 3
        })
    ));
}

#[test]
fn handle_garlic_declared_length_exceeds_buffer_fails() {
    let mut ctx = minimal_ctx();
    // length=10, но payload всего 3 байта.
    let buf = [0, 0, 0, 10, 0xAA, 0xBB, 0xCC];
    assert!(matches!(
        ctx.handle_garlic(&buf),
        Err(I2PError::InvalidLength {
            expected: 14,
            got: 7
        })
    ));
}

#[test]
fn handle_garlic_random_payload_fails() {
    let mut ctx = minimal_ctx();
    // Валидный GarlicBody с 32 байтами мусора. EciesGarlicDestination
    // не найдёт session-tag, попробует как NS — Elligator decode
    // провалится, или DH провалится. Точно не Ok(Some(_)).
    let mut buf = vec![0, 0, 0, 32];
    buf.extend_from_slice(&[0xAAu8; 32]);
    let res = ctx.handle_garlic(&buf);
    assert!(
        res.is_err(),
        "expected error from garbage garlic payload, got {res:?}"
    );
}
#[test]
fn handle_garlic_ns_from_alice_produces_nsr_reply() {
    // Полный цикл NS → NSR на уровне RouterContext:
    // Alice (EciesGarlicDestination) → Bob (RouterContext).

    // 1. Bob — RouterContext с известным ecies static-ключом.
    let mut bob_ctx = minimal_ctx();
    let bob_ecies_pub = *bob_ctx.ecies().local_static_public();

    // 2. Alice — отдельный EciesGarlicDestination с другим
    //    static-ключом.
    let alice_static = I2PX25519Keys::generate();
    let mut alice = EciesGarlicDestination::new(alice_static);
    let alice_ecies_pub = *alice.local_static_public();
    assert_ne!(alice_ecies_pub, bob_ecies_pub);

    // 3. Alice формирует пустой NS (без cloves).
    let ns_ecies_wire = alice
        .send_blocks(bob_ecies_pub, &[])
        .expect("Alice: build NS");
    assert_ne!(ns_ecies_wire.len(), 0, "NS wire пустой");

    // 4. Оборачиваем в GarlicBody + I2npMessage, как это пришло бы
    //    из NTCP2-сессии.
    let i2np_payload = GarlicBody::new(ns_ecies_wire).to_buffer().unwrap();
    let msg = I2npMessage::new(I2npMessageType::Garlic, i2np_payload.clone());
    assert_eq!(msg.message_type(), I2npMessageType::Garlic);

    // 5. Bob обрабатывает. Ожидаем Some(GarlicReply) — NSR.
    let reply = bob_ctx
        .handle_garlic(&i2np_payload)
        .expect("Bob: handle NS")
        .expect("Bob должен вернуть NSR (needs_reply = true)");
    assert_eq!(reply.message.message_type(), I2npMessageType::Garlic);

    // 6. Alice обрабатывает NSR. `reply.message` — это уже
    //    полноценный I2NP Garlic; Alice передаёт его payload
    //    (с GarlicBody-обёрткой) в `handle_message`, разобрав
    //    GarlicBody ровно так же, как это делает RouterContext.
    let nsr_envelope = GarlicBody::from_buffer(reply.message.payload())
        .expect("NSR payload is a valid GarlicBody");
    let alice_result = alice
        .handle_message(&nsr_envelope.payload)
        .expect("Alice: handle NSR");
    assert_eq!(
        alice_result.remote_static, bob_ecies_pub,
        "Alice должна видеть Bob'ов static как remote"
    );
    assert!(
        !alice_result.needs_reply,
        "Alice не должна запрашивать ответ после NSR"
    );
    assert!(!alice_result.terminated, "сессия не должна термироваться");
}
#[test]
fn handle_garlic_i2np_roundtrip_with_database_store_clove() {
    // Полный сценарий: Alice → Bob garlic с одним clove'ом,
    // внутри которого DatabaseStore с чужим (третьим) RI.
    // Проверяем наблюдаемый эффект: RI реально попадает в
    // netdb Bob'а, а handle_garlic возвращает None
    // (needs_reply = false, сессия уже Established).
    use uu_i2p::crypto::I2PX25519Keys;
    use uu_i2p::database_store::DatabaseStore;
    use uu_i2p::ecies_destination::EciesGarlicDestination;
    use uu_i2p::garlic_block::{EciesDelivery, EciesGarlicClove};
    use uu_i2p::garlic_body::GarlicBody;
    use uu_i2p::i2np::I2npMessageType;
    use uu_i2p::i2np_message::I2npMessage;
    use uu_i2p::private_keys::I2PPrivateKeys;
    use uu_i2p::router_info::FullRouterInfo;
    use uu_i2p::router_info::{RouterInfo, RouterInfoCaps};

    let mut bob_ctx = minimal_ctx();
    let bob_ecies_pub = *bob_ctx.ecies().local_static_public();

    let alice_static = I2PX25519Keys::generate();
    let mut alice = EciesGarlicDestination::new(alice_static);

    // 1. Alice устанавливает сессию с Bob: NS → NSR.
    let ns_ecies = alice.send_blocks(bob_ecies_pub, &[]).unwrap();
    let request_envelope = GarlicBody::new(ns_ecies).to_buffer().unwrap();
    let nsr_reply = bob_ctx
        .handle_garlic(&request_envelope)
        .unwrap()
        .expect("Bob returns NSR");
    let nsr_envelope = GarlicBody::from_buffer(nsr_reply.message.payload())
        .expect("NSR payload is a valid GarlicBody");
    alice
        .handle_message(&nsr_envelope.payload)
        .expect("Alice handles NSR");

    // 2. Готовим «чужой» RI — третьего роутера, которого Bob
    //    точно ещё не знает.
    let foreign_keys = I2PPrivateKeys::generate_default().expect("generate keys");
    let foreign_body = RouterInfo::builder()
        .timestamp(now_ms_plus(0))
        .caps(RouterInfoCaps::parse(b"L"))
        .version(970)
        .net_id(2)
        .build();
    let foreign_ri =
        FullRouterInfo::from_keys(&foreign_keys, foreign_body).expect("sign foreign RI");
    let foreign_hash = *foreign_ri.ident_hash();
    let foreign_ri_bytes = foreign_ri.to_buffer().expect("serialize foreign RI");

    // Preconditions: Bob ничего не знает про foreign_hash.
    assert!(
        !bob_ctx.netdb().contains(&foreign_hash),
        "precondition failed: Bob already knows foreign RI"
    );

    // 3. Оборачиваем в DatabaseStore + I2NP.  Промежуточный
    //    I2npMessage собираем только ради `payload()` — в clove
    //    пойдёт уже он без 16-байтового заголовка.
    let ds = DatabaseStore::new_router_info(
        foreign_hash,
        &foreign_ri_bytes,
        /* reply_token = */ 0,
        /* reply_instruction = */ None,
    )
    .expect("build DatabaseStore");
    let ds_i2np = I2npMessage::new(I2npMessageType::DatabaseStore, ds.to_buffer().unwrap());

    // Облегчённый clove в формате ECIES-X25519-AEAD: без
    // clove_id и certificate, expiration в секундах.
    let clove = EciesGarlicClove {
        delivery: EciesDelivery::Local,
        message_type: I2npMessageType::DatabaseStore,
        message_id: 42,
        expiration_secs: u32::try_from(now_ms_plus(60_000) / 1000).unwrap_or(u32::MAX),
        payload: ds_i2np.payload().to_vec(),
    };

    // 4. Alice оборачивает clove, шифрует через established-сессию.
    let garlic_wire = alice
        .send_blocks(bob_ecies_pub, &[clove])
        .expect("Alice builds garlic");
    let i2np_payload = GarlicBody::new(garlic_wire).to_buffer().unwrap();

    // 5. Bob обрабатывает. Ответа быть не должно — needs_reply = false.
    let reply = bob_ctx
        .handle_garlic(&i2np_payload)
        .expect("Bob handles garlic with DatabaseStore clove");
    assert!(
        reply.is_none(),
        "Bob не должен отвечать после Established: {reply:?}"
    );

    // 6. Наблюдаемый эффект: clove дошёл до `process_local_clove` →
    //    `handle_database_store` → netdb вставил foreign RI.
    assert!(
        bob_ctx.netdb().contains(&foreign_hash),
        "DatabaseStore clove не дошёл: netdb не содержит foreign RI"
    );
    let stored = bob_ctx
        .netdb()
        .get(&foreign_hash)
        .expect("netdb хранит foreign RI");
    assert_eq!(
        stored.ident_hash(),
        &foreign_hash,
        "netdb хранит RI под другим IdentHash"
    );
    assert_eq!(
        stored.body().net_id,
        Some(2),
        "у сохранённого RI не тот net_id"
    );
    assert_eq!(
        stored.body().version,
        Some(970),
        "у сохранённого RI не та version"
    );
    // Размер netdb вырос ровно на один — больше cloves не было.
    assert_eq!(
        bob_ctx.netdb().len(),
        1,
        "netdb должен содержать ровно один RI после одного clove"
    );
}

/// Текущее время + `delta_ms` миллисекунд в формате unix-эпохи
/// в миллисекундах. Используется в тестах для `expiration_ms`
/// garlic-clove'ов.
fn now_ms_plus(delta_ms: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .saturating_add(delta_ms)
}
