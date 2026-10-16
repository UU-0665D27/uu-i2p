//! Тесты для `netdb_requests`.

use std::collections::HashSet;
use uu_i2p::{
    IdentHash,
    database_search_reply::DatabaseSearchReply,
    i2np::I2npMessageType,
    netdb_requests::{
        MAX_EXPLORATORY_REQUEST_TIME_MS, MAX_NUM_REQUEST_ATTEMPTS, MAX_REQUEST_TIME_MS,
        MIN_DIRECT_REQUEST_TIME_MS, MIN_REQUEST_TIME_MS, NetDbRequests, SendAction,
    },
};

// --- хелперы -------------------------------------------------------------
const fn ident(seed: u8) -> IdentHash {
    IdentHash::from_array([seed; 32])
}

/// Замыкание-заглушка, возвращающее заранее заданных пиров по
/// порядку.
fn peer_picker(
    peers: Vec<IdentHash>,
) -> impl FnMut(&IdentHash, &HashSet<IdentHash>, &IdentHash) -> Option<IdentHash> {
    let mut idx = 0;
    move |_target, excluded, our| {
        while idx < peers.len() {
            let p = peers[idx];
            idx += 1;
            if !excluded.contains(&p) && p != *our {
                return Some(p);
            }
        }
        None
    }
}

const OUR_HASH: IdentHash = IdentHash::from_array([0xFFu8; 32]);

// --- new_request ---------------------------------------------------------

#[test]
fn new_request_returns_true_first_time() {
    let mut reqs = NetDbRequests::new();
    assert!(reqs.new_request(ident(0x11), false, true, 1_000));
    assert!(reqs.is_active(&ident(0x11)));
    assert_eq!(reqs.len(), 1);
}

#[test]
fn new_request_returns_false_for_active_duplicate() {
    let mut reqs = NetDbRequests::new();
    assert!(reqs.new_request(ident(0x11), false, true, 1_000));
    assert!(!reqs.new_request(ident(0x11), false, true, 1_100));
    assert_eq!(reqs.len(), 1);
}

#[test]
fn new_request_restarts_after_complete() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);
    reqs.complete(&ident(0x11));
    assert!(!reqs.is_active(&ident(0x11)));
    // Запрос ещё в пуле (неактивный), до tick.
    assert_eq!(reqs.len(), 1);
    // Повторный запуск разрешён.
    assert!(reqs.new_request(ident(0x11), false, true, 2_000));
}

// --- tick: базовый сценарий ---------------------------------------------

#[test]
fn tick_empty_is_noop() {
    let mut reqs = NetDbRequests::new();
    let actions = reqs.tick(&OUR_HASH, 1_000, peer_picker(vec![]));
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "empty pool must yield no actions"
    );
}

#[test]
fn tick_sends_lookup_to_first_peer() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    let peer = ident(0xAA);
    let actions = reqs.tick(&OUR_HASH, 1_000, peer_picker(vec![peer]));

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].to, peer);
    assert_eq!(
        actions[0].message.message_type(),
        I2npMessageType::DatabaseLookup
    );

    let req = reqs.get(&ident(0x11)).unwrap();
    assert_eq!(req.num_attempts, 1);
    assert_eq!(req.last_request_time_ms, 1_000);
    assert!(req.excluded.contains(&peer));
}

#[test]
fn tick_does_not_spam_before_min_interval() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    let peer = ident(0xAA);
    let _ = reqs.tick(&OUR_HASH, 1_000, peer_picker(vec![peer]));
    // Прошло меньше MIN_DIRECT_REQUEST_TIME_MS.
    let actions = reqs.tick(
        &OUR_HASH,
        1_000 + MIN_DIRECT_REQUEST_TIME_MS - 1,
        peer_picker(vec![peer]),
    );
    assert!(
        actions.is_empty(),
        "must not resend before MIN_DIRECT interval"
    );
}

#[test]
fn tick_resends_after_min_interval() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    let peers = vec![ident(0xAA), ident(0xBB)];
    let mut picker = peer_picker(peers);

    let a1 = reqs.tick(&OUR_HASH, 1_000, &mut picker);
    assert_eq!(a1.len(), 1);
    assert_eq!(a1[0].to, ident(0xAA));

    let a2 = reqs.tick(&OUR_HASH, 1_000 + MIN_DIRECT_REQUEST_TIME_MS, &mut picker);
    assert_eq!(a2.len(), 1);
    assert_eq!(a2[0].to, ident(0xBB), "second tick should ask next peer");

    let req = reqs.get(&ident(0x11)).unwrap();
    assert_eq!(req.num_attempts, 2);
    assert!(req.excluded.contains(&ident(0xAA)));
    assert!(req.excluded.contains(&ident(0xBB)));
}

// --- tick: таймауты ------------------------------------------------------

#[test]
fn tick_fails_after_max_request_time() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    // Прыгаем в MAX_REQUEST_TIME от создания.
    let actions = reqs.tick(
        &OUR_HASH,
        1_000 + MAX_REQUEST_TIME_MS,
        peer_picker(vec![ident(0xAA)]),
    );
    assert!(actions.is_empty(), "expired request must not send");
    // Запрос помечен неактивным и удалён retain'ом.
    assert!(!reqs.is_active(&ident(0x11)));
    assert_eq!(reqs.len(), 0);
}

#[test]
fn exploratory_has_longer_lifetime() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), true, true, 1_000);

    // На MAX_REQUEST_TIME обычный бы умер, exploratory жив.
    let actions = reqs.tick(
        &OUR_HASH,
        1_000 + MAX_REQUEST_TIME_MS,
        peer_picker(vec![ident(0xAA)]),
    );
    assert_eq!(
        actions.len(),
        1,
        "exploratory must survive past normal timeout"
    );

    // А на MAX_EXPLORATORY_REQUEST_TIME — умирает.
    let actions = reqs.tick(
        &OUR_HASH,
        1_000 + MAX_EXPLORATORY_REQUEST_TIME_MS,
        peer_picker(vec![ident(0xAA)]),
    );
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "exploratory must die past MAX_EXPLORATORY_REQUEST_TIME_MS",
    );
    assert!(!reqs.is_active(&ident(0x11)));
}

#[test]
fn tick_fails_after_max_attempts() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    let mut now = 1_000;
    // Каждая попытка — новый peer.
    let peers: Vec<IdentHash> = (0u8..10).map(|i| ident(0xA0 + i)).collect();
    let mut picker = peer_picker(peers);

    for _ in 0..MAX_NUM_REQUEST_ATTEMPTS {
        let _ = reqs.tick(&OUR_HASH, now, &mut picker);
        now += MIN_DIRECT_REQUEST_TIME_MS;
    }
    assert_eq!(
        reqs.get(&ident(0x11)).unwrap().num_attempts,
        MAX_NUM_REQUEST_ATTEMPTS
    );

    // Следующий tick не должен пытаться ещё раз.
    let actions = reqs.tick(&OUR_HASH, now, &mut picker);
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "must not send after MAX_NUM_REQUEST_ATTEMPTS",
    );
    assert!(!reqs.is_active(&ident(0x11)));
}

// --- tick: нет пиров -----------------------------------------------------

#[test]
fn tick_fails_when_no_peers_left() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    // Пул пуст.
    let actions = reqs.tick(&OUR_HASH, 1_000, peer_picker(vec![]));
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "no peers left — nothing to send",
    );
    assert!(!reqs.is_active(&ident(0x11)));
}

#[test]
fn tick_excludes_our_hash() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    // «Единственный пир» — мы сами. Не должны спросить себя.
    let actions = reqs.tick(&OUR_HASH, 1_000, peer_picker(vec![OUR_HASH]));
    assert!(actions.is_empty(), "must not send lookup to ourselves");
}

// --- handle_search_reply -------------------------------------------------

#[test]
fn search_reply_adds_peers_to_excluded() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    let reply = DatabaseSearchReply::new(ident(0x11), vec![ident(0xCC), ident(0xDD)]);
    reqs.handle_search_reply(&reply);

    let req = reqs.get(&ident(0x11)).unwrap();
    assert!(req.excluded.contains(&ident(0xCC)));
    assert!(req.excluded.contains(&ident(0xDD)));
}

#[test]
fn search_reply_for_unknown_is_ignored() {
    let mut reqs = NetDbRequests::new();
    let reply = DatabaseSearchReply::new(ident(0x11), vec![ident(0xCC)]);
    // Не паникует.
    reqs.handle_search_reply(&reply);
}

#[test]
fn search_reply_for_completed_is_ignored() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);
    reqs.complete(&ident(0x11));

    let reply = DatabaseSearchReply::new(ident(0x11), vec![ident(0xCC)]);
    reqs.handle_search_reply(&reply);

    // Запись всё ещё в пуле (до tick), но excluded не обновился.
    let req = reqs.get(&ident(0x11)).unwrap();
    assert!(!req.excluded.contains(&ident(0xCC)));
}

// --- complete / remove ---------------------------------------------------

#[test]
fn complete_returns_true_only_for_active() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    assert!(reqs.complete(&ident(0x11)));
    assert!(!reqs.complete(&ident(0x11)), "second complete is no-op");
}

#[test]
fn complete_unknown_is_false() {
    let mut reqs = NetDbRequests::new();
    assert!(!reqs.complete(&ident(0x11)));
}

#[test]
fn remove_drops_immediately() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);
    assert!(reqs.remove(&ident(0x11)).is_some());
    assert!(reqs.get(&ident(0x11)).is_none());
    assert_eq!(reqs.len(), 0);
}

// --- multiple requests ---------------------------------------------------

#[test]
fn multiple_requests_independent() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);
    reqs.new_request(ident(0x22), false, true, 1_000);

    let peers = vec![ident(0xAA), ident(0xBB), ident(0xCC)];
    let actions = reqs.tick(&OUR_HASH, 1_000, peer_picker(peers));

    assert_eq!(actions.len(), 2, "both requests get one action each");
    let targets: HashSet<_> = actions.iter().map(|a| a.to).collect();
    assert_eq!(targets.len(), 2, "different peers for different requests");
}
// --- границы и ветки, не покрытые ранее --------------------------------

#[test]
fn non_direct_uses_longer_min_interval() {
    let mut reqs = NetDbRequests::new();
    // direct = false ⇒ MIN_REQUEST_TIME_MS (1200), а не MIN_DIRECT_REQUEST_TIME_MS (600).
    reqs.new_request(ident(0x11), false, false, 1_000);

    // Два разных пира: первый уйдёт в excluded после первого
    // tick'а, второй пойдёт во вторую попытку. С одним пиром
    // второй tick упёрся бы в то, что единственный пир уже
    // в excluded, и `choose_floodfill` вернул бы None — запрос
    // умер бы раньше, чем мы проверили интервал.
    let peers = vec![ident(0xAA), ident(0xBB)];
    let mut picker = peer_picker(peers);

    let a1 = reqs.tick(&OUR_HASH, 1_000, &mut picker);
    assert_eq!(a1.len(), 1);
    assert_eq!(a1[0].to, ident(0xAA));

    // На 600+ε всё ещё нельзя повторять — интервал 1200.
    let actions = reqs.tick(&OUR_HASH, 1_000 + MIN_DIRECT_REQUEST_TIME_MS, &mut picker);
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "non-direct request must not resend at MIN_DIRECT_REQUEST_TIME_MS",
    );

    // А на 1200 — можно. Пикер пойдёт дальше по своему списку
    // и вернёт второго пира.
    let actions = reqs.tick(&OUR_HASH, 1_000 + MIN_REQUEST_TIME_MS, &mut picker);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].to, ident(0xBB));
}

#[test]
fn request_expires_exactly_at_max_time() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    // Ровно на границе `now == created + MAX_REQUEST_TIME_MS` —
    // по коду (`now_ms >= created.saturating_add(max_time)`) это
    // уже истёк.
    let actions = reqs.tick(
        &OUR_HASH,
        1_000 + MAX_REQUEST_TIME_MS,
        peer_picker(vec![ident(0xAA)]),
    );
    assert_eq!(
        actions,
        Vec::<SendAction>::new(),
        "boundary time must count as expired",
    );
    assert!(!reqs.is_active(&ident(0x11)));
}
#[test]
fn tick_dies_when_all_peers_already_asked() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);

    let peers = vec![ident(0xAA), ident(0xBB)];
    let mut picker = peer_picker(peers);

    // Первый tick — спрашиваем 0xAA.
    let a1 = reqs.tick(&OUR_HASH, 1_000, &mut picker);
    assert_eq!(a1.len(), 1);
    assert_eq!(a1[0].to, ident(0xAA));

    // Второй tick — спрашиваем 0xBB.
    let a2 = reqs.tick(&OUR_HASH, 1_000 + MIN_DIRECT_REQUEST_TIME_MS, &mut picker);
    assert_eq!(a2.len(), 1);
    assert_eq!(a2[0].to, ident(0xBB));

    // Третий tick — больше пиров нет (все в excluded), запрос умирает.
    let a3 = reqs.tick(
        &OUR_HASH,
        1_000 + 2 * MIN_DIRECT_REQUEST_TIME_MS,
        &mut picker,
    );
    assert_eq!(
        a3,
        Vec::<SendAction>::new(),
        "no more peers → request must die",
    );
    assert!(!reqs.is_active(&ident(0x11)));
}
#[test]
fn tick_removes_completed_request() {
    let mut reqs = NetDbRequests::new();
    reqs.new_request(ident(0x11), false, true, 1_000);
    reqs.complete(&ident(0x11));

    // До tick запись ещё в пуле (по дизайну — чтобы caller мог
    // заглянуть в `get` и узнать исход).
    assert_eq!(reqs.len(), 1);
    assert!(!reqs.is_active(&ident(0x11)));

    // Первый tick — `retain` его убирает.
    let _ = reqs.tick(&OUR_HASH, 1_000, peer_picker(vec![]));
    assert_eq!(reqs.len(), 0);
    assert!(reqs.get(&ident(0x11)).is_none());
}
