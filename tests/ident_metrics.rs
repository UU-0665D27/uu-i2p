//! Тесты для `ident_metrics`: `create_routing_key` и `PeerOrdering`.

use uu_i2p::{
    IdentHash,
    ident_metrics::{PEER_ORDERING_INACTIVITY_TIMEOUT, PeerOrdering, create_routing_key},
};

// --- helpers -------------------------------------------------------------

const fn ident(seed: u8) -> IdentHash {
    IdentHash::from_array([seed; 32])
}

/// Даты в формате i2pd `YYYYMMDD`.
const DATE_2026_01_01: [u8; 8] = *b"20260101";
const DATE_2026_01_02: [u8; 8] = *b"20260102";

// --- create_routing_key --------------------------------------------------

#[test]
fn routing_key_is_deterministic() {
    let id = ident(0x11);
    let k1 = create_routing_key(&id, &DATE_2026_01_01);
    let k2 = create_routing_key(&id, &DATE_2026_01_01);
    assert_eq!(k1, k2);
}

#[test]
fn routing_key_differs_by_date() {
    let id = ident(0x11);
    let k1 = create_routing_key(&id, &DATE_2026_01_01);
    let k2 = create_routing_key(&id, &DATE_2026_01_02);
    assert_ne!(k1, k2, "next-day key must differ");
}

#[test]
fn routing_key_differs_by_ident() {
    let k1 = create_routing_key(&ident(0x11), &DATE_2026_01_01);
    let k2 = create_routing_key(&ident(0x22), &DATE_2026_01_01);
    assert_ne!(k1, k2);
}

#[test]
fn routing_key_matches_sha256_of_ident_then_date() {
    // Проверяем вручную, что раскладка байтов совпадает с i2pd:
    // SHA256(ident || YYYYMMDD), ровно 40 байт на входе.
    use uu_i2p::hash::I2PHash;

    let id = ident(0xAB);
    let mut expected_input = [0u8; 40];
    expected_input[..32].copy_from_slice(id.as_bytes());
    expected_input[32..].copy_from_slice(&DATE_2026_01_01);
    let expected: IdentHash = I2PHash::of(&expected_input).into();

    assert_eq!(create_routing_key(&id, &DATE_2026_01_01), expected);
}

// --- PeerOrdering: конструирование ---------------------------------------

#[test]
fn peer_ordering_new_has_random_key() {
    // Два `new()` почти наверняка дадут разные ключи.
    // Это не крипто-тест, а дымовой: ловит регресс, если кто-то
    // случайно захардкодит ключ.
    let a = PeerOrdering::new();
    let b = PeerOrdering::new();
    assert_ne!(a.key(), b.key(), "random keys should differ");
}

#[test]
fn peer_ordering_with_key_preserves_it() {
    let key = [0x77u8; 16];
    let po = PeerOrdering::with_key(key);
    assert_eq!(po.key(), &key);
}

#[test]
fn peer_ordering_empty_initially() {
    let po = PeerOrdering::with_key([0u8; 16]);
    assert!(po.is_empty());
    assert_eq!(po.len(), 0);
}

// --- PeerOrdering: детерминизм -------------------------------------------

#[test]
fn peer_ordering_group_is_deterministic() {
    let key = [0x42u8; 16];
    let mut a = PeerOrdering::with_key(key);
    let mut b = PeerOrdering::with_key(key);

    for s in 0..32u8 {
        let id = ident(s);
        assert_eq!(
            a.group_of(&id, 0),
            b.group_of(&id, 0),
            "same key, same ident => same group",
        );
    }
}

#[test]
fn peer_ordering_group_is_in_range() {
    let mut po = PeerOrdering::new();
    for s in 0..64u8 {
        let g = po.group_of(&ident(s), 0);
        assert!(g < 4, "group must be 0..=3, got {g}");
    }
}

#[test]
fn peer_ordering_different_keys_different_groups() {
    // Не строгая гарантия (могло совпасть), но при 64 роутерах
    // и двух разных ключах вероятность полного совпадения — 4^-64.
    let mut a = PeerOrdering::with_key([0x01u8; 16]);
    let mut b = PeerOrdering::with_key([0x02u8; 16]);

    let mut differs = false;
    for s in 0..64u8 {
        let id = ident(s);
        if a.group_of(&id, 0) != b.group_of(&id, 0) {
            differs = true;
            break;
        }
    }
    assert!(
        differs,
        "different keys must yield at least one different group"
    );
}

// --- PeerOrdering: first/last hop ----------------------------------------

#[test]
fn peer_ordering_first_hop_is_group_zero() {
    let mut po = PeerOrdering::with_key([0x55u8; 16]);
    for s in 0..32u8 {
        let id = ident(s);
        let g = po.group_of(&id, 0);
        // `is_first_hop` только что обновил ts, но group должен
        // совпасть с уже вычисленным.
        let first = po.is_first_hop(&id, 0);
        assert_eq!(first, g == 0);
    }
}

#[test]
fn peer_ordering_last_hop_is_bit_2() {
    let mut po = PeerOrdering::with_key([0x55u8; 16]);
    for s in 0..32u8 {
        let id = ident(s);
        let g = po.group_of(&id, 0);
        let last = po.is_last_hop(&id, 0);
        assert_eq!(last, g & 0x02 != 0);
    }
}

#[test]
fn peer_ordering_first_and_last_independent() {
    // По построению группы 0 и 2/3 не пересекаются, но
    // есть группа 0 (первый) и группа 2 (последний).
    // Найдём хотя бы по одному примеру в каждом классе при
    // достаточно большом пуле.
    let mut po = PeerOrdering::with_key([0x9Au8; 16]);

    let mut saw_first = false;
    let mut saw_last = false;
    let mut saw_neither = false;

    for s in 0..128u8 {
        let id = ident(s);
        let g = po.group_of(&id, 0);
        match (g == 0, g & 0x02 != 0) {
            (true, false) => saw_first = true,
            (false, true) => saw_last = true,
            (false, false) => saw_neither = true,
            (true, true) => panic!("group 0 must not have bit 0x02 set"),
        }
    }

    assert!(saw_first, "expected at least one first-hop peer");
    assert!(saw_last, "expected at least one last-hop peer");
    assert!(saw_neither, "expected at least one neutral peer");
}

// --- PeerOrdering: cleanup -----------------------------------------------

#[test]
fn peer_ordering_cleanup_keeps_fresh() {
    let mut po = PeerOrdering::with_key([0u8; 16]);
    let now = 1_000u64;
    po.group_of(&ident(0x01), now);
    po.group_of(&ident(0x02), now);
    assert_eq!(po.len(), 2);

    // Момент времени внутри таймаута — ничего не удаляем.
    po.cleanup(now + PEER_ORDERING_INACTIVITY_TIMEOUT);
    assert_eq!(
        po.len(),
        2,
        "entry exactly at timeout boundary must survive"
    );
}

#[test]
fn peer_ordering_cleanup_removes_stale() {
    let mut po = PeerOrdering::with_key([0u8; 16]);
    let now = 1_000u64;
    po.group_of(&ident(0x01), now);
    po.group_of(&ident(0x02), now);
    assert_eq!(po.len(), 2);

    // Ушли на секунду за таймаут — оба удалены.
    po.cleanup(now + PEER_ORDERING_INACTIVITY_TIMEOUT + 1);
    assert_eq!(po.len(), 0);
}

#[test]
fn peer_ordering_cleanup_only_stale_removed() {
    let mut po = PeerOrdering::with_key([0u8; 16]);
    let stale_id = ident(0x01);
    let fresh_id = ident(0x02);

    po.group_of(&stale_id, 1_000);
    po.group_of(&fresh_id, 2_000);

    // stale_id не трогали с 1_000, fresh_id — с 2_000.
    // Текущее время 1_000 + timeout + 1: stale истёк,
    // fresh ещё жив (2_000 + timeout > 1_000 + timeout + 1).
    po.cleanup(1_000 + PEER_ORDERING_INACTIVITY_TIMEOUT + 1);

    assert!(!po.contains(&stale_id), "stale entry must be removed");
    assert!(po.contains(&fresh_id), "fresh entry must survive");
    assert_eq!(po.len(), 1);
}

#[test]
fn peer_ordering_group_updates_last_seen() {
    let mut po = PeerOrdering::with_key([0u8; 16]);
    let id = ident(0x33);

    po.group_of(&id, 1_000);
    // Продлеваем жизнь тому же роутеру повторным обращением.
    po.group_of(&id, 5_000);

    // Если бы ts не обновился, запись удалилась бы при cleanup.
    po.cleanup(1_000 + PEER_ORDERING_INACTIVITY_TIMEOUT + 1);
    assert!(po.contains(&id), "recently touched entry must survive");
    assert_eq!(po.len(), 1);
}

// --- PeerOrdering: дефолт -------------------------------------------------

#[test]
fn peer_ordering_default_equals_new() {
    let a = PeerOrdering::default();
    assert!(a.is_empty());
    // Ключ случайный — просто проверяем, что не паникует и не пустой.
    assert_ne!(a.key(), &[0u8; 16]);
}
