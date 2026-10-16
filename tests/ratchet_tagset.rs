#[cfg(test)]
mod tests {
    use uu_i2p::MAX_TAG_INDEX;
    use uu_i2p::RatchetTagSet;

    fn key_a() -> [u8; 32] {
        [0xAAu8; 32]
    }

    fn key_b() -> [u8; 32] {
        [0xBBu8; 32]
    }

    fn make_tagset() -> RatchetTagSet {
        let mut ts = RatchetTagSet::new();
        ts.dh_initialize(&key_a(), &key_b());
        ts.next_session_tag_ratchet();
        ts
    }

    // ---- init ----------------------------------------------------------

    #[test]
    fn new_is_zeroed() {
        let ts = RatchetTagSet::new();
        assert_eq!(ts.next_index(), 0);
        assert_eq!(ts.tagset_id(), 0);
        assert_eq!(ts.next_root_key(), &[0u8; 32]);
    }

    #[test]
    fn dh_initialize_fills_state() {
        let mut ts = RatchetTagSet::new();
        ts.dh_initialize(&key_a(), &key_b());
        // next_root_key = HKDF(...) — не равен ни a, ни b
        assert_ne!(ts.next_root_key(), &[0u8; 32]);
        assert_ne!(ts.next_root_key(), &key_a());
        assert_ne!(ts.next_root_key(), &key_b());
    }

    #[test]
    fn dh_initialize_deterministic() {
        let mut a = RatchetTagSet::new();
        let mut b = RatchetTagSet::new();
        a.dh_initialize(&key_a(), &key_b());
        b.dh_initialize(&key_a(), &key_b());
        assert_eq!(a.next_root_key(), b.next_root_key());

        a.next_session_tag_ratchet();
        b.next_session_tag_ratchet();
        assert_eq!(a.get_next_session_tag(), b.get_next_session_tag());
    }

    #[test]
    fn dh_initialize_different_inputs_differ() {
        let mut a = RatchetTagSet::new();
        let mut b = RatchetTagSet::new();
        a.dh_initialize(&key_a(), &key_b());
        b.dh_initialize(&key_b(), &key_a());
        assert_ne!(a.next_root_key(), b.next_root_key());
    }

    // ---- session tags --------------------------------------------------

    #[test]
    fn tags_are_deterministic() {
        let mut ts1 = make_tagset();
        let mut ts2 = make_tagset();
        for _ in 0..10 {
            assert_eq!(ts1.get_next_session_tag(), ts2.get_next_session_tag());
        }
    }

    #[test]
    fn tags_are_unique() {
        let mut ts = make_tagset();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let tag = ts.get_next_session_tag().unwrap();
            assert!(seen.insert(tag), "duplicate tag {tag:016x}");
        }
    }

    #[test]
    fn next_index_increments() {
        let mut ts = make_tagset();
        assert_eq!(ts.next_index(), 0);
        let _ = ts.get_next_session_tag();
        assert_eq!(ts.next_index(), 1);
        let _ = ts.get_next_session_tag();
        assert_eq!(ts.next_index(), 2);
    }

    #[test]
    fn next_session_tag_ratchet_resets_index() {
        let mut ts = make_tagset();
        let _ = ts.get_next_session_tag();
        let _ = ts.get_next_session_tag();
        assert_eq!(ts.next_index(), 2);
        ts.next_session_tag_ratchet();
        assert_eq!(ts.next_index(), 0);
    }

    #[test]
    fn tag_exhaustion() {
        let mut ts = make_tagset();
        // Подкрутить индекс до предела без генерации 65534 тегов.
        // Используем публичный API: генерируем теги и проверяем
        // только границу через сатурацию.
        // Быстрая проверка — только после `next_index = 65534`.
        // Прямого сеттера нет, поэтому имитируем через внутренний
        // доступ в тестах (модуль тестов видит приватные поля).
        ts.next_index = MAX_TAG_INDEX - 1;
        assert_eq!(ts.get_next_session_tag(), None);
        assert_eq!(ts.next_index(), MAX_TAG_INDEX);
        // Повторный вызов — снова None, индекс не растёт.
        assert_eq!(ts.get_next_session_tag(), None);
        assert_eq!(ts.next_index(), MAX_TAG_INDEX);
    }

    #[test]
    fn tag_differs_between_toolsets() {
        let mut ts1 = RatchetTagSet::new();
        ts1.dh_initialize(&key_a(), &key_b());
        ts1.next_session_tag_ratchet();

        let mut ts2 = RatchetTagSet::new();
        ts2.dh_initialize(&key_b(), &key_a());
        ts2.next_session_tag_ratchet();

        assert_ne!(ts1.get_next_session_tag(), ts2.get_next_session_tag());
    }

    // ---- symmetric keys ------------------------------------------------

    #[test]
    fn symm_key_deterministic() {
        let mut ts1 = make_tagset();
        let mut ts2 = make_tagset();
        for i in 0..10 {
            let k1 = ts1.get_symm_key(i).unwrap();
            let k2 = ts2.get_symm_key(i).unwrap();
            assert_eq!(k1, k2, "index {i}");
        }
    }

    #[test]
    fn symm_keys_are_unique() {
        let mut ts = make_tagset();
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let key = ts.get_symm_key(i).unwrap();
            assert!(seen.insert(key), "duplicate key at index {i}");
        }
    }

    #[test]
    fn symm_key_index_zero_works() {
        let mut ts = make_tagset();
        let k = ts.get_symm_key(0).unwrap();
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn symm_key_out_of_order_from_cache() {
        let mut ts = make_tagset();
        // Сгенерим ключ для 5 — он построит 0..5, закэширует 0..4.
        let k5 = ts.get_symm_key(5).unwrap();
        // Теперь запросим 3 — должен вернуться из кэша, тот же, что
        // мы бы получили, генерируя по порядку.
        let k3 = ts.get_symm_key(3).unwrap();
        assert_ne!(k3, k5);

        // Свежая копия, генерируем только 3.
        let mut ts2 = make_tagset();
        let k3_fresh = ts2.get_symm_key(3).unwrap();
        assert_eq!(k3, k3_fresh);
    }

    #[test]
    fn symm_key_consumed_once() {
        let mut ts = make_tagset();
        let _ = ts.get_symm_key(5);
        // 3 — из кэша
        assert!(ts.get_symm_key(3).is_some());
        // 3 — уже изъят, None
        assert!(ts.get_symm_key(3).is_none());
    }

    #[test]
    fn symm_key_delete_removes_from_cache() {
        let mut ts = make_tagset();
        let _ = ts.get_symm_key(5);
        ts.delete_symm_key(3);
        assert!(ts.get_symm_key(3).is_none());
    }

    #[test]
    fn symm_key_stale_index_returns_none() {
        let mut ts = make_tagset();
        // До любого ratchet'а next_symm_key_index = 0.
        // Запрос 0 сгенерирует ключ 0, "съест" его.
        let _ = ts.get_symm_key(0);
        // Второй запрос 0 — None.
        assert!(ts.get_symm_key(0).is_none());
    }

    // ---- tagset_id / msg_id --------------------------------------------

    #[test]
    fn tagset_id_default_zero() {
        let ts = RatchetTagSet::new();
        assert_eq!(ts.tagset_id(), 0);
        assert_eq!(ts.msg_id(), 0);
    }

    #[test]
    fn tagset_id_roundtrip() {
        let mut ts = RatchetTagSet::new();
        ts.set_tagset_id(0x1234);
        assert_eq!(ts.tagset_id(), 0x1234);
    }

    #[test]
    fn msg_id_combines_tagset_and_index() {
        let mut ts = make_tagset();
        ts.set_tagset_id(3);
        let _ = ts.get_next_session_tag();
        let _ = ts.get_next_session_tag();
        // msg_id = (3 << 16) | 2
        assert_eq!(ts.msg_id(), (3 << 16) | 2);
    }

    #[test]
    fn msg_id_differs_for_different_tagsets() {
        let mut a = make_tagset();
        let mut b = make_tagset();
        a.set_tagset_id(0);
        b.set_tagset_id(1);
        assert_ne!(a.msg_id(), b.msg_id());
    }
}
