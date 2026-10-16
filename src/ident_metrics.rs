//! Метрики идентификаторов: XOR-расстояние для DHT и группировка
//! роутеров для выбора пиров в туннелях.
//!
//! Соответствует `IdentMetrics.cpp` / `IdentMetrics.h` в i2pd.
//!
//! ## Что внутри
//!
//! - [`create_routing_key`] — ключ, по которому объект кладётся
//!   в netDb на сутки. Меняется раз в день, чтобы нагрузка
//!   «размазывалась» по разным floodfill'ам.
//! - [`PeerOrdering`] — детерминированный (по SipHash-8) разбор
//!   роутеров на 4 группы. Позволяет равномерно выбирать первых
//!   и последних хопов туннелей.
//!
//! ## Чего нет
//!
//! - `XORMetric` как отдельный тип: текущий порт использует
//!   `[u8; 32]` напрямую (см. [`crate::netdb::xor_distance`]).
//!   Когда понадобится типизированное сравнение — добавим.
//! - `GetCurrentDate` / `GetNextDayDate` (форматирование UTC-даты):
//!   это Gregorian-конвертация, которой место в `timestamp.rs`.
//!   Здесь `create_routing_key` принимает дату уже готовой.

use crate::{IdentHash, hash::I2PHash, siphash::siphash24_128bit_first_word};
use std::collections::HashMap;

/// Через сколько секунд без обращения запись о роутере
/// удаляется из [`PeerOrdering`].
///
/// Соответствует `PEER_ORDERING_INACTIVITY_TIMEOUT` в i2pd.
pub const PEER_ORDERING_INACTIVITY_TIMEOUT: u64 = 400;

// --- routing key ---------------------------------------------------------

/// SHA256 от `ident || date`, где `date` — 8 ASCII-символов `YYYYMMDD`.
///
/// Совпадает с `CreateRoutingKey` в i2pd: там `GetCurrentDate(buf + 32)`
/// пишет `YYYYMMDD\0`, но хешируется только 40 байт (ident + 8 знаков),
/// без нулевого терминатора.
///
/// Используется:
/// - в DHT — как ключ для поиска ближайшего floodfill'а к объекту;
/// - при публикации — чтобы один и тот же объект каждый день «переезжал»
///   на другой набор floodfill'ов (размазывает нагрузку).
#[must_use]
pub fn create_routing_key(ident: &IdentHash, date: &[u8; 8]) -> IdentHash {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(ident.as_bytes());
    buf[32..].copy_from_slice(date);
    I2PHash::of(&buf).into()
}

// --- PeerOrdering --------------------------------------------------------

/// Детерминированное разбиение роутеров на группы для выбора пиров.
///
/// Каждый роутер по SipHash-128 от своего `IdentHash` (с секретным
/// ключом) попадает в одну из 4 групп — младшие 2 бита хеша.
/// Ключ переживает рестарт (в i2pd его можно задать через
/// `inbound.randomKey` / `outbound.randomKey`), поэтому выбор
/// «первых» и «последних» хопов стабилен между запусками, но
/// одинаков для всех узлов, знающих ключ — что и нужно туннелям.
///
/// Семантика групп:
///
/// - группа `0` — «первый хоп» (IBGW / OBEP внутри туннеля);
/// - бит `0x02` (группы `2`, `3`) — «последний хоп»;
/// - группы `1` — нейтральная, ни первого, ни последнего.
///
/// Разбиение на 4 группы, а не на 2, даёт 50% роутеров, пригодных
/// на роль первого хопа, и 50% — на роль последнего. Проверка
/// `IsFirstHop` и `IsLastHop` независима, так что один роутер может
/// быть и тем, и другим (группа 0 не пересекается с битом 0x02).
#[derive(Debug)]
pub struct PeerOrdering {
    key: [u8; 16],
    /// `IdentHash -> (group, last_seen_s)`.
    ///
    /// i2pd хранит только `(group, ts)` и обновляет `ts` на каждом
    /// обращении: свежие роутеры остаются, редко используемые
    /// вычищаются [`Self::cleanup`].
    groups: HashMap<IdentHash, (u8, u64)>,
}

impl PeerOrdering {
    /// Новый экземпляр со случайным ключом.
    #[must_use]
    pub fn new() -> Self {
        let mut key = [0u8; 16];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut key);
        Self {
            key,
            groups: HashMap::new(),
        }
    }

    /// Новый экземпляр с явно заданным ключом.
    ///
    /// Используется в тестах и когда ключ приходит из конфига
    /// (`inbound.randomKey` / `outbound.randomKey` в i2pd).
    #[must_use]
    pub fn with_key(key: [u8; 16]) -> Self {
        Self {
            key,
            groups: HashMap::new(),
        }
    }

    /// Ключ, которым подписываются `IdentHash`.
    #[must_use]
    pub const fn key(&self) -> &[u8; 16] {
        &self.key
    }
    /// Есть ли запись о роутере? Не обновляет `last_seen`.
    #[must_use]
    pub fn contains(&self, ident: &IdentHash) -> bool {
        self.groups.contains_key(ident)
    }
    /// Группа `(0..=3)` для роутера. Обновляет `last_seen_s`.
    ///
    /// Соответствует `PeerOrdering::GetPeerOrderingGroup` в i2pd:
    /// SipHash-128 от `IdentHash` с ключом `self.key`, берём
    /// младшие 2 бита.
    pub fn group_of(&mut self, ident: &IdentHash, now_s: u64) -> u8 {
        let word = siphash24_128bit_first_word(ident.as_bytes(), &self.key);
        let group = (word & 0x03) as u8;
        self.groups.insert(*ident, (group, now_s));
        group
    }

    /// `true`, если роутер годен на роль первого хопа.
    ///
    /// Соответствует `PeerOrdering::IsFirstHop` в i2pd — это
    /// `group == 0`.
    pub fn is_first_hop(&mut self, ident: &IdentHash, now_s: u64) -> bool {
        self.group_of(ident, now_s) == 0
    }

    /// `true`, если роутер годен на роль последнего хопа.
    ///
    /// Соответствует `PeerOrdering::IsLastHop` в i2pd — это
    /// `group & 0x02 != 0`.
    pub fn is_last_hop(&mut self, ident: &IdentHash, now_s: u64) -> bool {
        self.group_of(ident, now_s) & 0x02 != 0
    }

    /// Удаляет записи, к которым не обращались дольше
    /// [`PEER_ORDERING_INACTIVITY_TIMEOUT`] секунд.
    ///
    /// Вызывающий код (туннельный пул) делает это периодически,
    /// чтобы `groups` не рос бесконечно.
    pub fn cleanup(&mut self, now_s: u64) {
        self.groups
            .retain(|_, (_, ts)| now_s <= ts.saturating_add(PEER_ORDERING_INACTIVITY_TIMEOUT));
    }

    /// Сколько роутеров запомнено. Для тестов и диагностики.
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Пусто?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

impl Default for PeerOrdering {
    fn default() -> Self {
        Self::new()
    }
}
