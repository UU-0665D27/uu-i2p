//! `NetDb` — локальное хранилище `RouterInfo` других роутеров.
//!
//! Соответствует `NetDb` из i2pd: мапа `IdentHash → RouterInfo` плюс
//! Kademlia-выборка ближайших по XOR-метрике (для поиска floodfill'ов).
//!
//! ## Что хранится
//!
//! [`FullRouterInfo`] — identity + body + signature. Мы храним **полный**
//! RI, а не только `body`, потому что:
//!
//! - RI нужен целиком, чтобы отдать его peer'у в `DatabaseStore`;
//! - подпись уже проверена при парсинге, повторно проверять не надо;
//! - адреса и `IdentHash` вычисляются один раз при вставке.
//!
//! Свой собственный RI в `NetDb` **не** кладём — в i2pd он живёт
//! отдельно (`RouterContext::GetRouterInfo`), потому что у него нет
//! смысла обновляться по timestamp'у и участвовать в XOR-выборке.
//!
//! ## Что НЕ реализовано
//!
//! - **Persist на диск**: i2pd хранит netDb в `netDb/r*/routerInfo-*.dat`
//!   и перезагружает при старте. У нас — только память, caller сам
//!   решает, что сохранять.
//! - **Лимит размера и автоэвикция**: у i2pd есть `m_RouterInfos` с
//!   проверкой `IsUnreachable` и `MAX_NUM_ROUTERS`. У нас — без
//!   лимита, но есть [`NetDb::retain`], чтобы caller мог чистить
//!   вручную по своему критерию.
//! - **Недостижимость по профилю пира**: i2pd помечает RI недостижимым,
//!   если профиль пира это говорит (`NetDb::SetUnreachable`,
//!   `NetDb.cpp:704`), и снимает флаг на обновлении RI. У нас профилей
//!   нет, поэтому признак считается из самого RI
//!   ([`RouterInfo::is_unreachable`]); см. [`Reachability`].
//! - **Floodfill-подмножество**: отдельного индекса нет, `floodfills()`
//!   фильтрует по `is_floodfill()`. Когда floodfill'ов станет много,
//!   можно добавить отдельный `HashSet` — сейчас преждевременно.
//! - **Запросы** (`DatabaseLookup` / `DatabaseSearchReply`): netDb — это
//!   только хранилище; логика поиска — в `RouterContext` (шаг 3a-3).

use crate::IdentHash;
use crate::config::DEFAULT_NET_ID;
use crate::router_info::FullRouterInfo;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Политика «этот RI недостижим» для выбора из netDb.
///
/// Шов для решения, которое i2pd принимает флагом
/// `RouterInfo::m_IsUnreachable`. У i2pd флаг выставляется в трёх
/// местах: при разборе RI (`RouterInfo.cpp:508`), по профилю пира
/// (`NetDb.cpp:704`) и снимается на обновлении (`RouterInfo.cpp:100`).
/// У нас RI неизменяем, поэтому политика — отдельный объект, а не флаг
/// в записи.
///
/// Дефолт — [`I2pdReachability`]: правила из `RouterInfo::ReadFromBuffer`.
/// [`AcceptAllReachability`] нужен там, где RI синтетический (тесты,
/// подделки) и адресов заведомо нет.
pub trait Reachability: std::fmt::Debug + Send + Sync {
    /// Считать ли `ri` недостижимым (не отдавать в `DatabaseLookup`,
    /// не выбирать флудфиллом, не слать ему запросы).
    fn is_unreachable(&self, ri: &FullRouterInfo) -> bool;
}

/// Правила i2pd: нет валидных адресов, чужой/отсутствующий `netId`
/// или нет `router.version` → RI недостижим.
///
/// См. [`crate::router_info::RouterInfo::is_unreachable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I2pdReachability {
    net_id: i32,
}

impl I2pdReachability {
    /// Политика для сети `net_id`.
    #[must_use]
    pub const fn new(net_id: i32) -> Self {
        Self { net_id }
    }

    /// Политика для сети по умолчанию ([`DEFAULT_NET_ID`]).
    #[must_use]
    pub const fn for_default_network() -> Self {
        Self::new(DEFAULT_NET_ID as i32)
    }

    /// `netId`, по которому проверяются RI.
    #[must_use]
    pub const fn net_id(self) -> i32 {
        self.net_id
    }
}

impl Default for I2pdReachability {
    fn default() -> Self {
        Self::for_default_network()
    }
}

impl Reachability for I2pdReachability {
    fn is_unreachable(&self, ri: &FullRouterInfo) -> bool {
        ri.is_unreachable(self.net_id)
    }
}

/// Политика «все достижимы»: фильтра нет.
///
/// Нужна для тестов и для хранилищ, собранных из поддельных RI без
/// адресов — иначе такие записи не участвуют ни в выборе флудфиллов,
/// ни в ответах на `DatabaseLookup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AcceptAllReachability;

impl Reachability for AcceptAllReachability {
    fn is_unreachable(&self, _ri: &FullRouterInfo) -> bool {
        false
    }
}

/// Минимальный срок годности `RouterInfo` (`NETDB_MIN_EXPIRATION_TIMEOUT`):
/// RI старше этого с момента `timestamp` не принимается.
pub const NETDB_MIN_EXPIRATION_TIMEOUT: Duration = Duration::from_mins(90);

/// Допустимый запас «в будущее» для `timestamp` `RouterInfo`
/// (`NETDB_EXPIRATION_TIMEOUT_THRESHOLD`): RI из более далёкого будущего
/// не принимается.
pub const NETDB_EXPIRATION_TIMEOUT_THRESHOLD: Duration = Duration::from_mins(2);

/// Минимальная версия роутера (`NETDB_MIN_ALLOWED_VERSION`, 0.9.57).
///
/// Как и в i2pd, версия — это склейка цифр из property `router.version`
/// (`MAKE_VERSION_NUMBER` там используется только для констант): роутер
/// старее этой версии принимается, лишь если он high-bandwidth.
/// В i2pd 3.0 порог опущен с 0.9.58 до 0.9.57 ради Debian 12
/// (`NetDb.hpp:58`).
pub const NETDB_MIN_ALLOWED_VERSION: u32 = 957;

/// Хранилище `RouterInfo` других роутеров.
///
/// ## Инварианты
///
/// - Все записи — валидные `FullRouterInfo` (подпись проверена при
///   парсинге в [`FullRouterInfo::from_buffer`]);
/// - В мапе для каждого `IdentHash` лежит ровно один RI — при
///   добавлении более новой версии старая заменяется;
/// - Порядок итерации не гарантирован (это `HashMap`).
#[derive(Debug)]
pub struct NetDb {
    entries: HashMap<IdentHash, FullRouterInfo>,
    reachability: Box<dyn Reachability>,
}

impl Default for NetDb {
    fn default() -> Self {
        Self::new()
    }
}

impl NetDb {
    /// Создаёт пустое хранилище с правилами достижимости i2pd
    /// ([`I2pdReachability`] для [`DEFAULT_NET_ID`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_reachability(I2pdReachability::for_default_network())
    }

    /// Пустое хранилище с явной политикой достижимости.
    #[must_use]
    pub fn with_reachability(reachability: impl Reachability + 'static) -> Self {
        Self {
            entries: HashMap::new(),
            reachability: Box::new(reachability),
        }
    }

    /// Пустое хранилище для сети `net_id`.
    #[must_use]
    pub fn with_net_id(net_id: i32) -> Self {
        Self::with_reachability(I2pdReachability::new(net_id))
    }

    /// Достижим ли RI: `!reachability.is_unreachable (ri)`.
    #[must_use]
    pub fn is_reachable(&self, ri: &FullRouterInfo) -> bool {
        !self.reachability.is_unreachable(ri)
    }

    /// Есть ли в хранилище RI с таким `IdentHash`, и если есть —
    /// недостижим ли он.
    ///
    /// `None` — записи нет.
    #[must_use]
    pub fn unreachable(&self, ident: &IdentHash) -> Option<bool> {
        self.entries
            .get(ident)
            .map(|ri| self.reachability.is_unreachable(ri))
    }

    /// Количество роутеров в хранилище.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Хранилище пусто?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Есть ли RI с указанным `IdentHash`.
    #[must_use]
    pub fn contains(&self, ident: &IdentHash) -> bool {
        self.entries.contains_key(ident)
    }

    /// Добавляет `RouterInfo` в хранилище.
    ///
    /// Если RI с таким `IdentHash` уже есть:
    ///
    /// - **timestamp нового больше** → старая запись заменяется, возврат `true`;
    /// - **timestamp нового ≤** → запись не меняется, возврат `false`.
    ///
    /// Если RI не было — добавляется, возврат `true`.
    ///
    /// Сравнение по timestamp, а не по байтам: в I2P timestamp
    /// монотонно растёт при каждой публикации, а байты могут отличаться
    /// от порядка полей в `RouterInfo` (см. i2pd `RouterInfo::IsNewer`).
    ///
    /// Недостижимые RI тоже принимаются: в i2pd новая запись с
    /// `IsUnreachable`/без валидных адресов не попадает в netDb вообще
    /// (`NetDb.cpp:315`), а обновление существующей — выкидывает её
    /// (`NetDb.cpp:272`). У нас проверка живёт в выборе
    /// ([`Self::is_reachable`]), чтобы вызывающий мог посмотреть, что
    /// именно отвергнуто; — TODO(floodfill): повторить и отказ на
    /// вставке, когда все источники RI будут давать валидные адреса.
    pub fn insert(&mut self, ri: FullRouterInfo) -> bool {
        let ident = *ri.ident_hash();
        if let Some(existing) = self.entries.get_mut(&ident) {
            if ri.body().timestamp > existing.body().timestamp {
                *existing = ri;
                true
            } else {
                false
            }
        } else {
            self.entries.insert(ident, ri);
            true
        }
    }

    /// Возвращает RI по `IdentHash`.
    #[must_use]
    pub fn get(&self, ident: &IdentHash) -> Option<&FullRouterInfo> {
        self.entries.get(ident)
    }

    /// Возвращает изменяемый RI по `IdentHash`.
    ///
    /// Изменение `body` без переподписи ломает инвариант «подпись
    /// валидна» — caller должен понимать, что делает.
    pub fn get_mut(&mut self, ident: &IdentHash) -> Option<&mut FullRouterInfo> {
        self.entries.get_mut(ident)
    }

    /// Удаляет RI, возвращает его, если был.
    pub fn remove(&mut self, ident: &IdentHash) -> Option<FullRouterInfo> {
        self.entries.remove(ident)
    }

    /// Удаляет всё.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Итератор по всем записям. Порядок не гарантирован.
    pub fn iter(&self) -> impl Iterator<Item = (&IdentHash, &FullRouterInfo)> {
        self.entries.iter()
    }

    /// Итератор по floodfill-роутерам.
    ///
    /// Floodfill — роутер с флагом `f` в caps. Эти роутеры участвуют
    /// в DHT: к ним идут `DatabaseLookup`, они хранят чужие RI и LS.
    pub fn floodfills(&self) -> impl Iterator<Item = (&IdentHash, &FullRouterInfo)> {
        self.entries
            .iter()
            .filter(|(_, ri)| ri.body().caps.is_floodfill())
    }

    /// Удаляет записи, для которых `keep` вернул `false`.
    ///
    /// Используется для очистки устаревших RI (по timestamp), для
    /// удаления недостижимых, для лимита размера — критерий целиком
    /// на caller'е.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&IdentHash, &FullRouterInfo) -> bool,
    {
        self.entries.retain(|k, v| keep(k, v));
    }

    /// Возвращает `n` роутеров, ближайших к `target` по XOR-метрике.
    ///
    /// Используется для DHT-поиска: «кто ближайший к хешу, который
    /// я ищу». XOR-расстояние между двумя 256-битными хешами —
    /// побайтовый XOR, лексикографическое сравнение результата
    /// совпадает с числовым (big-endian).
    ///
    /// Параметр `filter` — опциональный предикат: например,
    /// «только floodfill'ы» или «только достижимые».
    ///
    /// Возвращает меньше `n`, если подходящих меньше.
    ///
    /// ## Сложность
    ///
    /// `O(N log N)` — сортируем всех подходящих. Для netDb на
    /// несколько тысяч роутеров это дешевле, чем поддерживать
    /// Kademlia-дерево (см. `KadDHT.cpp` в i2pd). Когда netDb
    /// перевалит за 10 000 — можно заменить на bucket-структуру.
    #[must_use]
    pub fn closest_to<F>(&self, target: &IdentHash, n: usize, filter: F) -> Vec<&FullRouterInfo>
    where
        F: Fn(&FullRouterInfo) -> bool,
    {
        if n == 0 {
            return Vec::new();
        }
        let mut candidates: Vec<(&FullRouterInfo, [u8; 32])> = self
            .entries
            .values()
            .filter(|ri| filter(ri))
            .map(|ri| (ri, xor_distance(ri.ident_hash(), target)))
            .collect();
        // `[u8; 32]` лексикографически упорядочен по значению BE-числа,
        // так что `sort_unstable_by_key` даёт правильный порядок.
        candidates.sort_unstable_by_key(|(_, d)| *d);
        candidates.truncate(n);
        candidates.into_iter().map(|(ri, _)| ri).collect()
    }

    /// Удобная обёртка: `n` ближайших floodfill'ов к `target`.
    ///
    /// Частный случай [`Self::closest_to`] с фильтром «floodfill».
    #[must_use]
    pub fn closest_floodfills(&self, target: &IdentHash, n: usize) -> Vec<&FullRouterInfo> {
        self.closest_floodfills_excluding(target, n, &HashSet::new())
    }

    /// `n` ближайших floodfill'ов к `target`, кроме `excluded`.
    ///
    /// Соответствует `NetDb::GetClosestFloodfill` в i2pd: кандидаты,
    /// попавшие в `excluded`, не участвуют в выборе, поэтому в
    /// результат попадают именно `n` следующих по расстоянию (если
    /// они есть), а не «n минус исключённые».
    ///
    /// Недостижимые RI (по политике [`Self::is_reachable`]) и RI без
    /// валидных адресов **пропускаются**: i2pd в
    /// `GetClosestFloodfill` проверяет `!IsUnreachable () &&
    /// HasValidAddresses ()` (`NetDb.cpp:537`), иначе выбрал бы
    /// флудфиллом того, до кого нельзя достучаться.
    #[must_use]
    pub fn closest_floodfills_excluding(
        &self,
        target: &IdentHash,
        n: usize,
        excluded: &HashSet<IdentHash>,
    ) -> Vec<&FullRouterInfo> {
        self.closest_to(target, n, |ri| {
            ri.body().caps.is_floodfill() && !excluded.contains(ri.ident_hash()) && self.is_reachable(ri)
        })
    }

    /// `n` ближайших роутеров к `target` без фильтра по caps.
    ///
    /// Недостижимые RI пропускаются — как `NetDb::FindRandomRouter` /
    /// обход `m_RouterInfos` в i2pd (`NetDb.cpp:704`), которые
    /// отбрасывают `IsUnreachable` и неполные RI.
    #[must_use]
    pub fn closest_routers(&self, target: &IdentHash, n: usize) -> Vec<&FullRouterInfo> {
        self.closest_to(target, n, |ri| self.is_reachable(ri))
    }
}

/// XOR-расстояние между двумя `IdentHash`.
///
/// Результат — `[u8; 32]`. Лексикографический порядок массива
/// совпадает с числовым порядком при интерпретации как BE-числа.
///
/// Публичный, потому что полезен и вне netDb — например, для
/// `CreateRoutingKey` и сравнения маршрутов.
#[must_use]
pub fn xor_distance(a: &IdentHash, b: &IdentHash) -> [u8; 32] {
    let mut d = [0u8; 32];
    let a = a.as_bytes();
    let b = b.as_bytes();
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}
