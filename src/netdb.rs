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
//! - **Floodfill-подмножество**: отдельного индекса нет, `floodfills()`
//!   фильтрует по `is_floodfill()`. Когда floodfill'ов станет много,
//!   можно добавить отдельный `HashSet` — сейчас преждевременно.
//! - **Запросы** (`DatabaseLookup` / `DatabaseSearchReply`): netDb — это
//!   только хранилище; логика поиска — в `RouterContext` (шаг 3a-3).

use crate::IdentHash;
use crate::router_info::FullRouterInfo;
use std::collections::HashMap;

/// Хранилище `RouterInfo` других роутеров.
///
/// ## Инварианты
///
/// - Все записи — валидные `FullRouterInfo` (подпись проверена при
///   парсинге в [`FullRouterInfo::from_buffer`]);
/// - В мапе для каждого `IdentHash` лежит ровно один RI — при
///   добавлении более новой версии старая заменяется;
/// - Порядок итерации не гарантирован (это `HashMap`).
#[derive(Debug, Default)]
pub struct NetDb {
    entries: HashMap<IdentHash, FullRouterInfo>,
}

impl NetDb {
    /// Создаёт пустое хранилище.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
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
        self.closest_to(target, n, |ri| ri.body().caps.is_floodfill())
    }

    /// `n` ближайших роутеров к `target` без фильтра.
    #[must_use]
    pub fn closest_routers(&self, target: &IdentHash, n: usize) -> Vec<&FullRouterInfo> {
        self.closest_to(target, n, |_| true)
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
