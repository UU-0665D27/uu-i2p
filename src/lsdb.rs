//! `Lsdb` — хранилище `LeaseSet`'ов, вторая половина netDb флудфилла.
//!
//! # Зачем отдельный модуль
//!
//! В i2pd netDb хранит два разных вида объектов: `RouterInfo`
//! (`m_RouterInfos`, у нас [`crate::netdb::NetDb`]) и `LeaseSet`
//! (`m_LeaseSets`). Правила у них разные: RI обновляется по timestamp'у,
//! `LeaseSet` — по времени публикации и типу, и хранит их **только**
//! флудфилл (`NetDb::HandleDatabaseStoreMsg`: «Not Floodfill, `LeaseSet`
//! store request ignored»). Поэтому `Lsdb` — отдельная структура, а не
//! поле `NetDb`: у неё свои инварианты и свои тесты.
//!
//! # Швы
//!
//! - **Разбор и проверка** — здесь ([`Lsdb::insert`]): сигнатура,
//!   срок жизни, порядок версий. `RouterContext` только решает,
//!   звать ли `insert` (мы флудфилл?) и как назвать результат.
//! - **Ответ на `DatabaseLookup`** — [`crate::router_context::RouterContext`]:
//!   берёт [`Lsdb::get`] и заворачивает байты в `DatabaseStore`.
//! - **Пересылка дальше** (flood) — [`crate::router::Router`]: `Lsdb`
//!   ничего не отправляет, он только хранит.
//!
//! # Что повторяет i2pd
//!
//! - `MAX_LS_BUFFER_SIZE` — 4096 байт на один `LeaseSet`
//!   (`libi2pd/LeaseSet.h:64`);
//! - `LEASE_ENDDATE_THRESHOLD` — 51 с: запись считается мёртвой чуть
//!   раньше формального истечения (`LeaseSet.h:35`,
//!   `NetDb::ManageLeaseSets`);
//! - `AddLeaseSet2`: обновляем, если тип другой или timestamp публикации
//!   больше; «непубличный» или истёкший `LeaseSet2` **удаляет** старую
//!   запись (`NetDb.cpp:405-428`);
//! - `AddLeaseSet` (тип 1): обновляем, только если в хранилище не
//!   `LeaseSet2`, и по времени истечения (`NetDb.cpp:363-397`);
//! - срок жизни `LeaseSet` (тип 1) — максимум `end_date` его lease'ов
//!   (`LeaseSet.cpp:168`); у `LeaseSet2` — `(published + expires) * 1000`.
//!
//! # Чего нет
//!
//! - `EncryptedLeaseSet2` (тип 5) и `MetaLeaseSet2` (тип 7): у нас нет
//!   разбора их тел. i2pd тип 5 принимает (`ReadFromBufferEncrypted`),
//!   тип 7 сам отвергает («Store type 7 is not supported»). Наш отказ
//!   для обоих — `Error::Unsupported`, см.
//!   `// TODO(floodfill): разбор EncryptedLeaseSet2 (тип 5).`
//! - точного аналога пула памяти i2pd (`m_LeasesPool`, `CleanUpMt`):
//!   вместо него — грубый предел [`MAX_LSDB_BYTES`] с вытеснением
//!   самой близкой к истечению записи. См.
//!   `// TODO(floodfill): пул/лимиты как m_LeasesPool в i2pd.`

use std::collections::HashMap;

use tracing::{debug, warn};

use crate::{
    IdentHash,
    database_store::StoreType,
    error::{I2PError, Result},
    lease_set::LeaseSet,
    lease_set2::LeaseSet2,
};

/// Максимальный размер одного `LeaseSet` (i2pd `MAX_LS_BUFFER_SIZE`,
/// `libi2pd/LeaseSet.h:64`).
pub const MAX_LS_BUFFER_SIZE: usize = 4096;

/// За сколько до формального истечения `LeaseSet` считается мёртвым
/// (i2pd `LEASE_ENDDATE_THRESHOLD`, `libi2pd/LeaseSet.h:35`).
pub const LEASE_ENDDATE_THRESHOLD_MS: u64 = 51_000;

/// Верхняя граница суммарного объёма хранилища.
///
/// Своё значение, не из i2pd: там память ограничивает пул
/// (`m_LeasesPool`), у нас — простой счётчик с вытеснением.
pub const MAX_LSDB_BYTES: usize = 16 * 1024 * 1024;

/// Что случилось с `LeaseSet` при [`Lsdb::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsdbOutcome {
    /// Записи не было — сохранили.
    Inserted,
    /// Запись была, новая версия новее — заменили.
    Updated,
    /// Запись была и она не старее новой — ничего не делали.
    Stale,
    /// `LeaseSet` валиден, но хранить его нельзя/незачем:
    /// `unpublished` или уже истёк (i2pd в этом случае ещё и удаляет
    /// старую запись).
    Rejected,
}

/// Одна запись хранилища.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsdbEntry {
    store_type: StoreType,
    bytes: Vec<u8>,
    published_ms: u64,
    expires_ms: u64,
}

impl LsdbEntry {
    /// Тип `DatabaseStore`, которым эта запись публикуется.
    #[must_use]
    pub const fn store_type(&self) -> StoreType {
        self.store_type
    }

    /// Сырые байты `LeaseSet` (как в payload `DatabaseStore`).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Время публикации (мс since epoch); `0` — у `LeaseSet` типа 1.
    #[must_use]
    pub const fn published_ms(&self) -> u64 {
        self.published_ms
    }

    /// Время истечения (мс since epoch).
    #[must_use]
    pub const fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}

/// Хранилище `LeaseSet`'ов флудфилла (i2pd `NetDb::m_LeaseSets`).
#[derive(Debug, Default)]
pub struct Lsdb {
    entries: HashMap<IdentHash, LsdbEntry>,
    total_bytes: usize,
}

impl Lsdb {
    /// Пустое хранилище.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Сколько `LeaseSet`'ов лежит.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Пусто ли хранилище.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Суммарный объём сохранённых байтов.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Есть ли живая запись по ключу `key` на момент `now_ms`.
    #[must_use]
    pub fn contains(&self, key: &IdentHash, now_ms: u64) -> bool {
        self.get(key, now_ms).is_some()
    }

    /// Живая запись по ключу `key` на момент `now_ms`.
    ///
    /// Просроченные записи не отдаём, даже если уборка
    /// ([`Self::expire`]) ещё не проходила: i2pd проверяет
    /// `!leaseSet->IsExpired ()` прямо в `HandleDatabaseLookupMsg`.
    #[must_use]
    pub fn get(&self, key: &IdentHash, now_ms: u64) -> Option<&LsdbEntry> {
        self.entries
            .get(key)
            .filter(|entry| entry.expires_ms > now_ms)
    }

    /// Удаляет запись (например, если пришла истёкшая версия).
    pub fn remove(&mut self, key: &IdentHash) -> Option<LsdbEntry> {
        let entry = self.entries.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes.len());
        Some(entry)
    }

    /// Кладёт `LeaseSet`, проверяя его так же, как i2pd.
    ///
    /// `store_type` — тип из `DatabaseStore`; `bytes` — его payload
    /// (начинается с identity, без байта типа).
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — `bytes` длиннее
    ///   [`MAX_LS_BUFFER_SIZE`] (i2pd отбрасывает такие с ошибкой);
    /// - ошибки разбора/проверки подписи [`LeaseSet::from_buffer`] и
    ///   [`LeaseSet2::from_buffer`];
    /// - [`I2PError::Unsupported`] — тип 5/7: разбора их тела у нас нет.
    pub fn insert(
        &mut self,
        key: IdentHash,
        store_type: StoreType,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<LsdbOutcome> {
        if bytes.len() > MAX_LS_BUFFER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: MAX_LS_BUFFER_SIZE,
                got: bytes.len(),
            });
        }

        let parsed = ParsedLs::parse(&bytes, store_type)?;
        debug!(
            key = %key.to_base32(),
            ?store_type,
            published_ms = parsed.published_ms,
            expires_ms = parsed.expires_ms,
            len = bytes.len(),
            "lsdb::insert: LeaseSet разобран"
        );

        if let Some(existing) = self.entries.get(&key)
            && !parsed.is_newer_than(existing)
        {
            debug!(
                key = %key.to_base32(),
                existing_published_ms = existing.published_ms,
                existing_expires_ms = existing.expires_ms,
                "lsdb::insert: запись не новее имеющейся"
            );
            return Ok(LsdbOutcome::Stale);
        }

        // i2pd `AddLeaseSet2`: unpublished/expired версия не просто
        // игнорируется, а стирает старую запись.
        if !parsed.storable(now_ms) {
            warn!(
                key = %key.to_base32(),
                ?store_type,
                published_ms = parsed.published_ms,
                expires_ms = parsed.expires_ms,
                "lsdb::insert: unpublished или истёкший LeaseSet"
            );
            self.remove(&key);
            return Ok(LsdbOutcome::Rejected);
        }

        let existed = self.entries.contains_key(&key);
        let entry = LsdbEntry {
            store_type,
            bytes,
            published_ms: parsed.published_ms,
            expires_ms: parsed.expires_ms,
        };
        self.total_bytes = self
            .total_bytes
            .saturating_sub(self.entries.get(&key).map_or(0, |old| old.bytes.len()));
        self.total_bytes += entry.bytes.len();
        self.entries.insert(key, entry);
        self.enforce_limit();

        Ok(if existed {
            LsdbOutcome::Updated
        } else {
            LsdbOutcome::Inserted
        })
    }

    /// Убирает просроченные записи. Возвращает число удалённых.
    ///
    /// Аналог i2pd `NetDb::ManageLeaseSets`: запись живёт до
    /// `expires - LEASE_ENDDATE_THRESHOLD`.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let deadline =
            |entry: &LsdbEntry| entry.expires_ms.saturating_sub(LEASE_ENDDATE_THRESHOLD_MS);
        let dead: Vec<IdentHash> = self
            .entries
            .iter()
            .filter(|(_, entry)| now_ms > deadline(entry))
            .map(|(key, _)| *key)
            .collect();
        for key in &dead {
            if let Some(entry) = self.entries.remove(key) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.bytes.len());
                debug!(
                    key = %key.to_base32(),
                    expires_ms = entry.expires_ms,
                    "lsdb::expire: LeaseSet удалён"
                );
            }
        }
        dead.len()
    }

    /// Держит суммарный объём в пределах [`MAX_LSDB_BYTES`], вытесняя
    /// записи с ближайшим сроком истечения.
    fn enforce_limit(&mut self) {
        while self.total_bytes > MAX_LSDB_BYTES {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_ms)
                .map(|(key, _)| *key)
            else {
                return;
            };
            if let Some(entry) = self.entries.remove(&victim) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.bytes.len());
                warn!(
                    key = %victim.to_base32(),
                    released = entry.bytes.len(),
                    total_bytes = self.total_bytes,
                    "lsdb: превышен лимит, LeaseSet вытеснен"
                );
            }
        }
    }
}

/// Разобранные метаданные `LeaseSet` — общее для типа 1 и 3.
struct ParsedLs {
    published_ms: u64,
    expires_ms: u64,
    /// `false` — `LeaseSet2` с флагом `UNPUBLISHED_LEASESET`.
    public: bool,
}

impl ParsedLs {
    fn parse(bytes: &[u8], store_type: StoreType) -> Result<Self> {
        match store_type {
            StoreType::LeaseSet => {
                let ls = LeaseSet::from_buffer(bytes)?;
                ls.verify(bytes)?;
                // i2pd `LeaseSet::ReadFromBuffer`: m_ExpirationTime —
                // максимум end_date живых lease'ов (`LeaseSet.cpp:168`).
                // i2pd добавляет к сроку `LEASE_ENDDATE_THRESHOLD`
                // (`LeaseSet::ReadFromBuffer`: `m_ExpirationTime +=
                // LEASE_ENDDATE_THRESHOLD`), а уборка его же
                // вычитает — в сумме запись живёт ровно до `end_date`.
                let expires_ms = ls
                    .leases()
                    .iter()
                    .filter(|lease| lease.is_valid())
                    .map(|lease| lease.end_date_ms)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(LEASE_ENDDATE_THRESHOLD_MS);
                Ok(Self {
                    published_ms: 0,
                    expires_ms,
                    public: true,
                })
            }
            StoreType::LeaseSet2 => {
                let ls = LeaseSet2::from_buffer(bytes)?;
                ls.verify(bytes)?;
                Ok(Self {
                    published_ms: u64::from(ls.published_timestamp()) * 1000,
                    expires_ms: ls.expiration_time_ms(),
                    public: !ls.is_unpublished(),
                })
            }
            StoreType::EncryptedLeaseSet2 | StoreType::MetaLeaseSet2 => Err(I2PError::Unsupported(
                "lsdb: EncryptedLeaseSet2/MetaLeaseSet2 пока не разбираем",
            )),
            StoreType::RouterInfo | StoreType::Unknown(_) => {
                Err(I2PError::Malformed("lsdb: insert с не-LeaseSet store_type"))
            }
        }
    }

    /// Правила обновления (i2pd `AddLeaseSet`/`AddLeaseSet2`).
    const fn is_newer_than(&self, existing: &LsdbEntry) -> bool {
        match existing.store_type {
            StoreType::LeaseSet => {
                // Тип 1 обновляется только по времени истечения, и
                // только если лежит такой же тип 1.
                self.expires_ms > existing.expires_ms
            }
            _ => {
                // `LeaseSet2`: i2pd сравнивает published timestamp
                // (и считает «другим» любой другой store_type).
                self.published_ms > existing.published_ms
            }
        }
    }

    /// Можно ли хранить: не `unpublished` и ещё не истёк.
    const fn storable(&self, now_ms: u64) -> bool {
        self.public && self.expires_ms > now_ms
    }
}
