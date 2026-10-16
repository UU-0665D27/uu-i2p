//! State machine поиска `RouterInfo` через floodfill'ы.
//!
//! Соответствует `NetDbRequests` из `NetDbRequests.cpp` / `NetDbRequests.h`
//! в i2pd. Модуль синхронный и без I/O: caller вызывает
//! [`NetDbRequests::tick`] периодически, получает список [`SendAction`]
//! и сам отправляет `I2npMessage` через свой транспорт (`Ntcp2Pool`
//! в [`crate::router_context::RouterContext`], в будущем — через
//! туннели).
//!
//! ## Что реализовано
//!
//! - [`RequestedDestination`] — состояние одного запроса;
//! - [`NetDbRequests`] — пул запросов и тайминги;
//! - перебор floodfill'ов по XOR-расстоянию с исключением уже
//!   опрошенных;
//! - exploratory-запросы (поиск «любых» роутеров для расширения
//!   netdb).
//!
//! ## Что НЕ реализовано
//!
//! - кэш завершённых запросов (`REQUEST_CACHE_TIME`): удаляем сразу,
//!   повторный запрос всегда даёт новую запись. Вернёмся, если
//!   обнаружим спам;
//! - поиск `LeaseSet` (`LookupType::LeaseSet` и `Normal` для LS):
//!   у нас нет LS-хранилища, отдельный шаг;
//! - отправка через туннели (пока у нас их нет, всё direct);
//! - `FindRequest` / `PostRequestDestination` с разделением потоков:
//!   у нас всё в одном потоке, блокировки не нужны.

use crate::{
    I2npMessage, IdentHash, database_lookup::DatabaseLookup,
    database_search_reply::DatabaseSearchReply, i2np::I2npMessageType,
};
use std::collections::{HashMap, HashSet};

// --- константы -----------------------------------------------------------
// Значения синхронизированы с i2pd `NetDbRequests.h`.

/// Сколько раз пробуем опросить floodfill'ы для обычного запроса.
pub const MAX_NUM_REQUEST_ATTEMPTS: u32 = 5;

/// Минимальный интервал между попытками (обычный запрос).
pub const MIN_REQUEST_TIME_MS: u64 = 1200;

/// Минимальный интервал между попытками, если запрос шёл «напрямую».
/// Для нас это всегда так, но поле `is_direct` в
/// [`RequestedDestination`] сохранено для совместимости с i2pd.
pub const MIN_DIRECT_REQUEST_TIME_MS: u64 = 600;

/// Максимальное время жизни обычного запроса.
pub const MAX_REQUEST_TIME_MS: u64 = 9_500;

/// Максимальное время жизни exploratory-запроса.
pub const MAX_EXPLORATORY_REQUEST_TIME_MS: u64 = 30_000;

// --- RequestedDestination ------------------------------------------------

/// Состояние одного поиска.
///
/// Поля публичны для удобства тестов и диагностики; менять их
/// снаружи в обход [`NetDbRequests`] не нужно — это сломает тайминги.
#[derive(Debug, Clone)]
pub struct RequestedDestination {
    /// Что ищем.
    pub destination: IdentHash,
    /// Exploratory (любые роутеры) или обычный (конкретный RI).
    pub is_exploratory: bool,
    /// Отправляем напрямую. Пока у нас всегда `true`, но поле
    /// сохранено: `MIN_DIRECT_REQUEST_TIME_MS` и
    /// `MIN_REQUEST_TIME_MS` различаются.
    pub is_direct: bool,
    /// Ждём ли ещё ответа. `false` — запрос завершён (успех или
    /// провал), `tick` его удалит.
    pub is_active: bool,
    /// Кого уже спросили (или кто сам исключён пиром).
    pub excluded: HashSet<IdentHash>,
    /// Когда запрос создан (ms since epoch).
    pub creation_time_ms: u64,
    /// Когда последний раз отправляли запрос.
    pub last_request_time_ms: u64,
    /// Сколько попыток сделано.
    pub num_attempts: u32,
}

impl RequestedDestination {
    /// Новый запрос.
    #[must_use]
    fn new(destination: IdentHash, is_exploratory: bool, is_direct: bool, now_ms: u64) -> Self {
        Self {
            destination,
            is_exploratory,
            is_direct,
            is_active: true,
            excluded: HashSet::new(),
            creation_time_ms: now_ms,
            last_request_time_ms: 0,
            num_attempts: 0,
        }
    }

    /// Максимальное время жизни запроса.
    #[must_use]
    const fn max_time_ms(&self) -> u64 {
        if self.is_exploratory {
            MAX_EXPLORATORY_REQUEST_TIME_MS
        } else {
            MAX_REQUEST_TIME_MS
        }
    }

    /// Минимальный интервал между попытками.
    #[must_use]
    const fn min_interval_ms(&self) -> u64 {
        if self.is_direct {
            MIN_DIRECT_REQUEST_TIME_MS
        } else {
            MIN_REQUEST_TIME_MS
        }
    }
}

// --- SendAction ----------------------------------------------------------

/// Что caller должен сделать после [`NetDbRequests::tick`].
///
/// Пока только отправка `DatabaseLookup`; в будущем сюда добавится
/// отправка через туннель и/или через garlic-шифрование.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendAction {
    /// Кому.
    pub to: IdentHash,
    /// Что.
    pub message: I2npMessage,
}

// --- NetDbRequests -------------------------------------------------------

/// Пул активных запросов.
///
/// Все методы берут `&mut self` — состояние меняется на каждом шаге
/// (обновление `last_request_time`, `excluded`, `num_attempts`).
/// Это ожидаемо: `NetDbRequests` живёт внутри `RouterContext`,
/// один экземпляр.
#[derive(Debug, Default)]
pub struct NetDbRequests {
    requests: HashMap<IdentHash, RequestedDestination>,
}

impl NetDbRequests {
    /// Пустой пул.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Сколько запросов сейчас в пуле (включая завершённые,
    /// которые ещё не успел удалить [`Self::tick`]).
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Пул пуст?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Есть ли активный запрос по этому `IdentHash`.
    #[must_use]
    pub fn is_active(&self, dest: &IdentHash) -> bool {
        self.requests.get(dest).is_some_and(|r| r.is_active)
    }

    /// Состояние запроса, если есть.
    #[must_use]
    pub fn get(&self, dest: &IdentHash) -> Option<&RequestedDestination> {
        self.requests.get(dest)
    }

    /// Начать запрос `RouterInfo` по `dest`.
    ///
    /// Возвращает `true`, если запрос зарегистрирован. `false` —
    /// если такой уже есть **и активен**. Завершённый (неактивный)
    /// запрос перезапускается с нуля.
    pub fn new_request(
        &mut self,
        dest: IdentHash,
        exploratory: bool,
        direct: bool,
        now_ms: u64,
    ) -> bool {
        if let Some(existing) = self.requests.get(&dest)
            && existing.is_active
        {
            return false;
        }
        self.requests.insert(
            dest,
            RequestedDestination::new(dest, exploratory, direct, now_ms),
        );
        true
    }

    /// Обработать входящий `DatabaseSearchReply`.
    ///
    /// Пир, которому мы послали запрос, вернул список известных
    /// ему роутеров. Записываем их в `excluded`, чтобы не спрашивать
    /// тех же в следующий раз.
    ///
    /// Если запрос не найден или неактивен — тихо игнорируем
    /// (поздний ответ на уже завершённый запрос).
    pub fn handle_search_reply(&mut self, reply: &DatabaseSearchReply) {
        let Some(req) = self.requests.get_mut(&reply.key) else {
            return;
        };
        if !req.is_active {
            return;
        }
        for h in &reply.peer_hashes {
            req.excluded.insert(*h);
        }
    }

    /// Пометить запрос завершённым (успех или провал).
    ///
    /// Возвращает `true`, если запрос был активен и теперь закрыт.
    /// `false` — если запроса нет или он уже завершён.
    ///
    /// Само удаление — в [`Self::tick`]: до следующего tick
    /// caller может заглянуть в [`Self::get`] и узнать исход.
    /// Если этого не нужно — можно и удалять сразу, но пока
    /// оставляем как есть.
    pub fn complete(&mut self, dest: &IdentHash) -> bool {
        let Some(req) = self.requests.get_mut(dest) else {
            return false;
        };
        let was_active = req.is_active;
        req.is_active = false;
        was_active
    }

    /// Удалить запрос немедленно.
    pub fn remove(&mut self, dest: &IdentHash) -> Option<RequestedDestination> {
        self.requests.remove(dest)
    }

    /// Пройтись по всем запросам, обновить тайминги, построить
    /// действия.
    ///
    /// Завершённые (неактивные) запросы удаляются. Для активных:
    ///
    /// 1. Если истёк `MAX_*_TIME` — пометить неактивным.
    /// 2. Если прошло меньше `MIN_*_TIME` с последней попытки —
    ///    пропустить.
    /// 3. Если исчерпаны `MAX_NUM_REQUEST_ATTEMPTS` — пометить
    ///    неактивным.
    /// 4. Иначе — выбрать следующего floodfill'а, собрать
    ///    `DatabaseLookup`, вернуть [`SendAction`].
    ///
    /// `choose_floodfill` — функция выбора пира. Caller передаёт
    /// обычно что-то вроде
    /// `|target, excluded, our| netdb.closest_floodfills(target, N)…`.
    /// Вынесено в параметр, чтобы модуль не зависел от внутренних
    /// деталей `NetDb` и легко тестировался.
    pub fn tick<F>(
        &mut self,
        our_hash: &IdentHash,
        now_ms: u64,
        mut choose_floodfill: F,
    ) -> Vec<SendAction>
    where
        F: FnMut(&IdentHash, &HashSet<IdentHash>, &IdentHash) -> Option<IdentHash>,
    {
        /// Решение по одному запросу, принятое до мутаций
        /// `self.requests`. Нужно, потому что борроучекер не даёт
        /// одновременно держать immutable-заимствование `req`
        /// и делать `get_mut` на том же `HashMap`.
        enum Decision {
            /// Пропустить на этом tick'е: запрос уже неактивен
            /// или ещё рано повторять.
            Skip,
            /// Пометить неактивным (истёк таймаут или исчерпаны
            /// попытки).
            Expire,
            /// Готовы послать запрос. `excluded` склонирован,
            /// чтобы вызывать `choose_floodfill` без заимствования
            /// из `self.requests`.
            Ready {
                is_exploratory: bool,
                excluded: HashSet<IdentHash>,
            },
        }

        let mut actions = Vec::new();
        let dests: Vec<IdentHash> = self.requests.keys().copied().collect();

        for dest in dests {
            let decision = {
                let Some(req) = self.requests.get(&dest) else {
                    continue;
                };

                if !req.is_active {
                    Decision::Skip
                } else if now_ms >= req.creation_time_ms.saturating_add(req.max_time_ms()) {
                    Decision::Expire
                } else if req.last_request_time_ms != 0
                    && now_ms
                        < req
                            .last_request_time_ms
                            .saturating_add(req.min_interval_ms())
                {
                    Decision::Skip
                } else if !req.is_exploratory && req.num_attempts >= MAX_NUM_REQUEST_ATTEMPTS {
                    Decision::Expire
                } else {
                    Decision::Ready {
                        is_exploratory: req.is_exploratory,
                        excluded: req.excluded.clone(),
                    }
                }
            };

            let (is_exploratory, excluded_clone) = match decision {
                Decision::Skip => continue,
                Decision::Expire => {
                    if let Some(req) = self.requests.get_mut(&dest) {
                        req.is_active = false;
                    }
                    continue;
                }
                Decision::Ready {
                    is_exploratory,
                    excluded,
                } => (is_exploratory, excluded),
            };

            // Ищем пира. Уже опрошенных и нас самих пропускает
            // `choose_floodfill` (по `excluded` и `our_hash`).
            let Some(peer) = choose_floodfill(&dest, &excluded_clone, our_hash) else {
                // Больше floodfill'ов нет — запрос «зашёл в тупик».
                // Для обычного запроса это провал; для exploratory
                // ещё есть шанс, что появятся новые floodfill'ы,
                // но по i2pd exploratory тоже сдаётся по времени.
                // Помечаем неактивным, следующий tick удалит.
                if let Some(req) = self.requests.get_mut(&dest) {
                    req.is_active = false;
                }
                continue;
            };

            // Строим DatabaseLookup.
            let mut lookup = if is_exploratory {
                DatabaseLookup::new_exploratory(dest, *our_hash, None, Vec::new())
            } else {
                DatabaseLookup::new_router_info(dest, *our_hash, None, Vec::new())
            };
            // Заполняем excluded отдельно: конструкторы принимают
            // Vec, а у нас HashSet. Порядок не важен, важно
            // содержимое.
            lookup.excluded = excluded_clone.iter().copied().collect();

            let Ok(payload) = lookup.to_buffer() else {
                // Собрать DatabaseLookup не удалось — считаем
                // попытку неудачной и продолжаем.
                continue;
            };
            let message = I2npMessage::new(I2npMessageType::DatabaseLookup, payload);

            actions.push(SendAction { to: peer, message });

            if let Some(req) = self.requests.get_mut(&dest) {
                req.excluded.insert(peer);
                req.last_request_time_ms = now_ms;
                req.num_attempts += 1;
            }
        }

        // Убираем завершённые.
        self.requests.retain(|_, r| r.is_active);

        actions
    }
}
