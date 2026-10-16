//! `RouterProfile` — история поведения роутера в сети.
//!
//! i2pd ведёт профиль для каждого встреченного роутера и использует
//! его при выборе первых/последних хопов туннеля: если роутер часто
//! отказывает, не отвечает на build-запросы или помечался unreachable,
//! его не выбирают.
//!
//! Соответствует `RouterProfile` из `Profiling.cpp` / `Profiling.h`.
//! Портирована только **логика**: структура полей, инкременты, пороги
//! и `IsBad`. Файловая персистентность (`Save`/`Load` через INI,
//! каталог `peerProfiles/`) и глобальный пул профилей
//! (`g_Profiles`, `GetRouterProfile`, `PersistProfiles`,
//! `DeleteObsoleteProfiles`) — отдельный слой, который появится
//! вместе с `fs`.
//!
//! ## Что НЕ портировано
//!
//! - `m_LastEndpoint` (SSU2) — вернётся вместе с SSU2.
//! - `UpdateRouterProfile` (postponed updates) — глобальный стейт,
//!   ему не место в этом модуле.

use rand::Rng;

// --- константы -----------------------------------------------------------

/// Через сколько секунд профиль считается устаревшим и может быть
/// удалён (в i2pd — `PEER_PROFILE_EXPIRATION_TIMEOUT`).
pub const PEER_PROFILE_EXPIRATION_TIMEOUT: u64 = 36 * 60 * 60; // 1.5 суток

/// Через сколько секунд после последнего отказа роутер перестаёт
/// считаться «недавно отказавшим».
pub const PEER_PROFILE_DECLINED_RECENTLY_INTERVAL: u64 = 330;

/// Через сколько секунд после пометки unreachable она сбрасывается
/// (если роутер не помечен снова).
pub const PEER_PROFILE_UNREACHABLE_INTERVAL: u64 = 480;

/// Сколько неотвеченных build-запросов нужно, чтобы профиль
/// считался «полезным» (для сохранения на диск и повторного
/// использования).
pub const PEER_PROFILE_USEFUL_THRESHOLD: f32 = 3.0;

/// Порог declined (без agreed), после которого роутер считается
/// «всегда отказывающим».
pub const PEER_PROFILE_ALWAYS_DECLINING_NUM: u32 = 5;

// --- RouterProfile -------------------------------------------------------

/// Накопительная статистика по одному роутеру.
///
/// ## Обновляемость
///
/// Все мутирующие методы обновляют [`last_update_time`] и ставят
/// флаг [`is_updated`]. Это позволяет слою персистентности сохранять
/// только изменённые профили. Геттеры времени (`last_update_time`,
/// `last_access_time`, `last_persist_time`) не мутируют.
///
/// ## Замечание про `now_s`
///
/// Каждый метод, которому нужно текущее время, принимает его
/// параметром. Это (а) делает тесты детерминированными, (б) не
/// тащит сюда `SystemTime` и не создаёт соблазн читать часы из
/// середины логики.
///
/// [`last_update_time`]: Self::last_update_time
/// [`is_updated`]: Self::is_updated
#[derive(Debug, Clone)]
pub struct RouterProfile {
    // --- timestamps (seconds since epoch) ---
    last_decline_time: u64,
    last_unreachable_time: u64,
    last_update_time: u64,
    last_access_time: u64,
    last_persist_time: u64,
    // --- participation ---
    num_tunnels_agreed: u32,
    num_tunnels_declined: u32,
    /// Дробное: половина туннеля, в котором мы — не первый хоп,
    /// приносит +0.5. Округление до `u32` теряло бы это.
    num_tunnels_non_replied: f32,
    // --- usage ---
    num_times_taken: u32,
    num_times_rejected: u32,
    has_connected: bool,
    is_duplicated: bool,
    // --- dirty ---
    is_updated: bool,
}

impl RouterProfile {
    /// Новый профиль. Все счётчики — нули, `last_update_time = now_s`.
    #[must_use]
    pub const fn new(now_s: u64) -> Self {
        Self {
            last_decline_time: 0,
            last_unreachable_time: 0,
            last_update_time: now_s,
            last_access_time: 0,
            last_persist_time: 0,
            num_tunnels_agreed: 0,
            num_tunnels_declined: 0,
            num_tunnels_non_replied: 0.0,
            num_times_taken: 0,
            num_times_rejected: 0,
            has_connected: false,
            is_duplicated: false,
            is_updated: false,
        }
    }

    // --- timestamps ------------------------------------------------------

    #[must_use]
    pub const fn last_update_time(&self) -> u64 {
        self.last_update_time
    }

    #[must_use]
    pub const fn last_access_time(&self) -> u64 {
        self.last_access_time
    }

    pub const fn set_last_access_time(&mut self, ts: u64) {
        self.last_access_time = ts;
    }

    #[must_use]
    pub const fn last_persist_time(&self) -> u64 {
        self.last_persist_time
    }

    pub const fn set_last_persist_time(&mut self, ts: u64) {
        self.last_persist_time = ts;
    }

    #[must_use]
    pub const fn is_updated(&self) -> bool {
        self.is_updated
    }

    pub const fn set_updated(&mut self, updated: bool) {
        self.is_updated = updated;
    }

    // --- participation ---------------------------------------------------

    /// Ответ роутера на build-request туннеля.
    ///
    /// Соответствует `RouterProfile::TunnelBuildResponse`:
    /// `ret > 0` — отказ (declined), `ret == 0` — согласие (agreed).
    /// При согласии `last_decline_time` сбрасывается в ноль: i2pd
    /// считает, что «недавно отказавший» статус снимается первым же
    /// согласием.
    pub const fn tunnel_build_response(&mut self, ret: u8, now_s: u64) {
        self.update_time(now_s);
        if ret > 0 {
            self.num_tunnels_declined += 1;
            self.last_decline_time = now_s;
        } else {
            self.num_tunnels_agreed += 1;
            self.last_decline_time = 0;
        }
    }

    /// Роутер не ответил на build-request.
    ///
    /// `tunnel_length` — число хопов в туннеле. Вклад роутера в
    /// `non_replied` равен `1 / tunnel_length`: чем длиннее туннель,
    /// тем меньше вероятность, что «молчание» — именно на этом хопе.
    ///
    /// Соответствует `RouterProfile::TunnelNonReplied`.
    pub fn tunnel_non_replied(&mut self, tunnel_length: u32, now_s: u64) {
        if tunnel_length == 0 {
            return;
        }
        if tunnel_length == 1 {
            self.num_tunnels_non_replied += 1.0;
        } else {
            // i2pd: `1.0f/tunnelLength` — float-деление, приводим явно.
            #[allow(clippy::cast_precision_loss)]
            let fl = tunnel_length as f32;
            self.num_tunnels_non_replied += 1.0 / fl;
        }
        self.update_time(now_s);
        // i2pd: если non_replied больше половины от «ответивших» и
        // больше 3 — пометить как недавно отказавшего.
        let responded = u64::from(self.num_tunnels_agreed) + u64::from(self.num_tunnels_declined);
        #[allow(clippy::cast_precision_loss)]
        let responded_f = responded as f32;
        if self.num_tunnels_non_replied > responded_f && self.num_tunnels_non_replied > 3.0 {
            self.last_decline_time = now_s;
        }
    }

    // --- reachability ----------------------------------------------------

    /// Помечает роутер как unreachable (или снимает пометку).
    ///
    /// Соответствует `RouterProfile::Unreachable`.
    pub const fn set_unreachable(&mut self, unreachable: bool, now_s: u64) {
        self.last_unreachable_time = if unreachable { now_s } else { 0 };
        self.update_time(now_s);
    }

    /// Успешное соединение с роутером (любое: входящее или NTCP2).
    ///
    /// Соответствует `RouterProfile::Connected`.
    pub const fn connected(&mut self, now_s: u64) {
        self.has_connected = true;
        self.update_time(now_s);
    }

    /// Помечает роутер как duplicated (найден другой с тем же ключом,
    /// или адрес в `SessionConfirmed` не совпал с опубликованным).
    ///
    /// Соответствует `RouterProfile::Duplicated`. В отличие от
    /// остальных мутаторов, `UpdateTime` здесь i2pd **не делает** —
    /// `Duplicated` вызывается из `UpdateRouterProfile`-колбэка,
    /// время не важно.
    pub const fn set_duplicated(&mut self) {
        self.is_duplicated = true;
    }

    /// Роутер помечался unreachable и пометка ещё не истекла?
    ///
    /// Побочно сбрасывает `last_unreachable_time` в ноль, если он
    /// устарел (i2pd делает так же — см. `RouterProfile::IsUnreachable`).
    /// Поэтому `&mut self`.
    pub const fn is_unreachable(&mut self, now_s: u64) -> bool {
        if self.last_unreachable_time == 0 {
            return false;
        }
        // i2pd проверяет оба направления, чтобы пережить скачок часов.
        if now_s > self.last_unreachable_time + PEER_PROFILE_UNREACHABLE_INTERVAL
            || now_s + PEER_PROFILE_UNREACHABLE_INTERVAL < self.last_unreachable_time
        {
            self.last_unreachable_time = 0;
        }
        self.last_unreachable_time != 0
    }

    /// Роутер недавно отказал (или «молчал» слишком много раз)?
    ///
    /// Побочно сбрасывает `last_decline_time`, если он устарел.
    pub const fn is_declined_recently(&mut self, now_s: u64) -> bool {
        if self.last_decline_time == 0 {
            return false;
        }
        if now_s > self.last_decline_time + PEER_PROFILE_DECLINED_RECENTLY_INTERVAL
            || now_s + PEER_PROFILE_DECLINED_RECENTLY_INTERVAL < self.last_decline_time
        {
            self.last_decline_time = 0;
        }
        self.last_decline_time != 0
    }

    // --- accessors для persistence / diagnostics -------------------------

    #[must_use]
    pub const fn is_duplicated(&self) -> bool {
        self.is_duplicated
    }

    /// У роутера есть хоть какая-то осмысленная история?
    ///
    /// Соответствует `RouterProfile::IsReal`: успешное соединение,
    /// либо хотя бы один agreed/declined build-response.
    #[must_use]
    pub const fn is_real(&self) -> bool {
        self.has_connected || self.num_tunnels_agreed > 0 || self.num_tunnels_declined > 0
    }

    /// Профиль стоит сохранять на диск?
    ///
    /// Соответствует `RouterProfile::IsUseful`.
    #[must_use]
    pub fn is_useful(&self) -> bool {
        self.is_real() || self.num_tunnels_non_replied >= PEER_PROFILE_USEFUL_THRESHOLD
    }

    /// Доля согласий меньше 20%?
    ///
    /// Соответствует `RouterProfile::IsLowPartcipationRate`
    /// (`4*agreed < declined`).
    #[must_use]
    pub const fn is_low_participation_rate(&self) -> bool {
        4 * self.num_tunnels_agreed < self.num_tunnels_declined
    }

    /// Слишком много молчаний относительно ответов?
    ///
    /// Соответствует `RouterProfile::IsLowReplyRate`.
    #[must_use]
    pub fn is_low_reply_rate(&self) -> bool {
        let total = u64::from(self.num_tunnels_agreed) + u64::from(self.num_tunnels_declined);
        #[allow(clippy::cast_precision_loss)]
        let threshold = 10.0 * ((total + 1) as f32);
        self.num_tunnels_non_replied > threshold
    }

    /// Ни одного согласия, но много отказов?
    ///
    /// Соответствует `RouterProfile::IsAlwaysDeclining`.
    #[must_use]
    pub const fn is_always_declining(&self) -> bool {
        self.num_tunnels_agreed == 0
            && self.num_tunnels_declined >= PEER_PROFILE_ALWAYS_DECLINING_NUM
    }

    // --- selection -------------------------------------------------------

    /// Стоит ли пропустить этого роутера при выборе пиров?
    ///
    /// ... (док про параметры как был) ...
    ///
    /// ## Порядок проверок
    ///
    /// Ровно как в i2pd:
    ///
    /// 1. `is_unreachable` / `is_duplicated` / `is_declined_recently`
    ///    — без rng.
    /// 2. Один `roll = rng.next_u32() % 100` — вычисление
    ///    `check_is_known`. Если `check_is_known` и у роутера нет
    ///    ни одного agreed/declined — сразу `return true`.
    /// 3. Второй бросок — либо `rng.next_u32() % total`, либо,
    ///    если история пустая, но есть `non_replied` — сравнение
    ///    через `%` от `floor(non_replied)`.
    ///
    /// ## Отличие от i2pd
    ///
    /// В i2pd шаг 3 делает C-cast `(int)m_NumTunnelsNonReplied`.
    /// При `non_replied < 1.0` это даёт ноль, и следующая операция
    /// `rng() % 0` — UB. При очень больших значениях — тоже UB.
    /// Мы работаем в `f64` без приведения к целому (значения
    /// представимы точно, а `%` на f64 даёт тот же результат, что
    /// целочисленный `%`), а на входе явно проверяем инвариант
    /// «неотрицательно и конечно».
    ///
    /// # Panics
    ///
    /// Паникует, если `num_tunnels_non_replied` оказался NaN,
    /// `±∞` или отрицательным. По построению ([`Self::tunnel_non_replied`]
    /// прибавляет только `1.0` или `1.0/n` при `n >= 1`) это
    /// невозможно; нарушение инварианта сигналит о баге в самом
    /// `RouterProfile`, а не о проблеме входных данных.
    pub fn is_bad(
        &mut self,
        now_s: u64,
        tunnel_creation_success_rate: f64,
        rng: &mut impl Rng,
    ) -> bool {
        if self.is_unreachable(now_s) || self.is_duplicated {
            return true;
        }
        if self.is_declined_recently(now_s) {
            return true;
        }

        // Инвариант по построению. Проверяем явно: дальше это
        // значение участвует в арифметике, и тихо пропущенный
        // NaN привёл бы к «случайно неверному» решению при выборе
        // пиров, которое очень трудно отловить.
        assert!(
            self.num_tunnels_non_replied.is_finite() && self.num_tunnels_non_replied >= 0.0,
            "RouterProfile invariant violated: \
             num_tunnels_non_replied must be finite and non-negative, got {}",
            self.num_tunnels_non_replied,
        );

        let roll1 = rng.next_u32() % 100;
        let check_is_known = tunnel_creation_success_rate < f64::from(roll1);
        if check_is_known && self.num_tunnels_agreed == 0 && self.num_tunnels_declined == 0 {
            return true;
        }

        let total = u64::from(self.num_tunnels_agreed) + u64::from(self.num_tunnels_declined);

        let is_bad = if total > 0 {
            let roll2 = u64::from(rng.next_u32()) % total;
            u64::from(self.num_tunnels_agreed) < roll2
        } else if self.num_tunnels_non_replied >= 1.0 {
            // i2pd: `isBad = m_ProfilesRng () % (int)m_NumTunnelsNonReplied;`
            //
            // Эквивалент: «rng() % floor(non_replied) != 0».
            // Считаем в f64: и rng(), и floor-значение представимы
            // точно, `%` для f64 здесь даёт тот же результат, что
            // целочисленный `%`. Никаких C-cast'ов.
            let n = f64::from(self.num_tunnels_non_replied.trunc());
            let r = f64::from(rng.next_u32());
            (r % n) != 0.0
        } else {
            // Сюда попадаем при `0 < non_replied < 1.0` (или ровно 0).
            // i2pd в этом случае уходит в `% 0` — UB. Возвращать
            // здесь «случайное» значение было бы маскировкой баги,
            // поэтому честно возвращаем false: «не считаем роутера
            // плохим по этому критерию».
            false
        };

        if is_bad {
            self.num_times_rejected += 1;
        } else {
            self.num_times_taken += 1;
        }
        is_bad
    }

    // --- private ---------------------------------------------------------

    const fn update_time(&mut self, now_s: u64) {
        self.last_update_time = now_s;
        self.is_updated = true;
    }
}
