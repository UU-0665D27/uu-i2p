//! SSU2 — таймеры сессии: connect-таймер и не-data-ветки переотправки.
//!
//! Зеркалит ту часть `SSU2Session::Resend` (`SSU2Session.cpp:614`), которая
//! идёт **до** переотправки data-пакетов: троттлинг попыток, повторную отправку
//! handshake-пакета и плановую переотправку своего `RouterInfo`. Плюс
//! connect-таймер (`ScheduleConnectTimer` / `HandleConnectTimer`, `:138`/`:146`)
//! и `m_LastResendTime`, по которому сервер (`SSU2.cpp:1228`) решает, кого
//! звать в очередном тике.
//!
//! Переотправка data-пакетов по RTO живёт отдельно —
//! [`crate::ssu2_session::SendState::plan_resend`]; этот модуль только говорит,
//! доходить ли до неё в этом тике.
//!
//! Все времена — монотонные [`Duration`] от вызывающего (как `uint64`
//! миллисекунд since epoch у i2pd), сравнения — точь-в-точь как в i2pd.
//!
//! ## Троттлинг
//!
//! Первая строка i2pd-`Resend` (`:616`) — заведомо невыполнимое условие, из-за
//! которого троттлинг не работает (см. `notes/i2pd-bugs.md`, п. 3). Решение
//! вынесено в [`Ssu2Policy::can_attempt_resend`]; дефолт повторяет i2pd.

use std::time::Duration;

use crate::ssu2_policy::Ssu2Policy;

/// Ход попытки переотправки до ветки data-пакетов (см. [`SessionTimers::resend_step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendTimerPlan {
    /// Троттлинг не пропустил попытку — выходить сразу (i2pd `return 0`).
    pub throttled: bool,
    /// Переотправить handshake-пакет. i2pd после этого делает `return 0`:
    /// data-пакеты в этом тике не переотправляются.
    pub resend_handshake: bool,
    /// Переслать свой `RouterInfo` (data-пакеты это не исключает).
    pub resend_router_info: bool,
}

impl ResendTimerPlan {
    /// Пустой план (троттлинга нет, ничего не переотправляем).
    const fn idle() -> Self {
        Self {
            throttled: false,
            resend_handshake: false,
            resend_router_info: false,
        }
    }
}

/// Таймеры одной SSU2-сессии.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionTimers {
    /// Дедлайн connect-таймера (`m_ConnectTimer`).
    connect_deadline: Option<Duration>,
    /// Время последней отправки неподтверждённого handshake-пакета
    /// (`m_SentHandshakePacket->sendTime`); `None` — handshake завершён.
    handshake_sent: Option<Duration>,
    /// Когда в следующий раз переслать свой `RouterInfo`
    /// (`m_NextRouterInfoResendTime`); `None`/`0` — не запланировано.
    next_router_info_resend: Option<Duration>,
    /// Время последней попытки переотправки (`m_LastResendAttemptTime`).
    last_attempt: Option<Duration>,
    /// Время последней фактической переотправки data-пакетов
    /// (`m_LastResendTime`).
    last_resend: Option<Duration>,
}

impl SessionTimers {
    /// Все таймеры выключены.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // --- connect-таймер ---------------------------------------------------

    /// `ScheduleConnectTimer` (`SSU2Session.cpp:138`): дедлайн — `now + connect_timeout`.
    pub fn schedule_connect<P: Ssu2Policy>(&mut self, policy: &P, now: Duration) {
        self.connect_deadline = Some(now.saturating_add(policy.connect_timeout()));
    }

    /// `m_ConnectTimer.cancel ()` (в `Established`/`Terminate`).
    pub const fn cancel_connect(&mut self) {
        self.connect_deadline = None;
    }

    /// Дедлайн connect-таймера, если он идёт.
    #[must_use]
    pub const fn connect_deadline(&self) -> Option<Duration> {
        self.connect_deadline
    }

    /// Сработал ли connect-таймер (`HandleConnectTimer`): сессию пора завершать.
    #[must_use]
    pub fn connect_expired(&self, now: Duration) -> bool {
        self.connect_deadline.is_some_and(|d| now >= d)
    }

    // --- handshake --------------------------------------------------------

    /// Запомнить, что handshake-пакет отправлен в `now`.
    pub const fn note_handshake_sent(&mut self, now: Duration) {
        self.handshake_sent = Some(now);
    }

    /// `m_SentHandshakePacket.reset ()` (в `Established`/`Terminate`).
    pub const fn clear_handshake(&mut self) {
        self.handshake_sent = None;
    }

    /// Есть ли неподтверждённый handshake-пакет.
    #[must_use]
    pub const fn handshake_pending(&self) -> bool {
        self.handshake_sent.is_some()
    }

    /// Пора ли переотправить handshake-пакет
    /// (`ts >= sendTime + SSU2_HANDSHAKE_RESEND_INTERVAL`).
    #[must_use]
    pub fn handshake_resend_due<P: Ssu2Policy>(&self, policy: &P, now: Duration) -> bool {
        self.handshake_sent
            .is_some_and(|t| now >= t.saturating_add(policy.handshake_resend_interval()))
    }

    // --- RouterInfo -------------------------------------------------------

    /// Время плановой переотправки `RouterInfo`, если она назначена.
    #[must_use]
    pub const fn next_router_info_resend(&self) -> Option<Duration> {
        self.next_router_info_resend
    }

    /// `m_NextRouterInfoResendTime = ts + INTERVAL + rng % VARIANCE`
    /// (`Established` `:343`, `Resend` `:630`). `jitter` — сырой бросок rng,
    /// остаток берётся от [`Ssu2Policy::router_info_resend_variance`].
    pub fn schedule_router_info_resend<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        now: Duration,
        jitter: u64,
    ) {
        let variance_ms =
            u64::try_from(policy.router_info_resend_variance().as_millis()).unwrap_or(u64::MAX);
        let extra = if variance_ms == 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(jitter % variance_ms)
        };
        self.next_router_info_resend = Some(
            now.saturating_add(policy.router_info_resend_interval())
                .saturating_add(extra),
        );
    }

    /// Пора ли переслать свой `RouterInfo` (i2pd: `ts > m_NextRouterInfoResendTime`).
    #[must_use]
    pub fn router_info_resend_due(&self, now: Duration) -> bool {
        self.next_router_info_resend.is_some_and(|t| now > t)
    }

    // --- попытки переотправки --------------------------------------------

    /// Время последней попытки переотправки.
    #[must_use]
    pub const fn last_attempt(&self) -> Option<Duration> {
        self.last_attempt
    }

    /// Время последней фактической переотправки data-пакетов (`GetLastResendTime`).
    #[must_use]
    pub const fn last_resend(&self) -> Option<Duration> {
        self.last_resend
    }

    /// Отметить фактическую переотправку data-пакетов (`m_LastResendTime = ts`).
    pub const fn note_data_resent(&mut self, now: Duration) {
        self.last_resend = Some(now);
    }

    /// Одна попытка `Resend` до ветки data-пакетов (`SSU2Session.cpp:614`).
    ///
    /// Порядок ровно как в i2pd:
    /// 1. троттлинг ([`Ssu2Policy::can_attempt_resend`]) — при отказе
    ///    [`ResendTimerPlan::throttled`];
    /// 2. handshake-пакет по `handshake_resend_interval` — при срабатывании
    ///    время отправки обновляется и i2pd делает `return 0` (только
    ///    [`ResendTimerPlan::resend_handshake`]);
    /// 3. плановая переотправка `RouterInfo` — перепланируется и может идти
    ///    вместе с data-пакетами.
    ///
    /// Если ничего не сработало (план «idle») — можно переходить к
    /// [`crate::ssu2_session::SendState::plan_resend`].
    pub fn resend_step<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        now: Duration,
        jitter: u64,
    ) -> ResendTimerPlan {
        if !policy.can_attempt_resend(self.last_attempt, now) {
            return ResendTimerPlan {
                throttled: true,
                ..ResendTimerPlan::idle()
            };
        }
        self.last_attempt = Some(now);

        if self.handshake_resend_due(policy, now) {
            self.handshake_sent = Some(now);
            return ResendTimerPlan {
                resend_handshake: true,
                ..ResendTimerPlan::idle()
            };
        }

        if self.router_info_resend_due(now) {
            self.schedule_router_info_resend(policy, now, jitter);
            return ResendTimerPlan {
                resend_router_info: true,
                ..ResendTimerPlan::idle()
            };
        }

        ResendTimerPlan::idle()
    }
}
