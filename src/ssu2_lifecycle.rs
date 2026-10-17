//! SSU2 — жизненный цикл сессии: состояния и переходы.
//!
//! Зеркалит `SSU2SessionState` (`SSU2Session.h:107`) и переходы, которые i2pd
//! делает вне ввода-вывода: `Established` (`SSU2Session.cpp:338`), `Terminate`
//! (`:280`) и `RequestTermination` (`:316`). Побочные эффекты (очистка
//! очередей, снятие relay-тега, уведомление `transports.PeerDisconnected`,
//! отмена таймеров) выполняет движок — здесь только состояние и решение, что
//! именно должно произойти.
//!
//! Имена вариантов — как в i2pd; `Display`/`name` нужны для логов.

use crate::ssu2_block::Ssu2TerminationReason;

/// Состояние SSU2-сессии (`SSU2SessionState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Ssu2SessionState {
    /// Начальное состояние.
    #[default]
    Unknown,
    /// Получен токен в ответ на `TokenRequest`.
    TokenReceived,
    /// Отправлен `SessionRequest`.
    SessionRequestSent,
    /// Получен `SessionRequest` (мы Bob).
    SessionRequestReceived,
    /// Отправлен `SessionCreated`.
    SessionCreatedSent,
    /// Получен `SessionCreated` (мы Alice).
    SessionCreatedReceived,
    /// Отправлен `SessionConfirmed`.
    SessionConfirmedSent,
    /// Handshake завершён, data phase.
    Established,
    /// Отправлен `Termination`, ждём подтверждения.
    Closing,
    /// Подтверждён `Termination` в состоянии `Closing`.
    ClosingConfirmed,
    /// Сессия завершена.
    Terminated,
    /// Сессия провалилась (в т.ч. по connect-таймауту до получения ответа).
    Failed,
    /// Ждём, пока нас «представят» (`WaitForIntroduction`).
    Introduced,
    /// Hole punch.
    HolePunch,
    /// Peer test.
    PeerTest,
    /// Получен `TokenRequest` (мы Bob).
    TokenRequestReceived,
}

impl Ssu2SessionState {
    /// Сессия в data phase.
    #[must_use]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }

    /// Сессия больше не работает (`Terminated`/`Failed`).
    #[must_use]
    pub const fn is_terminated(self) -> bool {
        matches!(self, Self::Terminated | Self::Failed)
    }

    /// Идёт handshake (до data phase и без ухода из неё).
    #[must_use]
    pub const fn is_handshake(self) -> bool {
        matches!(
            self,
            Self::TokenReceived
                | Self::TokenRequestReceived
                | Self::SessionRequestSent
                | Self::SessionRequestReceived
                | Self::SessionCreatedSent
                | Self::SessionCreatedReceived
                | Self::SessionConfirmedSent
        )
    }

    /// Короткое имя для логов (как печатает i2pd в `Resending <state>`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::TokenReceived => "TokenReceived",
            Self::SessionRequestSent => "SessionRequestSent",
            Self::SessionRequestReceived => "SessionRequestReceived",
            Self::SessionCreatedSent => "SessionCreatedSent",
            Self::SessionCreatedReceived => "SessionCreatedReceived",
            Self::SessionConfirmedSent => "SessionConfirmedSent",
            Self::Established => "Established",
            Self::Closing => "Closing",
            Self::ClosingConfirmed => "ClosingConfirmed",
            Self::Terminated => "Terminated",
            Self::Failed => "Failed",
            Self::Introduced => "Introduced",
            Self::HolePunch => "HolePunch",
            Self::PeerTest => "PeerTest",
            Self::TokenRequestReceived => "TokenRequestReceived",
        }
    }
}

/// Что делать при завершении сессии ([`SessionLifecycle::request_termination`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminationPlan {
    /// Отправить блок `Termination` и перейти в `Closing`.
    pub send_termination: bool,
    /// Завершать сразу (`Done`), без отправки `Termination`.
    pub terminate_now: bool,
}

/// Состояние сессии и причина завершения (`m_State` + `m_TerminationReason`).
#[derive(Debug, Clone, Copy)]
pub struct SessionLifecycle {
    state: Ssu2SessionState,
    termination_reason: Ssu2TerminationReason,
}

impl Default for SessionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionLifecycle {
    /// Новая сессия: `Unknown`, причина — `NormalClose` (i2pd `:94`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Ssu2SessionState::Unknown,
            termination_reason: Ssu2TerminationReason::NormalClose,
        }
    }

    /// Текущее состояние.
    #[must_use]
    pub const fn state(&self) -> Ssu2SessionState {
        self.state
    }

    /// Текущая причина завершения.
    #[must_use]
    pub const fn termination_reason(&self) -> Ssu2TerminationReason {
        self.termination_reason
    }

    /// Сессия в data phase.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.state.is_established()
    }

    /// Сессия больше не работает.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.state.is_terminated()
    }

    /// Переводит в новое состояние и возвращает предыдущее (как
    /// `m_State.exchange` — удобно для логов).
    pub const fn set_state(&mut self, state: Ssu2SessionState) -> Ssu2SessionState {
        let previous = self.state;
        self.state = state;
        previous
    }

    /// `Established` (`SSU2Session.cpp:338`): переход в data phase.
    ///
    /// Возвращает `true`, если сессия действительно стала established (для
    /// идемпотентности). Эффекты (`cancel` connect-таймера, сброс handshake,
    /// планирование переотправки `RouterInfo`, `SendQueue`, `PeerConnected`)
    /// выполняет движок.
    pub const fn establish(&mut self) -> bool {
        let was = self.is_established();
        self.state = Ssu2SessionState::Established;
        !was
    }

    /// `SSU2Session.cpp:1656`: причина завершения снова `NormalClose`.
    pub const fn reset_termination_reason(&mut self) {
        self.termination_reason = Ssu2TerminationReason::NormalClose;
    }

    /// `RequestTermination` (`SSU2Session.cpp:316`).
    ///
    /// В `Established`/`Closing` — запоминаем причину, шлём `Termination`,
    /// переходим в `Closing`; иначе — [`TerminationPlan::terminate_now`]
    /// (i2pd `Done ()`).
    pub const fn request_termination(&mut self, reason: Ssu2TerminationReason) -> TerminationPlan {
        if matches!(
            self.state,
            Ssu2SessionState::Established | Ssu2SessionState::Closing
        ) {
            self.termination_reason = reason;
            self.state = Ssu2SessionState::Closing;
            TerminationPlan {
                send_termination: true,
                terminate_now: false,
            }
        } else {
            TerminationPlan {
                send_termination: false,
                terminate_now: true,
            }
        }
    }

    /// `Terminate` (`SSU2Session.cpp:280`): переход в `Terminated`.
    ///
    /// Возвращает `true`, только если сессия завершилась впервые — очистку
    /// (relay-тег, очереди, `m_SentPackets`, `m_IncompleteMessages`, …) надо
    /// делать именно тогда; повторный вызов — no-op.
    pub const fn terminate(&mut self) -> bool {
        let previous = self.set_state(Ssu2SessionState::Terminated);
        !matches!(previous, Ssu2SessionState::Terminated)
    }
}
