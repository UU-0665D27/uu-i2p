//! SSU2 — соединение: драйвер рукопожатия и переход в data phase.
//!
//! Слой над [`crate::ssu2_handshake`] и [`crate::ssu2_engine`]: ведёт
//! состояния рукопожатия (i2pd `SSU2Session::Connect`,
//! `ProcessTokenRequest`, `ProcessSessionRequest`, `ProcessSessionCreated`,
//! `ProcessSessionConfirmed`, `ProcessRetry`) и в момент завершения создаёт
//! data-сессию ([`Ssu2DataSession`]).
//!
//! Ввод-вывод (UDP-сокет, поиск соединения по `destConnID`, отправка) остаётся
//! транспорту: здесь только состояния, решения и байты пакетов.
//!
//! ## Состояния (i2pd `SSU2SessionState`)
//!
//! Инициатор (Alice):
//! `Unknown` (отправлен `TokenRequest`) → `TokenReceived` (пришёл `Retry`) →
//! `SessionRequestSent` → `SessionCreatedReceived` → `SessionConfirmedSent`
//! → `Established` (пришёл `Ack`).
//!
//! Ответчик (Bob):
//! `Unknown` → `TokenRequestReceived` (`TokenRequest`, отвечаем `Retry`) или
//! (при верном токене) `SessionRequestReceived` → `SessionCreatedSent` →
//! `Established` (пришёл `SessionConfirmed`), после чего сразу шлём `QuickAck`.
//!
//! ## Разделение ответственности
//!
//! Токены хранит вызывающий ([`crate::ssu2_token::TokenStore`]): он выдаёт
//! входящий токен (`GetIncomingToken`) и передаёт его сюда в
//! [`ResponderEnv::expected_token`], а полученный в `Retry` токен кладёт в
//! исходящее хранилище по [`ConnReport::token`]. `RouterInfo` собеседника
//! проверяет тоже вызывающий — сессия отдаёт лишь его байты
//! ([`ConnReport::remote_router_info`]).

use std::time::Duration;

use tracing::{debug, trace, warn};

use crate::error::{I2PError, Result};
use crate::ssu2_block::{
    AddressBlock, Blocks, NewTokenBlock, RouterInfoBlock, Ssu2Block, Ssu2BlockType,
    Ssu2TerminationReason, TerminationBlock,
};
use crate::ssu2_crypto::DataPhaseKeys;
use crate::ssu2_engine::{
    DataSessionParams, DataSessionRole, RecvReport, SendContext, Ssu2DataSession, handshake_phase,
};
use crate::ssu2_handshake::{
    ConfirmedOutcome, HandshakeConfig, InitiatorHandshake, ResponderHandshake, RetryParams,
    SessionConfirmedParams, SessionCreatedParams, SessionRequestParams, TokenRequestParams,
    build_retry, build_token_request, handle_retry, handle_token_request,
};
use crate::ssu2_header::{
    ConnectionId, SSU2_LONG_HEADER_SIZE, Ssu2MessageType, header_mask, obfuscate_extended_header,
};
use crate::ssu2_lifecycle::{SessionLifecycle, Ssu2SessionState};
use crate::ssu2_policy::{DateTimeAction, DateTimeSession, Ssu2CongestionPolicy, Ssu2Policy};
use crate::ssu2_recv::handle_datetime;
use crate::ssu2_send::RandomSource;
use crate::ssu2_timers::SessionTimers;

/// Роль стороны в соединении.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Alice — инициирует соединение.
    Initiator,
    /// Bob — принимает входящее соединение.
    Responder,
}

/// Общие параметры соединения.
#[derive(Debug, Clone)]
pub struct ConnParams {
    /// Версия, netID, MTU (для заголовков handshake-пакетов).
    pub config: HandshakeConfig,
    /// Наш intro-ключ (деобфускация входящих заголовков).
    pub local_intro_key: [u8; 32],
    /// Intro-ключ собеседника (обфускация исходящих handshake-заголовков).
    ///
    /// У инициатора известен заранее (из `RouterInfo`); у ответчика
    /// заполняется вызывающим из `RouterInfo`, полученного в
    /// `SessionConfirmed`, — до этого байты заголовков data-пакетов
    /// зашифровать нельзя.
    pub remote_intro_key: [u8; 32],
    /// Максимальный размер payload'а пакета (`m_MaxPayloadSize`).
    pub max_payload: usize,
    /// Просить ли relay-тег в `SessionRequest` (i2pd `UsesIntroducer`).
    pub relay_tag_requested: bool,
    /// Наш `RouterInfo` для `SessionConfirmed` (значимо только у инициатора).
    pub local_router_info: Vec<u8>,
    /// Роутер в тестовом режиме.
    pub testing: bool,
    /// `m_Server.IsSyncClockFromPeers()`.
    pub sync_clock_from_peers: bool,
}

/// Контекст приёма на стороне ответчика.
#[derive(Debug, Default, Clone)]
pub struct ResponderEnv<'a> {
    /// Действующий входящий токен этого endpoint (`GetIncomingToken`).
    ///
    /// Вызывающий получает его у [`crate::ssu2_token::TokenStore`] и передаёт
    /// сюда: для `TokenRequest` это токен, который нужно выдать, для
    /// `SessionRequest` — с которым сравнивается предъявленный.
    pub expected_token: u64,
    /// Адрес источника, каким его видит сервер (блок `Address` в `Retry`).
    pub address: Option<AddressBlock>,
    /// Блоки, добавляемые в `SessionCreated` (например, `New Token`).
    pub extra_blocks: &'a [u8],
}

/// Итог обработки одного входящего пакета.
#[derive(Debug, Default)]
pub struct ConnReport {
    /// Пакеты для отправки (в порядке отправки).
    pub packets: Vec<Vec<u8>>,
    /// Рукопожатие завершено — доступна data-сессия.
    pub established: bool,
    /// Токен из `Retry`: положить в исходящее хранилище.
    pub token: Option<u64>,
    /// `New Token` из payload'а `SessionCreated` (инициатор): `(expires,
    /// token)`. i2pd `ProcessSessionCreated` → `HandlePayload` →
    /// `UpdateOutgoingToken`.
    ///
    /// Нужен, чтобы следующий `SessionRequest` ушёл без лишнего `Retry`:
    /// в `SessionCreated` ответчик выдаёт новый входящий токен, а
    /// предъявленный в `SessionRequest` — аннулирует
    /// (`NewIncomingToken`, `SSU2Session.cpp:1020`).
    pub new_token: Option<(u32, u64)>,
    /// `RouterInfo` собеседника из `SessionConfirmed` (ответчик).
    pub remote_router_info: Option<Vec<u8>>,
    /// Статический ключ `S` инициатора из `SessionConfirmed` (ответчик).
    ///
    /// Вызывающему нужен, чтобы сверить его с `s=` из полученного
    /// `RouterInfo` (i2pd `ProcessSessionConfirmed`, `SSU2Session.cpp:1415`:
    /// `memcmp (S, m_Address->s, 32)`).
    pub remote_static_key: Option<[u8; 32]>,
    /// Наш внешний адрес, каким его видит собеседник (блок `Address` в
    /// payload'е `Retry` или `SessionCreated`; i2pd `HandlePayload` →
    /// `HandleAddress`, `SSU2Session.cpp:2104` → `i2p::context.UpdateAddress`).
    ///
    /// Пакет по своей инициативе адрес не обновляет — это решение уровня
    /// роутера (какой адрес публиковать в своём `RouterInfo`).
    pub external_address: Option<AddressBlock>,
    /// Решение по блоку `DateTime` из payload'а handshake-пакета
    /// (i2pd `HandleDateTime`, `SSU2Session.cpp:1964`).
    ///
    /// Как и [`RecvReport::datetime`], ничего не применяет само: коррекцию
    /// часов (`AdjustTimeOffset`) и ошибку `ClockSkew` решает вызывающий.
    pub datetime: Option<DateTimeAction>,
    /// Собеседник отказал (`Retry` с нулевым токеном).
    pub rejected: bool,
    /// Ответчику нужно отправить `QuickAck` (i2pd `SendQuickAck` в конце
    /// `ProcessSessionConfirmed`).
    ///
    /// Отправку делает вызывающий — **после**
    /// [`Ssu2Connection::set_remote_intro_key`]: intro-ключ инициатора
    /// известен лишь из [`ConnReport::remote_router_info`], а без него
    /// заголовок `QuickAck` не замаскировать (i2pd берёт его из `m_Address`,
    /// заполненного в `ProcessSessionConfirmed`, `:1394`).
    ///
    /// Флаг поднимается и в установленной сессии, когда вместо data-пакета
    /// пришёл повторный handshake-пакет (i2pd `ProcessData`,
    /// `SSU2Session.cpp:1746`); тогда intro-ключ уже известен.
    pub quick_ack_pending: bool,
    /// Отчёт data-слоя, если входящий пакет оказался data-пакетом.
    pub data: Option<RecvReport>,
}

impl ConnReport {
    /// Единственный пакет ответа, если он есть (удобно вызывающему).
    #[must_use]
    pub fn single_packet(&self) -> Option<&[u8]> {
        if self.packets.len() == 1 {
            Some(&self.packets[0])
        } else {
            None
        }
    }
}

/// Окружение одного шага соединения: время и генератор.
pub struct ConnContext<'a, R: RandomSource> {
    /// Монотонное время (таймеры, повторы).
    pub now: Duration,
    /// Unix-время в миллисекундах (`DateTime` в data phase).
    pub now_ms: u64,
    /// Unix-время в секундах (блок `DateTime` в handshake).
    pub now_secs: u32,
    /// Монотонные микросекунды (лаг очереди отправки).
    pub now_micros: u64,
    /// Генератор (`m_Server.GetRng()`).
    pub rng: &'a mut R,
}

impl<R: RandomSource> ConnContext<'_, R> {
    /// Окружение для отправки data-пакетов.
    pub const fn send(&mut self) -> SendContext<'_, R> {
        SendContext {
            now: self.now,
            now_ms: self.now_ms,
            now_micros: self.now_micros,
            rng: &mut *self.rng,
        }
    }
}

/// `destConnID` из первых 8 байт пакета (i2pd `ProcessNextPacket`,
/// `SSU2.cpp:700`).
///
/// Нужен транспорту, чтобы найти соединение по входящему пакету. Пакет не
/// изменяется.
#[must_use]
pub fn peek_dest_conn_id(packet: &[u8], intro_key: &[u8; 32]) -> Option<ConnectionId> {
    if packet.len() < SSU2_LONG_HEADER_SIZE {
        return None;
    }
    let end = packet.len();
    let iv = packet.get(end.checked_sub(24)?..end.checked_sub(12)?)?;
    let mut iv_arr = [0u8; 12];
    iv_arr.copy_from_slice(iv);
    let mask = header_mask(intro_key, &iv_arr);
    let mut bytes = [0u8; 8];
    for (i, b) in packet[..8].iter().enumerate() {
        bytes[i] = b ^ mask[i];
    }
    Some(ConnectionId::new(bytes))
}

/// `sourceConnID` и `token` из длинного заголовка без расшифровки payload'а
/// (i2pd `ProcessSessionRequest`/`ProcessTokenRequest`: `headerX`
/// деобфусцируется intro-ключом получателя).
///
/// Нужен, чтобы проверить токен **до** создания/использования Noise-состояния
/// ответчика (иначе неверный `SessionRequest` испортил бы его).
#[must_use]
pub fn peek_long_header_ids(packet: &[u8], intro_key: &[u8; 32]) -> Option<(ConnectionId, u64)> {
    if packet.len() < SSU2_LONG_HEADER_SIZE {
        return None;
    }
    let mut ext = [0u8; 16];
    ext.copy_from_slice(&packet[16..32]);
    obfuscate_extended_header(intro_key, &mut ext);
    let mut source = [0u8; 8];
    source.copy_from_slice(&ext[..8]);
    let mut token = [0u8; 8];
    token.copy_from_slice(&ext[8..]);
    Some((ConnectionId::new(source), u64::from_be_bytes(token)))
}

/// Тип входящего длинного handshake-пакета по ключу второй половины
/// cover-заголовка (`k_header_2`).
///
/// Байт типа — 12, то есть элемент 4 второй половины (байты 8..16). У
/// `TokenRequest`/`SessionRequest`/`Retry` вторая половина замаскирована
/// intro-ключом получателя (i2pd `ProcessFirstIncomingMessage`,
/// `SSU2Session.cpp:683`), у `SessionCreated` — `k_header_2` из состояния
/// Noise (i2pd `ProcessSessionCreated`, `:1068`), у `SessionConfirmed` —
/// `k_header_2` из состояния ответчика (i2pd `ProcessSessionConfirmed`,
/// `:1219`).
///
/// Пакет не изменяется: ключ применяется к копии байтов заголовка.
#[must_use]
pub fn peek_message_type_with(packet: &[u8], k_header_2: &[u8; 32]) -> Option<Ssu2MessageType> {
    if packet.len() < SSU2_LONG_HEADER_SIZE {
        return None;
    }
    let end = packet.len();
    let mut iv = [0u8; 12];
    iv.copy_from_slice(packet.get(end.checked_sub(12)?..end)?);
    let mask = header_mask(k_header_2, &iv);
    Ssu2MessageType::from_u8(packet[12] ^ mask[4]).ok()
}

/// Тип входящего длинного handshake-пакета с одним ключом на обе половины.
#[must_use]
fn peek_message_type(packet: &[u8], intro_key: &[u8; 32]) -> Option<Ssu2MessageType> {
    peek_message_type_with(packet, intro_key)
}

/// Итог [`Ssu2Connection::poll_resend`] — что отправить в этом тике
/// (i2pd `SSU2Session::Resend`, `SSU2Session.cpp:614`).
///
/// Оба пункта могут быть сразу: i2pd после переотправки своего `RouterInfo`
/// не выходит из `Resend`, а доходит до повторa data-пакетов.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResendPlan {
    /// Неподтверждённые handshake-пакеты (i2pd `ResendHandshakePacket`).
    pub handshake_packets: Vec<Vec<u8>>,
    /// Пора переслать свой `RouterInfo` (i2pd `SendLocalRouterInfo` по
    /// `SSU2_ROUTERINFO_RESEND_INTERVAL`).
    pub resend_router_info: bool,
}

/// Одно SSU2-соединение: рукопожатие и (после него) data phase.
pub struct Ssu2Connection {
    params: ConnParams,
    role: HandshakeRole,
    lifecycle: SessionLifecycle,
    timers: SessionTimers,
    source_conn_id: ConnectionId,
    dest_conn_id: ConnectionId,
    token: u64,
    token_request_sent: bool,
    session_request_sent: bool,
    initiator: Option<InitiatorHandshake>,
    responder: Option<ResponderHandshake>,
    data: Option<Ssu2DataSession>,
    sent_handshake: Vec<Vec<u8>>,
}

impl Ssu2Connection {
    /// Соединение-инициатор (Alice).
    ///
    /// `source_conn_id` — наш идентификатор, `dest_conn_id` — идентификатор,
    /// выбранный нами для Bob'а (i2pd генерирует оба случайно,
    /// `SSU2Session.cpp:107`).
    #[must_use]
    pub fn initiator(
        params: ConnParams,
        handshake: InitiatorHandshake,
        source_conn_id: ConnectionId,
        dest_conn_id: ConnectionId,
    ) -> Self {
        Self {
            params,
            role: HandshakeRole::Initiator,
            lifecycle: SessionLifecycle::new(),
            timers: SessionTimers::new(),
            source_conn_id,
            dest_conn_id,
            token: 0,
            token_request_sent: false,
            session_request_sent: false,
            initiator: Some(handshake),
            responder: None,
            data: None,
            sent_handshake: Vec::new(),
        }
    }

    /// Соединение-ответчик (Bob) для нового входящего пакета.
    ///
    /// `source_conn_id` — наш идентификатор (то, что инициатор прислал как
    /// `destConnID`), `dest_conn_id` — идентификатор инициатора (его
    /// `sourceConnID`).
    #[must_use]
    pub fn responder(
        params: ConnParams,
        handshake: ResponderHandshake,
        source_conn_id: ConnectionId,
        dest_conn_id: ConnectionId,
    ) -> Self {
        Self {
            params,
            role: HandshakeRole::Responder,
            lifecycle: SessionLifecycle::new(),
            timers: SessionTimers::new(),
            source_conn_id,
            dest_conn_id,
            token: 0,
            token_request_sent: false,
            session_request_sent: false,
            initiator: None,
            responder: Some(handshake),
            data: None,
            sent_handshake: Vec::new(),
        }
    }

    // --- наблюдаемое состояние ------------------------------------------

    /// Роль стороны.
    #[must_use]
    pub const fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Состояние сессии.
    #[must_use]
    pub const fn state(&self) -> Ssu2SessionState {
        self.lifecycle.state()
    }

    /// Сессия в data phase.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.lifecycle.is_established()
    }

    /// Наш идентификатор соединения.
    #[must_use]
    pub const fn source_conn_id(&self) -> ConnectionId {
        self.source_conn_id
    }

    /// Идентификатор собеседника.
    #[must_use]
    pub const fn dest_conn_id(&self) -> ConnectionId {
        self.dest_conn_id
    }

    /// Токен, предъявляемый в `SessionRequest`.
    #[must_use]
    pub const fn token(&self) -> u64 {
        self.token
    }

    /// Intro-ключ собеседника (обфускация исходящих заголовков).
    #[must_use]
    pub const fn remote_intro_key(&self) -> &[u8; 32] {
        &self.params.remote_intro_key
    }

    /// Задаёт intro-ключ собеседника (ответчик узнаёт его из `RouterInfo`
    /// инициатора в `SessionConfirmed`).
    pub fn set_remote_intro_key(&mut self, intro_key: [u8; 32]) {
        debug!(intro_key = %hex32(&intro_key), "set_remote_intro_key: peer intro key");
        self.params.remote_intro_key = intro_key;
        if let Some(data) = self.data.as_mut() {
            data.set_remote_intro_key(intro_key);
        }
    }

    /// Таймеры соединения (connect-таймер, переотправка).
    #[must_use]
    pub const fn timers(&self) -> &SessionTimers {
        &self.timers
    }

    /// Таймеры соединения — изменяемые.
    pub const fn timers_mut(&mut self) -> &mut SessionTimers {
        &mut self.timers
    }

    /// Data-сессия (есть, начиная с `SessionConfirmedSent` у инициатора и с
    /// момента установления у ответчика).
    #[must_use]
    pub const fn data(&self) -> Option<&Ssu2DataSession> {
        self.data.as_ref()
    }

    /// Data-сессия — изменяемая.
    pub const fn data_mut(&mut self) -> Option<&mut Ssu2DataSession> {
        self.data.as_mut()
    }

    /// Параметры соединения.
    #[must_use]
    pub const fn params(&self) -> &ConnParams {
        &self.params
    }

    /// Ключ `k_header_2` входящего `SessionConfirmed` (только у ответчика).
    ///
    /// Транспорту нужен, чтобы в состоянии `SessionCreatedSent` отличить
    /// `SessionConfirmed` от повторного `SessionRequest` и не завершать сессию
    /// (i2pd `ProcessSessionConfirmed`, `SSU2Session.cpp:1223`).
    #[must_use]
    pub fn session_confirmed_header_key(&self) -> Option<[u8; 32]> {
        self.responder
            .as_ref()
            .map(ResponderHandshake::session_confirmed_header_key)
    }

    // --- рукопожатие -----------------------------------------------------

    /// `Connect` (i2pd `SSU2Session.cpp:117`): начинает рукопожатие.
    ///
    /// `outgoing_token` — ранее полученный токен (`FindOutgoingToken`). Если
    /// он есть, сразу отправляется `SessionRequest`, иначе — `TokenRequest`
    /// (сервер ответит `Retry` с токеном). Заводит connect-таймер.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если соединение не инициатор; ошибки сборки
    /// пакета.
    pub fn connect<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut ConnContext<'_, R>,
        outgoing_token: Option<u64>,
    ) -> Result<Vec<Vec<u8>>> {
        if self.role != HandshakeRole::Initiator {
            return Err(I2PError::Malformed("ssu2: connect called on responder"));
        }
        self.timers.schedule_connect(policy, ctx.now);
        if let Some(token) = outgoing_token {
            self.token = token;
            debug!(token, "connect: using cached outgoing token");
            self.send_session_request(policy, ctx)
        } else {
            debug!("connect: no cached token; sending TokenRequest");
            self.send_token_request(policy, ctx)
        }
    }

    /// Обрабатывает один входящий пакет.
    ///
    /// `packet` может изменяться на месте (как и в i2pd). `responder`
    /// используется только ответчиком ([`ResponderEnv`]).
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`] или [`I2PError::Malformed`] при неверном
    /// пакете/состоянии.
    pub fn recv<P: Ssu2Policy, C: Ssu2CongestionPolicy, R: RandomSource>(
        &mut self,
        policy: &P,
        congestion: &C,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
        responder: &ResponderEnv<'_>,
    ) -> Result<ConnReport> {
        match self.role {
            HandshakeRole::Initiator => self.recv_initiator(policy, congestion, packet, ctx),
            HandshakeRole::Responder => {
                self.recv_responder(policy, congestion, packet, ctx, responder)
            }
        }
    }

    /// Пора ли завершать соединение по connect-таймеру
    /// (i2pd `HandleConnectTimer`).
    #[must_use]
    pub fn connect_expired(&self, now: Duration) -> bool {
        self.timers.connect_expired(now)
    }

    /// Один тик переотправки на этапе рукопожатия (i2pd `Resend`,
    /// `ResendHandshakePacket`): возвращает неподтверждённые handshake-пакеты,
    /// если таймер сработал.
    #[must_use]
    pub fn poll_resend<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        now: Duration,
        jitter: u64,
    ) -> ResendPlan {
        let plan = self.timers.resend_step(policy, now, jitter);
        let handshake_packets = if plan.resend_handshake {
            debug!(
                state = self.lifecycle.state().name(),
                packets = self.sent_handshake.len(),
                "poll_resend: resending handshake packets"
            );
            self.sent_handshake.clone()
        } else {
            Vec::new()
        };
        ResendPlan {
            handshake_packets,
            resend_router_info: plan.resend_router_info,
        }
    }

    /// Отправляет `QuickAck` (i2pd `SendQuickAck`).
    ///
    /// Ответчик вызывает её сразу после [`ConnReport::quick_ack_pending`] и
    /// [`Self::set_remote_intro_key`]: заголовок data-пакета маскируется
    /// intro-ключом собеседника.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если data-сессии ещё нет; ошибки сборки.
    pub fn send_quick_ack<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<Vec<u8>> {
        let data = self
            .data
            .as_mut()
            .ok_or(I2PError::Malformed("ssu2: no data session for QuickAck"))?;
        let mut send_ctx = ctx.send();
        let packet = data.send_quick_ack(policy, &mut send_ctx)?;
        debug!("send_quick_ack: QuickAck sent");
        Ok(packet)
    }

    // --- внутреннее ------------------------------------------------------

    /// Меняет состояние и (если есть) зеркалит его в data-сессию — от него
    /// зависят решения по `DateTime`.
    fn set_state(&mut self, state: Ssu2SessionState) -> Ssu2SessionState {
        let previous = self.lifecycle.set_state(state);
        if previous != state {
            trace!(from = previous.name(), to = state.name(), "state");
        }
        if let Some(data) = self.data.as_mut() {
            data.set_state(state);
        }
        previous
    }

    /// `Established` (i2pd `SSU2Session.cpp:331`): data phase, отмена
    /// connect-таймера и плановая переотправка своего `RouterInfo`.
    fn establish<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut ConnContext<'_, R>,
    ) {
        self.set_state(Ssu2SessionState::Established);
        self.timers.cancel_connect();
        self.timers.clear_handshake();
        let jitter = u64::from(ctx.rng.roll());
        self.timers
            .schedule_router_info_resend(policy, ctx.now, jitter);
        debug!("establish: session established");
    }

    fn data_session<C: Ssu2CongestionPolicy>(
        &self,
        role: DataSessionRole,
        data_keys: DataPhaseKeys,
        congestion: &C,
        now: Duration,
    ) -> Ssu2DataSession {
        Ssu2DataSession::new(
            DataSessionParams {
                role,
                source_conn_id: self.source_conn_id,
                dest_conn_id: self.dest_conn_id,
                data_keys,
                local_intro_key: self.params.local_intro_key,
                remote_intro_key: self.params.remote_intro_key,
                max_payload: self.params.max_payload,
                testing: self.params.testing,
                sync_clock_from_peers: self.params.sync_clock_from_peers,
            },
            congestion,
            now,
        )
    }

    fn remember_handshake(&mut self, packets: &[Vec<u8>], now: Duration) {
        self.sent_handshake = packets.to_vec();
        self.timers.note_handshake_sent(now);
    }

    fn send_token_request<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<Vec<Vec<u8>>> {
        let params = TokenRequestParams {
            dest_conn_id: self.dest_conn_id,
            source_conn_id: self.source_conn_id,
            packet_num: ctx.rng.roll(),
            now_secs: ctx.now_secs,
            pad_roll: roll_u8(ctx.rng),
        };
        let packet = build_token_request(
            policy,
            &self.params.config,
            &self.params.remote_intro_key,
            &params,
        )?;
        // i2pd оставляет состояние `Unknown` (Connect выставляет его перед
        // вызовом), а признаком служит `m_SentHandshakePacket`.
        self.token_request_sent = true;
        let packets = vec![packet];
        self.remember_handshake(&packets, ctx.now);
        debug!("send_token_request: TokenRequest sent");
        Ok(packets)
    }

    fn send_session_request<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<Vec<Vec<u8>>> {
        let params = SessionRequestParams {
            dest_conn_id: self.dest_conn_id,
            source_conn_id: self.source_conn_id,
            token: self.token,
            packet_num: ctx.rng.roll(),
            now_secs: ctx.now_secs,
            relay_tag_requested: self.params.relay_tag_requested,
            pad_roll: roll_u8(ctx.rng),
        };
        let handshake = self
            .initiator
            .as_mut()
            .ok_or(I2PError::Malformed("ssu2: no initiator handshake"))?;
        if self.session_request_sent {
            // i2pd `ProcessRetry`: Noise-состояние пересоздаётся заново.
            handshake.restart();
        }
        let packet = handshake.build_session_request(policy, &params)?;
        self.session_request_sent = true;
        self.set_state(Ssu2SessionState::SessionRequestSent);
        let packets = vec![packet];
        self.remember_handshake(&packets, ctx.now);
        debug!(
            token = self.token,
            "send_session_request: SessionRequest sent"
        );
        Ok(packets)
    }

    /// Собирает `Retry` (i2pd `SendRetry`).
    fn send_retry<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut ConnContext<'_, R>,
        token: u64,
        reason: Option<Ssu2TerminationReason>,
        address: Option<&AddressBlock>,
    ) -> Result<Vec<Vec<u8>>> {
        let params = RetryParams {
            dest_conn_id: self.dest_conn_id,
            source_conn_id: self.source_conn_id,
            packet_num: ctx.rng.roll(),
            token,
            now_secs: ctx.now_secs,
            valid_packets: 0,
            address,
            reason,
            pad_roll: roll_u8(ctx.rng),
        };
        let packet = build_retry(
            policy,
            &self.params.config,
            &self.params.local_intro_key,
            &params,
        )?;
        let packets = vec![packet];
        self.remember_handshake(&packets, ctx.now);
        debug!(token, ?reason, "send_retry: Retry sent");
        Ok(packets)
    }

    fn recv_initiator<P: Ssu2Policy, C: Ssu2CongestionPolicy, R: RandomSource>(
        &mut self,
        policy: &P,
        congestion: &C,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<ConnReport> {
        match self.lifecycle.state() {
            // `Unknown`/`TokenReceived` — ждём `Retry` (i2pd:
            // `ProcessRetry` для незавершённой исходящей сессии).
            Ssu2SessionState::Unknown | Ssu2SessionState::TokenReceived => {
                self.recv_retry(policy, packet, ctx)
            }
            Ssu2SessionState::SessionRequestSent => {
                // В этом состоянии от собеседника приходит либо `SessionCreated`
                // (токен принят), либо `Retry` (токен устарел). i2pd пробует
                // `ProcessSessionCreated`, а при неудаче — `ProcessRetry`; мы
                // различаем их по типу, посчитанному ключами обеих половин
                // заголовка, — так пробная попытка не портит Noise-состояние.
                if self.peek_is_session_created(packet) {
                    self.recv_session_created(policy, congestion, packet, ctx)
                } else {
                    self.recv_retry(policy, packet, ctx)
                }
            }
            Ssu2SessionState::SessionConfirmedSent
            | Ssu2SessionState::Established
            | Ssu2SessionState::Closing
            | Ssu2SessionState::ClosingConfirmed => self.recv_data(policy, congestion, packet, ctx),
            other => {
                warn!(state = other.name(), "recv_initiator: unexpected state");
                Err(I2PError::Malformed("ssu2: packet in unexpected state"))
            }
        }
    }

    /// Похож ли пакет на `SessionCreated`: вторая половина его заголовка
    /// замаскирована `k_header_2` из состояния инициатора, поэтому тип нужно
    /// считать именно этим ключом (i2pd `ProcessSessionCreated`).
    fn peek_is_session_created(&self, packet: &[u8]) -> bool {
        let Some(handshake) = self.initiator.as_ref() else {
            return false;
        };
        peek_message_type_with(packet, &handshake.session_created_header_key())
            == Some(Ssu2MessageType::SessionCreated)
    }

    /// Решение по блоку `DateTime` из payload'а handshake-пакета
    /// (i2pd `HandleDateTime`, `SSU2Session.cpp:1964`): фаза берётся из текущего
    /// состояния сессии, семейство адреса и `sync_clock_from_peers` — из
    /// [`ConnParams`].
    fn datetime_action<P: Ssu2Policy>(
        &self,
        policy: &P,
        body: &[u8],
        now_secs: u32,
    ) -> DateTimeAction {
        let session = DateTimeSession {
            phase: handshake_phase(self.state()),
            testing: self.params.testing,
            sync_clock_from_peers: self.params.sync_clock_from_peers,
        };
        handle_datetime(policy, body, u64::from(now_secs), &session)
    }

    fn recv_retry<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<ConnReport> {
        let received = handle_retry(&self.params.remote_intro_key, packet)?;
        self.set_state(Ssu2SessionState::TokenReceived);
        let mut report = ConnReport::default();
        // i2pd `ProcessRetry` → `HandlePayload` (`:1638`): в payload'е `Retry`
        // приходят `DateTime`, `Address` (наш внешний адрес) и `Termination`
        // (ответчик отказал, например по версии протокола). Payload
        // разбирается и при нулевом токене — i2pd это отдельно оговаривает
        // («to handle Datetime block and adjust clock in case of clock skew»).
        let mut termination = None;
        for block in Blocks::new(&received.payload) {
            let Ok(block) = block else { break };
            match block.kind() {
                Some(Ssu2BlockType::DateTime) => {
                    report.datetime = Some(self.datetime_action(policy, block.body, ctx.now_secs));
                }
                Some(Ssu2BlockType::Address) => {
                    report.external_address = AddressBlock::parse(block.body).ok();
                }
                Some(Ssu2BlockType::Termination) => {
                    termination = TerminationBlock::parse(block.body).ok();
                }
                _ => {}
            }
        }
        if let Some(termination) = termination {
            // i2pd `HandlePayload` (`:1843`): `Termination` в неустановленной
            // сессии → `Done ()`. Токен в таком `Retry` нулевой
            // (`SendRetry` кладёт его только при `NormalClose`), так что
            // переспрашивать ответчика не о чем.
            warn!(
                reason = termination.reason,
                reason_kind = ?termination.reason_kind(),
                "recv_retry: Retry with Termination; connection rejected"
            );
            report.rejected = true;
            self.set_state(Ssu2SessionState::Failed);
            return Ok(report);
        }
        if received.token == 0 {
            warn!("recv_retry: Retry with zero token; connection rejected");
            report.rejected = true;
            self.set_state(Ssu2SessionState::Failed);
            return Ok(report);
        }
        debug!(token = received.token, "recv_retry: token received");
        self.token = received.token;
        report.token = Some(received.token);
        report.packets = self.send_session_request(policy, ctx)?;
        Ok(report)
    }

    fn recv_session_created<P: Ssu2Policy, C: Ssu2CongestionPolicy, R: RandomSource>(
        &mut self,
        policy: &P,
        congestion: &C,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<ConnReport> {
        let received = {
            let handshake = self
                .initiator
                .as_mut()
                .ok_or(I2PError::Malformed("ssu2: no initiator handshake"))?;
            handshake.handle_session_created(policy, packet)?
        };
        if received.source_conn_id != self.dest_conn_id {
            warn!(
                got = ?received.source_conn_id,
                expected = ?self.dest_conn_id,
                "recv_session_created: source conn id mismatch"
            );
            return Err(I2PError::Malformed("ssu2: SessionCreated source conn id"));
        }
        self.set_state(Ssu2SessionState::SessionCreatedReceived);
        debug!(ephemeral = %hex32(&received.ephemeral), "recv_session_created: SessionCreated");

        // i2pd `ProcessSessionCreated` -> `HandlePayload`: в payload'е
        // `SessionCreated` приходят `DateTime`, `Address` (наш внешний адрес),
        // `New Token` и `Padding`. Токен отдаём вызывающему: он положит его в
        // исходящее хранилище и следующий `SessionRequest` уйдёт без `Retry`.
        // `Address` и `DateTime` — тоже вызывающему (решения уровня роутера).
        let mut new_token = None;
        let mut external_address = None;
        let mut datetime = None;
        for block in Blocks::new(&received.payload) {
            let Ok(block) = block else { break };
            match block.kind() {
                Some(Ssu2BlockType::NewToken) => {
                    if let Ok(token) = NewTokenBlock::parse(block.body) {
                        debug!(
                            expires = token.expires,
                            "recv_session_created: NewToken for outgoing requests"
                        );
                        new_token = Some((token.expires, token.token));
                    }
                }
                Some(Ssu2BlockType::Address) => {
                    external_address = AddressBlock::parse(block.body).ok();
                }
                Some(Ssu2BlockType::DateTime) => {
                    datetime = Some(self.datetime_action(policy, block.body, ctx.now_secs));
                }
                _ => {}
            }
        }

        let params = SessionConfirmedParams {
            dest_conn_id: self.dest_conn_id,
            router_info: &self.params.local_router_info,
            pad_roll: roll_u8(ctx.rng),
            frag_roll: roll_u8(ctx.rng),
        };
        let (packets, keys) = {
            let handshake = self
                .initiator
                .as_mut()
                .ok_or(I2PError::Malformed("ssu2: no initiator handshake"))?;
            let packets = handshake.build_session_confirmed(policy, &params)?;
            let keys = *handshake.data_keys().ok_or(I2PError::Malformed(
                "ssu2: no data keys after SessionConfirmed",
            ))?;
            (packets, keys)
        };

        // Data-сессия создаётся сразу: i2pd в состоянии `SessionConfirmedSent`
        // уже обрабатывает data-пакеты (`ProcessData`) и ждёт `Ack`.
        let mut data = self.data_session(DataSessionRole::Initiator, keys, congestion, ctx.now);
        // i2pd `SendSessionConfirmed`: `m_SendPacketNum++`; номер `0` i2pd не
        // учитывает в приёме, поэтому первый data-пакет инициатора — `1`.
        data.set_send_packet_num(1);
        self.data = Some(data);
        self.set_state(Ssu2SessionState::SessionConfirmedSent);

        let mut out = vec![packets.first];
        if let Some(second) = packets.second {
            out.push(second);
        }
        self.remember_handshake(&out, ctx.now);
        debug!(
            packets = out.len(),
            "recv_session_created: SessionConfirmed sent"
        );
        Ok(ConnReport {
            packets: out,
            new_token,
            external_address,
            datetime,
            ..ConnReport::default()
        })
    }

    fn recv_responder<P: Ssu2Policy, C: Ssu2CongestionPolicy, R: RandomSource>(
        &mut self,
        policy: &P,
        congestion: &C,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
        env: &ResponderEnv<'_>,
    ) -> Result<ConnReport> {
        match self.lifecycle.state() {
            Ssu2SessionState::Established
            | Ssu2SessionState::Closing
            | Ssu2SessionState::ClosingConfirmed => self.recv_data(policy, congestion, packet, ctx),
            Ssu2SessionState::SessionCreatedSent => {
                self.recv_session_confirmed(policy, congestion, packet, ctx)
            }
            _ => self.recv_first_incoming(policy, packet, ctx, env),
        }
    }

    fn recv_first_incoming<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
        env: &ResponderEnv<'_>,
    ) -> Result<ConnReport> {
        let msg = peek_message_type(packet, &self.params.local_intro_key).ok_or(
            I2PError::Malformed("ssu2: unknown message type for a new incoming session"),
        )?;
        match msg {
            Ssu2MessageType::TokenRequest => self.recv_token_request(policy, packet, ctx, env),
            Ssu2MessageType::SessionRequest => self.recv_session_request(policy, packet, ctx, env),
            other => {
                warn!(?other, "recv_first_incoming: unexpected message type");
                Err(I2PError::Malformed("ssu2: unexpected first message"))
            }
        }
    }

    fn recv_token_request<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
        env: &ResponderEnv<'_>,
    ) -> Result<ConnReport> {
        let received = handle_token_request(&self.params.local_intro_key, packet)?;
        debug!(
            source_conn_id = ?received.source_conn_id,
            "recv_token_request: TokenRequest"
        );
        self.set_state(Ssu2SessionState::TokenRequestReceived);
        // i2pd `SendRetry`: токен `GetIncomingToken` (вызывающий уже взял его
        // в `env.expected_token`).
        let packets =
            self.send_retry(policy, ctx, env.expected_token, None, env.address.as_ref())?;
        Ok(ConnReport {
            packets,
            ..ConnReport::default()
        })
    }

    fn recv_session_request<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
        env: &ResponderEnv<'_>,
    ) -> Result<ConnReport> {
        // Токен проверяем до Noise-состояния (i2pd `:886`).
        let (_, token) = peek_long_header_ids(packet, &self.params.local_intro_key)
            .ok_or(I2PError::Malformed("ssu2: short SessionRequest"))?;
        if token == 0 || token != env.expected_token {
            debug!(
                token,
                expected = env.expected_token,
                "recv_session_request: token mismatch; sending Retry"
            );
            let packets =
                self.send_retry(policy, ctx, env.expected_token, None, env.address.as_ref())?;
            return Ok(ConnReport {
                packets,
                ..ConnReport::default()
            });
        }

        let received = {
            let handshake = self
                .responder
                .as_mut()
                .ok_or(I2PError::Malformed("ssu2: no responder handshake"))?;
            match handshake.handle_session_request(policy, packet) {
                Ok(received) => received,
                Err(I2PError::Unsupported(message)) => {
                    // i2pd: несовместимая версия -> `Retry` с нулевым токеном
                    // и блоком `Termination`.
                    warn!(
                        message,
                        "recv_session_request: unsupported version; refusing"
                    );
                    let packets = self.send_retry(
                        policy,
                        ctx,
                        0,
                        Some(Ssu2TerminationReason::IncompatibleVersion),
                        env.address.as_ref(),
                    )?;
                    return Ok(ConnReport {
                        packets,
                        ..ConnReport::default()
                    });
                }
                Err(error) => return Err(error),
            }
        };
        self.set_state(Ssu2SessionState::SessionRequestReceived);
        debug!(
            source_conn_id = ?received.source_conn_id,
            ephemeral = %hex32(&received.ephemeral),
            "recv_session_request: token ok; sending SessionCreated"
        );

        let params = SessionCreatedParams {
            dest_conn_id: received.source_conn_id,
            source_conn_id: self.source_conn_id,
            packet_num: ctx.rng.roll(),
            now_secs: ctx.now_secs,
            extra_blocks: env.extra_blocks,
            pad_roll: roll_u8(ctx.rng),
        };
        let packet = {
            let handshake = self
                .responder
                .as_mut()
                .ok_or(I2PError::Malformed("ssu2: no responder handshake"))?;
            handshake.build_session_created(policy, &params)?
        };
        self.set_state(Ssu2SessionState::SessionCreatedSent);
        let packets = vec![packet];
        self.remember_handshake(&packets, ctx.now);
        debug!("recv_session_request: SessionCreated sent");
        Ok(ConnReport {
            packets,
            ..ConnReport::default()
        })
    }

    fn recv_session_confirmed<P: Ssu2Policy, C: Ssu2CongestionPolicy, R: RandomSource>(
        &mut self,
        policy: &P,
        congestion: &C,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<ConnReport> {
        let outcome = {
            let handshake = self
                .responder
                .as_mut()
                .ok_or(I2PError::Malformed("ssu2: no responder handshake"))?;
            handshake.handle_session_confirmed(policy, packet)?
        };
        let ConfirmedOutcome::Complete(confirmed) = outcome else {
            trace!("recv_session_confirmed: fragment stored; waiting for the other");
            return Ok(ConnReport::default());
        };
        let router_info = extract_router_info(&confirmed.payload)?;
        debug!(
            static_key = %hex32(&confirmed.static_key),
            router_info_len = router_info.len(),
            "recv_session_confirmed: SessionConfirmed complete"
        );
        // Проверки `RouterInfo` (i2pd `:1360`: подпись, свежесть, версия, адрес
        // семейства, `s=` против ключа handshake) делает вызывающий — они
        // требуют netdb, которого у соединения нет. Сюда же уходит статический
        // ключ `S` ([`ConnReport::remote_static_key`]), чтобы сверить его с
        // `s=` из `RouterInfo` (см. `Ssu2Pool::accept_remote_router_info`).

        let keys = {
            let handshake = self
                .responder
                .as_mut()
                .ok_or(I2PError::Malformed("ssu2: no responder handshake"))?;
            *handshake.data_keys().ok_or(I2PError::Malformed(
                "ssu2: no data keys after SessionConfirmed",
            ))?
        };
        let mut data = self.data_session(DataSessionRole::Responder, keys, congestion, ctx.now);
        data.set_state(Ssu2SessionState::Established);
        // i2pd `:1453`: Established(). `QuickAck` шлёт вызывающий — после
        // того как задаст intro-ключ инициатора из полученного `RouterInfo`
        // ([`Self::send_quick_ack`], [`ConnReport::quick_ack_pending`]).
        self.data = Some(data);
        self.establish(policy, ctx);
        debug!("recv_session_confirmed: session established (responder)");
        Ok(ConnReport {
            established: true,
            quick_ack_pending: true,
            remote_router_info: Some(router_info),
            remote_static_key: Some(confirmed.static_key),
            ..ConnReport::default()
        })
    }

    fn recv_data<P: Ssu2Policy, C: Ssu2CongestionPolicy, R: RandomSource>(
        &mut self,
        policy: &P,
        congestion: &C,
        packet: &mut [u8],
        ctx: &mut ConnContext<'_, R>,
    ) -> Result<ConnReport> {
        let state = self.lifecycle.state();
        let awaiting_ack = state == Ssu2SessionState::SessionConfirmedSent;
        let is_data = {
            let data = self.data.as_ref().ok_or(I2PError::Malformed(
                "ssu2: data packet before handshake completion",
            ))?;
            data.peek_message_type(packet) == Some(Ssu2MessageType::Data)
        };
        if !is_data {
            return Ok(self.non_data_report());
        }
        let data = self.data.as_mut().ok_or(I2PError::Malformed(
            "ssu2: data packet before handshake completion",
        ))?;
        let recv = data.recv(packet, policy, congestion, ctx.now, u64::from(ctx.now_secs))?;
        let ack_received = recv.ack_received;
        let mut report = ConnReport {
            data: Some(recv),
            ..ConnReport::default()
        };
        if awaiting_ack && ack_received {
            // i2pd `HandleAck`: в `SessionConfirmedSent` любой `Ack` завершает
            // рукопожатие (`SSU2Session.cpp:2037`).
            self.establish(policy, ctx);
            report.established = true;
        }
        Ok(report)
    }

    /// Ответ на пакет, который в data-состоянии оказался не data-пакетом
    /// (i2pd `ProcessData`, `SSU2Session.cpp:1743-1751`).
    ///
    /// Так приходит повторный handshake-пакет — например, повторный
    /// `SessionCreated`, если наш `SessionConfirmed` потерялся. i2pd в
    /// `SessionConfirmedSent` повторяет `SessionConfirmed`
    /// (`ResendHandshakePacket`), в `Established` шлёт `QuickAck` («in case it
    /// was `SessionConfirmed`»), в `Closing` — `ResendHandshakePacket`, который к
    /// тому моменту уже сброшен, то есть ничего.
    fn non_data_report(&self) -> ConnReport {
        match self.lifecycle.state() {
            Ssu2SessionState::SessionConfirmedSent => {
                debug!(
                    packets = self.sent_handshake.len(),
                    "recv_data: not a data packet; resending handshake"
                );
                ConnReport {
                    packets: self.sent_handshake.clone(),
                    ..ConnReport::default()
                }
            }
            Ssu2SessionState::Established => {
                debug!("recv_data: not a data packet; sending QuickAck");
                ConnReport {
                    quick_ack_pending: true,
                    ..ConnReport::default()
                }
            }
            state => {
                debug!(
                    state = state.name(),
                    "recv_data: not a data packet; ignored"
                );
                ConnReport::default()
            }
        }
    }
}

/// Первый блок `RouterInfo` из payload'а `SessionConfirmed`
/// (i2pd `ProcessSessionConfirmed`, `:1339`).
fn extract_router_info(payload: &[u8]) -> Result<Vec<u8>> {
    let first = Blocks::new(payload)
        .next()
        .ok_or(I2PError::Malformed("ssu2: empty SessionConfirmed payload"))??;
    if first.kind() != Some(Ssu2BlockType::RouterInfo) {
        return Err(I2PError::Malformed(
            "ssu2: SessionConfirmed first block is not RouterInfo",
        ));
    }
    let block: RouterInfoBlock = first.parse()?;
    // `body()` снимает флаги/`frag` и распаковывает gzip — как
    // `ExtractRouterInfo` в i2pd (`SSU2Session.cpp:3290`).
    Ok(block.body()?.into_owned())
}

/// Младший байт броска генератора.
///
/// i2pd всюду берёт у генератора `uint32` и оставляет от него только младшие
/// биты (`GetRng () & 0x1F` для padding'а, `% 16` для `frag`), поэтому
/// усечение до байта ничего не меняет (маску всё равно накладывает политика).
fn roll_u8<R: RandomSource>(rng: &mut R) -> u8 {
    u8::try_from(rng.roll() & 0xFF).unwrap_or_default()
}

/// Hex-представление 32-байтового ключа (для логов, как в i2pd).
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
