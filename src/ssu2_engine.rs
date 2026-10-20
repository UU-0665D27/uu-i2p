//! SSU2 — движок сессии, приём data-пакетов.
//!
//! Связывает примитивы в одну сессию: заголовок и деобфускация
//! ([`crate::ssu2_data::decode_data_packet`]), диспетчер блоков
//! ([`crate::ssu2_recv::process_data`] / [`PayloadSink`]), дедуп и истечение
//! I2NP ([`crate::ssu2_recv::ReceivedMsgIds`]), сборку фрагментов
//! ([`crate::ssu2_fragments::IncompleteMessages`]), учёт подтверждений
//! ([`crate::ssu2_session::SendState`]) и состояние сессии
//! ([`crate::ssu2_lifecycle::SessionLifecycle`]).
//!
//! Зеркалит `SSU2Session::ProcessData` (`SSU2Session.cpp:1737`) и `HandlePayload`
//! (`:1780`) в части приёма; решения, зависящие от политики (`HandleAck`,
//! `HandleDateTime`), принимает [`Ssu2Policy`]/[`Ssu2CongestionPolicy`].
//!
//! ## Что делает вызывающий
//!
//! Всё, что в i2pd завязано на роутер, отдаётся наружу — их нужно обработать
//! самим (пока не реализовано):
//!
//! - [`PendingBlock`] — `RouterInfo` (netdb), relay-блоки и peer test;
//! - [`RecvReport::external_address`] — `HandleAddress` (обновление своего
//!   внешнего адреса и детект NAT);
//! - [`RecvReport::new_token`] — `NewToken` (обновление токена у сервера);
//! - [`RecvReport::datetime`] — решение `HandleDateTime` (коррекция часов или
//!   завершение), применяет вызывающий;
//! - [`RecvReport::path_challenge`] — данные, на которые надо ответить
//!   `PathResponse` (`SendPathResponse`);
//! - [`RecvReport::termination`] — что делать с `Termination` (ответить своим
//!   `Termination` или завершать сразу).
//!
//! ## Отправка
//!
//! [`Ssu2DataSession::enqueue_i2np`] ставит I2NP-сообщения в очередь, а
//! [`Ssu2DataSession::flush`] упаковывает её в data-пакеты (i2pd `SendQueue`).
//! Готовые пакеты — байты для отправки транспортом; сессия сама ведёт номера
//! пакетов, окно (`SendState`) и копии payload'ов для повторов. Контрольные
//! пакеты — отдельные методы (`send_quick_ack`, `send_keep_alive`,
//! `send_termination`, `send_path_challenge`, `send_path_response`);
//! [`Ssu2DataSession::resend`] повторяет data-пакеты по RTO (i2pd `Resend`).
//!
//! Драйвер рукопожатия (состояния `SessionRequestSent`/`SessionConfirmedSent`
//! и переход в `Established` по `Ack`) — в [`crate::ssu2_conn`].
//!
//! Таймеры ([`crate::ssu2_timers`]) живут там же: connect-таймер и
//! переотправка handshake-пакетов — в [`crate::ssu2_conn::Ssu2Connection`],
//! а тик `HandleResendTimer` (`SSU2.cpp:1228`) — в [`crate::ssu2_pool`]
//! (триггер повторов, плановая переотправка своего `RouterInfo`, idle-таймаут).

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use tracing::{debug, trace, warn};

use crate::error::I2PError;
use crate::i2np_message::I2npMessage;
use crate::ssu2_ack::Ssu2AckBlock;
use crate::ssu2_block::{
    AddressBlock, FirstFragmentBlock, FollowOnFragmentBlock, NewTokenBlock, PathChallengeBlock,
    PathResponseBlock, PeerTestBlock, RelayTagBlock, RouterInfoBlock, Ssu2Block, Ssu2BlockType,
    Ssu2TerminationReason, TerminationBlock, write_block,
};
use crate::ssu2_crypto::{DataPhaseKey, DataPhaseKeys};
use crate::ssu2_data::{SSU2_DATA_OVERHEAD, decode_data_packet, encode_data_packet};
use crate::ssu2_fragments::IncompleteMessages;
use crate::ssu2_header::{
    ConnectionId, SSU2_FLAG_IMMEDIATE_ACK_REQUESTED, ShortHeader, Ssu2MessageType, header_mask,
};
use crate::ssu2_lifecycle::{SessionLifecycle, Ssu2SessionState};
use crate::ssu2_policy::{
    DateTimeAction, DateTimeSession, HandshakePhase, Ssu2CongestionPolicy, Ssu2Policy,
};
use crate::ssu2_recv::{self, PayloadSink, ReceivedI2np, ReceivedMsgIds};
use crate::ssu2_send::{self, QueuedMessage, RandomSource, SendQueueConfig, padding_roll};
use crate::ssu2_session::{ReceiveState, SendState};

/// Роль стороны в data phase (определяет направление ключей).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSessionRole {
    /// Alice (инициатор): отправляет ключом `ab`, принимает `ba`.
    Initiator,
    /// Bob (ответчик): наоборот.
    Responder,
}

/// Параметры установленной data-сессии (результат handshake).
#[derive(Debug, Clone, Copy)]
pub struct DataSessionParams {
    /// Роль стороны.
    pub role: DataSessionRole,
    /// Наш идентификатор соединения (id отправителя).
    pub source_conn_id: ConnectionId,
    /// Идентификатор собеседника (id получателя).
    pub dest_conn_id: ConnectionId,
    /// Ключи data phase обоих направлений.
    pub data_keys: DataPhaseKeys,
    /// Наш intro-ключ (деобфускация входящих заголовков).
    pub local_intro_key: [u8; 32],
    /// Intro-ключ собеседника (обфускация исходящих заголовков).
    pub remote_intro_key: [u8; 32],
    /// Максимальный размер payload'а пакета (`m_MaxPayloadSize`).
    pub max_payload: usize,
    /// Роутер в тестовом режиме (для `HandleDateTime`).
    pub testing: bool,
    /// `m_Server.IsSyncClockFromPeers()`.
    pub sync_clock_from_peers: bool,
}

/// Итог обработки блока `Termination` (ветки `SSU2Session.cpp:1855`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationAction {
    /// Ответить своим `Termination` (i2pd `RequestTermination`).
    ReplyAndClose,
    /// Завершить сразу (i2pd `Done`); при состоянии `Closing` и коде
    /// `TerminationReceived` — предварительно `ClosingConfirmed`.
    CloseNow,
    /// Сессия уже завершена — запомнить причину (i2pd `m_TerminationReason`).
    RecordReason(Ssu2TerminationReason),
}

/// Блок, который обрабатывает вызывающий (в i2pd — уровень роутера).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingBlock {
    /// `RouterInfo` (netdb, `HandleRouterInfo`).
    RouterInfo(Vec<u8>),
    /// Relay request (`HandleRelayRequest`).
    RelayRequest(Vec<u8>),
    /// Relay response (`HandleRelayResponse`).
    RelayResponse(Vec<u8>),
    /// Relay intro (`HandleRelayIntro`).
    RelayIntro(Vec<u8>),
    /// Peer test (`HandlePeerTest`).
    PeerTest(Vec<u8>),
}

/// Итог [`Ssu2DataSession::recv`].
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecvReport {
    /// Принятые I2NP-сообщения (после дедупа и сборки фрагментов).
    pub i2np: Vec<I2npMessage>,
    /// i2pd `m_IsDataReceived`.
    pub data_received: bool,
    /// i2pd `m_IsInvalidMessage`.
    pub invalid_message: bool,
    /// Пакет содержал блок `Ack` (нужно инициатору в `SessionConfirmedSent`:
    /// i2pd `HandleAck` сразу переводит сессию в `Established`, `:2037`).
    pub ack_received: bool,
    /// Решение по блоку `DateTime` (последнему в пакете).
    pub datetime: Option<DateTimeAction>,
    /// Что делать с блоком `Termination`.
    pub termination: Option<TerminationAction>,
    /// Данные `Path Challenge`, на которые нужно ответить.
    pub path_challenge: Option<Vec<u8>>,
    /// Наш `Path Challenge` подтверждён (i2pd обновляет endpoint).
    pub path_response_accepted: bool,
    /// `NewToken`: `(expires, token)` — обновить исходящий токен на сервере.
    pub new_token: Option<(u32, u64)>,
    /// `Address`: наш внешний адрес, каким его видит собеседник.
    pub external_address: Option<AddressBlock>,
    /// Блоки, которые должен обработать вызывающий (см. [`PendingBlock`]).
    pub pending: Vec<PendingBlock>,
}

/// Итог [`Ssu2DataSession::flush`] (i2pd `SendQueue`).
#[derive(Debug, Default)]
pub struct SendReport {
    /// Пакеты для отправки (в порядке отправки).
    pub packets: Vec<Vec<u8>>,
    /// Отправлен ли где-нибудь ACK-блок (i2pd `ackBlockSent`).
    pub ack_block_sent: bool,
    /// Снятые с очереди истёкшие/просроченные сообщения (i2pd `Drop`).
    pub dropped: Vec<I2npMessage>,
}

/// Итог [`Ssu2DataSession::resend`] (i2pd `Resend`, часть с data-пакетами).
#[derive(Debug, Default)]
pub struct ResendReport {
    /// Повторно отправленные пакеты.
    pub packets: Vec<Vec<u8>>,
    /// Каким номерам соответствуют повторно отправленные пакеты (в том же
    /// порядке, что [`Self::packets`]).
    pub resent: Vec<u32>,
    /// Превышен предел повторов — сессия завершается (`Timeout`).
    pub terminate: bool,
}

/// Окружение отправки: время и генератор.
///
/// - `now` — монотонное время (`m_SentPackets.sendTime`, RTT/RTO);
/// - `now_ms` — Unix-время в миллисекундах (`DateTime`, истечение I2NP);
/// - `now_micros` — монотонные микросекунды (лаг очереди, `m_SendQueue`);
/// - `rng` — `m_Server.GetRng()`.
pub struct SendContext<'a, R: RandomSource> {
    /// Монотонное время.
    pub now: Duration,
    /// Unix-время в миллисекундах.
    pub now_ms: u64,
    /// Монотонное время в микросекундах.
    pub now_micros: u64,
    /// Генератор.
    pub rng: &'a mut R,
}

/// Событие одного блока payload'а, собранное [`Collector`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum BlockEvent {
    I2np(Vec<u8>),
    FirstFragment(Vec<u8>),
    FollowOnFragment(Vec<u8>),
    Ack(Vec<u8>),
    Termination(Vec<u8>),
    DateTime(Vec<u8>),
    PathChallenge(Vec<u8>),
    PathResponse(Vec<u8>),
    RelayTag(Vec<u8>),
    RelayTagRequest,
    NewToken(Vec<u8>),
    Address(Vec<u8>),
    RouterInfo(Vec<u8>),
    RelayRequest(Vec<u8>),
    RelayResponse(Vec<u8>),
    RelayIntro(Vec<u8>),
    PeerTest(Vec<u8>),
}

/// Простой [`PayloadSink`], складывающий блоки в список событий.
///
/// Так обработка блоков не конфликтует с заимствованием состояния сессии:
/// сперва диспетчер собирает события, затем сессия их применяет.
#[derive(Debug, Default)]
struct Collector {
    events: Vec<BlockEvent>,
}

impl Collector {
    fn push(&mut self, event: BlockEvent) {
        self.events.push(event);
    }
}

impl PayloadSink for Collector {
    fn on_datetime(&mut self, body: &[u8]) {
        self.push(BlockEvent::DateTime(body.to_vec()));
    }

    fn on_router_info(&mut self, body: &[u8]) {
        self.push(BlockEvent::RouterInfo(body.to_vec()));
    }

    fn on_i2np_message(&mut self, body: &[u8]) {
        self.push(BlockEvent::I2np(body.to_vec()));
    }

    fn on_first_fragment(&mut self, body: &[u8]) {
        self.push(BlockEvent::FirstFragment(body.to_vec()));
    }

    fn on_follow_on_fragment(&mut self, body: &[u8]) {
        self.push(BlockEvent::FollowOnFragment(body.to_vec()));
    }

    fn on_termination(&mut self, body: &[u8]) {
        self.push(BlockEvent::Termination(body.to_vec()));
    }

    fn on_relay_request(&mut self, body: &[u8]) {
        self.push(BlockEvent::RelayRequest(body.to_vec()));
    }

    fn on_relay_response(&mut self, body: &[u8]) {
        self.push(BlockEvent::RelayResponse(body.to_vec()));
    }

    fn on_relay_intro(&mut self, body: &[u8]) {
        self.push(BlockEvent::RelayIntro(body.to_vec()));
    }

    fn on_peer_test(&mut self, body: &[u8]) {
        self.push(BlockEvent::PeerTest(body.to_vec()));
    }

    fn on_ack(&mut self, body: &[u8]) {
        self.push(BlockEvent::Ack(body.to_vec()));
    }

    fn on_address(&mut self, body: &[u8]) {
        self.push(BlockEvent::Address(body.to_vec()));
    }

    fn on_relay_tag_request(&mut self) {
        self.push(BlockEvent::RelayTagRequest);
    }

    fn on_relay_tag(&mut self, body: &[u8]) {
        self.push(BlockEvent::RelayTag(body.to_vec()));
    }

    fn on_new_token(&mut self, body: &[u8]) {
        self.push(BlockEvent::NewToken(body.to_vec()));
    }

    fn on_path_challenge(&mut self, body: &[u8]) {
        self.push(BlockEvent::PathChallenge(body.to_vec()));
    }

    fn on_path_response(&mut self, body: &[u8]) {
        self.push(BlockEvent::PathResponse(body.to_vec()));
    }
}

/// Состояние одной SSU2-сессии (пока — только приём data-пакетов).
#[derive(Debug, Clone)]
pub struct Ssu2DataSession {
    lifecycle: SessionLifecycle,
    receive: ReceiveState,
    send: SendState,
    received_msg_ids: ReceivedMsgIds,
    incomplete: IncompleteMessages,
    params: DataSessionParams,
    send_key: DataPhaseKey,
    recv_key: DataPhaseKey,
    last_activity: Duration,
    relay_tag: Option<u32>,
    relay_tag_requested: bool,
    external_address: Option<AddressBlock>,
    remote_termination: Option<Ssu2TerminationReason>,
    path_challenge_sent: Option<u64>,
    path_validated: bool,
    send_packet_num: u32,
    last_datetime_packet_num: u32,
    out_queue: VecDeque<QueuedMessage>,
    sent_payloads: BTreeMap<u32, Vec<u8>>,
}

impl Ssu2DataSession {
    /// Создаёт сессию в состоянии [`Ssu2SessionState::Unknown`].
    ///
    /// `congestion` нужна [`SendState`] для начальных окна и RTO.
    ///
    /// `now` — время создания: от него считается «время последней активности»
    /// ([`Self::last_activity`], i2pd `TransportSession` инициализирует
    /// `m_LastActivityTimestamp` временем создания). Без этого свежая сессия,
    /// ещё не принявшая ни одного data-пакета, выглядит простаивающей
    /// `SSU2_TERMINATION_TIMEOUT` и её сразу завершает idle-таймер.
    #[must_use]
    pub fn new<C: Ssu2CongestionPolicy>(
        params: DataSessionParams,
        congestion: &C,
        now: Duration,
    ) -> Self {
        let (send_key, recv_key) = match params.role {
            DataSessionRole::Initiator => (params.data_keys.ab, params.data_keys.ba),
            DataSessionRole::Responder => (params.data_keys.ba, params.data_keys.ab),
        };
        Self {
            lifecycle: SessionLifecycle::new(),
            receive: ReceiveState::new(),
            send: SendState::new(congestion),
            received_msg_ids: ReceivedMsgIds::new(),
            incomplete: IncompleteMessages::new(),
            params,
            send_key,
            recv_key,
            last_activity: now,
            relay_tag: None,
            relay_tag_requested: false,
            external_address: None,
            remote_termination: None,
            path_challenge_sent: None,
            path_validated: false,
            send_packet_num: 0,
            last_datetime_packet_num: 0,
            out_queue: VecDeque::new(),
            sent_payloads: BTreeMap::new(),
        }
    }

    /// Состояние сессии.
    #[must_use]
    pub const fn state(&self) -> Ssu2SessionState {
        self.lifecycle.state()
    }

    /// Сессия установлена?
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.lifecycle.is_established()
    }

    /// Переход в `Established` (i2pd `Established`, `SSU2Session.cpp:331`).
    ///
    /// Таймеры и очередь отправки `Established` трогает не здесь: connect-таймер
    /// и расписание `RouterInfo` — в [`crate::ssu2_conn`], `SendQueue` —
    /// [`Self::flush`].
    pub const fn establish(&mut self) -> bool {
        self.lifecycle.establish()
    }

    /// Регистрирует отправленный пакет в окне (для `SendData`/повторов).
    pub fn register_sent(&mut self, packet_num: u32, now: Duration) {
        self.send.register_sent(packet_num, now);
    }

    /// Начинает завершение (i2pd `RequestTermination`): в `Established`/
    /// `Closing` — запомнить причину и перейти в `Closing`, иначе — сразу
    /// `Terminate`.
    pub const fn request_termination(
        &mut self,
        reason: Ssu2TerminationReason,
    ) -> crate::ssu2_lifecycle::TerminationPlan {
        self.lifecycle.request_termination(reason)
    }

    /// Немедленное завершение (i2pd `Terminate`); идемпотентно.
    pub const fn terminate(&mut self) -> bool {
        self.lifecycle.terminate()
    }

    /// Причина завершения (`m_TerminationReason`).
    #[must_use]
    pub const fn termination_reason(&self) -> Ssu2TerminationReason {
        self.lifecycle.termination_reason()
    }

    /// Время последней активности (`m_LastActivityTimestamp`).
    #[must_use]
    pub const fn last_activity(&self) -> Duration {
        self.last_activity
    }

    /// Номер следующего отправляемого пакета (`m_SendPacketNum`).
    #[must_use]
    pub const fn send_packet_num(&self) -> u32 {
        self.send_packet_num
    }

    /// Длина очереди отправки (`m_SendQueue.size ()`).
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.out_queue.len()
    }

    /// Приёмное состояние (номера пакетов, ACK).
    #[must_use]
    pub const fn receive(&self) -> &ReceiveState {
        &self.receive
    }

    /// Отправное состояние (окно, RTT/RTO, неподтверждённые пакеты).
    #[must_use]
    pub const fn send(&self) -> &SendState {
        &self.send
    }

    /// Наш relay-тег, если прислан блоком `Relay Tag`.
    #[must_use]
    pub const fn relay_tag(&self) -> Option<u32> {
        self.relay_tag
    }

    /// Просили ли relay-тег (пришёл блок `Relay Tag Request`).
    #[must_use]
    pub const fn relay_tag_requested(&self) -> bool {
        self.relay_tag_requested
    }

    /// Внешний адрес, каким его видит собеседник (блок `Address`).
    #[must_use]
    pub const fn external_address(&self) -> Option<&AddressBlock> {
        self.external_address.as_ref()
    }

    /// Причина завершения, присланная собеседником после терминации.
    #[must_use]
    pub const fn remote_termination(&self) -> Option<Ssu2TerminationReason> {
        self.remote_termination
    }

    /// Подтверждён ли наш `Path Challenge` (новый endpoint валиден).
    #[must_use]
    pub const fn path_validated(&self) -> bool {
        self.path_validated
    }

    /// Ключ отправки data-пакетов (`SendData` шифрует им payload).
    #[must_use]
    pub const fn send_key(&self) -> &DataPhaseKey {
        &self.send_key
    }

    /// Запоминает отправленный `Path Challenge` (i2pd `m_PathChallenge`).
    pub const fn set_path_challenge_sent(&mut self, challenge: u64) {
        self.path_challenge_sent = Some(challenge);
    }

    /// Синхронизирует состояние с драйвером рукопожатия
    /// ([`crate::ssu2_conn::Ssu2Connection`]): сессия создаётся до `Established`
    /// (у инициатора — в `SessionConfirmedSent`), и от состояния зависят
    /// решения по `DateTime`.
    pub const fn set_state(&mut self, state: Ssu2SessionState) {
        self.lifecycle.set_state(state);
    }

    /// Начальный номер отправляемого data-пакета.
    ///
    /// Нужен из-за асимметрии i2pd: `SendSessionConfirmed` делает
    /// `m_SendPacketNum++`, поэтому первый data-пакет инициатора имеет
    /// номер `1` (у ответчика — `0`). Номер `0` i2pd не учитывает в
    /// `UpdateReceivePacketNum`, так что данные под ним подтверждены не будут.
    pub const fn set_send_packet_num(&mut self, packet_num: u32) {
        self.send_packet_num = packet_num;
    }

    /// Задаёт intro-ключ собеседника: у ответчика он становится известен лишь
    /// из `RouterInfo` инициатора, уже после обработки `SessionConfirmed`.
    pub const fn set_remote_intro_key(&mut self, intro_key: [u8; 32]) {
        self.params.remote_intro_key = intro_key;
    }

    /// Тип входящего пакета по второй половине cover-заголовка — тем же ключом,
    /// каким i2pd разбирает его в `ProcessData` (`SSU2Session.cpp:1742`).
    ///
    /// У настоящего data-пакета это [`Ssu2MessageType::Data`]. Другое значение
    /// (или `None` на коротком пакете) означает, что собеседник повторил
    /// handshake-пакет — тогда отвечает [`crate::ssu2_conn`]
    /// (`ResendHandshakePacket`/`SendQuickAck`), а не data-слой.
    ///
    /// Пакет не изменяется: ключ применяется к копии байтов заголовка.
    #[must_use]
    pub fn peek_message_type(&self, packet: &[u8]) -> Option<Ssu2MessageType> {
        let end = packet.len();
        let tail = packet.get(end.checked_sub(12)?..end)?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(tail);
        let mask = header_mask(&self.recv_key.k_header_2, &iv);
        Ssu2MessageType::from_u8(*packet.get(12)? ^ mask[4]).ok()
    }

    /// Принимает один data-пакет: деобфусцирует, расшифровывает, разбирает
    /// блоки и применяет их.
    ///
    /// `packet` деобфусцируется **на месте** (как и в i2pd). `now` — монотонное
    /// время (для фрагментов и RTT), `now_secs` — Unix-время в секундах (для
    /// `DateTime`).
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки разбора/расшифровки из
    /// [`crate::ssu2_data::decode_data_packet`].
    ///
    /// # Panics
    ///
    /// Не паникует: размер scratch-буфера выведен из длины пакета.
    pub fn recv<P: Ssu2Policy, C: Ssu2CongestionPolicy>(
        &mut self,
        packet: &mut [u8],
        policy: &P,
        congestion: &C,
        now: Duration,
        now_secs: u64,
    ) -> crate::Result<RecvReport> {
        let mut plain = vec![0u8; packet.len()];
        let (header, payload) = decode_data_packet(
            packet,
            &self.params.local_intro_key,
            &self.recv_key,
            &mut plain,
        )?;
        trace!(
            packet_num = header.packet_num,
            flags = header.flags[0],
            payload_len = payload.len(),
            state = ?self.lifecycle.state(),
            "recv: decoded data packet"
        );
        // i2pd обновляет m_LastActivityTimestamp при активной работе с
        // пакетом (base TransportSession::UpdateNumReceivedBytes).
        self.last_activity = now;

        let mut collector = Collector::default();
        let result = ssu2_recv::process_data(
            header.flags[0],
            header.packet_num,
            payload,
            &mut self.receive,
            &mut collector,
        );

        let mut report = RecvReport {
            data_received: result.data_received,
            invalid_message: result.invalid_message,
            ..RecvReport::default()
        };
        if result.invalid_message {
            warn!(
                packet_num = header.packet_num,
                "recv: invalid message in payload"
            );
        }
        for event in collector.events {
            self.apply_event(event, policy, congestion, now, now_secs, &mut report);
        }
        trace!(
            packet_num = header.packet_num,
            i2np = report.i2np.len(),
            data_received = report.data_received,
            "recv: applied payload blocks"
        );
        Ok(report)
    }

    /// Применяет одно событие блока к состоянию сессии.
    fn apply_event<P: Ssu2Policy, C: Ssu2CongestionPolicy>(
        &mut self,
        event: BlockEvent,
        policy: &P,
        congestion: &C,
        now: Duration,
        now_secs: u64,
        report: &mut RecvReport,
    ) {
        trace!(block = ?event_kind(&event), "apply_event: dispatching block");
        match event {
            BlockEvent::I2np(body) => self.accept_i2np_body(&body, report),
            BlockEvent::FirstFragment(body) => {
                if let Ok(block) = FirstFragmentBlock::parse(&body)
                    && let Some(msg) = self.incomplete.handle_first_fragment(&block, now)
                {
                    self.accept_i2np(msg, report);
                }
            }
            BlockEvent::FollowOnFragment(body) => {
                if let Ok(block) = FollowOnFragmentBlock::parse(&body)
                    && let Some(msg) = self.incomplete.handle_follow_on_fragment(
                        &block,
                        now,
                        policy.max_num_fragments(),
                    )
                {
                    self.accept_i2np(msg, report);
                }
            }
            BlockEvent::Ack(body) => {
                report.ack_received = true;
                self.apply_ack(&body, congestion, now);
            }
            BlockEvent::Termination(body) => self.apply_termination(&body, report),
            BlockEvent::DateTime(body) => {
                let session = DateTimeSession {
                    phase: handshake_phase(self.lifecycle.state()),
                    testing: self.params.testing,
                    sync_clock_from_peers: self.params.sync_clock_from_peers,
                };
                let action = ssu2_recv::handle_datetime(policy, &body, now_secs, &session);
                debug!(action = ?action, "apply_event: datetime decision");
                report.datetime = Some(action);
            }
            BlockEvent::PathChallenge(body) => {
                if let Ok(block) = PathChallengeBlock::parse(&body) {
                    debug!(
                        challenge_len = block.data.len(),
                        "apply_event: path challenge received; response required"
                    );
                    report.path_challenge = Some(block.data.to_vec());
                }
            }
            BlockEvent::PathResponse(body) => {
                if let Ok(block) = PathResponseBlock::parse(&body)
                    && let Some(sent) = self.path_challenge_sent
                    && let Some(head) = block.data.first_chunk::<8>()
                    && u64::from_be_bytes(*head) == sent
                {
                    debug!("apply_event: path challenge validated");
                    self.path_validated = true;
                    self.path_challenge_sent = None;
                    report.path_response_accepted = true;
                }
            }
            BlockEvent::RelayTag(body) => {
                if let Ok(block) = RelayTagBlock::parse(&body) {
                    debug!(relay_tag = block.relay_tag, "apply_event: relay tag");
                    self.relay_tag = Some(block.relay_tag);
                }
            }
            BlockEvent::RelayTagRequest => {
                debug!("apply_event: relay tag requested");
                self.relay_tag_requested = true;
            }
            BlockEvent::NewToken(body) => {
                if let Ok(block) = NewTokenBlock::parse(&body) {
                    trace!(
                        expires = block.expires,
                        "apply_event: new token for outgoing requests"
                    );
                    report.new_token = Some((block.expires, block.token));
                }
            }
            BlockEvent::Address(body) => {
                if let Ok(address) = AddressBlock::parse(&body) {
                    debug!(?address, "apply_event: external address from peer");
                    self.external_address = Some(address);
                    report.external_address = Some(address);
                }
            }
            BlockEvent::RouterInfo(body) => report.pending.push(PendingBlock::RouterInfo(body)),
            BlockEvent::RelayRequest(body) => report.pending.push(PendingBlock::RelayRequest(body)),
            BlockEvent::RelayResponse(body) => {
                report.pending.push(PendingBlock::RelayResponse(body));
            }
            BlockEvent::RelayIntro(body) => report.pending.push(PendingBlock::RelayIntro(body)),
            BlockEvent::PeerTest(body) => report.pending.push(PendingBlock::PeerTest(body)),
        }
    }

    /// Разбирает тело блока `I2NP` и, если сообщение новое и не истекло,
    /// отдаёт его в [`RecvReport::i2np`].
    fn accept_i2np_body(&mut self, body: &[u8], report: &mut RecvReport) {
        match I2npMessage::from_ntcp2_bytes(body) {
            Ok(msg) => self.accept_i2np(msg, report),
            Err(error) => {
                warn!(%error, "accept_i2np_body: malformed I2NP message");
            }
        }
    }

    /// Дедуп + проверка истечения по времени последней активности
    /// (`HandleI2NPMsg`), иначе — в отчёт.
    fn accept_i2np(&mut self, msg: I2npMessage, report: &mut RecvReport) {
        match self
            .received_msg_ids
            .handle_i2np_msg(&msg, self.last_activity)
        {
            ReceivedI2np::Accept => {
                debug!(
                    msg_id = msg.header().msg_id,
                    msg_type = ?msg.header().message_type,
                    "accept_i2np: accepted"
                );
                report.i2np.push(msg);
            }
            ReceivedI2np::Duplicate => {
                trace!(
                    msg_id = msg.header().msg_id,
                    "accept_i2np: duplicate; dropped"
                );
            }
            ReceivedI2np::Expired => {
                debug!(
                    msg_id = msg.header().msg_id,
                    "accept_i2np: expired; dropped"
                );
            }
        }
    }

    /// `HandleAck`: применяет подтверждённые диапазоны к [`SendState`].
    ///
    /// Разбор диапазонов и замер RTT по первому (`acnt`-)диапазону — внутри
    /// [`SendState::handle_ack`].
    fn apply_ack<C: Ssu2CongestionPolicy>(&mut self, body: &[u8], congestion: &C, now: Duration) {
        if self.send.in_flight() == 0 {
            trace!("apply_ack: nothing sent; ignored");
            return; // i2pd: m_SentPackets.empty ()
        }
        let Ok(ack) = Ssu2AckBlock::parse(body) else {
            trace!("apply_ack: ack block too short; ignored");
            return; // i2pd: len < 5
        };
        let acked = self.send.handle_ack(&ack, now, congestion);
        debug!(
            acked = ?acked,
            in_flight = self.send.in_flight(),
            "apply_ack: ack applied"
        );
    }

    /// Блок `Termination` (`SSU2Session.cpp:1855`).
    fn apply_termination(&mut self, body: &[u8], report: &mut RecvReport) {
        let Ok(block) = TerminationBlock::parse(body) else {
            warn!("apply_termination: malformed termination block");
            return;
        };
        let reason = block
            .reason_kind()
            .unwrap_or(Ssu2TerminationReason::NormalClose);
        if self.lifecycle.is_established() && reason != Ssu2TerminationReason::TerminationReceived {
            debug!(?reason, "apply_termination: answering with termination");
            let _ = self
                .lifecycle
                .request_termination(Ssu2TerminationReason::TerminationReceived);
            report.termination = Some(TerminationAction::ReplyAndClose);
        } else if !self.lifecycle.is_terminated() {
            debug!(?reason, "apply_termination: closing session now");
            if self.lifecycle.state() == Ssu2SessionState::Closing
                && reason == Ssu2TerminationReason::TerminationReceived
            {
                self.lifecycle.set_state(Ssu2SessionState::ClosingConfirmed);
            }
            report.termination = Some(TerminationAction::CloseNow);
        } else {
            debug!(
                ?reason,
                "apply_termination: already terminated; reason recorded"
            );
            self.remote_termination = Some(reason);
            report.termination = Some(TerminationAction::RecordReason(reason));
        }
    }
}

/// Отправная половина сессии (i2pd `SendQueue` / `SendData` / `SendQuickAck`
/// / `SendKeepAlive` / `SendTermination` / `SendPath*` / `Resend`).
impl Ssu2DataSession {
    /// Ставит I2NP-сообщение в очередь отправки (i2pd `SendI2NPMessages`).
    ///
    /// `now_micros` — монотонные микросекунды (`GetMonotonicMicroseconds`);
    /// по ним [`flush`](Self::flush) отсеивает «просроченные» в очереди
    /// сообщения.
    ///
    /// Отправка — отдельно: [`flush`](Self::flush) (i2pd `PostI2NPMessages`
    /// зовёт `SendQueue`, а при заполненном окне ещё и `Resend`).
    pub fn enqueue_i2np(&mut self, message: I2npMessage, now_micros: u64) {
        trace!(
            msg_id = message.msg_id(),
            queue = self.out_queue.len() + 1,
            "enqueue_i2np: queued"
        );
        self.out_queue.push_back(QueuedMessage {
            message,
            enqueue_time: now_micros,
        });
    }

    /// Упаковывает очередь в data-пакеты (i2pd `SendQueue`).
    ///
    /// Отправленные пакеты регистрируются в окне и запоминаются для повторов
    /// ([`resend`](Self::resend)). Возвращает байты пакетов — их отправляет
    /// вызывающий.
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки сборки блоков/шифрования.
    pub fn flush<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
    ) -> crate::Result<SendReport> {
        if !self.lifecycle.is_established() {
            return Ok(SendReport::default());
        }
        let ack = self.receive.to_ack_block(policy.ack_limits());
        let cfg = SendQueueConfig {
            ack: &ack,
            max_payload: self.params.max_payload,
            window_size: self.send.window(),
            sent_packets: self.send.in_flight(),
            established: true,
            now_ms: ctx.now_ms,
            now_micros: ctx.now_micros,
        };
        let plan = ssu2_send::send_queue(&mut self.out_queue, &cfg, ctx.rng, policy)?;
        for msg in &plan.dropped {
            debug!(msg_id = msg.msg_id(), "flush: dropped message from queue");
        }
        let mut packets = Vec::with_capacity(plan.packets.len());
        for payload in plan.packets {
            packets.push(self.send_data(&payload.payload, payload.flags, ctx.now, true)?);
        }
        debug!(
            packets = packets.len(),
            ack_block_sent = plan.ack_block_sent,
            queue = self.out_queue.len(),
            in_flight = self.send.in_flight(),
            "flush: SendQueue"
        );
        Ok(SendReport {
            packets,
            ack_block_sent: plan.ack_block_sent,
            dropped: plan.dropped,
        })
    }

    /// `SendQuickAck`: `[DateTime]` + Ack + Padding.
    ///
    /// i2pd зовёт его из `ProcessData` при `IsEstablished()`; проверки
    /// состояния здесь нет — решение за вызывающим.
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки сборки/шифрования.
    pub fn send_quick_ack<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
    ) -> crate::Result<Vec<u8>> {
        let ack = self.receive.to_ack_block(policy.ack_limits());
        let roll = padding_roll(ctx.rng, policy);
        let payload = ssu2_send::quick_ack(
            self.send_packet_num,
            &mut self.last_datetime_packet_num,
            &ack,
            roll,
            secs_rounded(ctx.now_ms),
            self.params.max_payload,
            policy,
        )?;
        self.send_data(&payload.payload, payload.flags, ctx.now, false)
    }

    /// `SendKeepAlive`: Padding (не меньше 8) + флаг `IMMEDIATE_ACK_REQUESTED`.
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки сборки/шифрования.
    pub fn send_keep_alive<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
    ) -> crate::Result<Vec<u8>> {
        let roll = padding_roll(ctx.rng, policy);
        let payload = ssu2_send::keep_alive(roll, policy)?;
        self.send_data(&payload.payload, payload.flags, ctx.now, false)
    }

    /// `SendTermination`: Termination + Padding; причина — текущая причина
    /// завершения сессии (`m_TerminationReason`).
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки сборки/шифрования.
    pub fn send_termination<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
    ) -> crate::Result<Vec<u8>> {
        let roll = padding_roll(ctx.rng, policy);
        let payload = ssu2_send::termination(
            u64::from(self.receive.receive_packet_num()),
            self.lifecycle.termination_reason().as_u8(),
            roll,
            policy,
        )?;
        self.send_data(&payload.payload, payload.flags, ctx.now, false)
    }

    /// `SendPathChallenge`: запоминает челлендж и шлёт `DateTime` + Address +
    /// `Path Challenge` + Ack + Padding.
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки сборки/шифрования.
    pub fn send_path_challenge<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
        address: &AddressBlock,
        challenge: u64,
    ) -> crate::Result<Vec<u8>> {
        let ack = self.receive.to_ack_block(policy.ack_limits());
        let roll = padding_roll(ctx.rng, policy);
        let payload = ssu2_send::path_challenge(
            address,
            challenge,
            &ack,
            roll,
            secs_rounded(ctx.now_ms),
            self.params.max_payload,
            policy,
        )?;
        self.path_challenge_sent = Some(challenge);
        debug!(address = ?address, "send_path_challenge: challenge sent");
        self.send_data(&payload.payload, payload.flags, ctx.now, false)
    }

    /// `SendPathResponse`: `DateTime` + Address + `Path Response` + Ack +
    /// Padding. `data` — данные из принятого `Path Challenge`.
    ///
    /// # Errors
    ///
    /// [`crate::error::I2PError::InvalidLength`], если данные не помещаются
    /// (i2pd в этом случае только пишет предупреждение и ничего не отправляет).
    pub fn send_path_response<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
        address: &AddressBlock,
        data: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let ack = self.receive.to_ack_block(policy.ack_limits());
        let roll = padding_roll(ctx.rng, policy);
        let payload = ssu2_send::path_response(
            address,
            data,
            &ack,
            roll,
            secs_rounded(ctx.now_ms),
            self.params.max_payload,
            policy,
        )?;
        self.send_data(&payload.payload, payload.flags, ctx.now, false)
    }

    /// Отправляет блок `Peer Test` (i2pd `SendData` с payload'ом
    /// `CreatePeerTestBlock`): `payload = PeerTest + Padding`, пакет
    /// регистрируется для повторов.
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки сериализации и шифрования.
    pub fn send_peer_test<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
        block: &PeerTestBlock<'_>,
    ) -> crate::Result<Vec<u8>> {
        let mut payload = Vec::new();
        block.write(&mut payload)?;
        let roll = padding_roll(ctx.rng, policy);
        let remaining = self.params.max_payload.saturating_sub(payload.len());
        if let Some(size) = policy.padding_size(roll, remaining, 0) {
            let zeros = vec![0u8; size];
            write_block(&mut payload, Ssu2BlockType::Padding, &zeros)?;
        }
        debug!(
            msg = block.msg,
            code = block.code,
            "send_peer_test: PeerTest sent"
        );
        self.send_data(&payload, 0, ctx.now, true)
    }

    /// Отправляет свой `RouterInfo` одним data-пакетом
    /// (i2pd `SendLocalRouterInfo`, `SSU2Session.cpp:362`).
    ///
    /// Payload — блок `RouterInfo` плюс `Padding` до `max_payload`; ни
    /// `DateTime`, ни Ack не добавляются. Пакет регистрируется для повторов
    /// (то есть `SendData(..., register = true)`).
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если `RouterInfo` не влезает в
    /// `max_payload - 32` (i2pd в этом случае шлёт `DatabaseStore` фрагментами).
    pub fn send_router_info<P: Ssu2Policy, R: RandomSource>(
        &mut self,
        policy: &P,
        ctx: &mut SendContext<'_, R>,
        router_info: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let max = self.params.max_payload.saturating_sub(32);
        let mut payload = Vec::new();
        RouterInfoBlock {
            flags: 0,
            frag: 1,
            router_info,
        }
        .write(&mut payload)?;
        if payload.len() > max {
            return Err(I2PError::Malformed(
                "ssu2: RouterInfo does not fit into a single packet",
            ));
        }
        let roll = padding_roll(ctx.rng, policy);
        let remaining = self.params.max_payload.saturating_sub(payload.len());
        if let Some(size) = policy.padding_size(roll, remaining, 0) {
            let zeros = vec![0u8; size];
            write_block(&mut payload, Ssu2BlockType::Padding, &zeros)?;
        }
        debug!(
            router_info_len = router_info.len(),
            payload_len = payload.len(),
            "send_router_info: local RouterInfo"
        );
        self.send_data(&payload, 0, ctx.now, true)
    }

    /// Повторяет data-пакеты по RTO (i2pd `Resend`, часть с `m_SentPackets`).
    ///
    /// Каждому повтору выдаётся новый номер пакета; при `num_resends > 1`
    /// ставится флаг `IMMEDIATE_ACK_REQUESTED`. Предел попыток —
    /// [`Ssu2Policy::max_num_resends`]: тогда очередь и неподтверждённые
    /// пакеты очищаются, а сессия завершается по `Timeout` (i2pd
    /// `RequestTermination(eSSU2TerminationReasonTimeout)`).
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки шифрования.
    pub fn resend<P: Ssu2Policy, C: Ssu2CongestionPolicy, R: RandomSource>(
        &mut self,
        policy: &P,
        congestion: &C,
        ctx: &mut SendContext<'_, R>,
    ) -> crate::Result<ResendReport> {
        let plan = self.send.plan_resend(ctx.now, policy.max_num_resends());
        let mut packets = Vec::new();
        let mut mapping: Vec<(u32, u32)> = Vec::new();
        for old in plan.resend {
            let Some(payload) = self.sent_payloads.get(&old).cloned() else {
                continue;
            };
            let num_resends = self
                .send
                .sent_packets()
                .get(&old)
                .map_or(0, |p| p.num_resends);
            let flags = if num_resends > 1 {
                SSU2_FLAG_IMMEDIATE_ACK_REQUESTED
            } else {
                0
            };
            let new_num = self.send_packet_num;
            packets.push(self.send_data(&payload, flags, ctx.now, false)?);
            self.sent_payloads.remove(&old);
            self.sent_payloads.insert(new_num, payload);
            mapping.push((old, new_num));
        }
        if !mapping.is_empty() {
            self.send.apply_resends(&mapping, ctx.now, congestion);
            debug!(
                resent = mapping.len(),
                window = self.send.window(),
                "resend: data packets resent"
            );
        }
        if plan.terminate {
            warn!(
                resent = mapping.len(),
                "resend: too many attempts; terminating session by timeout"
            );
            self.send.clear();
            self.sent_payloads.clear();
            self.out_queue.clear();
            let _ = self
                .lifecycle
                .request_termination(Ssu2TerminationReason::Timeout);
        }
        Ok(ResendReport {
            packets,
            resent: mapping.iter().map(|&(old, _)| old).collect(),
            terminate: plan.terminate,
        })
    }

    /// Шифрует payload в data-пакет и выдаёт номер (`SendData`).
    ///
    /// `register` — класть ли пакет в `m_SentPackets` (i2pd делает это только
    /// для `SendQueue`/`SendFragmentedMessage`/`Resend`, но не для
    /// контрольных пакетов).
    fn send_data(
        &mut self,
        payload: &[u8],
        flags: u8,
        now: Duration,
        register: bool,
    ) -> crate::Result<Vec<u8>> {
        let packet_num = self.send_packet_num;
        let header = ShortHeader {
            dest_conn_id: self.params.dest_conn_id,
            packet_num,
            msg_type: Ssu2MessageType::Data,
            flags: [flags, 0, 0],
        };
        let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
        let len = encode_data_packet(
            &header,
            &self.params.remote_intro_key,
            &self.send_key,
            payload,
            &mut out,
        )?;
        out.truncate(len);
        self.send_packet_num = self.send_packet_num.wrapping_add(1);
        if register {
            self.send.register_sent(packet_num, now);
            self.sent_payloads.insert(packet_num, payload.to_vec());
        }
        trace!(
            packet_num,
            payload_len = payload.len(),
            flags,
            register,
            "send_data: data packet"
        );
        Ok(out)
    }
}

/// `(GetMillisecondsSinceEpoch () + 500) / 1000` — секунды с округлением.
fn secs_rounded(now_ms: u64) -> u32 {
    u32::try_from(now_ms.saturating_add(500) / 1000).unwrap_or(u32::MAX)
}

/// Имя варианта [`BlockEvent`] для `tracing`.
const fn event_kind(event: &BlockEvent) -> &'static str {
    match event {
        BlockEvent::I2np(_) => "I2np",
        BlockEvent::FirstFragment(_) => "FirstFragment",
        BlockEvent::FollowOnFragment(_) => "FollowOnFragment",
        BlockEvent::Ack(_) => "Ack",
        BlockEvent::Termination(_) => "Termination",
        BlockEvent::DateTime(_) => "DateTime",
        BlockEvent::PathChallenge(_) => "PathChallenge",
        BlockEvent::PathResponse(_) => "PathResponse",
        BlockEvent::RelayTag(_) => "RelayTag",
        BlockEvent::RelayTagRequest => "RelayTagRequest",
        BlockEvent::NewToken(_) => "NewToken",
        BlockEvent::Address(_) => "Address",
        BlockEvent::RouterInfo(_) => "RouterInfo",
        BlockEvent::RelayRequest(_) => "RelayRequest",
        BlockEvent::RelayResponse(_) => "RelayResponse",
        BlockEvent::RelayIntro(_) => "RelayIntro",
        BlockEvent::PeerTest(_) => "PeerTest",
    }
}

/// Фаза сессии для [`Ssu2Policy::datetime_action`] (i2pd `m_State`).
///
/// Нужна везде, где решается судьба блока `DateTime` — и в data phase, и в
/// рукопожатии ([`crate::ssu2_conn`], payload `Retry`/`SessionCreated`).
#[must_use]
pub const fn handshake_phase(state: Ssu2SessionState) -> HandshakePhase {
    match state {
        Ssu2SessionState::SessionRequestReceived => HandshakePhase::SessionRequestReceived,
        Ssu2SessionState::TokenRequestReceived => HandshakePhase::TokenRequestReceived,
        Ssu2SessionState::SessionCreatedReceived => HandshakePhase::SessionCreatedReceived,
        Ssu2SessionState::TokenReceived => HandshakePhase::TokenReceived,
        Ssu2SessionState::Established => HandshakePhase::Established,
        _ => HandshakePhase::Other,
    }
}
