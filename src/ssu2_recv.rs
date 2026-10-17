//! SSU2 — приём data-пакетов: диспетчер блоков `HandlePayload` и обвязка
//! `ProcessData`.
//!
//! Зеркалит `ProcessData` (`SSU2Session.cpp:1737`) и `HandlePayload` (`:1780`).
//! Диспетчер разбирает payload на блоки и рапортует о них через [`PayloadSink`]:
//! по методу на каждый обработчик `SSU2Session` (`HandleDateTime`,
//! `HandleRouterInfo`, `HandleI2NPMsg`, `HandleFirstFragment`, `HandleAck`,
//! `HandleRelay*`, `HandlePeerTest`, `SendPathResponse`, ...). У методов есть
//! пустые реализации по умолчанию (как лог в i2pd), поэтому реализация
//! переопределяет только нужные ей — и может на любой блок ответить своими
//! сущностями, имея доступ к состоянию сессии.
//!
//! Шифрование, номер пакета и endpoint — выше по стеку: [`process_data`] берёт
//! уже расшифрованный payload и флаги короткого заголовка.
//!
//! ## Границы проверок
//!
//! Проверки, которые в i2pd стоят прямо в `switch`, повторяет диспетчер:
//! `I2NP` — `size >= 9` и предел размера сообщения (иначе `invalid_message`);
//! `Termination` — `size >= 9`; `RelayTag` — `size >= 4`; `NewToken` —
//! `size >= 12`; `PathResponse` — `size >= 8`. Остальные ограничения
//! (`DateTime` — `len >= 4`, `RouterInfo` — `len >= 2`) применяет реализация
//! [`PayloadSink`], как и обработчики в i2pd; для `DateTime` обвязка уже есть —
//! [`handle_datetime`].
//!
//! ## Отличия от i2pd
//!
//! - `HandlePayload` не строит `I2NPMessage` сам: `on_i2np_message` получает
//!   тело блока, и реализация разбирает его
//!   ([`crate::i2np_message::I2npMessage::from_ntcp2_bytes`]). i2pd не проверяет
//!   `typeID`, а наш парсер отвергает незарегистрированные типы.
//! - Тело блока передаётся целиком, а тип — [`Ssu2BlockType`] (сырой `u8` для
//!   незарегистрированных).

use crate::i2np::{I2NP_MAX_MESSAGE_SIZE, I2NP_MAX_SHORT_MESSAGE_SIZE, I2npMessageType};
use crate::ssu2_block::Ssu2BlockType;
use crate::ssu2_header::SSU2_FLAG_IMMEDIATE_ACK_REQUESTED;
use crate::ssu2_policy::{DateTimeAction, DateTimeSession, Ssu2Policy};
use crate::ssu2_session::ReceiveState;

/// Итог [`handle_payload`]/[`process_data`] — флаги i2pd `m_IsDataReceived`
/// и `m_IsInvalidMessage`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandlePayloadResult {
    /// Пришёл «значимый» блок (i2pd `m_IsDataReceived`).
    pub data_received: bool,
    /// Блок `I2NP` неприемлемого размера (i2pd `m_IsInvalidMessage`).
    pub invalid_message: bool,
}

/// Приёмник блоков payload'а (`HandlePayload`).
///
/// По методу на каждый обработчик `SSU2Session`. Тело блока (`body`) — байты
/// после 3-байтового заголовка блока; детерминированные проверки длины уже
/// сделаны диспетчером там, где в i2pd они стоят в `switch` (см. модуль).
/// Пустые реализации по умолчанию соответствуют «только лог» в i2pd.
pub trait PayloadSink {
    /// `HandleDateTime`: блок `DateTime` (тело — 4 байта времени, если валиден).
    fn on_datetime(&mut self, _body: &[u8]) {}

    /// `HandleRouterInfo`: блок `Router Info`.
    fn on_router_info(&mut self, _body: &[u8]) {}

    /// `HandleI2NPMsg`: блок `I2NP Message` (`size >= 9` уже проверен).
    ///
    /// Реализация сама решает, разбирать ли тело
    /// ([`crate::i2np_message::I2npMessage::from_ntcp2_bytes`]) и что с ним
    /// делать.
    fn on_i2np_message(&mut self, _body: &[u8]) {}

    /// `HandleFirstFragment`: первый фрагмент I2NP-сообщения.
    fn on_first_fragment(&mut self, _body: &[u8]) {}

    /// `HandleFollowOnFragment`: продолжение фрагмента.
    fn on_follow_on_fragment(&mut self, _body: &[u8]) {}

    /// `Termination`: блок завершения (`size >= 9` уже проверен).
    ///
    /// Тело: `valid packets` (8, BE) + `reason` (1).
    fn on_termination(&mut self, _body: &[u8]) {}

    /// `HandleRelayRequest`: блок `Relay Request`.
    fn on_relay_request(&mut self, _body: &[u8]) {}

    /// `HandleRelayResponse`: блок `Relay Response`.
    fn on_relay_response(&mut self, _body: &[u8]) {}

    /// `HandleRelayIntro`: блок `Relay Intro`.
    fn on_relay_intro(&mut self, _body: &[u8]) {}

    /// `HandlePeerTest`: блок `Peer Test` (вызывается без проверок длины).
    fn on_peer_test(&mut self, _body: &[u8]) {}

    /// `HandleAck`: блок `ACK`.
    fn on_ack(&mut self, _body: &[u8]) {}

    /// `HandleAddress`: блок `Address`.
    fn on_address(&mut self, _body: &[u8]) {}

    /// `RelayTagRequest`: запрос relay-тега (тело пустое).
    fn on_relay_tag_request(&mut self) {}

    /// `RelayTag`: присланный relay-тег (`size >= 4` уже проверен).
    fn on_relay_tag(&mut self, _body: &[u8]) {}

    /// `NewToken`: новый токен (`size >= 12` уже проверен).
    fn on_new_token(&mut self, _body: &[u8]) {}

    /// `SendPathResponse`: ответить на `Path Challenge`.
    fn on_path_challenge(&mut self, _body: &[u8]) {}

    /// `PathResponse`: ответ на наш `Path Challenge` (`size >= 8` уже проверен).
    fn on_path_response(&mut self, _body: &[u8]) {}

    /// Блок, который i2pd только пишет в лог: `Options`, `Next Nonce`,
    /// `Intro Key`, `First Packet Number`, `Padding`.
    fn on_ignored_block(&mut self, _kind: Ssu2BlockType, _body: &[u8]) {}

    /// Блок незарегистрированного типа (i2pd пишет warning и продолжает).
    fn on_unknown_block(&mut self, _raw_type: u8, _body: &[u8]) {}
}

/// `HandlePayload` (`SSU2Session.cpp:1780`): разбирает payload на блоки и
/// рапортует о них в `sink`.
///
/// Блок — `type` (1) + `size` (2, BE) + тело (`size`). Разбор идёт, пока
/// влезает заголовок; если тело блока выходит за payload, разбор
/// прекращается (i2pd: `Unexpected block length`).
#[must_use]
pub fn handle_payload<S: PayloadSink>(payload: &[u8], sink: &mut S) -> HandlePayloadResult {
    let mut result = HandlePayloadResult::default();
    let mut offset = 0usize;
    while offset + 3 <= payload.len() {
        let raw_type = payload[offset];
        let size = usize::from(u16::from_be_bytes([
            payload[offset + 1],
            payload[offset + 2],
        ]));
        offset += 3;
        if offset + size > payload.len() {
            break; // i2pd: Unexpected block length
        }
        let body = &payload[offset..offset + size];
        dispatch_block(raw_type, body, sink, &mut result);
        offset += size;
    }
    result
}

/// Разбирает один блок и зовёт соответствующий метод [`PayloadSink`].
fn dispatch_block<S: PayloadSink>(
    raw_type: u8,
    body: &[u8],
    sink: &mut S,
    result: &mut HandlePayloadResult,
) {
    match Ssu2BlockType::from_u8(raw_type) {
        Some(Ssu2BlockType::DateTime) => sink.on_datetime(body),
        Some(
            kind @ (Ssu2BlockType::Options
            | Ssu2BlockType::NextNonce
            | Ssu2BlockType::IntroKey
            | Ssu2BlockType::FirstPacketNumber
            | Ssu2BlockType::Padding),
        ) => sink.on_ignored_block(kind, body),
        Some(Ssu2BlockType::RouterInfo) => sink.on_router_info(body),
        Some(Ssu2BlockType::I2npMessage) => {
            if body.len() < 9 {
                // i2pd: блок слишком короткий
                result.invalid_message = true;
            } else if body.len() + 9 > i2np_buffer_size(body[0]) {
                // i2pd: блок больше буфера I2NP-сообщения
                result.invalid_message = true;
            } else {
                sink.on_i2np_message(body);
                result.data_received = true;
            }
        }
        Some(Ssu2BlockType::FirstFragment) => {
            sink.on_first_fragment(body);
            result.data_received = true;
        }
        Some(Ssu2BlockType::FollowOnFragment) => {
            sink.on_follow_on_fragment(body);
            result.data_received = true;
        }
        Some(Ssu2BlockType::Termination) => {
            if body.len() >= 9 {
                sink.on_termination(body);
            }
        }
        Some(Ssu2BlockType::RelayRequest) => {
            sink.on_relay_request(body);
            result.data_received = true;
        }
        Some(Ssu2BlockType::RelayResponse) => {
            sink.on_relay_response(body);
            result.data_received = true;
        }
        Some(Ssu2BlockType::RelayIntro) => {
            sink.on_relay_intro(body);
            result.data_received = true;
        }
        Some(Ssu2BlockType::PeerTest) => {
            sink.on_peer_test(body);
            // i2pd: `size >= 1 && buf[offset] < 5`
            if body.first().is_some_and(|&b| b < 5) {
                result.data_received = true;
            }
        }
        Some(Ssu2BlockType::Ack) => sink.on_ack(body),
        Some(Ssu2BlockType::Address) => sink.on_address(body),
        Some(Ssu2BlockType::RelayTagRequest) => sink.on_relay_tag_request(),
        Some(Ssu2BlockType::RelayTag) => {
            if body.len() >= 4 {
                sink.on_relay_tag(body);
            }
        }
        Some(Ssu2BlockType::NewToken) => {
            if body.len() >= 12 {
                sink.on_new_token(body);
            }
        }
        Some(Ssu2BlockType::PathChallenge) => sink.on_path_challenge(body),
        Some(Ssu2BlockType::PathResponse) => {
            if body.len() >= 8 {
                sink.on_path_response(body);
            }
        }
        None => sink.on_unknown_block(raw_type, body),
    }
}

/// `HandleDateTime` (`SSU2Session.cpp:1964`): разбирает тело блока `DateTime`
/// (4 байта, BE) и отдаёт решение [`Ssu2Policy::datetime_action`].
///
/// `now_secs` — текущее время (`i2p::util::GetSecondsSinceEpoch`), расхождение
/// считается как `now_secs - time`, как `int64` в i2pd. Тело короче 4 байт —
/// [`DateTimeAction::Ignore`] (i2pd: `if (len < 4) return;`).
#[must_use]
pub fn handle_datetime<P: Ssu2Policy>(
    policy: &P,
    body: &[u8],
    now_secs: u64,
    session: &DateTimeSession,
) -> DateTimeAction {
    let Some(head) = body.first_chunk::<4>() else {
        return DateTimeAction::Ignore;
    };
    let remote = i64::from(u32::from_be_bytes(*head));
    policy.datetime_action(session, now_secs.cast_signed().saturating_sub(remote))
}

/// Предел буфера I2NP-сообщения под блок `I2NP`: `NewI2NPTunnelMessage` для
/// `TunnelData`, иначе `NewI2NPShortMessage` (`SSU2Session.cpp:1819`).
///
/// Блок должен поместиться с запасом 2 байта (reserved под NTCP2-заголовок) и
/// 7 байт полного I2NP-заголовка, то есть проверка — `size + 9 > предел`.
/// Для конформного SSU2-пакета (payload ≤ 1500) недостижимо.
const fn i2np_buffer_size(first_byte: u8) -> usize {
    if first_byte == I2npMessageType::TunnelData.as_u8() {
        I2NP_MAX_MESSAGE_SIZE
    } else {
        I2NP_MAX_SHORT_MESSAGE_SIZE
    }
}

/// Обвязка `ProcessData` над расшифрованным data-пакетом
/// (`SSU2Session.cpp:1737`, после AEAD и проверки длины).
///
/// Ставит `data_received` при флаге `IMMEDIATE_ACK_REQUESTED`, проверяет номер
/// пакета (`!packetNum || UpdateReceivePacketNum` — [`ReceiveState::accept`])
/// и при успехе зовёт [`handle_payload`]. Флаги из обоих источников
/// объединяются.
pub fn process_data<S: PayloadSink>(
    flags: u8,
    packet_num: u32,
    payload: &[u8],
    receive_state: &mut ReceiveState,
    sink: &mut S,
) -> HandlePayloadResult {
    let mut result = HandlePayloadResult::default();
    if flags & SSU2_FLAG_IMMEDIATE_ACK_REQUESTED != 0 {
        result.data_received = true;
    }
    if receive_state.accept(packet_num) {
        let inner = handle_payload(payload, sink);
        result.data_received |= inner.data_received;
        result.invalid_message |= inner.invalid_message;
    }
    result
}
