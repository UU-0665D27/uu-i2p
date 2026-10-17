//! SSU2 — сборка payload'ов data phase (управляющие блоки, нарезка и очередь).
//!
//! Зеркалит `SendQuickAck`, `SendKeepAlive`, `SendTermination`,
//! `SendPathChallenge` и `SendPathResponse` из i2pd (`SSU2Session.cpp:3350`,
//! `:269`, `:3367`, `:3405`, `:3375`), `SendFragmentedMessage` (`:550`) с её
//! помощниками `CreateFirstFragmentBlock`/`CreateFollowOnFragmentBlock`, а
//! также упаковку очереди `SendQueue` (`:465`).
//!
//! Функции собирают только `payload` (последовательность блоков) и `flags[0]`
//! короткого заголовка; шифрование, номер пакета и сокет — на стороне
//! вызывающего ([`crate::ssu2_data::encode_data_packet`]). `roll` — «бросок»
//! для выбора размера padding'а, `now_secs` — Unix-время в секундах (как у
//! handshake); обе величины передаёт вызывающий, чтобы функция оставалась
//! чистой.
//!
//! ## Отличия от i2pd
//!
//! - ACK-блок принимается готовым [`Ssu2AckBlock`], а не строится «по месту»
//!   (`CreateAckBlock(buf, len)`). Байтовый бюджет воспроизводится обрезкой
//!   хвостовых диапазонов ([`Ssu2AckBlock::to_body_with_max_ranges`]); `ack
//!   through`/`acnt` не пересчитываются — i2pd в этом случае переразбил бы
//!   `acnt` на диапазоны.
//! - При переполнении `max_payload` padding не дописывается (i2pd «переполнил
//!   бы» `size_t` в `CreatePaddingBlock`); конформный вызывающий не допускает
//!   такой ситуации.
//! - [`fragmented_message`] возвращает список запланированных пакетов, включая
//!   отправленный ACK-пакет. Если нарезка рвётся на первом фрагменте
//!   (`CreateFirstFragmentBlock` вернул 0), план помечается
//!   [`FragmentedPlan::aborted`], а набранные до обрыва пакеты сохраняются
//!   (в i2pd они к этому моменту уже ушли бы в сокет).
//! - Случай `len < 8` в `CreateFollowOnFragmentBlock` (i2pd вызывает `SendData`
//!   с нулевой длиной — пакет теряется, а в `m_SentPackets` попадает запись с
//!   номером `0`) здесь просто не порождает пакета, и цикл продолжается с
//!   уменьшенным `extra_size`. `max_payload <= 8` отсекается ошибкой
//!   ([`I2PError::InvalidLength`]) — в i2pd это деление по модулю на ноль.
//! - [`send_queue`] не пишет в сокет: она возвращает готовые пакеты, а номер
//!   пакета, шифрование и `m_SentPackets` остаются вызывающему (как `SendData`
//!   в сессии).
//! - Очередь — [`VecDeque`] из [`QueuedMessage`] без `null`-элементов (проверка
//!   `!msg` в i2pd не воспроизводится); снятые `Drop`-ом сообщения
//!   возвращаются в [`SendQueuePlan::dropped`].

use std::collections::VecDeque;

use crate::error::{I2PError, Result};
use crate::i2np::I2NP_MESSAGE_LOCAL_EXPIRATION_TIMEOUT_TRANSIT_MICROS;
use crate::i2np_message::I2npMessage;
use crate::ssu2_ack::{SSU2_ACK_MIN_BODY_SIZE, Ssu2AckBlock};
use crate::ssu2_block::{
    AddressBlock, SSU2_BLOCK_HEADER_SIZE, Ssu2Block, Ssu2BlockType, follow_on_frag_byte,
    write_block,
};
use crate::ssu2_header::SSU2_FLAG_IMMEDIATE_ACK_REQUESTED;
use crate::ssu2_policy::Ssu2Policy;

/// Максимальный размер payload'а `SendKeepAlive` (i2pd: `uint8_t payload[20]`).
const KEEPALIVE_MAX_PAYLOAD: usize = 20;
/// Минимальный размер блока padding'а в `SendKeepAlive` (i2pd: `minSize = 8`).
const KEEPALIVE_MIN_BLOCK: usize = 8;
/// Максимальный размер payload'а `SendTermination` (i2pd: `uint8_t payload[32]`).
const TERMINATION_MAX_PAYLOAD: usize = 32;

/// Готовый payload data-пакета.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    /// Байты payload'а (последовательность блоков).
    pub payload: Vec<u8>,
    /// Значение `flags[0]` короткого заголовка (остальные флаги нули).
    pub flags: u8,
}

/// `CreateAckBlock`: дописывает ACK-блок в пределах `max_size` байт.
fn append_ack(out: &mut Vec<u8>, ack: &Ssu2AckBlock, max_size: usize) -> Result<()> {
    let budget = max_size.saturating_sub(out.len());
    append_ack_limited(out, ack, budget).map(|_| ())
}

/// `CreateAckBlock(buf, len)`: пишет ACK-блок в пределах `budget` байт.
///
/// Число диапазонов обрезается по `(budget - 8) / 2` (`8` — пустой блок),
/// как `maxNumRanges` в i2pd. Возвращает `false`, если не хватает даже пустого
/// блока (`budget < 8`).
fn append_ack_limited(out: &mut Vec<u8>, ack: &Ssu2AckBlock, budget: usize) -> Result<bool> {
    const ACK_EMPTY_SIZE: usize = SSU2_BLOCK_HEADER_SIZE + SSU2_ACK_MIN_BODY_SIZE;
    let Some(rest) = budget.checked_sub(ACK_EMPTY_SIZE) else {
        return Ok(false);
    };
    let body = ack.to_body_with_max_ranges(rest / 2);
    write_block(out, Ssu2BlockType::Ack, &body)?;
    Ok(true)
}

/// `CreateAddressBlock`: дописывает `Address`, если он помещается.
///
/// i2pd требует не меньше 9 байт под IPv4-блок и 21 под IPv6 (иначе
/// `CreateEndpoint` возвращает 0); при нехватке блок просто не пишется.
/// `CreateAddressBlock`: дописывает `Address`, если он помещается в `max_size`.
///
/// Публична: тот же приём нужен `Retry` (`CreateAddressBlock` в i2pd).
///
/// # Errors
///
/// [`I2PError::Malformed`], если тело блока не влезает в лимит блока.
pub fn append_address(out: &mut Vec<u8>, address: &AddressBlock, max_size: usize) -> Result<()> {
    let body = address.to_body();
    if max_size.saturating_sub(out.len()) < SSU2_BLOCK_HEADER_SIZE + body.len() {
        return Ok(());
    }
    write_block(out, Ssu2BlockType::Address, &body)
}

/// `CreatePaddingBlock`: дописывает `Padding`, если он помещается.
///
/// Тело `0..=31` (с маской `roll`), обрезается по остатку и поднимается до
/// `min_size`; если места меньше минимального блока — ничего не пишется
/// (i2pd возвращает 0).
///
/// Публична: тот же приём нужен handshake-пакетам `TokenRequest`/`Retry`.
///
/// # Errors
///
/// [`I2PError::Malformed`], если тело блока не влезает в лимит блока.
pub fn append_padding<P: Ssu2Policy>(
    policy: &P,
    out: &mut Vec<u8>,
    roll: u8,
    max_size: usize,
    min_size: usize,
) -> Result<()> {
    let Some(remaining) = max_size.checked_sub(out.len()) else {
        return Ok(()); // payload уже переполнен
    };
    if let Some(size) = policy.padding_size(roll, remaining, min_size) {
        let zeros = vec![0u8; size];
        write_block(out, Ssu2BlockType::Padding, &zeros)?;
    }
    Ok(())
}

/// `SendQuickAck`: `[DateTime]` + Ack + Padding.
///
/// `DateTime` добавляется, когда `send_packet_num` ушёл вперёд более чем на
/// [`Ssu2Policy::send_datetime_every`] от `last_datetime_packet_num`; тогда
/// счётчик обновляется. Флагов у пакета нет.
///
/// # Errors
///
/// [`I2PError::Malformed`] — недостижимо для контрольных блоков (тело > 64 `КиБ`).
pub fn quick_ack<P: Ssu2Policy>(
    send_packet_num: u32,
    last_datetime_packet_num: &mut u32,
    ack: &Ssu2AckBlock,
    roll: u8,
    now_secs: u32,
    max_payload: usize,
    policy: &P,
) -> Result<DataPayload> {
    let mut payload = Vec::new();
    if send_packet_num > last_datetime_packet_num.wrapping_add(policy.send_datetime_every()) {
        write_block(
            &mut payload,
            Ssu2BlockType::DateTime,
            &now_secs.to_be_bytes(),
        )?;
        *last_datetime_packet_num = send_packet_num;
    }
    append_ack(&mut payload, ack, max_payload)?;
    append_padding(policy, &mut payload, roll, max_payload, 0)?;
    Ok(DataPayload { payload, flags: 0 })
}

/// `SendKeepAlive`: Padding (не меньше 8 байт, буфер 20), флаг
/// `IMMEDIATE_ACK_REQUESTED`.
///
/// # Errors
///
/// [`I2PError::Malformed`] — недостижимо для контрольных блоков.
pub fn keep_alive<P: Ssu2Policy>(roll: u8, policy: &P) -> Result<DataPayload> {
    let mut payload = Vec::new();
    append_padding(
        policy,
        &mut payload,
        roll,
        KEEPALIVE_MAX_PAYLOAD,
        KEEPALIVE_MIN_BLOCK,
    )?;
    Ok(DataPayload {
        payload,
        flags: SSU2_FLAG_IMMEDIATE_ACK_REQUESTED,
    })
}

/// `SendTermination`: Termination + Padding (буфер 32).
///
/// `valid_packets` — `m_ReceivePacketNum` из i2pd (наибольший подряд принятый
/// номер), `reason` — [`crate::ssu2_block::Ssu2TerminationReason`].
///
/// # Errors
///
/// [`I2PError::Malformed`] — недостижимо для контрольных блоков.
pub fn termination<P: Ssu2Policy>(
    valid_packets: u64,
    reason: u8,
    roll: u8,
    policy: &P,
) -> Result<DataPayload> {
    let mut payload = Vec::new();
    let mut body = Vec::with_capacity(9);
    body.extend_from_slice(&valid_packets.to_be_bytes());
    body.push(reason);
    write_block(&mut payload, Ssu2BlockType::Termination, &body)?;
    append_padding(policy, &mut payload, roll, TERMINATION_MAX_PAYLOAD, 0)?;
    Ok(DataPayload { payload, flags: 0 })
}

/// `SendPathChallenge`: `DateTime` + Address + `PathChallenge` (8) + Ack + Padding.
///
/// Блок `PathChallenge` пишется без проверки размера (как в i2pd); будь
/// `address` непригоден, он просто не будет дописан.
///
/// # Errors
///
/// [`I2PError::Malformed`] — недостижимо для контрольных блоков.
pub fn path_challenge<P: Ssu2Policy>(
    address: &AddressBlock,
    challenge: u64,
    ack: &Ssu2AckBlock,
    roll: u8,
    now_secs: u32,
    max_payload: usize,
    policy: &P,
) -> Result<DataPayload> {
    let mut payload = Vec::new();
    write_block(
        &mut payload,
        Ssu2BlockType::DateTime,
        &now_secs.to_be_bytes(),
    )?;
    append_address(&mut payload, address, max_payload)?;
    write_block(
        &mut payload,
        Ssu2BlockType::PathChallenge,
        &challenge.to_be_bytes(),
    )?;
    append_ack(&mut payload, ack, max_payload)?;
    append_padding(policy, &mut payload, roll, max_payload, 0)?;
    Ok(DataPayload { payload, flags: 0 })
}

/// `SendPathResponse`: `DateTime` + Address + `PathResponse` + Ack + Padding.
///
/// `challenge_data` — данные из полученного `PathChallenge`, которые
/// возвращаются как есть.
///
/// # Errors
///
/// [`I2PError::InvalidLength`], если `challenge_data` не помещается (i2pd в этом
/// случае только логирует и ничего не отправляет). Проверка повторяет оригинал:
/// `payload + len > max` **без** учёта 3-байтового заголовка блока.
/// [`I2PError::Malformed`] — недостижимо для контрольных блоков.
pub fn path_response<P: Ssu2Policy>(
    address: &AddressBlock,
    challenge_data: &[u8],
    ack: &Ssu2AckBlock,
    roll: u8,
    now_secs: u32,
    max_payload: usize,
    policy: &P,
) -> Result<DataPayload> {
    let mut payload = Vec::new();
    write_block(
        &mut payload,
        Ssu2BlockType::DateTime,
        &now_secs.to_be_bytes(),
    )?;
    append_address(&mut payload, address, max_payload)?;
    if payload.len() + challenge_data.len() > max_payload {
        return Err(I2PError::InvalidLength {
            expected: max_payload,
            got: payload.len() + challenge_data.len(),
        });
    }
    write_block(&mut payload, Ssu2BlockType::PathResponse, challenge_data)?;
    append_ack(&mut payload, ack, max_payload)?;
    append_padding(policy, &mut payload, roll, max_payload, 0)?;
    Ok(DataPayload { payload, flags: 0 })
}

/// Источник «бросков» — аналог `m_Server.GetRng()` в i2pd.
///
/// Из одного значения берётся `offset` (по модулю) и `roll` для padding'а
/// (младшие [`Ssu2Policy::padding_roll_mask`] бита). Реализация по умолчанию —
/// любой [`rand::Rng`].
pub trait RandomSource {
    /// Следующее 32-битное значение (`rng()()` в i2pd).
    fn roll(&mut self) -> u32;
}

impl<R: rand::Rng + ?Sized> RandomSource for R {
    fn roll(&mut self) -> u32 {
        self.next_u32()
    }
}

/// План нарезки одного I2NP-сообщения (`SendFragmentedMessage`, `SSU2Session.cpp:550`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentedPlan {
    /// Пакеты в порядке отправки.
    pub packets: Vec<DataPayload>,
    /// Отправлен ли ACK-блок (i2pd `ackBlockSent`).
    pub ack_block_sent: bool,
    /// Нарезка оборвалась на первом фрагменте (i2pd `return false`).
    ///
    /// Пакеты в [`Self::packets`] к этому моменту уже отправлены, а сообщение —
    /// нет. i2pd в этом случае вернул бы `false` независимо от
    /// [`Self::ack_block_sent`].
    pub aborted: bool,
}

/// `CreateFirstFragmentBlock(buf, len, msg)`.
///
/// Пишет в `out` блок `FirstFragment` с `len - 3` байтами NTCP2-буфера от
/// `cursor` и сдвигает `cursor`. `false` — не помещается (`len < 12`) или
/// остаток уже влезает целиком (`remaining + 3 <= len`); в обоих случаях
/// `cursor` не трогается (i2pd `return 0`).
fn first_fragment_block(
    out: &mut Vec<u8>,
    ntcp2: &[u8],
    cursor: &mut usize,
    len: usize,
) -> Result<bool> {
    if len < 12 {
        return Ok(false);
    }
    let remaining = ntcp2.len() - *cursor;
    if remaining + 3 <= len {
        return Ok(false);
    }
    let msg_len = len - 3;
    write_block(
        out,
        Ssu2BlockType::FirstFragment,
        &ntcp2[*cursor..*cursor + msg_len],
    )?;
    *cursor += msg_len;
    Ok(true)
}

/// `CreateFollowOnFragmentBlock(buf, len, msg, fragmentNum, msgID)`.
///
/// Увеличивает `fragment_num` и сдвигает `cursor`; `Some(is_last)` — блок
/// записан (`is_last` — сообщение исчерпано), `None` — не помещается
/// (`len < 8`), ничего не меняется (i2pd `return 0`).
fn follow_on_fragment_block(
    out: &mut Vec<u8>,
    ntcp2: &[u8],
    cursor: &mut usize,
    fragment_num: &mut u8,
    msg_id: u32,
    len: usize,
) -> Result<Option<bool>> {
    if len < 8 {
        return Ok(None);
    }
    let remaining = ntcp2.len() - *cursor;
    let (msg_len, is_last) = if remaining + 8 > len {
        (len - 8, false)
    } else {
        (remaining, true)
    };
    *fragment_num = fragment_num.wrapping_add(1);
    let mut body = Vec::with_capacity(5 + msg_len);
    body.push(follow_on_frag_byte(*fragment_num, is_last));
    body.extend_from_slice(&msg_id.to_be_bytes());
    body.extend_from_slice(&ntcp2[*cursor..*cursor + msg_len]);
    write_block(out, Ssu2BlockType::FollowOnFragment, &body)?;
    *cursor += msg_len;
    Ok(Some(is_last))
}

/// `SendFragmentedMessage(packet)`: нарезает I2NP-сообщение на data-пакеты.
///
/// Если сообщение влезает целиком (`ntcp2_len + 3 <= max_payload`), план — один
/// пакет с блоком `I2NP`. Иначе сначала (при `extra_size >= 8`) пишется ACK-блок:
/// либо отдельным пакетом, либо в начало первого фрагмента. Смещения фрагментов
/// разыгрываются по `rng`, как `rng() % extraSize` в i2pd; последний фрагмент
/// может дополняться padding'ом с флагом `IMMEDIATE_ACK_REQUESTED`.
///
/// # Errors
///
/// [`I2PError::InvalidLength`], если `max_payload <= 8` (в i2pd — деление по
/// модулю на ноль); [`I2PError::Malformed`] — недостижимо (тело блока > 64 `КиБ`).
pub fn fragmented_message<P: Ssu2Policy>(
    msg: &I2npMessage,
    max_payload: usize,
    ack: &Ssu2AckBlock,
    rng: &mut impl RandomSource,
    policy: &P,
) -> Result<FragmentedPlan> {
    let ntcp2 = msg.to_ntcp2_bytes();
    let ntcp2_len = ntcp2.len();

    // Влезает одним блоком — нарезка не нужна.
    if ntcp2_len + 3 <= max_payload {
        let mut payload = Vec::new();
        write_block(&mut payload, Ssu2BlockType::I2npMessage, &ntcp2)?;
        return Ok(FragmentedPlan {
            packets: vec![DataPayload { payload, flags: 0 }],
            ack_block_sent: false,
            aborted: false,
        });
    }
    // i2pd: `(msgLen + 3 - len) % (len - 8)` — при `len <= 8` это деление на ноль.
    if max_payload <= 8 {
        return Err(I2PError::InvalidLength {
            expected: 9,
            got: max_payload,
        });
    }

    let last_fragment_size = (ntcp2_len + 3 - max_payload) % (max_payload - 8);
    let mut extra_size = max_payload - last_fragment_size;
    let mut packets: Vec<DataPayload> = Vec::new();

    let mut payload: Vec<u8> = Vec::new();
    let ack_block_sent = if extra_size >= 8 {
        append_ack_limited(&mut payload, ack, extra_size)?;
        if payload.len() + 12 < max_payload {
            // ACK уходит отдельным пакетом, первый фрагмент начинается с нуля.
            packets.push(DataPayload {
                payload: std::mem::take(&mut payload),
                flags: 0,
            });
        } else {
            extra_size -= payload.len();
        }
        true
    } else {
        false
    };

    let mut offset = if extra_size > 0 {
        (rng.roll() as usize) % extra_size
    } else {
        0
    };
    if offset + payload.len() >= max_payload {
        offset = 0;
    }
    let mut cursor = 0usize;
    let first_len = max_payload - offset - payload.len();
    if !first_fragment_block(&mut payload, &ntcp2, &mut cursor, first_len)? {
        return Ok(FragmentedPlan {
            packets,
            ack_block_sent: false,
            aborted: true,
        });
    }
    extra_size -= offset;
    packets.push(DataPayload { payload, flags: 0 });

    let msg_id = msg.msg_id();
    let mut fragment_num: u8 = 0;
    while cursor < ntcp2_len {
        let offset = if extra_size > 0 {
            (rng.roll() as usize) % extra_size
        } else {
            0
        };
        let len = max_payload.saturating_sub(offset);
        let mut payload = Vec::new();
        let written = follow_on_fragment_block(
            &mut payload,
            &ntcp2,
            &mut cursor,
            &mut fragment_num,
            msg_id,
            len,
        )?;
        extra_size -= offset;
        if let Some(is_last) = written {
            let mut flags = 0;
            if is_last && payload.len() + 16 < max_payload {
                let pad_roll = u8::try_from(rng.roll() & u32::from(policy.padding_roll_mask()))
                    .unwrap_or_default();
                let remaining = max_payload - payload.len();
                append_padding(policy, &mut payload, pad_roll, remaining, 0)?;
                if fragment_num > 2 {
                    flags |= SSU2_FLAG_IMMEDIATE_ACK_REQUESTED;
                }
            }
            packets.push(DataPayload { payload, flags });
        }
    }

    Ok(FragmentedPlan {
        packets,
        ack_block_sent,
        aborted: false,
    })
}

/// Один «бросок» для padding'а: `GetRng()() & padding_roll_mask`.
///
/// Публична, чтобы вызывающий мог повторить ту же маску для контрольных
/// пакетов (`SendQuickAck`/`SendKeepAlive`/`SendTermination`), которые i2pd
/// собирает вне [`send_queue`].
pub fn padding_roll<P: Ssu2Policy>(rng: &mut impl RandomSource, policy: &P) -> u8 {
    u8::try_from(rng.roll() & u32::from(policy.padding_roll_mask())).unwrap_or_default()
}

/// Сообщение в очереди отправки (зеркало `I2NPMessage` в `m_SendQueue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessage {
    /// Само I2NP-сообщение.
    pub message: I2npMessage,
    /// Момент постановки в очередь (`enqueueTime`, монотонные микросекунды).
    pub enqueue_time: u64,
}

/// Параметры [`send_queue`] — срез состояния сессии из i2pd.
#[derive(Debug, Clone, Copy)]
pub struct SendQueueConfig<'a> {
    /// ACK-блок, который кладётся в начало каждого пакета (`CreateAckBlock`).
    pub ack: &'a Ssu2AckBlock,
    /// Максимум payload'а пакета (`m_MaxPayloadSize`).
    pub max_payload: usize,
    /// Размер окна (`m_WindowSize`).
    pub window_size: usize,
    /// Сколько пакетов отправлено и не подтверждено (`m_SentPackets.size()`).
    pub sent_packets: usize,
    /// Установлена ли сессия (`IsEstablished`).
    pub established: bool,
    /// `i2p::util::GetMillisecondsSinceEpoch()`.
    pub now_ms: u64,
    /// `i2p::util::GetMonotonicMicroseconds()`.
    pub now_micros: u64,
}

/// Результат [`send_queue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendQueuePlan {
    /// Пакеты в порядке отправки; номер, шифрование и `m_SentPackets` — за
    /// вызывающим (i2pd `SendData`).
    pub packets: Vec<DataPayload>,
    /// Отправлен ли где-нибудь ACK-блок (i2pd `ackBlockSent`).
    pub ack_block_sent: bool,
    /// Сообщения, снятые с очереди как истёкшие/просроченные (i2pd `Drop`).
    pub dropped: Vec<I2npMessage>,
}

/// `SendQueue` (`SSU2Session.cpp:465`): упаковывает очередь в data-пакеты.
///
/// Пока в очереди есть что-то, сессия установлена и окно не переполнено,
/// сообщения складываются в пакеты: в начало каждого идёт ACK-блок
/// (`CreateAckBlock`), затем блоки `I2NP`; не влезающие целиком сообщения
/// уходят через [`fragmented_message`]. Истёкшие (`IsExpired`) и «просроченные»
/// по `I2NP_MESSAGE_LOCAL_EXPIRATION_TIMEOUT_TRANSIT` снимаются и попадают в
/// [`SendQueuePlan::dropped`].
///
/// Готовые пакеты возвращаются в порядке отправки: последний несёт флаг
/// `IMMEDIATE_ACK_REQUESTED` (как и «завершающий» пакет в i2pd).
///
/// # Errors
///
/// Пробрасывает ошибки сборки блоков ([`I2PError::Malformed`] — недостижимо).
pub fn send_queue<P: Ssu2Policy>(
    queue: &mut VecDeque<QueuedMessage>,
    cfg: &SendQueueConfig<'_>,
    rng: &mut impl RandomSource,
    policy: &P,
) -> Result<SendQueuePlan> {
    let mut packets: Vec<DataPayload> = Vec::new();
    let mut dropped: Vec<I2npMessage> = Vec::new();
    if queue.is_empty() || cfg.sent_packets > cfg.window_size || !cfg.established {
        return Ok(SendQueuePlan {
            packets,
            ack_block_sent: false,
            dropped,
        });
    }

    let mut sent = cfg.sent_packets;
    let mut ack_block_sent = false;

    // Каждый пакет начинается с ACK-блока, записанного с полным бюджетом
    // (`CreateAckBlock(payload, m_MaxPayloadSize)`).
    let mut current: Vec<u8> = Vec::new();
    append_ack_limited(&mut current, cfg.ack, cfg.max_payload)?;
    let ack_block_size = current.len();

    while !queue.is_empty() && sent <= cfg.window_size {
        let (expired, ntcp2) = {
            let Some(front) = queue.front() else { break };
            (
                front.message.is_expired(cfg.now_ms)
                    || front.enqueue_time + I2NP_MESSAGE_LOCAL_EXPIRATION_TIMEOUT_TRANSIT_MICROS
                        < cfg.now_micros,
                front.message.to_ntcp2_bytes(),
            )
        };
        if expired {
            let Some(msg) = queue.pop_front() else {
                break;
            };
            dropped.push(msg.message);
            continue;
        }

        let len = ntcp2.len() + 3;
        if len > cfg.max_payload {
            // сообщение слишком длинное — уходит фрагментами
            let Some(msg) = queue.pop_front() else {
                break;
            };
            let plan = fragmented_message(&msg.message, cfg.max_payload, cfg.ack, rng, policy)?;
            if !plan.aborted && plan.ack_block_sent {
                ack_block_sent = true;
            }
            sent += plan.packets.len();
            packets.extend(plan.packets);
        } else if current.len() + len <= cfg.max_payload {
            queue.pop_front();
            write_block(&mut current, Ssu2BlockType::I2npMessage, &ntcp2)?;
        } else {
            // новому пакету — копия ACK-блока
            let new_packet = current[..ack_block_size].to_vec();
            if current.len() > ack_block_size {
                // текущий пакет содержит больше, чем ACK-блок — отправляем
                ack_block_sent = true;
                if current.len() + 16 < cfg.max_payload {
                    let roll = padding_roll(rng, policy);
                    append_padding(policy, &mut current, roll, cfg.max_payload, 0)?;
                }
            } else {
                // в текущем пакете только ACK-блок
                if len + 8 < cfg.max_payload {
                    // оставляем ACK-блок, обрезая диапазоны под размер сообщения
                    ack_block_sent = true;
                    let mut size = cfg.max_payload - len;
                    if size % 2 == 1 {
                        size -= 1; // сделать чётным
                    }
                    let mut reduced = Vec::new();
                    append_ack_limited(&mut reduced, cfg.ack, size)?;
                    current = reduced;
                } else {
                    // ACK-блок не помещается — выбрасываем
                    current.clear();
                }
                queue.pop_front();
                write_block(&mut current, Ssu2BlockType::I2npMessage, &ntcp2)?;
            }
            packets.push(DataPayload {
                payload: std::mem::take(&mut current),
                flags: 0,
            });
            sent += 1;
            current = new_packet;
        }
    }

    if current.len() > ack_block_size {
        // последний пакет: padding и флаг IMMEDIATE_ACK_REQUESTED
        ack_block_sent = true;
        if current.len() + 16 < cfg.max_payload {
            let roll = padding_roll(rng, policy);
            append_padding(policy, &mut current, roll, cfg.max_payload, 0)?;
        }
        packets.push(DataPayload {
            payload: current,
            flags: SSU2_FLAG_IMMEDIATE_ACK_REQUESTED,
        });
    }

    Ok(SendQueuePlan {
        packets,
        ack_block_sent,
        dropped,
    })
}
