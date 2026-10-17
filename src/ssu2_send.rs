//! SSU2 — сборка payload'ов data phase (управляющие блоки).
//!
//! Зеркалит `SendQuickAck`, `SendKeepAlive`, `SendTermination`,
//! `SendPathChallenge` и `SendPathResponse` из i2pd (`SSU2Session.cpp:3350`,
//! `:269`, `:3367`, `:3405`, `:3375`).
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
//! - ACK-блок строится не «по месту» (`CreateAckBlock(buf, len)`), а принимается
//!   готовым [`Ssu2AckBlock`]. Если он не помещается целиком, блок не пишется;
//!   i2pd в этом случае обрезает диапазоны по бюджету места. В управляющих
//!   payload'ах места заведомо хватает, поэтому расхождение недостижимо.
//! - При переполнении `max_payload` padding не дописывается (i2pd «переполнил
//!   бы» `size_t` в `CreatePaddingBlock`); конформный вызывающий не допускает
//!   такой ситуации.

use crate::error::{I2PError, Result};
use crate::ssu2_ack::Ssu2AckBlock;
use crate::ssu2_block::{
    AddressBlock, SSU2_BLOCK_HEADER_SIZE, Ssu2Block, Ssu2BlockType, write_block,
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

/// `CreateAckBlock`: дописывает ACK-блок, если он помещается целиком.
fn append_ack(out: &mut Vec<u8>, ack: &Ssu2AckBlock, max_size: usize) -> Result<()> {
    let body = ack.to_body();
    if max_size.saturating_sub(out.len()) < SSU2_BLOCK_HEADER_SIZE + body.len() {
        return Ok(());
    }
    write_block(out, Ssu2BlockType::Ack, &body)
}

/// `CreateAddressBlock`: дописывает `Address`, если он помещается.
///
/// i2pd требует не меньше 9 байт под IPv4-блок и 21 под IPv6 (иначе
/// `CreateEndpoint` возвращает 0); при нехватке блок просто не пишется.
fn append_address(out: &mut Vec<u8>, address: &AddressBlock, max_size: usize) -> Result<()> {
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
fn append_padding<P: Ssu2Policy>(
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
