//! SSU2 — пакет data phase.
//!
//! Верхний «примитив» над заголовком, криптой и блоками: собирает и
//! разбирает один UDP-пакет data phase.
//!
//! Формат (i2pd `SendData` / `ProcessData`):
//!
//! ```text
//! 0..16   короткий заголовок (короткий, тип Data)
//! 16..    AEAD(plaintext) + 16-байтовый MAC Poly1305
//! ```
//!
//! AEAD: `ChaCha20-Poly1305`, ключ `k_data`, nonce = [`crate::ssu2_crypto::aead_nonce`]
//! от номера пакета, ассоциированные данные — **незашифрованный** 16-байтовый
//! заголовок. После шифрования заголовок обфусцируется cover-маской:
//! `k_header_1` = intro-ключ (байты `0..8`), `k_header_2` = посыл
//! [`crate::ssu2_crypto::DataPhaseKey::k_header_2`] (байты `8..16`), IV — из
//! хвоста пакета.
//!
//! ## Отличие от i2pd на приёме
//!
//! i2pd при приёме не деобфусцирует первые 8 байт: он подставляет туда
//! известный ему `m_SourceConnID` и расшифровывает только вторую половину
//! заголовка. Мы деобфусцируем обе половины (intro-ключ известен обеим
//! сторонам), что даёт тот же результат, но требует пакет не короче
//! [`SSU2_MIN_PACKET_SIZE`] — при меньшей длине хвостовые IV пересеклись бы с
//! изменяемым регионом. Конформный отправитель (i2pd `SendData`: payload ≥ 8)
//! всегда даёт ровно 40 байт и больше.

use crate::{
    crypto::AeadChaCha20Poly1305,
    error::{I2PError, Result},
    ssu2_crypto::{DataPhaseKey, aead_nonce},
    ssu2_header::{
        SSU2_HEADER_SIZE, SSU2_MIN_PACKET_SIZE, ShortHeader, Ssu2MessageType,
        obfuscate_cover_header,
    },
};

/// Накладные расходы data-пакета: короткий заголовок (16) + MAC Poly1305 (16).
pub const SSU2_DATA_OVERHEAD: usize = SSU2_HEADER_SIZE + 16;

/// Собирает data-пакет в `out`.
///
/// `header.msg_type` обязан быть [`Ssu2MessageType::Data`]. `out` — не меньше
/// `payload.len() + SSU2_DATA_OVERHEAD`. Возвращает длину записанного пакета.
///
/// # Errors
///
/// - [`I2PError::Malformed`], если тип заголовка не `Data`;
/// - [`I2PError::InvalidLength`], если итоговый пакет короче
///   [`SSU2_MIN_PACKET_SIZE`] или `out` мал.
pub fn encode_data_packet(
    header: &ShortHeader,
    intro_key: &[u8; 32],
    key: &DataPhaseKey,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    if header.msg_type != Ssu2MessageType::Data {
        return Err(I2PError::Malformed(
            "ssu2: data packet must have Data message type",
        ));
    }
    let total = payload.len() + SSU2_DATA_OVERHEAD;
    if total < SSU2_MIN_PACKET_SIZE {
        return Err(I2PError::InvalidLength {
            expected: SSU2_MIN_PACKET_SIZE,
            got: total,
        });
    }
    if out.len() < total {
        return Err(I2PError::InvalidLength {
            expected: total,
            got: out.len(),
        });
    }

    let header_bytes = header.to_bytes();
    out[..SSU2_HEADER_SIZE].copy_from_slice(&header_bytes);
    let nonce = aead_nonce(u64::from(header.packet_num));
    let aead = AeadChaCha20Poly1305::new();
    aead.encrypt(
        &key.k_data,
        &nonce,
        &header_bytes,
        payload,
        &mut out[SSU2_HEADER_SIZE..total],
    )?;
    // Обфускация заголовка — после шифрования (IV берётся из ciphertext-хвоста).
    obfuscate_cover_header(intro_key, &key.k_header_2, &mut out[..total])?;
    Ok(total)
}

/// Разбирает data-пакет: деобфусцирует заголовок и расшифровывает payload.
///
/// Деобфусцирует `packet` **на месте** (операция инволютивна) и записывает
/// plaintext в `out`. Возвращает заголовок и срез расшифрованного payload
/// внутри `out`.
///
/// # Errors
///
/// - [`I2PError::InvalidLength`], если `packet` короче
///   [`SSU2_MIN_PACKET_SIZE`];
/// - [`I2PError::UnknownSsu2MessageType`] / [`I2PError::Malformed`], если
///   заголовок не разбирается или тип не `Data`;
/// - [`I2PError::Malformed`], если не сходится AEAD-тег или `out` мал.
pub fn decode_data_packet<'a>(
    packet: &mut [u8],
    intro_key: &[u8; 32],
    key: &DataPhaseKey,
    out: &'a mut [u8],
) -> Result<(ShortHeader, &'a [u8])> {
    if packet.len() < SSU2_MIN_PACKET_SIZE {
        return Err(I2PError::InvalidLength {
            expected: SSU2_MIN_PACKET_SIZE,
            got: packet.len(),
        });
    }
    obfuscate_cover_header(intro_key, &key.k_header_2, packet)?;
    let header = ShortHeader::parse(&packet[..SSU2_HEADER_SIZE])?;
    if header.msg_type != Ssu2MessageType::Data {
        return Err(I2PError::Malformed(
            "ssu2: data packet must have Data message type",
        ));
    }
    let nonce = aead_nonce(u64::from(header.packet_num));
    let aead = AeadChaCha20Poly1305::new();
    let len = aead.decrypt(
        &key.k_data,
        &nonce,
        &packet[..SSU2_HEADER_SIZE],
        &packet[SSU2_HEADER_SIZE..],
        out,
    )?;
    Ok((header, &out[..len]))
}
