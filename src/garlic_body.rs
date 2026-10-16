//! I2NP body типа `Garlic` (type=11) — конверт для зашифрованного
//! garlic-payload'а.
//!
//! ## Wire-формат
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     4  length  — BE u32, длина payload'а
//!        4     ?  payload — зашифрованный garlic payload
//! ```
//!
//! `length` считает только байты payload'а — 4-байтовый префикс в
//! длину не входит. Это тот же приём, что в I2NP `Data` и в
//! tunnel-gateway: `u32 BE` + тело.
//!
//! ## Что здесь и чего нет
//!
//! **Есть**: конверт — 4 байта префикса и `Vec<u8>` внутри.
//!
//! **Нет**:
//!
//! - **расшифровки** — она живёт в
//!   [`crate::ecies_destination::EciesGarlicDestination`]
//!   (ECIES-X25519-AEAD-Ratchet) и в ElGamal/AES-сессии, и
//!   диспетчеризуется по session-tag;
//! - **парсинга cloves** — это [`crate::garlic`], работает уже с
//!   расшифрованным payload'ом;
//! - **парсинга garlic-blocks** — это [`crate::garlic_block`],
//!   работает с payload'ом после AEAD-расшифровки внутри сессии.
//!
//! Этот модуль не знает, ECIES там или ElGamal/AES. Содержимое
//! `payload` зависит от шифрования:
//!
//! - **ECIES-X25519-AEAD-Ratchet**: `session-tag(8) || AEAD-шифртекст`.
//!   Первые 8 байт — session-tag для поиска сессии, остальное —
//!   ChaCha20-Poly1305 от garlic-blocks.
//! - **ElGamal/AES**: `session-tag(32) || AES-CBC` **или**
//!   `ElGamal-блок(514) || AES-CBC`. AES-блок содержит cloves.
//!
//! i2pd в [`GarlicDestination::HandleGarlicMessage`] делает ровно
//! это: читает 4-байтовый `length`, отдаёт payload сессии, никаких
//! семантических проверок на этом уровне нет.
//!
//! [`GarlicDestination::HandleGarlicMessage`]: https://github.com/PurpleI2P/i2pd/blob/openssl/libi2pd/Garlic.cpp

use crate::endian::{read_u32_be, write_u32_be};
use crate::error::{I2PError, Result};

/// Тело I2NP-сообщения типа `Garlic` (type=11).
///
/// ## Инварианты
///
/// - `payload.len() <= u32::MAX` — иначе [`Self::to_buffer`] вернёт
///   ошибку. На практике недостижимо: I2NP-сообщение ограничено
///   `I2NP_MAX_MESSAGE_SIZE = 62_708` байт, поле `size` в I2NP-заголовке
///   — `u16`, а 4-байтовый префикс garlic-body оставляет ещё меньше.
/// - Никаких других проверок на этом уровне: payload рассматривается
///   как непрозрачные байты для транспорта.
///
/// ## Trailing байты
///
/// Если после `4 + length` байт в буфере есть ещё данные, они
/// игнорируются — так же, как в [`crate::i2np_message::I2npMessage::from_buffer`]
/// и в i2pd. Byte-perfect roundtrip для буферов с хвостом не
/// гарантируется: [`Self::to_buffer`] всегда пишет каноническую
/// форму (`4 + payload.len()`, без хвоста).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarlicBody {
    /// Зашифрованный payload. `payload.len()` соответствует полю
    /// `length` в wire-формате.
    pub payload: Vec<u8>,
}

impl GarlicBody {
    /// Размер 4-байтового префикса длины.
    pub const LENGTH_PREFIX_SIZE: usize = 4;

    /// Конструктор из готового payload'а.
    ///
    /// Поле `length` в wire-формате будет посчитано из
    /// `payload.len()` при [`Self::to_buffer`].
    #[must_use]
    pub const fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    /// Разбирает тело `Garlic` из буфера.
    ///
    /// Первые 4 байта — BE `u32` длина. Следующие `length` байт —
    /// payload. Любые байты после `4 + length` игнорируются.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — буфер короче 4 байт (нет
    ///   даже length-поля), или объявленный `length` больше, чем
    ///   доступно байт после префикса;
    /// - [`I2PError::Malformed`] — `length` не влезает в `usize`
    ///   (на 32/64-битных платформах невозможно, но проверяем —
    ///   это защита на будущее, если `read_u32_be` вернёт `u32`,
    ///   больший чем `usize::MAX` при каком-то экзотическом target);
    /// - [`I2PError::Malformed`] — `4 + length` переполняет `usize`.
    ///   Тоже на практике недостижимо, потому что `length: u32`, а
    ///   `usize >= u32` на всех поддерживаемых платформах.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::LENGTH_PREFIX_SIZE {
            return Err(I2PError::InvalidLength {
                expected: Self::LENGTH_PREFIX_SIZE,
                got: buf.len(),
            });
        }
        let length = usize::try_from(read_u32_be(buf))
            .map_err(|_| I2PError::Malformed("garlic_body: length does not fit usize"))?;
        let end = Self::LENGTH_PREFIX_SIZE
            .checked_add(length)
            .ok_or(I2PError::Malformed("garlic_body: length overflow"))?;
        if buf.len() < end {
            return Err(I2PError::InvalidLength {
                expected: end,
                got: buf.len(),
            });
        }
        Ok(Self {
            payload: buf[Self::LENGTH_PREFIX_SIZE..end].to_vec(),
        })
    }

    /// Сериализует тело в wire-формат.
    ///
    /// Пишет `payload.len()` как BE `u32`, затем сам payload.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если `payload.len() > u32::MAX`.
    /// На практике недостижимо — см. инварианты [`GarlicBody`].
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let length = u32::try_from(self.payload.len())
            .map_err(|_| I2PError::Malformed("garlic_body: payload too long for u32"))?;
        let mut out = Vec::with_capacity(Self::LENGTH_PREFIX_SIZE + self.payload.len());
        let mut len_buf = [0u8; Self::LENGTH_PREFIX_SIZE];
        write_u32_be(&mut len_buf, length);
        out.extend_from_slice(&len_buf);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Длина зашифрованного payload'а в байтах (без 4-байтового
    /// префикса).
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// `true`, если payload пуст.
    ///
    /// Пустой garlic-body валиден на уровне wire-формата
    /// (`length = 0`). Решение о том, осмысленно ли пустое
    /// содержимое, принимает сессия.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

// --- conversions ---------------------------------------------------------

impl From<Vec<u8>> for GarlicBody {
    fn from(payload: Vec<u8>) -> Self {
        Self::new(payload)
    }
}

impl From<GarlicBody> for Vec<u8> {
    fn from(b: GarlicBody) -> Self {
        b.payload
    }
}

impl AsRef<[u8]> for GarlicBody {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}
