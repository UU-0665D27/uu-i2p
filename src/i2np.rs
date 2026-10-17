//! I2NP — I2P Network Protocol.
//!
//! Все сообщения I2P ходят внутри I2NP-конверта. Формат заголовка
//! зафиксирован в спеке и занимает **16 байт**:
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     1  typeID
//!        1     4  msgID            (BE u32)
//!        5     8  expiration       (BE u64, в миллисекундах)
//!       13     2  size             (BE u16, длина payload)
//!       15     1  chks             (SHA256(payload)[0], опционально)
//! ```
//!
//! Заголовок **не выравнен** ни на что — это просто поток байт.
//! После заголовка идёт payload длиной `size`.
//!
//! ## Что пока реализовано (шаг 1e)
//!
//! - [`I2npMessageType`] — 12 используемых типов + редко используемые;
//! - [`I2npHeader`] — parse / serialize / roundtrip;
//! - константы смещений, совпадающие с i2pd (`I2NPProtocol.h`).
//!
//! ## Что дальше
//!
//! - `I2npMessage` — заголовок + payload + `from` (опциональный inbound-туннель);
//! - конкретные тела (`DatabaseStoreBody`, `DatabaseLookupBody`, ...);
//! - `I2NPMessagesHandler` — очередь между транспортом и обработчиком.

use crate::endian::{
    read_u16_be, read_u32_be, read_u64_be, write_u16_be, write_u32_be, write_u64_be,
};
use crate::error::{I2PError, Result};
use std::fmt;

// --- константы смещений (совпадают с I2NPProtocol.h) ---------------------

/// Смещение поля `typeID` в заголовке.
pub const I2NP_HEADER_TYPEID_OFFSET: usize = 0;
/// Смещение поля `msgID`.
pub const I2NP_HEADER_MSGID_OFFSET: usize = I2NP_HEADER_TYPEID_OFFSET + 1;
/// Смещение поля `expiration`.
pub const I2NP_HEADER_EXPIRATION_OFFSET: usize = I2NP_HEADER_MSGID_OFFSET + 4;
/// Смещение поля `size`.
pub const I2NP_HEADER_SIZE_OFFSET: usize = I2NP_HEADER_EXPIRATION_OFFSET + 8;
/// Смещение поля `chks`.
pub const I2NP_HEADER_CHKS_OFFSET: usize = I2NP_HEADER_SIZE_OFFSET + 2;
/// Полная длина заголовка.
pub const I2NP_HEADER_SIZE: usize = I2NP_HEADER_CHKS_OFFSET + 1;

/// Время жизни сообщения по умолчанию (8 секунд).
pub const I2NP_MESSAGE_EXPIRATION_TIMEOUT_MS: u64 = 8_000;

/// `I2NP_MESSAGE_LOCAL_EXPIRATION_TIMEOUT_TRANSIT`: сколько микросекунд
/// сообщение может пролежать в локальной очереди отправки (`m_SendQueue`),
/// прежде чем его снимут и «уронят».
pub const I2NP_MESSAGE_LOCAL_EXPIRATION_TIMEOUT_TRANSIT_MICROS: u64 = 4_000_000;

/// Допустимое отклонение часов (1 минута).
pub const I2NP_MESSAGE_CLOCK_SKEW_MS: u64 = 60_000;

/// Максимальный размер I2NP-сообщения.
pub const I2NP_MAX_MESSAGE_SIZE: usize = 62_708;

/// Максимальный размер «короткого» I2NP-сообщения.
pub const I2NP_MAX_SHORT_MESSAGE_SIZE: usize = 4_096;

/// Максимальный размер «среднего» I2NP-сообщения.
pub const I2NP_MAX_MEDIUM_MESSAGE_SIZE: usize = 16_384;

// --- тип сообщения -------------------------------------------------------

/// Тип I2NP-сообщения.
///
/// Значения совпадают с `enum I2NPMessageType` в i2pd. Не все типы
/// активно используются в ECIES-роутере (`eI2NPTunnelBuild`,
/// `eI2NPTunnelBuildReply` — legacy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum I2npMessageType {
    /// `DatabaseStore` — `RouterInfo` или `LeaseSet`.
    DatabaseStore = 1,
    /// `DatabaseLookup` — запрос.
    DatabaseLookup = 2,
    /// `DatabaseSearchReply` — ответ на Lookup.
    DatabaseSearchReply = 3,
    /// `DeliveryStatus` — подтверждение доставки.
    DeliveryStatus = 10,
    /// Garlic — garlic-сообщение.
    Garlic = 11,
    /// `TunnelData` — данные туннеля.
    TunnelData = 18,
    /// `TunnelGateway` — вход в туннель.
    TunnelGateway = 19,
    /// Data — данные streaming/datagram.
    Data = 20,
    /// `TunnelBuild` (legacy).
    TunnelBuild = 21,
    /// `TunnelBuildReply` (legacy).
    TunnelBuildReply = 22,
    /// `VariableTunnelBuild` — построение туннеля (ECIES).
    VariableTunnelBuild = 23,
    /// `VariableTunnelBuildReply`.
    VariableTunnelBuildReply = 24,
    /// `ShortTunnelBuild` — короткое построение туннеля.
    ShortTunnelBuild = 25,
    /// `ShortTunnelBuildReply`.
    ShortTunnelBuildReply = 26,
    /// `TunnelTest` — проверка туннеля.
    TunnelTest = 231,
}

impl I2npMessageType {
    /// Преобразует `u8` из заголовка в тип.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::UnknownI2npType`], если значение не описано
    /// в спеке.
    pub const fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::DatabaseStore,
            2 => Self::DatabaseLookup,
            3 => Self::DatabaseSearchReply,
            10 => Self::DeliveryStatus,
            11 => Self::Garlic,
            18 => Self::TunnelData,
            19 => Self::TunnelGateway,
            20 => Self::Data,
            21 => Self::TunnelBuild,
            22 => Self::TunnelBuildReply,
            23 => Self::VariableTunnelBuild,
            24 => Self::VariableTunnelBuildReply,
            25 => Self::ShortTunnelBuild,
            26 => Self::ShortTunnelBuildReply,
            231 => Self::TunnelTest,
            _ => return Err(I2PError::UnknownI2npType(v)),
        })
    }

    /// Числовое значение для заголовка.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Человекочитаемое имя для логов (как в i2pd).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DatabaseStore => "DatabaseStore",
            Self::DatabaseLookup => "DatabaseLookup",
            Self::DatabaseSearchReply => "DatabaseSearchReply",
            Self::DeliveryStatus => "DeliveryStatus",
            Self::Garlic => "Garlic",
            Self::TunnelData => "TunnelData",
            Self::TunnelGateway => "TunnelGateway",
            Self::Data => "Data",
            Self::TunnelBuild => "TunnelBuild",
            Self::TunnelBuildReply => "TunnelBuildReply",
            Self::VariableTunnelBuild => "VariableTunnelBuild",
            Self::VariableTunnelBuildReply => "VariableTunnelBuildReply",
            Self::ShortTunnelBuild => "ShortTunnelBuild",
            Self::ShortTunnelBuildReply => "ShortTunnelBuildReply",
            Self::TunnelTest => "TunnelTest",
        }
    }
}

impl fmt::Display for I2npMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// --- заголовок -----------------------------------------------------------

/// Заголовок I2NP-сообщения (16 байт).
///
/// Не хранит payload — только метаданные. Payload идёт сразу после
/// заголовка в том же буфере.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I2npHeader {
    /// Тип сообщения.
    pub message_type: I2npMessageType,
    /// Уникальный ID сообщения (обычно random).
    pub msg_id: u32,
    /// Время истечения в миллисекундах since epoch.
    pub expiration_ms: u64,
    /// Длина payload в байтах.
    pub size: u16,
    /// Опциональный SHA256(payload)[0]; `None`, если checksum не нужен.
    pub checksum: Option<u8>,
}

impl I2npHeader {
    /// Размер заголовка в байтах (константа).
    pub const SIZE: usize = I2NP_HEADER_SIZE;

    /// Создаёт новый заголовок с текущим временем + `EXPIRATION_TIMEOUT`.
    #[must_use]
    pub fn new(message_type: I2npMessageType, msg_id: u32, size: u16) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            message_type,
            msg_id,
            expiration_ms: now_ms + I2NP_MESSAGE_EXPIRATION_TIMEOUT_MS,
            size,
            checksum: None,
        }
    }

    /// Разбирает заголовок из первых [`I2NP_HEADER_SIZE`] байт `buf`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `buf` короче 16 байт.
    /// - [`Error::UnknownI2npType`] — typeID не описан в спеке.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < I2NP_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: I2NP_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let message_type = I2npMessageType::from_u8(buf[I2NP_HEADER_TYPEID_OFFSET])?;
        let msg_id = read_u32_be(&buf[I2NP_HEADER_MSGID_OFFSET..]);
        let expiration_ms = read_u64_be(&buf[I2NP_HEADER_EXPIRATION_OFFSET..]);
        let size = read_u16_be(&buf[I2NP_HEADER_SIZE_OFFSET..]);
        let chks = buf[I2NP_HEADER_CHKS_OFFSET];
        // В i2pd chks=0 означает "checksum отсутствует". Так же и мы.
        let checksum = if chks == 0 { None } else { Some(chks) };

        Ok(Self {
            message_type,
            msg_id,
            expiration_ms,
            size,
            checksum,
        })
    }

    /// Записывает заголовок в первые [`I2NP_HEADER_SIZE`] байт `buf`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `buf` короче 16 байт.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < I2NP_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: I2NP_HEADER_SIZE,
                got: buf.len(),
            });
        }
        buf[I2NP_HEADER_TYPEID_OFFSET] = self.message_type.as_u8();
        write_u32_be(&mut buf[I2NP_HEADER_MSGID_OFFSET..], self.msg_id);
        write_u64_be(
            &mut buf[I2NP_HEADER_EXPIRATION_OFFSET..],
            self.expiration_ms,
        );
        write_u16_be(&mut buf[I2NP_HEADER_SIZE_OFFSET..], self.size);
        buf[I2NP_HEADER_CHKS_OFFSET] = self.checksum.unwrap_or(0);
        Ok(())
    }

    /// Проверяет, истекло ли сообщение с учётом clock skew.
    ///
    /// Возвращает `true`, если:
    /// - `now > expiration + CLOCK_SKEW`, или
    /// - `now < expiration - 3*CLOCK_SKEW` (слишком далеко в будущем).
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expiration_ms + I2NP_MESSAGE_CLOCK_SKEW_MS
            || now_ms
                < self
                    .expiration_ms
                    .saturating_sub(3 * I2NP_MESSAGE_CLOCK_SKEW_MS)
    }

    /// Полная длина сообщения (заголовок + payload).
    #[must_use]
    pub const fn total_len(&self) -> usize {
        I2NP_HEADER_SIZE + self.size as usize
    }
}
