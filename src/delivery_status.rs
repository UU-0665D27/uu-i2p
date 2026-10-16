//! `DeliveryStatus` — I2NP body, подтверждающий доставку другого
//! сообщения.
//!
//! Отправляется в ответ на `DatabaseStore` (и другие типы), когда
//! в исходном сообщении был ненулевой `reply_token`. Получатель
//! `DeliveryStatus` понимает, что адресат получил сообщение.
//!
//! ## Wire-формат
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     4  msg_id      (BE u32) — id подтверждаемого сообщения
//!        4     8  timestamp   (BE u64, ms since epoch)
//! ```
//!
//! Всего 12 байт. Timestamp не проверяется получателем — нужен для
//! отладки и потенциальной оценки RTT.
//!
//! ## Особый случай: `msg_id = 0`
//!
//! Для SSU2 establishment handshake (когда `msg_id = 0`) вместо
//! timestamp в wire лежит `net_id` (как `u64 BE`). См.
//! `CreateDeliveryStatusMsg` в `I2NPProtocol.cpp`. На уровне нашего
//! API это просто `timestamp_ms` — caller сам решает, что туда
//! класть.

use crate::endian::{read_u32_be, read_u64_be, write_u32_be, write_u64_be};
use crate::error::{I2PError, Result};

/// Размер `DeliveryStatus` в байтах.
pub const DELIVERY_STATUS_SIZE: usize = 12;

/// `DeliveryStatus` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryStatus {
    /// ID сообщения, которое подтверждаем.
    pub msg_id: u32,
    /// Timestamp в миллисекундах since epoch. `0` допустим — i2pd
    /// так пишет при отсутствии осмысленного значения.
    pub timestamp_ms: u64,
}

impl DeliveryStatus {
    /// Конструктор с текущим временем.
    #[must_use]
    pub fn now(msg_id: u32) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            msg_id,
            timestamp_ms: now_ms,
        }
    }

    /// Конструктор с явными значениями.
    #[must_use]
    pub const fn new(msg_id: u32, timestamp_ms: u64) -> Self {
        Self {
            msg_id,
            timestamp_ms,
        }
    }

    /// Разбирает `DeliveryStatus` из буфера.
    ///
    /// Trailing байты игнорируются — как в i2pd.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если буфер короче
    /// [`DELIVERY_STATUS_SIZE`] (12 байт).
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < DELIVERY_STATUS_SIZE {
            return Err(I2PError::InvalidLength {
                expected: DELIVERY_STATUS_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            msg_id: read_u32_be(buf),
            timestamp_ms: read_u64_be(&buf[4..]),
        })
    }

    /// Сериализует в wire-формат (12 байт).
    #[must_use]
    pub fn to_buffer(&self) -> [u8; DELIVERY_STATUS_SIZE] {
        let mut out = [0u8; DELIVERY_STATUS_SIZE];
        write_u32_be(&mut out[0..], self.msg_id);
        write_u64_be(&mut out[4..], self.timestamp_ms);
        out
    }
}
