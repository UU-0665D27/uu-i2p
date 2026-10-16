//! Тело I2NP `ShortTunnelBuild` (type 25) и `ShortTunnelBuildReply`
//! (type 26).
//!
//! Оба сообщения имеют один и тот же payload: счётчик и подряд
//! идущие зашифрованные записи (см. [`crate::tunnel_build_record`]).
//! Ответ — это те же записи, которые хопы расшифровали и
//! перешифровали, поэтому и для запроса, и для ответа используется
//! один тип [`ShortTunnelBuildBody`]; тип сообщения определяется
//! I2NP-заголовком.
//!
//! ## Wire-формат
//!
//! ```text
//!   offset  size    field
//!   ------  ----    -----
//!        0     1    num      (0..=8)
//!        1  num*218 records  (EncryptedShortRecord)
//! ```
//!
//! Как и i2pd (`HandleShortTransitTunnelBuildMsg`), при разборе мы:
//! - отвергаем `num > 8`;
//! - требуем `len >= 1 + num * 218`;
//! - игнорируем хвост после последней записи.
//!
//! При сериализации хвоста нет.

use crate::error::{I2PError, Result};
use crate::tag::IdentHash;
use crate::tunnel_build_record::{
    EncryptedShortRecord, NUM_TUNNEL_BUILD_RECORDS, SHORT_TUNNEL_BUILD_RECORD_SIZE,
};

/// Размер заголовка (поле `num`).
pub const SHORT_TUNNEL_BUILD_HEADER_SIZE: usize = 1;

/// Payload `ShortTunnelBuild` / `ShortTunnelBuildReply`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShortTunnelBuildBody {
    /// Записи в порядке следования на wire (не больше 8).
    pub records: Vec<EncryptedShortRecord>,
}

impl ShortTunnelBuildBody {
    /// Создаёт тело из записей.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если записей больше
    /// [`NUM_TUNNEL_BUILD_RECORDS`].
    pub fn new(records: Vec<EncryptedShortRecord>) -> Result<Self> {
        if records.len() > NUM_TUNNEL_BUILD_RECORDS {
            return Err(I2PError::Malformed("short tunnel build: too many records"));
        }
        Ok(Self { records })
    }

    /// Разбирает payload.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — пустой буфер или он короче
    ///   `1 + num * 218`;
    /// - [`I2PError::Malformed`] — `num` больше 8.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let Some(&num) = buf.first() else {
            return Err(I2PError::InvalidLength {
                expected: SHORT_TUNNEL_BUILD_HEADER_SIZE,
                got: 0,
            });
        };
        let num = usize::from(num);
        if num > NUM_TUNNEL_BUILD_RECORDS {
            return Err(I2PError::Malformed("short tunnel build: too many records"));
        }
        let expected = SHORT_TUNNEL_BUILD_HEADER_SIZE + num * SHORT_TUNNEL_BUILD_RECORD_SIZE;
        if buf.len() < expected {
            return Err(I2PError::InvalidLength {
                expected,
                got: buf.len(),
            });
        }
        let records = buf[SHORT_TUNNEL_BUILD_HEADER_SIZE..expected]
            .as_chunks::<SHORT_TUNNEL_BUILD_RECORD_SIZE>()
            .0
            .iter()
            .map(|chunk| EncryptedShortRecord::from_bytes(chunk))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { records })
    }

    /// Сериализует payload.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если в `records` больше 8 записей
    /// (поле публичное, поэтому проверяем и здесь).
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        if self.records.len() > NUM_TUNNEL_BUILD_RECORDS {
            return Err(I2PError::Malformed("short tunnel build: too many records"));
        }
        let mut out = Vec::with_capacity(self.wire_size());
        // len <= 8, приведение без потерь
        out.push(u8::try_from(self.records.len()).unwrap_or(u8::MAX));
        for rec in &self.records {
            out.extend_from_slice(&rec.to_bytes());
        }
        Ok(out)
    }

    /// Размер payload на wire.
    #[must_use]
    pub const fn wire_size(&self) -> usize {
        SHORT_TUNNEL_BUILD_HEADER_SIZE + self.records.len() * SHORT_TUNNEL_BUILD_RECORD_SIZE
    }

    /// Первая запись, адресованная роутеру с данным ident (сравнение
    /// первых 16 байт), и её индекс.
    #[must_use]
    pub fn find_record_for(&self, ident: &IdentHash) -> Option<(usize, &EncryptedShortRecord)> {
        self.records
            .iter()
            .enumerate()
            .find(|(_, r)| r.is_for(ident))
    }
}
