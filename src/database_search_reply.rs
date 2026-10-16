//! `DatabaseSearchReply` — ответ на `DatabaseLookup`.
//!
//! Приходит, когда запрошенный объект (`RouterInfo` / `LeaseSet`)
//! не найден у floodfill'а. Содержит список ближайших известных
//! роутеров, у которых можно спросить снова. Это основа Kademlia-like
//! поиска в netDb.
//!
//! ## Wire-формат
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0    32  key            — IdentHash искомого объекта
//!       32     1  num            — количество hashes
//!       33     ?  hashes         — num * 32
//!        ?    32  from           — IdentHash отправителя (optional, i2pd пишет)
//! ```
//!
//! `from` — trailing блок, который i2pd **пишет**, но **не читает**
//! (см. `NetDbRequests::HandleDatabaseSearchReplyMsg`). Мы сохраняем
//! его, если он есть в буфере, для byte-perfect round-trip.

use crate::IdentHash;
use crate::error::{I2PError, Result};

/// Размер фиксированного заголовка (key + num).
pub const DATABASE_SEARCH_REPLY_HEADER_SIZE: usize = 33;

/// `DatabaseSearchReply` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseSearchReply {
    /// Идентификатор, по которому был запрос.
    pub key: IdentHash,
    /// Список хэшей роутеров, у которых стоит спросить снова.
    pub peer_hashes: Vec<IdentHash>,
    /// Идентификатор отправителя. `None`, если trailing-блок
    /// отсутствует (некоторые реализации могут его не писать).
    pub from: Option<IdentHash>,
}

impl DatabaseSearchReply {
    /// Разбирает `DatabaseSearchReply` body.
    ///
    /// Trailing байты после `from` (если они есть) игнорируются —
    /// как в i2pd.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — буфер короче `33 + num*32`.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < DATABASE_SEARCH_REPLY_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: DATABASE_SEARCH_REPLY_HEADER_SIZE,
                got: buf.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&buf[0..32]);
        let key = IdentHash::from_array(key_bytes);

        let num = usize::from(buf[32]);
        let hashes_end = DATABASE_SEARCH_REPLY_HEADER_SIZE + num * 32;
        if buf.len() < hashes_end {
            return Err(I2PError::InvalidLength {
                expected: hashes_end,
                got: buf.len(),
            });
        }

        let mut peer_hashes = Vec::with_capacity(num);
        for i in 0..num {
            let off = DATABASE_SEARCH_REPLY_HEADER_SIZE + i * 32;
            let mut h = [0u8; 32];
            h.copy_from_slice(&buf[off..off + 32]);
            peer_hashes.push(IdentHash::from_array(h));
        }

        // Опциональный `from` — 32 байта после hashes.
        let from = if buf.len() >= hashes_end + 32 {
            let mut f = [0u8; 32];
            f.copy_from_slice(&buf[hashes_end..hashes_end + 32]);
            Some(IdentHash::from_array(f))
        } else {
            None
        };

        Ok(Self {
            key,
            peer_hashes,
            from,
        })
    }

    /// Сериализует в wire-формат.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `peer_hashes.len() > 255`.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let num = u8::try_from(self.peer_hashes.len())
            .map_err(|_| I2PError::Malformed("database_search_reply: too many hashes"))?;

        let total = DATABASE_SEARCH_REPLY_HEADER_SIZE
            + self.peer_hashes.len() * 32
            + if self.from.is_some() { 32 } else { 0 };
        let mut out = Vec::with_capacity(total);

        out.extend_from_slice(self.key.as_bytes());
        out.push(num);
        for h in &self.peer_hashes {
            out.extend_from_slice(h.as_bytes());
        }
        if let Some(f) = &self.from {
            out.extend_from_slice(f.as_bytes());
        }
        Ok(out)
    }

    /// Конструктор без `from`.
    #[must_use]
    pub const fn new(key: IdentHash, peer_hashes: Vec<IdentHash>) -> Self {
        Self {
            key,
            peer_hashes,
            from: None,
        }
    }

    /// Конструктор с `from` — то, что пишет i2pd.
    #[must_use]
    pub const fn with_from(key: IdentHash, peer_hashes: Vec<IdentHash>, from: IdentHash) -> Self {
        Self {
            key,
            peer_hashes,
            from: Some(from),
        }
    }
}
