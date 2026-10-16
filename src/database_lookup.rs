//! `DatabaseLookup` — I2NP body, запрашивающий `RouterInfo` или
//! `LeaseSet` из netDb.
//!
//! Ответ приходит `DatabaseStore` (если найден) или
//! `DatabaseSearchReply` (если нет — со списком ближайших floodfill'ов).
//!
//! ## Wire-формат
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0    32  key            — IdentHash искомого объекта
//!       32    32  from           — IdentHash отправителя
//!       64     1  flags          — см. LOOKUP_FLAG_* и LookupType
//!       65     4  reply_tunnel_id (BE u32, только если DELIVERY)
//!        ?     2  num_excluded   (BE u16)
//!        ?     ?  excluded       — num_excluded * 32
//!        ?    32  session_key    (только если ENCRYPTION|ECIES)
//!        ?     1  num_tags       (только если ENCRYPTION|ECIES)
//!        ?     ?  tags           — num_tags * tag_len
//! ```
//!
//! `tag_len` = 8 байт для ECIES, 32 байта для `ElGamal`.
//!
//! ## Что не реализовано
//!
//! - шифрование `session_key` + теги — caller делает это сам,
//!   передавая уже готовые байты в [`DatabaseLookup::new`].

use crate::IdentHash;
use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{I2PError, Result};

/// Флаг: reply доставляется через inbound-туннель.
pub const LOOKUP_FLAG_DELIVERY: u8 = 0x01;
/// Флаг: reply зашифрован (ElGamal/AES).
pub const LOOKUP_FLAG_ENCRYPTION: u8 = 0x02;
/// Флаг: reply зашифрован для ECIES-X25519-AEAD.
pub const LOOKUP_FLAG_ECIES: u8 = 0x10;

/// Маска для type flags (биты 2-3).
pub const LOOKUP_TYPE_MASK: u8 = 0x0C;

/// Размер фиксированной части заголовка (до optional'ов).
pub const DATABASE_LOOKUP_HEADER_SIZE: usize = 65;

/// Размер тега `ElGamal` (32 байта).
pub const ELGAMAL_TAG_LEN: usize = 32;
/// Размер тега ECIES (8 байт).
pub const ECIES_TAG_LEN: usize = 8;

/// Тип lookup'а.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    /// Искать `RouterInfo`.
    RouterInfo,
    /// Искать `LeaseSet`.
    LeaseSet,
    /// Exploratory: найти любого роутера (для расширения netDb).
    Exploratory,
    /// Обычный: искать и `RouterInfo`, и `LeaseSet`.
    Normal,
}

impl LookupType {
    /// Значение для битов 2-3 flags.
    #[must_use]
    pub const fn as_flags_bits(self) -> u8 {
        match self {
            Self::Normal => 0x00,
            Self::LeaseSet => 0x04,
            Self::RouterInfo => 0x08,
            Self::Exploratory => 0x0C,
        }
    }

    /// Разбирает биты 2-3 flags.
    #[must_use]
    pub const fn from_flags_bits(bits: u8) -> Self {
        match bits & LOOKUP_TYPE_MASK {
            0x04 => Self::LeaseSet,
            0x08 => Self::RouterInfo,
            0x0C => Self::Exploratory,
            _ => Self::Normal,
        }
    }
}

/// Зашифрованный reply-session.
///
/// Для ECIES: `session_key` = ephemeral static, `tags` = список
/// 8-байтовых тегов. Для `ElGamal`: `tags` = список 32-байтовых тегов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedReply {
    /// 32-байтовый session key для расшифровки reply.
    pub session_key: [u8; 32],
    /// Теги. Для ECIES каждый 8 байт, для `ElGamal` — 32.
    pub tags: Vec<Vec<u8>>,
}

/// `DatabaseLookup` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseLookup {
    /// Идентификатор искомого объекта.
    pub key: IdentHash,
    /// Идентификатор отправителя.
    pub from: IdentHash,
    /// Тип lookup'а.
    pub lookup_type: LookupType,
    /// `TunnelID` для reply. `None` — reply придёт напрямую.
    pub reply_tunnel_id: Option<u32>,
    /// Список исключённых роутеров.
    pub excluded: Vec<IdentHash>,
    /// Зашифрованный reply (если `ENCRYPTION` или `ECIES`).
    pub encrypted_reply: Option<EncryptedReply>,
}

impl DatabaseLookup {
    /// Разбирает `DatabaseLookup` body.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — буфер короче ожидаемого;
    /// - [`Error::Malformed`] — структурные проблемы (например,
    ///   `num_excluded > 512`).
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < DATABASE_LOOKUP_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: DATABASE_LOOKUP_HEADER_SIZE,
                got: buf.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&buf[0..32]);
        let key = IdentHash::from_array(key_bytes);

        let mut from_bytes = [0u8; 32];
        from_bytes.copy_from_slice(&buf[32..64]);
        let from = IdentHash::from_array(from_bytes);

        let flags = buf[64];
        let lookup_type = LookupType::from_flags_bits(flags);
        let has_delivery = flags & LOOKUP_FLAG_DELIVERY != 0;
        let has_encryption = flags & (LOOKUP_FLAG_ENCRYPTION | LOOKUP_FLAG_ECIES) != 0;
        let is_ecies = flags & LOOKUP_FLAG_ECIES != 0;

        let mut offset = DATABASE_LOOKUP_HEADER_SIZE;

        // reply_tunnel_id
        let reply_tunnel_id = if has_delivery {
            if buf.len() < offset + 4 {
                return Err(I2PError::InvalidLength {
                    expected: offset + 4,
                    got: buf.len(),
                });
            }
            let id = read_u32_be(&buf[offset..]);
            offset += 4;
            Some(id)
        } else {
            None
        };

        // num_excluded
        if buf.len() < offset + 2 {
            return Err(I2PError::InvalidLength {
                expected: offset + 2,
                got: buf.len(),
            });
        }
        let num_excluded = usize::from(read_u16_be(&buf[offset..]));
        offset += 2;
        // Разумный лимит — как в i2pd. Реально не больше пары десятков.
        if num_excluded > 512 {
            return Err(I2PError::Malformed(
                "database_lookup: too many excluded peers",
            ));
        }
        let excluded_end = offset + num_excluded * 32;
        if buf.len() < excluded_end {
            return Err(I2PError::InvalidLength {
                expected: excluded_end,
                got: buf.len(),
            });
        }
        let mut excluded = Vec::with_capacity(num_excluded);
        for i in 0..num_excluded {
            let mut h = [0u8; 32];
            h.copy_from_slice(&buf[offset + i * 32..offset + (i + 1) * 32]);
            excluded.push(IdentHash::from_array(h));
        }
        offset = excluded_end;

        // encrypted_reply
        let encrypted_reply = if has_encryption {
            if buf.len() < offset + 33 {
                return Err(I2PError::InvalidLength {
                    expected: offset + 33,
                    got: buf.len(),
                });
            }
            let mut session_key = [0u8; 32];
            session_key.copy_from_slice(&buf[offset..offset + 32]);
            let num_tags = usize::from(buf[offset + 32]);
            offset += 33;
            let tag_len = if is_ecies {
                ECIES_TAG_LEN
            } else {
                ELGAMAL_TAG_LEN
            };
            let tags_end = offset + num_tags * tag_len;
            if buf.len() < tags_end {
                return Err(I2PError::InvalidLength {
                    expected: tags_end,
                    got: buf.len(),
                });
            }
            let mut tags = Vec::with_capacity(num_tags);
            for i in 0..num_tags {
                tags.push(buf[offset + i * tag_len..offset + (i + 1) * tag_len].to_vec());
            }
            Some(EncryptedReply { session_key, tags })
        } else {
            None
        };

        Ok(Self {
            key,
            from,
            lookup_type,
            reply_tunnel_id,
            excluded,
            encrypted_reply,
        })
    }

    /// Сериализует в wire-формат.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `excluded.len() > 512`;
    /// - [`Error::Malformed`], если `encrypted_reply.tags.len() > 255`;
    /// - [`Error::Malformed`], если тег не того размера для своего типа.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        if self.excluded.len() > 512 {
            return Err(I2PError::Malformed(
                "database_lookup: too many excluded peers",
            ));
        }

        let mut out =
            Vec::with_capacity(DATABASE_LOOKUP_HEADER_SIZE + self.excluded.len() * 32 + 64);
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(self.from.as_bytes());

        // Собираем flags
        let mut flags = self.lookup_type.as_flags_bits();
        if self.reply_tunnel_id.is_some() {
            flags |= LOOKUP_FLAG_DELIVERY;
        }
        // Определяем, ECIES или ElGamal — по размеру первого тега.
        // Если тег 8 байт — ECIES, если 32 — ElGamal. Если тегов нет,
        // считаем ECIES (современный протокол).
        let is_ecies = self
            .encrypted_reply
            .as_ref()
            .is_some_and(|er| er.tags.first().is_none_or(|t| t.len() == ECIES_TAG_LEN));
        if self.encrypted_reply.is_some() {
            flags |= LOOKUP_FLAG_ENCRYPTION;
            if is_ecies {
                flags |= LOOKUP_FLAG_ECIES;
            }
        }
        out.push(flags);

        // reply_tunnel_id
        if let Some(id) = self.reply_tunnel_id {
            out.extend_from_slice(&id.to_be_bytes());
        }

        // num_excluded + excluded
        let excluded_len = u16::try_from(self.excluded.len())
            .map_err(|_| I2PError::Malformed("database_lookup: too many excluded peers"))?;
        out.extend_from_slice(&excluded_len.to_be_bytes());
        for h in &self.excluded {
            out.extend_from_slice(h.as_bytes());
        }

        // encrypted_reply
        if let Some(er) = &self.encrypted_reply {
            out.extend_from_slice(&er.session_key);
            let num_tags = u8::try_from(er.tags.len())
                .map_err(|_| I2PError::Malformed("database_lookup: too many tags"))?;
            out.push(num_tags);
            let expected_tag_len = if is_ecies {
                ECIES_TAG_LEN
            } else {
                ELGAMAL_TAG_LEN
            };
            for tag in &er.tags {
                if tag.len() != expected_tag_len {
                    return Err(I2PError::Malformed(
                        "database_lookup: unexpected tag length",
                    ));
                }
                out.extend_from_slice(tag);
            }
        }

        Ok(out)
    }

    /// Конструктор для запроса `RouterInfo` (простой случай).
    #[must_use]
    pub const fn new_router_info(
        key: IdentHash,
        from: IdentHash,
        reply_tunnel_id: Option<u32>,
        excluded: Vec<IdentHash>,
    ) -> Self {
        Self {
            key,
            from,
            lookup_type: LookupType::RouterInfo,
            reply_tunnel_id,
            excluded,
            encrypted_reply: None,
        }
    }

    /// Конструктор для exploratory lookup'а.
    #[must_use]
    pub const fn new_exploratory(
        key: IdentHash,
        from: IdentHash,
        reply_tunnel_id: Option<u32>,
        excluded: Vec<IdentHash>,
    ) -> Self {
        Self {
            key,
            from,
            lookup_type: LookupType::Exploratory,
            reply_tunnel_id,
            excluded,
            encrypted_reply: None,
        }
    }
}
