//! `DatabaseStore` — I2NP body, несущий `RouterInfo` или `LeaseSet`.
//!
//! Самое частое сообщение в сети: публикует в netDb новый/обновлённый
//! `RouterInfo` или `LeaseSet`. Используется для публикации собственного
//! RI, для запроса чужих RI, для floodfill'ов.
//!
//! ## Wire-формат
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0    32  key            — IdentHash хранимого объекта
//!       32     1  store_type     — 0=RI, 1=LS1, 3=LS2, 5=EncLS2, 7=MetaLS2
//!       33     4  reply_token    — BE u32, 0 = не запрашивать DeliveryStatus
//!       37     ?  reply_instr    — только если reply_token != 0:
//!                                     tunnel_id(4 BE) | gateway(32)
//!        ?     ?  payload        — зависит от store_type (см. ниже)
//! ```
//!
//! ### Payload (`store_type` = 0, `RouterInfo`)
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     2  gzip_len   — BE u16
//!        2     ?  gzip_data  — сжатый или stored gzip-контейнер
//! ```
//!
//! При приёме: снять 2-байтовый префикс, разжать gzip — получить
//! сырые байты `RouterInfo` (identity + body + signature).
//!
//! ### Payload (`store_type` = 1, 3, 5, 7, `LeaseSet`)
//!
//! Сырые байты `LeaseSet` / `LeaseSet2`, **без сжатия и без префикса
//! длины**. Границу определяет длина I2NP payload'а.

use crate::IdentHash;
use crate::endian::{read_u16_be, read_u32_be, write_u16_be};
use crate::error::{I2PError, Result};
use crate::gzip;

/// Store type `RouterInfo` в `DatabaseStore`.
pub const STORE_TYPE_ROUTER_INFO: u8 = 0;
/// Store type `LeaseSet` (type 1).
pub const STORE_TYPE_LEASESET: u8 = 1;
/// Store type `LeaseSet2` (type 3).
pub const STORE_TYPE_STANDARD_LEASESET2: u8 = 3;
/// Store type `EncryptedLeaseSet2` (type 5).
pub const STORE_TYPE_ENCRYPTED_LEASESET2: u8 = 5;
/// Store type `MetaLeaseSet2` (type 7).
pub const STORE_TYPE_META_LEASESET2: u8 = 7;

/// Размер фиксированной части заголовка (до `reply_instruction`).
pub const DATABASE_STORE_HEADER_SIZE: usize = 37;

/// Размер блока reply-instruction (`tunnel_id` + gateway).
pub const REPLY_INSTRUCTION_SIZE: usize = 36;

/// Куда отправить `DeliveryStatus` в ответ.
///
/// Пишется только если `reply_token != 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyInstruction {
    /// `TunnelID` на `gateway`-роутере.
    pub tunnel_id: u32,
    /// Router, к которому слать `DeliveryStatus`.
    pub gateway: IdentHash,
}

/// Тип хранимого объекта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreType {
    /// `RouterInfo` (сжатый gzip'ом, с 2-байтовым префиксом длины).
    RouterInfo,
    /// `LeaseSet` (type 1).
    LeaseSet,
    /// `LeaseSet2` (type 3).
    LeaseSet2,
    /// `EncryptedLeaseSet2` (type 5).
    EncryptedLeaseSet2,
    /// `MetaLeaseSet2` (type 7).
    MetaLeaseSet2,
    /// Неизвестный тип.
    Unknown(u8),
}

impl StoreType {
    /// Числовое значение для wire-формата.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::RouterInfo => STORE_TYPE_ROUTER_INFO,
            Self::LeaseSet => STORE_TYPE_LEASESET,
            Self::LeaseSet2 => STORE_TYPE_STANDARD_LEASESET2,
            Self::EncryptedLeaseSet2 => STORE_TYPE_ENCRYPTED_LEASESET2,
            Self::MetaLeaseSet2 => STORE_TYPE_META_LEASESET2,
            Self::Unknown(v) => v,
        }
    }

    /// Разбирает `u8`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            STORE_TYPE_ROUTER_INFO => Self::RouterInfo,
            STORE_TYPE_LEASESET => Self::LeaseSet,
            STORE_TYPE_STANDARD_LEASESET2 => Self::LeaseSet2,
            STORE_TYPE_ENCRYPTED_LEASESET2 => Self::EncryptedLeaseSet2,
            STORE_TYPE_META_LEASESET2 => Self::MetaLeaseSet2,
            other => Self::Unknown(other),
        }
    }
}

/// `DatabaseStore` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseStore {
    /// Идентификатор хранимого объекта — `RouterInfo` hash или
    /// `LeaseSet` hash (для encrypted LS2 — store hash, не ident).
    pub key: IdentHash,
    /// Тип хранимого объекта.
    pub store_type: StoreType,
    /// Токен для `DeliveryStatus`. `0` — не запрашивать.
    pub reply_token: u32,
    /// Инструкция доставки `DeliveryStatus`. `None` — доставлять
    /// напрямую отправителю.
    pub reply_instruction: Option<ReplyInstruction>,
    /// Сырой payload (см. doc модуля — формат зависит от `store_type`).
    payload: Vec<u8>,
}

impl DatabaseStore {
    /// Разбирает `DatabaseStore` body.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — буфер короче ожидаемого;
    /// - [`Error::Malformed`] — для `RouterInfo` размер payload'а
    ///   не сходится.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < DATABASE_STORE_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: DATABASE_STORE_HEADER_SIZE,
                got: buf.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&buf[0..32]);
        let key = IdentHash::from_array(key_bytes);
        let store_type = StoreType::from_u8(buf[32]);
        let reply_token = read_u32_be(&buf[33..37]);

        let mut offset = DATABASE_STORE_HEADER_SIZE;
        let reply_instruction = if reply_token != 0 {
            let end = offset + REPLY_INSTRUCTION_SIZE;
            if buf.len() < end {
                return Err(I2PError::InvalidLength {
                    expected: end,
                    got: buf.len(),
                });
            }
            let tunnel_id = read_u32_be(&buf[offset..]);
            let mut gw = [0u8; 32];
            gw.copy_from_slice(&buf[offset + 4..offset + 36]);
            offset = end;
            Some(ReplyInstruction {
                tunnel_id,
                gateway: IdentHash::from_array(gw),
            })
        } else {
            None
        };

        // Payload
        let payload = match store_type {
            StoreType::RouterInfo => {
                // size(2 BE) || gzip_data
                if buf.len() < offset + 2 {
                    return Err(I2PError::InvalidLength {
                        expected: offset + 2,
                        got: buf.len(),
                    });
                }
                let gzip_len = usize::from(read_u16_be(&buf[offset..]));
                offset += 2;
                if buf.len() < offset + gzip_len {
                    return Err(I2PError::InvalidLength {
                        expected: offset + gzip_len,
                        got: buf.len(),
                    });
                }
                buf[offset..offset + gzip_len].to_vec()
            }
            _ => buf[offset..].to_vec(),
        };

        Ok(Self {
            key,
            store_type,
            reply_token,
            reply_instruction,
            payload,
        })
    }

    /// Сериализует в wire-формат.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если для `RouterInfo` payload
    ///   больше `u16::MAX`;
    /// - [`Error::Malformed`], если `reply_token != 0`, но
    ///   `reply_instruction == None`.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            DATABASE_STORE_HEADER_SIZE + REPLY_INSTRUCTION_SIZE + self.payload.len() + 2,
        );
        out.extend_from_slice(self.key.as_bytes());
        out.push(self.store_type.as_u8());
        out.extend_from_slice(&self.reply_token.to_be_bytes());

        if self.reply_token != 0 {
            let Some(instr) = &self.reply_instruction else {
                return Err(I2PError::Malformed(
                    "database_store: reply_token set without reply_instruction",
                ));
            };
            out.extend_from_slice(&instr.tunnel_id.to_be_bytes());
            out.extend_from_slice(instr.gateway.as_bytes());
        }

        if self.store_type == StoreType::RouterInfo {
            let len = u16::try_from(self.payload.len())
                .map_err(|_| I2PError::Malformed("database_store: RouterInfo payload > 64KB"))?;
            let mut len_buf = [0u8; 2];
            write_u16_be(&mut len_buf, len);
            out.extend_from_slice(&len_buf);
        }
        out.extend_from_slice(&self.payload);

        Ok(out)
    }

    /// Создаёт `DatabaseStore` для `RouterInfo` (type 0).
    ///
    /// `ri_bytes` — сырые байты `RouterInfo` (identity + body +
    /// signature, как в `routerInfo-*.dat`). Метод сам сжимает их
    /// gzip'ом.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `ri_bytes` больше `u16::MAX`.
    pub fn new_router_info(
        key: IdentHash,
        ri_bytes: &[u8],
        reply_token: u32,
        reply_instruction: Option<ReplyInstruction>,
    ) -> Result<Self> {
        if reply_token != 0 && reply_instruction.is_none() {
            return Err(I2PError::Malformed(
                "database_store: reply_token set without reply_instruction",
            ));
        }
        let payload = gzip::compress(ri_bytes)?;
        Ok(Self {
            key,
            store_type: StoreType::RouterInfo,
            reply_token,
            reply_instruction,
            payload,
        })
    }

    /// Создаёт `DatabaseStore` для `LeaseSet` (type 1).
    ///
    /// `ls_bytes` — сырые байты `LeaseSet`. Без сжатия.
    #[must_use]
    pub const fn new_lease_set(key: IdentHash, ls_bytes: Vec<u8>) -> Self {
        Self {
            key,
            store_type: StoreType::LeaseSet,
            reply_token: 0,
            reply_instruction: None,
            payload: ls_bytes,
        }
    }

    /// Создаёт `DatabaseStore` для `LeaseSet2` (type 3).
    #[must_use]
    pub const fn new_lease_set2(key: IdentHash, ls_bytes: Vec<u8>) -> Self {
        Self {
            key,
            store_type: StoreType::LeaseSet2,
            reply_token: 0,
            reply_instruction: None,
            payload: ls_bytes,
        }
    }

    /// Создаёт `DatabaseStore` для `LeaseSet` любого типа
    /// (`LeaseSet`, `LeaseSet2`, `EncryptedLeaseSet2`, `MetaLeaseSet2`).
    ///
    /// `ls_bytes` — payload как есть, без байта типа: для `LeaseSet2`
    /// он начинается с identity (так же, как в i2pd
    /// `NetDb::HandleDatabaseStoreMsg` передаёт `buf + offset` в
    /// `AddLeaseSet2`).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `store_type` — не LeaseSet-тип.
    pub fn new_lease_set_typed(
        key: IdentHash,
        store_type: StoreType,
        ls_bytes: Vec<u8>,
    ) -> Result<Self> {
        if !matches!(
            store_type,
            StoreType::LeaseSet
                | StoreType::LeaseSet2
                | StoreType::EncryptedLeaseSet2
                | StoreType::MetaLeaseSet2
        ) {
            return Err(I2PError::Malformed(
                "database_store: new_lease_set_typed с не-LeaseSet типом",
            ));
        }
        Ok(Self {
            key,
            store_type,
            reply_token: 0,
            reply_instruction: None,
            payload: ls_bytes,
        })
    }

    /// Пересобирает `DatabaseStore` из уже проверенных частей.
    ///
    /// Нужен ровно для пересылки дальше (i2pd `NetDb::Flood`: «zero
    /// reply token»): payload берётся как есть, без повторного
    /// сжатия/разбора, `reply_token` обнуляется. Поэтому функция
    /// `pub(crate)`: снаружи ею можно было бы собрать несогласованный
    /// `DatabaseStore`.
    #[must_use]
    pub(crate) const fn from_parts(
        key: IdentHash,
        store_type: StoreType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            key,
            store_type,
            reply_token: 0,
            reply_instruction: None,
            payload,
        }
    }

    /// Сырой payload (в wire-формате для данного `store_type`).
    #[must_use]
    pub fn payload_raw(&self) -> &[u8] {
        &self.payload
    }

    /// Раскодированный payload.
    ///
    /// Для `RouterInfo` — разжимает gzip и возвращает сырые байты RI.
    /// Для остальных типов — возвращает payload как есть.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] при провале gzip-декомпрессии (только
    /// для `RouterInfo`).
    pub fn payload_decoded(&self) -> Result<Vec<u8>> {
        match self.store_type {
            StoreType::RouterInfo => gzip::decompress(&self.payload),
            _ => Ok(self.payload.clone()),
        }
    }

    /// Размер payload'а в wire-формате.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload.len()
    }
}
