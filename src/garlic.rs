//! Garlic payload и cloves.
//!
//! После расшифровки I2NP `Garlic` body (ElGamal/AES или
//! ECIES-X25519-AEAD-Ratchet) получается **garlic payload** — список
//! cloves. Каждый clove содержит delivery instructions, I2NP message,
//! `CloveID`, expiration и certificate.
//!
//! **Важно**: этот модуль работает с **уже расшифрованным** payload'ом.
//! Сам I2NP `Garlic` body шифруется — это отдельный слой
//! (ECIES-ratchet или ElGamal/AES), здесь не реализован.
//!
//! ## Формат (по `Garlic.cpp`)
//!
//! ```text
//!   numCloves:  1 байт
//!   cloves:     numCloves * Clove
//! ```
//!
//! Clove:
//!
//! ```text
//!   flag:       1 байт
//!     bit 7:    encrypted clove (в i2pd закомментирован, мы даём Unsupported)
//!     bits 5-6: delivery type (0=Local, 1=Destination, 2=Tunnel, 3=Router)
//!     bits 0-4: не используются
//!   delivery:   зависит от delivery type
//!     Local:       0 байт
//!     Destination: 32 байта ident
//!     Tunnel:      32 байта gateway + 4 байта tunnelID (BE)
//!     Router:      32 байта router ident
//!   msg:        I2NP message (raw bytes, включая I2NP header)
//!   clove_id:   4 байта BE u32
//!   expiration: 8 байт BE u64, миллисекунды since epoch
//!   cert:       3 байта (обычно `[0, 0, 0]`)
//! ```
//!
//! ## Что не реализовано
//!
//! - encrypted clove (bit 7 flag = 1) — i2pd его тоже не реализует;
//! - certificate непустой (пока принимается как есть);
//! - шифрование garlic body — отдельный слой.

use crate::IdentHash;
use crate::endian::{read_u32_be, read_u64_be};
use crate::error::{I2PError, Result};
use crate::i2np_message::I2npMessage;

// --- Delivery ------------------------------------------------------------

/// Delivery instructions — куда доставить clove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Локально.
    Local,
    /// К конкретному destination'у.
    Destination(IdentHash),
    /// К входу в tunnel.
    Tunnel {
        /// Gateway-роутер.
        gateway: IdentHash,
        /// `TunnelID` на gateway.
        tunnel_id: u32,
    },
    /// К роутеру (по ident hash).
    Router(IdentHash),
}

impl Delivery {
    /// Байт-флаг delivery type (bits 5-6 без encrypted-bit).
    #[must_use]
    pub const fn flag(&self) -> u8 {
        match self {
            Self::Local => 0b000 << 5,
            Self::Destination(_) => 0b001 << 5,
            Self::Tunnel { .. } => 0b010 << 5,
            Self::Router(_) => 0b011 << 5,
        }
    }

    /// Размер delivery-суффикса в байтах (без флага).
    #[must_use]
    pub const fn suffix_len(&self) -> usize {
        match self {
            Self::Local => 0,
            Self::Destination(_) | Self::Router(_) => 32,
            Self::Tunnel { .. } => 36,
        }
    }
}

// --- GarlicClove ---------------------------------------------------------

/// Один clove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarlicClove {
    /// Куда доставить.
    pub delivery: Delivery,
    /// Сообщение.
    pub message: I2npMessage,
    /// Уникальный ID clove'а.
    pub clove_id: u32,
    /// Expiration в миллисекундах since epoch.
    pub expiration_ms: u64,
    /// Certificate (3 байта). Обычно `[0, 0, 0]`.
    pub certificate: [u8; 3],
}

impl GarlicClove {
    /// Конструктор с certificate по умолчанию (`[0, 0, 0]`).
    #[must_use]
    pub const fn new(
        delivery: Delivery,
        message: I2npMessage,
        clove_id: u32,
        expiration_ms: u64,
    ) -> Self {
        Self {
            delivery,
            message,
            clove_id,
            expiration_ms,
            certificate: [0, 0, 0],
        }
    }

    /// Сериализует clove в wire-формат (включая flag).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если сообщение не сериализуется.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let mut out =
            Vec::with_capacity(1 + self.delivery.suffix_len() + self.message.total_len() + 15);
        out.push(self.delivery.flag());
        match &self.delivery {
            Delivery::Local => {}
            Delivery::Destination(h) | Delivery::Router(h) => {
                out.extend_from_slice(h.as_bytes());
            }
            Delivery::Tunnel { gateway, tunnel_id } => {
                out.extend_from_slice(gateway.as_bytes());
                out.extend_from_slice(&tunnel_id.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.message.to_buffer()?);
        out.extend_from_slice(&self.clove_id.to_be_bytes());
        out.extend_from_slice(&self.expiration_ms.to_be_bytes());
        out.extend_from_slice(&self.certificate);
        Ok(out)
    }

    /// Парсит один clove, возвращает `(clove, consumed)`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — буфер короче ожидаемого;
    /// - [`Error::Malformed`] — I2NP внутри clove не парсится;
    /// - [`Error::Unsupported`] — encrypted clove (bit 7 flag).
    pub fn from_buffer(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(I2PError::InvalidLength {
                expected: 1,
                got: 0,
            });
        }
        let flag = buf[0];
        if flag & 0x80 != 0 {
            return Err(I2PError::Unsupported("garlic: encrypted clove"));
        }
        let delivery_type = (flag >> 5) & 0x03;
        let mut offset = 1;

        let delivery = match delivery_type {
            0 => Delivery::Local,
            1 => {
                if buf.len() < offset + 32 {
                    return Err(I2PError::InvalidLength {
                        expected: offset + 32,
                        got: buf.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&buf[offset..offset + 32]);
                offset += 32;
                Delivery::Destination(IdentHash::from_array(h))
            }
            2 => {
                if buf.len() < offset + 36 {
                    return Err(I2PError::InvalidLength {
                        expected: offset + 36,
                        got: buf.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&buf[offset..offset + 32]);
                offset += 32;
                let tunnel_id = read_u32_be(&buf[offset..]);
                offset += 4;
                Delivery::Tunnel {
                    gateway: IdentHash::from_array(h),
                    tunnel_id,
                }
            }
            3 => {
                if buf.len() < offset + 32 {
                    return Err(I2PError::InvalidLength {
                        expected: offset + 32,
                        got: buf.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&buf[offset..offset + 32]);
                offset += 32;
                Delivery::Router(IdentHash::from_array(h))
            }
            _ => unreachable!(),
        };

        let message = I2npMessage::from_buffer(&buf[offset..])?;
        offset += message.total_len();

        if buf.len() < offset + 15 {
            return Err(I2PError::InvalidLength {
                expected: offset + 15,
                got: buf.len(),
            });
        }
        let clove_id = read_u32_be(&buf[offset..]);
        offset += 4;
        let expiration_ms = read_u64_be(&buf[offset..]);
        offset += 8;
        let mut certificate = [0u8; 3];
        certificate.copy_from_slice(&buf[offset..offset + 3]);
        offset += 3;

        Ok((
            Self {
                delivery,
                message,
                clove_id,
                expiration_ms,
                certificate,
            },
            offset,
        ))
    }
}

// --- garlic payload ------------------------------------------------------

/// Парсит garlic payload (уже расшифрованный).
///
/// # Errors
///
/// - [`Error::InvalidLength`] — буфер короче ожидаемого;
/// - [`Error::Malformed`] — структурные проблемы;
/// - [`Error::Unsupported`] — encrypted clove.
pub fn parse_garlic_payload(buf: &[u8]) -> Result<Vec<GarlicClove>> {
    if buf.is_empty() {
        return Err(I2PError::InvalidLength {
            expected: 1,
            got: 0,
        });
    }
    let num_cloves = usize::from(buf[0]);
    let mut offset = 1;
    let mut cloves = Vec::with_capacity(num_cloves);
    for _ in 0..num_cloves {
        let (clove, consumed) = GarlicClove::from_buffer(&buf[offset..])?;
        cloves.push(clove);
        offset += consumed;
    }
    Ok(cloves)
}

/// Сериализует garlic payload.
///
/// # Errors
///
/// [`Error::Malformed`], если cloves больше 255.
pub fn serialize_garlic_payload(cloves: &[GarlicClove]) -> Result<Vec<u8>> {
    let num =
        u8::try_from(cloves.len()).map_err(|_| I2PError::Malformed("garlic: too many cloves"))?;
    let mut out = Vec::new();
    out.push(num);
    for clove in cloves {
        out.extend_from_slice(&clove.to_buffer()?);
    }
    Ok(out)
}
