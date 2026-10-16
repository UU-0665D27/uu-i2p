//! Тела I2NP-сообщений уровня туннелей: `TunnelData` (type 18),
//! `TunnelGateway` (type 19) и `TunnelTest` (type 231).
//!
//! Только wire-формат; шифрование слоя и фрагментация — отдельно.
//!
//! ## `TunnelData` (1028 байт, фиксированный размер)
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     4  tunnel_id  (BE u32)
//!        4    16  iv
//!       20  1008  encrypted data
//! ```
//!
//! ## `TunnelGateway` (6 байт заголовка + данные)
//!
//! ```text
//!        0     4  tunnel_id  (BE u32)
//!        4     2  length     (BE u16)
//!        6   len  data       (вложенное I2NP-сообщение с заголовком)
//! ```
//!
//! Как в i2pd (`Tunnels::HandleTunnelGatewayMsg`), `length` не должен
//! превышать число оставшихся байт; хвост сверх `length` игнорируется.
//!
//! ## `TunnelTest` (12 байт)
//!
//! ```text
//!        0     4  msg_id     (BE u32)
//!        4     8  timestamp  (BE u64)
//! ```
//!
//! i2pd пишет в `timestamp` монотонное время в микросекундах;
//! получатель сверяет его со своими часами, поэтому здесь это
//! просто `u64`.

use crate::endian::{
    read_u16_be, read_u32_be, read_u64_be, write_u16_be, write_u32_be, write_u64_be,
};
use crate::error::{I2PError, Result};

/// Размер `TunnelData`.
pub const TUNNEL_DATA_MSG_SIZE: usize = 1028;
/// Размер IV в `TunnelData`.
pub const TUNNEL_DATA_IV_SIZE: usize = 16;
/// Размер зашифрованных данных в `TunnelData`.
pub const TUNNEL_DATA_ENCRYPTED_SIZE: usize = 1008;
/// Размер заголовка `TunnelGateway`.
pub const TUNNEL_GATEWAY_HEADER_SIZE: usize = 6;
/// Размер `TunnelTest`.
pub const TUNNEL_TEST_SIZE: usize = 12;

// --- TunnelData -------------------------------------------------------------

/// Тело `TunnelData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelDataBody {
    /// Tunnel ID получателя.
    pub tunnel_id: u32,
    /// IV слоя.
    pub iv: [u8; TUNNEL_DATA_IV_SIZE],
    /// Зашифрованные данные (в `Box`, чтобы не раздувать enum-ы).
    pub encrypted: Box<[u8; TUNNEL_DATA_ENCRYPTED_SIZE]>,
}

impl TunnelDataBody {
    /// Разбирает payload. Хвост игнорируется.
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если буфер короче 1028 байт.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < TUNNEL_DATA_MSG_SIZE {
            return Err(I2PError::InvalidLength {
                expected: TUNNEL_DATA_MSG_SIZE,
                got: buf.len(),
            });
        }
        let mut iv = [0u8; TUNNEL_DATA_IV_SIZE];
        iv.copy_from_slice(&buf[4..4 + TUNNEL_DATA_IV_SIZE]);
        let mut encrypted = Box::new([0u8; TUNNEL_DATA_ENCRYPTED_SIZE]);
        encrypted.copy_from_slice(&buf[4 + TUNNEL_DATA_IV_SIZE..TUNNEL_DATA_MSG_SIZE]);
        Ok(Self {
            tunnel_id: read_u32_be(buf),
            iv,
            encrypted,
        })
    }

    /// Сериализует payload (1028 байт).
    #[must_use]
    pub fn to_buffer(&self) -> Vec<u8> {
        let mut out = vec![0u8; TUNNEL_DATA_MSG_SIZE];
        write_u32_be(&mut out, self.tunnel_id);
        out[4..4 + TUNNEL_DATA_IV_SIZE].copy_from_slice(&self.iv);
        out[4 + TUNNEL_DATA_IV_SIZE..].copy_from_slice(&*self.encrypted);
        out
    }
}

// --- TunnelGateway ----------------------------------------------------------

/// Тело `TunnelGateway`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelGatewayBody {
    /// Tunnel ID gateway'я.
    pub tunnel_id: u32,
    /// Вложенное I2NP-сообщение (с заголовком), байты как есть.
    pub data: Vec<u8>,
}

impl TunnelGatewayBody {
    /// Разбирает payload; байты сверх `length` игнорируются.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — буфер короче заголовка;
    /// - [`I2PError::Malformed`] — `length` больше оставшихся байт.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < TUNNEL_GATEWAY_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: TUNNEL_GATEWAY_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let len = usize::from(read_u16_be(&buf[4..]));
        let data = buf[TUNNEL_GATEWAY_HEADER_SIZE..]
            .get(..len)
            .ok_or(I2PError::Malformed(
                "tunnel gateway: length exceeds payload",
            ))?;
        Ok(Self {
            tunnel_id: read_u32_be(buf),
            data: data.to_vec(),
        })
    }

    /// Сериализует payload.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если `data.len() > u16::MAX`.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let len = u16::try_from(self.data.len())
            .map_err(|_| I2PError::Malformed("tunnel gateway: data > 64KB"))?;
        let mut out = vec![0u8; TUNNEL_GATEWAY_HEADER_SIZE + self.data.len()];
        write_u32_be(&mut out, self.tunnel_id);
        write_u16_be(&mut out[4..], len);
        out[TUNNEL_GATEWAY_HEADER_SIZE..].copy_from_slice(&self.data);
        Ok(out)
    }
}

// --- TunnelTest -------------------------------------------------------------

/// Тело `TunnelTest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelTestBody {
    /// ID теста.
    pub msg_id: u32,
    /// Метка времени (i2pd: монотонные микросекунды).
    pub timestamp: u64,
}

impl TunnelTestBody {
    /// Разбирает payload. Хвост игнорируется.
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если буфер короче 12 байт.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < TUNNEL_TEST_SIZE {
            return Err(I2PError::InvalidLength {
                expected: TUNNEL_TEST_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            msg_id: read_u32_be(buf),
            timestamp: read_u64_be(&buf[4..]),
        })
    }

    /// Сериализует payload (12 байт).
    #[must_use]
    pub fn to_buffer(&self) -> [u8; TUNNEL_TEST_SIZE] {
        let mut out = [0u8; TUNNEL_TEST_SIZE];
        write_u32_be(&mut out, self.msg_id);
        write_u64_be(&mut out[4..], self.timestamp);
        out
    }
}
