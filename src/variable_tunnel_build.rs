//! Тело I2NP `VariableTunnelBuild` (type 23) и
//! `VariableTunnelBuildReply` (type 24) — ECIES-записи по 528 байт.
//!
//! Формат payload тот же, что у short-варианта
//! ([`crate::short_tunnel_build`]), но запись длиннее:
//!
//! ```text
//!   Payload:  num(1) | num * record(528)
//!   Record:   to_peer(16) | ephemeral(32) | ciphertext(480)
//! ```
//!
//! Правила разбора — как в i2pd: `num <= 8`, `len >= 1 + num * 528`,
//! хвост игнорируется.

use crate::error::{I2PError, Result};
use crate::tunnel_build_record::NUM_TUNNEL_BUILD_RECORDS;

/// Размер длинной ECIES-записи.
pub const TUNNEL_BUILD_RECORD_SIZE: usize = 528;
/// Размер `to_peer`.
pub const LONG_RECORD_TO_PEER_SIZE: usize = 16;
/// Размер эфемерного ключа.
pub const LONG_RECORD_EPHEMERAL_SIZE: usize = 32;
/// Размер шифртекста (464 clear text + 16 tag).
pub const LONG_RECORD_CIPHERTEXT_SIZE: usize = 480;

/// Зашифрованная длинная запись (528 байт).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedLongRecord {
    /// Первые 16 байт `IdentHash` хопа.
    pub to_peer: [u8; LONG_RECORD_TO_PEER_SIZE],
    /// Эфемерный X25519 public key.
    pub ephemeral_key: [u8; LONG_RECORD_EPHEMERAL_SIZE],
    /// Шифртекст с tag.
    pub ciphertext: [u8; LONG_RECORD_CIPHERTEXT_SIZE],
}

impl EncryptedLongRecord {
    /// Разбирает запись.
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если длина не 528.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != TUNNEL_BUILD_RECORD_SIZE {
            return Err(I2PError::InvalidLength {
                expected: TUNNEL_BUILD_RECORD_SIZE,
                got: buf.len(),
            });
        }
        let key_start = LONG_RECORD_TO_PEER_SIZE;
        let ct_start = key_start + LONG_RECORD_EPHEMERAL_SIZE;
        let mut to_peer = [0u8; LONG_RECORD_TO_PEER_SIZE];
        to_peer.copy_from_slice(&buf[..key_start]);
        let mut ephemeral_key = [0u8; LONG_RECORD_EPHEMERAL_SIZE];
        ephemeral_key.copy_from_slice(&buf[key_start..ct_start]);
        let mut ciphertext = [0u8; LONG_RECORD_CIPHERTEXT_SIZE];
        ciphertext.copy_from_slice(&buf[ct_start..]);
        Ok(Self {
            to_peer,
            ephemeral_key,
            ciphertext,
        })
    }

    /// Сериализует запись.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TUNNEL_BUILD_RECORD_SIZE] {
        let key_start = LONG_RECORD_TO_PEER_SIZE;
        let ct_start = key_start + LONG_RECORD_EPHEMERAL_SIZE;
        let mut out = [0u8; TUNNEL_BUILD_RECORD_SIZE];
        out[..key_start].copy_from_slice(&self.to_peer);
        out[key_start..ct_start].copy_from_slice(&self.ephemeral_key);
        out[ct_start..].copy_from_slice(&self.ciphertext);
        out
    }
}

/// Payload `VariableTunnelBuild` / `VariableTunnelBuildReply`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VariableTunnelBuildBody {
    /// Записи (не больше 8).
    pub records: Vec<EncryptedLongRecord>,
}

impl VariableTunnelBuildBody {
    /// Создаёт тело.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если записей больше 8.
    pub fn new(records: Vec<EncryptedLongRecord>) -> Result<Self> {
        if records.len() > NUM_TUNNEL_BUILD_RECORDS {
            return Err(I2PError::Malformed(
                "variable tunnel build: too many records",
            ));
        }
        Ok(Self { records })
    }

    /// Разбирает payload.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — пустой или слишком короткий буфер;
    /// - [`I2PError::Malformed`] — `num` больше 8.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let Some(&num) = buf.first() else {
            return Err(I2PError::InvalidLength {
                expected: 1,
                got: 0,
            });
        };
        let num = usize::from(num);
        if num > NUM_TUNNEL_BUILD_RECORDS {
            return Err(I2PError::Malformed(
                "variable tunnel build: too many records",
            ));
        }
        let expected = 1 + num * TUNNEL_BUILD_RECORD_SIZE;
        if buf.len() < expected {
            return Err(I2PError::InvalidLength {
                expected,
                got: buf.len(),
            });
        }
        let records = buf[1..expected]
            .as_chunks::<TUNNEL_BUILD_RECORD_SIZE>()
            .0
            .iter()
            .map(|chunk| EncryptedLongRecord::from_bytes(chunk))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { records })
    }

    /// Сериализует payload.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если записей больше 8.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        if self.records.len() > NUM_TUNNEL_BUILD_RECORDS {
            return Err(I2PError::Malformed(
                "variable tunnel build: too many records",
            ));
        }
        let mut out = Vec::with_capacity(self.wire_size());
        out.push(u8::try_from(self.records.len()).unwrap_or(u8::MAX));
        for rec in &self.records {
            out.extend_from_slice(&rec.to_bytes());
        }
        Ok(out)
    }

    /// Размер payload на wire.
    #[must_use]
    pub const fn wire_size(&self) -> usize {
        1 + self.records.len() * TUNNEL_BUILD_RECORD_SIZE
    }
}
