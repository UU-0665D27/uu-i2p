//! Обёртка над SHA256.
//!
//! Используется везде, где i2pd вызывает `SHA256()`:
//! - хеш `RouterIdentity` → `IdentHash`
//! - checksum туннельного сообщения
//! - payload hash внутри garlic-блока
//! - HKDF-info при построении ключей
//!
//! Отличие от [`Tag<32>`](crate::Tag) чисто семантическое:
//! `Hash` — это *результат хеширования*, `Tag<32>` — *произвольные 32 байта*.
//! Оба конвертируются друг в друга через `From`, но в коде сигнатуры
//! говорят сами за себя: `fn verify(ident: IdentHash, h: Hash)` читается
//! лучше, чем `fn verify(a: Tag<32>, b: Tag<32>)`.

use crate::{
    I2PTag, base32, base64,
    error::{I2PError, Result},
};
use sha2::{Digest, Sha256};
use std::fmt;

/// SHA256-хеш (32 байта).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct I2PHash(pub [u8; 32]);

impl I2PHash {
    /// Длина в байтах.
    pub const LEN: usize = 32;

    /// SHA256 от одного буфера.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    /// SHA256 от конкатенации нескольких буферов.
    ///
    /// Эквивалентно `Hash::of` от склеенного буфера, но без промежуточной
    /// аллокации. Совпадает с поведением `SHA256_Update(a); SHA256_Update(b)`
    /// из i2pd.
    #[must_use]
    pub fn of_concat(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    /// Ссылка на байты.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Все байты — нули?
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Base32-представление (lowercase, без padding).
    #[must_use]
    pub fn to_base32(&self) -> String {
        base32::encode(&self.0)
    }

    /// Base64-представление (I2P-алфавит, с padding).
    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }

    /// Парсит base32-строку.
    ///
    /// # Errors
    ///
    /// См. [`crate::Tag::from_base32`] — те же варианты.
    pub fn from_base32(s: &str) -> Result<Self> {
        base32::decode_to::<32>(s).map(Self)
    }

    /// Парсит base64-строку (с padding и без).
    ///
    /// # Errors
    ///
    /// См. [`crate::Tag::from_base64`] — те же варианты.
    pub fn from_base64(s: &str) -> Result<Self> {
        base64::decode_to::<32>(s).map(Self)
    }
}

// --- conversions ---------------------------------------------------------

impl From<[u8; 32]> for I2PHash {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<I2PHash> for [u8; 32] {
    fn from(h: I2PHash) -> Self {
        h.0
    }
}

impl AsRef<[u8]> for I2PHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for I2PHash {
    type Error = I2PError;

    fn try_from(s: &[u8]) -> Result<Self> {
        if s.len() != 32 {
            return Err(I2PError::InvalidLength {
                expected: 32,
                got: s.len(),
            });
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(s);
        Ok(Self(b))
    }
}

// --- Tag<32> <-> Hash ----------------------------------------------------
// Разные семантические роли, но один и тот же wire-формат.
// Конверсия бесплатна на уровне кода (memcpy 32 байт компилятор обычно
// оптимизирует).

impl From<I2PHash> for I2PTag<32> {
    fn from(h: I2PHash) -> Self {
        Self::from_array(h.0)
    }
}

impl From<I2PTag<32>> for I2PHash {
    fn from(t: I2PTag<32>) -> Self {
        Self(t.0)
    }
}

// --- display -------------------------------------------------------------

impl fmt::Debug for I2PHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_base64())
    }
}

impl fmt::Display for I2PHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}
