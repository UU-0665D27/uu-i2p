//! `Tag<N>` — обёртка над массивом фиксированной длины.
//!
//! Зачем отдельный тип вместо `[u8; N]`:
//! - нельзя случайно перепутать `IdentHash` (32) и `AesKey` (32) — разные типы;
//! - методы `is_zero`, `random`, `from_slice` собраны в одном месте;
//! - будущие кодировки (`to_base64` / `to_base32`) добавляются только сюда.

use crate::{
    base32, base64,
    error::{I2PError, Result},
};
use rand::RngCore;
use std::fmt;

/// Массив из ровно `N` байт.
///
/// Гарантии:
/// - `Tag<N>` всегда содержит ровно `N` байт (это следует из типа);
/// - `from_slice` возвращает `None`, если длина не совпадает;
/// - `random` заполняет все `N` байт из `rng`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct I2PTag<const N: usize>(pub [u8; N]);

impl<const N: usize> I2PTag<N> {
    /// Длина в байтах. Компилируется в константу.
    pub const LEN: usize = N;

    /// Base32-представление (lowercase, без padding).
    #[must_use]
    pub fn to_base32(&self) -> String {
        base32::encode(&self.0)
    }

    /// Base64-представление (с padding `=`, I2P-алфавит).
    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }

    /// Парсит base32-строку.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBase32`] — недопустимый символ.
    /// - [`Error::NonCanonical`] — значащие биты в хвосте.
    /// - [`Error::InvalidLength`] — длина результата не равна `N`.
    pub fn from_base32(s: &str) -> Result<Self> {
        base32::decode_to::<N>(s).map(Self)
    }

    /// Парсит base64-строку (с padding и без).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBase64`] — недопустимый символ.
    /// - [`Error::NonCanonical`] — неверная длина или значащие биты в хвосте.
    /// - [`Error::InvalidLength`] — длина результата не равна `N`.
    pub fn from_base64(s: &str) -> Result<Self> {
        base64::decode_to::<N>(s).map(Self)
    }
    /// Конструктор из массива. Не может провалиться.
    #[must_use]
    pub const fn from_array(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Конструктор из среза. Возвращает `None`, если длина не `N`.
    #[must_use]
    pub const fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() != N {
            return None;
        }
        let mut b = [0u8; N];
        // const-совместимая альтернатива `copy_from_slice`
        let mut i = 0;
        while i < N {
            b[i] = s[i];
            i += 1;
        }
        Some(Self(b))
    }

    /// Ссылка на массив внутри.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Ссылка на байты как срез.
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Все байты — нули?
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Заполнить случайными байтами из `rng`.
    #[must_use]
    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut b = [0u8; N];
        rng.fill_bytes(&mut b);
        Self(b)
    }
}

// --- conversions ---------------------------------------------------------

impl<const N: usize> From<[u8; N]> for I2PTag<N> {
    fn from(b: [u8; N]) -> Self {
        Self(b)
    }
}

impl<const N: usize> From<I2PTag<N>> for [u8; N] {
    fn from(t: I2PTag<N>) -> Self {
        t.0
    }
}

impl<const N: usize> AsRef<[u8]> for I2PTag<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// --- display -------------------------------------------------------------

impl<const N: usize> fmt::Debug for I2PTag<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag<{N}>(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

// --- fallible conversion -------------------------------------------------

impl<const N: usize> TryFrom<&[u8]> for I2PTag<N> {
    type Error = I2PError;

    fn try_from(s: &[u8]) -> Result<Self> {
        Self::from_slice(s).ok_or(I2PError::InvalidLength {
            expected: N,
            got: s.len(),
        })
    }
}

// --- type aliases --------------------------------------------------------

/// 32-байтовый идентификатор (хеш `RouterIdentity` / `Destination`).
pub type IdentHash = I2PTag<32>;

/// 32-байтовый ключ AES-256.
pub type I2PAesKey = I2PTag<32>;

/// 32-байтовый session tag (для garlic-шифрования).
pub type SessionTag = I2PTag<32>;
