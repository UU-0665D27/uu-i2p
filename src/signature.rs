//! Типы signing-ключей и crypto-ключей I2P.
//!
//! Каждая `Identity` в I2P имеет два типа ключей:
//!
//! 1. **signing key type** (`u16`) — какой алгоритм подписи используется
//!    для `RouterInfo` / `LeaseSet` / garlic-clove. Значения `0..=11`.
//! 2. **crypto key type** (`u16`) — каким алгоритмом шифруются данные для
//!    этой identity. Значения `0..=7`.
//!
//! Оба — `u16` big-endian, оба хранятся в *certificate* поля `IdentityEx`
//! (см. `Identity.cpp` в i2pd), поэтому здесь только enum'ы без crypto.
//!
//! ## Что пока реализовано (шаг 1f)
//!
//! - [`SigningKeyType`] — 12 значений;
//! - [`CryptoKeyType`] — 8 значений;
//! - `from_u16` / `as_u16` / `name()` / `Display`;
//! - флаги «is_*» для удобства вызывающего кода.
//!
//! ## Что дальше
//!
//! - `Identity` и `IdentityEx` (структуры) — шаг 1g;
//! - реальный крипто-код (Ed25519, X25519, ML-KEM) — шаг 2.

use crate::error::{I2PError, Result};
use std::fmt;

// --- signing key types ---------------------------------------------------

/// Тип ключа подписи.
///
/// Числовые значения совпадают с `SIGNING_KEY_TYPE_*` в i2pd
/// (`Identity.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SigningKeyType {
    /// DSA с SHA1. Устаревший, но всё ещё используется в сети.
    DsaSha1 = 0,
    /// ECDSA на P-256 с SHA256.
    EcdsaSha256P256 = 1,
    /// ECDSA на P-384 с SHA384.
    EcdsaSha384P384 = 2,
    /// ECDSA на P-521 с SHA512.
    EcdsaSha512P521 = 3,
    /// RSA 2048 с SHA256. **Не поддерживается** в i2pd, только для парсинга.
    RsaSha256_2048 = 4,
    /// RSA 3072 с SHA384. **Не поддерживается**.
    RsaSha384_3072 = 5,
    /// RSA 4096 с SHA512. **Не поддерживается**.
    RsaSha512_4096 = 6,
    /// `EdDSA` на Ed25519. Основной тип для роутеров.
    EdDsaSha512Ed25519 = 7,
    /// `EdDSA` на Ed25519ph (prehash). С OpenSSL 3.0.
    EdDsaSha512Ed25519Ph = 8,
    /// ГОСТ Р 34.10-2012 (`CryptoPro` A) с ГОСТ Р 34.11-2012 256.
    GostR3410CryptoProA = 9,
    /// ГОСТ Р 34.10-2012 (TC26 A 512) с ГОСТ Р 34.11-2012 512.
    GostR3410Tc26A512 = 10,
    /// `RedDSA` на Ed25519. Только для `LeaseSet2`.
    RedDsaSha512Ed25519 = 11,
}

impl SigningKeyType {
    /// Все значения в порядке объявления — удобно для тестов и итерации.
    pub const ALL: [Self; 12] = [
        Self::DsaSha1,
        Self::EcdsaSha256P256,
        Self::EcdsaSha384P384,
        Self::EcdsaSha512P521,
        Self::RsaSha256_2048,
        Self::RsaSha384_3072,
        Self::RsaSha512_4096,
        Self::EdDsaSha512Ed25519,
        Self::EdDsaSha512Ed25519Ph,
        Self::GostR3410CryptoProA,
        Self::GostR3410Tc26A512,
        Self::RedDsaSha512Ed25519,
    ];

    /// Парсит `u16` из wire-формата.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSigningKeyType`], если значение не описано.
    pub const fn from_u16(v: u16) -> Result<Self> {
        Ok(match v {
            0 => Self::DsaSha1,
            1 => Self::EcdsaSha256P256,
            2 => Self::EcdsaSha384P384,
            3 => Self::EcdsaSha512P521,
            4 => Self::RsaSha256_2048,
            5 => Self::RsaSha384_3072,
            6 => Self::RsaSha512_4096,
            7 => Self::EdDsaSha512Ed25519,
            8 => Self::EdDsaSha512Ed25519Ph,
            9 => Self::GostR3410CryptoProA,
            10 => Self::GostR3410Tc26A512,
            11 => Self::RedDsaSha512Ed25519,
            _ => return Err(I2PError::UnknownSigningKeyType(v)),
        })
    }

    /// Числовое значение для wire-формата.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Человекочитаемое имя для логов (как в i2pd).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DsaSha1 => "DSA-SHA1",
            Self::EcdsaSha256P256 => "ECDSA-SHA256-P256",
            Self::EcdsaSha384P384 => "ECDSA-SHA384-P384",
            Self::EcdsaSha512P521 => "ECDSA-SHA512-P521",
            Self::RsaSha256_2048 => "RSA-SHA256-2048",
            Self::RsaSha384_3072 => "RSA-SHA384-3072",
            Self::RsaSha512_4096 => "RSA-SHA512-4096",
            Self::EdDsaSha512Ed25519 => "EdDSA-SHA512-Ed25519",
            Self::EdDsaSha512Ed25519Ph => "EdDSA-SHA512-Ed25519ph",
            Self::GostR3410CryptoProA => "GOSTR3410-CryptoPro-A",
            Self::GostR3410Tc26A512 => "GOSTR3410-TC26-A-512",
            Self::RedDsaSha512Ed25519 => "RedDSA-SHA512-Ed25519",
        }
    }

    /// DSA-SHA1 — единственный тип, для которого `Identity` **не** использует
    /// certificate (т.е. «стандартный» формат 387 байт без extension).
    #[must_use]
    pub const fn is_legacy_dsa(self) -> bool {
        matches!(self, Self::DsaSha1)
    }

    /// RSA. i2pd **не поддерживает** генерацию/подпись, только парсинг.
    #[must_use]
    pub const fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::RsaSha256_2048 | Self::RsaSha384_3072 | Self::RsaSha512_4096
        )
    }

    /// Может быть использован как offline-подпись (transient key).
    #[must_use]
    pub const fn is_blindable(self) -> bool {
        matches!(self, Self::EdDsaSha512Ed25519 | Self::RedDsaSha512Ed25519)
    }
    /// Длина signing public key без padding.
    ///
    /// `None` для RSA — i2pd не поддерживает этот тип при парсинге.
    #[must_use]
    pub const fn public_key_len(self) -> Option<usize> {
        Some(match self {
            Self::DsaSha1 | Self::GostR3410Tc26A512 => 128,
            Self::EcdsaSha256P256 | Self::GostR3410CryptoProA => 64,
            Self::EcdsaSha384P384 => 96,
            Self::EcdsaSha512P521 => 132,
            Self::RsaSha256_2048 | Self::RsaSha384_3072 | Self::RsaSha512_4096 => return None,
            Self::EdDsaSha512Ed25519 | Self::EdDsaSha512Ed25519Ph | Self::RedDsaSha512Ed25519 => 32,
        })
    }

    /// Длина подписи.
    #[must_use]
    pub const fn signature_len(self) -> Option<usize> {
        Some(match self {
            Self::DsaSha1 => 40,
            Self::EcdsaSha256P256
            | Self::EdDsaSha512Ed25519
            | Self::EdDsaSha512Ed25519Ph
            | Self::RedDsaSha512Ed25519
            | Self::GostR3410CryptoProA => 64,
            Self::EcdsaSha384P384 => 96,
            Self::EcdsaSha512P521 => 132,
            Self::RsaSha256_2048 => 256,
            Self::RsaSha384_3072 => 384,
            Self::RsaSha512_4096 => 512,
            Self::GostR3410Tc26A512 => 128,
        })
    }

    /// Длина signing private key.
    ///
    /// Для всех типов, кроме DSA, равна `signature_len / 2`. Для DSA
    /// совпадает: `40/2 = 20`.
    #[must_use]
    pub const fn private_key_len(self) -> Option<usize> {
        match self.signature_len() {
            Some(n) => Some(n / 2),
            None => None,
        }
    }
}

impl fmt::Display for SigningKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// --- crypto key types ----------------------------------------------------

/// Тип ключа шифрования.
///
/// Числовые значения совпадают с `CRYPTO_KEY_TYPE_*` в i2pd (`Identity.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CryptoKeyType {
    /// `ElGamal` 2048. Устаревший.
    ElGamal = 0,
    /// ECIES на P-256 с SHA256 и AES-256-CBC.
    EciesP256Sha256Aes256Cbc = 1,
    /// ECIES на X25519 с AEAD-ChaCha20-Poly1305. Основной тип.
    EciesX25519Aead = 4,
    /// Гибрид ML-KEM-512 + X25519.
    EciesMlKem512X25519Aead = 5,
    /// Гибрид ML-KEM-768 + X25519.
    EciesMlKem768X25519Aead = 6,
    /// Гибрид ML-KEM-1024 + X25519.
    EciesMlKem1024X25519Aead = 7,
}

impl CryptoKeyType {
    /// Все значения в порядке объявления.
    pub const ALL: [Self; 6] = [
        Self::ElGamal,
        Self::EciesP256Sha256Aes256Cbc,
        Self::EciesX25519Aead,
        Self::EciesMlKem512X25519Aead,
        Self::EciesMlKem768X25519Aead,
        Self::EciesMlKem1024X25519Aead,
    ];

    /// Парсит `u16` из wire-формата.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownCryptoKeyType`], если значение не описано.
    pub const fn from_u16(v: u16) -> Result<Self> {
        Ok(match v {
            0 => Self::ElGamal,
            1 => Self::EciesP256Sha256Aes256Cbc,
            4 => Self::EciesX25519Aead,
            5 => Self::EciesMlKem512X25519Aead,
            6 => Self::EciesMlKem768X25519Aead,
            7 => Self::EciesMlKem1024X25519Aead,
            _ => return Err(I2PError::UnknownCryptoKeyType(v)),
        })
    }

    /// Числовое значение для wire-формата.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Человекочитаемое имя.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ElGamal => "ElGamal",
            Self::EciesP256Sha256Aes256Cbc => "ECIES-P256-AES256CBC",
            Self::EciesX25519Aead => "ECIES-X25519-AEAD",
            Self::EciesMlKem512X25519Aead => "ECIES-MLKEM512-X25519-AEAD",
            Self::EciesMlKem768X25519Aead => "ECIES-MLKEM768-X25519-AEAD",
            Self::EciesMlKem1024X25519Aead => "ECIES-MLKEM1024-X25519-AEAD",
        }
    }

    /// Поддерживает ли этот тип ECIES-X25519-AEAD-Ratchet (ratchets).
    ///
    /// Возвращает `true` для типов 4, 5, 6, 7.
    #[must_use]
    pub const fn supports_ratchets(self) -> bool {
        !matches!(self, Self::ElGamal | Self::EciesP256Sha256Aes256Cbc)
    }

    /// Гибрид ML-KEM (post-quantum).
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self,
            Self::EciesMlKem512X25519Aead
                | Self::EciesMlKem768X25519Aead
                | Self::EciesMlKem1024X25519Aead
        )
    }

    /// Уровень ML-KEM (только для PQ-типов). `None` для non-PQ.
    #[must_use]
    pub const fn ml_kem_level(self) -> Option<u16> {
        match self {
            Self::EciesMlKem512X25519Aead => Some(512),
            Self::EciesMlKem768X25519Aead => Some(768),
            Self::EciesMlKem1024X25519Aead => Some(1024),
            _ => None,
        }
    }
    /// Длина public key в `Identity.public_key` (с padding).
    ///
    /// Совпадает с `GetCryptoPublicKeyLen` в i2pd: 256 для `ElGamal` и
    /// ECIES-P256 (для совместимости со старыми файлами ключей),
    /// 32 для ECIES-X25519 и ML-KEM.
    #[must_use]
    pub const fn storage_public_key_len(self) -> Option<usize> {
        Some(match self {
            Self::ElGamal | Self::EciesP256Sha256Aes256Cbc => 256,
            Self::EciesX25519Aead
            | Self::EciesMlKem512X25519Aead
            | Self::EciesMlKem768X25519Aead
            | Self::EciesMlKem1024X25519Aead => 32,
        })
    }

    /// Длина private key в файле ключей.
    #[must_use]
    pub const fn storage_private_key_len(self) -> Option<usize> {
        Some(match self {
            Self::ElGamal | Self::EciesP256Sha256Aes256Cbc => 256,
            Self::EciesX25519Aead
            | Self::EciesMlKem512X25519Aead
            | Self::EciesMlKem768X25519Aead
            | Self::EciesMlKem1024X25519Aead => 32,
        })
    }
}

impl fmt::Display for CryptoKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
