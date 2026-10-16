//! `Identity` — публичная идентичность роутера или destination.
//!
//! В I2P identity состоит из:
//!
//! - **encryption public key** (256 байт) — для приёма зашифрованных
//!   сообщений; реальный ключ лежит в начале, padding — в конце;
//! - **signing public key** (128 байт) — для проверки подписей;
//!   реальный ключ лежит в конце, padding — в начале;
//! - **certificate** (3 байта) — тип и длина extension.
//!
//! Всего 387 байт. Для DSA-SHA1 (`certificate_type = 0`) это полная
//! identity. Для остальных типов используется `IdentityEx`:
//! `certificate_type = CERTIFICATE_TYPE_KEY (5)`, следующие два байта —
//! длина extension (BE u16), сразу за 387 байтами идёт extension:
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     2  signing_key_type (BE u16)
//!        2     2  crypto_key_type  (BE u16)
//!        4     N  excess            (для P521 — 4 байта)
//! ```
//!
//! Хеш `IdentityEx` берётся от полной длины (387 + extension) — это и
//! есть `IdentHash`.
//!
//! ## Что реализовано
//!
//! - [`Identity`] (387 байт) — parse / serialize / hash;
//! - [`IdentityEx`] — parse / serialize с extension;
//! - accessors: `signing_key_type`, `crypto_key_type`, `signing_public_key`,
//!   `encryption_public_key`, `signature_len`;
//! - golden-тесты.
//!
//! ## Чего нет
//!
//! - verifier'ов и encryptor'ов (реальная криптография) — отдельный шаг;
//! - `PrivateKeys` и генерации ключей — отдельный шаг.

use crate::IdentHash;
use crate::endian::read_u16_be;
use crate::error::{I2PError, Result};
use crate::hash::I2PHash;
use crate::signature::{CryptoKeyType, SigningKeyType};

/// Размер стандартной `Identity` (без extension).
pub const DEFAULT_IDENTITY_SIZE: usize = 387;

/// Максимальный inline-размер extension `IdentityEx`.
///
/// 2 (signing key type) + 2 (crypto key type) + 4 (P521 excess) = 8.
pub const MAX_EXTENDED_BUFFER_SIZE: usize = 8;

/// Certificate type: NULL (используется по умолчанию для DSA-SHA1).
pub const CERTIFICATE_TYPE_NULL: u8 = 0;
/// Certificate type: KEY (расширенный формат `IdentityEx`).
pub const CERTIFICATE_TYPE_KEY: u8 = 5;

const PUBLIC_KEY_LEN: usize = 256;
const SIGNING_KEY_LEN: usize = 128;
const CERTIFICATE_LEN: usize = 3;

// --- Identity ------------------------------------------------------------

/// Стандартная `Identity` (387 байт).
///
/// Хранится как три поля, но сериализуется в один непрерывный блок.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// Encryption public key (256 байт).
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// Signing public key (128 байт).
    pub signing_key: [u8; SIGNING_KEY_LEN],
    /// Certificate: `[type, len_hi, len_lo]`.
    pub certificate: [u8; CERTIFICATE_LEN],
}

impl Identity {
    /// Размер стандартной `Identity` в байтах.
    pub const SIZE: usize = DEFAULT_IDENTITY_SIZE;

    /// Читает 387 байт из начала буфера.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если буфер короче 387 байт.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < DEFAULT_IDENTITY_SIZE {
            return Err(I2PError::InvalidLength {
                expected: DEFAULT_IDENTITY_SIZE,
                got: buf.len(),
            });
        }
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        let mut signing_key = [0u8; SIGNING_KEY_LEN];
        let mut certificate = [0u8; CERTIFICATE_LEN];
        public_key.copy_from_slice(&buf[0..PUBLIC_KEY_LEN]);
        signing_key.copy_from_slice(&buf[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + SIGNING_KEY_LEN]);
        certificate.copy_from_slice(&buf[PUBLIC_KEY_LEN + SIGNING_KEY_LEN..DEFAULT_IDENTITY_SIZE]);
        Ok(Self {
            public_key,
            signing_key,
            certificate,
        })
    }

    /// Пишет 387 байт в начало буфера.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если буфер короче 387 байт.
    pub fn to_buffer(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < DEFAULT_IDENTITY_SIZE {
            return Err(I2PError::InvalidLength {
                expected: DEFAULT_IDENTITY_SIZE,
                got: out.len(),
            });
        }
        out[0..PUBLIC_KEY_LEN].copy_from_slice(&self.public_key);
        out[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + SIGNING_KEY_LEN].copy_from_slice(&self.signing_key);
        out[PUBLIC_KEY_LEN + SIGNING_KEY_LEN..DEFAULT_IDENTITY_SIZE]
            .copy_from_slice(&self.certificate);
        Ok(())
    }

    /// Собирает 387-байтовый массив.
    #[must_use]
    pub fn to_array(&self) -> [u8; DEFAULT_IDENTITY_SIZE] {
        let mut buf = [0u8; DEFAULT_IDENTITY_SIZE];
        buf[0..PUBLIC_KEY_LEN].copy_from_slice(&self.public_key);
        buf[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + SIGNING_KEY_LEN].copy_from_slice(&self.signing_key);
        buf[PUBLIC_KEY_LEN + SIGNING_KEY_LEN..DEFAULT_IDENTITY_SIZE]
            .copy_from_slice(&self.certificate);
        buf
    }

    /// SHA256 от 387 байт → `IdentHash`.
    #[must_use]
    pub fn hash(&self) -> IdentHash {
        I2PHash::of(&self.to_array()).into()
    }

    /// Certificate type (`certificate[0]`).
    #[must_use]
    pub const fn certificate_type(&self) -> u8 {
        self.certificate[0]
    }

    /// Длина extension (BE u16 из `certificate[1..3]`).
    #[must_use]
    pub const fn extended_len(&self) -> u16 {
        u16::from_be_bytes([self.certificate[1], self.certificate[2]])
    }

    /// DSA-SHA1 (`certificate_type == 0`)?
    #[must_use]
    pub const fn is_legacy_dsa(&self) -> bool {
        self.certificate_type() == CERTIFICATE_TYPE_NULL
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Identity {{ cert={:?}, hash={} }}",
            self.certificate,
            self.hash().to_base64()
        )
    }
}

// --- IdentityEx ----------------------------------------------------------

/// Расширенная identity: `Identity` (387 байт) + extension.
///
/// Для DSA-SHA1 extension пуст, и `IdentityEx` эквивалентна `Identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEx {
    standard: Identity,
    extended: Vec<u8>,
    ident_hash: IdentHash,
}

impl IdentityEx {
    /// Разбирает identity из буфера.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если буфер короче 387 или 387 + `ext_len`.
    /// - [`Error::Malformed`], если `ext_len` > 0 при certificate type != KEY
    ///   или если `ext_len` < 4.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let standard = Identity::from_buffer(buf)?;
        let cert_type = standard.certificate_type();
        let ext_len = standard.extended_len() as usize;

        let extended = if ext_len == 0 {
            Vec::new()
        } else {
            if cert_type != CERTIFICATE_TYPE_KEY {
                return Err(I2PError::Malformed(
                    "non-zero extended length with non-KEY certificate",
                ));
            }
            if buf.len() < DEFAULT_IDENTITY_SIZE + ext_len {
                return Err(I2PError::InvalidLength {
                    expected: DEFAULT_IDENTITY_SIZE + ext_len,
                    got: buf.len(),
                });
            }
            if ext_len < 4 {
                return Err(I2PError::Malformed(
                    "extended part is too short for key types",
                ));
            }
            buf[DEFAULT_IDENTITY_SIZE..DEFAULT_IDENTITY_SIZE + ext_len].to_vec()
        };

        let ident_hash = if extended.is_empty() {
            standard.hash()
        } else {
            let mut full = Vec::with_capacity(DEFAULT_IDENTITY_SIZE + extended.len());
            full.extend_from_slice(&standard.to_array());
            full.extend_from_slice(&extended);
            I2PHash::of(&full).into()
        };

        Ok(Self {
            standard,
            extended,
            ident_hash,
        })
    }
    /// Собирает `IdentityEx` из сырых публичных ключей.
    ///
    /// Раскладка в standard (387 байт):
    /// - `public_key[..ek_len]` = encryption key (для X25519 — 32 байта);
    ///   остальное — padding (нули);
    /// - `signing_key[128-sk_len..]` = signing key (для `EdDSA` — 32 байта);
    ///   начало — padding (нули).
    ///
    /// i2pd использует **случайный** padding в этих местах, из-за
    /// чего один и тот же ключ даёт разный `IdentHash` при повторной
    /// генерации. Мы используем **нули** — детерминированно. На
    /// безопасность это не влияет: entropy идёт из самих ключей.
    ///
    /// Поле extended — 4 байта: `sig_type(2 BE) || crypto_type(2 BE)`.
    /// Для P521 нужен ext 8 байт (excess 4) — пока не поддерживается.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] — для DSA (legacy), P521 и любых
    ///   signing/crypto типов, где ключ не влезает в standard;
    /// - [`Error::UnknownSigningKeyType`] / [`Error::UnknownCryptoKeyType`];
    /// - [`Error::InvalidLength`], если буферы ключей короче ожидаемого.
    pub fn new(
        public_key: &[u8],
        signing_key: &[u8],
        sig_type: SigningKeyType,
        crypto_type: CryptoKeyType,
    ) -> Result<Self> {
        if sig_type.is_legacy_dsa() {
            return Err(I2PError::Unsupported(
                "identity: DSA construction is not implemented",
            ));
        }

        let ck_len = crypto_type
            .storage_public_key_len()
            .ok_or(I2PError::UnknownCryptoKeyType(crypto_type.as_u16()))?;
        let sk_len = sig_type
            .public_key_len()
            .ok_or(I2PError::UnknownSigningKeyType(sig_type.as_u16()))?;

        if ck_len > PUBLIC_KEY_LEN {
            return Err(I2PError::Unsupported(
                "identity: encryption key does not fit in 256-byte block",
            ));
        }
        if sk_len > SIGNING_KEY_LEN {
            return Err(I2PError::Unsupported(
                "identity: signing key does not fit in 128-byte block (P521 not supported)",
            ));
        }
        if public_key.len() < ck_len {
            return Err(I2PError::InvalidLength {
                expected: ck_len,
                got: public_key.len(),
            });
        }
        if signing_key.len() < sk_len {
            return Err(I2PError::InvalidLength {
                expected: sk_len,
                got: signing_key.len(),
            });
        }

        let mut standard = Identity {
            public_key: [0u8; PUBLIC_KEY_LEN],
            signing_key: [0u8; SIGNING_KEY_LEN],
            certificate: [0u8; CERTIFICATE_LEN],
        };
        // Encryption key: real at start, padding (zeros) at end
        standard.public_key[..ck_len].copy_from_slice(&public_key[..ck_len]);
        // Signing key: real at end, padding (zeros) at start
        let sk_offset = SIGNING_KEY_LEN - sk_len;
        standard.signing_key[sk_offset..].copy_from_slice(&signing_key[..sk_len]);

        // Certificate + extended (4 bytes: sig_type BE || crypto_type BE)
        standard.certificate[0] = CERTIFICATE_TYPE_KEY;
        standard.certificate[1] = 0;
        standard.certificate[2] = 4;
        let mut extended = vec![0u8; 4];
        extended[..2].copy_from_slice(&sig_type.as_u16().to_be_bytes());
        extended[2..].copy_from_slice(&crypto_type.as_u16().to_be_bytes());

        let mut full = standard.to_array().to_vec();
        full.extend_from_slice(&extended);
        let ident_hash: IdentHash = I2PHash::of(&full).into();

        Ok(Self {
            standard,
            extended,
            ident_hash,
        })
    }
    /// Пишет identity в буфер, возвращает полную длину.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если буфер меньше [`Self::full_len`].
    pub fn to_buffer(&self, out: &mut [u8]) -> Result<usize> {
        let full = self.full_len();
        if out.len() < full {
            return Err(I2PError::InvalidLength {
                expected: full,
                got: out.len(),
            });
        }
        self.standard.to_buffer(&mut out[..DEFAULT_IDENTITY_SIZE])?;
        out[DEFAULT_IDENTITY_SIZE..full].copy_from_slice(&self.extended);
        Ok(full)
    }

    /// Полная длина в байтах.
    #[must_use]
    pub const fn full_len(&self) -> usize {
        DEFAULT_IDENTITY_SIZE + self.extended.len()
    }

    /// Идентификационный хеш.
    #[must_use]
    pub const fn ident_hash(&self) -> &IdentHash {
        &self.ident_hash
    }

    /// Ссылка на стандартную часть.
    #[must_use]
    pub const fn standard(&self) -> &Identity {
        &self.standard
    }

    /// DSA-SHA1?
    #[must_use]
    pub const fn is_legacy_dsa(&self) -> bool {
        self.standard.is_legacy_dsa()
    }

    /// Тип signing key.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если extended короткий.
    /// - [`Error::UnknownSigningKeyType`], если тип не описан.
    pub fn signing_key_type(&self) -> Result<SigningKeyType> {
        if self.standard.is_legacy_dsa() {
            return Ok(SigningKeyType::DsaSha1);
        }
        if self.extended.len() < 2 {
            return Err(I2PError::Malformed(
                "extended part is too short for signing key type",
            ));
        }
        SigningKeyType::from_u16(read_u16_be(&self.extended[0..2]))
    }

    /// Тип crypto key.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если extended короткий.
    /// - [`Error::UnknownCryptoKeyType`], если тип не описан.
    pub fn crypto_key_type(&self) -> Result<CryptoKeyType> {
        if self.standard.is_legacy_dsa() {
            return Ok(CryptoKeyType::ElGamal);
        }
        if self.extended.len() < 4 {
            return Err(I2PError::Malformed(
                "extended part is too short for crypto key type",
            ));
        }
        CryptoKeyType::from_u16(read_u16_be(&self.extended[2..4]))
    }

    /// Длина signing public key (без padding).
    ///
    /// # Errors
    ///
    /// См. [`Self::signing_key_type`], плюс [`Error::UnknownSigningKeyType`]
    /// для RSA (не поддерживается в i2pd).
    pub fn signing_public_key_len(&self) -> Result<usize> {
        let skt = self.signing_key_type()?;
        skt.public_key_len()
            .ok_or(I2PError::UnknownSigningKeyType(skt.as_u16()))
    }

    /// Длина подписи.
    ///
    /// # Errors
    ///
    /// См. [`Self::signing_key_type`].
    pub fn signature_len(&self) -> Result<usize> {
        let skt = self.signing_key_type()?;
        skt.signature_len()
            .ok_or(I2PError::UnknownSigningKeyType(skt.as_u16()))
    }
    /// Проверяет подпись над `buf` публичным ключом из этой identity.
    ///
    /// Работает для `EdDsaSha512Ed25519` (type 7). Для остальных
    /// типов подписи возвращает [`Error::Unsupported`] — они будут
    /// добавлены отдельно (ECDSA, DSA, `RedDSA`).
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] — для типов подписи, которые ещё
    ///   не реализованы;
    /// - [`Error::Malformed`], если подпись не сходится или ключ
    ///   невалиден;
    /// - [`Error::InvalidLength`], если `signature` неверной длины.
    pub fn verify(&self, buf: &[u8], signature: &[u8]) -> Result<()> {
        let skt = self.signing_key_type()?;
        match skt {
            SigningKeyType::EdDsaSha512Ed25519 => {
                let key = self.signing_public_key()?;
                let verifier = crate::ed25519::I2PVerifier::new(&key)?;
                verifier.verify(buf, signature)
            }
            _ => Err(I2PError::Unsupported(
                "identity: unsupported signing key type",
            )),
        }
    }
    /// Signing public key без padding (копия).
    ///
    /// Для P521 ключ разорван между standard и extended — возвращает
    /// склеенный результат.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если extended не содержит достаточно байт.
    pub fn signing_public_key(&self) -> Result<Vec<u8>> {
        let len = self.signing_public_key_len()?;
        if len <= SIGNING_KEY_LEN {
            return Ok(self.standard.signing_key[SIGNING_KEY_LEN - len..].to_vec());
        }
        let excess_len = len - SIGNING_KEY_LEN;
        if self.extended.len() < 4 + excess_len {
            return Err(I2PError::Malformed(
                "extended part is too short for excess bytes",
            ));
        }
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&self.standard.signing_key);
        out.extend_from_slice(&self.extended[4..4 + excess_len]);
        Ok(out)
    }

    /// Signing public key без padding, если он целиком лежит в standard
    /// (то есть для всех типов, кроме P521).
    #[must_use]
    pub fn signing_public_key_buf(&self) -> Option<&[u8]> {
        let len = self.signing_public_key_len().ok()?;
        if len > SIGNING_KEY_LEN {
            return None;
        }
        Some(&self.standard.signing_key[SIGNING_KEY_LEN - len..])
    }

    /// Encryption public key: первые `storage_public_key_len` байт
    /// `standard.public_key`.
    ///
    /// # Errors
    ///
    /// См. [`Self::crypto_key_type`].
    pub fn encryption_public_key(&self) -> Result<&[u8]> {
        let ckt = self.crypto_key_type()?;
        let len = ckt
            .storage_public_key_len()
            .ok_or(I2PError::UnknownCryptoKeyType(ckt.as_u16()))?;
        Ok(&self.standard.public_key[..len])
    }

    /// Все 256 байт `public_key`, включая padding.
    #[must_use]
    pub const fn encryption_public_key_full(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.standard.public_key
    }
}
