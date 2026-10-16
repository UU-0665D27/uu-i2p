//! `PrivateKeys` — приватная пара (crypto + signing) для роутера
//! или destination'а.
//!
//! Хранит:
//!
//! - [`IdentityEx`] — публичная часть;
//! - `crypto_private` — приватный ключ шифрования;
//! - `signing_private` — приватный ключ подписи.
//!
//! Wire-формат — это ровно то, что лежит в `router.keys` / `*.dat`
//! у destination'ов в i2pd:
//!
//! ```text
//!   offset              size          field
//!   ------              ----          -----
//!        0        identity.full_len() identity (387 или 387+ext)
//!        ?      crypto_priv_len       crypto private key
//!        ?      signing_priv_len      signing private key
//! ```
//!
//! Длины приватных ключей зависят от типов:
//! - для ECIES-X25519 — 32 байта;
//! - для `EdDSA` — 32 байта (seed, из которого Ed25519 расширяется).
//!
//! ## Что поддерживается
//!
//! - **`EdDSA` + ECIES-X25519** — единственная комбинация.
//!
//! ## Что не поддерживается (пока)
//!
//! - DSA, ECDSA, GOST, RSA — нет signing-реализации;
//! - `ElGamal`, ECIES-P256, ML-KEM — нет crypto-реализации;
//! - offline-подписи (transient keys);
//! - b33 offline keys.
//!
//! Все неподдерживаемые типы → [`Error::Unsupported`].

use crate::{
    crypto::I2PX25519Keys,
    ed25519,
    error::{I2PError, Result},
    identity::IdentityEx,
    signature::{CryptoKeyType, SigningKeyType},
};

/// Приватные ключи роутера или destination'а.
#[derive(Debug)]
pub struct I2PPrivateKeys {
    public: IdentityEx,
    crypto_private: Vec<u8>,
    signing_private: Vec<u8>,
}

impl I2PPrivateKeys {
    /// Генерирует новую пару ключей заданных типов.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] для любой комбинации, кроме
    /// `EdDsaSha512Ed25519 + EciesX25519Aead`.
    pub fn generate(sig_type: SigningKeyType, crypto_type: CryptoKeyType) -> Result<Self> {
        // Пока поддерживается только EdDSA + ECIES-X25519.
        if sig_type != SigningKeyType::EdDsaSha512Ed25519 {
            return Err(I2PError::Unsupported(
                "private_keys: only EdDSA signing key is implemented",
            ));
        }
        if crypto_type != CryptoKeyType::EciesX25519Aead {
            return Err(I2PError::Unsupported(
                "private_keys: only ECIES-X25519 crypto key is implemented",
            ));
        }

        // Crypto: X25519
        let crypto_keys = I2PX25519Keys::generate();
        let crypto_private = crypto_keys.private_key();
        let crypto_public = *crypto_keys.public_key();

        // Signing: Ed25519
        let signing_signer = ed25519::I2PSigner::generate();
        let signing_private = signing_signer.private_key();
        let signing_public = signing_signer.public_key();

        let public = IdentityEx::new(&crypto_public, &signing_public, sig_type, crypto_type)?;

        Ok(Self {
            public,
            crypto_private: crypto_private.to_vec(),
            signing_private: signing_private.to_vec(),
        })
    }

    /// Комбинация по умолчанию: `EdDSA` + ECIES-X25519.
    ///
    /// # Errors
    ///
    /// См. [`Self::generate`] — на практике не падает.
    pub fn generate_default() -> Result<Self> {
        Self::generate(
            SigningKeyType::EdDsaSha512Ed25519,
            CryptoKeyType::EciesX25519Aead,
        )
    }

    /// Разбирает `PrivateKeys` из буфера.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] для неподдерживаемых типов;
    /// - [`Error::InvalidLength`], если буфер короче ожидаемого;
    /// - ошибки [`IdentityEx::from_buffer`].
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let public = IdentityEx::from_buffer(buf)?;
        let sig_type = public.signing_key_type()?;
        let crypto_type = public.crypto_key_type()?;

        if sig_type != SigningKeyType::EdDsaSha512Ed25519
            || crypto_type != CryptoKeyType::EciesX25519Aead
        {
            return Err(I2PError::Unsupported(
                "private_keys: only EdDSA + ECIES-X25519 is supported",
            ));
        }

        let mut offset = public.full_len();

        let crypto_priv_len = 32;
        if buf.len() < offset + crypto_priv_len {
            return Err(I2PError::InvalidLength {
                expected: offset + crypto_priv_len,
                got: buf.len(),
            });
        }
        let crypto_private = buf[offset..offset + crypto_priv_len].to_vec();
        offset += crypto_priv_len;

        let signing_priv_len = 32;
        if buf.len() < offset + signing_priv_len {
            return Err(I2PError::InvalidLength {
                expected: offset + signing_priv_len,
                got: buf.len(),
            });
        }
        let signing_private = buf[offset..offset + signing_priv_len].to_vec();

        Ok(Self {
            public,
            crypto_private,
            signing_private,
        })
    }

    /// Сериализует в wire-формат.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `public.to_buffer` не сойдётся.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let id_len = self.public.full_len();
        let mut id_buf = vec![0u8; id_len];
        self.public.to_buffer(&mut id_buf)?;

        let mut out = Vec::with_capacity(id_len + 64);
        out.extend_from_slice(&id_buf);
        out.extend_from_slice(&self.crypto_private);
        out.extend_from_slice(&self.signing_private);
        Ok(out)
    }

    /// Публичная часть (identity).
    #[must_use]
    pub const fn public(&self) -> &IdentityEx {
        &self.public
    }

    /// Приватный crypto key (сырые байты).
    #[must_use]
    pub fn crypto_private(&self) -> &[u8] {
        &self.crypto_private
    }

    /// Приватный signing key (сырые байты).
    #[must_use]
    pub fn signing_private(&self) -> &[u8] {
        &self.signing_private
    }

    /// Подписывает `data`, возвращает подпись (64 байта для `EdDSA`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если `signing_private` не 32 байта
    /// (не должно случиться для валидного `PrivateKeys`).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signer = ed25519::I2PSigner::from_private_key(&self.signing_private)?;
        Ok(signer.sign(data).to_vec())
    }

    /// Длина подписи в байтах (для `EdDSA` — 64).
    ///
    /// # Errors
    ///
    /// См. [`IdentityEx::signature_len`].
    pub fn signature_len(&self) -> Result<usize> {
        self.public.signature_len()
    }
}
