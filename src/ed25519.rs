//! Ed25519 — подписи для I2P-роутеров.
//!
//! `SigningKeyType::EdDsaSha512Ed25519` (type 7) — основной тип подписи
//! в современной сети. Реализован поверх `ed25519-dalek` (`RustCrypto`),
//! без системного OpenSSL.
//!
//! ## Формат ключей
//!
//! - публичный: 32 байта (RFC 8032);
//! - приватный (seed): 32 байта (из него выводится расширенный ключ);
//! - подпись: 64 байта.
//!
//! ## Что внутри
//!
//! - [`Verifier`] — проверка подписи по публичному ключу;
//! - [`Signer`] — подпись приватным ключом.
//!
//! ## Что не внутри
//!
//! - Ed25519ph (prehash, type 8) — редкий вариант, добавим при
//!   необходимости;
//! - `RedDSA` (type 11) — используется только в blinded `LeaseSet2`,
//!   отдельный модуль.

use ed25519_dalek::Verifier as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::error::{I2PError, Result};

/// Размер публичного ключа Ed25519 в байтах.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Размер приватного ключа (seed) Ed25519 в байтах.
pub const PRIVATE_KEY_LEN: usize = 32;

/// Размер подписи Ed25519 в байтах.
pub const SIGNATURE_LEN: usize = 64;

/// Верификатор Ed25519.
///
/// Хранит только публичный ключ. Проверка — без секретов,
/// безопасна в любом потоке.
#[derive(Debug, Clone)]
pub struct I2PVerifier {
    inner: VerifyingKey,
}

impl I2PVerifier {
    /// Создаёт верификатор из публичного ключа (32 байта).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если `public_key.len() != 32`.
    /// [`Error::Malformed`], если байты не являются валидной точкой
    /// Ed25519 (проверяется `ed25519-dalek`).
    pub fn new(public_key: &[u8]) -> Result<Self> {
        let bytes: [u8; PUBLIC_KEY_LEN] =
            public_key.try_into().map_err(|_| I2PError::InvalidLength {
                expected: PUBLIC_KEY_LEN,
                got: public_key.len(),
            })?;
        let vk = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| I2PError::Malformed("ed25519: invalid public key"))?;
        Ok(Self { inner: vk })
    }

    /// Публичный ключ как 32-байтовый массив.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Проверяет подпись над сообщением.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если `signature.len() != 64`.
    /// [`Error::Malformed`], если подпись не сходится.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        let sig_bytes: [u8; SIGNATURE_LEN] =
            signature.try_into().map_err(|_| I2PError::InvalidLength {
                expected: SIGNATURE_LEN,
                got: signature.len(),
            })?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.inner
            .verify(msg, &sig)
            .map_err(|_| I2PError::Malformed("ed25519: signature verification failed"))
    }

    /// `true`, если подпись валидна. Никогда не паникует.
    #[must_use]
    pub fn is_valid(&self, msg: &[u8], signature: &[u8]) -> bool {
        self.verify(msg, signature).is_ok()
    }
}

/// Подписыватель Ed25519.
///
/// Хранит приватный ключ. `SigningKey` из `ed25519-dalek` затирает
/// себя при drop'е.
#[derive(Debug)]
pub struct I2PSigner {
    inner: SigningKey,
}

impl I2PSigner {
    /// Создаёт подписыватель из приватного ключа (seed, 32 байта).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если `private_key.len() != 32`.
    pub fn from_private_key(private_key: &[u8]) -> Result<Self> {
        let bytes: [u8; PRIVATE_KEY_LEN] =
            private_key
                .try_into()
                .map_err(|_| I2PError::InvalidLength {
                    expected: PRIVATE_KEY_LEN,
                    got: private_key.len(),
                })?;
        Ok(Self {
            inner: SigningKey::from_bytes(&bytes),
        })
    }

    /// Создаёт подписыватель из 32-байтового seed'а.
    ///
    /// Синоним [`Self::from_private_key`], назван так, чтобы
    /// подчеркнуть, что это seed, а не расширенный ключ.
    ///
    /// # Errors
    ///
    /// См. [`Self::from_private_key`].
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        Self::from_private_key(seed)
    }

    /// Генерирует новый случайный ключ.
    #[must_use]
    pub fn generate() -> Self {
        // `SigningKey::from_bytes` принимает seed, а `rand 0.8`
        // даёт `fill_bytes`. Так мы не тянем `rand_core` отдельно.
        let mut seed = [0u8; PRIVATE_KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        Self {
            inner: SigningKey::from_bytes(&seed),
        }
    }

    /// Публичный ключ (32 байта).
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.inner.verifying_key().to_bytes()
    }

    /// Приватный ключ (seed, 32 байта).
    #[must_use]
    pub fn private_key(&self) -> [u8; PRIVATE_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Подписывает сообщение. Подпись — 64 байта.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.inner.sign(msg).to_bytes()
    }

    /// Верификатор, соответствующий этому ключу.
    #[must_use]
    pub fn verifier(&self) -> I2PVerifier {
        I2PVerifier {
            inner: self.inner.verifying_key(),
        }
    }
}
