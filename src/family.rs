//! «Семейства» роутеров — доверенные группы с общим ECDSA-ключом.
//!
//! Владелец семейства генерирует ECDSA P-256 пару. Публичный ключ
//! публикуется (обычно через X509-сертификат с CN = `<name>.family`),
//! приватным владелец подписывает `(family_name || ident_hash)` каждого
//! роутера, вступающего в семейство. Роутер кладёт в свой
//! `RouterInfo` два property: `family` (имя) и `family.sig` (base64
//! от подписи).
//!
//! При выборе пиров для туннеля роутер может не ставить в один
//! туннель двух членов одного семейства — так операторы страхуются
//! от коррелированных отказов.
//!
//! Соответствует `Families` из `Family.cpp` / `Family.h`.
//!
//! ## Что реализовано
//!
//! - [`Families`] — реестр «имя → (публичный ключ, id)»;
//! - [`FamilyKey`] — обёртка над SEC1-байтами P-256 публичного ключа;
//! - [`create_family_signature`] — подпись владельца семейства.
//!
//! ## Что НЕ реализовано
//!
//! - загрузка `.crt` из файловой системы (каталог `certificates/family/`):
//!   это работа слоя `fs` + X509-парсера, а не этого модуля. Caller
//!   сам достаёт публичный ключ из сертификата и вызывает
//!   [`FamilyKey::from_sec1`].
//! - `LoadCertificate` через `SSL_CTX` — не тащим OpenSSL в дерево
//!   зависимостей.

use crate::{
    IdentHash, base64,
    error::{I2PError, Result},
};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use std::collections::HashMap;

/// Идентификатор семейства. `0` означает «нет семейства / не найдено».
///
/// Так же, как `FamilyID` в i2pd: нулевой id зарезервирован под
/// «invalid», реальные id начинаются с 1.
pub type FamilyId = i32;

/// Максимальная длина имени семейства.
///
/// i2pd: `family.length () + 32 <= 100` → `family.length () <= 68`.
pub const MAX_FAMILY_NAME_LEN: usize = 68;

// --- FamilyKey -----------------------------------------------------------

/// Публичный ключ семейства — ECDSA P-256, в SEC1-кодировке.
///
/// Принимаем как uncompressed (`0x04 || X(32) || Y(32)`, 65 байт),
/// так и compressed (`0x02/0x03 || X(32)`, 33 байта) — обе формы
/// валидны и `p256` их разбирает.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyKey {
    /// Сырые SEC1-байты (33 или 65).
    bytes: Vec<u8>,
}

impl FamilyKey {
    /// Создаёт ключ из SEC1-байтов.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] — байты не являются валидной точкой P-256
    /// (неверная длина, X/Y вне поля, точка не на кривой).
    pub fn from_sec1(bytes: &[u8]) -> Result<Self> {
        // Проверяем, что `p256` реально принимает эти байты:
        // иначе ошибка всплыла бы при первом `verify`, что гораздо
        // хуже — ключ должен быть валиден уже при регистрации.
        VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| I2PError::Malformed("family: invalid P-256 public key"))?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Сырые SEC1-байты.
    #[must_use]
    pub fn as_sec1(&self) -> &[u8] {
        &self.bytes
    }

    /// Внутренний разбор в `VerifyingKey`. `from_sec1` уже проверил,
    /// что байты валидны, так что здесь ошибка — индикатор бага.
    fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(&self.bytes)
            .map_err(|_| I2PError::Malformed("family: invalid P-256 public key"))
    }
}

// --- Families ------------------------------------------------------------

/// Реестр доверенных семейств.
///
/// Имена хранятся в lowercase. Дубликат имени — ошибка (в i2pd тоже
/// так: `emplace` вернёт `false`, и запись не добавится).
#[derive(Debug, Default)]
pub struct Families {
    keys: HashMap<String, (FamilyKey, FamilyId)>,
    next_id: FamilyId,
}

impl Families {
    /// Пустой реестр.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            next_id: 1, // 0 зарезервирован под «не найдено»
        }
    }

    /// Число зарегистрированных семейств.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Реестр пуст?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Регистрирует семейство, возвращает присвоенный id (≥ 1).
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — имя пустое или длиннее
    ///   [`MAX_FAMILY_NAME_LEN`];
    /// - [`Error::Malformed`] — семейство с таким именем уже есть
    ///   (регистр не важен).
    pub fn insert(&mut self, family: &str, key: FamilyKey) -> Result<FamilyId> {
        let name = family.to_lowercase();
        if name.is_empty() {
            return Err(I2PError::Malformed("family: empty name"));
        }
        if name.len() > MAX_FAMILY_NAME_LEN {
            return Err(I2PError::Malformed("family: name too long"));
        }
        if self.keys.contains_key(&name) {
            return Err(I2PError::Malformed("family: duplicate name"));
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(I2PError::Malformed("family: id overflow"))?;
        self.keys.insert(name, (key, id));
        Ok(id)
    }

    /// Id семейства или `0`, если такого нет.
    #[must_use]
    pub fn get_id(&self, family: &str) -> FamilyId {
        let name = family.to_lowercase();
        self.keys.get(&name).map_or(0, |(_, id)| *id)
    }

    /// Проверяет подпись `(family || ident)` публичным ключом семейства.
    ///
    /// `signature` — 64 байта, `r || s` в big-endian (то же, что
    /// `ECDSA_SIG` даёт после `i2d` в i2pd).
    ///
    /// Любая ошибка (нет семейства, неверная длина подписи, подпись
    /// не сходится, ключ битый) даёт `false` — этот метод специально
    /// не возвращает `Result`, чтобы вызывающий код в
    /// `RouterInfo::parse` не превращал «не наше семейство» в
    /// фатальную ошибку парсинга.
    #[must_use]
    pub fn verify(&self, family: &str, ident: &IdentHash, signature: &[u8]) -> bool {
        let name = family.to_lowercase();
        let Some((key, _)) = self.keys.get(&name) else {
            return false;
        };
        verify_with_key(&name, key, ident, signature).is_ok()
    }
}

// --- create_family_signature --------------------------------------------

/// Подпись владельца семейства: `ECDSA_P256_SHA256(family || ident)`.
///
/// Возвращает base64-строку — ровно то, что кладётся в property
/// `family.sig` в `RouterInfo`.
///
/// # Errors
///
/// - [`Error::Malformed`] — имя пустое или не влезает в лимит
///   (`name + 32 <= 100`);
/// - [`Error::Malformed`] — `private_key` не является валидным
///   скаляром P-256.
pub fn create_family_signature(
    family: &str,
    ident: &IdentHash,
    private_key: &[u8; 32],
) -> Result<String> {
    let name = family.to_lowercase();
    if name.is_empty() {
        return Err(I2PError::Malformed("family: empty name"));
    }
    if name.len() + 32 > 100 {
        return Err(I2PError::Malformed("family: name too long"));
    }

    let sk = SigningKey::from_slice(private_key)
        .map_err(|_| I2PError::Malformed("family: invalid private key"))?;

    let signed = signed_message(&name, ident);
    let sig: Signature = sk.sign(&signed);
    Ok(base64::encode(sig.to_bytes().as_ref()))
}

// --- helpers -------------------------------------------------------------

/// То, что подписывается: `lowercased_family || ident_hash`.
fn signed_message(name: &str, ident: &IdentHash) -> Vec<u8> {
    let mut buf = Vec::with_capacity(name.len() + 32);
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(ident.as_bytes());
    buf
}

/// Общая часть `verify` — вынесена, чтобы можно было вернуть `Result`
/// и в тестах отличать «подпись не сошлась» от «ключ битый».
fn verify_with_key(name: &str, key: &FamilyKey, ident: &IdentHash, signature: &[u8]) -> Result<()> {
    let sig = Signature::from_slice(signature)
        .map_err(|_| I2PError::Malformed("family: signature must be 64 bytes"))?;
    let vk = key.verifying_key()?;
    let signed = signed_message(name, ident);
    vk.verify(&signed, &sig)
        .map_err(|_| I2PError::Malformed("family: signature verification failed"))
}
