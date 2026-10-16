//! `LeaseSet2` (type 3) — расширенный `LeaseSet` для современных destination'ов.
//!
//! Отличается от `LeaseSet` (type 1) заголовком и структурой:
//!
//! - вместо одного 256-байтового `encryption_key` — **несколько
//!   key sections** с типами и длинами (для совместимости с ML-KEM
//!   и пост-квантовых типов);
//! - добавлены `published timestamp`, `expires`, `flags`, `properties`;
//! - `Lease` — 40 байт (LS2 формат), endDate в секундах.
//!
//! ## Wire-формат (type 3)
//!
//! ```text
//!   offset              size          field
//!   ------              ----          -----
//!        0        identity.full_len() identity
//!        ?                4            published timestamp (BE u32, sec)
//!        ?                2            expires (BE u16, sec after published)
//!        ?                2            flags (BE u16)
//!        ?                2            properties length (BE u16)
//!        ?       props_len             properties
//!        ?                1            num key sections
//!        ?       sum(key_section)      key sections
//!        ?                1            num leases (1..=16)
//!        ?       num_leases * 40       leases
//!        ?        signature_len        signature
//! ```
//!
//! Каждая key section: `key_type(2 BE u16) | key_len(2 BE u16) | key`.
//!
//! ## Что не реализовано
//!
//! - `OFFLINE_KEYS` (transient signing key) — будет отдельно;
//! - `PUBLISHED_ENCRYPTED` (type 5) — отдельный модуль;
//! - верификация подписи.

use crate::IdentHash;
use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{I2PError, Result};
use crate::identity::IdentityEx;
use crate::lease::{LEASE2_SIZE, Lease, MAX_NUM_LEASES};
use crate::private_keys::I2PPrivateKeys;
use crate::router_info::param;
use crate::signature::CryptoKeyType;

/// Одно property: `(key, value)`.
///
/// В wire-формате LS2 properties — повторяющиеся `key=value;` где
/// `key` и `value` — length-prefixed строки. Порядок сохраняется.
pub type Property = (Vec<u8>, Vec<u8>);

/// Список properties в порядке появления.
pub type Properties = Vec<Property>;

/// Store type стандартного `LeaseSet2` в netDb.
pub const NETDB_STORE_TYPE_STANDARD_LEASESET2: u8 = 3;

/// `LeaseSet2` version, published как encrypted (type 5).
pub const NETDB_STORE_TYPE_ENCRYPTED_LEASESET2: u8 = 5;

/// `LeaseSet2` version, meta (type 7).
pub const NETDB_STORE_TYPE_META_LEASESET2: u8 = 7;

/// Флаг: `LeaseSet` опубликован с offline signing key.
pub const LEASESET2_FLAG_OFFLINE_KEYS: u16 = 0x0001;
/// Флаг: `LeaseSet` не публикуется в netDb.
pub const LEASESET2_FLAG_UNPUBLISHED_LEASESET: u16 = 0x0002;
/// Флаг: `LeaseSet` опубликован как encrypted.
pub const LEASESET2_FLAG_PUBLISHED_ENCRYPTED: u16 = 0x0004;

/// Одна секция encryption ключа — `(type, key)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySection {
    /// Тип ключа (ECIES-X25519, ML-KEM-768, ...).
    pub key_type: CryptoKeyType,
    /// Байты ключа. Реальная длина определяется `key_type`.
    pub key: Vec<u8>,
}

/// `LeaseSet2` (type 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSet2 {
    identity: IdentityEx,
    published_timestamp: u32,
    expires: u16,
    flags: u16,
    properties: Properties,
    key_sections: Vec<KeySection>,
    leases: Vec<Lease>,
    signature: Vec<u8>,
}

impl LeaseSet2 {
    /// Разбирает `LeaseSet2` (type 3) из буфера.
    ///
    /// `buf` начинается сразу с identity. Если он содержит префикс
    /// `store_type` (как в I2NP `DatabaseStore`), caller отрезает его сам.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — буфер короче ожидаемого;
    /// - [`Error::Malformed`] — `num_leases` вне `1..=16`, или
    ///   `properties` не парсятся;
    /// - [`Error::Unsupported`] — флаг `OFFLINE_KEYS` выставлен;
    /// - ошибки [`IdentityEx::from_buffer`].
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let identity = IdentityEx::from_buffer(buf)?;
        let mut offset = identity.full_len();

        let (published_timestamp, expires, flags, consumed) = parse_ls2_header(&buf[offset..])?;
        offset += consumed;

        if flags & LEASESET2_FLAG_OFFLINE_KEYS != 0 {
            return Err(I2PError::Unsupported("leaseset2: offline keys"));
        }

        let (properties, consumed) = parse_properties_field(&buf[offset..])?;
        offset += consumed;

        let (key_sections, consumed) = parse_key_sections_field(&buf[offset..])?;
        offset += consumed;

        let (leases, consumed) = parse_leases_field(&buf[offset..])?;
        offset += consumed;

        let sig_len = identity.signature_len()?;
        if buf.len() < offset + sig_len {
            return Err(I2PError::InvalidLength {
                expected: offset + sig_len,
                got: buf.len(),
            });
        }
        let signature = buf[offset..offset + sig_len].to_vec();

        Ok(Self {
            identity,
            published_timestamp,
            expires,
            flags,
            properties,
            key_sections,
            leases,
            signature,
        })
    }

    /// Сериализует в wire-формат (type 3).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `leases.len() > 255` или
    /// `properties > 65535 байт`.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let mut out = Self::unsigned_bytes(
            &self.identity,
            self.published_timestamp,
            self.expires,
            self.flags,
            &self.properties,
            &self.key_sections,
            &self.leases,
        )?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Собирает signed-часть (всё, что до хвостовой signature).
    #[allow(clippy::too_many_arguments)]
    fn unsigned_bytes(
        identity: &IdentityEx,
        published_timestamp: u32,
        expires: u16,
        flags: u16,
        properties: &[Property],
        key_sections: &[KeySection],
        leases: &[Lease],
    ) -> Result<Vec<u8>> {
        let id_len = identity.full_len();
        let num_leases = u8::try_from(leases.len())
            .map_err(|_| I2PError::Malformed("leaseset2: too many leases"))?;

        let mut props_buf = Vec::new();
        for (k, v) in properties {
            props_buf.extend_from_slice(&param(k, v));
        }
        let props_size = u16::try_from(props_buf.len())
            .map_err(|_| I2PError::Malformed("leaseset2: properties > 65535 bytes"))?;

        let mut out = Vec::new();

        let mut id_buf = vec![0u8; id_len];
        identity.to_buffer(&mut id_buf)?;
        out.extend_from_slice(&id_buf);

        out.extend_from_slice(&published_timestamp.to_be_bytes());
        out.extend_from_slice(&expires.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());

        out.extend_from_slice(&props_size.to_be_bytes());
        out.extend_from_slice(&props_buf);

        let num_keys = u8::try_from(key_sections.len())
            .map_err(|_| I2PError::Malformed("leaseset2: too many key sections"))?;
        out.push(num_keys);
        for section in key_sections {
            let key_len = u16::try_from(section.key.len())
                .map_err(|_| I2PError::Malformed("leaseset2: key > 65535 bytes"))?;
            out.extend_from_slice(&section.key_type.as_u16().to_be_bytes());
            out.extend_from_slice(&key_len.to_be_bytes());
            out.extend_from_slice(&section.key);
        }

        out.push(num_leases);
        for lease in leases {
            out.extend_from_slice(&lease.to_buffer_ls2());
        }

        Ok(out)
    }

    /// Собирает и подписывает `LeaseSet2` из `PrivateKeys` и минимально
    /// необходимых полей.
    ///
    /// Проставляет:
    /// - `identity` из `keys.public()`;
    /// - `key_sections` = одна секция с crypto-типом identity и
    ///   32-байтовым X25519 public;
    /// - `flags` = 0 (published, не encrypted, без offline keys);
    /// - `properties` = пусто;
    /// - `signature` = Ed25519 над `unsigned_bytes()`.
    ///
    /// Для нестандартных LS2 (свой `flags`, properties, несколько
    /// key sections) используйте [`Self::unsigned_bytes`] напрямую
    /// или будущий `LeaseSet2Builder`.
    ///
    /// # Errors
    ///
    /// См. [`Self::unsigned_bytes`] и [`PrivateKeys::sign`].
    pub fn from_keys(
        keys: &I2PPrivateKeys,
        published_timestamp: u32,
        expires: u16,
        leases: Vec<Lease>,
    ) -> Result<Self> {
        Self::builder()
            .published_timestamp(published_timestamp)
            .expires(expires)
            .leases(leases)
            .build(keys)
    }

    /// Возвращает новый [`LeaseSet2Builder`].
    ///
    /// Пример:
    ///
    /// ```
    /// use uu_i2p::lease::Lease;
    /// use uu_i2p::lease_set2::LeaseSet2;
    /// use uu_i2p::private_keys::I2PPrivateKeys;
    /// use uu_i2p::IdentHash;
    ///
    /// let keys = I2PPrivateKeys::generate_default().unwrap();
    /// let lease = Lease::new(
    ///     IdentHash::from_array([0x11; 32]),
    ///     42,
    ///     1_700_000_000_000,
    /// );
    ///
    /// let ls = LeaseSet2::builder()
    ///     .published_timestamp(1_700_000_000)
    ///     .expires(3600)
    ///     .add_lease(lease)
    ///     .build(&keys)
    ///     .unwrap();
    ///
    /// assert_eq!(ls.published_timestamp(), 1_700_000_000);
    /// ```
    #[must_use]
    pub fn builder() -> LeaseSet2Builder {
        LeaseSet2Builder::default()
    }

    /// Идентичность destination'а.
    #[must_use]
    pub const fn identity(&self) -> &IdentityEx {
        &self.identity
    }

    /// `IdentHash` destination'а.
    #[must_use]
    pub const fn ident_hash(&self) -> &IdentHash {
        self.identity.ident_hash()
    }

    /// Время публикации (seconds since epoch).
    #[must_use]
    pub const fn published_timestamp(&self) -> u32 {
        self.published_timestamp
    }

    /// Время истечения в секундах после `published`.
    #[must_use]
    pub const fn expires(&self) -> u16 {
        self.expires
    }

    /// Абсолютное время истечения в миллисекундах.
    #[must_use]
    pub const fn expiration_time_ms(&self) -> u64 {
        (self.published_timestamp as u64 + self.expires as u64) * 1000
    }

    /// Флаги (см. `LEASESET2_FLAG_*`).
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// `UNPUBLISHED_LEASESET`.
    #[must_use]
    pub const fn is_unpublished(&self) -> bool {
        self.flags & LEASESET2_FLAG_UNPUBLISHED_LEASESET != 0
    }

    /// `PUBLISHED_ENCRYPTED`.
    #[must_use]
    pub const fn is_published_encrypted(&self) -> bool {
        self.flags & LEASESET2_FLAG_PUBLISHED_ENCRYPTED != 0
    }

    /// Properties как срез.
    #[must_use]
    pub fn properties(&self) -> &[Property] {
        &self.properties
    }

    /// Значение property по ключу (последнее при дубликатах).
    #[must_use]
    pub fn get_property(&self, key: &[u8]) -> Option<&[u8]> {
        self.properties
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// Key sections.
    #[must_use]
    pub fn key_sections(&self) -> &[KeySection] {
        &self.key_sections
    }

    /// Первая key section — самая предпочтительная (i2pd кладёт
    /// preferred первой).
    #[must_use]
    pub fn encryption_key(&self) -> Option<&KeySection> {
        self.key_sections.first()
    }

    /// Список `Lease`.
    #[must_use]
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }

    /// Подпись.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    /// Проверяет подпись над исходными байтами `buf`.
    ///
    /// `buf` — это **исходные байты** `LeaseSet2`, ровно те, что
    /// были прочитаны из `DatabaseStore` payload. Публичный ключ
    /// берётся из [`Self::identity`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если `buf` короче `signature_len`;
    /// - [`Error::Unsupported`] — тип подписи не реализован;
    /// - [`Error::Malformed`] — подпись не сходится.
    pub fn verify(&self, buf: &[u8]) -> Result<()> {
        let sig_len = self.identity.signature_len()?;
        if buf.len() < sig_len {
            return Err(I2PError::InvalidLength {
                expected: sig_len,
                got: buf.len(),
            });
        }
        let (signed, sig) = buf.split_at(buf.len() - sig_len);
        self.identity.verify(signed, sig)
    }
}

// --- LeaseSet2Builder ---------------------------------------------------

/// Конструктор `LeaseSet2`.
///
/// Собирает тело LS2 (published, expires, flags, properties,
/// key sections, leases) и подписывает его приватными ключами.
///
/// Если `key_sections` не заданы явно, при `build()` автоматически
/// создаётся одна секция из crypto-типа `keys` — совпадает с
/// поведением [`LeaseSet2::from_keys`].
///
/// Флаг `OFFLINE_KEYS` нельзя выставить через builder — при
/// попытке `build()` вернёт [`Error::Unsupported`].
#[derive(Debug, Clone, Default)]
pub struct LeaseSet2Builder {
    published_timestamp: u32,
    expires: u16,
    flags: u16,
    properties: Properties,
    key_sections: Vec<KeySection>,
    leases: Vec<Lease>,
}

impl LeaseSet2Builder {
    /// Устанавливает `published_timestamp` (seconds since epoch).
    #[must_use]
    pub const fn published_timestamp(mut self, ts: u32) -> Self {
        self.published_timestamp = ts;
        self
    }

    /// Устанавливает `expires` (секунды после `published`).
    #[must_use]
    pub const fn expires(mut self, expires: u16) -> Self {
        self.expires = expires;
        self
    }

    /// Устанавливает `flags` целиком (низкоуровневый доступ).
    ///
    /// Обычно предпочтительнее [`Self::unpublished`] /
    /// [`Self::published_encrypted`].
    #[must_use]
    pub const fn flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Выставляет флаг `UNPUBLISHED_LEASESET`.
    #[must_use]
    pub const fn unpublished(mut self) -> Self {
        self.flags |= LEASESET2_FLAG_UNPUBLISHED_LEASESET;
        self
    }

    /// Выставляет флаг `PUBLISHED_ENCRYPTED`.
    #[must_use]
    pub const fn published_encrypted(mut self) -> Self {
        self.flags |= LEASESET2_FLAG_PUBLISHED_ENCRYPTED;
        self
    }

    /// Добавляет property, **не** удаляя существующее с тем же
    /// ключом. В wire-формате окажутся оба.
    #[must_use]
    pub fn add_property(mut self, key: &[u8], value: &[u8]) -> Self {
        self.properties.push((key.to_vec(), value.to_vec()));
        self
    }

    /// Устанавливает property, заменяя существующее с тем же ключом.
    #[must_use]
    pub fn set_property(mut self, key: &[u8], value: &[u8]) -> Self {
        self.properties.retain(|(k, _)| k != key);
        self.properties.push((key.to_vec(), value.to_vec()));
        self
    }

    /// Добавляет key section.
    ///
    /// Если ни одной секции не добавлено, `build()` создаст одну
    /// автоматически из crypto-типа `keys`.
    #[must_use]
    pub fn add_key_section(mut self, section: KeySection) -> Self {
        self.key_sections.push(section);
        self
    }

    /// Добавляет lease.
    #[must_use]
    pub fn add_lease(mut self, lease: Lease) -> Self {
        self.leases.push(lease);
        self
    }

    /// Заменяет весь список leases.
    #[must_use]
    pub fn leases(mut self, leases: Vec<Lease>) -> Self {
        self.leases = leases;
        self
    }

    /// Собирает и подписывает `LeaseSet2` ключами `keys`.
    ///
    /// Подпись — Ed25519 над `identity || body` (то есть над всем,
    /// что до хвостовой signature).
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] — если выставлен флаг `OFFLINE_KEYS`;
    /// - [`Error::Malformed`] — если `leases.len() > 16` или
    ///   properties/key sections не влезают в формат;
    /// - [`Error::UnknownCryptoKeyType`] / [`Error::UnknownSigningKeyType`]
    ///   при неподдерживаемых типах `keys`;
    /// - [`PrivateKeys::sign`] при ошибке подписи.
    pub fn build(mut self, keys: &I2PPrivateKeys) -> Result<LeaseSet2> {
        let identity = keys.public().clone();

        if self.flags & LEASESET2_FLAG_OFFLINE_KEYS != 0 {
            return Err(I2PError::Unsupported("leaseset2: offline keys"));
        }

        // Если key_sections не заданы — создать одну из crypto-типа keys.
        if self.key_sections.is_empty() {
            let crypto_type = identity.crypto_key_type()?;
            let pub_key = identity.encryption_public_key()?.to_vec();
            self.key_sections.push(KeySection {
                key_type: crypto_type,
                key: pub_key,
            });
        }

        let unsigned = LeaseSet2::unsigned_bytes(
            &identity,
            self.published_timestamp,
            self.expires,
            self.flags,
            &self.properties,
            &self.key_sections,
            &self.leases,
        )?;
        let signature = keys.sign(&unsigned)?;

        let expected_sig_len = identity.signature_len()?;
        if signature.len() != expected_sig_len {
            return Err(I2PError::Malformed("leaseset2: signature length mismatch"));
        }

        Ok(LeaseSet2 {
            identity,
            published_timestamp: self.published_timestamp,
            expires: self.expires,
            flags: self.flags,
            properties: self.properties,
            key_sections: self.key_sections,
            leases: self.leases,
            signature,
        })
    }
}
// --- helpers -------------------------------------------------------------

/// Разбирает properties LS2 (`key=value;` * в общем буфере длины `size`).
fn parse_properties(buf: &[u8]) -> Result<Properties> {
    let mut props = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        // Используем общий `lp` для чтения length-prefixed.
        let (key, k_consumed) = read_lp(&buf[offset..])?;
        offset += k_consumed;
        if buf.get(offset) != Some(&b'=') {
            return Err(I2PError::Malformed(
                "leaseset2: expected '=' after property key",
            ));
        }
        offset += 1;
        let (value, v_consumed) = read_lp(&buf[offset..])?;
        offset += v_consumed;
        if buf.get(offset) != Some(&b';') {
            return Err(I2PError::Malformed(
                "leaseset2: expected ';' after property value",
            ));
        }
        offset += 1;
        props.push((key.to_vec(), value.to_vec()));
    }
    Ok(props)
}
/// Разбирает `published(4) | expires(2) | flags(2)`. Возвращает
/// `(published, expires, flags, consumed=8)`.
fn parse_ls2_header(buf: &[u8]) -> Result<(u32, u16, u16, usize)> {
    if buf.len() < 8 {
        return Err(I2PError::InvalidLength {
            expected: 8,
            got: buf.len(),
        });
    }
    Ok((
        read_u32_be(buf),
        read_u16_be(&buf[4..]),
        read_u16_be(&buf[6..]),
        8,
    ))
}

/// Разбирает поле properties: `size(2 BE) | data`. Возвращает
/// `(properties, consumed=2+size)`.
fn parse_properties_field(buf: &[u8]) -> Result<(Properties, usize)> {
    if buf.len() < 2 {
        return Err(I2PError::InvalidLength {
            expected: 2,
            got: buf.len(),
        });
    }
    let size = usize::from(read_u16_be(buf));
    let total = 2 + size;
    if buf.len() < total {
        return Err(I2PError::InvalidLength {
            expected: total,
            got: buf.len(),
        });
    }
    let props = parse_properties(&buf[2..total])?;
    Ok((props, total))
}

/// Разбирает `num_keys(1) | sections`. Возвращает `(sections, consumed)`.
fn parse_key_sections_field(buf: &[u8]) -> Result<(Vec<KeySection>, usize)> {
    if buf.is_empty() {
        return Err(I2PError::InvalidLength {
            expected: 1,
            got: 0,
        });
    }
    let num_keys = usize::from(buf[0]);
    let mut offset = 1;
    let mut sections = Vec::with_capacity(num_keys);
    for _ in 0..num_keys {
        if buf.len() < offset + 4 {
            return Err(I2PError::InvalidLength {
                expected: offset + 4,
                got: buf.len(),
            });
        }
        let key_type = CryptoKeyType::from_u16(read_u16_be(&buf[offset..]))?;
        offset += 2;
        let key_len = usize::from(read_u16_be(&buf[offset..]));
        offset += 2;
        if buf.len() < offset + key_len {
            return Err(I2PError::InvalidLength {
                expected: offset + key_len,
                got: buf.len(),
            });
        }
        sections.push(KeySection {
            key_type,
            key: buf[offset..offset + key_len].to_vec(),
        });
        offset += key_len;
    }
    Ok((sections, offset))
}

/// Разбирает `num_leases(1) | leases`. Возвращает `(leases, consumed)`.
fn parse_leases_field(buf: &[u8]) -> Result<(Vec<Lease>, usize)> {
    if buf.is_empty() {
        return Err(I2PError::InvalidLength {
            expected: 1,
            got: 0,
        });
    }
    let num_leases = buf[0];
    if num_leases == 0 || num_leases > MAX_NUM_LEASES {
        return Err(I2PError::Malformed("leaseset2: invalid number of leases"));
    }
    let n = usize::from(num_leases);
    let total = 1 + n * LEASE2_SIZE;
    if buf.len() < total {
        return Err(I2PError::InvalidLength {
            expected: total,
            got: buf.len(),
        });
    }
    let mut leases = Vec::with_capacity(n);
    for i in 0..n {
        leases.push(Lease::parse_ls2(&buf[1 + i * LEASE2_SIZE..])?);
    }
    Ok((leases, total))
}
/// Декодирует length-prefixed строку и возвращает `(data, consumed)`.
fn read_lp(buf: &[u8]) -> Result<(&[u8], usize)> {
    let Some(&len) = buf.first() else {
        return Err(I2PError::InvalidLength {
            expected: 1,
            got: 0,
        });
    };
    let len = usize::from(len);
    let end = 1 + len;
    if buf.len() < end {
        return Err(I2PError::InvalidLength {
            expected: end,
            got: buf.len(),
        });
    }
    Ok((&buf[1..end], end))
}
