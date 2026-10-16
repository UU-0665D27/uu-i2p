//! `LeaseSet` — публичное описание destination'а.
//!
//! `LeaseSet` (type 1) содержит identity destination'а, ключ шифрования
//! и список `Lease` — записей о том, как доставить пакет до destination'а
//! через inbound-туннели.
//!
//! ## Wire-формат (type 1)
//!
//! ```text
//!   offset              size          field
//!   ------              ----          -----
//!        0        identity.full_len() identity
//!        ?              256           encryption key (с padding)
//!        ?        signing_pubkey_len   signing key (redundant, нули)
//!        ?                1            num_leases
//!        ?       num_leases * 44       leases
//!        ?        signature_len        signature
//! ```
//!
//! `encryption key` — 256-байтовый блок с padding'ом. Реальная длина
//! ключа зависит от `crypto_key_type` (256 для `ElGamal`, 32 для
//! ECIES-X25519, ...). Реальные байты лежат в начале блока.
//!
//! `signing key` — устаревшее поле, дублирует signing public key из
//! identity. i2pd его читает, но игнорирует и заполняет нулями при
//! генерации. Мы делаем так же — на serialize всегда пишем нули.
//!
//! ## Что не реализовано
//!
//! - верификация подписи — нужен Ed25519/DSA/ECDSA verifier (отдельно);
//! - `LeaseSet2` (типы 3, 5, 7) — отдельный модуль.

use crate::IdentHash;
use crate::error::{I2PError, Result};
use crate::identity::IdentityEx;
use crate::lease::{LEASE_SIZE, Lease, MAX_NUM_LEASES};
use crate::private_keys::I2PPrivateKeys;

/// Store type `LeaseSet` (type 1) в netDb.
pub const NETDB_STORE_TYPE_LEASESET: u8 = 1;

/// Размер `encryption_key` в wire-формате.
pub const ENCRYPTION_KEY_SIZE: usize = 256;

/// `LeaseSet` (тип 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSet {
    identity: IdentityEx,
    encryption_key: [u8; ENCRYPTION_KEY_SIZE],
    leases: Vec<Lease>,
    signature: Vec<u8>,
}

impl LeaseSet {
    /// Разбирает `LeaseSet` (type 1) из буфера.
    ///
    /// Хвостовые байты после signature игнорируются — так же, как
    /// i2pd `LeaseSet::ReadFromBuffer`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — буфер короче ожидаемого;
    /// - [`Error::Malformed`] — `num_leases` вне диапазона `1..=16`;
    /// - ошибки [`IdentityEx::from_buffer`].
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let identity = IdentityEx::from_buffer(buf)?;
        let mut offset = identity.full_len();

        // encryption_key (256 байт, с padding'ом)
        let ek_end = offset + ENCRYPTION_KEY_SIZE;
        if buf.len() < ek_end {
            return Err(I2PError::InvalidLength {
                expected: ek_end,
                got: buf.len(),
            });
        }
        let mut encryption_key = [0u8; ENCRYPTION_KEY_SIZE];
        encryption_key.copy_from_slice(&buf[offset..ek_end]);
        offset = ek_end;

        // signing_key (redundant, skip)
        let sig_pub_len = identity.signing_public_key_len()?;
        let sk_end = offset + sig_pub_len;
        if buf.len() < sk_end {
            return Err(I2PError::InvalidLength {
                expected: sk_end,
                got: buf.len(),
            });
        }
        offset = sk_end;

        // num_leases
        if buf.len() < offset + 1 {
            return Err(I2PError::InvalidLength {
                expected: offset + 1,
                got: buf.len(),
            });
        }
        let num_leases = buf[offset];
        offset += 1;

        if num_leases == 0 || num_leases > MAX_NUM_LEASES {
            return Err(I2PError::Malformed("leaseset: invalid number of leases"));
        }

        // leases
        let leases_bytes_len = usize::from(num_leases) * LEASE_SIZE;
        let leases_end = offset + leases_bytes_len;
        if buf.len() < leases_end {
            return Err(I2PError::InvalidLength {
                expected: leases_end,
                got: buf.len(),
            });
        }
        let mut leases = Vec::with_capacity(usize::from(num_leases));
        for i in 0..usize::from(num_leases) {
            let lease = Lease::parse_ls1(&buf[offset + i * LEASE_SIZE..])?;
            leases.push(lease);
        }
        offset = leases_end;

        // signature
        let sig_len = identity.signature_len()?;
        let sig_end = offset + sig_len;
        if buf.len() < sig_end {
            return Err(I2PError::InvalidLength {
                expected: sig_end,
                got: buf.len(),
            });
        }
        let signature = buf[offset..sig_end].to_vec();

        Ok(Self {
            identity,
            encryption_key,
            leases,
            signature,
        })
    }

    /// Сериализует в wire-формат.
    ///
    /// Поле `signing key` заполняется нулями, как это делает i2pd
    /// (`LocalLeaseSet` constructor). Если исходный буфер содержал
    /// там нечто иное, byte-perfect round-trip не сойдётся — но
    /// семантически всё восстановится.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `leases.len() > 255` (защита от
    /// переполнения `u8`).
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let mut out = Self::unsigned_bytes(&self.identity, &self.encryption_key, &self.leases)?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }
    /// Собирает signed-часть (всё, что до хвостовой signature).
    ///
    /// Общий код для [`Self::to_buffer`] и [`Self::from_keys`].
    fn unsigned_bytes(
        identity: &IdentityEx,
        encryption_key: &[u8; ENCRYPTION_KEY_SIZE],
        leases: &[Lease],
    ) -> Result<Vec<u8>> {
        let id_len = identity.full_len();
        let sig_pub_len = identity.signing_public_key_len()?;
        let num_leases = u8::try_from(leases.len())
            .map_err(|_| I2PError::Malformed("leaseset: too many leases"))?;

        let mut out = Vec::with_capacity(
            id_len + ENCRYPTION_KEY_SIZE + sig_pub_len + 1 + leases.len() * LEASE_SIZE,
        );

        let mut id_buf = vec![0u8; id_len];
        identity.to_buffer(&mut id_buf)?;
        out.extend_from_slice(&id_buf);

        out.extend_from_slice(encryption_key);

        // signing_key — redundant, всегда нули
        out.extend(std::iter::repeat_n(0u8, sig_pub_len));

        out.push(num_leases);
        for lease in leases {
            out.extend_from_slice(&lease.to_buffer_ls1());
        }

        Ok(out)
    }
    /// Собирает и подписывает `LeaseSet` из `PrivateKeys` и списка leases.
    ///
    /// Identity берётся из `keys.public()`, encryption key — 32-байтовый
    /// X25519 public, размещённый в начале 256-байтового блока (padding
    /// = нули, как i2pd при генерации). Подпись — Ed25519 над
    /// `unsigned_bytes()`.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`], если у `keys` не `EdDSA` подпись
    ///   (для `PrivateKeys::generate_default` невозможно);
    /// - [`Error::Malformed`] при рассинхроне длин.
    pub fn from_keys(keys: &I2PPrivateKeys, leases: Vec<Lease>) -> Result<Self> {
        let identity = keys.public().clone();

        let mut encryption_key = [0u8; ENCRYPTION_KEY_SIZE];
        encryption_key.copy_from_slice(identity.encryption_public_key_full());

        let unsigned = Self::unsigned_bytes(&identity, &encryption_key, &leases)?;
        let signature = keys.sign(&unsigned)?;

        let expected_sig_len = identity.signature_len()?;
        if signature.len() != expected_sig_len {
            return Err(I2PError::Malformed("leaseset: signature length mismatch"));
        }

        Ok(Self {
            identity,
            encryption_key,
            leases,
            signature,
        })
    }

    /// Идентичность destination'а.
    #[must_use]
    pub const fn identity(&self) -> &IdentityEx {
        &self.identity
    }

    /// `IdentHash` destination'а — ключ, по которому `LeaseSet` лежит
    /// в netDb.
    #[must_use]
    pub const fn ident_hash(&self) -> &IdentHash {
        self.identity.ident_hash()
    }

    /// Все 256 байт `encryption_key`, включая padding.
    #[must_use]
    pub const fn encryption_key_full(&self) -> &[u8; ENCRYPTION_KEY_SIZE] {
        &self.encryption_key
    }

    /// Реальный encryption key без padding'а.
    ///
    /// Длина определяется [`CryptoKeyType::storage_public_key_len`]:
    /// 256 для `ElGamal` и ECIES-P256, 32 для ECIES-X25519 и ML-KEM.
    ///
    /// [`CryptoKeyType::storage_public_key_len`]: crate::signature::CryptoKeyType::storage_public_key_len
    ///
    /// # Errors
    ///
    /// См. [`IdentityEx::crypto_key_type`].
    pub fn encryption_key(&self) -> Result<&[u8]> {
        let ckt = self.identity.crypto_key_type()?;
        let len = ckt
            .storage_public_key_len()
            .ok_or(crate::error::I2PError::UnknownCryptoKeyType(ckt.as_u16()))?;
        Ok(&self.encryption_key[..len])
    }

    /// Список `Lease` (1..=16).
    #[must_use]
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }

    /// Подпись (только хвост).
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    /// Проверяет подпись над исходными байтами `buf`.
    ///
    /// `buf` — это **исходные байты** `LeaseSet`, ровно те, что
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
