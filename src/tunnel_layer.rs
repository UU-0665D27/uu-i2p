//! Слои шифрования туннеля: `TunnelEncryption` / `TunnelDecryption`
//! и цепочка слоёв владельца туннеля.
//!
//! Соответствует `TunnelEncryption` / `TunnelDecryption` из
//! `Crypto.cpp` и `Tunnel::EncryptTunnelMsg` из `Tunnel.cpp`.
//!
//! ## Один слой (1024 байта = IV 16 + данные 1008)
//!
//! ```text
//! encrypt:                          decrypt:
//!   iv   = ECB_enc(iv_key, in[0..16])   iv   = ECB_dec(iv_key, in[0..16])
//!   out[16..] = CBC_enc(layer_key, iv, in[16..])
//!                                       out[16..] = CBC_dec(layer_key, iv, in[16..])
//!   out[0..16] = ECB_enc(iv_key, iv)    out[0..16] = ECB_dec(iv_key, iv)
//! ```
//!
//! IV шифруется «дважды» (до и после CBC), поэтому хоп не может
//! сопоставить входящее сообщение с исходящим по IV.
//! Ключи — AES-256: `layer_key` для CBC, `iv_key` для ECB.
//!
//! ## Кто что делает
//!
//! - каждый **хоп** вызывает [`TunnelEncryption::encrypt`] со своими
//!   ключами (`layer_key`, `iv_key` из [`crate::RecordKeys`]);
//! - **владелец** туннеля вызывает [`TunnelDecryption::decrypt`]
//!   ключами всех хопов от последнего к первому
//!   ([`TunnelLayerChain`]):
//!   - inbound: снимает слои с принятого сообщения;
//!   - outbound: «расшифровывает» исходящее сообщение заранее,
//!     чтобы слои хопов сократились по пути.
//!
//! ## Zeroize
//!
//! `layer_key` затирается при `drop`; раундовые ключи `aes::Aes256`
//! затираются, только если у крейта `aes` включена feature `zeroize`.

use zeroize::Zeroize;

use crate::crypto::{Aes256Cbc, Aes256Ecb};
use crate::error::{I2PError, Result};
use crate::tunnel_config::TunnelConfig;
use crate::tunnel_messages::{TUNNEL_DATA_ENCRYPTED_SIZE, TUNNEL_DATA_IV_SIZE, TunnelDataBody};

/// Размер обрабатываемого слоем блока: IV + зашифрованные данные.
pub const TUNNEL_LAYER_SIZE: usize = TUNNEL_DATA_IV_SIZE + TUNNEL_DATA_ENCRYPTED_SIZE;

fn pack(msg: &TunnelDataBody) -> [u8; TUNNEL_LAYER_SIZE] {
    let mut out = [0u8; TUNNEL_LAYER_SIZE];
    out[..TUNNEL_DATA_IV_SIZE].copy_from_slice(&msg.iv);
    out[TUNNEL_DATA_IV_SIZE..].copy_from_slice(&*msg.encrypted);
    out
}

fn unpack(tunnel_id: u32, layer: &[u8; TUNNEL_LAYER_SIZE]) -> TunnelDataBody {
    let mut iv = [0u8; TUNNEL_DATA_IV_SIZE];
    iv.copy_from_slice(&layer[..TUNNEL_DATA_IV_SIZE]);
    let mut encrypted = Box::new([0u8; TUNNEL_DATA_ENCRYPTED_SIZE]);
    encrypted.copy_from_slice(&layer[TUNNEL_DATA_IV_SIZE..]);
    TunnelDataBody {
        tunnel_id,
        iv,
        encrypted,
    }
}

fn iv_of(layer: &[u8; TUNNEL_LAYER_SIZE]) -> [u8; TUNNEL_DATA_IV_SIZE] {
    let mut iv = [0u8; TUNNEL_DATA_IV_SIZE];
    iv.copy_from_slice(&layer[..TUNNEL_DATA_IV_SIZE]);
    iv
}

/// Шифрование одного слоя (сторона хопа).
pub struct TunnelEncryption {
    iv_cipher: Aes256Ecb,
    layer_key: [u8; 32],
}

impl TunnelEncryption {
    /// Создаёт слой из ключей хопа.
    #[must_use]
    pub fn new(layer_key: &[u8; 32], iv_key: &[u8; 32]) -> Self {
        Self {
            iv_cipher: Aes256Ecb::new(iv_key),
            layer_key: *layer_key,
        }
    }

    /// Шифрует 1024 байта (IV и данные).
    ///
    /// # Errors
    ///
    /// Ошибки AES-CBC (при фиксированной длине не возникают).
    pub fn encrypt(&self, input: &[u8; TUNNEL_LAYER_SIZE]) -> Result<[u8; TUNNEL_LAYER_SIZE]> {
        let iv = self.iv_cipher.encrypt_block(&iv_of(input));
        let mut out = [0u8; TUNNEL_LAYER_SIZE];
        out[TUNNEL_DATA_IV_SIZE..].copy_from_slice(&input[TUNNEL_DATA_IV_SIZE..]);
        Aes256Cbc::encrypt_in_place(&self.layer_key, &iv, &mut out[TUNNEL_DATA_IV_SIZE..])?;
        out[..TUNNEL_DATA_IV_SIZE].copy_from_slice(&self.iv_cipher.encrypt_block(&iv));
        Ok(out)
    }

    /// То же для `TunnelData`; `tunnel_id` сохраняется как есть
    /// (хоп подставляет свой следующий ID отдельно).
    ///
    /// # Errors
    ///
    /// Как [`TunnelEncryption::encrypt`].
    pub fn encrypt_tunnel_data(&self, msg: &TunnelDataBody) -> Result<TunnelDataBody> {
        Ok(unpack(msg.tunnel_id, &self.encrypt(&pack(msg))?))
    }
}

impl core::fmt::Debug for TunnelEncryption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunnelEncryption").finish_non_exhaustive()
    }
}

impl Drop for TunnelEncryption {
    fn drop(&mut self) {
        self.layer_key.zeroize();
    }
}

/// Расшифровка одного слоя (сторона владельца туннеля).
pub struct TunnelDecryption {
    iv_cipher: Aes256Ecb,
    layer_key: [u8; 32],
}

impl TunnelDecryption {
    /// Создаёт слой из ключей хопа.
    #[must_use]
    pub fn new(layer_key: &[u8; 32], iv_key: &[u8; 32]) -> Self {
        Self {
            iv_cipher: Aes256Ecb::new(iv_key),
            layer_key: *layer_key,
        }
    }

    /// Расшифровывает 1024 байта (IV и данные).
    ///
    /// # Errors
    ///
    /// Ошибки AES-CBC (при фиксированной длине не возникают).
    pub fn decrypt(&self, input: &[u8; TUNNEL_LAYER_SIZE]) -> Result<[u8; TUNNEL_LAYER_SIZE]> {
        let iv = self.iv_cipher.decrypt_block(&iv_of(input));
        let mut out = [0u8; TUNNEL_LAYER_SIZE];
        out[TUNNEL_DATA_IV_SIZE..].copy_from_slice(&input[TUNNEL_DATA_IV_SIZE..]);
        Aes256Cbc::decrypt_in_place(&self.layer_key, &iv, &mut out[TUNNEL_DATA_IV_SIZE..])?;
        out[..TUNNEL_DATA_IV_SIZE].copy_from_slice(&self.iv_cipher.decrypt_block(&iv));
        Ok(out)
    }

    /// То же для `TunnelData`; `tunnel_id` сохраняется как есть.
    ///
    /// # Errors
    ///
    /// Как [`TunnelDecryption::decrypt`].
    pub fn decrypt_tunnel_data(&self, msg: &TunnelDataBody) -> Result<TunnelDataBody> {
        Ok(unpack(msg.tunnel_id, &self.decrypt(&pack(msg))?))
    }
}

impl core::fmt::Debug for TunnelDecryption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunnelDecryption").finish_non_exhaustive()
    }
}

impl Drop for TunnelDecryption {
    fn drop(&mut self) {
        self.layer_key.zeroize();
    }
}

/// Слои владельца туннеля: расшифровка ключами хопов от последнего
/// к первому (как `m_Hops` в `Tunnel`).
#[derive(Debug, Default)]
pub struct TunnelLayerChain {
    layers: Vec<TunnelDecryption>,
}

impl TunnelLayerChain {
    /// Собирает цепочку из конфигурации с уже выведенными ключами
    /// (после [`crate::build_short_tunnel_request`]).
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если у какого-либо хопа `layer_key`
    /// или `iv_key` нулевые, т.е. ключи ещё не выведены.
    pub fn from_config(config: &TunnelConfig) -> Result<Self> {
        let mut layers = Vec::with_capacity(config.num_hops());
        for hop in config.hops().iter().rev() {
            if hop.layer_key == [0; 32] || hop.iv_key == [0; 32] {
                return Err(I2PError::Malformed("tunnel layer: hop keys are not set"));
            }
            layers.push(TunnelDecryption::new(&hop.layer_key, &hop.iv_key));
        }
        Ok(Self { layers })
    }

    /// Число слоёв.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.layers.len()
    }

    /// Пуста ли цепочка.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Применяет все слои по порядку (последний хоп первым).
    ///
    /// # Errors
    ///
    /// Ошибки [`TunnelDecryption::decrypt`].
    pub fn decrypt(&self, input: &[u8; TUNNEL_LAYER_SIZE]) -> Result<[u8; TUNNEL_LAYER_SIZE]> {
        let mut buf = *input;
        for layer in &self.layers {
            buf = layer.decrypt(&buf)?;
        }
        Ok(buf)
    }

    /// То же для `TunnelData`; `tunnel_id` сохраняется как есть.
    ///
    /// # Errors
    ///
    /// Ошибки [`TunnelDecryption::decrypt`].
    pub fn decrypt_tunnel_data(&self, msg: &TunnelDataBody) -> Result<TunnelDataBody> {
        Ok(unpack(msg.tunnel_id, &self.decrypt(&pack(msg))?))
    }
}
