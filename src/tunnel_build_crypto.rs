//! Криптография записей `ShortTunnelBuild` (ECIES-X25519, Noise N).
//!
//! Соответствует `ShortECIESTunnelHopConfig::{EncryptECIES,
//! CreateBuildRequestRecord, DecryptBuildResponseRecord, DecryptRecord}`
//! (`TunnelConfig.cpp`), `RouterContext::DecryptECIESTunnelBuildRecord`
//! и `TransitTunnels::HandleShortTransitTunnelBuildMsg`.
//! Форматы байтов — в [`crate::tunnel_build_record`].
//!
//! ## Запрос (отправитель → хоп)
//!
//! ```text
//!   Noise_N_25519_ChaChaPoly_SHA256, статический ключ получателя = hop
//!   h = H(hh || hop_pub);  h = H(h || epk)
//!   MixKey(DH(esk, hop_pub));  ct = AEAD(k, nonce=0, ad=h, clear_text)
//!   h = H(h || ct)
//! ```
//!
//! После этого обе стороны выводят ключи одной цепочкой HKDF
//! (`ck` — chaining key после `MixKey`):
//!
//! ```text
//!   "SMTunnelReplyKey"  -> reply_key  (ck = первая половина)
//!   "SMTunnelLayerKey"  -> layer_key
//!   не endpoint: iv_key = ck
//!   endpoint:    "TunnelLayerIVKey" -> iv_key,
//!                "RGarlicKeyAndTag" -> garlic key; tag = ck[..8]
//! ```
//!
//! ## Ответ (хоп → отправитель)
//!
//! Хоп `i` заменяет **свою** запись (индекс `i` в сообщении) на
//! `ChaCha20-Poly1305(reply_key, nonce[4] = i, ad = h, plaintext)`,
//! а **все остальные** записи пропускает через `ChaCha20`
//! (счётчик 1, `nonce[4] = индекс записи`) своим `reply_key`.
//! Отправитель заранее «расшифровывает» записи более поздних хопов
//! ключами предыдущих ([`pre_decrypt_records`]), чтобы к моменту,
//! когда хоп получит свою запись, слои взаимно сократились; на
//! обратном пути слои снимаются в обратном порядке
//! ([`decrypt_build_reply`]).
//!
//! ## Чего здесь нет
//!
//! - phony hop (padding-запись для inbound-туннелей): для неё нет
//!   ключей, добавляется на уровне сборки сообщения;
//! - выбор ephemeral-ключей и случайных padding-записей: ключи
//!   передаются параметрами, чтобы функции были детерминированы.

use zeroize::Zeroize;

use crate::crypto::{
    AeadChaCha20Poly1305, I2PX25519Keys, NoiseSymmetricState, chacha20_counter1, hkdf,
    init_noise_n_state,
};
use crate::error::{I2PError, Result};
use crate::tag::IdentHash;
use crate::tunnel_build_record::{
    BUILD_RECORD_TO_PEER_SIZE, DEFAULT_REQUEST_EXPIRATION_SECS, EncryptedShortRecord,
    SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE, SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE,
    SHORT_RESPONSE_PLAINTEXT_SIZE, SHORT_TUNNEL_BUILD_RECORD_SIZE, ShortBuildRequestRecord,
    ShortBuildResponseRecord,
};
use crate::tunnel_config::TunnelHopConfig;

/// Ключ и тег garlic-обёртки ответа (только для endpoint-хопа).
#[derive(Clone, PartialEq, Eq)]
pub struct GarlicReplyKeys {
    /// Ключ ECIES-garlic (32 байта).
    pub key: [u8; 32],
    /// Session tag: первые 8 байт `ck` после `RGarlicKeyAndTag`.
    pub tag: [u8; 8],
}

/// Ключи, выведенные из одной записи.
///
/// Секретные поля затираются при `drop`; `Debug` ничего не печатает.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordKeys {
    /// Ключ ответа (`ChaCha20-Poly1305` и `ChaCha20`).
    pub reply_key: [u8; 32],
    /// Ключ слоя туннеля (AES).
    pub layer_key: [u8; 32],
    /// IV-ключ слоя туннеля (AES).
    pub iv_key: [u8; 32],
    /// Garlic-ключ и тег — только для endpoint.
    pub garlic: Option<GarlicReplyKeys>,
    /// Хеш Noise после записи (`h`), AD для AEAD ответа.
    pub h: [u8; 32],
}

impl RecordKeys {
    /// Копирует `layer_key`, `iv_key` и `reply_key` в конфиг хопа.
    pub const fn apply_to(&self, hop: &mut TunnelHopConfig) {
        hop.layer_key = self.layer_key;
        hop.iv_key = self.iv_key;
        hop.reply_key = self.reply_key;
    }
}

impl core::fmt::Debug for RecordKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordKeys").finish_non_exhaustive()
    }
}

impl Drop for RecordKeys {
    fn drop(&mut self) {
        self.reply_key.zeroize();
        self.layer_key.zeroize();
        self.iv_key.zeroize();
        self.h.zeroize();
        if let Some(g) = self.garlic.as_mut() {
            g.key.zeroize();
            g.tag.zeroize();
        }
    }
}

/// Один шаг `HKDF(ck, "", info, 64)`: обновляет `ck`, возвращает ключ.
fn kdf_step(ck: &mut [u8; 32], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 64];
    hkdf(ck, &[], info, &mut out);
    ck.copy_from_slice(&out[..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[32..]);
    out.zeroize();
    key
}

/// Выводит ключи записи из состояния Noise **после** `mix_hash`
/// шифртекста запроса.
#[must_use]
pub fn derive_record_keys(noise: &NoiseSymmetricState, is_endpoint: bool) -> RecordKeys {
    let mut ck = noise.ck;
    let reply_key = kdf_step(&mut ck, b"SMTunnelReplyKey");
    let layer_key = kdf_step(&mut ck, b"SMTunnelLayerKey");
    let (iv_key, garlic) = if is_endpoint {
        let iv_key = kdf_step(&mut ck, b"TunnelLayerIVKey");
        let key = kdf_step(&mut ck, b"RGarlicKeyAndTag");
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&ck[..8]);
        (iv_key, Some(GarlicReplyKeys { key, tag }))
    } else {
        (ck, None)
    };
    ck.zeroize();
    RecordKeys {
        reply_key,
        layer_key,
        iv_key,
        garlic,
        h: noise.h,
    }
}

/// Строит clear text запроса для хопа из его конфигурации.
///
/// Как i2pd: пустые options, `layer_encryption_type = 0` (AES),
/// срок жизни 600 секунд.
#[must_use]
pub const fn request_for_hop(
    hop: &TunnelHopConfig,
    request_time_minutes: u32,
    send_msg_id: u32,
) -> ShortBuildRequestRecord {
    ShortBuildRequestRecord {
        receive_tunnel: hop.tunnel_id,
        next_tunnel: hop.next_tunnel_id,
        next_ident: hop.next_ident,
        is_gateway: hop.is_gateway,
        is_endpoint: hop.is_endpoint,
        more_flags: [0, 0],
        layer_encryption_type: 0,
        request_time_minutes,
        request_expiration_secs: DEFAULT_REQUEST_EXPIRATION_SECS,
        send_msg_id,
        options: crate::tunnel_build_record::BuildOptions::new(),
    }
}

/// Шифрует запрос для хопа (сторона отправителя).
///
/// `ephemeral` — одноразовая пара ключей; её публичная часть
/// попадает в запись.
///
/// # Errors
///
/// - ошибки [`ShortBuildRequestRecord::to_clear_text`];
/// - [`I2PError::Malformed`], если `hop_static_public` — точка малого
///   порядка (DH дал нулевой секрет) или AEAD не сработал.
pub fn encrypt_short_request(
    request: &ShortBuildRequestRecord,
    hop_ident: &IdentHash,
    hop_static_public: &[u8; 32],
    ephemeral: &I2PX25519Keys,
) -> Result<(EncryptedShortRecord, RecordKeys)> {
    let clear = request.to_clear_text()?;
    let mut noise = NoiseSymmetricState::new(&[0; 32], &[0; 32], &[0; 32]);
    init_noise_n_state(&mut noise, hop_static_public);
    noise.mix_hash(ephemeral.public_key()); // h = H(h || sepk)
    let mut shared = ephemeral
        .agree(hop_static_public)
        .ok_or(I2PError::Malformed("tunnel build: invalid hop public key"))?;
    noise.mix_key(&shared);
    shared.zeroize();
    let mut ciphertext = [0u8; SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE];
    noise.encrypt(&clear, &mut ciphertext)?;
    noise.mix_hash(&ciphertext); // h = H(h || ciphertext)
    let keys = derive_record_keys(&noise, request.is_endpoint);

    let mut to_peer = [0u8; BUILD_RECORD_TO_PEER_SIZE];
    to_peer.copy_from_slice(&hop_ident.as_bytes()[..BUILD_RECORD_TO_PEER_SIZE]);
    let record = EncryptedShortRecord {
        to_peer,
        ephemeral_key: *ephemeral.public_key(),
        ciphertext,
    };
    Ok((record, keys))
}

/// Расшифровывает запрос (сторона хопа).
///
/// `static_keys` — X25519-ключи шифрования роутера. Проверку
/// `to_peer` вызывающий делает сам (например, через
/// [`crate::ShortTunnelBuildBody::find_record_for`]).
///
/// # Errors
///
/// [`I2PError::Malformed`], если ephemeral-ключ — точка малого
/// порядка, не сходится тег AEAD, повреждён clear text или
/// `layer_encryption_type != 0` (i2pd отвергает такие запросы).
pub fn decrypt_short_request(
    record: &EncryptedShortRecord,
    static_keys: &I2PX25519Keys,
) -> Result<(ShortBuildRequestRecord, RecordKeys)> {
    let mut noise = NoiseSymmetricState::new(&[0; 32], &[0; 32], &[0; 32]);
    init_noise_n_state(&mut noise, static_keys.public_key());
    noise.mix_hash(&record.ephemeral_key);
    let mut shared = static_keys
        .agree(&record.ephemeral_key)
        .ok_or(I2PError::Malformed("tunnel build: invalid ephemeral key"))?;
    noise.mix_key(&shared);
    shared.zeroize();
    let mut clear = [0u8; SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE];
    noise.decrypt(&record.ciphertext, &mut clear)?;
    noise.mix_hash(&record.ciphertext);
    let request = ShortBuildRequestRecord::from_clear_text(&clear)?;
    if request.layer_encryption_type != 0 {
        return Err(I2PError::Malformed(
            "tunnel build: unsupported layer encryption type",
        ));
    }
    let keys = derive_record_keys(&noise, request.is_endpoint);
    Ok((request, keys))
}

/// Nonce записи: нули, `nonce[4] = индекс записи`.
fn record_nonce(index: usize) -> Result<[u8; 12]> {
    let idx = u8::try_from(index).map_err(|_| I2PError::Malformed("record index out of range"))?;
    let mut nonce = [0u8; 12];
    nonce[4] = idx;
    Ok(nonce)
}

/// `ChaCha20` (счётчик 1) поверх всей записи ключом `reply_key`.
///
/// Операция симметрична: одинаково добавляет и снимает слой.
///
/// # Errors
///
/// [`I2PError::Malformed`], если `index > 255`.
pub fn apply_reply_layer(
    reply_key: &[u8; 32],
    index: usize,
    record: &mut EncryptedShortRecord,
) -> Result<()> {
    let nonce = record_nonce(index)?;
    let mut bytes = record.to_bytes();
    chacha20_counter1(reply_key, &nonce, &mut bytes);
    *record = EncryptedShortRecord::from_bytes(&bytes)?;
    Ok(())
}

/// Шифрует ответ хопа в его собственную запись (AEAD).
///
/// # Errors
///
/// Ошибки [`ShortBuildResponseRecord::to_plaintext`] и AEAD.
pub fn encrypt_reply_record(
    keys: &RecordKeys,
    index: usize,
    response: &ShortBuildResponseRecord,
) -> Result<EncryptedShortRecord> {
    let nonce = record_nonce(index)?;
    let plain = response.to_plaintext()?;
    let mut out = [0u8; SHORT_TUNNEL_BUILD_RECORD_SIZE];
    AeadChaCha20Poly1305::new().encrypt(&keys.reply_key, &nonce, &keys.h, &plain, &mut out)?;
    EncryptedShortRecord::from_bytes(&out)
}

/// Расшифровывает ответ хопа из его записи (AEAD).
///
/// # Errors
///
/// [`I2PError::Malformed`], если тег не сходится, и ошибки разбора
/// [`ShortBuildResponseRecord::from_plaintext`].
pub fn decrypt_reply_record(
    keys: &RecordKeys,
    index: usize,
    record: &EncryptedShortRecord,
) -> Result<ShortBuildResponseRecord> {
    let nonce = record_nonce(index)?;
    let mut plain = [0u8; SHORT_RESPONSE_PLAINTEXT_SIZE];
    AeadChaCha20Poly1305::new().decrypt(
        &keys.reply_key,
        &nonce,
        &keys.h,
        &record.to_bytes(),
        &mut plain,
    )?;
    ShortBuildResponseRecord::from_plaintext(&plain)
}

/// Сторона хопа: заменяет запись `own_index` ответом, остальные
/// записи пропускает через `ChaCha20`.
///
/// # Errors
///
/// [`I2PError::Malformed`], если `own_index` вне `records`, и ошибки
/// [`encrypt_reply_record`].
pub fn encrypt_reply_records(
    keys: &RecordKeys,
    own_index: usize,
    response: &ShortBuildResponseRecord,
    records: &mut [EncryptedShortRecord],
) -> Result<()> {
    if own_index >= records.len() {
        return Err(I2PError::Malformed("own record index out of range"));
    }
    for (j, rec) in records.iter_mut().enumerate() {
        if j == own_index {
            *rec = encrypt_reply_record(keys, j, response)?;
        } else {
            apply_reply_layer(&keys.reply_key, j, rec)?;
        }
    }
    Ok(())
}

/// Ключи хопа и номер его записи — для сборки и разбора сообщения
/// на стороне отправителя. Порядок элементов — порядок хопов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopCrypto {
    /// Ключи, возвращённые [`encrypt_short_request`].
    pub keys: RecordKeys,
    /// Индекс записи хопа в сообщении.
    pub record_index: usize,
}

fn check_indices(hops: &[HopCrypto], records_len: usize) -> Result<()> {
    let mut seen = vec![false; records_len];
    for hop in hops {
        let slot = seen
            .get_mut(hop.record_index)
            .ok_or(I2PError::Malformed("record index out of range"))?;
        if *slot {
            return Err(I2PError::Malformed("duplicate record index"));
        }
        *slot = true;
    }
    Ok(())
}

/// Сторона отправителя: «расшифровывает» записи поздних хопов
/// ключами предыдущих, чтобы слои сократились по пути (см. модуль).
///
/// Вызывается после того, как все запросы зашифрованы
/// ([`encrypt_short_request`]) и записи лежат на своих индексах.
///
/// # Errors
///
/// [`I2PError::Malformed`] при неверных или повторяющихся индексах.
pub fn pre_decrypt_records(hops: &[HopCrypto], records: &mut [EncryptedShortRecord]) -> Result<()> {
    check_indices(hops, records.len())?;
    for (k, hop) in hops.iter().enumerate() {
        for later in &hops[k + 1..] {
            apply_reply_layer(
                &hop.keys.reply_key,
                later.record_index,
                &mut records[later.record_index],
            )?;
        }
    }
    Ok(())
}

/// Сторона отправителя: снимает слои и расшифровывает ответы всех
/// хопов. Возвращает ответы в порядке хопов. `records` при этом
/// модифицируются (слои снимаются на месте).
///
/// # Errors
///
/// [`I2PError::Malformed`] при неверных индексах и при неудачной
/// проверке AEAD любого хопа.
pub fn decrypt_build_reply(
    hops: &[HopCrypto],
    records: &mut [EncryptedShortRecord],
) -> Result<Vec<ShortBuildResponseRecord>> {
    check_indices(hops, records.len())?;
    let mut responses = Vec::with_capacity(hops.len());
    for k in (0..hops.len()).rev() {
        let hop = &hops[k];
        responses.push(decrypt_reply_record(
            &hop.keys,
            hop.record_index,
            &records[hop.record_index],
        )?);
        for earlier in &hops[..k] {
            apply_reply_layer(
                &hop.keys.reply_key,
                earlier.record_index,
                &mut records[earlier.record_index],
            )?;
        }
    }
    responses.reverse();
    Ok(responses)
}
