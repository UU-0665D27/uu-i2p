//! Сборка `ShortTunnelBuild` и разбор ответа на стороне создателя туннеля.
//!
//! Соответствует `Tunnel::Build` и `Tunnel::HandleTunnelBuildResponse`
//! из `Tunnel.cpp`; шифрование записей — в
//! [`crate::tunnel_build_crypto`].
//!
//! ## Сборка ([`build_short_tunnel_request`])
//!
//! 1. Для inbound-туннеля короче 8 хопов добавляется **phony-запись**:
//!    `to_peer` — наш ident, ephemeral-ключ настоящий, остальное
//!    случайное. Ключей у неё нет, в [`HopCrypto`] она не попадает.
//! 2. Число записей: 4, если хопов (с phony) не больше 4, иначе 8.
//! 3. Индексы записей — случайная перестановка `0..num_records`;
//!    первые `n` достаются настоящим хопам, следующий — phony.
//! 4. Все слоты заполняются случайными байтами, затем настоящие
//!    запросы и phony перезаписывают свои.
//! 5. Каждому хопу выбирается `send_msg_id`: случайный, кроме
//!    последнего — ему `reply_msg_id`.
//! 6. Записи поздних хопов (и phony) «расшифровываются» ключами
//!    предыдущих хопов ([`pre_decrypt_records`]).
//!
//! Ключи слоя, IV и ответа сразу записываются в [`TunnelHopConfig`].
//!
//! ## Разбор ответа ([`process_short_build_reply`])
//!
//! Снимает слои, проверяет AEAD каждого хопа и возвращает ответы по
//! порядку хопов; туннель построен, только если все хопы приняли.
//!
//! ## Отличия от i2pd
//!
//! - ГСЧ передаётся параметром (в i2pd — `tunnels.GetRng()` и
//!   `RAND_bytes`), поэтому сборка детерминирована при заданном ГСЧ;
//! - `hop_static_publics` — X25519-ключи шифрования хопов, которые
//!   вызывающий достаёт из `RouterInfo`;
//! - сборка I2NP-заголовка и отправка — на вызывающем.

use rand::Rng;
use zeroize::Zeroize;

use crate::crypto::I2PX25519Keys;
use crate::error::{I2PError, Result};
use crate::short_tunnel_build::ShortTunnelBuildBody;
use crate::tag::IdentHash;
use crate::tunnel_build_crypto::{
    HopCrypto, apply_reply_layer, decrypt_build_reply, encrypt_short_request, pre_decrypt_records,
    request_for_hop,
};
use crate::tunnel_build_record::{
    BUILD_RECORD_TO_PEER_SIZE, BuildRetCode, EncryptedShortRecord, NUM_TUNNEL_BUILD_RECORDS,
    OPTION_AVAILABLE_BANDWIDTH, SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE,
    SHORT_TUNNEL_BUILD_RECORD_SIZE, ShortBuildResponseRecord,
};
use crate::tunnel_config::TunnelConfig;

/// Число записей в «стандартном» сообщении (`STANDARD_NUM_RECORDS`).
pub const STANDARD_NUM_RECORDS: usize = 4;

/// Результат сборки запроса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortBuildRequest {
    /// Payload `ShortTunnelBuild` (до 8 записей).
    pub body: ShortTunnelBuildBody,
    /// Ключи настоящих хопов (без phony) по порядку хопов — нужны
    /// для разбора ответа и, для endpoint, для garlic-ответа.
    pub hops: Vec<HopCrypto>,
}

fn random_bytes<const N: usize>(rng: &mut impl Rng) -> [u8; N] {
    let mut buf = [0u8; N];
    rng.fill_bytes(&mut buf);
    buf
}

fn random_record(rng: &mut impl Rng) -> Result<EncryptedShortRecord> {
    let bytes = random_bytes::<SHORT_TUNNEL_BUILD_RECORD_SIZE>(rng);
    EncryptedShortRecord::from_bytes(&bytes)
}

/// Пара ephemeral-ключей из ГСЧ; сырой приватный ключ затирается.
fn random_keypair(rng: &mut impl Rng) -> I2PX25519Keys {
    let mut private = random_bytes::<32>(rng);
    let keys = I2PX25519Keys::from_private(&private, None);
    private.zeroize();
    keys
}

/// Случайная перестановка `0..len` (Fisher–Yates).
fn shuffled_indices(len: usize, rng: &mut impl Rng) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    for i in (1..len).rev() {
        let bound = u64::try_from(i).unwrap_or(0) + 1;
        let j = usize::try_from((u64::from(rng.next_u32()) * bound) >> 32).unwrap_or(0);
        order.swap(i, j);
    }
    order
}

/// Собирает `ShortTunnelBuild` для `config`.
///
/// `hop_static_publics[k]` — X25519-ключ шифрования `k`-го хопа.
/// `our_ident` используется как `to_peer` у phony-записи.
/// `request_time_minutes` — минуты с эпохи.
///
/// # Errors
///
/// [`I2PError::Malformed`], если число ключей не равно числу хопов,
/// ключ хопа — точка малого порядка, или не удалось зашифровать запрос.
/// При ошибке `config` может остаться изменённым частично (индексы и
/// ключи уже записаны) — такой конфиг нужно выбросить.
pub fn build_short_tunnel_request(
    config: &mut TunnelConfig,
    hop_static_publics: &[[u8; 32]],
    our_ident: &IdentHash,
    reply_msg_id: u32,
    request_time_minutes: u32,
    rng: &mut impl Rng,
) -> Result<ShortBuildRequest> {
    let n = config.num_hops();
    if hop_static_publics.len() != n {
        return Err(I2PError::Malformed(
            "tunnel build: wrong number of hop public keys",
        ));
    }
    let insert_phony = config.is_inbound() && n < NUM_TUNNEL_BUILD_RECORDS;
    let total = n + usize::from(insert_phony);
    let num_records = if total <= STANDARD_NUM_RECORDS {
        STANDARD_NUM_RECORDS
    } else {
        NUM_TUNNEL_BUILD_RECORDS
    };

    let order = shuffled_indices(num_records, rng);
    config.assign_record_indices(&order[..n])?;

    let mut records = (0..num_records)
        .map(|_| random_record(rng))
        .collect::<Result<Vec<_>>>()?;

    let mut hops = Vec::with_capacity(n);
    for (k, public) in hop_static_publics.iter().enumerate() {
        let hop = config.hops()[k].clone();
        let send_msg_id = if k + 1 < n {
            rng.next_u32()
        } else {
            reply_msg_id
        };
        let request = request_for_hop(&hop, request_time_minutes, send_msg_id);
        let ephemeral = random_keypair(rng);
        let (record, keys) = encrypt_short_request(&request, &hop.ident, public, &ephemeral)?;
        keys.apply_to(&mut config.hops_mut()[k]);
        records[hop.record_index] = record;
        hops.push(HopCrypto {
            keys,
            record_index: hop.record_index,
        });
    }

    let phony_index = insert_phony.then(|| order[n]);
    if let Some(idx) = phony_index {
        let mut to_peer = [0u8; BUILD_RECORD_TO_PEER_SIZE];
        to_peer.copy_from_slice(&our_ident.as_bytes()[..BUILD_RECORD_TO_PEER_SIZE]);
        records[idx] = EncryptedShortRecord {
            to_peer,
            ephemeral_key: *random_keypair(rng).public_key(),
            ciphertext: random_bytes::<SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE>(rng),
        };
    }

    pre_decrypt_records(&hops, &mut records)?;
    if let Some(idx) = phony_index {
        // phony — «последний хоп» для всех настоящих
        for hop in &hops {
            apply_reply_layer(&hop.keys.reply_key, idx, &mut records[idx])?;
        }
    }

    Ok(ShortBuildRequest {
        body: ShortTunnelBuildBody::new(records)?,
        hops,
    })
}

/// Разобранные ответы хопов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildReplyResult {
    /// Ответы в порядке хопов.
    pub responses: Vec<ShortBuildResponseRecord>,
}

impl BuildReplyResult {
    /// Все ли хопы приняли туннель.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.responses.iter().all(|r| r.ret.is_accept())
    }

    /// Первый отказавший хоп: его номер и код.
    #[must_use]
    pub fn first_rejection(&self) -> Option<(usize, BuildRetCode)> {
        self.responses
            .iter()
            .enumerate()
            .find(|(_, r)| !r.ret.is_accept())
            .map(|(k, r)| (k, r.ret))
    }

    /// Доступная полоса, объявленная хопом `hop` (КБ/с), если есть.
    #[must_use]
    pub fn available_bandwidth(&self, hop: usize) -> Option<u32> {
        self.responses
            .get(hop)?
            .options
            .get_u32(OPTION_AVAILABLE_BANDWIDTH)
    }
}

/// Разбирает `ShortTunnelBuildReply` (или ответ, пришедший как
/// `ShortTunnelBuild`) на стороне создателя.
///
/// `body.records` при этом модифицируются: слои снимаются на месте.
///
/// # Errors
///
/// [`I2PError::Malformed`], если индекс записи хопа вне сообщения
/// или AEAD какого-либо хопа не сошёлся.
pub fn process_short_build_reply(
    body: &mut ShortTunnelBuildBody,
    hops: &[HopCrypto],
) -> Result<BuildReplyResult> {
    let responses = decrypt_build_reply(hops, &mut body.records)?;
    Ok(BuildReplyResult { responses })
}
