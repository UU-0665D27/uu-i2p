//! SSU2 — криптографические примитивы.
//!
//! Noise XK и KDF'ы SSU2 поверх [`crate::crypto`].
//!
//! - [`init_noise_ssu2_state`] — инициализация [`NoiseSymmetricState`] для
//!   протокола `Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256`;
//! - [`sess_create_header_key`] — `k_header_2` для `SessionCreated`;
//! - [`session_confirmed_header_key`] — `k_header_2` для `SessionConfirmed`;
//! - [`derive_data_phase_keys`] — ключи data phase (`k_data` и
//!   `k_header_2` для обоих направлений);
//! - [`aead_nonce`] — counter-based nonce.
//!
//! ## Что не внутри
//!
//! - Разбор/обфускация заголовков — в [`crate::ssu2_header`];
//! - сам handshake (рассылка `SessionRequest` / `SessionCreated` /
//!   `SessionConfirmed`) — следующий слой.
//!
//! ## Соответствие i2pd
//!
//! Функции повторяют `InitNoiseXKState1` (`Crypto.cpp`) и
//! `KDFDataPhase` (`SSU2Session.cpp`). Важная деталь: i2pd вызывает `HKDF`
//! с нулевой длиной ключа (`ZEROLEN`), что эквивалентно стандартному
//! HKDF-Extract с пустым `ikm` и последующим Expand — именно так работает
//! [`crate::crypto::hkdf`] при `key = &[]`.

use crate::crypto::{hkdf, NoiseSymmetricState};

/// Информационная строка KDF для `k_header_2` сообщения `SessionCreated`.
const INFO_SESS_CREATE_HEADER: &[u8] = b"SessCreateHeader";

/// Информационная строка KDF для `k_header_2` сообщения `SessionConfirmed`.
const INFO_SESSION_CONFIRMED: &[u8] = b"SessionConfirmed";

/// Информационная строка KDF для ключей data phase.
const INFO_DATA_KEYS: &[u8] = b"HKDFSSU2DataKeys";

/// Инициализирует [`NoiseSymmetricState`] для SSU2 (`Noise_XK`).
///
/// Соответствует `InitNoiseXKState1` из `Crypto.cpp`. `pub_key` — статический
/// публичный ключ Bob'а (`s` из его `RouterInfo`). После вызова
/// `state.h = SHA256(SHA256(SHA256(protocol_name)) || pub_key)`.
pub fn init_noise_ssu2_state(state: &mut NoiseSymmetricState, pub_key: &[u8; 32]) {
    const PROTOCOL_NAME_HASH: [u8; 32] = [
        0xb1, 0x37, 0x22, 0x81, 0x74, 0x23, 0xa8, 0xfd, 0xf4, 0x2d, 0xf2, 0xe6, 0x0e, 0xd1, 0xed,
        0xf4, 0x1b, 0x93, 0x07, 0x1d, 0xb1, 0xec, 0x24, 0xa3, 0x67, 0xf7, 0x84, 0xec, 0x27, 0x0d,
        0x81, 0x32,
    ];
    const HH: [u8; 32] = [
        0xdc, 0x85, 0xe6, 0xaf, 0x7b, 0x02, 0x65, 0x0c, 0xf1, 0xf9, 0x0d, 0x71, 0xfb, 0xc6, 0xd4,
        0x53, 0xa7, 0xcf, 0x6d, 0xbf, 0xbd, 0x52, 0x5e, 0xa5, 0xb5, 0x79, 0x1c, 0x47, 0xb3, 0x5e,
        0xbc, 0x33,
    ];
    *state = NoiseSymmetricState::new(&PROTOCOL_NAME_HASH, &HH, pub_key);
}

/// `k_header_2` для `SessionCreated` из chaining key `ck`.
///
/// `HKDF(ck, ZEROLEN, "SessCreateHeader", 32)`.
#[must_use]
pub fn sess_create_header_key(ck: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf(ck, &[], INFO_SESS_CREATE_HEADER, &mut out);
    out
}

/// `k_header_2` для `SessionConfirmed` из chaining key `ck`.
///
/// `HKDF(ck, ZEROLEN, "SessionConfirmed", 32)`.
#[must_use]
pub fn session_confirmed_header_key(ck: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf(ck, &[], INFO_SESSION_CONFIRMED, &mut out);
    out
}

/// Ключи data phase для одного направления.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPhaseKey {
    /// AEAD-ключ `k_data`.
    pub k_data: [u8; 32],
    /// Ключ обфускации заголовка `k_header_2`.
    pub k_header_2: [u8; 32],
}

/// Ключи data phase для обоих направлений.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPhaseKeys {
    /// Направление Alice -> Bob.
    pub ab: DataPhaseKey,
    /// Направление Bob -> Alice.
    pub ba: DataPhaseKey,
}

/// Выводит ключи data phase из chaining key `ck`.
///
/// Соответствует `KDFDataPhase` из `SSU2Session.cpp`:
///
/// ```text
/// keydata = HKDF(ck, ZEROLEN, "", 64)
/// ab      = HKDF(keydata[0..32],  ZEROLEN, "HKDFSSU2DataKeys", 64)
/// ba      = HKDF(keydata[32..64], ZEROLEN, "HKDFSSU2DataKeys", 64)
/// ```
///
/// В каждом 64-байтовом результате первые 32 байта — `k_data`, вторые —
/// `k_header_2`.
#[must_use]
pub fn derive_data_phase_keys(ck: &[u8; 32]) -> DataPhaseKeys {
    let mut keydata = [0u8; 64];
    hkdf(ck, &[], b"", &mut keydata);
    let ab = derive_directional_key(&keydata[..32]);
    let ba = derive_directional_key(&keydata[32..]);
    DataPhaseKeys { ab, ba }
}

/// Разворачивает 32-байтовый `keydata` направления в `k_data` + `k_header_2`.
fn derive_directional_key(keydata: &[u8]) -> DataPhaseKey {
    let mut out = [0u8; 64];
    hkdf(keydata, &[], INFO_DATA_KEYS, &mut out);
    let mut k_data = [0u8; 32];
    k_data.copy_from_slice(&out[..32]);
    let mut k_header_2 = [0u8; 32];
    k_header_2.copy_from_slice(&out[32..]);
    DataPhaseKey { k_data, k_header_2 }
}

/// Counter-based nonce: 4 нулевых байта, затем `counter` (LE u64).
///
/// В handshake-фазе `counter` — счётчик сообщений (`mix_key`), в data phase —
/// номер пакета из заголовка.
#[must_use]
pub const fn aead_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let bytes = counter.to_le_bytes();
    let mut i = 0;
    while i < 8 {
        nonce[4 + i] = bytes[i];
        i += 1;
    }
    nonce
}
