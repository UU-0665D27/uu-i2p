//! SipHash-2-4 — keyed хеш, используемый в NTCP2.
//!
//! NTCP2 применяет SipHash-2-4 с 16-байтовым ключом в двух местах:
//!
//! - **обфускация длины фрейма**: 2 байта от `SipHash` XOR'ятся с
//!   префиксом длины каждого фрейма (см. `NTCP2Session::SetNextSentFrameLength`);
//! - **SipHash-based IV counter** при handshake'е — IV обновляется
//!   от фрейма к фрейму через тот же примитив.
//!
//! Реализация следует референсному описанию (Aumasson, Bernstein):
//! <https://131002.net/siphash/siphash.pdf>. Совпадает с i2pd
//! (`Siphash.h`) в константах init, порядке раундов и little-endian
//! входе.
//!
//! ## API
//!
//! Одна stateless-функция [`siphash24`], возвращающая `u64`. Раскладка
//! в 8 LE-байт — забота вызывающего кода (в NTCP2 это делается один
//! раз — при XOR с длиной). Потокового варианта нет: i2pd каждый раз
//! инициализирует контекст заново, апдейтит его ровно одним буфером
//! и финализирует — то же самое, что один вызов [`siphash24`].

/// Инициализационная константа `v0`.
const V0_INIT: u64 = 0x736f_6d65_7073_6575;
/// Инициализационная константа `v1`.
const V1_INIT: u64 = 0x646f_7261_6e64_6f6d;
/// Инициализационная константа `v2`.
const V2_INIT: u64 = 0x6c79_6765_6e65_7261;
/// Инициализационная константа `v3`.
const V3_INIT: u64 = 0x7465_6462_7974_6573;

/// Число «compression»-раундов между блоками данных.
const C_ROUNDS: u32 = 2;
/// Число «finalization»-раундов в конце.
const D_ROUNDS: u32 = 4;

#[inline]
const fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// SipHash-2-4 с 16-байтовым ключом.
///
/// Возвращает 64-битовый хеш. Раскладывается в 8 LE-байт — как в i2pd.
///
/// Ключ читается как два LE-`u64`: `k0 = key[0..8]`, `k1 = key[8..16]`.
/// Входные блоки данных — тоже LE.
#[must_use]
pub fn siphash24(data: &[u8], key: &[u8; 16]) -> u64 {
    // Индексы 0..16 — гарантированно в границах `[u8; 16]`,
    // panic невозможен, `expect`/`unwrap` не нужны.
    let k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    let mut v0 = k0 ^ V0_INIT;
    let mut v1 = k1 ^ V1_INIT;
    let mut v2 = k0 ^ V2_INIT;
    let mut v3 = k1 ^ V3_INIT;

    let len = data.len();

    // 8-байтовые блоки
    let (chunks, remainder) = data.as_chunks::<8>();
    for chunk in chunks {
        let m = u64::from_le_bytes(*chunk);
        v3 ^= m;
        for _ in 0..C_ROUNDS {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= m;
    }

    // Последний блок: старший байт = длина mod 256, младшие = хвост.
    let mut b = ((len as u64) & 0xff) << 56;
    for (i, &byte) in remainder.iter().enumerate() {
        b |= u64::from(byte) << (i * 8);
    }
    v3 ^= b;
    for _ in 0..C_ROUNDS {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^= b;

    // Finalization
    v2 ^= 0xff;
    for _ in 0..D_ROUNDS {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}
/// SipHash-2-4 в 128-битном режиме, возвращает **первое**
/// 64-битное слово. Совпадает с `h[0..8]` из `i2p::crypto::Siphash<16>`.
///
/// Отличия от [`siphash24`]:
/// - начальное `v1 ^= 0xee`;
/// - финальное `v2 ^= 0xee` (вместо `v2 ^= 0xff`).
///
/// Используется в [`crate::ident_metrics::PeerOrdering`], где
/// i2pd вызывает `Siphash<16>` и берёт первый байт результата.
#[must_use]
pub fn siphash24_128bit_first_word(data: &[u8], key: &[u8; 16]) -> u64 {
    let k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    let mut v0 = k0 ^ V0_INIT;
    let mut v1 = k1 ^ V1_INIT ^ 0xee; // <-- 128-битный режим
    let mut v2 = k0 ^ V2_INIT;
    let mut v3 = k1 ^ V3_INIT;

    let len = data.len();

    let (chunks, remainder) = data.as_chunks::<8>();
    for chunk in chunks {
        let m = u64::from_le_bytes(*chunk);
        v3 ^= m;
        for _ in 0..C_ROUNDS {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= m;
    }

    let mut b = ((len as u64) & 0xff) << 56;
    for (i, &byte) in remainder.iter().enumerate() {
        b |= u64::from(byte) << (i * 8);
    }
    v3 ^= b;
    for _ in 0..C_ROUNDS {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^= b;

    v2 ^= 0xee; // <-- 128-битный режим
    for _ in 0..D_ROUNDS {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}
