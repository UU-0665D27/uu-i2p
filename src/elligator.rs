//! Elligator2 — обратимое кодирование X25519-ключей в
//! «равномерный шум».
//!
//! Используется в ECIES-X25519-AEAD-Ratchet: эфемерный публичный
//! ключ Alice'а в NS (и Bob'а в NSR) передаётся не «как есть», а
//! как псевдослучайное 32-байтовое значение. Без этого наблюдатель
//! мог бы легко отличить handshake-трафик I2P от случайных байт
//! по алгебраической структуре точек Curve25519.
//!
//! Соответствует `Elligator2` из `Elligator.cpp` / `Elligator.h`.
//!
//! ## API
//!
//! - [`encode`] — обратимо кодирует ключ при заданном `high_y`;
//! - [`encode_random`] — как i2pd: `high_y` и два старших бита
//!   берутся из RNG (используется в ECIES ratchet);
//! - [`decode`] — восстанавливает ключ из 32-байтового
//!   представления.
//!
//! ## Математика
//!
//! `p = 2^255 − 19`. `A = 486662`, `u = 2` (невычет, потому что
//! `p ≡ 5 (mod 8)`). Отображение `r → x`:
//!
//! ```text
//!   v = −A / (1 + u·r²)
//!   t = v³ + A·v² + v
//!   x = v,        если Legendre(t) = 1
//!   x = −v − A,   иначе
//! ```
//!
//! Обратное отображение `x → r`:
//!
//! ```text
//!   xA = −x − A
//!   r² = x / (xA · u)   (при high_y = false)
//!   r² = xA / (x · u)   (при high_y = true)
//!   r  = √(r²)
//! ```
//!
//! `r` всегда приводится к диапазону `[0, (p−1)/2]`, поэтому
//! старшие 2 бита 32-байтового представления можно использовать
//! под случайный шум (decode их отбрасывает).
//!
//! ## Что НЕ реализовано
//!
//! - кэш «ineligible» ключей: в i2pd `X25519Keys` помечается как
//!   невычислимый, если `Encode` не сработал, и не пробуется
//!   повторно. У нас `encode` просто возвращает `None`, а решение
//!   «что с этим делать» — на вызывающем коде.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::Rng;
use std::sync::OnceLock;

// --- константы -----------------------------------------------------------

/// Простое число поля Curve25519: `2^255 − 19`.
fn curve25519_p() -> BigUint {
    (BigUint::one() << 255) - BigUint::from(19u32)
}

// --- модульная арифметика -----------------------------------------------

/// `a^{−1} mod p` через малую теорему Ферма (`a^{p−2} mod p`).
///
/// `None`, если `a ≡ 0`: у нуля нет обратного.
fn mod_inv(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    if a.is_zero() {
        return None;
    }
    let exp = p - BigUint::from(2u32);
    Some(a.modpow(&exp, p))
}

/// `(a − b) mod p`. Корректно для любых `a, b` в `[0, p)`.
fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    // a + p всегда ≥ b при a, b < p.
    ((a + p) - b) % p
}

// --- Constants -----------------------------------------------------------

/// Предвычисленные константы Elligator2.
///
/// Все зависят только от `p` и `A`, считаются один раз при первом
/// обращении через [`constants`].
struct Constants {
    /// `p = 2^255 − 19`.
    p: BigUint,
    /// `(p − 1) / 2` — показатель в символе Лежандра.
    p12: BigUint,
    /// `(p − 1) / 4` — показатель в `sqrt(-1)` и промежуточный в `sqrt`.
    p14: BigUint,
    /// `(p + 3) / 8` — показатель в `sqrt`.
    p38: BigUint,
    /// Коэффициент Montgomery-кривой: `486662`.
    a: BigUint,
    /// `−A mod p`.
    na: BigUint,
    /// Невычет `u = 2` (Legendre(2) = −1, т.к. `p ≡ 5 (mod 8)`).
    u: BigUint,
    /// `1/u mod p = (p + 1) / 2` (для `u = 2`).
    iu: BigUint,
    /// `sqrt(−1) mod p = 2^{(p−1)/4}`.
    sqrtn1: BigUint,
}

impl Constants {
    fn new() -> Self {
        let p = curve25519_p();
        let p12 = (&p - BigUint::one()) >> 1;
        let p14 = (&p - BigUint::one()) >> 2;
        let p38 = (&p + BigUint::from(3u32)) >> 3;
        let a = BigUint::from(486_662_u32);
        let na = &p - &a;
        let u = BigUint::from(2u32);
        // 1/2 mod p = (p + 1) / 2.
        let iu = (&p + BigUint::one()) >> 1;
        // sqrt(−1) = u^{(p−1)/4} = 2^{(p−1)/4}.
        let sqrtn1 = u.modpow(&p14, &p);
        Self {
            p,
            p12,
            p14,
            p38,
            a,
            na,
            u,
            iu,
            sqrtn1,
        }
    }

    /// Символ Лежандра: `1` для квадратичного вычета, `0` для нуля,
    /// `−1` для невычета.
    fn legendre(&self, a: &BigUint) -> i32 {
        if a.is_zero() {
            return 0;
        }
        let r = a.modpow(&self.p12, &self.p);
        if r.is_one() {
            1
        } else if r.is_zero() {
            0
        } else {
            -1
        }
    }

    /// `√x mod p` по алгоритму i2pd (`SquareRoot`).
    ///
    /// Возвращает одно из двух значений квадратного корня;
    /// какое именно — совпадает с i2pd.
    fn sqrt(&self, x: &BigUint) -> BigUint {
        // t = x^{(p−1)/4}
        let mut t = x.modpow(&self.p14, &self.p);
        // r = x^{(p+3)/8}
        let mut r = x.modpow(&self.p38, &self.p);
        t += BigUint::one();
        if t == self.p {
            // x^{(p−1)/4} = −1 mod p — умножаем на √(−1).
            r = (r * &self.sqrtn1) % &self.p;
        }
        // Приводим к диапазону [0, (p−1)/2].
        if r > self.p12 {
            r = &self.p - &r;
        }
        r
    }
}

fn constants() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(Constants::new)
}

// --- вспомогательные преобразования -------------------------------------

/// `[u8; 32]` в LE-форме → `BigUint` (BE-интерпретация байтов,
/// прочитанных наоборот).
fn le_bytes_to_biguint(le: &[u8; 32]) -> BigUint {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    BigUint::from_bytes_be(&be)
}

/// `BigUint` → `[u8; 32]` в LE-форме. `None`, если значение
/// не влезает в 32 байта (на практике не случается: `value < p`).
fn biguint_to_le_bytes(value: &BigUint) -> Option<[u8; 32]> {
    let be = value.to_bytes_be();
    if be.len() > 32 {
        return None;
    }
    let mut be_padded = [0u8; 32];
    be_padded[32 - be.len()..].copy_from_slice(&be);
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be_padded[31 - i];
    }
    Some(le)
}

// --- encode --------------------------------------------------------------

/// Кодирует 32-байтовый X25519-ключ (в LE, как в wire-формате I2P)
/// в 32-байтовое «равномерное» представление.
///
/// Возвращает `None`, если ключ не представим в образе Elligator2
/// (примерно половина ключей). Caller должен сгенерировать другой
/// ключ и попробовать снова.
///
/// `high_y` — какой из двух вариантов обратного отображения
/// использовать. Оба дают корректный round-trip;
/// [`encode_random`] выбирает его случайно, как i2pd.
///
/// Старшие 2 бита вывода всегда нулевые. Если нужно их
/// рандомизировать — [`encode_random`] или `out[31] |= bits`.
#[must_use]
pub fn encode(key: &[u8; 32], high_y: bool) -> Option<[u8; 32]> {
    let c = constants();

    let x = le_bytes_to_biguint(key);

    // xA = p − (x + A) mod p = −x − A.
    let xa = mod_sub(&c.p, &((&x + &c.a) % &c.p), &c.p);

    // uxxA = u · x · xA mod p.
    let uxxa = (&c.u * &x % &c.p) * &xa % &c.p;

    // Encode возможен, только если uxxA — квадратичный вычет
    // или ноль. Иначе у ключа нет прообраза.
    if c.legendre(&uxxa) == -1 {
        return None;
    }

    // r = (xA / x) / u   (high_y = true)
    // r = ( x / xA) / u  (high_y = false)
    let r_inner = if high_y {
        let inv_x = mod_inv(&x, &c.p)?;
        (inv_x * &xa) % &c.p
    } else {
        let inv_xa = mod_inv(&xa, &c.p)?;
        (inv_xa * &x) % &c.p
    };
    let r_val = (r_inner * &c.iu) % &c.p;

    let r = c.sqrt(&r_val);
    biguint_to_le_bytes(&r)
}

/// Кодирует, случайно выбирая `high_y` и случайно заполняя два
/// старших бита.
///
/// Соответствует `Encode(key, buf, /*highY=*/false, /*random=*/true)`
/// в i2pd — именно так это используется в
/// `ECIESX25519AEADRatchetSession::GenerateEphemeralKeysAndEncode`.
#[must_use]
pub fn encode_random(key: &[u8; 32], rng: &mut impl Rng) -> Option<[u8; 32]> {
    let rb = (rng.next_u32() & 0xFF) as u8;
    let high_y = rb & 0x01 != 0;
    let mut out = encode(key, high_y)?;
    // Top 2 bits в LE-форме — это биты 6,7 последнего байта.
    out[31] |= rb & 0xC0;
    Some(out)
}

// --- decode --------------------------------------------------------------

/// Декодирует 32-байтовое представление в 32-байтовый X25519-ключ.
///
/// Возвращает `None`, если представление не является образом
/// ни одного ключа (например, значение больше `(p−1)/2`).
#[must_use]
pub fn decode(encoded: &[u8; 32]) -> Option<[u8; 32]> {
    let params = constants();

    // Отбрасываем два верхних бита — они зашумлены
    // [`encode_random`].
    let mut enc_le = *encoded;
    enc_le[31] &= 0x3F;
    let r_input = le_bytes_to_biguint(&enc_le);

    // Декодируемо только r ≤ (p−1)/2.
    if r_input > params.p12 {
        return None;
    }

    // v = −A / (1 + u·r²) mod p.
    let r_squared = (&r_input * &r_input) % &params.p;
    let denominator = ((&params.u * &r_squared) % &params.p + BigUint::one()) % &params.p;
    let inv_denom = mod_inv(&denominator, &params.p)?;
    let v_value = (&params.na * inv_denom) % &params.p;

    // t = v³ + A·v² + v mod p.
    let v_squared = (&v_value * &v_value) % &params.p;
    let v_cubed = (&v_squared * &v_value) % &params.p;
    let t_value = ((&params.a * &v_squared) % &params.p + &v_cubed + &v_value) % &params.p;

    // x = v при Legendre(t) = 1; иначе x = −v − A.
    let x_value = if params.legendre(&t_value) == 1 {
        v_value
    } else {
        mod_sub(&params.p, &((&v_value + &params.a) % &params.p), &params.p)
    };

    biguint_to_le_bytes(&x_value)
}
