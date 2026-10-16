//! I2P base32: алфавит `a-z2-7`, без padding, lowercase.
//!
//! Используется для `.b32.i2p` адресов и коротких имён роутеров.
//!
//! Отличия от RFC 4648:
//! - только lowercase;
//! - без символа `=` в конце;
//! - остаток бит (< 8) должен быть нулевым, иначе ошибка `NonCanonical`.

use crate::error::{I2PError, Result};

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[inline]
const fn decode_char(c: u8) -> Result<u8> {
    match c {
        b'a'..=b'z' => Ok(c - b'a'),
        b'2'..=b'7' => Ok(c - b'2' + 26),
        _ => Err(I2PError::InvalidBase32(c)),
    }
}

/// Кодирует байты в base32-строку (lowercase, без padding).
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;

    for &b in data {
        bits = (bits << 8) | u64::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// Декодирует base32-строку в байты.
///
/// # Errors
///
/// - [`Error::InvalidBase32`] — недопустимый символ во входе.
/// - [`Error::NonCanonical`] — строка содержит значащие биты в хвосте,
///   которые не помещаются в целый байт.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8 + 1);
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;

    for &b in s.as_bytes() {
        let v = u64::from(decode_char(b)?);
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xff) as u8);
        }
    }

    if nbits > 0 && (bits & ((1u64 << nbits) - 1)) != 0 {
        return Err(I2PError::NonCanonical);
    }
    Ok(out)
}

/// Декодирует base32-строку ровно в `N` байт.
///
/// # Errors
///
/// Возвращает те же ошибки, что [`decode`], плюс:
/// - [`Error::InvalidLength`] — длина результата не равна `N`.
pub fn decode_to<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = decode(s)?;
    if v.len() != N {
        return Err(I2PError::InvalidLength {
            expected: N,
            got: v.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}
