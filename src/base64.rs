//! I2P base64: алфавит `A-Za-z0-9-~` с padding `=`.
//!
//! Отличия от RFC 4648: символы 62/63 — `-` и `~` вместо `+` и `/`.

use crate::error::{I2PError, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
const PAD: u8 = b'=';

#[inline]
const fn decode_char(c: u8) -> Result<u8> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'-' => Ok(62),
        b'~' => Ok(63),
        _ => Err(I2PError::InvalidBase64(c)),
    }
}

/// Кодирует байты в base64 без padding.
#[must_use]
pub fn encode_no_pad(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, rem) = data.as_chunks::<3>();

    for c in chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
    }

    match rem.len() {
        0 => {}
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => unreachable!("chunks_exact(3).remainder() возвращает 0..=2"),
    }
    out
}

/// Кодирует байты в base64 с padding `=`.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut s = encode_no_pad(data);
    while !s.len().is_multiple_of(4) {
        s.push(PAD as char);
    }
    s
}

/// Декодирует base64, принимая оба варианта: с padding и без.
///
/// Padding `=` допускается только в конце.
///
/// # Errors
///
/// - [`Error::InvalidBase64`] — недопустимый символ во входе.
/// - [`Error::NonCanonical`] — неверная длина (1 мод 4) или значащие биты
///   в хвосте.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim_end_matches(PAD as char);
    let trimmed_len = trimmed.len();
    if trimmed_len % 4 == 1 {
        return Err(I2PError::NonCanonical);
    }

    let mut out = Vec::with_capacity(trimmed_len / 4 * 3 + 2);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;

    for &b in trimmed.as_bytes() {
        let v = u32::from(decode_char(b)?);
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    if nbits > 0 && (bits & ((1u32 << nbits) - 1)) != 0 {
        return Err(I2PError::NonCanonical);
    }
    Ok(out)
}

/// Декодирует base64 ровно в `N` байт.
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
