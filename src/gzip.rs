//! gzip-сжатие для I2NP payload.
//!
//! В `DatabaseStore` (type=0, `RouterInfo`) payload сжимается gzip'ом
//! с 2-байтовым префиксом длины. Иногда вместо сжатия пишется
//! gzip-контейнер с "stored"-блоком (без сжатия) — это быстрее для
//! маленьких сообщений, а формат контейнера совместим.
//!
//! Реализовано поверх `flate2` (`rust_backend`, чистый Rust).

use crate::error::{I2PError, Result};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::io::{Read, Write};

/// Сжимает `data` в gzip-контейнер.
///
/// # Errors
///
/// [`Error::Io`], если что-то не так с буферами (на практике
/// невозможно для `Vec`-based writer'а).
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| I2PError::Io(e.to_string()))?;
    encoder.finish().map_err(|e| I2PError::Io(e.to_string()))
}

/// Разжимает gzip-контейнер. Принимает и `deflate`-сжатый,
/// и `stored`-формат — `flate2` разбирает оба автоматически.
///
/// # Errors
///
/// [`Error::Malformed`], если данные не являются валидным gzip'ом.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|_| I2PError::Malformed("gzip: decompression failed"))?;
    Ok(out)
}
