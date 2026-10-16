//! Big-endian / little-endian helpers.
//!
//! В I2P почти все многобайтные числа — **big-endian** (network order):
//! заголовки I2NP, `RouterInfo`, NTCP2, SSU2, туннельные сообщения.
//!
//! Исключение — **little-endian** в:
//! - SSU2 nonce (первые 4 байта — нули, потом `htole64` от packetNum);
//! - `SipHash` (внутри себя оперирует LE);
//! - `read_u32_le` для checksum в SSU2 header mask.
//!
//! ## Зачем свои хелперы
//!
//! `u32::from_be_bytes([b0, b1, b2, b3])` работает, но:
//! - раздувает call-site: `read_u32_be(&buf[8..12])` читается яснее;
//! - позволяет проверять границы на этапе тестов;
//! - централизованное место для будущих SIMD-оптимизаций.
//!
//! ## Конвенция имён
//!
//! - `read_uXX_be(b) -> uXX` — читает `XX/8` байт из начала среза;
//! - `write_uXX_be(b, v)` — пишет в первые `XX/8` байт среза.
//!
//! Функции **не проверяют длину** — как и i2pd, мы полагаемся на то, что
//! вызывающий код уже проверил размер буфера. Дополнительно тесты
//! проверяют, что чтение и запись — инверсны друг другу.

#![allow(clippy::cast_possible_truncation)] // read_uXX возвращает uXX, преобразования нет

// --- big-endian read -----------------------------------------------------

/// Читает `u16` big-endian из первых 2 байт.
#[must_use]
pub const fn read_u16_be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Читает `u32` big-endian из первых 4 байт.
#[must_use]
pub const fn read_u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Читает `u64` big-endian из первых 8 байт.
#[must_use]
pub const fn read_u64_be(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

// --- little-endian read --------------------------------------------------

/// Читает `u16` little-endian из первых 2 байт.
#[must_use]
pub const fn read_u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// Читает `u32` little-endian из первых 4 байт.
#[must_use]
pub const fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Читает `u64` little-endian из первых 8 байт.
#[must_use]
pub const fn read_u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

// --- big-endian write ----------------------------------------------------

/// Пишет `u16` big-endian в первые 2 байта.
pub fn write_u16_be(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_be_bytes());
}

/// Пишет `u32` big-endian в первые 4 байта.
pub fn write_u32_be(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_be_bytes());
}

/// Пишет `u64` big-endian в первые 8 байт.
pub fn write_u64_be(b: &mut [u8], v: u64) {
    b[..8].copy_from_slice(&v.to_be_bytes());
}

// --- little-endian write -------------------------------------------------

/// Пишет `u16` little-endian в первые 2 байта.
pub fn write_u16_le(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_le_bytes());
}

/// Пишет `u32` little-endian в первые 4 байта.
pub fn write_u32_le(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_le_bytes());
}

/// Пишет `u64` little-endian в первые 8 байт.
pub fn write_u64_le(b: &mut [u8], v: u64) {
    b[..8].copy_from_slice(&v.to_le_bytes());
}
