//! Ошибки базового слоя.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I2PError {
    /// Длина буфера не совпадает с ожидаемой.
    InvalidLength { expected: usize, got: usize },
    /// Недопустимый символ в base32-строке.
    InvalidBase32(u8),
    /// Недопустимый символ в base64-строке.
    InvalidBase64(u8),
    /// Хвост строки содержит значащие биты, которых не должно быть.
    NonCanonical,
    /// Неизвестный typeID в I2NP-заголовке.
    UnknownI2npType(u8),
    /// Неизвестный block type в NTCP2 data phase.
    UnknownNtcp2BlockType(u8),
    /// Неизвестный NTCP2 termination reason.
    UnknownNtcp2TerminationReason(u8),
    /// Неизвестный signing key type.
    UnknownSigningKeyType(u16),
    /// Неизвестный crypto key type.
    UnknownCryptoKeyType(u16),
    /// Формат данных нарушен (байтовая последовательность не соответствует
    /// ожидаемой структуре).
    Malformed(&'static str),
    /// Ошибка ввода-вывода при чтении файлов.
    Io(String),
    /// Функциональность не поддерживается текущей версией библиотеки.
    Unsupported(&'static str),
}

impl fmt::Display for I2PError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => {
                write!(f, "invalid length: expected {expected}, got {got}")
            }
            Self::InvalidBase32(c) => {
                write!(f, "invalid base32 character: {:?}", *c as char)
            }
            Self::InvalidBase64(c) => {
                write!(f, "invalid base64 character: {:?}", *c as char)
            }
            Self::NonCanonical => f.write_str("non-canonical encoding"),
            Self::UnknownI2npType(v) => {
                write!(f, "unknown I2NP message type: {v}")
            }
            Self::UnknownNtcp2BlockType(v) => {
                write!(f, "unknown NTCP2 block type: {v}")
            }
            Self::UnknownNtcp2TerminationReason(v) => {
                write!(f, "unknown NTCP2 termination reason: {v}")
            }
            Self::UnknownSigningKeyType(v) => {
                write!(f, "unknown signing key type: {v}")
            }
            Self::UnknownCryptoKeyType(v) => {
                write!(f, "unknown crypto key type: {v}")
            }
            Self::Malformed(msg) => write!(f, "malformed data: {msg}"),
            Self::Io(msg) => write!(f, "io error: {msg}"),
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
        }
    }
}

impl std::error::Error for I2PError {}

/// Удобный алиас для `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, I2PError>;
