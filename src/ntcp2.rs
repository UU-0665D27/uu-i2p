//! NTCP2 — TCP-транспорт с обфускацией и Noise XK.
//!
//! Здесь живут константы протокола, типы блоков и Termination-reason,
//! а также [`Ntcp2Establisher`] — ядро handshake'а (Noise XK + KDF).
//!
//! ## Что реализовано (шаг 2y-1)
//!
//! - Константы протокола;
//! - [`Ntcp2BlockType`] и [`Ntcp2TerminationReason`];
//! - [`Ntcp2Establisher`] с KDF1/KDF2/KDF3 для Alice и Bob.
//!
//! ## Что дальше
//!
//! - Обфускация длины фрейма (`create_header_mask`, SipHash-based IV) — 2y-2;
//! - `SessionRequest` / `SessionCreated` / `SessionConfirmed` — 2y-3..2y-5;
//! - Data phase (фрейминг блоков) — 2y-6;
//! - tokio-сессия — 2y-7.

use crate::{
    crypto::{
        AeadChaCha20Poly1305, Aes256Cbc, I2PX25519Keys, NoiseSymmetricState, hkdf,
        init_noise_xk_state,
    },
    error::{I2PError, Result},
    i2np_message::I2npMessage,
    router_info::FullRouterInfo,
    router_info_address::I2PAddress,
    siphash::siphash24,
};
use rand::{
    Rng, SeedableRng,
    rngs::{StdRng, SysRng},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, info, trace, warn};

// --- лимиты --------------------------------------------------------------

/// Максимальный размер незашифрованного фрейма.
///
/// Все данные после обфускации (без 2-байтового префикса длины) не
/// должны превышать это значение. Совпадает с
/// `NTCP2_UNENCRYPTED_FRAME_MAX_SIZE` в i2pd.
pub const NTCP2_UNENCRYPTED_FRAME_MAX_SIZE: usize = 65519;

/// Порог, после которого NTCP2 отправляет накопленный фрейм, не
/// дожидаясь заполнения очереди.
pub const NTCP2_SEND_AFTER_FRAME_SIZE: usize = 16386;

/// Максимальный размер `SessionRequest` / `SessionCreated` без ML-KEM-фрейма.
pub const NTCP2_SESSION_HANDSHAKE_MAX_SIZE: usize = 287;

/// Максимальный размер `SessionRequest` / `SessionCreated` для не-PQ
/// роутеров (legacy, с длинным padding'ом).
pub const NTCP2_SESSION_HANDSHAKE_LONG_MAX_SIZE: usize = 944;

/// Максимальный размер padding'а в `SessionRequest` / `SessionCreated`.
///
/// Это `NTCP2_SESSION_HANDSHAKE_MAX_SIZE - 64`, где 64 — фиксированный
/// минимум (32 X/Y + 32 options). В i2pd то же число получается как
/// `maxPaddingLength = NTCP2_SESSION_HANDSHAKE_MAX_SIZE - 64`.
pub const NTCP2_MAX_HANDSHAKE_PADDING_LEN: u16 = 223;

/// Максимальный «процент» padding'а относительно длины сообщения.
pub const NTCP2_MAX_PADDING_RATIO: usize = 6;

/// Таймаут установления TCP-соединения.
pub const NTCP2_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Таймаут установления NTCP2-сессии (handshake).
pub const NTCP2_ESTABLISH_TIMEOUT_SECS: u64 = 10;

/// Таймаут бездействия установленной сессии.
pub const NTCP2_TERMINATION_TIMEOUT_SECS: u64 = 115;

/// Вариация таймаута бездействия.
pub const NTCP2_TERMINATION_TIMEOUT_VARIANCE_SECS: u64 = 10;

/// Период фоновой проверки сессий на termination.
pub const NTCP2_TERMINATION_CHECK_TIMEOUT_SECS: u64 = 28;

/// Вариация периода проверки сессий.
pub const NTCP2_TERMINATION_CHECK_TIMEOUT_VARIANCE_SECS: u64 = 5;

/// Таймаут удаления буфера приёмки, если в него ничего не пришло.
pub const NTCP2_RECEIVE_BUFFER_DELETION_TIMEOUT_SECS: u64 = 3;

/// Интервал пересылки собственного `RouterInfo` peer'у.
pub const NTCP2_ROUTERINFO_RESEND_INTERVAL_SECS: u64 = 25 * 60;

/// Вариация интервала пересылки `RouterInfo`.
pub const NTCP2_ROUTERINFO_RESEND_INTERVAL_VARIANCE_SECS: u64 = 25 * 60;

/// Допустимый clock skew при handshake.
pub const NTCP2_CLOCK_SKEW_SECS: u64 = 60;

/// Максимальный размер очереди исходящих сообщений до принудительного
/// разрыва сессии.
pub const NTCP2_MAX_OUTGOING_QUEUE_SIZE: usize = 500;

/// Флаг `RouterInfo`-блока: запросить у peer'а его RI (flood).
pub const NTCP2_ROUTER_INFO_FLAG_REQUEST_FLOOD: u8 = 0x01;

// --- типы блоков ---------------------------------------------------------

/// Тип блока в data phase NTCP2.
///
/// Значения совпадают с `enum NTCP2BlockType` в i2pd. Неизвестные
/// значения нужно пропускать (как это делает i2pd в `ProcessNextFrame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ntcp2BlockType {
    /// Метка времени (seconds since epoch, BE u32).
    DateTime = 0,
    /// Опции — сейчас не используются.
    Options = 1,
    /// `RouterInfo` peer'а.
    RouterInfo = 2,
    /// Вложенное I2NP-сообщение.
    I2npMessage = 3,
    /// Termination.
    Termination = 4,
    /// Padding.
    Padding = 254,
}

impl Ntcp2BlockType {
    /// Парсит `u8` из wire.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownNtcp2BlockType`], если значение не описано.
    pub const fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::DateTime,
            1 => Self::Options,
            2 => Self::RouterInfo,
            3 => Self::I2npMessage,
            4 => Self::Termination,
            254 => Self::Padding,
            _ => return Err(I2PError::UnknownNtcp2BlockType(v)),
        })
    }

    /// Числовое значение для wire.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Человекочитаемое имя для логов.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DateTime => "DateTime",
            Self::Options => "Options",
            Self::RouterInfo => "RouterInfo",
            Self::I2npMessage => "I2NPMessage",
            Self::Termination => "Termination",
            Self::Padding => "Padding",
        }
    }
}

impl std::fmt::Display for Ntcp2BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// --- причины завершения --------------------------------------------------

/// Причина завершения NTCP2-сессии (поле reason в Termination-блоке).
///
/// Значения совпадают с `enum NTCP2TerminationReason` в i2pd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ntcp2TerminationReason {
    /// Нормальное закрытие.
    NormalClose = 0,
    /// Получен Termination от peer'а.
    TerminationReceived = 1,
    /// Idle timeout.
    IdleTimeout = 2,
    /// Роутер выключается.
    RouterShutdown = 3,
    /// Ошибка AEAD в data phase.
    DataPhaseAeadFailure = 4,
    /// Несовместимые опции.
    IncompatibleOptions = 5,
    /// Несовместимый тип подписи.
    IncompatibleSignatureType = 6,
    /// Clock skew.
    ClockSkew = 7,
    /// Нарушение правил padding'а.
    PaddingViolation = 8,
    /// Ошибка AEAD-фрейминга.
    AeadFramingError = 9,
    /// Ошибка формата payload'а.
    PayloadFormatError = 10,
    /// Ошибка в Message 1 (`SessionRequest`).
    Message1Error = 11,
    /// Ошибка в Message 2 (`SessionCreated`).
    Message2Error = 12,
    /// Ошибка в Message 3 (`SessionConfirmed`).
    Message3Error = 13,
    /// Таймаут внутри фрейма.
    IntraFrameReadTimeout = 14,
    /// Провал верификации подписи `RouterInfo`.
    RouterInfoSignatureVerificationFail = 15,
    /// Неверный параметр `s`.
    IncorrectSParameter = 16,
    /// Peer забанен.
    Banned = 17,
}

impl Ntcp2TerminationReason {
    /// Парсит `u8` из wire.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownNtcp2TerminationReason`], если значение не описано.
    pub const fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::NormalClose,
            1 => Self::TerminationReceived,
            2 => Self::IdleTimeout,
            3 => Self::RouterShutdown,
            4 => Self::DataPhaseAeadFailure,
            5 => Self::IncompatibleOptions,
            6 => Self::IncompatibleSignatureType,
            7 => Self::ClockSkew,
            8 => Self::PaddingViolation,
            9 => Self::AeadFramingError,
            10 => Self::PayloadFormatError,
            11 => Self::Message1Error,
            12 => Self::Message2Error,
            13 => Self::Message3Error,
            14 => Self::IntraFrameReadTimeout,
            15 => Self::RouterInfoSignatureVerificationFail,
            16 => Self::IncorrectSParameter,
            17 => Self::Banned,
            _ => return Err(I2PError::UnknownNtcp2TerminationReason(v)),
        })
    }

    /// Числовое значение для wire.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Человекочитаемое имя для логов.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NormalClose => "NormalClose",
            Self::TerminationReceived => "TerminationReceived",
            Self::IdleTimeout => "IdleTimeout",
            Self::RouterShutdown => "RouterShutdown",
            Self::DataPhaseAeadFailure => "DataPhaseAEADFailure",
            Self::IncompatibleOptions => "IncompatibleOptions",
            Self::IncompatibleSignatureType => "IncompatibleSignatureType",
            Self::ClockSkew => "ClockSkew",
            Self::PaddingViolation => "PaddingViolation",
            Self::AeadFramingError => "AEADFramingError",
            Self::PayloadFormatError => "PayloadFormatError",
            Self::Message1Error => "Message1Error",
            Self::Message2Error => "Message2Error",
            Self::Message3Error => "Message3Error",
            Self::IntraFrameReadTimeout => "IntraFrameReadTimeout",
            Self::RouterInfoSignatureVerificationFail => "RouterInfoSignatureVerificationFail",
            Self::IncorrectSParameter => "IncorrectSParameter",
            Self::Banned => "Banned",
        }
    }
}

impl std::fmt::Display for Ntcp2TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// --- блоки data phase ----------------------------------------------------

/// Один блок внутри NTCP2-фрейма.
///
/// Соответствует блокам в `ProcessNextFrame` / `SendI2NPMsgs` из i2pd.
/// На wire каждый блок — это `type(1) | size(2 BE) | body(size)`.
///
/// ## Отличия от i2pd
///
/// В i2pd блоки представлены «сырыми» байтами в общем буфере и
/// сериализуются/парсятся in-place. У нас — явный enum; это даёт
/// типизацию и убирает риск рассинхронизации `offset`'ов.
/// На wire-уровне формат совпадает побайтово.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ntcp2Block {
    /// Метка времени (seconds since epoch).
    DateTime {
        /// Timestamp в секундах since epoch (BE u32).
        ts: u32,
    },
    /// Опции — сейчас не используются, но формат поддерживается.
    Options(Vec<u8>),
    /// `RouterInfo` peer'а. `flag` — битовые флаги из
    /// [`NTCP2_ROUTER_INFO_FLAG_REQUEST_FLOOD`] и др.
    RouterInfo {
        /// Флаги блока.
        flag: u8,
        /// Сырые байты `RouterInfo` (identity + body + signature).
        ri_bytes: Vec<u8>,
    },
    /// Вложенное I2NP-сообщение в **коротком** NTCP2-заголовке
    /// (см. [`crate::i2np_message::I2npMessage::to_ntcp2_bytes`]).
    I2npMessage(Vec<u8>),
    /// Termination.
    Termination {
        /// Sequence number на момент отправки.
        seqn: u64,
        /// Причина.
        reason: Ntcp2TerminationReason,
    },
    /// Padding из `n` нулевых байт.
    Padding(usize),
}

impl Ntcp2Block {
    /// Тип блока.
    #[must_use]
    pub const fn block_type(&self) -> Ntcp2BlockType {
        match self {
            Self::DateTime { .. } => Ntcp2BlockType::DateTime,
            Self::Options(_) => Ntcp2BlockType::Options,
            Self::RouterInfo { .. } => Ntcp2BlockType::RouterInfo,
            Self::I2npMessage(_) => Ntcp2BlockType::I2npMessage,
            Self::Termination { .. } => Ntcp2BlockType::Termination,
            Self::Padding(_) => Ntcp2BlockType::Padding,
        }
    }

    /// Тело блока **без** 3-байтового заголовка (type + size).
    fn body_bytes(&self) -> Vec<u8> {
        match self {
            Self::DateTime { ts } => ts.to_be_bytes().to_vec(),
            Self::Options(data) => data.clone(),
            Self::RouterInfo { flag, ri_bytes } => {
                let mut v = Vec::with_capacity(1 + ri_bytes.len());
                v.push(*flag);
                v.extend_from_slice(ri_bytes);
                v
            }
            Self::I2npMessage(bytes) => bytes.clone(),
            Self::Termination { seqn, reason } => {
                let mut v = Vec::with_capacity(9);
                v.extend_from_slice(&seqn.to_be_bytes());
                v.push(reason.as_u8());
                v
            }
            Self::Padding(n) => vec![0u8; *n],
        }
    }

    /// Сериализует блок в wire-формат (`type(1) | size(2 BE) | body(size)`).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `body` больше `u16::MAX`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = self.body_bytes();
        let size = u16::try_from(body.len())
            .map_err(|_| I2PError::Malformed("ntcp2: block body > 64KB"))?;
        let mut out = Vec::with_capacity(3 + body.len());
        out.push(self.block_type().as_u8());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&body);
        trace!(

            block_type = %self.block_type(),
            type_id = self.block_type().as_u8(),
            body_size = size,
            wire_size = out.len(),
            "Ntcp2Block::to_bytes"
        );
        Ok(out)
    }

    /// Разбирает один блок из `buf`, возвращает `(block, consumed)`.
    ///
    /// `buf` должен начинаться с заголовка блока. `consumed` —
    /// `3 + size`.
    ///
    /// ## Special case padding
    ///
    /// i2pd в `ProcessNextFrame` разрешает блоку `Padding` «съедать»
    /// хвост фрейма, если объявленный size больше доступного. Это
    /// нужно для фреймов, где padding дотягивает payload до нужной
    /// длины. Мы **не** делаем эту нормализацию на уровне блока:
    /// caller сам проверяет, что `consumed <= buf.len()`. Если нужно
    /// поведение i2pd — используй [`parse_ntcp2_blocks`], он
    /// обрабатывает этот случай.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `buf` короче заголовка или тела;
    /// - [`Error::UnknownNtcp2BlockType`] — type не из enum;
    /// - [`Error::Malformed`] — `DateTime` не 4 байта,
    ///   `Termination` не 9 байт.
    pub fn from_bytes(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 3 {
            trace!(
                buf_len = buf.len(),
                "Ntcp2Block::from_bytes: buffer too short for header"
            );
            return Err(I2PError::InvalidLength {
                expected: 3,
                got: buf.len(),
            });
        }
        let type_id = Ntcp2BlockType::from_u8(buf[0])?;
        let size = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let total = 3usize
            .checked_add(size)
            .ok_or(I2PError::Malformed("ntcp2: block size overflow"))?;
        if buf.len() < total {
            trace!(

                block_type = %type_id,
                declared_total = total,
                buf_len = buf.len(),
                "Ntcp2Block::from_bytes: buffer too short for body"
            );
            return Err(I2PError::InvalidLength {
                expected: total,
                got: buf.len(),
            });
        }
        let body = &buf[3..total];

        let block = match type_id {
            Ntcp2BlockType::DateTime => {
                if body.len() != 4 {
                    return Err(I2PError::Malformed("ntcp2: DateTime block must be 4 bytes"));
                }
                Self::DateTime {
                    ts: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                }
            }
            Ntcp2BlockType::Options => Self::Options(body.to_vec()),
            Ntcp2BlockType::RouterInfo => {
                if body.is_empty() {
                    return Err(I2PError::Malformed("ntcp2: RouterInfo block is empty"));
                }
                Self::RouterInfo {
                    flag: body[0],
                    ri_bytes: body[1..].to_vec(),
                }
            }
            Ntcp2BlockType::I2npMessage => Self::I2npMessage(body.to_vec()),
            Ntcp2BlockType::Termination => {
                if body.len() != 9 {
                    return Err(I2PError::Malformed(
                        "ntcp2: Termination block must be 9 bytes",
                    ));
                }
                let mut seqn_bytes = [0u8; 8];
                seqn_bytes.copy_from_slice(&body[..8]);
                let reason = Ntcp2TerminationReason::from_u8(body[8])?;
                Self::Termination {
                    seqn: u64::from_be_bytes(seqn_bytes),
                    reason,
                }
            }
            Ntcp2BlockType::Padding => Self::Padding(body.len()),
        };
        trace!(

            block_type = %block.block_type(),
            body_size = size,
            consumed = total,
            "Ntcp2Block::from_bytes: parsed"
        );
        Ok((block, total))
    }
}

/// Сериализует последовательность блоков в один payload фрейма.
///
/// # Errors
///
/// См. [`Ntcp2Block::to_bytes`].
pub fn serialize_ntcp2_blocks(blocks: &[Ntcp2Block]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for b in blocks {
        out.extend_from_slice(&b.to_bytes()?);
    }
    trace!(
        count = blocks.len(),
        total_bytes = out.len(),
        "serialize_ntcp2_blocks"
    );
    Ok(out)
}

/// Парсит последовательность блоков до конца `buf`.
///
/// Padding-блок с size, выходящим за границы буфера, **не** даёт
/// ошибки: его длина усекается до конца `buf` (как в i2pd
/// `ProcessNextFrame`). Это нужно для фреймов, где sender
/// использовал padding «до конца» — например, наш же
/// `create_frame` при добавлении padding'а.
///
/// # Errors
///
/// - [`Error::InvalidLength`] — данных не хватает на заголовок
///   блока или на тело (не-Padding) блока;
/// - [`Error::UnknownNtcp2BlockType`] — неизвестный тип;
/// - [`Error::Malformed`] — блок объявленного типа не распарсился.
pub fn parse_ntcp2_blocks(buf: &[u8]) -> Result<Vec<Ntcp2Block>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len() - offset < 3 {
            trace!(
                offset,
                remaining = buf.len() - offset,
                "parse_ntcp2_blocks: leftover bytes < 3"
            );
            return Err(I2PError::InvalidLength {
                expected: offset + 3,
                got: buf.len(),
            });
        }
        let type_id = Ntcp2BlockType::from_u8(buf[offset])?;
        let declared_size = u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]) as usize;
        let header_end = offset + 3;
        let declared_end = header_end.saturating_add(declared_size);

        // Padding может «съесть» хвост фрейма — так делает i2pd.
        // Конструируем блок напрямую (усечённый по границе буфера),
        // не заходя в `from_bytes`: там header утверждает больший
        // size, и валидация упадёт.
        if type_id == Ntcp2BlockType::Padding && declared_end > buf.len() {
            let actual_size = buf.len() - header_end;
            trace!(
                offset,
                declared_size, actual_size, "parse_ntcp2_blocks: Padding truncated to buffer end"
            );
            out.push(Ntcp2Block::Padding(actual_size));
            return Ok(out); // дошли до конца буфера
        }

        if declared_end > buf.len() {
            trace!(

                offset,
                block_type = %type_id,
                declared_end,
                buf_len = buf.len(),
                "parse_ntcp2_blocks: declared block extends past buffer"
            );
            return Err(I2PError::InvalidLength {
                expected: declared_end,
                got: buf.len(),
            });
        }

        let (block, _) = Ntcp2Block::from_bytes(&buf[offset..declared_end])?;
        out.push(block);
        offset = declared_end;
    }
    trace!(
        buf_len = buf.len(),
        blocks = out.len(),
        "parse_ntcp2_blocks: done"
    );
    Ok(out)
}

// --- Establisher ---------------------------------------------------------

/// Ядро handshake'а NTCP2 — Noise XK с протоколом
/// `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256`.
///
/// Соответствует `struct NTCP2Establisher` в i2pd. Хранит состояние
/// Noise (`h`, `ck`, `n`) и участников DH. Handshake состоит из трёх
/// шагов (`SessionRequest` → `SessionCreated` → `SessionConfirmed`), каждый
/// из которых вызывает свою пару KDF'ов.
///
/// ## Что внутри
///
/// - `noise` — состояние Noise XK, обновляется методами `kdf1_*`, `kdf2_*`, `kdf3_*`;
/// - `ephemeral` — наш эфемерный ключ (генерируется в `new()`);
/// - `remote_ephemeral_pub` — эфемерный pub peer'а;
/// - `remote_static_pub` — static pub peer'а (Bob's для Alice, Alice's для Bob).
///
/// ## Что снаружи (в следующих шагах)
///
/// - Обфускация заголовков (`iv` и SipHash-based counter);
/// - Создание wire-сообщений SessionRequest/SessionCreated/SessionConfirmed
///   с padding'ом и options-блоком.
pub struct Ntcp2Establisher {
    /// Состояние Noise XK.
    ///
    /// **Не** в `Debug` — содержит AEAD-ключ `k`, это секрет.
    pub noise: NoiseSymmetricState,
    /// Наш эфемерный ключ.
    ///
    /// **Не** в `Debug` — содержит приватный ключ.
    pub ephemeral: I2PX25519Keys,
    /// Публичный эфемерный ключ peer'а.
    ///
    /// Заполняется Alice при приёме `SessionCreated` (`Y`),
    /// Bob — при приёме `SessionRequest` (`X`).
    pub remote_ephemeral_pub: [u8; 32],
    /// Публичный static ключ peer'а.
    ///
    /// У Alice — static Bob'а (из его `RouterInfo`), у Bob — static
    /// Alice (узнаётся из расшифрованного `SessionConfirmed` part1).
    pub remote_static_pub: [u8; 32],

    // --- Alice-only поля (устанавливаются перед `create_session_request`) ---
    /// `IdentHash` peer'а. Используется как AES-ключ для обфускации
    /// эфемерного pub `X` в `SessionRequest`.
    pub remote_ident_hash: [u8; 32],

    // --- Shared (rolling IV для AES-CBC) ---------------------------------
    /// Текущий CBC IV.
    ///
    /// У Alice инициализируется IV из `RouterInfo` Bob'а, после
    /// шифрования `X` заменяется последними 16 байтами ciphertext'а
    /// (этот IV будет использован для `SessionCreated`).
    /// У Bob инициализируется своим локальным IV и обновляется так же
    /// после расшифровки `X`.
    pub iv: [u8; 16],

    // --- Payload для SessionConfirmed ------------------------------------
    /// Тело RouterInfo-блока для `SessionConfirmed` part2.
    ///
    /// Формат: `block-type(1) | size(2 BE) | flag(1) | RI(N)`.
    /// Создаётся при построении `SessionRequest` (Bob'а RI мы не знаем,
    /// но свой RI нужен нам для последующего `SessionConfirmed`).
    ///
    /// **Содержит личный `RouterInfo`** — не выводим в `Debug`.
    pub m3p2_block: Vec<u8>,
    /// Полная длина m3p2 в wire-формате: `m3p2_block.len() + 16`
    /// (16 — Poly1305 MAC, добавляемый при шифровании `SessionConfirmed`).
    pub m3p2_len: u16,
}
impl std::fmt::Debug for Ntcp2Establisher {
    /// Печатает только публичные поля.
    ///
    /// `noise` содержит AEAD-ключ, `ephemeral` — приватный ключ
    /// X25519; `m3p2_block` содержит личный `RouterInfo`; они в логи
    /// не попадают.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ntcp2Establisher")
            .field("remote_ephemeral_pub", &self.remote_ephemeral_pub)
            .field("remote_static_pub", &self.remote_static_pub)
            .field("remote_ident_hash", &self.remote_ident_hash)
            .field("noise_h_prefix", &&self.noise.h[..4])
            .field("ephemeral_pub", self.ephemeral.public_key())
            .field("m3p2_len", &self.m3p2_len)
            .finish_non_exhaustive()
    }
}
impl Ntcp2Establisher {
    /// Разбирает заголовки `SessionRequest` (первые `64` байта).
    ///
    /// Это «верхняя половина» [`Self::process_session_request`]: делает
    /// шаги 1–4 и 6, но **не** потребляет padding. Нужна потому, что
    /// i2pd читает `SessionRequest` в два приёма — сначала ровно `64`
    /// байта заголовков, потом `padding_len` байт padding'а — и
    /// padding на нашей стороне читается отдельным `async_read`.
    ///
    /// ## Что делает
    ///
    /// 1. Расшифровывает `X` через AES-256-CBC с ключом = `local_ident_hash`
    ///    и IV = `local_iv` (оба — **свои**, Bob'овы). Сохраняет результат
    ///    в [`Self::remote_ephemeral_pub`].
    /// 2. Обновляет [`Self::iv`] последними 16 байтами ciphertext'а `X` —
    ///    это IV для `SessionCreated`.
    /// 3. Делает [`Self::kdf1_bob`] (init Noise + MixHash(X) + DH).
    /// 4. Расшифровывает options (16 байт plaintext + 16 MAC),
    ///    `MixHash` на ciphertext.
    /// 5. Парсит `netId`, `ver`, `padLen`, `m3p2Len`, `tsA`.
    ///
    /// Шестой шаг [`Self::process_session_request`] — `MixHash` на padding —
    /// здесь **не** делается: caller должен сам прочитать `padding_len`
    /// байт padding'а из сокета и передать их в
    /// [`Self::apply_session_request_padding`].
    ///
    /// ## Обфускация `X`
    ///
    /// Если у расшифрованного `X` выставлен старший бит байта 31 —
    /// Alice просит post-quantum handshake (`ML-KEM`). У нас он не
    /// реализован, поэтому такая попытка отклоняется
    /// [`I2PError::Unsupported`].
    ///
    /// ## Clock skew
    ///
    /// Если `ts_a` расходится с `now_s` больше, чем на
    /// [`NTCP2_CLOCK_SKEW_SECS`], в результат кладётся
    /// [`SessionRequestInfo::clock_skew`] `= true`. Caller обязан
    /// всё равно отправить `SessionCreated` (это протокольная
    /// особенность NTCP2), а затем — Termination.
    ///
    /// ## Параметры
    ///
    /// - `wire` — первые `64` байта `SessionRequest`: `encrypted_X (32) ||
    ///   encrypted_options (32)`. Padding'а здесь быть не должно;
    /// - `local_ident_hash` — `IdentHash` Bob'а (32 байта);
    /// - `local_iv` — IV Bob'а из его `RouterInfo` (16 байт);
    /// - `local_static` — static X25519-ключи Bob'а (для DH);
    /// - `expected_net_id` — ожидаемый netId (обычно 2);
    /// - `now_s` — текущее время в секундах since epoch. Передаём
    ///   параметром, а не читаем из системных часов, чтобы
    ///   детерминированно тестировать clock skew.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — `wire` короче `64` байт;
    /// - [`I2PError::Malformed`] — netId или `ver` в options не совпал,
    ///   либо AES/AEAD не прошли;
    /// - [`I2PError::Unsupported`] — Alice запросила post-quantum.
    pub fn process_session_request_headers(
        &mut self,
        wire: &[u8],
        local_ident_hash: &[u8; 32],
        local_iv: &[u8; 16],
        local_static: &I2PX25519Keys,
        expected_net_id: u8,
        now_s: u64,
    ) -> Result<SessionRequestInfo> {
        trace!(
            wire_len = wire.len(),
            "process_session_request_headers: enter (Bob)"
        );

        // 1. Расшифровка X.
        if wire.len() < 32 {
            return Err(I2PError::InvalidLength {
                expected: 32,
                got: wire.len(),
            });
        }
        let x_plain = Aes256Cbc::decrypt(local_ident_hash, local_iv, &wire[..32])?;
        let mut remote_x = [0u8; 32];
        remote_x.copy_from_slice(&x_plain);

        debug!(
            x_last_byte = remote_x[31],
            x_head = format_args!("{}", hex_head(&remote_x, 8)),
            "process_session_request_headers: decrypted X"
        );

        if remote_x[31] & 0x80 != 0 {
            warn!(
                x_last_byte = remote_x[31],
                "process_session_request_headers: bit 7 of X[31] is set \
                 (post-quantum request or corrupted AES-CBC key/IV)"
            );
            return Err(I2PError::Unsupported(
                "ntcp2: post-quantum handshake is not supported",
            ));
        }
        self.remote_ephemeral_pub = remote_x;

        // IV для SessionCreated = последние 16 байт ciphertext'а X.
        self.iv.copy_from_slice(&wire[16..32]);

        // 2. KDF1 Bob.
        self.kdf1_bob(local_static)?;
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 8)),
            "process_session_request_headers: KDF1 Bob done"
        );

        // 3. Расшифровка options.
        if wire.len() < 64 {
            return Err(I2PError::InvalidLength {
                expected: 64,
                got: wire.len(),
            });
        }
        let mut options = [0u8; 16];
        self.noise.decrypt(&wire[32..64], &mut options)?;
        self.noise.mix_hash(&wire[32..64]);

        debug!(
            options = format_args!("{}", hex_head(&options, 16)),
            "process_session_request_headers: decrypted options"
        );

        // 4. Разбор options.
        //   offset  size  field
        //        0     1  netId
        //        1     1  ver = 2
        //        2     2  padLen (BE)
        //        4     2  m3p2Len (BE)
        //        6     2  reserved
        //        8     4  tsA (BE, seconds since epoch)
        //       12     4  reserved
        let net_id = options[0];
        if net_id != expected_net_id {
            warn!(
                got = net_id,
                expected = expected_net_id,
                "process_session_request_headers: netId mismatch"
            );
            return Err(I2PError::Malformed(
                "ntcp2: netId mismatch in SessionRequest",
            ));
        }
        if options[1] != 2 {
            warn!(
                ver = options[1],
                "process_session_request_headers: options version != 2"
            );
            return Err(I2PError::Malformed("ntcp2: options version != 2"));
        }
        let padding_len = u16::from_be_bytes([options[2], options[3]]);
        let m3p2_len = u16::from_be_bytes([options[4], options[5]]);
        let ts_a = u32::from_be_bytes([options[8], options[9], options[10], options[11]]);

        // 5. Clock skew.
        let clock_skew = is_clock_skew_exceeded(ts_a, now_s);

        info!(
            padding_len,
            m3p2_len,
            ts_a,
            clock_skew,
            "process_session_request_headers: SessionRequest headers ok"
        );

        // Bob запоминает m3p2Len Alice'а для буферизации SessionConfirmed.
        self.m3p2_len = m3p2_len;

        Ok(SessionRequestInfo {
            padding_len,
            m3p2_len,
            ts_a,
            clock_skew,
            remote_ephemeral_pub: remote_x,
        })
    }

    /// Потребляет padding `SessionRequest`: `h = SHA256(h || padding)`.
    ///
    /// Дополняет [`Self::process_session_request_headers`]: после того
    /// как caller прочитал `padding_len` байт padding'а из сокета,
    /// он обязан вызвать этот метод, чтобы `NoiseSymmetricState`
    /// продвинулся в то же состояние, что у Alice.
    ///
    /// `padding` — ровно `padding_len` байт, ничего больше. Пустой
    /// срез допустим (тогда `MixHash` от пустого буфера — это
    /// `SHA256(h || "")`, что тоже валидно и совпадает с i2pd
    /// `ApplyPadding(_, 0)`, если бы он вызывался с нулевой длиной).
    pub fn apply_session_request_padding(&mut self, padding: &[u8]) {
        trace!(len = padding.len(), "apply_session_request_padding");
        self.noise.mix_hash(padding);
    }

    /// Создаёт establisher со случайным эфемерным ключом.
    ///
    /// Noise-состояние инициализируется нулями — оно будет установлено
    /// первым `kdf1_*` (там вызывается [`init_noise_xk_state`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            noise: NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]),
            ephemeral: I2PX25519Keys::generate(),
            remote_ephemeral_pub: [0u8; 32],
            remote_static_pub: [0u8; 32],
            remote_ident_hash: [0u8; 32],
            iv: [0u8; 16],
            m3p2_block: Vec::new(),
            m3p2_len: 0,
        }
    }

    /// Публичный эфемерный ключ (для обмена с peer'ом).
    #[must_use]
    pub fn ephemeral_pub(&self) -> &[u8; 32] {
        self.ephemeral.public_key()
    }

    /// KDF1 Alice: инициализация Noise XK + первый DH.
    ///
    /// Инициализирует noise с static'ом Bob'а, `MixHash` на свой
    /// эфемерный pub, делает `DH(alice_ephemeral`, `bob_static`).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если DH вернул all-zero shared secret.
    pub fn kdf1_alice(&mut self) -> Result<()> {
        trace!(dh = "alice_ephemeral x bob_static", "kdf1_alice: enter");
        init_noise_xk_state(&mut self.noise, &self.remote_static_pub);
        self.noise.mix_hash(self.ephemeral.public_key());
        let shared = self
            .ephemeral
            .agree(&self.remote_static_pub)
            .ok_or_else(|| {
                warn!("kdf1_alice: DH returned all-zero shared");
                I2PError::Malformed("ntcp2: KDF1 Alice DH failed")
            })?;
        self.noise.mix_key(&shared);
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 4)),
            ck_head = format_args!("{}", hex_head(&self.noise.ck, 4)),
            n = self.noise.n,
            "kdf1_alice: done"
        );
        Ok(())
    }

    /// KDF1 Bob: инициализация Noise XK + первый DH со своей стороны.
    ///
    /// `local_static` — static-ключи Bob'а. Соответствует
    /// `KDF1Bob()` в i2pd, где `local_static` берётся из
    /// глобального `RouterContext`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если DH вернул all-zero shared secret.
    pub fn kdf1_bob(&mut self, local_static: &I2PX25519Keys) -> Result<()> {
        trace!(dh = "bob_static x alice_ephemeral", "kdf1_bob: enter");
        init_noise_xk_state(&mut self.noise, local_static.public_key());
        self.noise.mix_hash(&self.remote_ephemeral_pub);
        let shared = local_static
            .agree(&self.remote_ephemeral_pub)
            .ok_or_else(|| {
                warn!("kdf1_bob: DH returned all-zero shared");
                I2PError::Malformed("ntcp2: KDF1 Bob DH failed")
            })?;
        self.noise.mix_key(&shared);
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 4)),
            ck_head = format_args!("{}", hex_head(&self.noise.ck, 4)),
            n = self.noise.n,
            "kdf1_bob: done"
        );
        Ok(())
    }

    /// KDF2 Alice: `MixHash` на эфемерный pub Bob'а + DH.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если DH вернул all-zero shared secret.
    pub fn kdf2_alice(&mut self) -> Result<()> {
        trace!(dh = "alice_ephemeral x bob_ephemeral", "kdf2_alice: enter");
        self.noise.mix_hash(&self.remote_ephemeral_pub);
        let shared = self
            .ephemeral
            .agree(&self.remote_ephemeral_pub)
            .ok_or_else(|| {
                warn!("kdf2_alice: DH returned all-zero shared");
                I2PError::Malformed("ntcp2: KDF2 Alice DH failed")
            })?;
        self.noise.mix_key(&shared);
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 4)),
            n = self.noise.n,
            "kdf2_alice: done"
        );
        Ok(())
    }

    /// KDF2 Bob: `MixHash` на свой эфемерный pub + DH.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если DH вернул all-zero shared secret.
    pub fn kdf2_bob(&mut self) -> Result<()> {
        trace!(dh = "bob_ephemeral x alice_ephemeral", "kdf2_bob: enter");
        self.noise.mix_hash(self.ephemeral.public_key());
        let shared = self
            .ephemeral
            .agree(&self.remote_ephemeral_pub)
            .ok_or_else(|| {
                warn!("kdf2_bob: DH returned all-zero shared");
                I2PError::Malformed("ntcp2: KDF2 Bob DH failed")
            })?;
        self.noise.mix_key(&shared);
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 4)),
            n = self.noise.n,
            "kdf2_bob: done"
        );
        Ok(())
    }

    /// KDF3 Alice: `DH(alice_static`, `bob_ephemeral`).
    ///
    /// Соответствует `KDF3Alice` из i2pd; `MixHash` здесь не делается.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если DH вернул all-zero shared secret.
    pub fn kdf3_alice(&mut self, local_static: &I2PX25519Keys) -> Result<()> {
        trace!(dh = "alice_static x bob_ephemeral", "kdf3_alice: enter");
        let shared = local_static
            .agree(&self.remote_ephemeral_pub)
            .ok_or_else(|| {
                warn!("kdf3_alice: DH returned all-zero shared");
                I2PError::Malformed("ntcp2: KDF3 Alice DH failed")
            })?;
        self.noise.mix_key(&shared);
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 4)),
            ck_head = format_args!("{}", hex_head(&self.noise.ck, 4)),
            n = self.noise.n,
            "kdf3_alice: done"
        );
        Ok(())
    }

    /// KDF3 Bob: `DH(bob_ephemeral`, `alice_static`).
    ///
    /// `remote_static_pub` должен быть заполнен static'ом Alice
    /// до вызова (устанавливается при обработке `SessionConfirmed` part 1).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если DH вернул all-zero shared secret.
    pub fn kdf3_bob(&mut self) -> Result<()> {
        trace!(dh = "bob_ephemeral x alice_static", "kdf3_bob: enter");
        let shared = self
            .ephemeral
            .agree(&self.remote_static_pub)
            .ok_or_else(|| {
                warn!("kdf3_bob: DH returned all-zero shared");
                I2PError::Malformed("ntcp2: KDF3 Bob DH failed")
            })?;
        self.noise.mix_key(&shared);
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 4)),
            ck_head = format_args!("{}", hex_head(&self.noise.ck, 4)),
            n = self.noise.n,
            "kdf3_bob: done"
        );
        Ok(())
    }
}

impl Default for Ntcp2Establisher {
    fn default() -> Self {
        Self::new()
    }
}
// --- Data phase keys -----------------------------------------------------

/// Ключи и счётчики data phase NTCP2.
///
/// После успешного handshake'а (`SessionRequest` → `SessionCreated` →
/// `SessionConfirmed`) обе стороны выводят из финального `NoiseSymmetricState`
/// (`ck`, `h`) полный набор ключей для обмена фреймами:
///
/// - **AEAD-ключи** (`send_key`, `receive_key`) — ChaCha20-Poly1305 для
///   шифрования payload'а фрейма, `seq` — счётчик nonce;
/// - **SipHash-ключи** (`send_sip_key`, `receive_sip_key`) — для
///   обфускации 2-байтового префикса длины фрейма;
/// - **начальные IV** (`send_iv`, `receive_iv`) — 8-байтовые rolling
///   IV для SipHash-обфускации длины.
///
/// ## KDF (совпадает с `KeyDerivationFunctionDataPhase` в i2pd)
///
/// ```text
///   k_ab || k_ba = HKDF(ck, "", "", 64)
///   ask_master   = HKDF(ck, "", "ask", 32)
///   sip_master   = HKDF(ask_master, h || "siphash", "", 32)
///   sipk_ab || sipk_ba = HKDF(sip_master, "", "", 64)
/// ```
///
/// Направление:
///
/// - Alice: `send` ← `_ab`, `receive` ← `_ba`, IV для send берётся из
///   `sipk_ab[16..24]`, для receive — из `sipk_ba[16..24]`;
/// - Bob: `send` ← `_ba`, `receive` ← `_ab`, IV-источники зеркальны.
///
/// ## Обфускация длины
///
/// Каждый фрейм на wire начинается с 2-байтового BE-префикса длины.
/// Перед записью в wire он XOR'ится с младшими 16 битами SipHash-8
/// от текущего IV; IV после этого обновляется (`new_iv = SipHash(iv)`).
///
/// # Замечание о проверке
///
/// На этом шаге мы не имеем референс-векторов KDF из i2pd — они
/// появятся, когда будет полный handshake (2y-5). Тесты ниже проверяют
/// **согласованность** Alice/Bob (у них должны получиться зеркальные
/// ключи) и round-trip обфускации длины.
pub struct Ntcp2DataPhase {
    /// AEAD-ключ для шифрования исходящих фреймов.
    pub send_key: [u8; 32],
    /// AEAD-ключ для расшифровки входящих фреймов.
    pub receive_key: [u8; 32],
    /// SipHash-ключ для обфускации длины исходящих фреймов.
    send_sip_key: [u8; 16],
    /// SipHash-ключ для снятия обфускации длины входящих фреймов.
    receive_sip_key: [u8; 16],
    /// Текущий IV обфускации исходящих длин (rolling `SipHash`).
    send_iv: [u8; 8],
    /// Текущий IV обфускации входящих длин (rolling `SipHash`).
    receive_iv: [u8; 8],
    /// Счётчик nonce AEAD-шифрования (LE u64 в байтах `[4..12]`).
    send_seq: u64,
    /// Счётчик nonce AEAD-расшифровки.
    receive_seq: u64,
}

impl Ntcp2DataPhase {
    /// Выводит ключи и IV из финального состояния Noise.
    ///
    /// `is_alice` определяет направление (см. док модуля).
    #[must_use]
    pub fn derive(ck: &[u8; 32], h: &[u8; 32], is_alice: bool) -> Self {
        trace!(
            is_alice,
            ck_head = format_args!("{}", hex_head(ck, 4)),
            h_head = format_args!("{}", hex_head(h, 4)),
            "Ntcp2DataPhase::derive: enter"
        );
        // 1. k_ab || k_ba = HKDF(ck, "", "", 64)
        let mut k = [0u8; 64];
        hkdf(ck, &[], b"", &mut k);
        // `copy_from_slice` вместо `try_into().expect()`: размеры
        // известны статически, паника невозможна.
        let mut k_ab = [0u8; 32];
        k_ab.copy_from_slice(&k[..32]);
        let mut k_ba = [0u8; 32];
        k_ba.copy_from_slice(&k[32..]);

        // 2. ask_master = HKDF(ck, "", "ask", 32)
        let mut ask_master = [0u8; 32];
        hkdf(ck, &[], b"ask", &mut ask_master);

        // 3. sip_master = HKDF(ask_master, h || "siphash", "", 32)
        let mut h_with_siphash = [0u8; 39];
        h_with_siphash[..32].copy_from_slice(h);
        h_with_siphash[32..].copy_from_slice(b"siphash");
        let mut sip_master = [0u8; 32];
        hkdf(&ask_master, &h_with_siphash, b"", &mut sip_master);

        // 4. sipk_ab || sipk_ba = HKDF(sip_master, "", "", 64)
        let mut sipk = [0u8; 64];
        hkdf(&sip_master, &[], b"", &mut sipk);
        let mut sipk_ab = [0u8; 32];
        sipk_ab.copy_from_slice(&sipk[..32]);
        let mut sipk_ba = [0u8; 32];
        sipk_ba.copy_from_slice(&sipk[32..]);

        // 5. Направление и начальные IV.
        let (send_key, receive_key, send_sip_material, receive_sip_material) = if is_alice {
            (k_ab, k_ba, sipk_ab, sipk_ba)
        } else {
            (k_ba, k_ab, sipk_ba, sipk_ab)
        };

        let mut send_sip_key = [0u8; 16];
        send_sip_key.copy_from_slice(&send_sip_material[..16]);
        let mut receive_sip_key = [0u8; 16];
        receive_sip_key.copy_from_slice(&receive_sip_material[..16]);

        let mut send_iv = [0u8; 8];
        send_iv.copy_from_slice(&send_sip_material[16..24]);
        let mut receive_iv = [0u8; 8];
        receive_iv.copy_from_slice(&receive_sip_material[16..24]);
        debug!(
            is_alice,
            send_key_head = format_args!("{}", hex_head(&send_key, 4)),
            receive_key_head = format_args!("{}", hex_head(&receive_key, 4)),
            send_iv = format_args!("{}", hex_head(&send_iv, 8)),
            receive_iv = format_args!("{}", hex_head(&receive_iv, 8)),
            "Ntcp2DataPhase::derive: done"
        );
        Self {
            send_key,
            receive_key,
            send_sip_key,
            receive_sip_key,
            send_iv,
            receive_iv,
            send_seq: 0,
            receive_seq: 0,
        }
    }

    /// Обфусцирует длину исходящего фрейма: возвращает 2 байта для wire.
    ///
    /// Побочный эффект — `send_iv` обновляется (rolling `SipHash`). Каждый
    /// фрейм вызывает ровно один раз.
    pub fn obfuscate_send_length(&mut self, frame_len: u16) -> [u8; 2] {
        // new_iv = SipHash(iv); mask = low 16 bits of new_iv (LE); wire = (frame_len ^ mask) BE
        self.send_iv = siphash24(&self.send_iv, &self.send_sip_key).to_le_bytes();
        let mask = u16::from_le_bytes([self.send_iv[0], self.send_iv[1]]);
        (frame_len ^ mask).to_be_bytes()
    }

    /// Снимает обфускацию длины входящего фрейма.
    ///
    /// `wire` — 2 байта из wire (BE). Побочный эффект — `receive_iv`
    /// обновляется. Каждый фрейм вызывает ровно один раз.
    #[must_use]
    pub fn deobfuscate_receive_length(&mut self, wire: [u8; 2]) -> u16 {
        self.receive_iv = siphash24(&self.receive_iv, &self.receive_sip_key).to_le_bytes();
        let mask = u16::from_le_bytes([self.receive_iv[0], self.receive_iv[1]]);
        let frame_len = u16::from_be_bytes(wire) ^ mask;
        trace!(
            wire = format_args!("{:02x}{:02x}", wire[0], wire[1]),
            mask = format_args!("{mask:04x}"),
            frame_len,
            new_iv = format_args!("{}", hex_head(&self.receive_iv, 8)),
            "deobfuscate_receive_length"
        );
        frame_len
    }
    /// Оборачивает список блоков в один NTCP2-фрейм.
    ///
    /// ## Wire
    ///
    /// ```text
    ///   offset  size            field
    ///   ------  ----            -----
    ///        0     2            obfuscated length (BE)
    ///        2     frame_len    AEAD-шифрованный payload
    /// ```
    ///
    /// `frame_len = plaintext_blocks_len + 16` (Poly1305 MAC).
    ///
    /// ## Побочные эффекты
    ///
    /// - `send_seq` инкрементируется;
    /// - `send_iv` обновляется (rolling `SipHash` для длины).
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `frame_len > u16::MAX` или
    ///   `frame_len + 2 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE`;
    /// - ошибки сериализации блоков и AEAD.
    pub fn create_frame(&mut self, blocks: &[Ntcp2Block]) -> Result<Vec<u8>> {
        let plaintext = serialize_ntcp2_blocks(blocks)?;
        let frame_len = plaintext
            .len()
            .checked_add(16)
            .ok_or(I2PError::Malformed("ntcp2: frame length overflow"))?;
        if frame_len + 2 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE {
            return Err(I2PError::Malformed("ntcp2: frame payload too large"));
        }
        let frame_len_u16 = u16::try_from(frame_len)
            .map_err(|_| I2PError::Malformed("ntcp2: frame length > u16::MAX"))?;

        let nonce = self.next_send_nonce();
        let aead = AeadChaCha20Poly1305::new();
        let mut ciphertext = vec![0u8; frame_len];
        let n = aead.encrypt(&self.send_key, &nonce, &[], &plaintext, &mut ciphertext)?;
        debug_assert_eq!(n, frame_len);

        let len_bytes = self.obfuscate_send_length(frame_len_u16);
        let mut wire = Vec::with_capacity(2 + ciphertext.len());
        wire.extend_from_slice(&len_bytes);
        wire.extend_from_slice(&ciphertext);
        Ok(wire)
    }

    /// Читает длину входящего фрейма из 2-байтового префикса.
    ///
    /// **Побочный эффект**: `receive_iv` обновляется. Вызывается
    /// ровно один раз на каждый входящий фрейм, **до** того как
    /// прочитано тело фрейма.
    #[must_use]
    pub fn read_frame_length(&mut self, prefix: [u8; 2]) -> u16 {
        let l = self.deobfuscate_receive_length(prefix);
        debug!(frame_len = l, "read_frame_length");
        l
    }

    /// Расшифровывает тело фрейма.
    ///
    /// `ciphertext` — ровно `frame_len` байт, полученных после
    /// [`Self::read_frame_length`]. **Побочный эффект**: `receive_seq`
    /// инкрементируется.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если `ciphertext.len() < 16`;
    /// - [`Error::Malformed`], если AEAD не прошёл, или блоки не
    ///   распарсились.
    pub fn decrypt_frame(&mut self, ciphertext: &[u8]) -> Result<Vec<Ntcp2Block>> {
        if ciphertext.len() < 16 {
            return Err(I2PError::InvalidLength {
                expected: 16,
                got: ciphertext.len(),
            });
        }
        let nonce = self.next_receive_nonce();
        let aead = AeadChaCha20Poly1305::new();
        let plaintext_len = ciphertext.len() - 16;
        let mut plaintext = vec![0u8; plaintext_len];
        let n = aead.decrypt(&self.receive_key, &nonce, &[], ciphertext, &mut plaintext)?;
        debug_assert_eq!(n, plaintext_len);
        parse_ntcp2_blocks(&plaintext)
    }

    /// Удобная обёртка: весь фрейм (2-байтовый префикс + ciphertext)
    /// за один вызов.
    ///
    /// **Побочные эффекты**: `receive_iv` и `receive_seq` обновляются
    /// по одному разу.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `wire` короче заявленного;
    /// - ошибки [`Self::decrypt_frame`].
    pub fn parse_frame(&mut self, wire: &[u8]) -> Result<Vec<Ntcp2Block>> {
        if wire.len() < 2 {
            return Err(I2PError::InvalidLength {
                expected: 2,
                got: wire.len(),
            });
        }
        let frame_len = usize::from(self.read_frame_length([wire[0], wire[1]]));
        if wire.len() < 2 + frame_len {
            return Err(I2PError::InvalidLength {
                expected: 2 + frame_len,
                got: wire.len(),
            });
        }
        self.decrypt_frame(&wire[2..2 + frame_len])
    }

    /// Следующий nonce для AEAD-шифрования: 4 нуля + LE u64 `send_seq`.
    ///
    /// Счётчик инкрементируется.
    pub const fn next_send_nonce(&mut self) -> [u8; 12] {
        let nonce = create_nonce(self.send_seq);
        self.send_seq += 1;
        nonce
    }

    /// Следующий nonce для AEAD-расшифровки.
    ///
    /// Счётчик инкрементируется.
    pub const fn next_receive_nonce(&mut self) -> [u8; 12] {
        let nonce = create_nonce(self.receive_seq);
        self.receive_seq += 1;
        nonce
    }

    /// Разделяет состояние на отправляющую и приёмную половины.
    ///
    /// Нужно, чтобы **одновременно** писать и читать из `TcpStream`:
    /// после `TcpStream::into_split()` половинки потока отдаются двум
    /// независимым задачам, и у каждой — своя половина crypto state.
    ///
    /// Поля внутри [`Ntcp2DataPhase`] не пересекаются: send-сторона
    /// работает только с `send_*`, receive-сторона — с `receive_*`.
    /// Так что разделение бесплатное (никаких блокировок).
    #[must_use]
    pub const fn into_halves(self) -> (Ntcp2SendHalf, Ntcp2ReceiveHalf) {
        (
            Ntcp2SendHalf {
                key: self.send_key,
                sip_key: self.send_sip_key,
                iv: self.send_iv,
                seq: self.send_seq,
            },
            Ntcp2ReceiveHalf {
                key: self.receive_key,
                sip_key: self.receive_sip_key,
                iv: self.receive_iv,
                seq: self.receive_seq,
            },
        )
    }
}

/// Отправляющая половина data phase.
///
/// Обёртка над `send_key`/`send_sip_key`/`send_iv`/`send_seq`, доступная
/// только write-таску сессии.
pub struct Ntcp2SendHalf {
    key: [u8; 32],
    sip_key: [u8; 16],
    iv: [u8; 8],
    seq: u64,
}

impl Ntcp2SendHalf {
    /// Номер следующего исходящего фрейма (`seqn` в `Termination`).
    #[must_use]
    pub const fn sequence_number(&self) -> u64 {
        self.seq
    }

    /// См. [`Ntcp2DataPhase::obfuscate_send_length`].
    pub fn obfuscate_send_length(&mut self, frame_len: u16) -> [u8; 2] {
        self.iv = siphash24(&self.iv, &self.sip_key).to_le_bytes();
        let mask = u16::from_le_bytes([self.iv[0], self.iv[1]]);
        (frame_len ^ mask).to_be_bytes()
    }

    const fn next_nonce(&mut self) -> [u8; 12] {
        let n = create_nonce(self.seq);
        self.seq += 1;
        n
    }

    /// См. [`Ntcp2DataPhase::create_frame`].
    ///
    /// # Errors
    ///
    /// См. [`Ntcp2DataPhase::create_frame`].
    pub fn create_frame(&mut self, blocks: &[Ntcp2Block]) -> Result<Vec<u8>> {
        let plaintext = serialize_ntcp2_blocks(blocks)?;
        let frame_len = plaintext
            .len()
            .checked_add(16)
            .ok_or(I2PError::Malformed("ntcp2: frame length overflow"))?;
        if frame_len + 2 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE {
            warn!(
                frame_len,
                max = NTCP2_UNENCRYPTED_FRAME_MAX_SIZE,
                "create_frame: payload too large"
            );
            return Err(I2PError::Malformed("ntcp2: frame payload too large"));
        }
        let frame_len_u16 = u16::try_from(frame_len)
            .map_err(|_| I2PError::Malformed("ntcp2: frame length > u16::MAX"))?;
        let nonce = self.next_nonce();
        let aead = AeadChaCha20Poly1305::new();
        let mut ciphertext = vec![0u8; frame_len];
        let n = aead.encrypt(&self.key, &nonce, &[], &plaintext, &mut ciphertext)?;
        debug_assert_eq!(n, frame_len);
        let len_bytes = self.obfuscate_send_length(frame_len_u16);
        let mut wire = Vec::with_capacity(2 + ciphertext.len());
        wire.extend_from_slice(&len_bytes);
        wire.extend_from_slice(&ciphertext);
        trace!(
            blocks = blocks.len(),
            plaintext_len = plaintext.len(),
            frame_len,
            wire_len = wire.len(),
            seq = self.seq - 1,
            nonce = format_args!("{}", hex_head(&nonce, 12)),
            "create_frame: emitted"
        );
        Ok(wire)
    }
}

/// Приёмная половина data phase.
///
/// Обёртка над `receive_key`/`receive_sip_key`/`receive_iv`/`receive_seq`,
/// доступная только read-таску сессии.
pub struct Ntcp2ReceiveHalf {
    key: [u8; 32],
    sip_key: [u8; 16],
    iv: [u8; 8],
    seq: u64,
}

impl Ntcp2ReceiveHalf {
    /// См. [`Ntcp2DataPhase::read_frame_length`].
    pub fn read_frame_length(&mut self, prefix: [u8; 2]) -> u16 {
        self.iv = siphash24(&self.iv, &self.sip_key).to_le_bytes();
        let mask = u16::from_le_bytes([self.iv[0], self.iv[1]]);
        let frame_len = u16::from_be_bytes(prefix) ^ mask;
        debug!(
            wire = format_args!("{:02x}{:02x}", prefix[0], prefix[1]),
            mask = format_args!("{mask:04x}"),
            frame_len,
            "Ntcp2ReceiveHalf::read_frame_length"
        );
        frame_len
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let n = create_nonce(self.seq);
        trace!(seq = self.seq, "Ntcp2SendHalf::next_nonce");
        self.seq += 1;
        n
    }

    /// См. [`Ntcp2DataPhase::decrypt_frame`].
    ///
    /// # Errors
    ///
    /// См. [`Ntcp2DataPhase::decrypt_frame`].
    pub fn decrypt_frame(&mut self, ciphertext: &[u8]) -> Result<Vec<Ntcp2Block>> {
        if ciphertext.len() < 16 {
            warn!(
                got = ciphertext.len(),
                "Ntcp2ReceiveHalf::decrypt_frame: ciphertext shorter than MAC"
            );
            return Err(I2PError::InvalidLength {
                expected: 16,
                got: ciphertext.len(),
            });
        }
        let nonce = self.next_nonce();
        let aead = AeadChaCha20Poly1305::new();
        let plaintext_len = ciphertext.len() - 16;
        let mut plaintext = vec![0u8; plaintext_len];
        let n = aead.decrypt(&self.key, &nonce, &[], ciphertext, &mut plaintext)?;
        debug_assert_eq!(n, plaintext_len);
        let blocks = parse_ntcp2_blocks(&plaintext)?;
        trace!(
            ciphertext_len = ciphertext.len(),
            plaintext_len,
            blocks = blocks.len(),
            seq = self.seq - 1,
            "Ntcp2ReceiveHalf::decrypt_frame: ok"
        );
        Ok(blocks)
    }
}
/// Nonce NTCP2: 4 нулевых байта + LE u64 `seqn`.
///
/// Совпадает с `NTCP2Session::CreateNonce` в i2pd.
#[must_use]
const fn create_nonce(seqn: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let seq = seqn.to_le_bytes();
    nonce[4] = seq[0];
    nonce[5] = seq[1];
    nonce[6] = seq[2];
    nonce[7] = seq[3];
    nonce[8] = seq[4];
    nonce[9] = seq[5];
    nonce[10] = seq[6];
    nonce[11] = seq[7];
    nonce
}

/// Разобранный `SessionConfirmed` (Bob после обработки).
///
/// Возвращается из [`Ntcp2Establisher::process_session_confirmed`].
/// Содержит `RouterInfo` Alice'а в сырых байтах; caller (Bob)
/// сам добавляет его в netdb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfirmedInfo {
    /// Публичный static X25519-ключ Alice'а (`S`), расшифрованный из part1.
    pub remote_static_pub: [u8; 32],
    /// Сырые байты `RouterInfo` Alice'а — identity + body + signature.
    ///
    /// Ровно то, что лежит в `routerInfo-<hash>.dat` в netDb.
    pub remote_router_info: Vec<u8>,
}

/// Разобранный `SessionCreated` (Alice после обработки).
///
/// Возвращается из [`Ntcp2Establisher::process_session_created`].
/// Содержит `ts_b` и признак clock skew. Alice всегда переходит
/// к отправке `SessionConfirmed`; skew — только сигнал caller'у.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreatedInfo {
    /// Длина padding'а, объявленная в options.
    pub padding_len: u16,
    /// Timestamp Bob'а (секунды since epoch).
    pub ts_b: u32,
    /// `true`, если `ts_b` расходится с `now_s` больше, чем на
    /// [`NTCP2_CLOCK_SKEW_SECS`].
    pub clock_skew: bool,
    /// Публичный эфемерный ключ Bob'а (`Y` в открытом виде).
    pub remote_ephemeral_pub: [u8; 32],
}

/// Разобранный `SessionRequest` (Bob после обработки).
///
/// Возвращается из [`Ntcp2Establisher::process_session_request`].
/// Caller (Bob) использует это, чтобы:
///
/// - ответить `SessionCreated` (всегда — либо как успех, либо как
///   Termination при clock skew);
/// - отклонить запрос, если выставлен [`Self::clock_skew`] — по
///   протоколу i2pd всё равно отправляет `SessionCreated`, чтобы
///   Alice узнала точное время Bob'а, и затем закрывает соединение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequestInfo {
    /// Длина padding'а, объявленная в options.
    /// Wire содержит минимум `64 + padding_len` байт.
    pub padding_len: u16,
    /// `m3p2Len` из options — размер `SessionConfirmed part2`
    /// в wire (после шифрования). Bob'у нужен, чтобы правильно
    /// буферизовать `SessionConfirmed`.
    pub m3p2_len: u16,
    /// Timestamp Alice'а (секунды since epoch).
    pub ts_a: u32,
    /// `true`, если `ts_a` расходится с `now_s` больше, чем на
    /// [`NTCP2_CLOCK_SKEW_SECS`].
    pub clock_skew: bool,
    /// Публичный эфемерный ключ Alice'а (`X` в открытом виде).
    pub remote_ephemeral_pub: [u8; 32],
}

/// Проверяет, превышает ли расхождение `ts_a` и `now_s` допустимый
/// clock skew.
///
/// Вынесено отдельной функцией для тестируемости — в
/// [`Ntcp2Establisher::process_session_request`] вызовется с
/// реальным `now_s`.
#[must_use]
pub const fn is_clock_skew_exceeded(ts_a: u32, now_s: u64) -> bool {
    now_s.abs_diff(ts_a as u64) > NTCP2_CLOCK_SKEW_SECS
}

impl Ntcp2Establisher {
    /// Создаёт `SessionCreated` (Bob → Alice) в wire-формате.
    ///
    /// ## Wire
    ///
    /// ```text
    ///   offset  size  field
    ///   ------  ----  -----
    ///        0    32  encrypted Y (AES-256-CBC, key=local ident hash, IV=iv)
    ///       32    32  encrypted options (16 plaintext + 16 Poly1305)
    ///       64     P  padding (random, P ∈ [0, 223])
    /// ```
    ///
    /// ## Побочные эффекты
    ///
    /// - `self.iv` перезаписывается последними 16 байтами ciphertext'а
    ///   `Y` (это IV для `SessionConfirmed` part1);
    /// - `self.ephemeral` заменяется новым ключом (Bob генерирует
    ///   свою эфемерную пару здесь);
    /// - `self.noise` — MixHash(Y), MixKey(DH), MixHash(options),
    ///   MixHash(padding).
    ///
    /// ## Параметры
    ///
    /// - `local_ident_hash` — `IdentHash` Bob'а;
    /// - `expected_net_id` — обычно 2;
    /// - `now_s` — текущее время для `tsB` (секунды since epoch).
    ///   Передаём параметром, чтобы тест был детерминированным.
    /// - `rng` — источник padding'а.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `remote_ephemeral_pub` нулевой
    ///   (Bob не обработал `SessionRequest`);
    /// - ошибки AES-CBC и AEAD.
    pub fn create_session_created(
        &mut self,
        local_ident_hash: &[u8; 32],
        expected_net_id: u8,
        now_s: u64,
        rng: &mut impl Rng,
    ) -> Result<Vec<u8>> {
        trace!("create_session_created: enter (Bob)");
        // 1. Новый эфемерный ключ Bob'а.
        self.ephemeral = I2PX25519Keys::generate();
        let y_pub = *self.ephemeral.public_key();

        // 2. Обфускация Y через AES-256-CBC.
        let encrypted_y = Aes256Cbc::encrypt(local_ident_hash, &self.iv, &y_pub)?;
        debug_assert_eq!(encrypted_y.len(), 32);
        // IV для SessionConfirmed part1 = последние 16 байт ciphertext'а Y.
        self.iv.copy_from_slice(&encrypted_y[16..32]);

        // 3. KDF2 Bob: MixHash(Y) + MixKey(DH(bephemeral, aephemeral)).
        self.kdf2_bob()?;

        // 4. Options-блок (16 байт).
        //
        //   offset  size  field
        //   ------  ----  -----
        //        0     1  reserved (0)
        //        1     1  reserved (0)
        //        2     2  padLen (BE u16)
        //        4     6  reserved
        //        8    4  tsB (BE u32)  — обрати внимание: offset 8,
        //                                    а не 8, как в SessionRequest
        //       14     2  reserved
        let padding_len: u16 = (rng.next_u32() & 0xffff) as u16 % NTCP2_MAX_HANDSHAKE_PADDING_LEN;
        let ts_b = u32::try_from(now_s.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);

        let mut options = [0u8; 16];
        options[2..4].copy_from_slice(&padding_len.to_be_bytes());
        // tsB идёт по смещению 8, а не 10 — см. i2pd
        // `CreateSessionCreatedMessage`: `htobe32buf (options + 8, ...)`.
        options[8..12].copy_from_slice(&ts_b.to_be_bytes());

        // 5. AEAD-шифрование options.
        let mut encrypted_options = [0u8; 32];
        self.noise.encrypt(&options, &mut encrypted_options)?;
        self.noise.mix_hash(&encrypted_options);

        // 6. Padding.
        let mut padding = vec![0u8; usize::from(padding_len)];
        rng.fill_bytes(&mut padding);
        self.noise.mix_hash(&padding);

        // 7. Wire.
        let mut wire = Vec::with_capacity(64 + padding.len());
        wire.extend_from_slice(&encrypted_y);
        wire.extend_from_slice(&encrypted_options);
        wire.extend_from_slice(&padding);

        // expected_net_id пока не используется: в SessionCreated
        // netId не передаётся (только в SessionRequest). Параметр
        // оставлен на будущее для симметрии API и будет задействован
        // в SessionConfirmed, где netId тоже присутствует.
        let _ = expected_net_id;
        info!(

            padding_len,
            ts_b = %ts_b,
            wire_len = wire.len(),
            y_head = format_args!("{}", hex_head(&encrypted_y, 8)),
            "create_session_created: done"
        );
        Ok(wire)
    }

    /// Обрабатывает `SessionRequest` (Bob ← Alice) целиком, включая padding.
    ///
    /// Удобная обёртка: [`Self::process_session_request_headers`] +
    /// [`Self::apply_session_request_padding`]. Нужна для тестов и для
    /// случаев, когда `wire` уже содержит `64 + padding_len` байт
    /// (например, если буфер собран на стороне caller'а).
    ///
    /// Реальный сетевой код (`Ntcp2Session::accept`) вызывает эти два
    /// метода раздельно, потому что i2pd читает `SessionRequest` двумя
    /// `async_read`'ами.
    ///
    /// ## Что делает
    ///
    /// 1. Расшифровывает `X` через AES-256-CBC с ключом = `local_ident_hash`
    ///    и IV = `local_iv` (оба — **свои**, Bob'овы). Сохраняет результат
    ///    в [`Self::remote_ephemeral_pub`].
    /// 2. Обновляет [`Self::iv`] последними 16 байтами ciphertext'а `X` —
    ///    это IV для `SessionCreated`.
    /// 3. Делает [`Self::kdf1_bob`] (init Noise + MixHash(X) + DH).
    /// 4. Расшифровывает options (16 байт plaintext + 16 MAC),
    ///    `MixHash` на ciphertext.
    /// 5. Парсит `netId`, `ver`, `padLen`, `m3p2Len`, `tsA`.
    /// 6. `MixHash` на padding.
    ///
    /// ## Обфускация `X`
    ///
    /// Если у расшифрованного `X` выставлен старший бит байта 31 —
    /// Alice просит post-quantum handshake (`ML-KEM`). У нас он не
    /// реализован, поэтому такая попытка отклоняется
    /// [`I2PError::Unsupported`].
    ///
    /// ## Clock skew
    ///
    /// Если `ts_a` расходится с `now_s` больше, чем на
    /// [`NTCP2_CLOCK_SKEW_SECS`], в результат кладётся
    /// [`SessionRequestInfo::clock_skew`] `= true`. Caller обязан
    /// всё равно отправить `SessionCreated` (это протокольная
    /// особенность NTCP2), а затем — Termination.
    ///
    /// ## Параметры
    ///
    /// - `wire` — весь `SessionRequest`, включая padding;
    /// - `local_ident_hash` — `IdentHash` Bob'а (32 байта);
    /// - `local_iv` — IV Bob'а из его `RouterInfo` (16 байт);
    /// - `local_static` — static X25519-ключи Bob'а (для DH);
    /// - `expected_net_id` — ожидаемый netId (обычно 2);
    /// - `now_s` — текущее время в секундах since epoch. Передаём
    ///   параметром, а не читаем из системных часов, чтобы
    ///   детерминированно тестировать clock skew.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — `wire` короче `64` или короче
    ///   `64 + padding_len`;
    /// - [`I2PError::Malformed`] — netId или `ver` в options не совпал,
    ///   либо AES/AEAD не прошли;
    /// - [`I2PError::Unsupported`] — Alice запросила post-quantum.
    pub fn process_session_request(
        &mut self,
        wire: &[u8],
        local_ident_hash: &[u8; 32],
        local_iv: &[u8; 16],
        local_static: &I2PX25519Keys,
        expected_net_id: u8,
        now_s: u64,
    ) -> Result<SessionRequestInfo> {
        let info = self.process_session_request_headers(
            wire,
            local_ident_hash,
            local_iv,
            local_static,
            expected_net_id,
            now_s,
        )?;
        let total = 64usize
            .checked_add(usize::from(info.padding_len))
            .ok_or(I2PError::Malformed("ntcp2: padding_len overflow"))?;
        if wire.len() < total {
            return Err(I2PError::InvalidLength {
                expected: total,
                got: wire.len(),
            });
        }
        self.apply_session_request_padding(&wire[64..total]);
        Ok(info)
    }
    /// Разбирает заголовки `SessionCreated` (первые `64` байта).
    ///
    /// Это «верхняя половина» [`Self::process_session_created`]: делает
    /// шаги 1–4 и 6, но **не** потребляет padding. Нужна потому, что
    /// i2pd читает `SessionCreated` в два приёма — сначала ровно `64`
    /// байта заголовков, потом `padding_len` байт padding'а.
    ///
    /// ## Что делает
    ///
    /// 1. Расшифровывает `Y` через AES-256-CBC с ключом =
    ///    `self.remote_ident_hash` (`IdentHash` Bob'а) и IV = текущий
    ///    `self.iv` (после отправки `SessionRequest`). Сохраняет
    ///    результат в [`Self::remote_ephemeral_pub`].
    /// 2. Обновляет [`Self::iv`] последними 16 байтами ciphertext'а `Y` —
    ///    это IV для `SessionConfirmed part1`.
    /// 3. Делает [`Self::kdf2_alice`] (MixHash(Y) + DH(aephemeral,
    ///    bephemeral)).
    /// 4. Расшифровывает options (16 байт plaintext + 16 MAC),
    ///    `MixHash` на ciphertext.
    /// 5. Читает `padLen` и `tsB`.
    ///
    /// Шестой шаг [`Self::process_session_created`] — `MixHash` на padding —
    /// здесь **не** делается: caller должен сам прочитать `padding_len`
    /// байт padding'а из сокета и передать их в
    /// [`Self::apply_session_created_padding`].
    ///
    /// ## Обфускация `Y`
    ///
    /// Если у расшифрованного `Y` выставлен старший бит байта 31 —
    /// Bob подтвердил post-quantum handshake (`ML-KEM`). У нас он не
    /// реализован, поэтому такая попытка отклоняется
    /// [`I2PError::Unsupported`].
    ///
    /// ## Clock skew
    ///
    /// Если `ts_b` расходится с `now_s` больше, чем на
    /// [`NTCP2_CLOCK_SKEW_SECS`], в результат кладётся
    /// [`SessionCreatedInfo::clock_skew`] `= true`. Решение о разрыве
    /// соединения принимает caller.
    ///
    /// ## Параметры
    ///
    /// - `wire` — первые `64` байта `SessionCreated`: `encrypted_Y (32) ||
    ///   encrypted_options (32)`. Padding'а здесь быть не должно;
    /// - `now_s` — текущее время для проверки clock skew (секунды
    ///   since epoch).
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — `wire` короче `64` байт;
    /// - [`I2PError::Malformed`] — AES/AEAD не прошли;
    /// - [`I2PError::Unsupported`] — Bob подтвердил post-quantum.
    pub fn process_session_created_headers(
        &mut self,
        wire: &[u8],
        now_s: u64,
    ) -> Result<SessionCreatedInfo> {
        trace!(
            wire_len = wire.len(),
            "process_session_created_headers: enter (Alice)"
        );

        if wire.len() < 32 {
            return Err(I2PError::InvalidLength {
                expected: 32,
                got: wire.len(),
            });
        }

        // 1. Расшифровка Y.
        let y_plain = Aes256Cbc::decrypt(&self.remote_ident_hash, &self.iv, &wire[..32])?;
        let mut remote_y = [0u8; 32];
        remote_y.copy_from_slice(&y_plain);

        debug!(
            y_last_byte = remote_y[31],
            y_head = format_args!("{}", hex_head(&remote_y, 8)),
            "process_session_created_headers: decrypted Y"
        );

        if remote_y[31] & 0x80 != 0 {
            warn!(
                y_last_byte = remote_y[31],
                "process_session_created_headers: bit 7 of Y[31] is set"
            );
            return Err(I2PError::Unsupported(
                "ntcp2: post-quantum handshake is not supported",
            ));
        }
        self.remote_ephemeral_pub = remote_y;

        // IV для SessionConfirmed part1 = последние 16 байт ciphertext'а Y.
        self.iv.copy_from_slice(&wire[16..32]);

        // 2. KDF2 Alice.
        self.kdf2_alice()?;
        trace!(
            h_head = format_args!("{}", hex_head(&self.noise.h, 8)),
            "process_session_created_headers: KDF2 Alice done"
        );

        // 3. Расшифровка options.
        if wire.len() < 64 {
            return Err(I2PError::InvalidLength {
                expected: 64,
                got: wire.len(),
            });
        }
        let mut options = [0u8; 16];
        self.noise.decrypt(&wire[32..64], &mut options)?;
        self.noise.mix_hash(&wire[32..64]);

        debug!(
            options = format_args!("{}", hex_head(&options, 16)),
            "process_session_created_headers: decrypted options"
        );

        // 4. Разбор options.
        //   offset  size  field
        //        0     2  reserved
        //        2     2  padLen (BE u16)
        //        4     4  reserved
        //        8     4  tsB (BE u32, seconds since epoch)
        //       12     4  reserved
        //
        //   Смещение 8 — не 10 — как в i2pd `ProcessSessionCreatedMessage`:
        //   `uint32_t tsB = bufbe32toh (options + 8);`. В `SessionRequest`
        //   tsA тоже по смещению 8, обе структуры совпадают по раскладке.
        let padding_len = u16::from_be_bytes([options[2], options[3]]);
        let ts_b = u32::from_be_bytes([options[8], options[9], options[10], options[11]]);

        // 5. Clock skew.
        let clock_skew = is_clock_skew_exceeded(ts_b, now_s);

        info!(
            padding_len,
            ts_b, clock_skew, "process_session_created_headers: SessionCreated headers ok"
        );

        Ok(SessionCreatedInfo {
            padding_len,
            ts_b,
            clock_skew,
            remote_ephemeral_pub: remote_y,
        })
    }

    /// Потребляет padding `SessionCreated`: `h = SHA256(h || padding)`.
    ///
    /// Дополняет [`Self::process_session_created_headers`]: после того
    /// как caller прочитал `padding_len` байт padding'а из сокета,
    /// он обязан вызвать этот метод, чтобы `NoiseSymmetricState`
    /// продвинулся в то же состояние, что у Bob.
    ///
    /// `padding` — ровно `padding_len` байт, ничего больше. Пустой
    /// срез допустим (тогда `MixHash` от пустого буфера совпадает
    /// с i2pd `ApplyPadding(_, 0)`).
    pub fn apply_session_created_padding(&mut self, padding: &[u8]) {
        trace!(len = padding.len(), "apply_session_created_padding");
        self.noise.mix_hash(padding);
    }
    /// Создаёт `SessionRequest` (Alice → Bob) в wire-формате.
    ///
    /// ## Wire
    ///
    /// ```text
    ///   offset  size  field
    ///   ------  ----  -----
    ///        0    32  encrypted X     (AES-256-CBC, key=remote ident hash, IV=iv)
    ///       32    32  encrypted options  (16 plaintext + 16 Poly1305)
    ///       64     P  padding (random, P ∈ [0, 223])
    /// ```
    ///
    /// ## Побочные эффекты
    ///
    /// - `self.iv` переписывается последними 16 байтами ciphertext'а `X`
    ///   (это IV для `SessionCreated`);
    /// - `self.noise` переводится в состояние после KDF1;
    /// - `self.m3p2_block` / `self.m3p2_len` заполняются RouterInfo-блоком
    ///   для будущего `SessionConfirmed`.
    ///
    /// ## Параметры
    ///
    /// - `local_ri_bytes` — байты своего `RouterInfo` (identity + body +
    ///   signature), ровно как в `routerInfo-*.dat`;
    /// - `net_id` — текущий netId (обычно 2);
    /// - `rng` — источник случайного padding'а.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `remote_static_pub` /
    ///   `remote_ident_hash` / `iv` не заполнены (нулевые),
    ///   или если `local_ri_bytes` превышает лимит `u16`;
    /// - ошибки AES-CBC и AEAD.
    pub fn create_session_request(
        &mut self,
        local_ri_bytes: &[u8],
        net_id: u8,
        rng: &mut impl Rng,
    ) -> Result<Vec<u8>> {
        trace!(
            ri_len = local_ri_bytes.len(),
            net_id, "create_session_request: enter (Alice)"
        );
        // Свой RI кладём в m3p2 заранее — он уйдёт в SessionConfirmed.
        let m3p2_block_len = u16::try_from(local_ri_bytes.len())
            .ok()
            .and_then(|n| n.checked_add(4))
            .ok_or(I2PError::Malformed("ntcp2: RI too large for m3p2"))?;
        // + 16 — Poly1305 MAC, который появится при шифровании SessionConfirmed.
        let m3p2_len = m3p2_block_len
            .checked_add(16)
            .ok_or(I2PError::Malformed("ntcp2: m3p2 length overflow"))?;

        // 1. Обфускация X через AES-256-CBC.
        let x = *self.ephemeral.public_key();
        let encrypted_x = Aes256Cbc::encrypt(&self.remote_ident_hash, &self.iv, &x)?;
        debug_assert_eq!(encrypted_x.len(), 32);
        // IV для SessionCreated = последние 16 байт ciphertext'а X.
        self.iv.copy_from_slice(&encrypted_x[16..32]);

        // 2. KDF1: init Noise + MixHash(X) + MixKey(DH(aephemeral, bob_static)).
        self.kdf1_alice()?;

        // 3. Options-блок (16 байт).
        //
        //   offset  size  field
        //   ------  ----  -----
        //        0     1  netId
        //        1     1  ver = 2
        //        2     2  padLen (BE u16)
        //        4     2  m3p2Len (BE u16)
        //        6     2  reserved
        //        8     4  tsA (BE u32)
        //       12     4  reserved

        // `rng.next_u32() & 0xffff` даёт значение в 0..=65535; далее
        // берём остаток по модулю. Распределение слегка неравномерно
        // (как в i2pd) — для padding'а это допустимо.
        let padding_len: u16 = (rng.next_u32() & 0xffff) as u16 % NTCP2_MAX_HANDSHAKE_PADDING_LEN;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let ts_a = u32::try_from((now_ms + 500) / 1000).unwrap_or(u32::MAX);

        let mut options = [0u8; 16];
        options[0] = net_id;
        options[1] = 2;
        options[2..4].copy_from_slice(&padding_len.to_be_bytes());
        options[4..6].copy_from_slice(&m3p2_len.to_be_bytes());
        // options[6..8] = reserved (0)
        options[8..12].copy_from_slice(&ts_a.to_be_bytes());
        // options[12..16] = reserved (0)

        // 4. AEAD-шифрование options (16 → 32 с MAC).
        let mut encrypted_options = [0u8; 32];
        self.noise.encrypt(&options, &mut encrypted_options)?;
        self.noise.mix_hash(&encrypted_options);

        // 5. Случайный padding.
        let mut padding = vec![0u8; usize::from(padding_len)];
        rng.fill_bytes(&mut padding);
        self.noise.mix_hash(&padding);

        // 6. Сборка wire.
        let mut wire = Vec::with_capacity(64 + padding.len());
        wire.extend_from_slice(&encrypted_x);
        wire.extend_from_slice(&encrypted_options);
        wire.extend_from_slice(&padding);

        // 7. Сохраняем m3p2-блок для SessionConfirmed.
        //    RI-блок: block-type(1) | size(2 BE) | flag(1) | RI(N).
        let mut m3p2_block = Vec::with_capacity(usize::from(m3p2_block_len));
        m3p2_block.push(Ntcp2BlockType::RouterInfo.as_u8());
        // size = RI_len + 1 (флаг внутри блока).
        let size = u16::try_from(local_ri_bytes.len() + 1)
            .map_err(|_| I2PError::Malformed("ntcp2: RI block size overflow"))?;
        m3p2_block.extend_from_slice(&size.to_be_bytes());
        m3p2_block.push(0); // flag
        m3p2_block.extend_from_slice(local_ri_bytes);
        self.m3p2_block = m3p2_block;
        self.m3p2_len = m3p2_len;
        info!(
            padding_len,
            m3p2_len,
            wire_len = wire.len(),
            x_head = format_args!("{}", hex_head(&encrypted_x, 8)),
            "create_session_request: done"
        );
        Ok(wire)
    }

    /// Создаёт `SessionConfirmed` (Alice → Bob) в wire-формате.
    ///
    /// ## Wire
    ///
    /// ```text
    ///   offset  size       field
    ///   ------  ----       -----
    ///        0    48       part1 — AEAD-шифрование static pub Alice'а (32 + 16 MAC)
    ///       48    m3p2_len part2 — AEAD-шифрование RouterInfo-блока Alice'а
    /// ```
    ///
    /// ## Что внутри
    ///
    /// - part1 шифруется **Noise AEAD** (не AES) с текущим `n` (после
    ///   `SessionCreated` это `n = 1`), `MixHash` на ciphertext.
    /// - Затем [`Self::kdf3_alice`] делает MixKey(DH(`alice_static`, `bob_ephemeral`)),
    ///   сбрасывая `n` в 0.
    /// - part2 шифруется тем же Noise AEAD с `n = 0`.
    ///
    /// ## Побочные эффекты
    ///
    /// - `self.noise` переходит в финальное состояние — после этого
    ///   можно вызывать [`Self::derive_data_phase`];
    /// - `self.m3p2_block` очищается (больше не нужен).
    ///
    /// ## Параметры
    ///
    /// - `local_static` — static X25519-ключи Alice'а. Публичная часть
    ///   уходит в part1, приватная — в KDF3.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `m3p2_block` пуст (Alice не
    ///   вызывала `create_session_request`);
    /// - ошибки AEAD.
    pub fn create_session_confirmed(&mut self, local_static: &I2PX25519Keys) -> Result<Vec<u8>> {
        trace!(
            m3p2_len = self.m3p2_len,
            "create_session_confirmed: enter (Alice)"
        );
        if self.m3p2_block.is_empty() {
            return Err(I2PError::Malformed(
                "ntcp2: create_session_confirmed called without SessionRequest",
            ));
        }

        // part1: 32 plaintext + 16 MAC = 48 байт.
        let s_pub = *local_static.public_key();
        let mut part1 = [0u8; 48];
        self.noise.encrypt(&s_pub, &mut part1)?;
        self.noise.mix_hash(&part1);

        // KDF3 Alice: MixKey(DH(alice_static, bob_ephemeral)), n = 0.
        self.kdf3_alice(local_static)?;

        // part2: AEAD-шифрование m3p2-блока.
        let m3p2_plaintext_len = self.m3p2_block.len();
        let mut part2 = vec![0u8; m3p2_plaintext_len + 16];
        let written = self.noise.encrypt(&self.m3p2_block, &mut part2)?;
        debug_assert_eq!(written, self.m3p2_block.len() + 16);
        debug_assert_eq!(written, usize::from(self.m3p2_len));
        self.noise.mix_hash(&part2);

        // Сборка wire.
        let mut wire = Vec::with_capacity(48 + part2.len());
        wire.extend_from_slice(&part1);
        wire.extend_from_slice(&part2);

        // m3p2 больше не нужен, освобождаем память.
        self.m3p2_block = Vec::new();
        info!(wire_len = wire.len(), "create_session_confirmed: done");
        Ok(wire)
    }

    /// Обрабатывает `SessionCreated` (Alice ← Bob) целиком, включая padding.
    ///
    /// Удобная обёртка: [`Self::process_session_created_headers`] +
    /// [`Self::apply_session_created_padding`]. Нужна для тестов и для
    /// случаев, когда `wire` уже содержит `64 + padding_len` байт.
    ///
    /// Реальный сетевой код (`Ntcp2Session::connect`) вызывает эти два
    /// метода раздельно, потому что i2pd читает `SessionCreated` двумя
    /// `async_read`'ами.
    ///
    /// ## Что делает
    ///
    /// См. документацию [`Self::process_session_created_headers`] и
    /// [`Self::apply_session_created_padding`]. Разница только в том,
    /// что padding применяется здесь же, а не вызывающим кодом.
    ///
    /// ## Параметры
    ///
    /// - `wire` — весь `SessionCreated`, включая padding;
    /// - `now_s` — текущее время для проверки clock skew.
    ///
    /// # Errors
    ///
    /// См. [`Self::process_session_created_headers`], плюс:
    /// [`I2PError::InvalidLength`], если `wire` короче
    /// `64 + padding_len`.
    pub fn process_session_created(
        &mut self,
        wire: &[u8],
        now_s: u64,
    ) -> Result<SessionCreatedInfo> {
        let info = self.process_session_created_headers(wire, now_s)?;
        let total = 64usize
            .checked_add(usize::from(info.padding_len))
            .ok_or(I2PError::Malformed("ntcp2: padding_len overflow"))?;
        if wire.len() < total {
            return Err(I2PError::InvalidLength {
                expected: total,
                got: wire.len(),
            });
        }
        self.apply_session_created_padding(&wire[64..total]);
        Ok(info)
    }

    /// Обрабатывает `SessionConfirmed` (Bob ← Alice).
    ///
    /// ## Что делает
    ///
    /// 1. Расшифровывает part1 (48 байт) — получает static pub Alice'а.
    ///    Сохраняет его в [`Self::remote_static_pub`] и возвращает наружу.
    /// 2. MixHash(part1).
    /// 3. [`Self::kdf3_bob`] — MixKey(DH(`bob_ephemeral`, `alice_static`)).
    /// 4. Расшифровывает part2 (ровно `self.m3p2_len` байт, включая
    ///    16 MAC). Получает `RouterInfo`-блок в plaintext.
    /// 5. MixHash(part2).
    /// 6. Парсит RouterInfo-блок: ожидает ровно один блок типа
    ///    [`Ntcp2BlockType::RouterInfo`] с флагом и RI.
    ///
    /// ## Параметры
    ///
    /// - `wire` — весь `SessionConfirmed`.
    ///
    /// ## Ограничение
    ///
    /// Проверку «`RouterInfo` от того же роутера, к которому мы
    /// обращались» здесь не делаем — caller сам сверит
    /// [`SessionConfirmedInfo::remote_router_info`] с netdb.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `wire` короче, чем
    ///   `48 + m3p2_len`;
    /// - [`Error::Malformed`] — AEAD не прошёл, либо блок `RouterInfo`
    ///   отсутствует / имеет неверный формат;
    /// - [`Error::Unsupported`] — Alice запросила post-quantum.
    pub fn process_session_confirmed(&mut self, wire: &[u8]) -> Result<SessionConfirmedInfo> {
        trace!(
            wire_len = wire.len(),
            "process_session_confirmed: enter (Bob)"
        ); // 1. part1.
        if wire.len() < 48 {
            return Err(I2PError::InvalidLength {
                expected: 48,
                got: wire.len(),
            });
        }
        let mut s_pub = [0u8; 32];
        self.noise.decrypt(&wire[..48], &mut s_pub)?;
        self.noise.mix_hash(&wire[..48]);

        if s_pub[31] & 0x80 != 0 {
            return Err(I2PError::Unsupported(
                "ntcp2: post-quantum handshake is not supported",
            ));
        }
        self.remote_static_pub = s_pub;

        // 2. KDF3 Bob.
        self.kdf3_bob()?;

        // 3. part2.
        let m3p2_len = usize::from(self.m3p2_len);
        if m3p2_len < 16 {
            return Err(I2PError::Malformed(
                "ntcp2: m3p2_len too small to contain AEAD MAC",
            ));
        }
        let total = 48usize
            .checked_add(m3p2_len)
            .ok_or(I2PError::Malformed("ntcp2: m3p2_len overflow"))?;
        if wire.len() < total {
            return Err(I2PError::InvalidLength {
                expected: total,
                got: wire.len(),
            });
        }
        let part2 = &wire[48..total];
        let plaintext_len = m3p2_len - 16;
        let mut m3p2_plaintext = vec![0u8; plaintext_len];
        self.noise.decrypt(part2, &mut m3p2_plaintext)?;
        self.noise.mix_hash(part2);

        // 4. Парсинг m3p2: ровно один RouterInfo-блок.
        if m3p2_plaintext.len() < 4 {
            return Err(I2PError::Malformed("ntcp2: m3p2 plaintext too short"));
        }
        let block_type = Ntcp2BlockType::from_u8(m3p2_plaintext[0])?;
        if block_type != Ntcp2BlockType::RouterInfo {
            return Err(I2PError::Malformed(
                "ntcp2: first block in SessionConfirmed must be RouterInfo",
            ));
        }
        let size = u16::from_be_bytes([m3p2_plaintext[1], m3p2_plaintext[2]]) as usize;
        // size = RI_len + 1 (флаг + RI). Проверяем, что хватает байт.
        let expected = 3usize
            .checked_add(size)
            .ok_or(I2PError::Malformed("ntcp2: RI block size overflow"))?;
        if m3p2_plaintext.len() < expected {
            return Err(I2PError::InvalidLength {
                expected,
                got: m3p2_plaintext.len(),
            });
        }
        // flag = m3p2_plaintext[3]; пока не используется.
        let ri_bytes = m3p2_plaintext[4..expected].to_vec();

        // m3p2_len сбрасываем — после SessionConfirmed он не нужен.
        self.m3p2_len = 0;
        info!(
            remote_ri_len = ri_bytes.len(),
            "process_session_confirmed: done"
        );
        Ok(SessionConfirmedInfo {
            remote_static_pub: s_pub,
            remote_router_info: ri_bytes,
        })
    }

    /// Выводит [`Ntcp2DataPhase`] из текущего состояния Noise.
    ///
    /// Вызывать после успешного завершения handshake'а (обе стороны
    /// сделали KDF1, KDF2, KDF3).
    #[must_use]
    pub fn derive_data_phase(&self, is_alice: bool) -> Ntcp2DataPhase {
        trace!(
            is_alice,
            ck_head = format_args!("{}", hex_head(&self.noise.ck, 4)),
            h_head = format_args!("{}", hex_head(&self.noise.h, 4)),
            "derive_data_phase"
        );
        Ntcp2DataPhase::derive(&self.noise.ck, &self.noise.h, is_alice)
    }
    /// Длина `m3p2_len`, которая сейчас записана в options `SessionRequest`'а.
    ///
    /// Читается caller'ом, чтобы заранее знать размер `SessionConfirmed`.
    /// После успешного `create_session_confirmed` сбрасывается в 0.
    #[must_use]
    pub const fn m3p2_len(&self) -> u16 {
        self.m3p2_len
    }
}

// --- NTCP2 session (tokio) -----------------------------------------------

/// Локальная конфигурация для NTCP2-сессии.
///
/// В i2pd эти данные живут в `RouterContext`: статический NTCP2-ключ,
/// IV, свой `RouterInfo`. Здесь передаются явно — никакого глобального
/// состояния.
///
/// Ссылки вместо владения: `X25519Keys` не `Clone` (это секрет),
/// а `ri_bytes` может быть большим и мы не хотим его копировать на
/// каждой сессии.
pub struct Ntcp2LocalConfig<'a> {
    /// Static X25519-ключи для NTCP2.
    pub static_keys: &'a I2PX25519Keys,
    /// `IdentHash` своего роутера. Используется как AES-ключ для
    /// обфускации `X`/`Y` в handshake.
    pub ident_hash: [u8; 32],
    /// NTCP2 IV (16 байт из своего `RouterInfo`).
    pub iv: [u8; 16],
    /// Сырые байты своего `RouterInfo` (identity + body + signature).
    pub ri_bytes: &'a [u8],
    /// Ожидаемый `netId`. Обычно 2.
    pub net_id: u8,
}

/// Владеющая версия [`Ntcp2LocalConfig`].
///
/// Нужна там, где локальные данные живут дольше одного вызова: пул/транспорт
/// роутера держит их между соединениями, а [`Ntcp2LocalConfig`] только
/// заимствует ключи и байты RI. Ключи и IV берутся из [`RouterConfig`],
/// `ri_bytes` — из собственного `RouterInfo` (его надо обновлять
/// [`Self::set_router_info`] после [`crate::RouterContext::rebuild_own_ri`]).
///
/// i2pd держит то же самое в `RouterContext` (`m_NTCP2Keys`,
/// `m_RouterInfo`) и отдаёт в `NTCP2Session` при каждом соединении.
pub struct Ntcp2Local {
    static_keys: I2PX25519Keys,
    ident_hash: [u8; 32],
    iv: [u8; 16],
    ri_bytes: Vec<u8>,
    net_id: u8,
}

impl Ntcp2Local {
    /// Собирает локальные данные из любых источников.
    #[must_use]
    pub const fn new(
        static_keys: I2PX25519Keys,
        ident_hash: [u8; 32],
        iv: [u8; 16],
        ri_bytes: Vec<u8>,
        net_id: u8,
    ) -> Self {
        Self {
            static_keys,
            ident_hash,
            iv,
            ri_bytes,
            net_id,
        }
    }

    /// Берёт ключи, IV и `netId` из конфигурации, RI — снаружи.
    ///
    /// `ri_bytes` должен быть собран **той же** конфигурацией: i2pd сверяет
    /// `s` из NTCP2-адреса в `SessionConfirmed` со статическим ключом,
    /// которым шёл handshake (`NTCPSession.cpp`, `EstablishSessionAfter...`).
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если identity-ключ не даёт `IdentHash`
    /// ожидаемой длины.
    pub fn from_config(config: &crate::config::RouterConfig, ri_bytes: Vec<u8>) -> Result<Self> {
        let ident_hash: [u8; 32] = (*config.keys().public().ident_hash()).into();
        let private_key = config.ntcp2_static().private_key();
        Ok(Self {
            static_keys: I2PX25519Keys::from_private(
                &private_key,
                Some(config.ntcp2_static().public_key()),
            ),
            ident_hash,
            iv: *config.ntcp2_iv(),
            ri_bytes,
            net_id: config.net_id(),
        })
    }

    /// Заимствованная конфигурация для handshake.
    #[must_use]
    pub fn config(&self) -> Ntcp2LocalConfig<'_> {
        Ntcp2LocalConfig {
            static_keys: &self.static_keys,
            ident_hash: self.ident_hash,
            iv: self.iv,
            ri_bytes: &self.ri_bytes,
            net_id: self.net_id,
        }
    }

    /// `IdentHash` своего роутера.
    #[must_use]
    pub const fn ident_hash(&self) -> &[u8; 32] {
        &self.ident_hash
    }

    /// NTCP2 IV (тот, что опубликован в RI).
    #[must_use]
    pub const fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Сырые байты своего `RouterInfo`.
    #[must_use]
    pub fn router_info(&self) -> &[u8] {
        &self.ri_bytes
    }

    /// Обновляет свой `RouterInfo` (новый timestamp, адреса).
    pub fn set_router_info(&mut self, ri_bytes: Vec<u8>) {
        self.ri_bytes = ri_bytes;
    }
}

impl std::fmt::Debug for Ntcp2Local {
    /// Печатает, что есть, но не сами секреты.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ntcp2Local")
            .field("ident_hash", &crate::IdentHash::from_array(self.ident_hash))
            .field("iv", &self.iv)
            .field("ri_len", &self.ri_bytes.len())
            .field("net_id", &self.net_id)
            .finish_non_exhaustive()
    }
}

/// Установленная NTCP2-сессия.
///
/// Создаётся через [`Self::connect`] (Alice) или [`Self::accept`] (Bob).
/// После handshake'а методы [`Self::send_i2np`] и [`Self::recv_i2np`]
/// обмениваются I2NP-сообщениями в data phase.
///
/// ## Что НЕ реализовано
///
/// - Свой `RouterInfo` отправляется только Bob'ом, один раз, в первом
///   исходящем data-фрейме. Alice шлёт его в `SessionConfirmed` part2 и
///   через `send_i2np` повторно не отправляет.
/// - Автоматической обработки `Termination` — `recv_i2np` вернёт
///   `Error::Io` с текстом "peer terminated".
/// - Таймаутов на recv — caller сам решает, использовать ли
///   `tokio::time::timeout`.
pub struct Ntcp2Session {
    stream: TcpStream,
    data_phase: Ntcp2DataPhase,
    local_ri_bytes: Vec<u8>,
    remote_ri_bytes: Option<Vec<u8>>,
    remote_ident_hash: [u8; 32],
    remote_static_pub: [u8; 32],
    is_alice: bool,
}

impl Ntcp2Session {
    /// Устанавливает NTCP2-сессию как Alice (инициатор).
    ///
    /// `remote_ri_bytes` — сырые байты `RouterInfo` Bob'а, полученные
    /// из netDb. Из них берутся `static X25519 key` и IV NTCP2-адреса.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибки TCP;
    /// - [`Error::Malformed`] — handshake не сошёлся;
    /// - [`Error::Unsupported`] — peer запросил post-quantum;
    /// - ошибки разбора RI.
    pub async fn connect(
        mut stream: TcpStream,
        local: &Ntcp2LocalConfig<'_>,
        remote_ri_bytes: &[u8],
    ) -> Result<Self> {
        info!(
            ri_len = remote_ri_bytes.len(),
            "Ntcp2Session::connect: enter (Alice)"
        );

        let remote_ri = FullRouterInfo::from_buffer(remote_ri_bytes)?;
        let addr = find_ntcp2_address(&remote_ri).ok_or(I2PError::Malformed(
            "ntcp2: no published NTCP2 address in remote RI",
        ))?;
        let remote_static_pub = *addr.s.as_bytes();
        let mut remote_iv = [0u8; 16];
        remote_iv.copy_from_slice(&addr.i.as_bytes()[..16]);
        let remote_ident_hash = *remote_ri.ident_hash().as_bytes();

        debug!(

            remote_ident = %remote_ri.ident_hash().to_base64(),
            remote_host = %addr.host,
            remote_port = addr.port,
            "Ntcp2Session::connect: remote RI parsed"
        );

        let mut est = Ntcp2Establisher::new();
        est.remote_static_pub = remote_static_pub;
        est.remote_ident_hash = remote_ident_hash;
        est.iv = remote_iv;

        // 1. SessionRequest — голые байты, без префикса длины.
        //
        //    `StdRng::from_entropy()` вместо `thread_rng()`: future
        //    остаётся Send через `.await`.
        let mut rng = StdRng::try_from_rng(&mut SysRng)
            .map_err(|e| I2PError::Io(format!("ntcp2: failed to seed RNG: {e}")))?;
        let req = est.create_session_request(local.ri_bytes, local.net_id, &mut rng)?;
        info!(len = req.len(), "connect: sending SessionRequest");
        write_handshake(&mut stream, &req).await?;

        // 2. SessionCreated — сначала ровно 64 байта заголовков,
        //    потом отдельно padding.
        let headers = read_handshake(&mut stream, 64).await?;
        let created_info = est.process_session_created_headers(&headers, now_secs())?;
        if created_info.clock_skew {
            warn!(
                ts_b = created_info.ts_b,
                now_s = now_secs(),
                "connect: clock skew detected in SessionCreated"
            );
            return Err(I2PError::Malformed("ntcp2: clock skew in SessionCreated"));
        }
        if created_info.padding_len > 0 {
            let padding =
                read_handshake(&mut stream, usize::from(created_info.padding_len)).await?;
            est.apply_session_created_padding(&padding);
        }

        // 3. SessionConfirmed — голые байты.
        let confirmed = est.create_session_confirmed(local.static_keys)?;
        info!(len = confirmed.len(), "connect: sending SessionConfirmed");
        write_handshake(&mut stream, &confirmed).await?;

        let data_phase = est.derive_data_phase(true);
        info!("connect: handshake complete, data phase derived (is_alice=true)");

        Ok(Self {
            stream,
            data_phase,
            local_ri_bytes: local.ri_bytes.to_vec(),
            remote_ri_bytes: Some(remote_ri_bytes.to_vec()),
            remote_ident_hash,
            remote_static_pub,
            is_alice: true,
        })
    }

    /// Устанавливает NTCP2-сессию как Bob (принимающий).
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибки TCP;
    /// - [`Error::Malformed`] — handshake не сошёлся;
    /// - [`Error::Unsupported`] — peer запросил post-quantum.
    pub async fn accept(mut stream: TcpStream, local: &Ntcp2LocalConfig<'_>) -> Result<Self> {
        info!("Ntcp2Session::accept: enter (Bob)");

        let mut est = Ntcp2Establisher::new();
        est.iv = local.iv;
        let now_s = now_secs();

        // 1. SessionRequest — сначала ровно 64 байта заголовков,
        //    потом отдельно padding.
        let headers = read_handshake(&mut stream, 64).await?;
        let req_info = est.process_session_request_headers(
            &headers,
            &local.ident_hash,
            &local.iv,
            local.static_keys,
            local.net_id,
            now_s,
        )?;
        if req_info.clock_skew {
            warn!(
                ts_a = req_info.ts_a,
                now_s, "accept: clock skew detected in SessionRequest"
            );
            return Err(I2PError::Malformed("ntcp2: clock skew in SessionRequest"));
        }
        if req_info.padding_len > 0 {
            let padding = read_handshake(&mut stream, usize::from(req_info.padding_len)).await?;
            est.apply_session_request_padding(&padding);
        }

        // 2. SessionCreated — голые байты.
        let mut rng = StdRng::try_from_rng(&mut SysRng)
            .map_err(|e| I2PError::Io(format!("ntcp2: failed to seed RNG: {e}")))?;
        let created =
            est.create_session_created(&local.ident_hash, local.net_id, now_s, &mut rng)?;
        info!(len = created.len(), "accept: sending SessionCreated");
        write_handshake(&mut stream, &created).await?;

        // 3. SessionConfirmed — ровно 48 + m3p2_len байт.
        //    m3p2_len известна из options SessionRequest.
        let m3p2_len = usize::from(est.m3p2_len());
        let total = 48usize
            .checked_add(m3p2_len)
            .ok_or(I2PError::Malformed("ntcp2: m3p2_len overflow"))?;
        let confirmed = read_handshake(&mut stream, total).await?;
        let confirmed_info = est.process_session_confirmed(&confirmed)?;

        let alice_ri = FullRouterInfo::from_buffer(&confirmed_info.remote_router_info)?;
        let remote_ident_hash = *alice_ri.ident_hash().as_bytes();
        let remote_static_pub = confirmed_info.remote_static_pub;

        let data_phase = est.derive_data_phase(false);
        info!(

            remote_ident = %alice_ri.ident_hash().to_base64(),
            "accept: handshake complete, data phase derived (is_alice=false)"
        );

        let mut session = Self {
            stream,
            data_phase,
            local_ri_bytes: local.ri_bytes.to_vec(),
            remote_ri_bytes: Some(confirmed_info.remote_router_info),
            remote_ident_hash,
            remote_static_pub,
            is_alice: false,
        };

        // i2pd: Transports::PeerConnected -> SendLocalRouterInfo.
        session.send_router_info().await?;
        Ok(session)
    }

    /// `true`, если мы инициатор.
    #[must_use]
    pub const fn is_alice(&self) -> bool {
        self.is_alice
    }

    /// `IdentHash` peer'а (вычисляется из его `RouterInfo`).
    #[must_use]
    pub const fn remote_ident_hash(&self) -> &[u8; 32] {
        &self.remote_ident_hash
    }

    /// Static X25519-ключ peer'а, узнанный в handshake.
    #[must_use]
    pub const fn remote_static_pub(&self) -> &[u8; 32] {
        &self.remote_static_pub
    }

    /// Сырые байты `RouterInfo` peer'а, если уже известны.
    ///
    /// У Alice — с момента `connect` (передано вызывающим).
    /// У Bob — с момента обработки `SessionConfirmed`.
    #[must_use]
    pub fn remote_router_info(&self) -> Option<&[u8]> {
        self.remote_ri_bytes.as_deref()
    }

    /// Отправляет собственный `RouterInfo` отдельным фреймом
    /// (`DateTime` + `RouterInfo` + padding).
    ///
    /// Соответствует `NTCP2Session::SendRouterInfo()` в i2pd:
    /// фрейм из блоков `DateTime` + `RouterInfo` + padding.
    /// Никаких I2NP-блоков внутри — i2pd их отправляет
    /// отдельным фреймом через `SendI2NPMsgs`.
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибка записи в TCP-сокет;
    /// - [`Error::Malformed`] — фрейм не собирается (например,
    ///   сериализованный блок не влезает в лимит NTCP2).
    pub async fn send_router_info(&mut self) -> Result<()> {
        let blocks = vec![
            Ntcp2Block::DateTime { ts: now_secs_u32() },
            Ntcp2Block::RouterInfo {
                flag: 0,
                ri_bytes: self.local_ri_bytes.clone(),
            },
        ];
        let wire = self.data_phase.create_frame(&blocks)?;
        trace!(
            ri_len = self.local_ri_bytes.len(),
            wire_len = wire.len(),
            "Ntcp2Session::send_router_info: writing"
        );
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        debug!("Ntcp2Session::send_router_info: sent");
        Ok(())
    }

    /// Отправляет I2NP-сообщение в data phase.
    ///
    /// Внутри формируется NTCP2-фрейм: опциональный RouterInfo-блок
    /// (только Bob, один раз), `DateTime`, `I2npMessage`.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибка TCP;
    /// - [`Error::Malformed`] — I2NP-сообщение слишком велико или
    ///   не сериализуется.
    pub async fn send_i2np(&mut self, msg: &I2npMessage) -> Result<()> {
        let payload = msg.to_ntcp2_bytes();
        let blocks = vec![
            Ntcp2Block::DateTime { ts: now_secs_u32() },
            Ntcp2Block::I2npMessage(payload.clone()),
        ];
        let wire = self.data_phase.create_frame(&blocks)?;
        debug!(
            is_alice = self.is_alice,
            i2np_len = payload.len(),
            wire_len = wire.len(),
            "Ntcp2Session::send_i2np: writing"
        );
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        Ok(())
    }

    /// Принимает следующее I2NP-сообщение.
    ///
    /// Побочно обрабатывает `RouterInfo`-блоки (сохраняет RI peer'а,
    /// обновляет [`Self::remote_router_info`]) и `Termination`
    /// (возвращает ошибку).
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибка TCP или Termination от peer'а;
    /// - [`Error::Malformed`] — фрейм не расшифровался или I2NP не
    ///   распарсился.
    pub async fn recv_i2np(&mut self) -> Result<I2npMessage> {
        loop {
            let blocks = self.read_frame().await?;
            trace!(
                blocks = blocks.len(),
                "Ntcp2Session::recv_i2np: frame parsed"
            );
            for block in blocks {
                match block {
                    Ntcp2Block::I2npMessage(bytes) => {
                        debug!(i2np_len = bytes.len(), "Ntcp2Session::recv_i2np: got I2NP");
                        return I2npMessage::from_ntcp2_bytes(&bytes);
                    }
                    Ntcp2Block::RouterInfo { ri_bytes, .. } => {
                        debug!(
                            ri_len = ri_bytes.len(),
                            "Ntcp2Session::recv_i2np: peer RI updated"
                        );
                        self.remote_ri_bytes = Some(ri_bytes);
                    }
                    Ntcp2Block::Termination { reason, seqn, .. } => {
                        warn!(

                            reason = %reason,
                            seqn,
                            "Ntcp2Session::recv_i2np: peer terminated"
                        );
                        return Err(I2PError::Io(format!("ntcp2: peer terminated ({reason})")));
                    }
                    Ntcp2Block::DateTime { .. }
                    | Ntcp2Block::Options(_)
                    | Ntcp2Block::Padding(_) => {}
                }
            }
            // В этом фрейме I2NP не было — читаем следующий.
        }
    }

    /// Читает один NTCP2-фрейм и разбирает его на блоки.
    async fn read_frame(&mut self) -> Result<Vec<Ntcp2Block>> {
        let mut len_prefix = [0u8; 2];
        self.stream
            .read_exact(&mut len_prefix)
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        let frame_len = usize::from(self.data_phase.read_frame_length(len_prefix));
        if frame_len < 16 || frame_len + 2 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE {
            return Err(I2PError::Malformed("ntcp2: frame length out of range"));
        }
        let mut ciphertext = vec![0u8; frame_len];
        self.stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        self.data_phase.decrypt_frame(&ciphertext)
    }
}

/// Read-половина сессии.
///
/// Хранит `OwnedReadHalf` + `Ntcp2ReceiveHalf` + снимок идентичностей,
/// нужный для диспетчеризации принятых сообщений. `remote_ri_bytes`
/// обновляется, если peer прислал свой RI в data phase.
pub struct Ntcp2SessionRead {
    stream: tokio::net::tcp::OwnedReadHalf,
    receive: Ntcp2ReceiveHalf,
    remote_ident_hash: [u8; 32],
    remote_ri_bytes: Option<Vec<u8>>,
}

impl Ntcp2SessionRead {
    /// `IdentHash` peer'а.
    #[must_use]
    pub const fn remote_ident_hash(&self) -> &[u8; 32] {
        &self.remote_ident_hash
    }

    /// Сырые байты RI peer'а, если уже получены.
    #[must_use]
    pub fn remote_router_info(&self) -> Option<&[u8]> {
        self.remote_ri_bytes.as_deref()
    }

    /// Читает один NTCP2-фрейм и разбирает его на блоки.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибка TCP;
    /// - [`Error::Malformed`] — длина фрейма вне допустимого диапазона
    ///   или AEAD не прошёл.
    pub async fn read_frame(&mut self) -> Result<Vec<Ntcp2Block>> {
        let mut len_prefix = [0u8; 2];
        self.stream
            .read_exact(&mut len_prefix)
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        let frame_len = usize::from(self.receive.read_frame_length(len_prefix));
        if frame_len < 16 || frame_len + 2 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE {
            return Err(I2PError::Malformed("ntcp2: frame length out of range"));
        }
        let mut ciphertext = vec![0u8; frame_len];
        self.stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        self.receive.decrypt_frame(&ciphertext)
    }

    /// Читает фрейм, обновляет `remote_ri_bytes` при `RouterInfo`,
    /// возвращает первое I2NP-сообщение в этом фрейме.
    ///
    /// Пропускает фреймы, где I2NP не было. Прерывается на
    /// `Termination`.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибка TCP или `Termination` от peer'а;
    /// - [`Error::Malformed`] — I2NP в блоке не распарсился.
    pub async fn recv_i2np(&mut self) -> Result<I2npMessage> {
        loop {
            let blocks = self.read_frame().await?;
            for block in blocks {
                match block {
                    Ntcp2Block::I2npMessage(bytes) => {
                        return I2npMessage::from_ntcp2_bytes(&bytes);
                    }
                    Ntcp2Block::RouterInfo { ri_bytes, .. } => {
                        self.remote_ri_bytes = Some(ri_bytes);
                    }
                    Ntcp2Block::Termination { reason, .. } => {
                        return Err(I2PError::Io(format!("ntcp2: peer terminated ({reason})")));
                    }
                    Ntcp2Block::DateTime { .. }
                    | Ntcp2Block::Options(_)
                    | Ntcp2Block::Padding(_) => {}
                }
            }
        }
    }
}

/// Write-половина сессии.
///
/// Хранит `OwnedWriteHalf` + `Ntcp2SendHalf` + локальные данные,
/// которые нужно один раз дописать в первый data-фрейм (Bob — свой
/// `RouterInfo`).
pub struct Ntcp2SessionWrite {
    stream: tokio::net::tcp::OwnedWriteHalf,
    send: Ntcp2SendHalf,
}

impl Ntcp2SessionWrite {
    /// Отправляет готовый список блоков.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — ошибка TCP;
    /// - [`Error::Malformed`] — блоки не сериализуются или кадр
    ///   слишком велик.
    pub async fn send_blocks(&mut self, blocks: &[Ntcp2Block]) -> Result<()> {
        let wire = self.send.create_frame(blocks)?;
        trace!(
            blocks = blocks.len(),
            wire_len = wire.len(),
            "Ntcp2SessionWrite::send_blocks: writing"
        );
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| I2PError::Io(e.to_string()))?;
        Ok(())
    }

    /// Отправляет I2NP-сообщение. Bob в первом фрейме приложит свой RI.
    ///
    /// # Errors
    ///
    /// См. [`Self::send_blocks`].
    pub async fn send_i2np(&mut self, msg: &I2npMessage) -> Result<()> {
        let payload = msg.to_ntcp2_bytes();
        debug!(i2np_len = payload.len(), "Ntcp2SessionWrite::send_i2np");
        let blocks = vec![
            Ntcp2Block::DateTime { ts: now_secs_u32() },
            Ntcp2Block::I2npMessage(payload),
        ];
        self.send_blocks(&blocks).await
    }

    /// Отправляет `Termination` и закрывает свою сторону TCP
    /// (i2pd `NTCP2Session::SendTermination`).
    ///
    /// `seqn` — номер последнего отправленного/следующего фрейма, как в
    /// i2pd (`m_SendSequenceNumber`). После него write-половина
    /// бесполезна: TCP уходит в FIN, читать ответ можно до EOF.
    ///
    /// # Errors
    ///
    /// См. [`Self::send_blocks`].
    pub async fn send_termination(&mut self, reason: Ntcp2TerminationReason) -> Result<()> {
        let blocks = [Ntcp2Block::Termination {
            seqn: self.send.sequence_number(),
            reason,
        }];
        debug!(?reason, "Ntcp2SessionWrite::send_termination");
        self.send_blocks(&blocks).await?;
        self.stream
            .shutdown()
            .await
            .map_err(|e| I2PError::Io(e.to_string()))
    }
}

impl Ntcp2Session {
    /// Потребляет сессию, разделяя её на read- и write-половины.
    ///
    /// Каждая половина независима: read-таск сессии держит одну,
    /// write-таск — другую. Это позволяет читать и писать
    /// **одновременно** через `tokio::spawn`.
    #[must_use]
    pub fn split(self) -> (Ntcp2SessionRead, Ntcp2SessionWrite) {
        debug!(
            is_alice = self.is_alice,
            has_remote_ri = self.remote_ri_bytes.is_some(),
            "Ntcp2Session::split: into read/write halves"
        );
        let (read_half, write_half) = self.stream.into_split();
        let (send, receive) = self.data_phase.into_halves();
        (
            Ntcp2SessionRead {
                stream: read_half,
                receive,
                remote_ident_hash: self.remote_ident_hash,
                remote_ri_bytes: self.remote_ri_bytes,
            },
            Ntcp2SessionWrite {
                stream: write_half,
                send,
            },
        )
    }
}

// --- helpers -------------------------------------------------------------

/// Ищет в `RouterInfo` опубликованный NTCP2-адрес (v4 или v6).
///
/// Опубликованный — значит есть `host` (не unspecified) и ненулевой
/// `port`. У неопубликованных адресов `host` = `0.0.0.0`, к ним
/// подключиться нельзя.
fn find_ntcp2_address(ri: &FullRouterInfo) -> Option<&I2PAddress> {
    ri.body()
        .addresses
        .iter()
        .find(|a| a.is_ntcp2() && a.published && !a.host.is_unspecified() && a.port != 0)
}

/// Текущее время в секундах since epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Текущее время в секундах since epoch, усечённое до `u32`.
fn now_secs_u32() -> u32 {
    u32::try_from(now_secs()).unwrap_or(u32::MAX)
}

/// Пишет handshake-сообщение в TCP-сокет «как есть», без
/// 2-байтового префикса длины.
///
/// ## Почему без префикса
///
/// В NTCP2 префикс длины существует **только в data phase**, и он
/// обфусцирован `SipHash`'ем (см. [`Ntcp2DataPhase::obfuscate_send_length`]).
/// В handshake'е ни `SessionRequest`, ни `SessionCreated`, ни
/// `SessionConfirmed` не имеют length-prefix'а — i2pd читает их
/// через `async_read(socket, buffer, N)` с фиксированным `N`:
///
/// - `SessionRequest` — сначала ровно `64` байта заголовков, потом
///   `padding_len` байт padding'а (`NTCP2Session::ServerLogin` +
///   `HandleSessionRequestPaddingReceived`);
/// - `SessionCreated` — то же самое со стороны Alice
///   (`HandleSessionCreatedPaddingReceived`);
/// - `SessionConfirmed` — ровно `48 + m3p2_len` байт, обе величины
///   известны заранее из options `SessionRequest`'а
///   (`HandleSessionConfirmedReceived`).
///
/// ## Побочные эффекты
///
/// Делает `write_all` + `flush`. Ошибки ввода-вывода превращаются
/// в [`I2PError::Io`].
///
/// # Errors
///
/// [`I2PError::Io`] при любой ошибке записи или flush'а.
async fn write_handshake(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    trace!(
        len = data.len(),
        head = format_args!("{}", hex_head(data, 32)),
        "write_handshake: sending raw bytes (no length prefix)"
    );
    stream
        .write_all(data)
        .await
        .map_err(|e| I2PError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| I2PError::Io(e.to_string()))?;
    Ok(())
}

/// Читает ровно `len` байт handshake-сообщения из TCP-сокета.
///
/// Никакого префикса длины не читает — вызывающий сам знает, сколько
/// байт ожидает:
///
/// - `64` для заголовков `SessionRequest` / `SessionCreated`;
/// - `padding_len` для padding-хвоста после заголовков;
/// - `48 + m3p2_len` для `SessionConfirmed`.
///
/// Соответствует i2pd `boost::asio::async_read(m_Socket,
/// boost::asio::buffer(buf, N), boost::asio::transfer_all(), ...)`:
/// тот же контракт — прочитать ровно `N` байт или получить ошибку
/// (включая `eof`, если peer закрыл соединение).
///
/// # Errors
///
/// [`I2PError::Io`] при любой ошибке чтения, включая преждевременный
/// `eof`.
async fn read_handshake(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| I2PError::Io(e.to_string()))?;
    trace!(
        len = buf.len(),
        head = format_args!("{}", hex_head(&buf, 32)),
        "read_handshake: got raw bytes"
    );
    Ok(buf)
}

/// Печатает первые `n` байт среза в hex — для трейс-логов.
fn hex_head(data: &[u8], n: usize) -> String {
    use std::fmt::Write as _;
    let n = n.min(data.len());
    let mut s = String::with_capacity(n * 2 + 3);
    for b in &data[..n] {
        let _ = write!(s, "{b:02x}");
    }
    if data.len() > n {
        s.push_str("..");
    }
    s
}
