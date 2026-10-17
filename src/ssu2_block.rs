//! SSU2 — блоки payload'а.
//!
//! Слой ниже сообщений и выше «сырых байт»: после (де)обфускации заголовка
//! и AEAD-расшифровки остаётся последовательность блоков. Каждый блок:
//!
//! ```text
//! 0        block type (1 байт)
//! 1..3     block size (u16 big-endian, размер тела)
//! 3..      body (size байт)
//! ```
//!
//! Модуль даёт:
//! - [`Ssu2BlockType`] — зарегистрированные типы блоков (0..21, 254);
//! - [`Blocks`] — безопасный итератор по блокам payload'а (не выходит за
//!   границы; неизвестные типы отдаются как сырые — forward compatibility);
//! - [`write_block`] / [`write_raw_block`] — сборка блока;
//! - типизированные блоки через трейт [`Ssu2Block`].
//!
//! Формат повторяет i2pd (`HandlePayload` в `SSU2Session.cpp`) и
//! спецификацию SSU2.
//!
//! ## Реализованные блоки
//!
//! [`DateTimeBlock`], [`OptionsBlock`], [`RouterInfoBlock`], [`I2npBlock`],
//! [`FirstFragmentBlock`], [`FollowOnFragmentBlock`], [`TerminationBlock`],
//! [`AddressBlock`], [`RelayTagRequestBlock`], [`RelayTagBlock`],
//! [`NewTokenBlock`], [`PathChallengeBlock`], [`PathResponseBlock`],
//! [`FirstPacketNumberBlock`], [`PaddingBlock`].
//!
//! ## Что не внутри (следующие итерации)
//!
//! - `Ack` (12) — реализован в [`crate::ssu2_ack`];
//! - TODO(ssu2-blocks): `RelayRequest` / `RelayResponse` / `RelayIntro`
//!   (7-9) и `PeerTest` (10) — несут подписи, ближе к протокольной логике;
//! - TODO(ssu2-blocks): `Congestion` (21) и `NextNonce` (11) — не
//!   специфицированы.
//!
//! Типы уже присутствуют в [`Ssu2BlockType`], но без типизированных
//! обёрток — до реализации они читаются/пишутся через [`RawBlock`] /
//! [`write_block`].

use crate::{
    endian::{read_u16_be, read_u32_be, read_u64_be, write_u32_be, write_u64_be},
    error::{I2PError, Result},
    i2np_message::I2npMessage,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Размер заголовка блока: 1 байт типа + 2 байта длины.
pub const SSU2_BLOCK_HEADER_SIZE: usize = 3;

/// Максимальный размер тела блока (равен `u16::MAX`).
pub const SSU2_BLOCK_MAX_BODY_SIZE: usize = 0xFFFF;

/// Минимальный размер блока `Options`.
pub const SSU2_OPTIONS_MIN_SIZE: usize = 12;

/// Бит 0 флагов `RouterInfo`: запрошен flood.
pub const SSU2_ROUTER_INFO_FLAG_FLOOD: u8 = 0x01;

/// Бит 1 флагов `RouterInfo`: тело сжато gzip.
pub const SSU2_ROUTER_INFO_FLAG_GZIP: u8 = 0x02;

// --- типы блоков --------------------------------------------------------

/// Тип блока payload'а SSU2.
///
/// Совпадает с `enum SSU2BlockType` в i2pd. Неизвестные/зарезервированные
/// значения [`Self::from_u8`] возвращает как `None`: по спеке их нужно
/// пропускать (forward compatibility), поэтому [`Blocks`] отдаёт сырой
/// [`RawBlock`] с числовым типом.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ssu2BlockType {
    /// `DateTime` (0).
    DateTime = 0,
    /// Options (1).
    Options = 1,
    /// Router Info (2).
    RouterInfo = 2,
    /// I2NP Message (3).
    I2npMessage = 3,
    /// First Fragment (4).
    FirstFragment = 4,
    /// Follow-on Fragment (5).
    FollowOnFragment = 5,
    /// Termination (6).
    Termination = 6,
    /// Relay Request (7).
    RelayRequest = 7,
    /// Relay Response (8).
    RelayResponse = 8,
    /// Relay Intro (9).
    RelayIntro = 9,
    /// Peer Test (10).
    PeerTest = 10,
    /// Next Nonce (11).
    NextNonce = 11,
    /// ACK (12).
    Ack = 12,
    /// Address (13).
    Address = 13,
    /// Relay Tag Request (15).
    RelayTagRequest = 15,
    /// Relay Tag (16).
    RelayTag = 16,
    /// New Token (17).
    NewToken = 17,
    /// Path Challenge (18).
    PathChallenge = 18,
    /// Path Response (19).
    PathResponse = 19,
    /// First Packet Number (20).
    FirstPacketNumber = 20,
    /// Congestion (21).
    Congestion = 21,
    /// Padding (254).
    Padding = 254,
}

impl Ssu2BlockType {
    /// Разбирает числовой тип. `None` — тип не зарегистрирован.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::DateTime,
            1 => Self::Options,
            2 => Self::RouterInfo,
            3 => Self::I2npMessage,
            4 => Self::FirstFragment,
            5 => Self::FollowOnFragment,
            6 => Self::Termination,
            7 => Self::RelayRequest,
            8 => Self::RelayResponse,
            9 => Self::RelayIntro,
            10 => Self::PeerTest,
            11 => Self::NextNonce,
            12 => Self::Ack,
            13 => Self::Address,
            15 => Self::RelayTagRequest,
            16 => Self::RelayTag,
            17 => Self::NewToken,
            18 => Self::PathChallenge,
            19 => Self::PathResponse,
            20 => Self::FirstPacketNumber,
            21 => Self::Congestion,
            254 => Self::Padding,
            _ => return None,
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
            Self::I2npMessage => "I2npMessage",
            Self::FirstFragment => "FirstFragment",
            Self::FollowOnFragment => "FollowOnFragment",
            Self::Termination => "Termination",
            Self::RelayRequest => "RelayRequest",
            Self::RelayResponse => "RelayResponse",
            Self::RelayIntro => "RelayIntro",
            Self::PeerTest => "PeerTest",
            Self::NextNonce => "NextNonce",
            Self::Ack => "Ack",
            Self::Address => "Address",
            Self::RelayTagRequest => "RelayTagRequest",
            Self::RelayTag => "RelayTag",
            Self::NewToken => "NewToken",
            Self::PathChallenge => "PathChallenge",
            Self::PathResponse => "PathResponse",
            Self::FirstPacketNumber => "FirstPacketNumber",
            Self::Congestion => "Congestion",
            Self::Padding => "Padding",
        }
    }
}

impl std::fmt::Display for Ssu2BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// --- сырой разбор -------------------------------------------------------

/// Сырой блок: числовой тип + тело.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawBlock<'a> {
    /// Тип блока как на wire (может быть незарегистрированным).
    pub block_type: u8,
    /// Тело блока (без 3-байтового заголовка).
    pub body: &'a [u8],
}

impl<'a> RawBlock<'a> {
    /// Зарегистрированный тип или `None` для неизвестного.
    #[must_use]
    pub const fn kind(&self) -> Option<Ssu2BlockType> {
        Ssu2BlockType::from_u8(self.block_type)
    }

    /// Разбирает тело в типизированный блок `T`.
    ///
    /// # Errors
    ///
    /// Ошибки конкретного блока — см. `T::parse`.
    pub fn parse<T: Ssu2Block<'a>>(&self) -> Result<T> {
        T::parse(self.body)
    }
}

/// Итератор по блокам payload'а.
///
/// Не выходит за границы: если заголовок обрезан или тело длиннее
/// оставшихся байт — возвращает ошибку и завершается. Пустой хвост
/// (0 байт) означает нормальное окончание; 1-2 «висячих» байта — ошибка
/// (i2pd просто игнорирует хвост, но молчаливая потеря данных опаснее).
#[derive(Debug, Clone)]
pub struct Blocks<'a> {
    rest: &'a [u8],
    failed: bool,
}

impl<'a> Blocks<'a> {
    /// Итератор по `payload`.
    #[must_use]
    pub const fn new(payload: &'a [u8]) -> Self {
        Self {
            rest: payload,
            failed: false,
        }
    }
}

impl<'a> Iterator for Blocks<'a> {
    type Item = Result<RawBlock<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < SSU2_BLOCK_HEADER_SIZE {
            self.failed = true;
            return Some(Err(I2PError::InvalidLength {
                expected: SSU2_BLOCK_HEADER_SIZE,
                got: self.rest.len(),
            }));
        }
        let block_type = self.rest[0];
        let size = usize::from(read_u16_be(&self.rest[1..3]));
        let total = SSU2_BLOCK_HEADER_SIZE + size;
        if self.rest.len() < total {
            self.failed = true;
            return Some(Err(I2PError::InvalidLength {
                expected: total,
                got: self.rest.len(),
            }));
        }
        let body = &self.rest[SSU2_BLOCK_HEADER_SIZE..total];
        self.rest = &self.rest[total..];
        Some(Ok(RawBlock { block_type, body }))
    }
}

// --- сборка -------------------------------------------------------------

/// Дописывает блок (`type` + `u16` big-endian длина + тело) в `out`.
///
/// # Errors
///
/// [`Error::Malformed`], если `body` длиннее [`SSU2_BLOCK_MAX_BODY_SIZE`].
pub fn write_block(out: &mut Vec<u8>, block_type: Ssu2BlockType, body: &[u8]) -> Result<()> {
    write_raw_block(out, block_type.as_u8(), body)
}

/// То же, но тип задан сырым байтом.
///
/// Нужен для неизвестных/зарезервированных типов и при пересборке payload'а
/// «как есть».
///
/// # Errors
///
/// [`Error::Malformed`], если `body` длиннее [`SSU2_BLOCK_MAX_BODY_SIZE`].
pub fn write_raw_block(out: &mut Vec<u8>, block_type: u8, body: &[u8]) -> Result<()> {
    let size = u16::try_from(body.len())
        .map_err(|_| I2PError::Malformed("ssu2: block body exceeds 65535 bytes"))?;
    out.reserve(SSU2_BLOCK_HEADER_SIZE + body.len());
    out.push(block_type);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

// --- трейт типизированного блока ----------------------------------------

/// Типизированный блок payload'а SSU2.
///
/// Параметризован временем жизни `'a`: блоки, которые заимствуют тело
/// (`RouterInfoBlock`, `FollowOnFragmentBlock`, ...), реализуют
/// `Ssu2Block<'a>` для себя с тем же временем жизни; владеющие блоки
/// (`I2npBlock`, ...) — для любого `'a`.
pub trait Ssu2Block<'a>: Sized {
    /// Тип блока.
    const TYPE: Ssu2BlockType;

    /// Разбирает тело блока (без 3-байтового заголовка).
    ///
    /// # Errors
    ///
    /// Зависит от конкретного блока: [`Error::InvalidLength`] при
    /// недостаточной длине, [`Error::Malformed`] при неверном формате.
    fn parse(body: &'a [u8]) -> Result<Self>;

    /// Пишет тело блока (без заголовка) в `out`.
    fn write_body(&self, out: &mut Vec<u8>);

    /// Тело блока.
    #[must_use]
    fn to_body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out);
        out
    }

    /// Дописывает блок (вместе с заголовком) в `out`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если тело длиннее [`SSU2_BLOCK_MAX_BODY_SIZE`].
    fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        write_block(out, Self::TYPE, &self.to_body())
    }
}

// --- DateTime -----------------------------------------------------------

/// `DateTime` (0): синхронизация времени.
///
/// Тело — `u32` big-endian: Unix-timestamp в секундах (переполнение в 2106).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTimeBlock {
    /// Unix timestamp, unsigned seconds.
    pub timestamp: u32,
}

impl<'a> Ssu2Block<'a> for DateTimeBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::DateTime;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 4 {
            return Err(I2PError::InvalidLength {
                expected: 4,
                got: body.len(),
            });
        }
        Ok(Self {
            timestamp: read_u32_be(body),
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.timestamp.to_be_bytes());
    }
}

// --- Options ------------------------------------------------------------

/// `Options` (1): параметры padding'а и dummy-трафика.
///
/// Первые [`SSU2_OPTIONS_MIN_SIZE`] байт — фиксированные поля, далее
/// `more` (формат пока не определён спекой).
///
/// `tmin`/`tmax`/`rmin`/`rmax` — 4.4 fixed-point (`raw / 16.0`) в диапазоне
/// `0..=15.9375`: отношение объёма padding'а к данным (передающие/принимающие
/// ограничения отправителя блока).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionsBlock {
    /// `tmin` — минимальный padding для отправки.
    pub tmin: u8,
    /// `tmax` — максимальный padding для отправки.
    pub tmax: u8,
    /// `rmin` — желаемый минимальный padding приёма.
    pub rmin: u8,
    /// `rmax` — допустимый максимальный padding приёма.
    pub rmax: u8,
    /// `tdmy` — готовность отправлять dummy-трафик, байт/сек.
    pub tdmy: u16,
    /// `rdmy` — запрошенный dummy-трафик, байт/сек.
    pub rdmy: u16,
    /// `tdelay` — допустимая вставка intra-message задержки, мс.
    pub tdelay: u16,
    /// `rdelay` — запрошенная intra-message задержка, мс.
    pub rdelay: u16,
    /// `more_options` — дополнительные опции (формат TBD).
    pub more: Vec<u8>,
}

impl<'a> Ssu2Block<'a> for OptionsBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::Options;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < SSU2_OPTIONS_MIN_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SSU2_OPTIONS_MIN_SIZE,
                got: body.len(),
            });
        }
        Ok(Self {
            tmin: body[0],
            tmax: body[1],
            rmin: body[2],
            rmax: body[3],
            tdmy: read_u16_be(&body[4..6]),
            rdmy: read_u16_be(&body[6..8]),
            tdelay: read_u16_be(&body[8..10]),
            rdelay: read_u16_be(&body[10..12]),
            more: body[SSU2_OPTIONS_MIN_SIZE..].to_vec(),
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.tmin, self.tmax, self.rmin, self.rmax]);
        out.extend_from_slice(&self.tdmy.to_be_bytes());
        out.extend_from_slice(&self.rdmy.to_be_bytes());
        out.extend_from_slice(&self.tdelay.to_be_bytes());
        out.extend_from_slice(&self.rdelay.to_be_bytes());
        out.extend_from_slice(&self.more);
    }
}

// --- RouterInfo ---------------------------------------------------------

/// `RouterInfo` (2): `RouterInfo` отправителя.
///
/// Тело: `flags` (1) + `frag` (1) + `RouterInfo`. В SSU2 блок никогда не
/// фрагментируется: `frag` всегда `0/1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterInfoBlock<'a> {
    /// Флаги (см. [`SSU2_ROUTER_INFO_FLAG_FLOOD`] и
    /// [`SSU2_ROUTER_INFO_FLAG_GZIP`]).
    pub flags: u8,
    /// `frag`: старшие 4 бита — номер фрагмента (0), младшие 4 — всего (1).
    pub frag: u8,
    /// `RouterInfo` (возможно, gzip-сжатый).
    pub router_info: &'a [u8],
}

impl RouterInfoBlock<'_> {
    /// Запрошен ли flood (бит 0 `flags`).
    #[must_use]
    pub const fn flood_requested(&self) -> bool {
        self.flags & SSU2_ROUTER_INFO_FLAG_FLOOD != 0
    }

    /// Сжато ли тело gzip'ом (бит 1 `flags`).
    #[must_use]
    pub const fn gzip_compressed(&self) -> bool {
        self.flags & SSU2_ROUTER_INFO_FLAG_GZIP != 0
    }

    /// Номер фрагмента (старшие 4 бита `frag`).
    #[must_use]
    pub const fn fragment_number(&self) -> u8 {
        self.frag >> 4
    }

    /// Общее число фрагментов (младшие 4 бита `frag`).
    #[must_use]
    pub const fn num_fragments(&self) -> u8 {
        self.frag & 0x0F
    }
}

impl<'a> Ssu2Block<'a> for RouterInfoBlock<'a> {
    const TYPE: Ssu2BlockType = Ssu2BlockType::RouterInfo;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 2 {
            return Err(I2PError::InvalidLength {
                expected: 2,
                got: body.len(),
            });
        }
        Ok(Self {
            flags: body[0],
            frag: body[1],
            router_info: &body[2..],
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.flags);
        out.push(self.frag);
        out.extend_from_slice(self.router_info);
    }
}

// --- I2NP Message / фрагменты -------------------------------------------

/// `I2NP Message` (3): полное I2NP-сообщение с 9-байтовым заголовком.
///
/// Заголовок совпадает с NTCP2-форматом (`type | msg id | short exp`),
/// поэтому переиспользуем [`I2npMessage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2npBlock(pub I2npMessage);

impl<'a> Ssu2Block<'a> for I2npBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::I2npMessage;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 9 {
            return Err(I2PError::InvalidLength {
                expected: 9,
                got: body.len(),
            });
        }
        Ok(Self(I2npMessage::from_ntcp2_bytes(body)?))
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_ntcp2_bytes());
    }
}

/// `First Fragment` (4): первый фрагмент I2NP-сообщения.
///
/// Формат тот же, что у [`I2npBlock`], но тело должно содержать часть
/// сообщения после 9-байтового заголовка (непустую).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstFragmentBlock(pub I2npMessage);

impl<'a> Ssu2Block<'a> for FirstFragmentBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::FirstFragment;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 10 {
            return Err(I2PError::InvalidLength {
                expected: 10,
                got: body.len(),
            });
        }
        Ok(Self(I2npMessage::from_ntcp2_bytes(body)?))
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_ntcp2_bytes());
    }
}

/// Байт `frag` для [`FollowOnFragmentBlock`]: номер в старших 7 битах,
/// `isLast` в младшем.
#[must_use]
pub fn follow_on_frag_byte(fragment_number: u8, is_last: bool) -> u8 {
    (fragment_number << 1) | u8::from(is_last)
}

/// `Follow-on Fragment` (5): фрагмент с номером > 0.
///
/// Тело: `frag` (1) + `msg id` (4, BE) + часть сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowOnFragmentBlock<'a> {
    /// `frag`: старшие 7 бит — номер (1..127), младший — `isLast`.
    pub frag: u8,
    /// ID I2NP-сообщения.
    pub msg_id: u32,
    /// Часть сообщения.
    pub data: &'a [u8],
}

impl FollowOnFragmentBlock<'_> {
    /// Номер фрагмента (старшие 7 бит `frag`).
    #[must_use]
    pub const fn fragment_number(&self) -> u8 {
        self.frag >> 1
    }

    /// Последний ли это фрагмент (младший бит `frag`).
    #[must_use]
    pub const fn is_last(&self) -> bool {
        self.frag & 0x01 != 0
    }
}

impl<'a> Ssu2Block<'a> for FollowOnFragmentBlock<'a> {
    const TYPE: Ssu2BlockType = Ssu2BlockType::FollowOnFragment;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 5 {
            return Err(I2PError::InvalidLength {
                expected: 5,
                got: body.len(),
            });
        }
        Ok(Self {
            frag: body[0],
            msg_id: read_u32_be(&body[1..5]),
            data: &body[5..],
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.frag);
        out.extend_from_slice(&self.msg_id.to_be_bytes());
        out.extend_from_slice(self.data);
    }
}

// --- Termination --------------------------------------------------------

/// Причина завершения SSU2-сессии (значения из спеки, 0..22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ssu2TerminationReason {
    /// 0: normal close or unspecified.
    NormalClose = 0,
    /// 1: termination received.
    TerminationReceived = 1,
    /// 2: idle timeout.
    IdleTimeout = 2,
    /// 3: router shutdown.
    RouterShutdown = 3,
    /// 4: data phase AEAD failure.
    DataPhaseAeadFailure = 4,
    /// 5: incompatible options.
    IncompatibleOptions = 5,
    /// 6: incompatible signature type.
    IncompatibleSignatureType = 6,
    /// 7: clock skew.
    ClockSkew = 7,
    /// 8: padding violation.
    PaddingViolation = 8,
    /// 9: AEAD framing error.
    AeadFramingError = 9,
    /// 10: payload format error.
    PayloadFormatError = 10,
    /// 11: Session Request error.
    SessionRequestError = 11,
    /// 12: Session Created error.
    SessionCreatedError = 12,
    /// 13: Session Confirmed error.
    SessionConfirmedError = 13,
    /// 14: timeout.
    Timeout = 14,
    /// 15: RI signature verification failure.
    RouterInfoSignatureVerificationFail = 15,
    /// 16: некорректный параметр `s`.
    InvalidS = 16,
    /// 17: banned.
    Banned = 17,
    /// 18: bad token.
    BadToken = 18,
    /// 19: connection limits.
    ConnectionLimits = 19,
    /// 20: incompatible version.
    IncompatibleVersion = 20,
    /// 21: wrong net ID.
    WrongNetId = 21,
    /// 22: replaced by new session.
    ReplacedByNewSession = 22,
}

impl Ssu2TerminationReason {
    /// Разбирает числовой код. `None` — код не описан (допустимо).
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
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
            11 => Self::SessionRequestError,
            12 => Self::SessionCreatedError,
            13 => Self::SessionConfirmedError,
            14 => Self::Timeout,
            15 => Self::RouterInfoSignatureVerificationFail,
            16 => Self::InvalidS,
            17 => Self::Banned,
            18 => Self::BadToken,
            19 => Self::ConnectionLimits,
            20 => Self::IncompatibleVersion,
            21 => Self::WrongNetId,
            22 => Self::ReplacedByNewSession,
            _ => return None,
        })
    }

    /// Числовой код для wire.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Человекочитаемое имя.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NormalClose => "NormalClose",
            Self::TerminationReceived => "TerminationReceived",
            Self::IdleTimeout => "IdleTimeout",
            Self::RouterShutdown => "RouterShutdown",
            Self::DataPhaseAeadFailure => "DataPhaseAeadFailure",
            Self::IncompatibleOptions => "IncompatibleOptions",
            Self::IncompatibleSignatureType => "IncompatibleSignatureType",
            Self::ClockSkew => "ClockSkew",
            Self::PaddingViolation => "PaddingViolation",
            Self::AeadFramingError => "AeadFramingError",
            Self::PayloadFormatError => "PayloadFormatError",
            Self::SessionRequestError => "SessionRequestError",
            Self::SessionCreatedError => "SessionCreatedError",
            Self::SessionConfirmedError => "SessionConfirmedError",
            Self::Timeout => "Timeout",
            Self::RouterInfoSignatureVerificationFail => "RouterInfoSignatureVerificationFail",
            Self::InvalidS => "InvalidS",
            Self::Banned => "Banned",
            Self::BadToken => "BadToken",
            Self::ConnectionLimits => "ConnectionLimits",
            Self::IncompatibleVersion => "IncompatibleVersion",
            Self::WrongNetId => "WrongNetId",
            Self::ReplacedByNewSession => "ReplacedByNewSession",
        }
    }
}

impl std::fmt::Display for Ssu2TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// `Termination` (6): завершение соединения.
///
/// Должен быть последним не-padding блоком payload'а. Тело: число принятых
/// пакетов (8, BE) + код причины (1) + необязательные дополнительные данные.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminationBlock<'a> {
    /// Число валидных принятых пакетов (текущий receive nonce).
    pub valid_packets: u64,
    /// Код причины (см. [`Ssu2TerminationReason`]).
    pub reason: u8,
    /// Дополнительные данные (формат зависит от кода).
    pub additional: &'a [u8],
}

impl TerminationBlock<'_> {
    /// Причина как типизированное значение, если код описан.
    #[must_use]
    pub const fn reason_kind(&self) -> Option<Ssu2TerminationReason> {
        Ssu2TerminationReason::from_u8(self.reason)
    }
}

impl<'a> Ssu2Block<'a> for TerminationBlock<'a> {
    const TYPE: Ssu2BlockType = Ssu2BlockType::Termination;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 9 {
            return Err(I2PError::InvalidLength {
                expected: 9,
                got: body.len(),
            });
        }
        Ok(Self {
            valid_packets: read_u64_be(&body[0..8]),
            reason: body[8],
            additional: &body[9..],
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.valid_packets.to_be_bytes());
        out.push(self.reason);
        out.extend_from_slice(self.additional);
    }
}

// --- Address ------------------------------------------------------------

/// `Address` (13): `port` (2, BE) + IPv4 (4) или IPv6 (16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressBlock {
    /// Порт, big-endian.
    pub port: u16,
    /// IP-адрес.
    pub ip: IpAddr,
}

impl<'a> Ssu2Block<'a> for AddressBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::Address;

    fn parse(body: &'a [u8]) -> Result<Self> {
        let (port, ip) = match body.len() {
            6 => {
                let mut o = [0u8; 4];
                o.copy_from_slice(&body[2..6]);
                (read_u16_be(body), IpAddr::V4(Ipv4Addr::from(o)))
            }
            18 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&body[2..18]);
                (read_u16_be(body), IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => {
                return Err(I2PError::Malformed(
                    "ssu2: address block must be 6 or 18 bytes",
                ));
            }
        };
        Ok(Self { port, ip })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.port.to_be_bytes());
        match self.ip {
            IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
        }
    }
}

// --- мелкие фиксированные блоки -----------------------------------------

/// `Relay Tag Request` (15): пустое тело.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayTagRequestBlock;

impl<'a> Ssu2Block<'a> for RelayTagRequestBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::RelayTagRequest;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if !body.is_empty() {
            return Err(I2PError::Malformed(
                "ssu2: relay tag request block must be empty",
            ));
        }
        Ok(Self)
    }

    fn write_body(&self, _out: &mut Vec<u8>) {}
}

/// `Relay Tag` (16): `u32` big-endian (ненулевой).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayTagBlock {
    /// Relay-тег.
    pub relay_tag: u32,
}

impl<'a> Ssu2Block<'a> for RelayTagBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::RelayTag;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 4 {
            return Err(I2PError::InvalidLength {
                expected: 4,
                got: body.len(),
            });
        }
        Ok(Self {
            relay_tag: read_u32_be(body),
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.relay_tag.to_be_bytes());
    }
}

/// `New Token` (17): `expires` (4, BE) + `token` (8, BE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewTokenBlock {
    /// Unix timestamp истечения токена.
    pub expires: u32,
    /// Токен.
    pub token: u64,
}

impl<'a> Ssu2Block<'a> for NewTokenBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::NewToken;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 12 {
            return Err(I2PError::InvalidLength {
                expected: 12,
                got: body.len(),
            });
        }
        Ok(Self {
            expires: read_u32_be(body),
            token: read_u64_be(&body[4..12]),
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        let mut buf = [0u8; 12];
        write_u32_be(&mut buf[0..4], self.expires);
        write_u64_be(&mut buf[4..12], self.token);
        out.extend_from_slice(&buf);
    }
}

/// `Path Challenge` (18): произвольные данные (рекомендуется >= 8 байт).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChallengeBlock<'a> {
    /// Данные, которые нужно вернуть в `Path Response`.
    pub data: &'a [u8],
}

impl<'a> Ssu2Block<'a> for PathChallengeBlock<'a> {
    const TYPE: Ssu2BlockType = Ssu2BlockType::PathChallenge;

    fn parse(body: &'a [u8]) -> Result<Self> {
        Ok(Self { data: body })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.data);
    }
}

/// `Path Response` (19): данные из `Path Challenge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathResponseBlock<'a> {
    /// Данные, полученные в `Path Challenge`.
    pub data: &'a [u8],
}

impl<'a> Ssu2Block<'a> for PathResponseBlock<'a> {
    const TYPE: Ssu2BlockType = Ssu2BlockType::PathResponse;

    fn parse(body: &'a [u8]) -> Result<Self> {
        Ok(Self { data: body })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.data);
    }
}

/// `First Packet Number` (20): первый номер пакета data phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstPacketNumberBlock {
    /// Первый номер пакета, который будет отправлен.
    pub first_packet_number: u32,
}

impl<'a> Ssu2Block<'a> for FirstPacketNumberBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::FirstPacketNumber;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < 4 {
            return Err(I2PError::InvalidLength {
                expected: 4,
                got: body.len(),
            });
        }
        Ok(Self {
            first_packet_number: read_u32_be(body),
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.first_packet_number.to_be_bytes());
    }
}

/// `Padding` (254): произвольные байты (обычно нули).
///
/// Должен быть последним блоком payload'а; несколько padding-блоков в одном
/// payload'е не допускаются.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingBlock<'a> {
    /// Тело padding'а (содержимое не определено).
    pub data: &'a [u8],
}

impl<'a> Ssu2Block<'a> for PaddingBlock<'a> {
    const TYPE: Ssu2BlockType = Ssu2BlockType::Padding;

    fn parse(body: &'a [u8]) -> Result<Self> {
        Ok(Self { data: body })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.data);
    }
}
