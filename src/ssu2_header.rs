//! SSU2 — примитивы уровня заголовков.
//!
//! Модуль содержит только «низкоуровневую» часть SSU2:
//!
//! - [`Ssu2MessageType`] — типы сообщений;
//! - [`ConnectionId`] — 8-байтовый идентификатор соединения и вывод
//!   пары идентификаторов для Hole Punch / Peer Test из 4-байтового nonce;
//! - [`LongHeader`] и [`ShortHeader`] — разбор/сборка **незашифрованных**
//!   заголовков;
//! - обфускация заголовков: [`header_mask`], [`obfuscate_cover_header`],
//!   [`obfuscate_extended_header`] и композитная [`obfuscate_header`].
//!
//! Формат и алгоритмы повторяют i2pd (`SSU2Session.h`, `SSU2Session.cpp`,
//! `SSU2OutOfSession.cpp`) и спецификацию SSU2.
//!
//! ## Что не внутри
//!
//! - Noise handshake, KDF'ы и AEAD — в [`crate::ssu2_crypto`];
//! - блоки payload'а — отдельный модуль (следующая итерация).
//!
//! ## Замечания по спецификации
//!
//! В тексте спецификации есть опечатки в диапазонах срезов:
//! `packet[len-12:len-1]` и `packet[0:7]`. Мы следуем i2pd: берём
//! **последние** 12 байт пакета (для IV) и XOR'им ровно **8** байт в
//! каждую половину заголовка.
//!
//! Также в спецификации сказано, что короткий заголовок используется для
//! `SessionCreated`, однако таблица размеров заголовков и «сырой» формат
//! сообщения указывают длинный заголовок (32 байта) плюс эфемерный ключ.
//! i2pd тоже использует длинный заголовок — так делаем и мы.

use crate::crypto::chacha20_counter1;
use crate::endian::{read_u32_be, write_u32_be};
use crate::error::{I2PError, Result};
use rand::Rng;

// --- константы протокола ------------------------------------------------

/// Версия протокола SSU2.
pub const SSU2_VERSION: u8 = 2;

/// Размер «короткого» заголовка и первых 16 байт «длинного».
pub const SSU2_HEADER_SIZE: usize = 16;

/// Размер «длинного» заголовка (`SSU2_HEADER_SIZE` + source id + token).
pub const SSU2_LONG_HEADER_SIZE: usize = 32;

/// Размер эфемерного X25519-ключа (X в `SessionRequest`, Y в `SessionCreated`).
pub const SSU2_EPHEMERAL_KEY_SIZE: usize = 32;

/// Размер идентификатора соединения.
pub const SSU2_CONNECTION_ID_SIZE: usize = 8;

/// Минимальный размер SSU2-пакета.
pub const SSU2_MIN_PACKET_SIZE: usize = 40;

/// Максимальный размер SSU2-пакета поверх IPv4.
pub const SSU2_MAX_PACKET_SIZE_IPV4: usize = 1472;

/// Максимальный размер SSU2-пакета поверх IPv6.
pub const SSU2_MAX_PACKET_SIZE_IPV6: usize = 1452;

/// Флаг `Data`-заголовка: запрошен немедленный ACK.
pub const SSU2_FLAG_IMMEDIATE_ACK_REQUESTED: u8 = 0x01;

// --- типы сообщений -----------------------------------------------------

/// Тип SSU2-сообщения (байт 12 заголовка).
///
/// Значения совпадают с `enum SSU2MessageType` в i2pd. Неизвестные
/// значения нужно отбрасывать (как это делает i2pd в
/// `ProcessFirstIncomingMessage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ssu2MessageType {
    /// `SessionRequest` (Alice -> Bob).
    SessionRequest = 0,
    /// `SessionCreated` (Bob -> Alice).
    SessionCreated = 1,
    /// `SessionConfirmed` (Alice -> Bob), может фрагментироваться.
    SessionConfirmed = 2,
    /// Данные (data phase).
    Data = 6,
    /// Peer Test (вне сессии, фазы 5-7).
    PeerTest = 7,
    /// Retry (Bob -> Alice).
    Retry = 9,
    /// Token Request (Alice -> Bob).
    TokenRequest = 10,
    /// Hole Punch (вне сессии).
    HolePunch = 11,
}

impl Ssu2MessageType {
    /// Парсит `u8` из wire.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSsu2MessageType`], если значение не описано.
    pub const fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::SessionRequest,
            1 => Self::SessionCreated,
            2 => Self::SessionConfirmed,
            6 => Self::Data,
            7 => Self::PeerTest,
            9 => Self::Retry,
            10 => Self::TokenRequest,
            11 => Self::HolePunch,
            _ => return Err(I2PError::UnknownSsu2MessageType(v)),
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
            Self::SessionRequest => "SessionRequest",
            Self::SessionCreated => "SessionCreated",
            Self::SessionConfirmed => "SessionConfirmed",
            Self::Data => "Data",
            Self::PeerTest => "PeerTest",
            Self::Retry => "Retry",
            Self::TokenRequest => "TokenRequest",
            Self::HolePunch => "HolePunch",
        }
    }

    /// Использует ли сообщение «длинный» заголовок (32 байта).
    #[must_use]
    pub const fn is_long_header(self) -> bool {
        matches!(
            self,
            Self::SessionRequest
                | Self::SessionCreated
                | Self::Retry
                | Self::TokenRequest
                | Self::PeerTest
                | Self::HolePunch
        )
    }

    /// Несёт ли сообщение открытый эфемерный ключ сразу за заголовком.
    ///
    /// Только `SessionRequest` (X) и `SessionCreated` (Y).
    #[must_use]
    pub const fn has_ephemeral_key(self) -> bool {
        matches!(self, Self::SessionRequest | Self::SessionCreated)
    }

    /// Размер заголовка на wire: 32 для длинного, 16 для короткого.
    #[must_use]
    pub const fn header_len(self) -> usize {
        if self.is_long_header() {
            SSU2_LONG_HEADER_SIZE
        } else {
            SSU2_HEADER_SIZE
        }
    }

    /// Сколько байт после cover-заголовка обфусцируется вторым шагом.
    ///
    /// - 48 (`SessionRequest` / `SessionCreated`): хвост длинного
    ///   заголовка (16) + эфемерный ключ (32);
    /// - 16 (`Retry` / `TokenRequest` / `PeerTest` / `HolePunch`): только
    ///   хвост длинного заголовка;
    /// - 0 (`SessionConfirmed` / `Data`): второй шаг не применяется.
    #[must_use]
    pub const fn extended_header_len(self) -> usize {
        match self {
            Self::SessionRequest | Self::SessionCreated => 48,
            Self::Retry | Self::TokenRequest | Self::PeerTest | Self::HolePunch => 16,
            Self::SessionConfirmed | Self::Data => 0,
        }
    }
}

impl std::fmt::Display for Ssu2MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// --- ConnectionId -------------------------------------------------------

/// Идентификатор соединения SSU2 (8 байт на wire, big-endian).
///
/// Идентификаторы генерируются случайно; source и destination не должны
/// совпадать. Для Hole Punch / Peer Test оба идентификатора выводятся из
/// 4-байтового nonce (см. [`ConnectionId::relay_nonce_pair`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub [u8; SSU2_CONNECTION_ID_SIZE]);

impl ConnectionId {
    /// Конструктор из байт.
    #[must_use]
    pub const fn new(bytes: [u8; SSU2_CONNECTION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Из `u64` big-endian.
    #[must_use]
    pub const fn from_u64(v: u64) -> Self {
        Self(v.to_be_bytes())
    }

    /// В `u64` big-endian.
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    /// Ссылка на байты.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SSU2_CONNECTION_ID_SIZE] {
        &self.0
    }

    /// Случайный идентификатор из `rng`.
    #[must_use]
    pub fn random(rng: &mut impl Rng) -> Self {
        let mut b = [0u8; SSU2_CONNECTION_ID_SIZE];
        rng.fill_bytes(&mut b);
        Self(b)
    }

    /// Побитовое дополнение (source = `~dest`).
    #[must_use]
    pub const fn inverse(self) -> Self {
        let mut b = [0u8; SSU2_CONNECTION_ID_SIZE];
        let mut i = 0;
        while i < SSU2_CONNECTION_ID_SIZE {
            b[i] = !self.0[i];
            i += 1;
        }
        Self(b)
    }

    /// Пара идентификаторов для Hole Punch / Peer Test из 4-байтового nonce.
    ///
    /// Возвращает `(dest, source)`, где `dest` — это `nonce`, продублированный
    /// дважды (`(nonce << 32) | nonce`, big-endian), а `source = ~dest`.
    ///
    /// Совпадает с `SSU2HolePunchSession` / `SSU2PeerTestSession` в i2pd.
    #[must_use]
    pub const fn relay_nonce_pair(nonce: u32) -> (Self, Self) {
        let v = ((nonce as u64) << 32) | (nonce as u64);
        let dest = Self::from_u64(v);
        (dest, dest.inverse())
    }
}

impl From<[u8; SSU2_CONNECTION_ID_SIZE]> for ConnectionId {
    fn from(b: [u8; SSU2_CONNECTION_ID_SIZE]) -> Self {
        Self(b)
    }
}

impl From<ConnectionId> for [u8; SSU2_CONNECTION_ID_SIZE] {
    fn from(c: ConnectionId) -> Self {
        c.0
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectionId(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

// --- длинный заголовок --------------------------------------------------

/// Незашифрованный длинный заголовок SSU2 (32 байта).
///
/// Раскладка (до обфускации):
///
/// ```text
/// 0..8    destination connection id (BE u64)
/// 8..12   packet number (BE u32)
/// 12      type
/// 13      version (2)
/// 14      net id
/// 15      flag (0)
/// 16..24  source connection id (BE u64)
/// 24..32  token (BE u64)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongHeader {
    /// Идентификатор получателя (байты 0-7).
    pub dest_conn_id: ConnectionId,
    /// Номер пакета (байты 8-11, BE); для большинства handshake-сообщений
    /// случаен и игнорируется.
    pub packet_num: u32,
    /// Тип сообщения (байт 12).
    pub msg_type: Ssu2MessageType,
    /// Версия протокола (байт 13); для SSU2 — [`SSU2_VERSION`].
    pub version: u8,
    /// Network ID (байт 14).
    pub net_id: u8,
    /// Зарезервированный флаг (байт 15), 0.
    pub flag: u8,
    /// Идентификатор отправителя (байты 16-23).
    pub source_conn_id: ConnectionId,
    /// Token (байты 24-31, BE u64).
    pub token: u64,
}

impl LongHeader {
    /// Разбирает длинный заголовок из первых 32 байт `buf`.
    ///
    /// `buf` должен содержать **уже деобфусцированный** заголовок.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если `buf` короче 32 байт;
    /// - [`Error::UnknownSsu2MessageType`], если байт 12 не описан;
    /// - [`Error::Malformed`], если тип сообщения не использует длинный
    ///   заголовок.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < SSU2_LONG_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SSU2_LONG_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let msg_type = Ssu2MessageType::from_u8(buf[12])?;
        if !msg_type.is_long_header() {
            return Err(I2PError::Malformed(
                "ssu2: message type does not use the long header",
            ));
        }
        let mut dest = [0u8; SSU2_CONNECTION_ID_SIZE];
        dest.copy_from_slice(&buf[0..8]);
        let mut source = [0u8; SSU2_CONNECTION_ID_SIZE];
        source.copy_from_slice(&buf[16..24]);
        let mut token = [0u8; 8];
        token.copy_from_slice(&buf[24..32]);
        Ok(Self {
            dest_conn_id: ConnectionId(dest),
            packet_num: read_u32_be(&buf[8..12]),
            msg_type,
            version: buf[13],
            net_id: buf[14],
            flag: buf[15],
            source_conn_id: ConnectionId(source),
            token: u64::from_be_bytes(token),
        })
    }

    /// Сериализует заголовок в 32 байта (до обфускации).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SSU2_LONG_HEADER_SIZE] {
        let mut out = [0u8; SSU2_LONG_HEADER_SIZE];
        out[0..8].copy_from_slice(&self.dest_conn_id.0);
        write_u32_be(&mut out[8..12], self.packet_num);
        out[12] = self.msg_type.as_u8();
        out[13] = self.version;
        out[14] = self.net_id;
        out[15] = self.flag;
        out[16..24].copy_from_slice(&self.source_conn_id.0);
        out[24..32].copy_from_slice(&self.token.to_be_bytes());
        out
    }
}

// --- короткий заголовок -------------------------------------------------

/// Незашифрованный короткий заголовок SSU2 (16 байт).
///
/// Используется для `SessionConfirmed` и `Data`. Раскладка:
///
/// ```text
/// 0..8    destination connection id (BE u64)
/// 8..12   packet number (BE u32)
/// 12      type
/// 13..16  три байта flags (для SessionConfirmed — frag, для Data — флаги)
/// ```
///
/// Семантика байта 13 зависит от типа: см. [`ShortHeader::frag_number`],
/// [`ShortHeader::num_fragments`] и
/// [`ShortHeader::immediate_ack_requested`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortHeader {
    /// Идентификатор получателя (байты 0-7).
    pub dest_conn_id: ConnectionId,
    /// Номер пакета (байты 8-11, BE).
    pub packet_num: u32,
    /// Тип сообщения (байт 12): `SessionConfirmed` или `Data`.
    pub msg_type: Ssu2MessageType,
    /// Байты 13-15: `flags[0]` (байт 13) и `flags[1..3]` (байты 14-15).
    pub flags: [u8; 3],
}

impl ShortHeader {
    /// Разбирает короткий заголовок из первых 16 байт `buf`.
    ///
    /// `buf` должен содержать **уже деобфусцированный** заголовок.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если `buf` короче 16 байт;
    /// - [`Error::UnknownSsu2MessageType`], если байт 12 не описан;
    /// - [`Error::Malformed`], если тип сообщения не использует короткий
    ///   заголовок.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < SSU2_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SSU2_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let msg_type = Ssu2MessageType::from_u8(buf[12])?;
        if msg_type.is_long_header() {
            return Err(I2PError::Malformed(
                "ssu2: message type does not use the short header",
            ));
        }
        let mut dest = [0u8; SSU2_CONNECTION_ID_SIZE];
        dest.copy_from_slice(&buf[0..8]);
        Ok(Self {
            dest_conn_id: ConnectionId(dest),
            packet_num: read_u32_be(&buf[8..12]),
            msg_type,
            flags: [buf[13], buf[14], buf[15]],
        })
    }

    /// Сериализует заголовок в 16 байт (до обфускации).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SSU2_HEADER_SIZE] {
        let mut out = [0u8; SSU2_HEADER_SIZE];
        out[0..8].copy_from_slice(&self.dest_conn_id.0);
        write_u32_be(&mut out[8..12], self.packet_num);
        out[12] = self.msg_type.as_u8();
        out[13..16].copy_from_slice(&self.flags);
        out
    }

    /// Для `SessionConfirmed`: номер фрагмента (0-14, старшие 4 бита).
    #[must_use]
    pub const fn frag_number(&self) -> u8 {
        self.flags[0] >> 4
    }

    /// Для `SessionConfirmed`: общее число фрагментов (1-15, младшие 4 бита).
    #[must_use]
    pub const fn num_fragments(&self) -> u8 {
        self.flags[0] & 0x0F
    }

    /// Для `SessionConfirmed`: задаёт frag-инфо.
    ///
    /// `number` должен быть `<= 14`, `total` — в диапазоне `1..=15`.
    pub fn set_frag(&mut self, number: u8, total: u8) {
        debug_assert!(number <= 14, "ssu2: fragment number must be <= 14");
        debug_assert!((1..=15).contains(&total), "ssu2: total fragments 1..=15");
        self.flags[0] = (number << 4) | (total & 0x0F);
    }

    /// Для `Data`: запрошен ли немедленный ACK.
    #[must_use]
    pub const fn immediate_ack_requested(&self) -> bool {
        self.flags[0] & SSU2_FLAG_IMMEDIATE_ACK_REQUESTED != 0
    }

    /// Для `Data`: устанавливает флаг немедленного ACK.
    pub const fn set_immediate_ack_requested(&mut self, on: bool) {
        if on {
            self.flags[0] |= SSU2_FLAG_IMMEDIATE_ACK_REQUESTED;
        } else {
            self.flags[0] &= !SSU2_FLAG_IMMEDIATE_ACK_REQUESTED;
        }
    }
}

// --- обфускация заголовков ----------------------------------------------

/// Первые 8 байт keystream `ChaCha20` (counter = 1) для заданного IV.
///
/// Соответствует `CreateHeaderMask` из i2pd.
#[must_use]
pub fn header_mask(key: &[u8; 32], iv: &[u8; 12]) -> [u8; 8] {
    let mut mask = [0u8; 8];
    chacha20_counter1(key, iv, &mut mask);
    mask
}

/// XOR-обфускация cover-заголовка (первые 16 байт пакета).
///
/// `k_header_1` обфусцирует байты `0..8`, `k_header_2` — байты `8..16`.
/// В качестве IV берутся последние 24 байта пакета: сначала
/// `len-24..len-12`, затем `len-12..len`. Операция инволютивна: повторный
/// вызов с теми же ключами восстанавливает исходные байты.
///
/// `packet` — **весь** пакет (не только заголовок), т.к. IV берётся из
/// его хвоста. Требование `len >= 40` нужно, чтобы хвостовые IV не
/// пересекались с модифицируемыми байтами `0..16` (иначе повторное
/// применение не восстановит исходные данные).
///
/// # Errors
///
/// [`Error::InvalidLength`], если `packet` короче [`SSU2_MIN_PACKET_SIZE`].
pub fn obfuscate_cover_header(
    k_header_1: &[u8; 32],
    k_header_2: &[u8; 32],
    packet: &mut [u8],
) -> Result<()> {
    if packet.len() < SSU2_MIN_PACKET_SIZE {
        return Err(I2PError::InvalidLength {
            expected: SSU2_MIN_PACKET_SIZE,
            got: packet.len(),
        });
    }
    let len = packet.len();

    let mut iv1 = [0u8; 12];
    iv1.copy_from_slice(&packet[len - 24..len - 12]);
    let mask1 = header_mask(k_header_1, &iv1);
    for (b, m) in packet[..8].iter_mut().zip(mask1) {
        *b ^= m;
    }

    let mut iv2 = [0u8; 12];
    iv2.copy_from_slice(&packet[len - 12..len]);
    let mask2 = header_mask(k_header_2, &iv2);
    for (b, m) in packet[8..16].iter_mut().zip(mask2) {
        *b ^= m;
    }
    Ok(())
}

/// Обфускация extended-заголовка (байты 16 и далее).
///
/// Применяется к 48 байтам (`SessionRequest` / `SessionCreated`: хвост
/// длинного заголовка + эфемерный ключ) или к 16 байтам (`Retry` /
/// `TokenRequest` / `PeerTest` / `HolePunch`: только хвост заголовка).
///
/// Ключ — `k_header_2`; nonce нулевой, counter = 1. Операция инволютивна.
pub fn obfuscate_extended_header(k_header_2: &[u8; 32], buf: &mut [u8]) {
    chacha20_counter1(k_header_2, &[0u8; 12], buf);
}

/// Полная обфускация заголовка SSU2-пакета.
///
/// Выполняет обе стадии в порядке i2pd: сначала cover (байты `0..16`),
/// затем extended (`16..16 + extended_header_len()`). `packet` — весь
/// пакет. Операция инволютивна при тех же ключах и типе: i2pd применяет
/// те же два `XOR`/`ChaCha20` и на приёме.
///
/// Требуемая длина — `SSU2_MIN_PACKET_SIZE + extended_header_len()`
/// (например, 88 байт для `SessionRequest`, 56 для `Retry`): хвостовые IV
/// не должны пересекаться с extended-регионом. Проверка делается до любых
/// изменений, чтобы при ошибке пакет не портился.
///
/// # Errors
///
/// [`Error::InvalidLength`], если `packet` короче
/// `SSU2_MIN_PACKET_SIZE + extended_header_len()`.
pub fn obfuscate_header(
    msg_type: Ssu2MessageType,
    k_header_1: &[u8; 32],
    k_header_2: &[u8; 32],
    packet: &mut [u8],
) -> Result<()> {
    let ext_len = msg_type.extended_header_len();
    let min_len = SSU2_MIN_PACKET_SIZE + ext_len;
    if packet.len() < min_len {
        return Err(I2PError::InvalidLength {
            expected: min_len,
            got: packet.len(),
        });
    }
    obfuscate_cover_header(k_header_1, k_header_2, packet)?;
    if ext_len > 0 {
        obfuscate_extended_header(k_header_2, &mut packet[SSU2_HEADER_SIZE..16 + ext_len]);
    }
    Ok(())
}
