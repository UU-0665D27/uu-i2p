//! `Address` — адрес роутера в `RouterInfo`.
//!
//! Каждый роутер публикует один или несколько адресов — endpoint'ов,
//! по которым с ним можно связаться. В I2P два транспорта:
//!
//! - **NTCP2** — TCP с obfuscation, есть статический X25519-ключ и IV;
//! - **SSU2** — UDP, может работать через introducers при NAT,
//!   имеет intro key (32 байта) и опциональный список introducer'ов.
//!
//! ## Wire-формат (внутри `RouterInfo`)
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     1  cost           (игнорируется при чтении)
//!        1     8  date           (BE u64, ms since epoch или 0)
//!        9     ?  transport      ("NTCP2" / "SSU2", len-prefixed)
//!        ?     2  size           (BE u16, длина properties)
//!        ?     ?  properties     ("key=value;" *)
//! ```
//!
//! Ключи в `properties`:
//!
//! - `host` — IP (только у опубликованных);
//! - `port` — порт (только у опубликованных);
//! - `s` — X25519 static key (base64, 32 байта);
//! - `i` — NTCP2 IV (base64, 16 байт) или SSU2 intro key (32 байта);
//! - `caps` — однобуквенные флаги (см. [`caps`]);
//! - `v` — всегда `"2"`;
//! - `pq` — версия post-quantum (`3`..`5`);
//! - `mtu` — MTU для SSU2;
//! - `iexpN`, `ihN`, `itagN` — introducer'ы.
//!
//! ## Что реализовано
//!
//! - [`TransportStyle`], [`Introducer`], [`SsuExt`], [`Address`];
//! - caps (V4, V6, `SSU_TESTING`, `SSU_INTRODUCER`) + `parse`/`to_string`;
//! - методы `is_*`, `is_same_subnet`, `is_compatible_with`;
//! - конструкторы `ntcp2_published`, `ntcp2_unpublished`,
//!   `ssu2_published`, `ssu2_unpublished`;
//! - golden-тесты.
//!
//! ## Чего тут нет
//!
//! - парсинга/сериализации wire-формата (это часть `RouterInfo`);
//! - логики cost'а (i2pd выводит его из transport + published);
//! - валидации длин ключей (это делает вызывающий код).

use crate::{I2PTag, IdentHash};
use std::net::{IpAddr, Ipv4Addr};

// --- transport style -----------------------------------------------------

/// Транспорт, через который доступен роутер.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportStyle {
    /// Неизвестный/неподдерживаемый транспорт.
    Unknown,
    /// NTCP2 (TCP-based).
    Ntcp2,
    /// SSU2 (UDP-based).
    Ssu2,
}

impl TransportStyle {
    /// Имя транспорта — ровно та строка, что пишется в `RouterInfo`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Ntcp2 => "NTCP2",
            Self::Ssu2 => "SSU2",
        }
    }
}

impl std::fmt::Display for TransportStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// --- caps ----------------------------------------------------------------

/// Флаги `Address.caps`.
///
/// В wire-формате — строка из букв: `"4"`, `"6"`, `"B"`, `"C"`.
/// `4`/`6` встречаются только у неопубликованных адресов (содержат
/// `host.is_unspecified()`), `B`/`C` — только у опубликованных SSU2.
pub mod caps {
    /// IPv4.
    pub const V4: u8 = 0x01;
    /// IPv6.
    pub const V6: u8 = 0x02;
    /// SSU2 peer testing (адрес умеет тестировать других).
    pub const SSU_TESTING: u8 = 0x04;
    /// SSU2 introducer (адрес умеет вводить NAT'нутых в сеть).
    pub const SSU_INTRODUCER: u8 = 0x08;

    /// Парсит строку вида `"BC"` в битовую маску.
    ///
    /// Неизвестные символы молча игнорируются — так же, как в i2pd
    /// (`ExtractAddressCaps`).
    #[must_use]
    pub fn parse(s: &str) -> u8 {
        let mut out = 0u8;
        for c in s.chars() {
            match c {
                '4' => out |= V4,
                '6' => out |= V6,
                'B' => out |= SSU_TESTING,
                'C' => out |= SSU_INTRODUCER,
                _ => {}
            }
        }
        out
    }

    /// Обратная операция к [`parse`].
    #[must_use]
    pub fn to_string(caps: u8) -> String {
        let mut s = String::new();
        if caps & V4 != 0 {
            s.push('4');
        }
        if caps & V6 != 0 {
            s.push('6');
        }
        if caps & SSU_TESTING != 0 {
            s.push('B');
        }
        if caps & SSU_INTRODUCER != 0 {
            s.push('C');
        }
        s
    }
}

/// Cost адреса — «цена» использования. Используется при выборе
/// маршрута, чем меньше — тем предпочтительнее. Совпадает с
/// `COST_*` в `RouterInfo.h`.
///
/// i2pd при парсинге игнорирует cost (не сохраняет), но при
/// генерации своего RI пишет эти значения.
pub mod cost {
    /// NTCP2 с опубликованным `host`.
    pub const NTCP2_PUBLISHED: u8 = 3;
    /// NTCP2 без `host` (неопубликованный).
    pub const NTCP2_NON_PUBLISHED: u8 = 14;
    /// SSU2 с опубликованным `host`.
    pub const SSU2_DIRECT: u8 = 8;
    /// SSU2 без `host` (неопубликованный).
    pub const SSU2_NON_PUBLISHED: u8 = 15;
}
// --- introducer ----------------------------------------------------------

/// SSU2 introducer — роутер, через который мы можем получить relay-tag
/// для NAT-пробивания.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Introducer {
    /// `IdentHash` introducer-роутера.
    pub i_h: IdentHash,
    /// Relay tag, полученный от introducer'а.
    pub i_tag: u32,
    /// Момент истечения (seconds since epoch).
    pub i_exp: u32,
}

impl Introducer {
    /// Конструктор.
    #[must_use]
    pub const fn new(i_h: IdentHash, i_tag: u32, i_exp: u32) -> Self {
        Self { i_h, i_tag, i_exp }
    }

    /// Валиден ли introducer на момент `now_s`.
    ///
    /// Повторяет `RouterInfo::UpdateIntroducers`: годен, если у него
    /// ненулевой `i_tag`, не истёк `i_exp` и `i_h` не нулевой.
    #[must_use]
    pub fn is_valid(&self, now_s: u32) -> bool {
        self.i_tag != 0 && now_s < self.i_exp && !self.i_h.is_zero()
    }
}

impl Default for Introducer {
    fn default() -> Self {
        Self {
            i_h: IdentHash::from_array([0u8; 32]),
            i_tag: 0,
            i_exp: 0,
        }
    }
}

// --- SSU2 extension ------------------------------------------------------

/// SSU2-специфичные поля: MTU и список introducer'ов.
///
/// В i2pd это `std::unique_ptr<SSUExt>` — `nullptr` для NTCP2.
/// У нас — `Option<SsuExt>` внутри [`Address`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsuExt {
    /// MTU (0 = не установлен, использовать дефолт из транспорта).
    pub mtu: u32,
    /// Список introducer'ов (для NAT-пробивания).
    pub introducers: Vec<Introducer>,
}

impl SsuExt {
    /// Пустой SSU2-extension: MTU не задан, introducer'ов нет.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mtu: 0,
            introducers: Vec::new(),
        }
    }
}

// --- Address -------------------------------------------------------------

/// Один адрес роутера.
///
/// ## Equality
///
/// Полная: сравниваются **все** поля (включая ключи и SSU2-ext).
/// i2pd сравнивает только `(transportStyle, host, port)` — если
/// когда-нибудь понадобится такая семантика, добавь отдельный метод
/// `same_endpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2PAddress {
    /// Тип транспорта.
    pub transport_style: TransportStyle,
    /// IP-адрес. Для неопубликованных — unspecified (`0.0.0.0` или `::`).
    pub host: IpAddr,
    /// X25519 static public key (32 байта).
    pub s: I2PTag<32>,
    /// NTCP2 IV (первые 16 байт, остальные — нули) или SSU2 intro key.
    pub i: I2PTag<32>,
    /// Версия протокола. `2` = обычный; `3`/`4`/`5` = post-quantum.
    pub v: u8,
    /// Порт. `0` = не задан.
    pub port: u16,
    /// Timestamp (ms since epoch) или `0`.
    pub date: u64,
    /// Битовые флаги, см. [`caps`].
    pub caps: u8,
    /// Опубликован ли адрес в `RouterInfo` (есть `host` и `port`).
    pub published: bool,
    /// SSU2-расширение; `None` для NTCP2.
    pub ssu: Option<SsuExt>,
}

// --- constructors --------------------------------------------------------

impl I2PAddress {
    /// NTCP2, опубликованный (есть `host`).
    ///
    /// `iv` — 16 байт, дополняются нулями до 32.
    #[must_use]
    pub fn ntcp2_published(host: IpAddr, port: u16, static_key: I2PTag<32>, iv: [u8; 16]) -> Self {
        let mut i_bytes = [0u8; 32];
        i_bytes[..16].copy_from_slice(&iv);
        Self {
            transport_style: TransportStyle::Ntcp2,
            host,
            s: static_key,
            i: I2PTag::from_array(i_bytes),
            v: 2,
            port,
            date: 0,
            caps: 0,
            published: true,
            ssu: None,
        }
    }

    /// NTCP2, неопубликованный (только caps, без `host`).
    ///
    /// `v4`/`v6` → какие семейства адрес поддерживает. i2pd пишет эти
    /// биты в caps; `host` при этом unspecified.
    #[must_use]
    pub fn ntcp2_unpublished(
        port: u16,
        static_key: I2PTag<32>,
        iv: [u8; 16],
        v4: bool,
        v6: bool,
    ) -> Self {
        let mut i_bytes = [0u8; 32];
        i_bytes[..16].copy_from_slice(&iv);
        let mut c = 0u8;
        if v4 {
            c |= caps::V4;
        }
        if v6 {
            c |= caps::V6;
        }
        Self {
            transport_style: TransportStyle::Ntcp2,
            host: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            s: static_key,
            i: I2PTag::from_array(i_bytes),
            v: 2,
            port,
            date: 0,
            caps: c,
            published: false,
            ssu: None,
        }
    }

    /// SSU2, опубликованный. `BC` caps — так делает i2pd по умолчанию
    /// для published SSU2 (см. `RouterInfo::AddSSU2Address`).
    #[must_use]
    pub const fn ssu2_published(
        host: IpAddr,
        port: u16,
        static_key: I2PTag<32>,
        intro_key: I2PTag<32>,
    ) -> Self {
        Self {
            transport_style: TransportStyle::Ssu2,
            host,
            s: static_key,
            i: intro_key,
            v: 2,
            port,
            date: 0,
            caps: caps::SSU_TESTING | caps::SSU_INTRODUCER,
            published: true,
            ssu: Some(SsuExt::new()),
        }
    }

    /// SSU2, неопубликованный (только caps).
    #[must_use]
    pub const fn ssu2_unpublished(
        port: u16,
        static_key: I2PTag<32>,
        intro_key: I2PTag<32>,
        v4: bool,
        v6: bool,
    ) -> Self {
        let mut c = 0u8;
        if v4 {
            c |= caps::V4;
        }
        if v6 {
            c |= caps::V6;
        }
        Self {
            transport_style: TransportStyle::Ssu2,
            host: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            s: static_key,
            i: intro_key,
            v: 2,
            port,
            date: 0,
            caps: c,
            published: false,
            ssu: Some(SsuExt::new()),
        }
    }
}

// --- accessors -----------------------------------------------------------

impl I2PAddress {
    /// NTCP2?
    #[must_use]
    pub const fn is_ntcp2(&self) -> bool {
        matches!(self.transport_style, TransportStyle::Ntcp2)
    }

    /// SSU2?
    #[must_use]
    pub const fn is_ssu2(&self) -> bool {
        matches!(self.transport_style, TransportStyle::Ssu2)
    }

    /// NTCP2 и опубликован.
    #[must_use]
    pub const fn is_published_ntcp2(&self) -> bool {
        self.is_ntcp2() && self.published
    }

    /// Достижим ли SSU2-адрес: либо опубликован, либо есть introducer'ы.
    #[must_use]
    pub fn is_reachable_ssu(&self) -> bool {
        self.ssu.is_some() && (self.published || self.uses_introducer())
    }

    /// Есть ли хотя бы один introducer (непустой список).
    #[must_use]
    pub fn uses_introducer(&self) -> bool {
        self.ssu.as_ref().is_some_and(|s| !s.introducers.is_empty())
    }

    /// Флаг `SSU_INTRODUCER`.
    #[must_use]
    pub const fn is_introducer(&self) -> bool {
        self.caps & caps::SSU_INTRODUCER != 0
    }

    /// Флаг `SSU_TESTING`.
    #[must_use]
    pub const fn is_peer_testing(&self) -> bool {
        self.caps & caps::SSU_TESTING != 0
    }

    /// Считается ли адрес IPv4: либо caps, либо явный v4-host.
    #[must_use]
    pub const fn is_v4(&self) -> bool {
        (self.caps & caps::V4) != 0 || matches!(self.host, IpAddr::V4(a) if !a.is_unspecified())
    }

    /// Считается ли адрес IPv6: либо caps, либо явный v6-host.
    #[must_use]
    pub const fn is_v6(&self) -> bool {
        (self.caps & caps::V6) != 0 || matches!(self.host, IpAddr::V6(a) if !a.is_unspecified())
    }

    /// Совпадает ли семейство с заданным IP.
    #[must_use]
    pub const fn is_compatible_with(&self, other: &IpAddr) -> bool {
        (self.is_v4() && other.is_ipv4()) || (self.is_v6() && other.is_ipv6())
    }

    /// Тот же /24 (v4) или /56 (v6) подсеть?
    ///
    /// Возвращает `false`, если у любого из адресов `host` unspecified
    /// или семейства различаются.
    #[must_use]
    pub fn is_same_subnet(&self, other: &Self) -> bool {
        match (&self.host, &other.host) {
            (IpAddr::V4(a), IpAddr::V4(b)) if !a.is_unspecified() && !b.is_unspecified() => {
                a.octets()[..3] == b.octets()[..3] // /24
            }
            (IpAddr::V6(a), IpAddr::V6(b)) if !a.is_unspecified() && !b.is_unspecified() => {
                a.octets()[..7] == b.octets()[..7] // /56
            }
            _ => false,
        }
    }
    /// Cost адреса — «цена» использования. Вычисляется из
    /// `transport_style` и `published`, как это делает
    /// `LocalRouterInfo::WriteToStream` в i2pd.
    ///
    /// В wire-формате cost присутствует (1 байт перед `date`), но
    /// при парсинге **игнорируется** — значение детерминировано.
    /// При сериализации пишется каноническое значение.
    ///
    /// В i2pd это поле не хранится в `Address`, а выводится на
    /// момент записи. Совпадаем с i2pd: держать два источника
    /// истины для одного инварианта — источник багов.
    #[must_use]
    pub const fn cost(&self) -> u8 {
        match (self.transport_style, self.published) {
            (TransportStyle::Ntcp2, true) => cost::NTCP2_PUBLISHED,
            (TransportStyle::Ntcp2, false) => cost::NTCP2_NON_PUBLISHED,
            (TransportStyle::Ssu2, true) => cost::SSU2_DIRECT,
            (TransportStyle::Ssu2, false) => cost::SSU2_NON_PUBLISHED,
            (TransportStyle::Unknown, _) => 0x7F,
        }
    }
}

// --- совместимые транспорты ---------------------------------------------

/// Маска «какими транспортами и в каком семействе нас можно достать».
///
/// Порт `CompatibleTransports` из `RouterInfo.hpp`: те же биты, чтобы
/// один в один повторять решения i2pd (`m_SupportedTransports`,
/// `m_PublishedTransports`, `m_ReachableTransports`).
///
/// Mesh-семейство (Yggdrasil, `eNTCP2V6Mesh`) объявлено, но у нас пока
/// не выставляется: распознавания `200::/7` в порте нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompatibleTransports(u8);

impl CompatibleTransports {
    /// Пустая маска.
    pub const NONE: Self = Self(0);
    /// NTCP2, IPv4.
    pub const NTCP2_V4: Self = Self(0x01);
    /// NTCP2, IPv6.
    pub const NTCP2_V6: Self = Self(0x02);
    /// SSU2, IPv4.
    pub const SSU2_V4: Self = Self(0x04);
    /// SSU2, IPv6.
    pub const SSU2_V6: Self = Self(0x08);
    /// NTCP2 по Yggdrasil-адресу (mesh).
    pub const NTCP2_V6_MESH: Self = Self(0x10);

    /// Маска пуста.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Все биты `other` выставлены и здесь.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Сырые биты (для логов и сравнений).
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Пересекаются ли маски: хотя бы один общий транспорт.
    ///
    /// `RouterInfo::IsCompatible` в i2pd.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for CompatibleTransports {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CompatibleTransports {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Display for CompatibleTransports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = [
            (Self::NTCP2_V4, "NTCP2v4"),
            (Self::NTCP2_V6, "NTCP2v6"),
            (Self::SSU2_V4, "SSU2v4"),
            (Self::SSU2_V6, "SSU2v6"),
            (Self::NTCP2_V6_MESH, "NTCP2v6-mesh"),
        ];
        let mut first = true;
        for (bit, name) in names {
            if self.contains(bit) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("none")?;
        }
        Ok(())
    }
}

impl I2PAddress {
    /// Транспорты, которыми адрес **в принципе** достижим.
    ///
    /// Соответствует накоплению `supportedTransports` в
    /// `RouterInfo::ReadFromBuffer` (`RouterInfo.cpp:360-420`):
    ///
    /// - NTCP2: опубликованный адрес даёт семейство по `host`,
    ///   неопубликованный — по `caps`, а без `caps` считается v4
    ///   («most likely, since we don't have host»);
    /// - SSU2: семейства по `caps`/`host`; адрес без `host` не
    ///   публикуется, но остаётся достижимым через introducer'ы.
    ///
    /// Ключи (`s`, `i`) и `v=2` уже проверены при разборе RI: адрес с
    /// битыми ключами до нас не доходит (в i2pd такой адрес живёт с
    /// `transportStyle = eTransportUnknown` и в маску не попадает).
    #[must_use]
    pub fn supported_transports(&self) -> CompatibleTransports {
        match self.transport_style {
            TransportStyle::Ntcp2 => {
                if self.published {
                    if self.host.is_ipv6() {
                        CompatibleTransports::NTCP2_V6
                    } else {
                        CompatibleTransports::NTCP2_V4
                    }
                } else if self.is_v4() {
                    CompatibleTransports::NTCP2_V4
                } else if self.is_v6() {
                    CompatibleTransports::NTCP2_V6
                } else {
                    // i2pd: «most likely, since we don't have host».
                    CompatibleTransports::NTCP2_V4
                }
            }
            TransportStyle::Ssu2 => {
                let mut mask = CompatibleTransports::NONE;
                if self.is_v4() {
                    mask |= CompatibleTransports::SSU2_V4;
                }
                if self.is_v6() {
                    mask |= CompatibleTransports::SSU2_V6;
                }
                mask
            }
            TransportStyle::Unknown => CompatibleTransports::NONE,
        }
    }

    /// Транспорты, **опубликованные** в RI (`m_PublishedTransports`).
    ///
    /// Неопубликованный адрес (без `host`/`port`) в эту маску не
    /// попадает, даже если транспорт поддерживается.
    #[must_use]
    pub fn published_transports(&self) -> CompatibleTransports {
        if self.published {
            self.supported_transports()
        } else {
            CompatibleTransports::NONE
        }
    }

    /// Транспорты, которыми адрес реально достижим
    /// (`m_ReachableTransports`): опубликован или есть introducer'ы.
    #[must_use]
    pub fn reachable_transports(&self) -> CompatibleTransports {
        let published = self.published_transports();
        if published.is_empty() && self.is_ssu2() && self.uses_introducer() {
            self.supported_transports()
        } else {
            published
        }
    }
}
