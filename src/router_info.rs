//! `RouterInfo` — публичное описание роутера в I2P-сети.
//!
//! Wire-формат (`RouterInfo::ReadFromBuffer` в i2pd):
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     8  timestamp       (BE u64, ms since epoch)
//!        8     1  numAddresses
//!        9     ?  addresses*      (см. `parse_address`)
//!        ?     1  numPeers
//!        ?   32*N peer hashes
//!        ?     2  properties size (BE u16)
//!        ?     ?  properties      ("key=value;" *)
//!   ```
//!
//! Ключевое отличие от `i2pd`: мы парсим **только body** — без identity
//! и без signature. Caller должен передать `buf` уже после identity
//! (`IdentityEx::GetFullLen()`), а trailing signature (и любые padding)
//! игнорируются: `Reader` не требует «consume all».
//!
//! ## Ссылки
//!
//! - [`RouterInfoCaps`] — RI-level caps (`f`, `K`..`X`, `D`/`E`/`G`, `H`, `R`, `U`, `4`, `6`);
//! - [`extract_string`] / [`extract_param`] — примитивы парсинга свойств;
//! - [`Address`] (из `router_info_address`) — сам адрес.

use crate::{
    I2PTag, IdentHash, base64,
    endian::{read_u16_be, read_u64_be},
    error::{I2PError, Result},
    identity::IdentityEx,
    private_keys::I2PPrivateKeys,
    router_info_address::{I2PAddress, Introducer, SsuExt, TransportStyle, caps as addr_caps},
};
use std::net::{IpAddr, Ipv4Addr};

// --- константы -----------------------------------------------------------

/// Максимальный размер `RouterInfo` (включая identity и подпись).
pub const MAX_RI_BUFFER_SIZE: usize = 3072;

/// Property: `netdb.knownLeaseSets` — для floodfill'ов.
pub const ROUTER_INFO_PROPERTY_LEASESETS: &[u8] = b"netdb.knownLeaseSets";
/// Property: `netdb.knownRouters` — для floodfill'ов.
pub const ROUTER_INFO_PROPERTY_ROUTERS: &[u8] = b"netdb.knownRouters";
/// Property: `netId`.
pub const ROUTER_INFO_PROPERTY_NETID: &[u8] = b"netId";
/// Property: `router.version`.
pub const ROUTER_INFO_PROPERTY_VERSION: &[u8] = b"router.version";
/// Property: `family`.
pub const ROUTER_INFO_PROPERTY_FAMILY: &[u8] = b"family";
/// Property: `family.sig`.
pub const ROUTER_INFO_PROPERTY_FAMILY_SIG: &[u8] = b"family.sig";
/// Property: `caps`.
pub const ROUTER_INFO_PROPERTY_CAPS: &[u8] = b"caps";

// --- RI-level caps -------------------------------------------------------

/// RI-level caps — буквы из `properties["caps"]`.
///
/// Соответствует `enum Caps` в `RouterInfo.h`. Не путать с address caps
/// (`router_info_address::caps`) — они независимы.
pub mod ri_caps {
    /// `f` — floodfill.
    pub const FLOODFILL: u8 = 0x01;
    /// `O`/`P`/`X` — high bandwidth.
    pub const HIGH_BANDWIDTH: u8 = 0x02;
    /// `P`/`X` — extra bandwidth.
    pub const EXTRA_BANDWIDTH: u8 = 0x04;
    /// `R` — reachable.
    pub const REACHABLE: u8 = 0x08;
    /// `H` — hidden.
    pub const HIDDEN: u8 = 0x10;
    /// `U` — unreachable.
    pub const UNREACHABLE: u8 = 0x20;
    /// `4` — supports IPv4 (когда есть только caps).
    pub const V4: u8 = 0x40;
    /// `6` — supports IPv6.
    pub const V6: u8 = 0x80;
}

/// Уровень congestion (`D` / `E` / `G`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Congestion {
    /// Ничего не указано.
    #[default]
    Low,
    /// `D`.
    Medium,
    /// `E`.
    High,
    /// `G` — reject all.
    RejectAll,
}

/// Разобранные RI-level caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RouterInfoCaps {
    /// Битовая маска, см. [`ri_caps`].
    pub bits: u8,
    /// Буква bandwidth: `K`, `L`, `M`, `N`, `O`, `P`, `X`.
    pub bandwidth_cap: Option<u8>,
    /// Congestion.
    pub congestion: Congestion,
}

impl RouterInfoCaps {
    /// Парсит строку caps. Неизвестные символы игнорируются —
    /// ровно как `RouterInfo::ExtractCaps`.
    #[must_use]
    pub fn parse(s: &[u8]) -> Self {
        let mut bits = 0u8;
        let mut bandwidth_cap = None;
        let mut congestion = Congestion::Low;
        for &c in s {
            match c {
                b'f' => bits |= ri_caps::FLOODFILL,
                b'K'..=b'N' => bandwidth_cap = Some(c),
                b'O' => {
                    bits |= ri_caps::HIGH_BANDWIDTH;
                    bandwidth_cap = Some(c);
                }
                b'P' | b'X' => {
                    bits |= ri_caps::HIGH_BANDWIDTH | ri_caps::EXTRA_BANDWIDTH;
                    bandwidth_cap = Some(c);
                }
                b'D' => congestion = Congestion::Medium,
                b'E' => congestion = Congestion::High,
                b'G' => congestion = Congestion::RejectAll,
                b'H' => bits |= ri_caps::HIDDEN,
                b'R' => bits |= ri_caps::REACHABLE,
                b'U' => bits |= ri_caps::UNREACHABLE,
                b'4' => bits |= ri_caps::V4,
                b'6' => bits |= ri_caps::V6,
                _ => {}
            }
        }
        Self {
            bits,
            bandwidth_cap,
            congestion,
        }
    }

    /// `f`.
    #[must_use]
    pub const fn is_floodfill(self) -> bool {
        self.bits & ri_caps::FLOODFILL != 0
    }
    /// `O`/`P`/`X`.
    #[must_use]
    pub const fn is_high_bandwidth(self) -> bool {
        self.bits & ri_caps::HIGH_BANDWIDTH != 0
    }
    /// `P`/`X`.
    #[must_use]
    pub const fn is_extra_bandwidth(self) -> bool {
        self.bits & ri_caps::EXTRA_BANDWIDTH != 0
    }
    /// `R`.
    #[must_use]
    pub const fn is_reachable(self) -> bool {
        self.bits & ri_caps::REACHABLE != 0
    }
    /// `H`.
    #[must_use]
    pub const fn is_hidden(self) -> bool {
        self.bits & ri_caps::HIDDEN != 0
    }
    /// `U`.
    #[must_use]
    pub const fn is_unreachable(self) -> bool {
        self.bits & ri_caps::UNREACHABLE != 0
    }
    /// `4`.
    #[must_use]
    pub const fn supports_v4(self) -> bool {
        self.bits & ri_caps::V4 != 0
    }
    /// `6`.
    #[must_use]
    pub const fn supports_v6(self) -> bool {
        self.bits & ri_caps::V6 != 0
    }
}
impl std::fmt::Display for RouterInfoCaps {
    /// Реконструирует строку caps.
    ///
    /// Соответствует `LocalRouterInfo::UpdateCapsProperty` в i2pd.
    /// Порядок букв: bandwidth (одна из `K`/`L`/`M`/`N`/`O`/`P`/`X`),
    /// затем `f` если floodfill, затем `H`, `R`, `U`, затем
    /// congestion (`D`/`E`/`G`).
    ///
    /// Флаги `V4`/`V6` **не выводятся** — они относятся к address
    /// caps и в RI-level caps i2pd их не пишет.
    ///
    /// Если все поля дефолтные (нет флагов, bandwidth `None`,
    /// congestion `Low`) — печатает пустую строку. Это используется
    /// `RouterInfoBuilder::caps` для того, чтобы `caps(Default)`
    /// не создавал лишний property.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.bits == 0 && self.bandwidth_cap.is_none() && self.congestion == Congestion::Low {
            return Ok(());
        }
        // bandwidth: `L` как fallback (i2pd всегда пишет одну букву)
        let bw = self.bandwidth_cap.unwrap_or(b'L');
        f.write_str(&char::from(bw).to_string())?;
        if self.bits & ri_caps::FLOODFILL != 0 {
            f.write_str("f")?;
        }
        if self.bits & ri_caps::HIDDEN != 0 {
            f.write_str("H")?;
        }
        if self.bits & ri_caps::REACHABLE != 0 {
            f.write_str("R")?;
        }
        if self.bits & ri_caps::UNREACHABLE != 0 {
            f.write_str("U")?;
        }
        match self.congestion {
            Congestion::Medium => f.write_str("D")?,
            Congestion::High => f.write_str("E")?,
            Congestion::RejectAll => f.write_str("G")?,
            Congestion::Low => {}
        }
        Ok(())
    }
}
// --- низкоуровневые парсеры ----------------------------------------------

/// Читает length-prefixed строку: `len(1 byte) | data(len bytes)`.
///
/// Возвращает `(data, consumed)`. Аналог `RouterInfo::ExtractString`.
///
/// # Errors
///
/// [`Error::InvalidLength`], если буфер короче заявленной длины.
pub fn extract_string(buf: &[u8]) -> Result<(&[u8], usize)> {
    let Some(&len_byte) = buf.first() else {
        return Err(I2PError::InvalidLength {
            expected: 1,
            got: 0,
        });
    };
    let len = len_byte as usize;
    let end = 1 + len;
    if buf.len() < end {
        return Err(I2PError::InvalidLength {
            expected: end,
            got: buf.len(),
        });
    }
    Ok((&buf[1..end], end))
}

/// Читает `key=value;` где `key` и `value` — length-prefixed строки.
///
/// Возвращает `(key, value, consumed)`. Аналог `RouterInfo::ExtractParam`.
///
/// # Errors
///
/// [`Error::Malformed`], если нет `=`, `;` или не хватает байт.
pub fn extract_param(buf: &[u8]) -> Result<(&[u8], &[u8], usize)> {
    let (key, mut pos) = extract_string(buf)?;
    if buf.len() <= pos || buf[pos] != b'=' {
        return Err(I2PError::Malformed("expected '=' after param key"));
    }
    pos += 1;
    let (value, n) = extract_string(&buf[pos..])?;
    pos += n;
    if buf.len() <= pos || buf[pos] != b';' {
        return Err(I2PError::Malformed("expected ';' after param value"));
    }
    pos += 1;
    Ok((key, value, pos))
}

// --- Reader --------------------------------------------------------------

/// Позиционный читатель из среза с проверкой границ на каждом шаге.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(I2PError::InvalidLength {
                expected: self.pos + n,
                got: self.buf.len(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16_be(&mut self) -> Result<u16> {
        Ok(read_u16_be(self.take(2)?))
    }

    fn u64_be(&mut self) -> Result<u64> {
        Ok(read_u64_be(self.take(8)?))
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.u8()? as usize;
        self.take(len)
    }

    fn param(&mut self) -> Result<(&'a [u8], &'a [u8])> {
        let key = self.length_prefixed()?;
        if self.u8()? != b'=' {
            return Err(I2PError::Malformed("expected '=' after param key"));
        }
        let value = self.length_prefixed()?;
        if self.u8()? != b';' {
            return Err(I2PError::Malformed("expected ';' after param value"));
        }
        Ok((key, value))
    }
}

// --- introducer keys -----------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntroducerKind {
    Tag,
    Hash,
    Exp,
}

/// Разбирает introducer-ключ вида `ih0`, `itag0`, `iexp0`.
///
/// i2pd поддерживает только single-digit индексы (0..=9), что соответствует
/// `SSU2_MAX_NUM_INTRODUCERS = 3`. Повторяем это поведение.
const fn parse_introducer_key(key: &[u8]) -> Option<(IntroducerKind, usize)> {
    let len = key.len();
    if len < 3 {
        return None;
    }
    let last = key[len - 1];
    if !last.is_ascii_digit() {
        return None;
    }
    let idx = (last - b'0') as usize;
    let prefix_len = len - 1;

    // "itag" (4 буквы + цифра)
    if prefix_len == 4 && key[0] == b'i' && key[1] == b't' && key[2] == b'a' && key[3] == b'g' {
        return Some((IntroducerKind::Tag, idx));
    }
    // "ih" (2 буквы + цифра)
    if prefix_len == 2 && key[0] == b'i' && key[1] == b'h' {
        return Some((IntroducerKind::Hash, idx));
    }
    // "iexp" (4 буквы + цифра)
    if prefix_len == 4 && key[0] == b'i' && key[1] == b'e' && key[2] == b'x' && key[3] == b'p' {
        return Some((IntroducerKind::Exp, idx));
    }
    None
}

fn ensure_introducer(v: &mut Vec<Introducer>, idx: usize) {
    while v.len() <= idx {
        v.push(Introducer::default());
    }
}

/// Кодирует length-prefixed строку: `len(1) | bytes`.
///
/// # Panics
///
/// Паникует, если `s.len() > 255` — length-префикс однобайтовый.
/// В I2P все строки в `RouterInfo` короче этого предела.
#[must_use]
pub fn lp(s: &[u8]) -> Vec<u8> {
    let len = u8::try_from(s.len()).expect("length-prefixed string > 255 bytes");
    let mut out = Vec::with_capacity(1 + s.len());
    out.push(len);
    out.extend_from_slice(s);
    out
}

/// Кодирует параметр `key=value;` где key и value — length-prefixed.
#[must_use]
pub fn param(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = lp(key);
    out.push(b'=');
    out.extend_from_slice(&lp(value));
    out.push(b';');
    out
}
// --- parse_address -------------------------------------------------------

/// Разбирает один `Address` из `Reader`.
///
/// Возвращает:
/// - `Ok(Some(addr))` — адрес валиден и поддерживается;
/// - `Ok(None)` — адрес валиден структурно, но не поддерживается
///   (неизвестный транспорт, битые ключи, отсутствует `v` для SSU2, ...).
///
/// Семантика совпадает с `RouterInfo::ReadFromBuffer(buf, len)`.
///
/// # Errors
///
/// [`Error::InvalidLength`] — `Reader` кончился раньше, чем
/// удалось прочитать структурную часть адреса (cost, date,
/// transport name, properties).
#[allow(clippy::too_many_lines)]
pub fn parse_address(r: &mut Reader<'_>) -> Result<Option<I2PAddress>> {
    //игнорируем как в i2pd
    let _cost = r.u8()?;
    let date = r.u64_be()?;
    let transport_name = r.length_prefixed()?;
    let transport_style = match transport_name {
        b"NTCP2" => TransportStyle::Ntcp2,
        b"SSU2" => TransportStyle::Ssu2,
        _ => TransportStyle::Unknown,
    };
    let props_size = r.u16_be()? as usize;
    let props = r.take(props_size)?;

    if transport_style == TransportStyle::Unknown {
        return Ok(None);
    }

    let mut pr = Reader::new(props);
    let mut host: Option<IpAddr> = None;
    let mut port: u16 = 0;
    let mut static_key = I2PTag::<32>::from_array([0u8; 32]);
    let mut intro_or_iv = I2PTag::<32>::from_array([0u8; 32]);
    let mut protocol_version: u8 = 2;
    let mut caps: u8 = 0;
    let mut mtu: u32 = 0;
    let mut introducers: Vec<Introducer> = Vec::new();
    let mut has_s = false;
    let mut has_i = false;
    let mut is_v2 = false;
    let mut valid = true;

    while !pr.is_empty() {
        let Ok((key, value)) = pr.param() else {
            valid = false;
            break;
        };
        match key {
            b"host" => match std::str::from_utf8(value)
                .ok()
                .and_then(|text| text.parse().ok())
            {
                Some(addr) => host = Some(addr),
                None => valid = false,
            },
            b"port" => match std::str::from_utf8(value)
                .ok()
                .and_then(|text| text.parse().ok())
            {
                Some(port_value) => port = port_value,
                None => valid = false,
            },
            b"s" => match std::str::from_utf8(value)
                .ok()
                .and_then(|text| I2PTag::<32>::from_base64(text).ok())
            {
                Some(key_bytes) => {
                    static_key = key_bytes;
                    has_s = true;
                }
                None => valid = false,
            },
            b"i" => match transport_style {
                TransportStyle::Ntcp2 => {
                    match std::str::from_utf8(value)
                        .ok()
                        .and_then(|text| base64::decode_to::<16>(text).ok())
                    {
                        Some(iv) => {
                            let mut buf = [0u8; 32];
                            buf[..16].copy_from_slice(&iv);
                            intro_or_iv = I2PTag::from_array(buf);
                            has_i = true;
                        }
                        None => valid = false,
                    }
                }
                TransportStyle::Ssu2 => {
                    match std::str::from_utf8(value)
                        .ok()
                        .and_then(|text| I2PTag::<32>::from_base64(text).ok())
                    {
                        Some(key_bytes) => {
                            intro_or_iv = key_bytes;
                            has_i = true;
                        }
                        None => valid = false,
                    }
                }
                TransportStyle::Unknown => {}
            },
            b"caps" => {
                caps = addr_caps::parse(std::str::from_utf8(value).unwrap_or(""));
            }
            b"v" => {
                if value == b"2" {
                    is_v2 = true;
                } else {
                    valid = false;
                }
            }
            b"pq" => {
                if value.len() == 1 {
                    let c = value[0];
                    let allowed = match transport_style {
                        TransportStyle::Ntcp2 => (b'3'..=b'5').contains(&c),
                        TransportStyle::Ssu2 => (b'3'..=b'4').contains(&c),
                        TransportStyle::Unknown => false,
                    };
                    if allowed {
                        protocol_version = c - b'0';
                    }
                }
                // иначе (multi-value или пустой) — игнорируем
            }
            b"mtu" => {
                if let Ok(mtu_value) = std::str::from_utf8(value).unwrap_or("").parse::<u32>() {
                    mtu = mtu_value;
                }
            }
            _ => {
                if let Some((kind, idx)) = parse_introducer_key(key) {
                    ensure_introducer(&mut introducers, idx);
                    let intro = &mut introducers[idx];
                    let Ok(text) = std::str::from_utf8(value) else {
                        continue;
                    };
                    match kind {
                        IntroducerKind::Tag => {
                            if let Ok(tag_value) = text.parse::<u32>() {
                                intro.i_tag = tag_value;
                            }
                        }
                        IntroducerKind::Hash => {
                            if let Ok(hash_value) = IdentHash::from_base64(text) {
                                intro.i_h = hash_value;
                            }
                        }
                        IntroducerKind::Exp => {
                            if let Ok(exp_value) = text.parse::<u32>() {
                                intro.i_exp = exp_value;
                            }
                        }
                    }
                }
            }
        }
    }

    if !valid {
        return Ok(None);
    }

    let transport_ok = match transport_style {
        TransportStyle::Ntcp2 => has_s && has_i,
        TransportStyle::Ssu2 => has_s && has_i && is_v2,
        TransportStyle::Unknown => false,
    };
    if !transport_ok {
        return Ok(None);
    }

    let published = host.is_some() && port != 0;
    let ssu = (transport_style == TransportStyle::Ssu2).then_some(SsuExt { mtu, introducers });

    Ok(Some(I2PAddress {
        transport_style,
        host: host.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        s: static_key,
        i: intro_or_iv,
        v: protocol_version,
        port,
        date,
        caps,
        published,
        ssu,
    }))
}

// --- serialize_address ---------------------------------------------------

/// Сериализует один `Address` в wire-формат.
///
/// Порядок properties совпадает с `LocalRouterInfo::WriteToStream`:
/// `caps`, `host`, `i`, `port`, `pq`, `s`, `v`, плюс SSU2-специфичные
/// `mtu` и introducers (`iexpN`, `ihN`, `itagN`).
///
/// Гарантирует `parse_address(serialize_address(a)) == Some(a)` для
/// всех полей, которые хранит [`Address`].
///
/// **Инвариант port**: `port` сериализуется только при
/// `published == true`. Для unpublished-адресов `port` теряется
/// (i2pd ведёт себя так же — `WriteToStream` пишет port только
/// для published). На read-back получим `port = 0`.
///
/// # Panics
///
/// Паникует, если размер properties превышает `u16::MAX`
/// (65535 байт). Для любого `Address`, полученного из
/// [`parse_address`] или конструкторов, это невозможно: один
/// static key — 32 байта, introducer — ~80 байт, список
/// introducer'ов ограничен `SSU2_MAX_NUM_INTRODUCERS = 3`.
#[must_use]
pub fn serialize_address(addr: &I2PAddress) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(addr.cost());
    out.extend_from_slice(&addr.date.to_be_bytes());
    out.extend_from_slice(&lp(addr.transport_style.name().as_bytes()));

    let mut props = Vec::new();

    // caps — как в i2pd: для NTCP2 только у неопубликованных,
    // для SSU2 — всегда.
    let write_caps = match addr.transport_style {
        TransportStyle::Ntcp2 => !addr.published,
        TransportStyle::Ssu2 => true,
        TransportStyle::Unknown => false,
    };
    if write_caps {
        let s = addr_caps::to_string(addr.caps);
        if !s.is_empty() {
            props.extend(param(b"caps", s.as_bytes()));
        }
    }

    // host — только если published и host задан
    if addr.published && !addr.host.is_unspecified() {
        props.extend(param(b"host", addr.host.to_string().as_bytes()));
    }

    // i — всегда
    let i_str = match addr.transport_style {
        TransportStyle::Ntcp2 => base64::encode(&addr.i.as_bytes()[..16]),
        TransportStyle::Ssu2 => base64::encode(addr.i.as_bytes()),
        TransportStyle::Unknown => String::new(),
    };
    if !i_str.is_empty() {
        props.extend(param(b"i", i_str.as_bytes()));
    } // SSU2-специфичные
    if let Some(ssu) = &addr.ssu {
        if ssu.mtu != 0 && ssu.mtu < 1500 {
            props.extend(param(b"mtu", ssu.mtu.to_string().as_bytes()));
        }
        // i2pd пишет три группы циклов: сначала все iexp, потом все ih,
        // потом все itag. Каждый introducer с i_tag == 0 пропускается.
        let write_idx = |i: usize, s: String| param(format!("iexp{i}").as_bytes(), s.as_bytes());
        let _ = write_idx; // не используется, оставлено для ясности
        let mut i = 0;
        for intro in &ssu.introducers {
            if intro.i_tag == 0 {
                continue;
            }
            if intro.i_exp != 0 {
                props.extend(param(
                    format!("iexp{i}").as_bytes(),
                    intro.i_exp.to_string().as_bytes(),
                ));
            }
            i += 1;
        }
        i = 0;
        for intro in &ssu.introducers {
            if intro.i_tag == 0 {
                continue;
            }
            props.extend(param(
                format!("ih{i}").as_bytes(),
                base64::encode(intro.i_h.as_bytes()).as_bytes(),
            ));
            i += 1;
        }
        i = 0;
        for intro in &ssu.introducers {
            if intro.i_tag == 0 {
                continue;
            }
            props.extend(param(
                format!("itag{i}").as_bytes(),
                intro.i_tag.to_string().as_bytes(),
            ));
            i += 1;
        }
    }

    // port — только если published
    if addr.published {
        props.extend(param(b"port", addr.port.to_string().as_bytes()));
    }

    // pq — если v >= 3
    if addr.v >= 3 {
        props.extend(param(b"pq", addr.v.to_string().as_bytes()));
    }

    // s — всегда
    props.extend(param(b"s", base64::encode(addr.s.as_bytes()).as_bytes()));

    // v — всегда "2" (формат адреса, не путать с pq)
    props.extend(param(b"v", b"2"));

    out.extend_from_slice(
        &u16::try_from(props.len())
            .expect("props > 65535 bytes")
            .to_be_bytes(),
    );
    out.extend_from_slice(&props);
    out
}
// --- RouterInfo ----------------------------------------------------------

/// Извлекает `caps`, `version`, `net_id` из properties.
///
/// Общая логика для [`RouterInfo::parse_body`] и
/// [`RouterInfoBuilder::build`]. Не мутирует `properties` —
/// источник истины остаётся за caller'ом.
fn extract_caps_version_netid(
    properties: &[(Vec<u8>, Vec<u8>)],
) -> (RouterInfoCaps, Option<u32>, Option<i32>) {
    let mut caps = RouterInfoCaps::default();
    let mut version: Option<u32> = None;
    let mut net_id: Option<i32> = None;
    for (k, v) in properties {
        if k == ROUTER_INFO_PROPERTY_CAPS {
            caps = RouterInfoCaps::parse(v);
        } else if k == ROUTER_INFO_PROPERTY_VERSION {
            let mut n: u32 = 0;
            for &b in v {
                if b.is_ascii_digit() {
                    n = n.wrapping_mul(10).wrapping_add(u32::from(b - b'0'));
                }
            }
            version = Some(n);
        } else if k == ROUTER_INFO_PROPERTY_NETID
            && let Ok(id) = std::str::from_utf8(v).unwrap_or("").parse::<i32>()
        {
            net_id = Some(id);
        }
    }
    (caps, version, net_id)
}

/// Разобранный `RouterInfo` body (без identity и без signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterInfo {
    /// Timestamp в миллисекундах since epoch.
    pub timestamp: u64,
    /// Все адреса в порядке появления.
    pub addresses: Vec<I2PAddress>,
    /// Устаревшее поле; в современных RI всегда пусто.
    pub peers: Vec<IdentHash>,
    /// Все свойства в порядке появления.
    pub properties: Vec<(Vec<u8>, Vec<u8>)>,
    /// Разобранные RI-level caps.
    pub caps: RouterInfoCaps,
    /// Версия из `router.version` (после парсинга «цифры, остальные знаки
    /// игнорируются», как в i2pd). `None` — если property нет.
    pub version: Option<u32>,
    /// `netId` из одноимённого property.
    pub net_id: Option<i32>,
}

impl RouterInfo {
    /// Разбирает RI body.
    ///
    /// `buf` начинается сразу после identity и может включать trailing
    /// signature — она игнорируется.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] и [`Error::Malformed`] — структурные ошибки.
    pub fn parse_body(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);

        let timestamp = r.u64_be()?;

        let num_addresses = r.u8()? as usize;
        let mut addresses = Vec::with_capacity(num_addresses);
        for _ in 0..num_addresses {
            if let Some(a) = parse_address(&mut r)? {
                addresses.push(a);
            }
        }

        let num_peers = r.u8()? as usize;
        let mut peers = Vec::with_capacity(num_peers);
        for _ in 0..num_peers {
            let bytes = r.take(32)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(bytes);
            peers.push(IdentHash::from_array(h));
        }

        let props_size = r.u16_be()? as usize;
        let props_buf = r.take(props_size)?;
        let mut prop_reader = Reader::new(props_buf);
        let mut properties: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        while !prop_reader.is_empty() {
            let (prop_key, prop_value) = prop_reader.param()?;
            properties.push((prop_key.to_vec(), prop_value.to_vec()));
        }

        let (caps, version, net_id) = extract_caps_version_netid(&properties);

        Ok(Self {
            timestamp,
            addresses,
            peers,
            properties,
            caps,
            version,
            net_id,
        })
    }
    /// Более ли `other` новой версией того же RI по timestamp'у.
    ///
    /// Сравнение двух body — без identity, без wire. Если нужно
    /// сравнить с wire-буфером (полным RI), см.
    /// [`FullRouterInfo::is_newer_than`].
    ///
    /// Соответствует `RouterInfo::IsNewer` в i2pd — но там сравнение
    /// идёт по wire-буферу, потому что identity и timestamp в одном
    /// буфере. У нас body отделён от identity, так что здесь
    /// просто сравнение timestamp'ов.
    #[must_use]
    pub const fn is_newer_than(&self, other: &Self) -> bool {
        other.timestamp > self.timestamp
    }
    /// Возвращает значение property по ключу.
    #[must_use]
    pub fn get_property(&self, key: &[u8]) -> Option<&[u8]> {
        self.properties
            .iter()
            .rev() // если дубликаты, последнее имеет приоритет
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }
    /// То же, но с `&str` для удобства.
    #[must_use]
    pub fn get_property_str(&self, key: &str) -> Option<&[u8]> {
        self.get_property(key.as_bytes())
    }

    /// `f`-флаг.
    #[must_use]
    pub const fn is_floodfill(&self) -> bool {
        self.caps.is_floodfill()
    }

    /// `O`/`P`/`X`.
    #[must_use]
    pub const fn is_high_bandwidth(&self) -> bool {
        self.caps.is_high_bandwidth()
    }

    /// `H`.
    #[must_use]
    pub const fn is_hidden(&self) -> bool {
        self.caps.is_hidden()
    }

    /// Первый NTCP2-адрес для v4.
    #[must_use]
    pub fn ntcp2_v4_address(&self) -> Option<&I2PAddress> {
        self.addresses.iter().find(|a| a.is_ntcp2() && a.is_v4())
    }

    /// Первый NTCP2-адрес для v6.
    #[must_use]
    pub fn ntcp2_v6_address(&self) -> Option<&I2PAddress> {
        self.addresses.iter().find(|a| a.is_ntcp2() && a.is_v6())
    }

    /// Первый SSU2-адрес для v4.
    #[must_use]
    pub fn ssu2_v4_address(&self) -> Option<&I2PAddress> {
        self.addresses.iter().find(|a| a.is_ssu2() && a.is_v4())
    }

    /// Первый SSU2-адрес для v6.
    #[must_use]
    pub fn ssu2_v6_address(&self) -> Option<&I2PAddress> {
        self.addresses.iter().find(|a| a.is_ssu2() && a.is_v6())
    }

    /// SSU2-адрес для семейства: `ipv6 == true` — v6, иначе v4.
    ///
    /// Соответствует выбору `GetSSU2V6Address` / `GetSSU2V4Address` в i2pd
    /// по семейству удалённого endpoint'а. Статический ключ такого адреса —
    /// `address.s`.
    #[must_use]
    pub fn ssu2_address(&self, ipv6: bool) -> Option<&I2PAddress> {
        if ipv6 {
            self.ssu2_v6_address()
        } else {
            self.ssu2_v4_address()
        }
    }

    /// Сериализует body в wire-формат.
    ///
    /// Обратная к [`Self::parse_body`]. Не включает identity и
    /// signature — их пишет [`FullRouterInfo::to_buffer`].
    ///
    /// Properties пишутся **как есть**, в порядке из [`Self::properties`].
    /// Это значит `caps`, `netId`, `router.version` сохраняются
    /// в том же порядке, в каком пришли.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если адресов, peers или properties
    ///   больше, чем допускает формат (255 / 65535).
    pub fn serialize_body(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        // timestamp
        out.extend_from_slice(&self.timestamp.to_be_bytes());

        // addresses
        let num_addr = u8::try_from(self.addresses.len())
            .map_err(|_| I2PError::Malformed("more than 255 addresses"))?;
        out.push(num_addr);
        for a in &self.addresses {
            out.extend_from_slice(&serialize_address(a));
        }

        // peers
        let num_peers = u8::try_from(self.peers.len())
            .map_err(|_| I2PError::Malformed("more than 255 peers"))?;
        out.push(num_peers);
        for p in &self.peers {
            out.extend_from_slice(p.as_bytes());
        }

        // properties
        let mut props = Vec::new();
        for (k, v) in &self.properties {
            props.extend_from_slice(&param(k, v));
        }
        let props_size = u16::try_from(props.len())
            .map_err(|_| I2PError::Malformed("properties > 65535 bytes"))?;
        out.extend_from_slice(&props_size.to_be_bytes());
        out.extend_from_slice(&props);

        Ok(out)
    }
}

// --- RouterInfoBuilder ---------------------------------------------------

/// Конструктор `RouterInfo`.
///
/// Пример:
///
/// ```
/// use uu_i2p::router_info::{RouterInfo, RouterInfoCaps};
///
/// let body = RouterInfo::builder()
///     .timestamp(1_700_000_000_000)
///     .caps(RouterInfoCaps::parse(b"OR"))
///     .version(970)
///     .net_id(2)
///     .add_property(b"family", b"myfamily")
///     .build();
///
/// assert_eq!(body.timestamp, 1_700_000_000_000);
/// assert!(body.caps.is_reachable());
/// assert_eq!(body.version, Some(970));
/// assert_eq!(body.net_id, Some(2));
/// ```
///
/// `caps`, `version` и `net_id` сериализуются в одноимённые
/// properties при `build()`. Если тот же ключ уже был добавлен через
/// `add_property`, `caps()`/`version()`/`net_id()` его **заменят**
/// (используют `set_property`).
#[derive(Debug, Clone, Default)]
pub struct RouterInfoBuilder {
    timestamp: u64,
    addresses: Vec<I2PAddress>,
    peers: Vec<IdentHash>,
    properties: Vec<(Vec<u8>, Vec<u8>)>,
}

impl RouterInfo {
    /// Возвращает новый [`RouterInfoBuilder`].
    #[must_use]
    pub fn builder() -> RouterInfoBuilder {
        RouterInfoBuilder::default()
    }
}

impl RouterInfoBuilder {
    /// Устанавливает timestamp (миллисекунды since epoch).
    #[must_use]
    pub const fn timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }

    /// Добавляет адрес.
    #[must_use]
    pub fn add_address(mut self, addr: I2PAddress) -> Self {
        self.addresses.push(addr);
        self
    }

    /// Добавляет peer-hash в устаревший список peers.
    #[must_use]
    pub fn add_peer(mut self, hash: IdentHash) -> Self {
        self.peers.push(hash);
        self
    }

    /// Добавляет property, **не** удаляя существующее с тем же
    /// ключом. В wire-формате окажутся оба.
    #[must_use]
    pub fn add_property(mut self, key: &[u8], value: &[u8]) -> Self {
        self.properties.push((key.to_vec(), value.to_vec()));
        self
    }

    /// Устанавливает property, заменяя существующее с тем же ключом.
    #[must_use]
    pub fn set_property(mut self, key: &[u8], value: &[u8]) -> Self {
        self.properties.retain(|(k, _)| k != key);
        self.properties.push((key.to_vec(), value.to_vec()));
        self
    }

    /// Устанавливает RI-level caps (пишет property `caps`).
    ///
    /// Если `caps` — полностью дефолтный (нет флагов, bandwidth
    /// `None`, congestion `Low`), property **не добавляется**.
    /// Это позволяет вызывать `caps(Default)` без побочных эффектов.
    #[must_use]
    pub fn caps(self, caps: RouterInfoCaps) -> Self {
        let s = caps.to_string();
        if s.is_empty() {
            return self;
        }
        self.set_property(ROUTER_INFO_PROPERTY_CAPS, s.as_bytes())
    }

    /// Устанавливает `router.version` (пишет property).
    #[must_use]
    pub fn version(self, v: u32) -> Self {
        self.set_property(ROUTER_INFO_PROPERTY_VERSION, v.to_string().as_bytes())
    }

    /// Устанавливает `netId` (пишет property).
    #[must_use]
    pub fn net_id(self, n: i32) -> Self {
        self.set_property(ROUTER_INFO_PROPERTY_NETID, n.to_string().as_bytes())
    }

    /// Собирает [`RouterInfo`].
    ///
    /// `caps`, `version`, `net_id` извлекаются из properties — та
    /// же логика, что в [`RouterInfo::parse_body`].
    #[must_use]
    pub fn build(self) -> RouterInfo {
        let (caps, version, net_id) = extract_caps_version_netid(&self.properties);
        RouterInfo {
            timestamp: self.timestamp,
            addresses: self.addresses,
            peers: self.peers,
            properties: self.properties,
            caps,
            version,
            net_id,
        }
    }
}

// --- FullRouterInfo ------------------------------------------------------

/// Полный `RouterInfo` — identity + body + signature.
///
/// Именно это лежит в файлах `routerInfo-<hash>.dat` в netDb, именно
/// это приходит в I2NP `DatabaseStore` (после снятия I2NP-заголовка).
///
/// ## Формат
///
/// ```text
///   offset          size            field
///   ------          ----            -----
///        0      identity.full_len() identity (387 или 387 + ext)
///        ?      body_len            body (timestamp, addresses, peers, props)
///        ?      sig_len             signature
/// ```
///
/// Длина `signature` берётся из `identity.signature_len()` — это
/// зависит от signing key type.
///
/// ## Что не реализовано
///
/// - верификация подписи — нужен Ed25519/DSA/ECDSA verifier (отдельный шаг);
/// - `RouterInfo::Update` — слияние с уже имеющимся RI (тоже отдельно).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullRouterInfo {
    identity: IdentityEx,
    body: RouterInfo,
    signature: Vec<u8>,
}

impl FullRouterInfo {
    /// Разбирает полный `RouterInfo` из буфера.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если буфера не хватает на identity,
    ///   body или signature.
    /// - любая ошибка [`IdentityEx::from_buffer`] или [`RouterInfo::parse_body`].
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let identity = IdentityEx::from_buffer(buf)?;
        let identity_len = identity.full_len();

        let sig_len = identity.signature_len()?;
        if buf.len() < identity_len + sig_len {
            return Err(I2PError::InvalidLength {
                expected: identity_len + sig_len,
                got: buf.len(),
            });
        }
        let body_end = buf.len() - sig_len;
        let body = RouterInfo::parse_body(&buf[identity_len..body_end])?;
        let signature = buf[body_end..].to_vec();

        Ok(Self {
            identity,
            body,
            signature,
        })
    }

    /// Читает полный `RouterInfo` из файла (например, из netDb i2pd).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] при ошибке чтения файла; остальное — как
    /// [`Self::from_buffer`].
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let buf = std::fs::read(path).map_err(|e| I2PError::Io(e.to_string()))?;
        Self::from_buffer(&buf)
    }

    /// Идентичность.
    #[must_use]
    pub const fn identity(&self) -> &IdentityEx {
        &self.identity
    }

    /// Body (всё, кроме identity и signature).
    #[must_use]
    pub const fn body(&self) -> &RouterInfo {
        &self.body
    }

    /// Подпись (только хвост, без identity и body).
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// `IdentHash` роутера.
    #[must_use]
    pub const fn ident_hash(&self) -> &IdentHash {
        self.identity.ident_hash()
    }

    /// Собирает полный `RouterInfo` из приватных ключей и тела.
    ///
    /// Подпись — Ed25519 (единственный реализованный тип) — считается
    /// над конкатенацией `identity_bytes || body_bytes`, то есть ровно
    /// над той частью wire-формата, которая идёт до подписи. Это
    /// соответствует `FullRouterInfo::verify`.
    ///
    /// `body` берётся как есть — caller сам выставляет `timestamp`,
    /// `addresses`, `properties` и т.д.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`], если у `keys` тип подписи, отличный
    ///   от `EdDSA` (что для `PrivateKeys::generate_default` не может
    ///   произойти, но `PrivateKeys` могла прийти из `from_buffer`);
    /// - [`Error::Malformed`], если `keys.sign` вернула подпись не
    ///   той длины, что заявлена identity;
    /// - [`RouterInfo::serialize_body`] и [`IdentityEx::to_buffer`].
    pub fn from_keys(keys: &I2PPrivateKeys, body: RouterInfo) -> Result<Self> {
        let identity = keys.public().clone();
        let id_len = identity.full_len();

        let mut id_buf = vec![0u8; id_len];
        identity.to_buffer(&mut id_buf)?;

        let body_bytes = body.serialize_body()?;

        // Подпись идёт над identity || body.
        let mut signing_data = Vec::with_capacity(id_buf.len() + body_bytes.len());
        signing_data.extend_from_slice(&id_buf);
        signing_data.extend_from_slice(&body_bytes);

        let signature = keys.sign(&signing_data)?;

        // Защитный инвариант: Ed25519 возвращает 64 байта, и
        // identity.signature_len() для EdDSA = 64. Если разойдётся,
        // это баг в `private_keys` или в identity.
        let expected_sig_len = identity.signature_len()?;
        if signature.len() != expected_sig_len {
            return Err(I2PError::Malformed(
                "full_router_info: signature length mismatch",
            ));
        }

        Ok(Self {
            identity,
            body,
            signature,
        })
    }
    /// Проверяет, является ли `buf` более новым RI того же роутера.
    ///
    /// Сравнивает **timestamp**, а не подпись. Соответствует
    /// `RouterInfo::IsNewer` в i2pd. Identity берётся из `self` —
    /// подразумевается, что `buf` содержит RI того же роутера.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если `buf` короче чем
    /// `identity.full_len() + 8`.
    pub fn is_newer_than(&self, buf: &[u8]) -> Result<bool> {
        let id_len = self.identity.full_len();
        if buf.len() < id_len + 8 {
            return Err(I2PError::InvalidLength {
                expected: id_len + 8,
                got: buf.len(),
            });
        }
        let ts = read_u64_be(&buf[id_len..]);
        Ok(ts > self.body.timestamp)
    }

    /// Принимает новую версию RI **того же роутера**, если она новее.
    ///
    /// Аналог `RouterInfo::Update` из i2pd. Не проверяет подпись —
    /// это делает caller ([`Self::verify`] или
    /// [`Self::update_verified`]). Здесь только сравнение
    /// timestamp'ов и обновление body.
    ///
    /// Возвращает `true`, если body был заменён, `false` — если новая
    /// версия не новее.
    ///
    /// # Errors
    ///
    /// См. [`Self::is_newer_than`] и [`RouterInfo::parse_body`].
    pub fn update(&mut self, buf: &[u8]) -> Result<bool> {
        if !self.is_newer_than(buf)? {
            return Ok(false);
        }

        let id_len = self.identity.full_len();
        let sig_len = self.identity.signature_len()?;
        if buf.len() < id_len + sig_len {
            return Err(I2PError::InvalidLength {
                expected: id_len + sig_len,
                got: buf.len(),
            });
        }

        let body = RouterInfo::parse_body(&buf[id_len..buf.len() - sig_len])?;
        self.body = body;
        Ok(true)
    }

    /// То же, что [`Self::update`], но с проверкой подписи.
    ///
    /// Требует полный RI-буфер (identity + body + signature).
    /// Верификация идёт через `self.identity.verify` — подпись
    /// должна быть от того же роутера.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — подпись не сходится;
    /// - остальные — как [`Self::update`].
    pub fn update_verified(&mut self, buf: &[u8]) -> Result<bool> {
        let sig_len = self.identity.signature_len()?;
        if buf.len() < sig_len {
            return Err(I2PError::InvalidLength {
                expected: sig_len,
                got: buf.len(),
            });
        }
        let (signed, sig) = buf.split_at(buf.len() - sig_len);
        self.identity.verify(signed, sig)?;
        self.update(buf)
    }
    /// Проверяет подпись над исходными байтами `buf`.
    ///
    /// `buf` — это **исходные байты** `RouterInfo`, ровно те, что
    /// были прочитаны из файла или получены из сети. Мы не
    /// пересобираем их из struct: если в исходном `RouterInfo`
    /// содержалось что-то, что наш writer нормализует (например
    /// multi-value `pq=4,3` у SSU2), подпись всё равно проверится —
    /// мы доверяем `buf`, а не своей ре-сериализации.
    ///
    /// Публичный ключ берётся из [`Self::identity`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если `buf` короче `signature_len`;
    /// - [`Error::Unsupported`] — тип подписи не реализован;
    /// - [`Error::Malformed`] — подпись не сходится.
    pub fn verify(&self, buf: &[u8]) -> Result<()> {
        let sig_len = self.identity.signature_len()?;
        if buf.len() < sig_len {
            return Err(I2PError::InvalidLength {
                expected: sig_len,
                got: buf.len(),
            });
        }
        let (signed, sig) = buf.split_at(buf.len() - sig_len);
        self.identity.verify(signed, sig)
    }
    /// Сериализует полный `RouterInfo` в wire-формат.
    ///
    /// Обратная к [`Self::from_buffer`].
    ///
    /// # Errors
    ///
    /// См. [`IdentityEx::to_buffer`] и [`RouterInfo::serialize_body`].
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let id_len = self.identity.full_len();
        let mut id_buf = vec![0u8; id_len];
        self.identity.to_buffer(&mut id_buf)?;

        let mut out = Vec::with_capacity(id_len + self.body.addresses.len() * 128 + 256);
        out.extend_from_slice(&id_buf);
        out.extend_from_slice(&self.body.serialize_body()?);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }
}
