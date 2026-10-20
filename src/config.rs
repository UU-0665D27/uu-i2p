//! `RouterConfig` — конфигурация роутера.
//!
//! Собирается через [`RouterConfigBuilder`], проверяется в [`RouterConfig::build`].
//! Иммутабелен после сборки; для runtime-изменений (например, добавления
//! нового listen-адреса) нужно построить новый конфиг и передать его
//! `RouterContext::reconfigure`.
//!
//! ## Множественные listen-endpoints
//!
//! Роутер слушает на любом количестве `bind`-адресов — в том числе на
//! нескольких интерфейсах и на разных транспортах сразу. Ограничения «один
//! endpoint на роутер» здесь нет. Каждый [`ListenEndpoint`] независим:
//!
//! - **bind** — куда открывать listener;
//! - **transport** — [`Transport::Ntcp2`] (TCP) или [`Transport::Ssu2`]
//!   (UDP). NTCP2 и SSU2 могут слушать один и тот же `IP:порт`: это разные
//!   сокеты (TCP и UDP), и так делает i2pd;
//! - **advertise** — какой IP публиковать в своём `RouterInfo`.
//!   `None` — не публикуем (полезно для `127.0.0.1`, для NAT'нутых
//!   роутеров, для тестового окружения).
//!
//! ## Что НЕ реализовано
//!
//! - загрузка из файла (i2pd-style `i2pd.conf`) — caller сам заполняет
//!   builder;
//! - bandwidth limits, congestion, auto-caps — пока всё вручную через
//!   [`RouterInfoCaps`].

use crate::{
    I2PTag,
    crypto::I2PX25519Keys,
    error::{I2PError, Result},
    private_keys::I2PPrivateKeys,
    router_info::{FullRouterInfo, RouterInfo, RouterInfoCaps, ri_caps},
    router_info_address::I2PAddress,
    signature::{CryptoKeyType, SigningKeyType},
};
use std::net::{IpAddr, SocketAddr};

/// Версия протокола по умолчанию (`0.9.71` → `971`, как i2pd 3.0).
pub const DEFAULT_VERSION: u32 = 971;

/// `netId` по умолчанию — основной I2P.
pub const DEFAULT_NET_ID: u8 = 2;

/// Транспорт listen-endpoint'а.
///
/// Отличается сокет: [`Transport::Ntcp2`] — TCP (`tokio::net::TcpListener`),
/// [`Transport::Ssu2`] — UDP (`tokio::net::UdpSocket`). Один и тот же
/// `IP:порт` может быть занят сразу обоими транспортами — это разные сокеты.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP — NTCP2.
    Ntcp2,
    /// UDP — SSU2.
    Ssu2,
}

impl Transport {
    /// Имя транспорта (для логов и ошибок).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ntcp2 => "NTCP2",
            Self::Ssu2 => "SSU2",
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Один listen-endpoint.
///
/// ## Пример
///
/// ```ignore
/// // Слушаем на 0.0.0.0:2827, но не публикуем адрес — годится
/// // для NAT'нутого роутера, который сам инициирует соединения.
/// let ep = ListenEndpoint::unpublished("0.0.0.0:2827".parse().unwrap());
///
/// // Слушаем на 0.0.0.0:2827, публикуем 1.2.3.4:2827 — для
/// // опубликованного роутера за NAT'ом.
/// let ep = ListenEndpoint::published(
///     "0.0.0.0:2827".parse().unwrap(),
///     "1.2.3.4".parse().unwrap(),
/// );
///
/// // SSU2 (UDP) на том же порту, что TCP выше — это разные сокеты.
/// let ep = ListenEndpoint::ssu2_auto("0.0.0.0:2827".parse().unwrap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenEndpoint {
    /// Адрес и порт, на которых открываем listener.
    pub bind: SocketAddr,
    /// IP, который публикуем в `RouterInfo`. `None` — не публикуем.
    ///
    /// Порт для advertise-адреса берётся из `bind.port()`.
    pub advertise: Option<IpAddr>,
    /// Транспорт (TCP — NTCP2, UDP — SSU2).
    pub transport: Transport,
}

impl ListenEndpoint {
    /// Непубликуемый endpoint транспорта `transport`.
    #[must_use]
    pub const fn unpublished_on(transport: Transport, bind: SocketAddr) -> Self {
        Self {
            bind,
            advertise: None,
            transport,
        }
    }

    /// Публикуемый endpoint транспорта `transport`.
    #[must_use]
    pub const fn published_on(transport: Transport, bind: SocketAddr, advertise: IpAddr) -> Self {
        Self {
            bind,
            advertise: Some(advertise),
            transport,
        }
    }

    /// Автоопределение advertise для транспорта `transport`: если `bind` —
    /// на конкретном IP (не unspecified), публикуем именно его; если на
    /// `0.0.0.0`/`::` — не публикуем.
    #[must_use]
    pub const fn auto_on(transport: Transport, bind: SocketAddr) -> Self {
        if bind.ip().is_unspecified() {
            Self::unpublished_on(transport, bind)
        } else {
            Self::published_on(transport, bind, bind.ip())
        }
    }

    /// NTCP2 (TCP), непубликуемый. Полезен для loopback'а, NAT-роутеров,
    /// тестового окружения.
    #[must_use]
    pub const fn unpublished(bind: SocketAddr) -> Self {
        Self::unpublished_on(Transport::Ntcp2, bind)
    }

    /// NTCP2 (TCP), публикуемый: `bind` для listener'а, `advertise` в RI.
    #[must_use]
    pub const fn published(bind: SocketAddr, advertise: IpAddr) -> Self {
        Self::published_on(Transport::Ntcp2, bind, advertise)
    }

    /// NTCP2 (TCP), автоопределение advertise.
    #[must_use]
    pub const fn auto(bind: SocketAddr) -> Self {
        Self::auto_on(Transport::Ntcp2, bind)
    }

    /// SSU2 (UDP), непубликуемый.
    #[must_use]
    pub const fn ssu2_unpublished(bind: SocketAddr) -> Self {
        Self::unpublished_on(Transport::Ssu2, bind)
    }

    /// SSU2 (UDP), публикуемый.
    #[must_use]
    pub const fn ssu2_published(bind: SocketAddr, advertise: IpAddr) -> Self {
        Self::published_on(Transport::Ssu2, bind, advertise)
    }

    /// SSU2 (UDP), автоопределение advertise.
    #[must_use]
    pub const fn ssu2_auto(bind: SocketAddr) -> Self {
        Self::auto_on(Transport::Ssu2, bind)
    }

    /// Сменить транспорт endpoint'а.
    #[must_use]
    pub const fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }
}

/// Конфигурация роутера.
///
/// ## Инварианты (проверяются в [`RouterConfigBuilder::build`])
///
/// - `keys.public().signing_key_type() == EdDsaSha512Ed25519`;
/// - `keys.public().crypto_key_type() == EciesX25519Aead`;
/// - `listen` непуст;
/// - в каждом публикуемом endpoint'е `advertise` не multicast,
///   не unspecified, порт ≠ 0; loopback запрещён, если не включён
///   [`RouterConfigBuilder::allow_reserved_advertise`].
///
/// ## Не `Clone`
///
/// `PrivateKeys` и `X25519Keys` содержат секреты и не реализуют `Clone`.
/// Один роутер — один конфиг; если нужны ссылки из нескольких мест,
/// оборачивай в `std::sync::Arc<RouterConfig>`.
pub struct RouterConfig {
    net_id: u8,
    version: u32,
    keys: I2PPrivateKeys,
    ntcp2_static: I2PX25519Keys,
    ntcp2_iv: [u8; 16],
    ssu2_intro_key: Option<[u8; 32]>,
    listen: Vec<ListenEndpoint>,
    caps: RouterInfoCaps,
    is_floodfill: bool,
    allow_reserved_advertise: bool,
}

impl RouterConfig {
    /// Возвращает новый [`RouterConfigBuilder`].
    #[must_use]
    pub fn builder() -> RouterConfigBuilder {
        RouterConfigBuilder::default()
    }

    /// `netId`.
    #[must_use]
    pub const fn net_id(&self) -> u8 {
        self.net_id
    }

    /// Версия роутера.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Приватные ключи.
    #[must_use]
    pub const fn keys(&self) -> &I2PPrivateKeys {
        &self.keys
    }

    /// Static X25519-ключ NTCP2.
    #[must_use]
    pub const fn ntcp2_static(&self) -> &I2PX25519Keys {
        &self.ntcp2_static
    }

    /// NTCP2 IV.
    #[must_use]
    pub const fn ntcp2_iv(&self) -> &[u8; 16] {
        &self.ntcp2_iv
    }

    /// Intro-ключ SSU2 (`i=` в адресе SSU2). `None`, пока нет SSU2-endpoint'ов.
    ///
    /// Один ключ на все SSU2-интерфейсы — так же, как i2pd хранит его в
    /// `RouterContext::m_SSU2Keys->intro`. Static-ключ (`s=`) у NTCP2 и SSU2
    /// общий ([`Self::ntcp2_static`]).
    #[must_use]
    pub const fn ssu2_intro_key(&self) -> Option<&[u8; 32]> {
        self.ssu2_intro_key.as_ref()
    }

    /// Listen-endpoints.
    #[must_use]
    pub fn listen(&self) -> &[ListenEndpoint] {
        &self.listen
    }

    /// RI-level caps.
    #[must_use]
    pub const fn caps(&self) -> RouterInfoCaps {
        self.caps
    }

    /// Флаг floodfill.
    #[must_use]
    pub const fn is_floodfill(&self) -> bool {
        self.is_floodfill
    }

    /// Разрешено ли публиковать адрес из reserved-диапазона.
    ///
    /// См. [`RouterConfigBuilder::allow_reserved_advertise`]: в обычной
    /// конфигурации — `false`, включается только для локальных проверок.
    #[must_use]
    pub const fn allow_reserved_advertise(&self) -> bool {
        self.allow_reserved_advertise
    }

    /// Собирает и подписывает собственный `RouterInfo`.
    ///
    /// `timestamp_ms` — метка времени в миллисекундах since epoch.
    /// Параметром, а не чтением системных часов — чтобы тесты были
    /// детерминированными.
    ///
    /// ## О стоимости
    ///
    /// Каждый вызов пересобирает RI заново и делает Ed25519-подпись
    /// (~50 мкс). В реальном `RouterContext` RI кэшируется и
    /// пересобирается только при `SetUnreachable` / смене адресов
    /// / периодическом обновлении `timestamp`. Здесь мы даём
    /// простой конструктор — caller сам решает про кэш.
    ///
    /// # Errors
    ///
    /// См. [`FullRouterInfo::from_keys`].
    pub fn build_router_info(&self, timestamp_ms: u64) -> Result<FullRouterInfo> {
        let mut static_bytes = [0u8; 32];
        static_bytes.copy_from_slice(self.ntcp2_static.public_key());
        let s = I2PTag::from_array(static_bytes);

        let mut builder = RouterInfo::builder().timestamp(timestamp_ms);

        // Инвариант `build()`: если есть SSU2-endpoint'ы, intro-ключ задан.
        let intro = I2PTag::from_array(self.ssu2_intro_key.unwrap_or_default());

        for ep in &self.listen {
            // Готовим общие параметры заранее, чтобы замыкания
            // в `map_or_else` были короткие.
            let port = ep.bind.port();
            let iv = self.ntcp2_iv;
            let is_v4 = ep.bind.is_ipv4();
            let is_v6 = ep.bind.is_ipv6();

            let address = match ep.transport {
                Transport::Ntcp2 => ep.advertise.map_or_else(
                    || I2PAddress::ntcp2_unpublished(port, s, iv, is_v4, is_v6),
                    |ip| I2PAddress::ntcp2_published(ip, port, s, iv),
                ),
                Transport::Ssu2 => ep.advertise.map_or_else(
                    || I2PAddress::ssu2_unpublished(port, s, intro, is_v4, is_v6),
                    |ip| I2PAddress::ssu2_published(ip, port, s, intro),
                ),
            };
            builder = builder.add_address(address);
        }

        let mut caps = self.caps;
        if self.is_floodfill {
            caps.bits |= ri_caps::FLOODFILL;
        }

        let body = builder
            .caps(caps)
            .version(self.version)
            .net_id(i32::from(self.net_id))
            .build();

        FullRouterInfo::from_keys(&self.keys, body)
    }
}

impl std::fmt::Debug for RouterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterConfig")
            .field("net_id", &self.net_id)
            .field("version", &self.version)
            .field("ident_hash", self.keys.public().ident_hash())
            .field("ntcp2_public", self.ntcp2_static.public_key())
            .field("ssu2_intro_key_set", &self.ssu2_intro_key.is_some())
            .field("listen", &self.listen)
            .field("caps", &self.caps)
            .field("is_floodfill", &self.is_floodfill)
            .field("allow_reserved_advertise", &self.allow_reserved_advertise)
            .finish_non_exhaustive()
    }
}

/// Builder для [`RouterConfig`].
///
/// ## Дефолты
///
/// - `net_id` = [`DEFAULT_NET_ID`] (2);
/// - `version` = [`DEFAULT_VERSION`] (971);
/// - `caps` = `L` (low bandwidth, low congestion);
/// - `is_floodfill` = `false`;
/// - `listen` = пусто — **обязательно** заполнить через
///   [`Self::listen_auto`] / [`Self::listen_unpublished`] /
///   [`Self::listen_published`] (NTCP2) либо их SSU2-аналоги
///   [`Self::listen_ssu2_auto`] / [`Self::listen_ssu2_unpublished`] /
///   [`Self::listen_ssu2_published`].
#[derive(Default)]
pub struct RouterConfigBuilder {
    net_id: Option<u8>,
    version: Option<u32>,
    keys: Option<I2PPrivateKeys>,
    ntcp2_static: Option<I2PX25519Keys>,
    ntcp2_iv: Option<[u8; 16]>,
    ssu2_intro_key: Option<[u8; 32]>,
    listen: Vec<ListenEndpoint>,
    caps: Option<RouterInfoCaps>,
    is_floodfill: bool,
    allow_reserved_advertise: bool,
}

impl std::fmt::Debug for RouterConfigBuilder {
    /// Печатает только «наличие» секретов, не сами секреты.
    ///
    /// `X25519Keys` не реализует `Debug` (`crypto.rs`), а `PrivateKeys`
    /// содержит приватные байты — оба попадают в builder как
    /// `Option<...>` без `Debug`. Ручной impl обходит это, выводя
    /// только публичный `ident_hash` (если есть) и флаги наличия
    /// остальных полей.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterConfigBuilder")
            .field("net_id", &self.net_id)
            .field("version", &self.version)
            .field(
                "keys_ident_hash",
                &self.keys.as_ref().map(|k| k.public().ident_hash()),
            )
            .field("ntcp2_static_set", &self.ntcp2_static.is_some())
            .field("ntcp2_iv", &self.ntcp2_iv)
            .field("ssu2_intro_key_set", &self.ssu2_intro_key.is_some())
            .field("listen", &self.listen)
            .field("caps", &self.caps)
            .field("is_floodfill", &self.is_floodfill)
            .field("allow_reserved_advertise", &self.allow_reserved_advertise)
            .finish()
    }
}
impl RouterConfigBuilder {
    /// `netId`.
    #[must_use]
    pub const fn net_id(mut self, net_id: u8) -> Self {
        self.net_id = Some(net_id);
        self
    }

    /// Версия роутера.
    #[must_use]
    pub const fn version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    /// Приватные ключи роутера.
    #[must_use]
    pub fn keys(mut self, keys: I2PPrivateKeys) -> Self {
        self.keys = Some(keys);
        self
    }

    /// NTCP2 static key + IV.
    #[must_use]
    pub fn ntcp2_keys(mut self, static_key: I2PX25519Keys, iv: [u8; 16]) -> Self {
        self.ntcp2_static = Some(static_key);
        self.ntcp2_iv = Some(iv);
        self
    }

    /// Intro-ключ SSU2. Обязателен, если среди listen-endpoint'ов есть SSU2.
    ///
    /// Static-ключ (`s=`) отдельно задавать не нужно: он общий с NTCP2
    /// ([`Self::ntcp2_keys`]) — как в i2pd, где NTCP2 и SSU2 используют одну
    /// пару статических ключей.
    #[must_use]
    pub const fn ssu2_intro_key(mut self, intro_key: [u8; 32]) -> Self {
        self.ssu2_intro_key = Some(intro_key);
        self
    }

    /// Добавляет listen-endpoint.
    #[must_use]
    pub fn listen(mut self, ep: ListenEndpoint) -> Self {
        self.listen.push(ep);
        self
    }

    /// Удобный шорткат: `listen(ListenEndpoint::auto(bind))`.
    #[must_use]
    pub fn listen_auto(mut self, bind: SocketAddr) -> Self {
        self.listen.push(ListenEndpoint::auto(bind));
        self
    }

    /// Удобный шорткат: `listen(ListenEndpoint::unpublished(bind))`.
    #[must_use]
    pub fn listen_unpublished(mut self, bind: SocketAddr) -> Self {
        self.listen.push(ListenEndpoint::unpublished(bind));
        self
    }

    /// Удобный шорткат: `listen(ListenEndpoint::published(bind, advertise))`.
    #[must_use]
    pub fn listen_published(mut self, bind: SocketAddr, advertise: IpAddr) -> Self {
        self.listen.push(ListenEndpoint::published(bind, advertise));
        self
    }

    /// Шорткат SSU2: `listen(ListenEndpoint::ssu2_auto(bind))`.
    #[must_use]
    pub fn listen_ssu2_auto(mut self, bind: SocketAddr) -> Self {
        self.listen.push(ListenEndpoint::ssu2_auto(bind));
        self
    }

    /// Шорткат SSU2: `listen(ListenEndpoint::ssu2_unpublished(bind))`.
    #[must_use]
    pub fn listen_ssu2_unpublished(mut self, bind: SocketAddr) -> Self {
        self.listen.push(ListenEndpoint::ssu2_unpublished(bind));
        self
    }

    /// Шорткат SSU2: `listen(ListenEndpoint::ssu2_published(bind, advertise))`.
    #[must_use]
    pub fn listen_ssu2_published(mut self, bind: SocketAddr, advertise: IpAddr) -> Self {
        self.listen
            .push(ListenEndpoint::ssu2_published(bind, advertise));
        self
    }

    /// RI-level caps.
    #[must_use]
    pub const fn caps(mut self, caps: RouterInfoCaps) -> Self {
        self.caps = Some(caps);
        self
    }

    /// Флаг floodfill.
    #[must_use]
    pub const fn floodfill(mut self, floodfill: bool) -> Self {
        self.is_floodfill = floodfill;
        self
    }

    /// Разрешить публиковать адрес из reserved-диапазона (loopback и т.п.).
    ///
    /// По умолчанию запрещено: в настоящей сети такой `advertise`
    /// бесполезен, а loopback в RI — признак ошибки. Нужно только для
    /// локальных interop-проверок (`127.0.0.1`), где повторяет смысл
    /// i2pd `reservedrange = false`.
    #[must_use]
    pub const fn allow_reserved_advertise(mut self, allow: bool) -> Self {
        self.allow_reserved_advertise = allow;
        self
    }

    /// Валидирует и собирает [`RouterConfig`].
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — отсутствуют обязательные поля
    ///   (`keys`, `ntcp2_keys`), `listen` пуст;
    /// - [`Error::Unsupported`] — ключи не `EdDSA` + ECIES-X25519;
    /// - [`Error::Malformed`] — публикуемый `advertise`-адрес
    ///   unspecified, multicast или loopback (loopback — если не включён
    ///   [`RouterConfigBuilder::allow_reserved_advertise`]); порт 0;
    /// - [`Error::Malformed`] — есть SSU2-endpoint, но не задан
    ///   `ssu2_intro_key`;
    /// - [`Error::Malformed`] — два endpoint'а одного транспорта на одном
    ///   `bind` (такой сокет не открыть дважды; NTCP2 и SSU2 на одном
    ///   `IP:порт` — можно, это разные сокеты).
    pub fn build(self) -> Result<RouterConfig> {
        let keys = self
            .keys
            .ok_or(I2PError::Malformed("config: keys not set"))?;
        let ntcp2_static = self
            .ntcp2_static
            .ok_or(I2PError::Malformed("config: ntcp2 static key not set"))?;
        let ntcp2_iv = self
            .ntcp2_iv
            .ok_or(I2PError::Malformed("config: ntcp2 iv not set"))?;

        // Тип подписи и crypto: мы поддерживаем только EdDSA + ECIES-X25519.
        let skt = keys.public().signing_key_type()?;
        if skt != SigningKeyType::EdDsaSha512Ed25519 {
            return Err(I2PError::Unsupported(
                "config: only EdDSA-SHA512-Ed25519 signing key is supported",
            ));
        }
        let ckt = keys.public().crypto_key_type()?;
        if ckt != CryptoKeyType::EciesX25519Aead {
            return Err(I2PError::Unsupported(
                "config: only ECIES-X25519-AEAD crypto key is supported",
            ));
        }

        if self.listen.is_empty() {
            return Err(I2PError::Malformed(
                "config: at least one listen endpoint required",
            ));
        }

        for ep in &self.listen {
            if let Some(ip) = ep.advertise {
                if ip.is_unspecified() {
                    return Err(I2PError::Malformed("config: advertise IP is unspecified"));
                }
                if ip.is_multicast() {
                    return Err(I2PError::Malformed("config: advertise IP is multicast"));
                }
                if ip.is_loopback() && !self.allow_reserved_advertise {
                    return Err(I2PError::Malformed("config: advertise IP is loopback"));
                }
                if ep.bind.port() == 0 {
                    return Err(I2PError::Malformed("config: advertise endpoint has port 0"));
                }
            }
        }

        let mut seen: Vec<(Transport, SocketAddr)> = Vec::with_capacity(self.listen.len());
        for ep in &self.listen {
            let key = (ep.transport, ep.bind);
            if seen.contains(&key) {
                return Err(I2PError::Malformed(
                    "config: duplicate listen endpoint for the same transport",
                ));
            }
            seen.push(key);
        }

        let ssu2_intro_key = self.ssu2_intro_key;
        if self.listen.iter().any(|ep| ep.transport == Transport::Ssu2) && ssu2_intro_key.is_none()
        {
            return Err(I2PError::Malformed(
                "config: ssu2 intro key not set, but SSU2 endpoint present",
            ));
        }

        Ok(RouterConfig {
            net_id: self.net_id.unwrap_or(DEFAULT_NET_ID),
            version: self.version.unwrap_or(DEFAULT_VERSION),
            keys,
            ntcp2_static,
            ntcp2_iv,
            ssu2_intro_key,
            listen: self.listen,
            caps: self.caps.unwrap_or_else(|| RouterInfoCaps::parse(b"L")),
            is_floodfill: self.is_floodfill,
            allow_reserved_advertise: self.allow_reserved_advertise,
        })
    }
}
