//! `RouterConfig` — конфигурация роутера.
//!
//! Собирается через [`RouterConfigBuilder`], проверяется в [`RouterConfig::build`].
//! Иммутабелен после сборки; для runtime-изменений (например, добавления
//! нового listen-адреса) нужно построить новый конфиг и передать его
//! `RouterContext::reconfigure`.
//!
//! ## Множественные listen-endpoints
//!
//! Роутер может слушать на любом количестве `bind`-адресов. Каждый
//! [`ListenEndpoint`] независим:
//!
//! - **bind** — куда открывать `tokio::net::TcpListener`;
//! - **advertise** — какой IP публиковать в своём `RouterInfo`.
//!   `None` — не публикуем (полезно для `127.0.0.1`, для NAT'нутых
//!   роутеров, для тестового окружения).
//!
//! ## Что НЕ реализовано
//!
//! - загрузка из файла (i2pd-style `i2pd.conf`) — caller сам заполняет
//!   builder;
//! - SSU2 (UDP) — только NTCP2 (TCP); когда появится SSU2, добавим
//!   `Transport` в [`ListenEndpoint`];
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

/// Версия протокола по умолчанию (`0.9.70` → `970`).
pub const DEFAULT_VERSION: u32 = 970;

/// `netId` по умолчанию — основной I2P.
pub const DEFAULT_NET_ID: u8 = 2;

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
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenEndpoint {
    /// Адрес и порт, на которых открываем listener.
    pub bind: SocketAddr,
    /// IP, который публикуем в `RouterInfo`. `None` — не публикуем.
    ///
    /// Порт для advertise-адреса берётся из `bind.port()`.
    pub advertise: Option<IpAddr>,
}

impl ListenEndpoint {
    /// Непубликуемый endpoint. Полезен для loopback'а, NAT-роутеров,
    /// тестового окружения.
    #[must_use]
    pub const fn unpublished(bind: SocketAddr) -> Self {
        Self {
            bind,
            advertise: None,
        }
    }

    /// Публикуемый endpoint: `bind` для listener'а, `advertise` в RI.
    #[must_use]
    pub const fn published(bind: SocketAddr, advertise: IpAddr) -> Self {
        Self {
            bind,
            advertise: Some(advertise),
        }
    }

    /// Автоопределение: если `bind` — на конкретном IP (не unspecified),
    /// то публикуем именно его; если на `0.0.0.0`/`::` — не публикуем.
    ///
    /// Разумный дефолт, чтобы не заставлять caller явно указывать
    /// advertise для тривиальных случаев.
    #[must_use]
    pub const fn auto(bind: SocketAddr) -> Self {
        if bind.ip().is_unspecified() {
            Self::unpublished(bind)
        } else {
            Self {
                bind,
                advertise: Some(bind.ip()),
            }
        }
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
///   не unspecified, порт ≠ 0.
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
    listen: Vec<ListenEndpoint>,
    caps: RouterInfoCaps,
    is_floodfill: bool,
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

        for ep in &self.listen {
            // Готовим общие параметры заранее, чтобы замыкания
            // в `map_or_else` были короткие.
            let port = ep.bind.port();
            let iv = self.ntcp2_iv;
            let is_v4 = ep.bind.is_ipv4();
            let is_v6 = ep.bind.is_ipv6();

            let address = ep.advertise.map_or_else(
                || I2PAddress::ntcp2_unpublished(port, s, iv, is_v4, is_v6),
                |ip| I2PAddress::ntcp2_published(ip, port, s, iv),
            );
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
            .field("listen", &self.listen)
            .field("caps", &self.caps)
            .field("is_floodfill", &self.is_floodfill)
            .finish_non_exhaustive()
    }
}

/// Builder для [`RouterConfig`].
///
/// ## Дефолты
///
/// - `net_id` = [`DEFAULT_NET_ID`] (2);
/// - `version` = [`DEFAULT_VERSION`] (970);
/// - `caps` = `L` (low bandwidth, low congestion);
/// - `is_floodfill` = `false`;
/// - `listen` = пусто — **обязательно** заполнить через
///   [`Self::listen_auto`] / [`Self::listen_unpublished`] /
///   [`Self::listen_published`].
#[derive(Default)]
pub struct RouterConfigBuilder {
    net_id: Option<u8>,
    version: Option<u32>,
    keys: Option<I2PPrivateKeys>,
    ntcp2_static: Option<I2PX25519Keys>,
    ntcp2_iv: Option<[u8; 16]>,
    listen: Vec<ListenEndpoint>,
    caps: Option<RouterInfoCaps>,
    is_floodfill: bool,
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
            .field("listen", &self.listen)
            .field("caps", &self.caps)
            .field("is_floodfill", &self.is_floodfill)
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

    /// Валидирует и собирает [`RouterConfig`].
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — отсутствуют обязательные поля
    ///   (`keys`, `ntcp2_keys`), `listen` пуст;
    /// - [`Error::Unsupported`] — ключи не `EdDSA` + ECIES-X25519;
    /// - [`Error::Malformed`] — публикуемый `advertise`-адрес
    ///   unspecified, multicast или loopback; порт 0.
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
                if ip.is_loopback() {
                    return Err(I2PError::Malformed("config: advertise IP is loopback"));
                }
                if ep.bind.port() == 0 {
                    return Err(I2PError::Malformed("config: advertise endpoint has port 0"));
                }
            }
        }

        Ok(RouterConfig {
            net_id: self.net_id.unwrap_or(DEFAULT_NET_ID),
            version: self.version.unwrap_or(DEFAULT_VERSION),
            keys,
            ntcp2_static,
            ntcp2_iv,
            listen: self.listen,
            caps: self.caps.unwrap_or_else(|| RouterInfoCaps::parse(b"L")),
            is_floodfill: self.is_floodfill,
        })
    }
}
