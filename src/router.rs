//! `Router` — объединённый роутер: состояние, транспорты и цикл событий.
//!
//! До этого модуля библиотека состояла из независимых частей:
//! [`RouterContext`] (синхронное состояние), пулы транспортов
//! ([`Ssu2Pool`], [`Ntcp2Pool`]) и примитивы туннелей. Здесь они
//! собираются в одно работающее целое — то, что в i2pd разделено между
//! `i2p::context` (`RouterContext` со своим `Run`) и `Transports`.
//!
//! ## Что делает `Router`
//!
//! - держит [`RouterContext`] — ключи, свой `RouterInfo`, netDb,
//!   ECIES-сессии, активные запросы;
//! - держит транспорты за трейтом [`TransportPool`] и раздаёт им исходящие
//!   I2NP-сообщения ([`Router::send`], [`Router::dial`]);
//! - собирает события всех транспортов в один канал (по pump-таске на
//!   транспорт) — вместо `m_Service` в i2pd;
//! - по таймеру прокручивает [`RouterContext::tick_netdb_requests`],
//!   публикует свой `RouterInfo` флудфиллам и обслуживает транспорты;
//! - разбирает входящие I2NP-сообщения — таблицей, как i2pd
//!   `HandleI2NPMessage` (`I2NPProtocol.cpp:452`).
//!
//! ## Швы (traits)
//!
//! Всё, что нужно подменять в тестах или доопределять под конкретную
//! политику, вынесено в трейты:
//!
//! | Трейт | Зачем |
//! |-------|-------|
//! | [`TransportPool`] | сеть: SSU2/NTCP2/что угодно; в тестах — подделка |
//! | [`Clock`] | время; в тестах — управляемые часы |
//! | [`RouterPolicy`] | решения: интервалы, кому публиковать, отвечать ли на lookup |
//! | [`RouterObserver`] | наблюдения наружу (UI/логи/тесты) |
//!
//! Дефолтные реализации повторяют i2pd: [`SystemClock`],
//! [`I2pdRouterPolicy`], [`NoopObserver`].
//!
//! ## Поток событий
//!
//! ```text
//!   транспорт ──next_event()──► pump-таска ──RouterEvent──► mpsc ──┐
//!                                                                 ▼
//!   run_until ──select!──► handle_event ──► handle_message ──► RouterContext
//!       ▲                                                          │
//!       └───────── tick (таймер) ─────────────────────────────────┤
//!                          dial()/send() ────────────────────────► транспорт
//! ```
//!
//! `run_until` — тонкая оболочка: вся логика живёт в
//! [`Router::handle_event`], [`Router::handle_message`] и
//! [`Router::tick`]. Их можно звать напрямую из тестов, без запуска
//! цикла и без сети.
//!
//! ## Кому отвечаем на `DatabaseLookup`
//!
//! Как в i2pd: если мы флудфилл (`caps` содержит `f`) — отвечаем из
//! своего netDb ([`RouterContext::process_database_lookup`]). Если нет —
//! запрос полагается переслать флудфиллу; пересылка требует туннелей и
//! пока не сделана (`// TODO(name)` ниже).
//!
//! ## Что TODO
//!
//! - туннели: `TunnelData`/`TunnelGateway`/`TunnelBuild*`/`TunnelTest`
//!   (шаг 3b) — сейчас логируются и отбрасываются;
//! - `LeaseSet` в netDb (`DatabaseStore` не-RI): отдаём на уровень
//!   destination'ов (шаг 3c);
//! - `DeliveryStatus` как подтверждение публикации своего `RouterInfo`
//!   (в i2pd — `RouterContext::PostDeliveryStatusMessage`);
//! - пересылка `DatabaseLookup` на флудфилл, когда мы не флудфилл;
//! - разброс интервала публикации `RouterInfo`
//!   (`ROUTER_INFO_PUBLISH_INTERVAL_VARIANCE` в i2pd) — нужен источник
//!   случайности в `RouterPolicy`;
//! - `ExternalAddress`: обновление своего адреса и `UpdateRouterInfo`
//!   (i2pd `RouterContext::UpdateAddress`).

use std::{
    collections::HashMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle, time::MissedTickBehavior};
use tracing::{debug, info, trace, warn};

use crate::{
    IdentHash,
    config::Transport as TransportKind,
    database_store::DatabaseStore,
    error::{I2PError, Result},
    i2np::I2npMessageType,
    i2np_message::{I2npBody, I2npMessage},
    ntcp2::Ntcp2Local,
    ntcp2_pool::{Ntcp2Pool, PoolEvent},
    router_context::{GarlicReply, RouterContext, StoreHandling},
    router_info::FullRouterInfo,
    router_info_address::I2PAddress,
    ssu2_pool::{Ssu2Event, Ssu2Pool},
};

// --- константы (значения — из i2pd) --------------------------------------

/// Период тика: как часто прокручивать таймеры роутера.
///
/// i2pd: `MANAGE_REQUESTS_INTERVAL` (`NetDbRequests.h:27`) — 400 мс,
/// плюс разброс до 300 мс; разброс не делаем, пока в
/// [`RouterPolicy`] нет источника случайности.
pub const TICK_INTERVAL_MS: u64 = 400;

/// Первая публикация своего `RouterInfo` после старта.
///
/// i2pd: `ROUTER_INFO_INITIAL_PUBLISH_INTERVAL` (`RouterContext.h:36`).
pub const INITIAL_RI_PUBLISH_INTERVAL_SECS: u64 = 10;

/// Периодичность публикации своего `RouterInfo`.
///
/// i2pd: `ROUTER_INFO_PUBLISH_INTERVAL` (`RouterContext.h:35`) — 39 мин.
pub const RI_PUBLISH_INTERVAL_SECS: u64 = 39 * 60;

/// Скольким флудфиллам публикуем свой `RouterInfo`.
///
/// i2pd публикует ближайшему (`GetClosestFloodfill`) и на неудаче
/// перебирает следующих; у нас тот же смысл с одним адресатом за тик.
pub const RI_PUBLISH_TARGETS: usize = 1;

/// Размер очереди событий «транспорты → роутер».
const EVENT_QUEUE: usize = 256;

// --- будущее трейт-объектов ----------------------------------------------

/// Боксованное будущее.
///
/// Трейт-объект [`TransportPool`] не может иметь `async fn` (нужна
/// dyn-совместимость), поэтому методы возвращают это явно.
/// `Send` — чтобы [`Router`] оставался `Send`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// --- вид транспорта ------------------------------------------------------

// Тип транспорта — [`crate::config::Transport`] из конфигурации
// (`Ntcp2`/`Ssu2`), а не свой enum: у него уже есть `name()` и
// `Display`, и роутер обязан говорить о транспортах теми же словами,
// что и конфиг. Локальный алиас — чтобы `Transport` (трейт) и тип
// транспорта читались по-разному.

// --- унифицированное событие транспорта ---------------------------------

/// Событие транспорта — то, что роутер получает от сети.
///
/// Объединение [`Ssu2Event`] и [`PoolEvent`]: NTCP2 пока умеет меньше
/// (см. адаптер [`Ntcp2Transport`]), но наружу вид один — роутеру не
/// важно, каким транспортом пришло сообщение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// Соединение установлено.
    Established {
        /// Собеседник.
        ident: IdentHash,
    },
    /// Принято I2NP-сообщение.
    Message {
        /// От кого.
        from: IdentHash,
        /// Само сообщение.
        message: I2npMessage,
    },
    /// Собеседник прислал свой `RouterInfo`.
    RouterInfo {
        /// От кого.
        from: IdentHash,
        /// Сырые байты `RouterInfo`.
        ri_bytes: Vec<u8>,
    },
    /// Соединение завершено.
    Disconnected {
        /// С кем.
        ident: IdentHash,
    },
    /// Собеседник сообщил, каким видит наш внешний адрес
    /// (i2pd `Transports::HandleAddress` → `RouterContext::UpdateAddress`).
    ///
    /// Что с этим делать (публиковать ли адрес) решает [`RouterPolicy`]:
    /// пул только сообщает наблюдение.
    ExternalAddress {
        /// Наш адрес, каким его видит собеседник.
        addr: SocketAddr,
        /// Через какую сессию узнали.
        from: Option<IdentHash>,
    },
}

// --- трейт транспорта ----------------------------------------------------

/// Транспорт, через который роутер говорит с другими роутерами.
///
/// Реализации: [`Ssu2Pool`] и [`Ntcp2Transport`] (NTCP2). Роутер держит
/// транспорты за `Arc<dyn TransportPool>`, `next_event` у каждого
/// вызывается ровно одной pump-таской.
///
/// # Errors
///
/// Ошибки транспорта не фатальны для роутера: `send_to`/`dial`
/// возвращают их вызывающему, а ошибка `next_event` означает, что
/// транспорт больше не работает (пул остановлен) — pump-таска сообщит
/// об этом роутеру.
// Тела по умолчанию `self` не используют — это нормально для
// политик-заглушек.
#[allow(clippy::unused_self)]
pub trait TransportPool: Send + Sync {
    /// Тип транспорта.
    fn kind(&self) -> TransportKind;

    /// Начинает соединение с роутером по его `RouterInfo`.
    ///
    /// `addr` — замена транспортного адреса (`None` — идти по
    /// опубликованному в `RouterInfo`); нужен для тестов на localhost.
    /// Возвращается сразу после отправки первого пакета: о готовности
    /// сообщит [`TransportEvent::Established`].
    fn connect<'a>(
        &'a self,
        remote_ri_bytes: &'a [u8],
        addr: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<IdentHash>>;

    /// Отправляет I2NP-сообщение собеседнику.
    fn send_to<'a>(
        &'a self,
        ident: &'a IdentHash,
        message: I2npMessage,
    ) -> BoxFuture<'a, Result<()>>;

    /// Завершает соединение. `false` — сессии не было.
    fn close<'a>(&'a self, ident: &'a IdentHash) -> BoxFuture<'a, Result<bool>>;

    /// Ждёт следующего события. Ровно один потребитель на транспорт.
    fn next_event(&self) -> BoxFuture<'_, Result<TransportEvent>>;

    /// Идентификаторы известных сессий (в том числе устанавливающихся).
    fn session_idents(&self) -> BoxFuture<'_, Vec<IdentHash>>;

    /// Периодическое обслуживание (уборка мёртвых сессий и т.п.).
    ///
    /// Роутер зовёт это на каждом тике; по умолчанию — ничего.
    fn maintenance(&self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::ready(()))
    }
}

// Явное `Ssu2Pool::…` — чтобы вызывались собственные методы пула, а не
// методы трейта с теми же именами (`connect`, `close`, `next_event`,
// `send_to`, `session_idents`): иначе `Self::connect` внутри
// `impl TransportPool for Ssu2Pool` рискует стать рекурсией.
#[allow(clippy::use_self)]
impl TransportPool for Ssu2Pool {
    fn kind(&self) -> TransportKind {
        TransportKind::Ssu2
    }

    fn connect<'a>(
        &'a self,
        remote_ri_bytes: &'a [u8],
        addr: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<IdentHash>> {
        Box::pin(async move {
            match addr {
                Some(addr) => Ssu2Pool::connect_to(self, remote_ri_bytes, addr).await,
                None => Ssu2Pool::connect(self, remote_ri_bytes).await,
            }
        })
    }

    fn send_to<'a>(
        &'a self,
        ident: &'a IdentHash,
        message: I2npMessage,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ssu2Pool::send_to(self, ident, message).await })
    }

    fn close<'a>(&'a self, ident: &'a IdentHash) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { Ssu2Pool::close(self, ident).await })
    }

    fn next_event(&self) -> BoxFuture<'_, Result<TransportEvent>> {
        Box::pin(async move {
            let event = Ssu2Pool::next_event(self).await?;
            Ok(match event {
                Ssu2Event::Established { ident } => TransportEvent::Established { ident },
                Ssu2Event::Message { from, message } => TransportEvent::Message { from, message },
                Ssu2Event::RouterInfo { from, ri_bytes } => {
                    TransportEvent::RouterInfo { from, ri_bytes }
                }
                Ssu2Event::Disconnected { ident } => TransportEvent::Disconnected { ident },
                Ssu2Event::ExternalAddress { addr, from } => {
                    TransportEvent::ExternalAddress { addr, from }
                }
            })
        })
    }

    fn session_idents(&self) -> BoxFuture<'_, Vec<IdentHash>> {
        Box::pin(async move { Ssu2Pool::session_idents(self).await.unwrap_or_default() })
    }
}

/// Адаптер [`Ntcp2Pool`] под трейт [`TransportPool`].
///
/// # Почему обёртка, а не `impl TransportPool for Ntcp2Pool`
///
/// Пул NTCP2 владеет и локальной идентичностью ([`Ntcp2Local`]), и
/// приёмом ([`Ntcp2Pool::listen`]) — это данные уровня роутера
/// (`RouterContext` в i2pd: `m_NTCP2Keys` и слушающий сокет). Адаптер
/// держит только пул и переводит [`PoolEvent`] в [`TransportEvent`],
/// добавляя то, чего у пула нет.
///
/// Свой `RouterInfo` в пуле надо обновлять после
/// [`RouterContext::rebuild_own_ri`] — для этого [`Self::set_router_info`];
/// i2pd шлёт свежий RI в `SessionConfirmed` и повторяет его раз в 25 минут
/// (`NTCP2Session::SendLocalRouterInfo`).
pub struct Ntcp2Transport {
    pool: Ntcp2Pool,
}

impl Ntcp2Transport {
    /// Создаёт адаптер с пустым пулом и **без** локального конфига.
    ///
    /// `connect` будет возвращать [`I2PError::Unsupported`]; приём и
    /// отправка по уже существующим сессиям работают.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pool: Ntcp2Pool::new(),
        }
    }

    /// Создаёт адаптер с локальным конфигом — исходящие соединения
    /// разрешены.
    #[must_use]
    pub fn with_local(local: Ntcp2Local) -> Self {
        let transport = Self::new();
        transport.pool.set_local(Arc::new(local));
        transport
    }

    /// Задаёт (или заменяет) локальный конфиг.
    pub fn set_local(&self, local: Ntcp2Local) {
        self.pool.set_local(Arc::new(local));
    }

    /// Обновляет свой `RouterInfo` в пуле.
    ///
    /// `false` — локального конфига нет (адаптер создан через
    /// [`Self::new`]); обновлять нечего.
    pub fn set_router_info(&self, ri_bytes: Vec<u8>) -> bool {
        let known = self.pool.local().is_some();
        if known {
            self.pool.set_router_info(ri_bytes);
        }
        known
    }

    /// Поднимает приём входящих NTCP2-соединений на `listener`.
    ///
    /// # Errors
    ///
    /// См. [`Ntcp2Pool::listen`]: нет локального конфига или приём уже
    /// поднят.
    pub fn listen(&self, listener: TcpListener) -> Result<()> {
        self.pool.listen(listener)
    }

    /// Доступ к пулу (например, для `connect_to` с явным адресом).
    #[must_use]
    pub const fn pool(&self) -> &Ntcp2Pool {
        &self.pool
    }
}

impl Default for Ntcp2Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportPool for Ntcp2Transport {
    fn kind(&self) -> TransportKind {
        TransportKind::Ntcp2
    }

    /// Исходящее соединение: `Ntcp2Pool::connect_to`, если адрес задан
    /// явно, иначе — адрес из `RouterInfo`.
    fn connect<'a>(
        &'a self,
        remote_ri_bytes: &'a [u8],
        addr: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<IdentHash>> {
        Box::pin(async move {
            match addr {
                Some(addr) => Ntcp2Pool::connect_to(&self.pool, remote_ri_bytes, addr).await,
                None => Ntcp2Pool::connect(&self.pool, remote_ri_bytes).await,
            }
        })
    }

    fn send_to<'a>(
        &'a self,
        ident: &'a IdentHash,
        message: I2npMessage,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ntcp2Pool::send_to(&self.pool, ident, message).await })
    }

    fn close<'a>(&'a self, ident: &'a IdentHash) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { Ok(Ntcp2Pool::remove_session(&self.pool, ident).await) })
    }

    fn next_event(&self) -> BoxFuture<'_, Result<TransportEvent>> {
        Box::pin(async move {
            let event = Ntcp2Pool::next_event(&self.pool).await?;
            Ok(match event {
                PoolEvent::Established { ident } => TransportEvent::Established { ident },
                PoolEvent::Message { from, message } => TransportEvent::Message { from, message },
                PoolEvent::RouterInfo { from, ri_bytes } => {
                    TransportEvent::RouterInfo { from, ri_bytes }
                }
                PoolEvent::Disconnected { ident } => TransportEvent::Disconnected { ident },
            })
        })
    }

    fn session_idents(&self) -> BoxFuture<'_, Vec<IdentHash>> {
        Box::pin(async move { Ntcp2Pool::session_idents(&self.pool).await })
    }

    fn maintenance(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move { Ntcp2Pool::cleanup_dead(&self.pool).await })
    }
}

// --- часы ----------------------------------------------------------------

/// Источник времени.
///
/// Отдельный трейт, потому что тесты должны управлять временем
/// (публикация `RouterInfo`, таймауты запросов).
pub trait Clock: Send + Sync {
    /// Миллисекунды с epoch.
    fn now_ms(&self) -> u64;

    /// Секунды с epoch.
    #[must_use]
    fn now_secs(&self) -> u64 {
        self.now_ms() / 1000
    }
}

/// Системные часы.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

// --- политика ------------------------------------------------------------

/// Решения роутера, которые зависят от конфигурации и от сети.
///
/// Всё, что «по-разному» — интервалы, кому публиковать свой `RouterInfo`,
/// отвечать ли на `DatabaseLookup` — собрано здесь, чтобы [`Router`]
/// оставался механикой. Значения по умолчанию повторяют i2pd
/// (реализация [`I2pdRouterPolicy`] их не меняет).
#[allow(clippy::unused_self)]
pub trait RouterPolicy: Send + Sync {
    /// Период тика роутера (запросы netDb, публикация RI, обслуживание).
    fn tick_interval(&self) -> Duration {
        Duration::from_millis(TICK_INTERVAL_MS)
    }

    /// Первая публикация своего `RouterInfo` после старта.
    fn initial_ri_publish_interval(&self) -> Duration {
        Duration::from_secs(INITIAL_RI_PUBLISH_INTERVAL_SECS)
    }

    /// Периодичность публикации своего `RouterInfo`.
    fn ri_publish_interval(&self) -> Duration {
        Duration::from_secs(RI_PUBLISH_INTERVAL_SECS)
    }

    /// Каким транспортом идти к роутеру с таким `RouterInfo`.
    ///
    /// По умолчанию: SSU2, если он есть в `RouterInfo`, иначе NTCP2
    /// (как i2pd в `Transports::SendMessage`, где SSU2 в приоритете).
    fn dial_transport(&self, remote_ri: &FullRouterInfo) -> TransportKind {
        let addresses = &remote_ri.body().addresses;
        if addresses.iter().any(I2PAddress::is_ssu2) {
            TransportKind::Ssu2
        } else {
            TransportKind::Ntcp2
        }
    }

    /// Отвечаем ли на входящий `DatabaseLookup`.
    ///
    /// i2pd: на запрос отвечает флудфилл (`i2p::context.IsFloodfill ()`).
    /// Флаг живёт в конфигурации ([`RouterConfig::is_floodfill`]), а не
    /// в caps своего RI: в caps `f` попадает только при сборке RI.
    fn answer_database_lookup(&self, ctx: &RouterContext) -> bool {
        ctx.config().is_floodfill()
    }

    /// Кому публиковать свой `RouterInfo`.
    ///
    /// По умолчанию — ближайшие к нам флудфиллы; пустой результат
    /// означает «публиковать некому» (роутер попробует на следующем
    /// тике).
    fn ri_publish_targets(&self, ctx: &RouterContext, limit: usize) -> Vec<IdentHash> {
        ctx.netdb()
            .closest_floodfills(ctx.own_ident_hash(), limit)
            .into_iter()
            .map(|ri| *ri.ident_hash())
            .collect()
    }

    /// Просить ли `RouterInfo` у роутеров из `DatabaseSearchReply`.
    fn request_from_search_reply(&self) -> bool {
        true
    }
}

/// Политика по умолчанию — значения i2pd.
#[derive(Debug, Clone, Copy, Default)]
pub struct I2pdRouterPolicy;

impl RouterPolicy for I2pdRouterPolicy {}

// --- наблюдатель ---------------------------------------------------------

/// Наблюдения наружу: логи в своём формате, UI, тесты.
///
/// Методы вызываются после обработки события; состояние роутера в этот
/// момент уже обновлено. Все методы по умолчанию ничего не делают: то,
/// что нужно для отладки, уже пишется через `tracing`.
///
/// `Sync` — потому что [`Router`] держит наблюдателя и обязан сам быть
/// `Sync` (иначе futures роутера не `Send`, и его нельзя запускать в
/// `tokio::spawn`).
#[allow(clippy::unused_self)]
pub trait RouterObserver: Send + Sync {
    /// Любое событие транспорта.
    fn on_transport_event(&mut self, kind: TransportKind, event: &TransportEvent);

    /// Результат входящего `RouterInfo` (`DatabaseStore` или событие
    /// транспорта).
    fn on_store(&mut self, handling: &StoreHandling);

    /// Сообщение, которое роутер не обработал (нет слоя туннелей и т.п.).
    fn on_unhandled_message(&mut self, from: &IdentHash, message: &I2npMessage);
}

/// Наблюдатель-заглушка.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopObserver;

impl RouterObserver for NoopObserver {
    fn on_transport_event(&mut self, _kind: TransportKind, _event: &TransportEvent) {}

    fn on_store(&mut self, _handling: &StoreHandling) {}

    fn on_unhandled_message(&mut self, _from: &IdentHash, _message: &I2npMessage) {}
}

// --- внутренний канал ----------------------------------------------------

/// Событие в общий канал «транспорты → роутер».
#[derive(Debug)]
enum RouterEvent {
    /// Событие транспорта.
    Transport {
        /// От какого транспорта.
        kind: TransportKind,
        /// Что случилось.
        event: TransportEvent,
    },
    /// Транспорт больше не отдаёт события.
    Closed {
        /// Какой транспорт.
        kind: TransportKind,
        /// Причина (текст ошибки).
        reason: String,
    },
}

/// Перекачивает события транспорта в общий канал роутера.
///
/// Пока задача жива, у транспорта ровно один потребитель `next_event` —
/// так же, как в i2pd события сессий попадают в общий `m_Service`.
async fn pump(transport: Arc<dyn TransportPool>, tx: mpsc::Sender<RouterEvent>) {
    let kind = transport.kind();
    loop {
        match transport.next_event().await {
            Ok(event) => {
                if tx
                    .send(RouterEvent::Transport { kind, event })
                    .await
                    .is_err()
                {
                    return; // роутер закрылся
                }
            }
            Err(error) => {
                warn!(transport = %kind, %error, "router: транспорт перестал отдавать события");
                let _ = tx
                    .send(RouterEvent::Closed {
                        kind,
                        reason: error.to_string(),
                    })
                    .await;
                return;
            }
        }
    }
}

// --- роутер --------------------------------------------------------------

/// Объединённый роутер.
///
/// Собирается из [`RouterContext`] и транспортов:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use uu_i2p::{Router, RouterContext, Ssu2Local, Ssu2Pool};
/// # async fn demo(local: Ssu2Local, context: RouterContext) -> uu_i2p::Result<()> {
/// let pool = Arc::new(Ssu2Pool::bind("0.0.0.0:0".parse().unwrap(), local).await?);
/// let mut router = Router::new(context);
/// router.attach(pool)?;
/// router.run_until(async {
///     let _ = tokio::signal::ctrl_c().await;
/// }).await
/// # }
/// ```
pub struct Router {
    context: RouterContext,
    clock: Box<dyn Clock>,
    policy: Box<dyn RouterPolicy>,
    observer: Box<dyn RouterObserver>,
    /// Подключённые транспорты, в порядке [`Router::attach`].
    transports: Vec<Arc<dyn TransportPool>>,
    /// Через какой транспорт говорить с пиром: сессия установленная или
    /// устанавливающаяся. Заполняется на `dial`/`Established`,
    /// очищается на `Disconnected`/обрыве транспорта.
    sessions: HashMap<IdentHash, TransportKind>,
    /// Канал событий от pump-тасок (берётся на время `run_until`).
    events_tx: mpsc::Sender<RouterEvent>,
    events_rx: Option<mpsc::Receiver<RouterEvent>>,
    /// Задачи-насосы; прерываются при drop роутера.
    pumps: Vec<JoinHandle<()>>,
    /// Завершившихся транспортов (для выхода из `run_until`).
    closed: usize,
    /// Время последней публикации своего `RouterInfo`.
    last_ri_publish_ms: u64,
    /// Публиковали ли уже хоть раз (выбор интервала).
    published_ri: bool,
}

impl Router {
    /// Создаёт роутер: системные часы, политика i2pd, без наблюдателя.
    #[must_use]
    pub fn new(context: RouterContext) -> Self {
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let clock: Box<dyn Clock> = Box::new(SystemClock);
        let last_ri_publish_ms = clock.now_ms();
        Self {
            context,
            clock,
            policy: Box::new(I2pdRouterPolicy),
            observer: Box::new(NoopObserver),
            transports: Vec::new(),
            sessions: HashMap::new(),
            events_tx,
            events_rx: Some(events_rx),
            pumps: Vec::new(),
            closed: 0,
            last_ri_publish_ms,
            published_ri: false,
        }
    }

    /// Заменяет часы (для тестов).
    #[must_use]
    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.last_ri_publish_ms = clock.now_ms();
        self.clock = clock;
        self
    }

    /// Заменяет политику.
    #[must_use]
    pub fn with_policy(mut self, policy: Box<dyn RouterPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// Заменяет наблюдателя.
    #[must_use]
    pub fn with_observer(mut self, observer: Box<dyn RouterObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Состояние роутера.
    #[must_use]
    pub const fn context(&self) -> &RouterContext {
        &self.context
    }

    /// Состояние роутера (изменяемое).
    pub const fn context_mut(&mut self) -> &mut RouterContext {
        &mut self.context
    }

    /// Подключает транспорт и запускает pump-таску.
    ///
    /// Требует tokio-runtime (внутри `tokio::spawn`).
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`] — транспорт такого типа уже подключён
    /// (в i2pd на каждый транспорт ровно один пул).
    pub fn attach(&mut self, transport: Arc<dyn TransportPool>) -> Result<()> {
        let kind = transport.kind();
        if self.transport(kind).is_some() {
            return Err(I2PError::Malformed(
                "router: транспорт такого типа уже подключён",
            ));
        }
        let events_tx = self.events_tx.clone();
        self.pumps
            .push(tokio::spawn(pump(transport.clone(), events_tx)));
        self.transports.push(transport);
        info!(transport = %kind, "router: транспорт подключён");
        Ok(())
    }

    /// Транспорт такого типа, если подключён.
    #[must_use]
    pub fn transport(&self, kind: TransportKind) -> Option<&Arc<dyn TransportPool>> {
        self.transports.iter().find(|t| t.kind() == kind)
    }

    /// Через какой транспорт роутер говорит с `ident`.
    #[must_use]
    pub fn session_transport(&self, ident: &IdentHash) -> Option<TransportKind> {
        self.sessions.get(ident).copied()
    }

    /// Начинает соединение с роутером.
    ///
    /// Транспорт выбирает [`RouterPolicy::dial_transport`], если `kind`
    /// не задан явно. Установленная (или устанавливающаяся) сессия
    /// запоминается, чтобы [`Router::send`] знал, куда идти.
    ///
    /// # Errors
    ///
    /// - ошибки разбора `RouterInfo`;
    /// - [`I2PError::Malformed`] — нужный транспорт не подключён;
    /// - ошибки транспорта.
    pub async fn dial(
        &mut self,
        remote_ri_bytes: &[u8],
        addr: Option<SocketAddr>,
        kind: Option<TransportKind>,
    ) -> Result<IdentHash> {
        let remote_ri = FullRouterInfo::from_buffer(remote_ri_bytes)?;
        let kind = kind.unwrap_or_else(|| self.policy.dial_transport(&remote_ri));
        let transport = Arc::clone(
            self.transport(kind)
                .ok_or(I2PError::Malformed("router: транспорт не подключён"))?,
        );
        let ident = transport.connect(remote_ri_bytes, addr).await?;
        debug!(transport = %kind, peer = %ident.to_base64(), "router: соединение начато");
        self.sessions.insert(ident, kind);
        Ok(ident)
    }

    /// Отправляет I2NP-сообщение, выбирая транспорт по известной сессии.
    ///
    /// Если сессия неизвестна (например, пир сам к нам подключился, а
    /// события `Established` ещё не было) — пробует транспорты по
    /// очереди подключения.
    ///
    /// # Errors
    ///
    /// Ошибка последнего транспорта, если ни один не смог отправить.
    pub async fn send(&self, to: &IdentHash, message: I2npMessage) -> Result<()> {
        if let Some(kind) = self.session_transport(to) {
            return self.send_via(kind, to, message).await;
        }
        if self.transports.is_empty() {
            return Err(I2PError::Malformed("router: нет подключённых транспортов"));
        }
        let mut last_error = None;
        for transport in &self.transports {
            match transport.send_to(to, message.clone()).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    debug!(transport = %transport.kind(), peer = %to.to_base64(), %error, "router: отправка не удалась");
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or(I2PError::Malformed("router: нет транспортов")))
    }

    /// Отправляет I2NP-сообщение конкретным транспортом.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`] — транспорт не подключён; иначе ошибки
    /// транспорта.
    pub async fn send_via(
        &self,
        kind: TransportKind,
        to: &IdentHash,
        message: I2npMessage,
    ) -> Result<()> {
        let transport = Arc::clone(
            self.transport(kind)
                .ok_or(I2PError::Malformed("router: транспорт не подключён"))?,
        );
        transport.send_to(to, message).await
    }

    /// Завершает сессию с собеседником (i2pd `Transports::CloseSession`).
    ///
    /// Закрытие — не «удалить из карты»: транспорт сам скажет
    /// [`TransportEvent::Disconnected`], и только по нему роутер убирает
    /// собеседника (i2pd `Transports::PeerDisconnected`). Так карта
    /// всегда отражает то, что видит транспорт.
    ///
    /// # Errors
    ///
    /// Ошибки транспорта.
    pub async fn close(&self, ident: &IdentHash) -> Result<bool> {
        let Some(kind) = self.session_transport(ident) else {
            return Ok(false);
        };
        let Some(transport) = self.transport(kind) else {
            return Ok(false);
        };
        let closed = transport.close(ident).await?;
        if closed {
            debug!(transport = %kind, peer = %ident.to_base64(), "router: сессия закрыта");
        }
        Ok(closed)
    }

    /// Крутит цикл событий до `shutdown`.
    ///
    /// Тик задаёт [`RouterPolicy::tick_interval`]; он же ведёт
    /// [`Router::tick`]. Цикл завершается, когда попросили `shutdown`
    /// или когда все транспорты перестали отдавать события.
    ///
    /// # Errors
    ///
    /// Только инфраструктурные: цикл уже запущен, канал событий закрыт.
    /// Ошибки обработки **отдельных** сообщений роняют не роутер, а
    /// само сообщение: логируем и живём дальше (в i2pd исключение в
    /// `HandleI2NPMessage` тоже не валит процесс). Иначе одно кривое
    /// garlic-сообщение убивает сессию со всем netDb.
    pub async fn run_until<F>(&mut self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let mut events = self
            .events_rx
            .take()
            .ok_or(I2PError::Malformed("router: цикл уже запущен"))?;
        let mut timer = tokio::time::interval(self.policy.tick_interval());
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        timer.tick().await; // первый тик — сразу, пропускаем

        tokio::pin!(shutdown);
        let result = loop {
            tokio::select! {
                () = &mut shutdown => {
                    info!("router: остановка по запросу");
                    break Ok(());
                }
                _ = timer.tick() => {
                    if let Err(error) = self.tick().await {
                        warn!(%error, "router: ошибка тика");
                    }
                }
                event = events.recv() => {
                    let Some(event) = event else {
                        info!("router: канал событий закрыт");
                        break Ok(());
                    };
                    if let Err(error) = self.handle_router_event(event).await {
                        warn!(%error, "router: ошибка обработки события");
                    }
                    if self.all_transports_closed() {
                        info!("router: все транспорты остановлены");
                        break Ok(());
                    }
                }
            }
        };
        self.events_rx = Some(events);
        result
    }

    /// Все подключённые транспорты завершились?
    #[must_use]
    pub fn all_transports_closed(&self) -> bool {
        !self.transports.is_empty() && self.closed >= self.transports.len()
    }

    /// Обрабатывает один тик таймеров.
    ///
    /// Ошибки отдельных действий логируются, но не роняют роутер:
    /// недоставленный `DatabaseLookup` — не повод останавливаться
    /// (в i2pd то же самое).
    ///
    /// # Errors
    ///
    /// Сейчас не возвращает ошибок; сигнатура на будущее (появятся
    /// действия, которые должны подниматься наверх).
    pub async fn tick(&mut self) -> Result<()> {
        let now_ms = self.clock.now_ms();

        for action in self.context.tick_netdb_requests(now_ms) {
            let to = action.to;
            if let Err(error) = self.send(&action.to, action.message).await {
                warn!(peer = %to.to_base64(), %error, "router: DatabaseLookup не отправлен");
            }
        }

        if let Err(error) = self.publish_own_ri_if_due(now_ms).await {
            warn!(%error, "router: публикация своего RouterInfo не удалась");
        }

        for transport in &self.transports {
            transport.maintenance().await;
        }
        Ok(())
    }

    /// Публикует свой `RouterInfo`, если пришло время.
    ///
    /// Первый интервал — [`RouterPolicy::initial_ri_publish_interval`]
    /// (i2pd `ScheduleInitialPublish`), дальше —
    /// [`RouterPolicy::ri_publish_interval`].
    ///
    /// # Errors
    ///
    /// Ошибки сборки `DatabaseStore`.
    pub async fn publish_own_ri_if_due(&mut self, now_ms: u64) -> Result<usize> {
        let interval = if self.published_ri {
            self.policy.ri_publish_interval()
        } else {
            self.policy.initial_ri_publish_interval()
        };
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        if now_ms < self.last_ri_publish_ms.saturating_add(interval_ms) {
            return Ok(0);
        }
        let sent = self.publish_own_ri().await?;
        if sent > 0 {
            self.last_ri_publish_ms = now_ms;
            self.published_ri = true;
        }
        Ok(sent)
    }

    /// Публикует свой `RouterInfo` флудфиллам из политики.
    ///
    /// Возвращает число флудфиллов, которым отправка удалась.
    ///
    /// # Errors
    ///
    /// Ошибки сборки `DatabaseStore` (RI не сериализуется).
    pub async fn publish_own_ri(&self) -> Result<usize> {
        let targets = self
            .policy
            .ri_publish_targets(&self.context, RI_PUBLISH_TARGETS);
        if targets.is_empty() {
            debug!("router: флудфиллов нет — свой RouterInfo не публикуем");
            return Ok(0);
        }
        let store = self.context.build_own_database_store()?;
        let message = I2npMessage::from_body(I2npBody::DatabaseStore(store))?;
        let mut sent = 0;
        for target in &targets {
            match self.send(target, message.clone()).await {
                Ok(()) => {
                    sent += 1;
                    debug!(peer = %target.to_base64(), "router: свой RouterInfo опубликован");
                }
                Err(error) => {
                    warn!(peer = %target.to_base64(), %error, "router: свой RouterInfo не опубликован");
                }
            }
        }
        Ok(sent)
    }

    /// Обрабатывает событие одного транспорта.
    ///
    /// # Errors
    ///
    /// Ошибки обработки вложенного сообщения (см.
    /// [`Router::handle_message`]).
    pub async fn handle_event(&mut self, kind: TransportKind, event: TransportEvent) -> Result<()> {
        trace!(transport = %kind, ?event, "router: событие транспорта");
        self.observer.on_transport_event(kind, &event);
        match event {
            TransportEvent::Established { ident } => {
                self.sessions.insert(ident, kind);
                info!(transport = %kind, peer = %ident.to_base64(), "router: соединение установлено");
            }
            TransportEvent::Disconnected { ident } => {
                self.sessions.remove(&ident);
                info!(transport = %kind, peer = %ident.to_base64(), "router: соединение закрыто");
            }
            TransportEvent::RouterInfo { from, ri_bytes } => {
                self.store_router_info(kind, &from, &ri_bytes)?;
            }
            TransportEvent::Message { from, message } => {
                self.handle_message(kind, &from, message).await?;
            }
            TransportEvent::ExternalAddress { addr, from } => {
                let peer = from.map_or_else(|| "-".to_owned(), |i| i.to_base64());
                debug!(transport = %kind, %addr, peer = %peer, "router: наш внешний адрес по мнению собеседника");
            }
        }
        Ok(())
    }

    /// Кладёт `RouterInfo` из события транспорта в netDb.
    ///
    /// Заворачивает байты в `DatabaseStore` и отдаёт
    /// [`RouterContext::handle_database_store`] — так у обоих путей
    /// (блок `RouterInfo` и сообщение `DatabaseStore`) одна проверка:
    /// ключ сообщения обязан совпадать с identity разобранного RI,
    /// поэтому «чужой» RI от имени `from` не пройдёт.
    ///
    /// # Errors
    ///
    /// См. [`RouterContext::handle_database_store`].
    fn store_router_info(
        &mut self,
        kind: TransportKind,
        from: &IdentHash,
        ri_bytes: &[u8],
    ) -> Result<()> {
        let store = DatabaseStore::new_router_info(*from, ri_bytes, 0, None)?;
        let handling = self.context.handle_database_store(&store.to_buffer()?)?;
        self.report_store(kind, &handling);
        Ok(())
    }

    /// Логирует и отдаёт наблюдателю результат `DatabaseStore`.
    ///
    /// Общий хвост обоих путей попадания RI в netDb (событие транспорта
    /// и сообщение `DatabaseStore`), чтобы логи не разъезжались.
    fn report_store(&mut self, kind: TransportKind, handling: &StoreHandling) {
        match handling {
            StoreHandling::Inserted(ident) => {
                info!(transport = %kind, peer = %ident.to_base64(), "router: RouterInfo добавлен в netDb");
            }
            StoreHandling::Updated(ident) => {
                debug!(transport = %kind, peer = %ident.to_base64(), "router: RouterInfo обновлён");
            }
            StoreHandling::Stale(ident) => {
                trace!(transport = %kind, peer = %ident.to_base64(), "router: RouterInfo устарел");
            }
            StoreHandling::NotRouterInfo(store_type) => {
                // `// TODO(step-3c): LeaseSet'ы в netDb роутера —
                // сейчас они уезжают наблюдателю и теряются.`
                debug!(transport = %kind, ?store_type, "router: DatabaseStore не RouterInfo");
            }
        }
        self.observer.on_store(handling);
    }

    /// Разбирает входящее I2NP-сообщение.
    ///
    /// Таблица — как i2pd `HandleI2NPMessage` (`I2NPProtocol.cpp:452`)
    /// плюс `RouterContext::PostGarlicMessage`:
    ///
    /// | Тип | Что делаем |
    /// |-----|------------|
    /// | `DatabaseStore` | RI → netDb; `LeaseSet` → наблюдателю (шаг 3c) |
    /// | `DatabaseLookup` | флудфилл → отвечаем из netDb, иначе TODO: переслать |
    /// | `DatabaseSearchReply` | записываем `excluded`, спрашиваем RI у новых |
    /// | `Garlic` | [`RouterContext::handle_garlic`] + ответ (NSR) тому же пиру |
    /// | `DeliveryStatus` | TODO: подтверждение публикации своего RI |
    /// | `TunnelData`/`TunnelGateway`/`Data`/`TunnelBuild*` | TODO: шаг 3b |
    ///
    /// # Errors
    ///
    /// Ошибки разбора и обработки; необрабатываемые типы — не ошибка.
    pub async fn handle_message(
        &mut self,
        kind: TransportKind,
        from: &IdentHash,
        message: I2npMessage,
    ) -> Result<()> {
        let msg_type = message.message_type();
        debug!(transport = %kind, peer = %from.to_base64(), msg_type = msg_type.name(), len = message.payload().len(), "router: принято I2NP");
        match msg_type {
            I2npMessageType::DatabaseStore => self.handle_database_store(kind, &message)?,
            I2npMessageType::DatabaseLookup => {
                self.handle_database_lookup(kind, from, &message).await?;
            }
            I2npMessageType::DatabaseSearchReply => {
                self.handle_database_search_reply(from, &message)?;
            }
            I2npMessageType::Garlic => self.handle_garlic(kind, from, &message).await?,
            // `// TODO(step-3a-6): DeliveryStatus — подтверждение
            // публикации: сверять msgID с токеном публикации и
            // перепланировать публикацию (i2pd
            // `RouterContext::PostDeliveryStatusMessage`).`
            I2npMessageType::DeliveryStatus => {
                debug!(peer = %from.to_base64(), "router: DeliveryStatus (обработка публикации — TODO)");
            }
            // `// TODO(step-3b): TunnelData/TunnelGateway/Data/
            // TunnelBuild*/TunnelTest — туннели и destination-трафик.`
            I2npMessageType::TunnelData
            | I2npMessageType::TunnelGateway
            | I2npMessageType::Data
            | I2npMessageType::TunnelBuild
            | I2npMessageType::TunnelBuildReply
            | I2npMessageType::VariableTunnelBuild
            | I2npMessageType::VariableTunnelBuildReply
            | I2npMessageType::ShortTunnelBuild
            | I2npMessageType::ShortTunnelBuildReply
            | I2npMessageType::TunnelTest => {
                debug!(peer = %from.to_base64(), msg_type = msg_type.name(), "router: туннельный тип (не реализовано)");
                self.observer.on_unhandled_message(from, &message);
            }
        }
        Ok(())
    }

    /// `DatabaseStore`: RI — в netDb, `LeaseSet` — наблюдателю.
    fn handle_database_store(&mut self, kind: TransportKind, message: &I2npMessage) -> Result<()> {
        let handling = self.context.handle_database_store(message.payload())?;
        self.report_store(kind, &handling);
        Ok(())
    }

    /// `DatabaseLookup`: отвечаем из netDb, если мы флудфилл.
    async fn handle_database_lookup(
        &self,
        kind: TransportKind,
        from: &IdentHash,
        message: &I2npMessage,
    ) -> Result<()> {
        if !self.policy.answer_database_lookup(&self.context) {
            // `// TODO(step-3b): не флудфилл пересылает lookup
            // флудфиллу через туннель (`NetDb::HandleDatabaseLookupMsg`).`
            debug!(peer = %from.to_base64(), "router: DatabaseLookup нам, но мы не флудфилл");
            return Ok(());
        }
        let lookup = self.context.handle_database_lookup(message.payload())?;
        debug!(
            peer = %from.to_base64(),
            key = %lookup.key.to_base32(),
            lookup_type = ?lookup.lookup_type,
            "router: DatabaseLookup"
        );
        let reply = self.context.build_lookup_reply(&lookup)?;
        self.send_via(kind, from, reply).await?;
        Ok(())
    }

    /// `DatabaseSearchReply`: исключаем названных и спрашиваем новых.
    fn handle_database_search_reply(
        &mut self,
        from: &IdentHash,
        message: &I2npMessage,
    ) -> Result<()> {
        let reply = self
            .context
            .handle_database_search_reply(message.payload())?;
        debug!(
            peer = %from.to_base64(),
            key = %reply.key.to_base32(),
            peers = reply.peer_hashes.len(),
            "router: DatabaseSearchReply"
        );
        // Помечаем названных как «уже спрошенных»: иначе следующий
        // запрос по этому ключу пойдёт тем же пирам (i2pd
        // `NetDbRequests::HandleSearchReply`). Второй разбор того же
        // payload — цена простого API.
        self.context
            .process_database_search_reply(message.payload())?;
        if !self.policy.request_from_search_reply() {
            return Ok(());
        }
        // Спрашиваем RI у тех, кто нам назван и кого у нас ещё нет
        // (i2pd `NetDbRequests::RequestRouter`).
        let now_ms = self.clock.now_ms();
        let our_hash = *self.context.own_ident_hash();
        let mut asked = 0;
        for hash in &reply.peer_hashes {
            let hash = *hash;
            if hash == our_hash || !self.needs_router_info(&hash, now_ms) {
                continue;
            }
            if self.context.request_router(hash, now_ms) {
                asked += 1;
            }
        }
        debug!(
            peer = %from.to_base64(),
            peers = reply.peer_hashes.len(),
            asked,
            "router: DatabaseSearchReply обработан"
        );
        Ok(())
    }

    /// Нужен ли нам `RouterInfo` этого роутера.
    ///
    /// Как i2pd `NetDbRequests::RequestRouter`: RI нет, или он старше
    /// часа. Забаненных у нас пока нет.
    fn needs_router_info(&self, ident: &IdentHash, now_ms: u64) -> bool {
        /// RI старше этого возраста считаем устаревшим (i2pd: 1 час).
        const MAX_RI_AGE_MS: u64 = 3600 * 1000;
        self.context
            .find_router(ident)
            .is_none_or(|ri| ri.body().timestamp.saturating_add(MAX_RI_AGE_MS) < now_ms)
    }

    /// `Garlic`: garlic самой разной природы — разбираем оба случая.
    ///
    /// У i2pd роутеру garlic приходит двумя путями (см.
    /// [`RouterContext::handle_router_garlic`]):
    ///
    /// 1. **destination-сессия** — тег/NS. Обрабатывается в
    ///    [`RouterContext::handle_garlic`], cloves разбираются там же;
    ///    если сессия требует ответа (NSR на NS) — отправляем его.
    /// 2. **роутерный `Noise_N`** — одноразовый, без состояния. Даёт
    ///    внутренние I2NP-сообщения, которые прогоняются через **этот
    ///    же** диспетчер (`Self::handle_message`), как в i2pd
    ///    `HandleCloveI2NPMessage` → `HandleI2NPMessage`: только так
    ///    ответ на `DatabaseLookup` (флудфилл) уходит по транспорту.
    async fn handle_garlic(
        &mut self,
        kind: TransportKind,
        from: &IdentHash,
        message: &I2npMessage,
    ) -> Result<()> {
        match self.context.handle_garlic(message.payload()) {
            Ok(Some(GarlicReply { message: reply })) => {
                debug!(transport = %kind, peer = %from.to_base64(), len = reply.total_len(), "router: ответ garlic");
                self.send_via(kind, from, reply).await?;
            }
            Ok(None) => {}
            // Не наша destination-сессия — это не ошибка, а повод
            // попробовать роутерный garlic ниже (i2pd
            // `PostGarlicMessage`: теги, затем `Noise_N`).
            Err(error) => {
                trace!(error = %error, peer = %from.to_base64(), "router: garlic не для destination-сессии");
            }
        }

        let inner = self.context.handle_router_garlic(message.payload())?;
        for nested in inner {
            // Рекурсия обязана быть косвенной (`Box::pin`): вложенный
            // garlic — легальный случай, а `async fn` сам себя по
            // значению не соберёт.
            Box::pin(self.handle_message(kind, from, nested)).await?;
        }
        Ok(())
    }

    /// Обрабатывает внутреннее событие канала.
    async fn handle_router_event(&mut self, event: RouterEvent) -> Result<()> {
        match event {
            RouterEvent::Transport { kind, event } => self.handle_event(kind, event).await,
            RouterEvent::Closed { kind, reason } => {
                warn!(transport = %kind, reason = %reason, "router: транспорт остановлен");
                self.sessions.retain(|_, k| *k != kind);
                self.closed += 1;
                Ok(())
            }
        }
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        for pump in &self.pumps {
            pump.abort();
        }
    }
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("own_ident_hash", self.context.own_ident_hash())
            .field("netdb_size", &self.context.netdb().len())
            .field("transports", &self.transports.len())
            .field("sessions", &self.sessions.len())
            .finish_non_exhaustive()
    }
}
