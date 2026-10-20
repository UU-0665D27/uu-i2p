//! Пул SSU2-соединений поверх одного UDP-сокета.
//!
//! Один `UdpSocket` — сколько угодно соединений: входящий пакет ищется в
//! таблице по `destConnID` (первые 8 байт, XOR-маска из последних 12 —
//! [`peek_dest_conn_id`]), дальше [`Ssu2Connection`] сам решает по роли и
//! состоянию, что с ним делать. Это зеркалит `SSU2Server::ProcessNextPacket`
//! (`SSU2.cpp:690`) и `m_Sessions` (ключ — **свой** `sourceConnID`,
//! `SSU2Session::GetConnID`, `SSU2Session.h:287`).
//!
//! ## Разделение обязанностей
//!
//! - [`Ssu2Pool`] — сокет, таблицы соединений, токены, таймеры (повторы,
//!   connect-таймаут, idle). **Не** знает про netDb и I2NP-диспетчеризацию:
//!   принятый `RouterInfo` отдаёт событием [`Ssu2Event::RouterInfo`].
//! - [`crate::ssu2_conn`] / [`crate::ssu2_engine`] — байты, состояния, решения.
//! - Вызывающий (в i2pd — `Transports`/`RouterContext`) проверяет `RouterInfo`
//!   и кладёт его в netDb.
//!
//! ## Модель
//!
//! Задача-владелец сокета синхронна внутри ([`PoolState`]), вся
//! асинхронность — в [`run`]: `select!` по сокету, каналу команд и тику
//! (40 мс, `SSU2_RESEND_INTERVAL`). Каждый обработчик складывает готовые
//! пакеты в `OutQueue`, и они уходят в сокет после обработки события — так
//! решения и I/O не смешиваются.
//!
//! Событийный канал — `try_send`: переполнение не блокирует пул, а теряет
//! событие с `warn` (в i2pd ту же роль играет
//! `SSU2_STOP_ACCEPTING_NEW_SESSIONS_QUEUE_SIZE`).
//!
//! ## Что НЕ реализовано
//!
//! - **Relay / Hole Punch / Peer Test** (`Introduce`, `WaitForIntroduction`,
//!   `PeerTest`): блоки отдаются наружу через
//!   [`crate::ssu2_engine::PendingBlock`], сессии этих типов не создаются.
//! - **Проверки `RouterInfo`** целиком (подпись, версия, `isOlder`, профиль):
//!   здесь — только то, без чего не работает data phase (наличие
//!   SSU2-адреса нужного семейства, совпадение `s=` со статическим ключом из
//!   `SessionConfirmed`, совпадение опубликованного `host` с источником).
//! - **Размер очереди приёма** (`m_ReceivedPacketsQueue` /
//!   `SSU2_STOP_ACCEPTING_NEW_SESSIONS_QUEUE_SIZE`): поток приёма у нас
//!   один и не буферизует «на потом», ограничивать нечего.
//! - **Фильтр reserved-адресов на приёме** (`transports.IsInReservedRange`,
//!   `SSU2.cpp:766`) — опция `reservedrange`; см. замечание у
//!   [`PoolState::maybe_send_path_challenge`].
//!
//! Бан-лист адресов — [`crate::transport_ban::BanList`]: проверяется до
//! создания сессии (`SSU2.cpp:767`), а адрес попадает в него, когда
//! собеседник подсунул чужой `s` при опубликованном адресе
//! (`SSU2Session.cpp:1428`). Список задаётся
//! [`Ssu2Pool::with_socket_and_ban`] — им же пользуется NTCP2.
//! - **Полный обмен `Closing`/`ClosingConfirmed`**: [`Ssu2Pool::close`] шлёт
//!   `Termination` и сразу сообщает наружу `Disconnected` (сессия исчезает из
//!   карт и из `session_idents`), но сам `conn_id` ещё
//!   `SSU2_TERMINATION_CHECK_TIMEOUT` подтверждает чужие пакеты и молча
//!   игнорирует их содержимое (`Session::drain_until`): у i2pd сессия живёт
//!   столько же, но он ещё и держит пира в `m_SessionsByRouterHash`.
//!
//! Смена пути собеседника (`Path Challenge`/`Path Response`, i2pd
//! `ProcessData`, `SSU2Session.cpp:1752`) — реализована; из уборки i2pd
//! (`SSU2Session::CleanUp`) взят только пункт про неподтверждённый челлендж.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::IdentHash;
use crate::config::{RouterConfig, Transport};
use crate::crypto::I2PX25519Keys;
use crate::error::{I2PError, Result};
use crate::i2np_message::I2npMessage;
use crate::netdb::{
    NETDB_EXPIRATION_TIMEOUT_THRESHOLD, NETDB_MIN_ALLOWED_VERSION, NETDB_MIN_EXPIRATION_TIMEOUT,
};
use crate::router_info::FullRouterInfo;
use crate::router_info_address::I2PAddress;
use crate::ssu2_block::{
    AddressBlock, NewTokenBlock, PeerTestBlock, RouterInfoBlock, Ssu2Block, Ssu2PeerTestCode,
    Ssu2TerminationReason,
};
use crate::ssu2_conn::{
    ConnContext, ConnParams, ConnReport, HandshakeRole, ResponderEnv, Ssu2Connection,
    peek_dest_conn_id, peek_long_header_ids, peek_message_type_with,
};
use crate::ssu2_engine::{PendingBlock, RecvReport, SendContext, TerminationAction};
use crate::ssu2_handshake::{HandshakeConfig, InitiatorHandshake, ResponderHandshake};
use crate::ssu2_header::{ConnectionId, SSU2_MIN_PACKET_SIZE, SSU2_VERSION, Ssu2MessageType};
use crate::ssu2_lifecycle::Ssu2SessionState;
use crate::ssu2_policy::{
    DateTimeAction, I2pdCongestionPolicy, I2pdPolicy, SSU2_CLEANUP_INTERVAL, SSU2_MAX_PACKET_SIZE,
    SSU2_TERMINATION_CHECK_TIMEOUT, SSU2_TERMINATION_TIMEOUT, SSU2_TOKEN_EXPIRATION_THRESHOLD,
    SSU2_TOKEN_EXPIRATION_TIMEOUT, Ssu2Policy,
};
use crate::ssu2_send::{RandomSource, append_address};
use crate::ssu2_token::{Token, TokenSource, TokenStore};
use crate::transport_ban::BanList;

/// Период тика обслуживания (i2pd `ScheduleResend`, `SSU2.cpp:1228`).
const SSU2_POOL_TICK: Duration = Duration::from_millis(40);

/// Ёмкость канала команд в задачу пула.
const COMMAND_QUEUE: usize = 64;

/// Ёмкость канала событий из задачи пула.
///
/// Переполнение возможно, только если вызывающий не читает
/// [`Ssu2Pool::next_event`]; тогда событие теряется с `warn` — так же, как
/// i2pd перестаёт принимать новые сессии при переполнении очереди.
const EVENT_QUEUE: usize = 256;

/// Пакеты, готовые к отправке: адрес и байты.
type OutQueue = Vec<(SocketAddr, Vec<u8>)>;

// --- локальные параметры -------------------------------------------------

/// Локальные параметры SSU2-транспорта: свои ключи и `RouterInfo`.
///
/// Владение ключами (`I2PX25519Keys` не `Clone`) — на стороне вызывающего:
/// пул живёт в отдельной задаче, а `RouterConfig` держит static-ключ
/// NTCP2/SSU2. [`Ssu2Local::from_router_config`] восстанавливает пару из
/// приватного и публичного ключей конфига, поэтому конфиг остаётся целым.
pub struct Ssu2Local {
    /// Static X25519-ключ (`s=`); тот же, что у NTCP2.
    static_keys: I2PX25519Keys,
    /// Intro-ключ (`i=`).
    intro_key: [u8; 32],
    /// Свой подписанный `RouterInfo`.
    ri_bytes: Vec<u8>,
    /// `IdentHash` из `ri_bytes`.
    ident: IdentHash,
    /// `netId` для заголовков.
    net_id: u8,
    /// Наш SSU2-интерфейс — IPv6 (влияет на размер payload'а).
    ipv6: bool,
    /// Роутер в тестовом режиме (`HandleDateTime`).
    testing: bool,
    /// `m_Server.IsSyncClockFromPeers()`.
    sync_clock_from_peers: bool,
}

impl Ssu2Local {
    /// Собирает параметры из конфигурации роутера.
    ///
    /// `now_ms` — метка времени своего `RouterInfo` (параметром, чтобы тесты
    /// были детерминированными — как [`RouterConfig::build_router_info`]).
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если в конфиге нет SSU2 intro-ключа (то есть
    /// нет SSU2-endpoint'ов), ошибки сборки `RouterInfo`.
    pub fn from_router_config(cfg: &RouterConfig, now_ms: u64) -> Result<Self> {
        let intro_key = *cfg.ssu2_intro_key().ok_or(I2PError::Malformed(
            "ssu2 pool: config has no SSU2 intro key (no SSU2 endpoints)",
        ))?;
        let ri = cfg.build_router_info(now_ms)?;
        let ri_bytes = ri.to_buffer()?;
        let ipv6 = cfg
            .listen()
            .iter()
            .any(|ep| ep.transport == Transport::Ssu2 && ep.bind.is_ipv6());
        debug!(
            ident = %ri.ident_hash().to_base64(),
            ipv6,
            ri_len = ri_bytes.len(),
            "Ssu2Local::from_router_config: local parameters ready"
        );
        Ok(Self {
            static_keys: I2PX25519Keys::from_private(
                &cfg.ntcp2_static().private_key(),
                Some(cfg.ntcp2_static().public_key()),
            ),
            intro_key,
            ri_bytes,
            ident: *ri.ident_hash(),
            net_id: cfg.net_id(),
            ipv6,
            testing: false,
            sync_clock_from_peers: false,
        })
    }

    /// Собирает параметры из готовых частей (для тестов и встраивания).
    ///
    /// # Errors
    ///
    /// [`I2PError`], если `ri_bytes` не разбирается как `RouterInfo`.
    pub fn new(
        static_keys: I2PX25519Keys,
        intro_key: [u8; 32],
        ri_bytes: Vec<u8>,
        net_id: u8,
        ipv6: bool,
    ) -> Result<Self> {
        let ri = FullRouterInfo::from_buffer(&ri_bytes)?;
        Ok(Self {
            static_keys,
            intro_key,
            ri_bytes,
            ident: *ri.ident_hash(),
            net_id,
            ipv6,
            testing: false,
            sync_clock_from_peers: false,
        })
    }

    /// Роутер в тестовом режиме (i2pd `SetTesting`).
    #[must_use]
    pub const fn with_testing(mut self, testing: bool) -> Self {
        self.testing = testing;
        self
    }

    /// Синхронизировать часы с собеседником (i2pd `IsSyncClockFromPeers`).
    #[must_use]
    pub const fn with_sync_clock_from_peers(mut self, sync: bool) -> Self {
        self.sync_clock_from_peers = sync;
        self
    }

    /// Intro-ключ (`i=`).
    #[must_use]
    pub const fn intro_key(&self) -> &[u8; 32] {
        &self.intro_key
    }

    /// Свой `RouterInfo`.
    #[must_use]
    pub fn ri_bytes(&self) -> &[u8] {
        &self.ri_bytes
    }

    /// Свой `IdentHash`.
    #[must_use]
    pub const fn ident(&self) -> &IdentHash {
        &self.ident
    }

    /// Наш SSU2-интерфейс — IPv6.
    #[must_use]
    pub const fn ipv6(&self) -> bool {
        self.ipv6
    }

    /// Конфигурация заголовков handshake-пакетов для семейства `ipv6`.
    #[must_use]
    const fn handshake_config(&self, ipv6: bool) -> HandshakeConfig {
        HandshakeConfig {
            version: SSU2_VERSION,
            net_id: self.net_id,
            ipv6,
            mtu: SSU2_MAX_PACKET_SIZE,
        }
    }

    /// Копия static-пары: `InitiatorHandshake`/`ResponderHandshake` забирают
    /// ключ по значению, а сессий много.
    fn static_keys_copy(&self) -> I2PX25519Keys {
        I2PX25519Keys::from_private(
            &self.static_keys.private_key(),
            Some(self.static_keys.public_key()),
        )
    }

    /// Максимальный размер payload'а data-пакета для семейства `ipv6`.
    #[must_use]
    fn max_payload(ipv6: bool) -> usize {
        I2pdPolicy.max_payload_size(ipv6, SSU2_MAX_PACKET_SIZE)
    }
}

impl std::fmt::Debug for Ssu2Local {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssu2Local")
            .field("ident", &self.ident.to_base64())
            .field("intro_key", &"<secret>")
            .field("ri_len", &self.ri_bytes.len())
            .field("net_id", &self.net_id)
            .field("ipv6", &self.ipv6)
            .finish_non_exhaustive()
    }
}

// --- события и команды ---------------------------------------------------

/// Событие из пула (наружу — вызывающему).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ssu2Event {
    /// Соединение установлено (i2pd `Transports::PeerConnected`).
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
    /// Собеседник прислал `RouterInfo` (в `SessionConfirmed` или блоком в
    /// data-пакете). Caller может положить его в netDb.
    RouterInfo {
        /// От кого.
        from: IdentHash,
        /// Сырые байты `RouterInfo`.
        ri_bytes: Vec<u8>,
    },
    /// Соединение завершено (по своей инициативе, по `Termination`, по
    /// таймауту или из-за ошибки).
    Disconnected {
        /// С кем.
        ident: IdentHash,
    },
    /// Собеседник сообщил, каким видит наш внешний адрес (блок `Address` в
    /// payload'е `Retry`/`SessionCreated`; i2pd `HandleAddress` →
    /// `i2p::context.UpdateAddress`, `SSU2Session.cpp:2104`).
    ///
    /// Что с этим делать (публиковать ли адрес в своём `RouterInfo`) решает
    /// роутер: пул только сообщает наблюдение.
    ExternalAddress {
        /// Наш адрес, каким его видит собеседник.
        addr: SocketAddr,
        /// Через какую сессию узнали (если `RouterInfo` собеседника уже
        /// известен).
        from: Option<IdentHash>,
    },
}

/// Команда в задачу пула.
enum Command {
    /// Установить соединение с роутером по его `RouterInfo`.
    Connect {
        /// `RouterInfo` собеседника.
        ri_bytes: Vec<u8>,
        /// Адрес вместо опубликованного в `RouterInfo` (для [`Ssu2Pool::connect_to`]).
        addr: Option<SocketAddr>,
        /// Ответ: `IdentHash` (сразу после отправки первого пакета).
        reply: oneshot::Sender<Result<IdentHash>>,
    },
    /// Отправить I2NP-сообщение собеседнику.
    Send {
        /// Кому.
        ident: IdentHash,
        /// Что.
        message: I2npMessage,
        /// Ответ об успешной постановке в очередь.
        reply: oneshot::Sender<Result<()>>,
    },
    /// Завершить соединение.
    Close {
        /// С кем.
        ident: IdentHash,
        /// `true`, если сессия была.
        reply: oneshot::Sender<bool>,
    },
    /// Список `IdentHash` известных сессий.
    Sessions {
        /// Ответ.
        reply: oneshot::Sender<Vec<IdentHash>>,
    },
}

// --- пул -----------------------------------------------------------------

/// Пул SSU2-соединений на одном UDP-сокете.
pub struct Ssu2Pool {
    /// Канал команд в задачу пула.
    cmds: mpsc::Sender<Command>,
    /// Канал событий из задачи пула.
    events: Mutex<mpsc::Receiver<Ssu2Event>>,
    /// Адрес сокета.
    local_addr: SocketAddr,
    /// Свой `IdentHash`.
    ident: IdentHash,
    /// Задача пула (abort при drop).
    task: JoinHandle<()>,
}

impl Ssu2Pool {
    /// Привязывает новый UDP-сокет и запускает пул.
    ///
    /// # Errors
    ///
    /// [`I2PError::Io`] при ошибке `bind`.
    pub async fn bind(bind: SocketAddr, local: Ssu2Local) -> Result<Self> {
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| I2PError::Io(format!("ssu2 pool: bind {bind}: {e}")))?;
        Self::with_socket(socket, local)
    }

    /// Запускает пул на уже привязанном сокете.
    ///
    /// Нужен, когда адрес сокета должен быть известен до сборки своего
    /// `RouterInfo` (публикуемый SSU2-адрес с реальным портом).
    ///
    /// Список банов — свой; чтобы делить его с NTCP2, см.
    /// [`Self::with_socket_and_ban`].
    ///
    /// # Errors
    ///
    /// [`I2PError::Io`] при ошибке `local_addr`.
    pub fn with_socket(socket: UdpSocket, local: Ssu2Local) -> Result<Self> {
        Self::with_socket_and_ban(socket, local, Arc::new(BanList::new()))
    }

    /// То же, но со своим (общим с NTCP2) списком банов.
    ///
    /// i2pd держит один `m_BanList` на все транспорты
    /// (`libi2pd/Transports.h`).
    ///
    /// # Errors
    ///
    /// [`I2PError::Io`] при ошибке `local_addr`.
    pub fn with_socket_and_ban(
        socket: UdpSocket,
        local: Ssu2Local,
        ban: Arc<BanList>,
    ) -> Result<Self> {
        let local_addr = socket
            .local_addr()
            .map_err(|e| I2PError::Io(format!("ssu2 pool: local_addr: {e}")))?;
        let ident = *local.ident();
        let (cmds, cmds_rx) = mpsc::channel(COMMAND_QUEUE);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let task = tokio::spawn(run(socket, local, cmds_rx, events_tx, ban));
        debug!(%local_addr, "Ssu2Pool::with_socket: pool started");
        Ok(Self {
            cmds,
            events: Mutex::new(events_rx),
            local_addr,
            ident,
            task,
        })
    }

    /// Адрес сокета.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Свой `IdentHash`.
    #[must_use]
    pub const fn ident(&self) -> &IdentHash {
        &self.ident
    }

    /// Начинает соединение с роутером, чей `RouterInfo` передан.
    ///
    /// Возвращается сразу после отправки `SessionRequest`/`TokenRequest`
    /// (как i2pd `SSU2Server::CreateSession`): о готовности сообщит
    /// [`Ssu2Event::Established`].
    ///
    /// # Errors
    ///
    /// - [`I2PError::Malformed`] — нет опубликованного SSU2-адреса в `RI`
    ///   или соединение с этим endpoint'ом уже устанавливается;
    /// - [`I2PError::Io`] — пул остановлен.
    pub async fn connect(&self, remote_ri_bytes: &[u8]) -> Result<IdentHash> {
        self.send_connect(remote_ri_bytes, None).await
    }

    /// Начинает соединение с роутером, но адрес берёт из `addr`, а не из
    /// опубликованного SSU2-адреса в `RouterInfo`.
    ///
    /// Ключи (`s=`, `i=`) всё равно берутся из `RouterInfo` — подменяется
    /// только транспортный адрес. Нужно, когда опубликованный адрес
    /// недостижим с нашей стороны (NAT, тест на localhost); i2pd в
    /// `SSU2Server::CreateSession` такого выбора не даёт и всегда идёт на
    /// опубликованный адрес.
    ///
    /// # Errors
    ///
    /// Как у [`Self::connect`].
    pub async fn connect_to(&self, remote_ri_bytes: &[u8], addr: SocketAddr) -> Result<IdentHash> {
        self.send_connect(remote_ri_bytes, Some(addr)).await
    }

    async fn send_connect(
        &self,
        remote_ri_bytes: &[u8],
        addr: Option<SocketAddr>,
    ) -> Result<IdentHash> {
        let (reply, wait) = oneshot::channel();
        self.cmds
            .send(Command::Connect {
                ri_bytes: remote_ri_bytes.to_vec(),
                addr,
                reply,
            })
            .await
            .map_err(|_| I2PError::Io("ssu2 pool: command channel closed".into()))?;
        wait.await
            .map_err(|_| I2PError::Io("ssu2 pool: connect task dropped".into()))?
    }

    /// Ставит I2NP-сообщение в очередь собеседнику.
    ///
    /// До установления соединения сообщение ждёт в очереди сессии (i2pd
    /// `m_IntermediateQueue`), после — уходит в `SendQueue`.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если сессии с таким `IdentHash` нет.
    pub async fn send_to(&self, ident: &IdentHash, message: I2npMessage) -> Result<()> {
        let (reply, wait) = oneshot::channel();
        self.cmds
            .send(Command::Send {
                ident: *ident,
                message,
                reply,
            })
            .await
            .map_err(|_| I2PError::Io("ssu2 pool: command channel closed".into()))?;
        wait.await
            .map_err(|_| I2PError::Io("ssu2 pool: send task dropped".into()))?
    }

    /// Ждёт следующего события от любой сессии.
    ///
    /// # Errors
    ///
    /// [`I2PError::Io`], если пул остановлен.
    pub async fn next_event(&self) -> Result<Ssu2Event> {
        let mut events = self.events.lock().await;
        events
            .recv()
            .await
            .ok_or_else(|| I2PError::Io("ssu2 pool: event channel closed".into()))
    }

    /// Завершает соединение с `ident`.
    ///
    /// Отправляет `Termination` и сразу забывает сессию (i2pd ждёт
    /// подтверждения в состоянии `Closing`).
    ///
    /// # Errors
    ///
    /// [`I2PError::Io`], если пул остановлен.
    pub async fn close(&self, ident: &IdentHash) -> Result<bool> {
        let (reply, wait) = oneshot::channel();
        self.cmds
            .send(Command::Close {
                ident: *ident,
                reply,
            })
            .await
            .map_err(|_| I2PError::Io("ssu2 pool: command channel closed".into()))?;
        wait.await
            .map_err(|_| I2PError::Io("ssu2 pool: close task dropped".into()))
    }

    /// `IdentHash` всех известных сессий (и устанавливающихся тоже).
    ///
    /// # Errors
    ///
    /// [`I2PError::Io`], если пул остановлен.
    pub async fn session_idents(&self) -> Result<Vec<IdentHash>> {
        let (reply, wait) = oneshot::channel();
        self.cmds
            .send(Command::Sessions { reply })
            .await
            .map_err(|_| I2PError::Io("ssu2 pool: command channel closed".into()))?;
        wait.await
            .map_err(|_| I2PError::Io("ssu2 pool: sessions task dropped".into()))
    }
}

impl Drop for Ssu2Pool {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl std::fmt::Debug for Ssu2Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssu2Pool")
            .field("local_addr", &self.local_addr)
            .field("ident", &self.ident.to_base64())
            .finish_non_exhaustive()
    }
}

// --- задача пула ---------------------------------------------------------

/// Одно соединение в пуле.
struct Session {
    /// Драйвер рукопожатия + data phase.
    conn: Ssu2Connection,
    /// Адрес собеседника.
    remote: SocketAddr,
    /// `IdentHash` собеседника (у инициатора известен сразу, у ответчика —
    /// после `RouterInfo` в `SessionConfirmed`).
    ident: Option<IdentHash>,
    /// Соединение установлено.
    established: bool,
    /// Мы инициатор (`IsOutgoing`).
    outgoing: bool,
    /// Отправленный `Path Challenge` и адрес, на который он ушёл, — ждём
    /// `Path Response` (i2pd `m_PathChallenge` = `(challenge, endpoint)`).
    ///
    /// Само значение челленджа живёт в движке
    /// ([`Ssu2DataSession::path_challenge_sent`]); пул помнит адрес и время
    /// отправки, чтобы обновить `remote` и закрыть сессию, если ответа нет.
    path_challenge: Option<(SocketAddr, Duration)>,
    /// I2NP-сообщения, ждущие установления (i2pd `m_IntermediateQueue`).
    queue: VecDeque<I2npMessage>,
    /// До какого момента «доигрываем» закрытую сессию.
    ///
    /// [`PoolState::close_session`] убирает сессию из `by_ident` (и сообщает
    /// наружу `Disconnected`) сразу, но сам `conn_id` ещё живёт: так мы
    /// успеваем подтвердить (Ack) пакеты, которые собеседник отправил
    /// раньше, чем получил `Termination`. i2pd держит такую сессию в
    /// `Closing` до тика терминации
    /// ([`SSU2_TERMINATION_CHECK_TIMEOUT`]); без этого его окно
    /// переполняется (`Outgoing messages queue ... is semi-full`) и
    /// `Termination` переотправляется до лимита (`Resend`).
    drain_until: Option<Duration>,
    /// `Disconnected` по этой сессии уже отправлен.
    ///
    /// Один `conn_id` — не более одного события: при закрытии мы сообщаем
    /// сразу, а когда доигранная сессия наконец исчезает — молчим (иначе
    /// роутер узнал бы о разрыве дважды, а при быстром переподключении ещё
    /// и «убил» бы уже новую сессию).
    disconnected: bool,
}

/// Состояние задачи пула (всё синхронно).
struct PoolState {
    /// Свои параметры.
    local: Ssu2Local,
    /// Политика SSU2 (i2pd).
    policy: I2pdPolicy,
    /// Политика перегрузки (i2pd).
    congestion: I2pdCongestionPolicy,
    /// Токены входящие/исходящие (`SSU2Server::m_IncomingTokens`).
    tokens: TokenStore,
    /// Соединения по нашему `sourceConnID`.
    sessions: HashMap<ConnectionId, Session>,
    /// Устанавливающиеся исходящие соединения по адресу
    /// (`m_PendingOutgoingSessions`).
    by_endpoint: HashMap<SocketAddr, ConnectionId>,
    /// Соединения по `IdentHash` (`m_SessionsByRouterHash`).
    by_ident: HashMap<IdentHash, ConnectionId>,
    /// Забаненные адреса (i2pd `Transports::m_BanList`).
    ban: Arc<BanList>,
    /// Канал событий наружу.
    events: mpsc::Sender<Ssu2Event>,
}

impl PoolState {
    /// Новое состояние.
    fn new(local: Ssu2Local, events: mpsc::Sender<Ssu2Event>, ban: Arc<BanList>) -> Self {
        Self {
            local,
            policy: I2pdPolicy,
            congestion: I2pdCongestionPolicy,
            tokens: TokenStore::new(),
            sessions: HashMap::new(),
            by_endpoint: HashMap::new(),
            by_ident: HashMap::new(),
            ban,
            events,
        }
    }

    /// Отправляет событие наружу, не блокируя задачу.
    fn emit(&self, event: Ssu2Event) {
        trace!(?event, "emit: event");
        if self.events.try_send(event).is_err() {
            warn!("emit: event queue is full or closed; event dropped");
        }
    }

    // --- обработка входных событий ---------------------------------------

    /// Один входящий датаграм (i2pd `ProcessNextPacket`, `SSU2.cpp:690`).
    fn on_datagram(&mut self, buf: &mut [u8], len: usize, from: SocketAddr, out: &mut OutQueue) {
        if len < SSU2_MIN_PACKET_SIZE {
            trace!(len, %from, "on_datagram: packet too short");
            return;
        }
        let Some(dest) = peek_dest_conn_id(&buf[..len], self.local.intro_key()) else {
            return;
        };
        // Как в i2pd: сперва поиск по `destConnID` (`m_Sessions`), и только
        // если не нашли — по адресу (`m_PendingOutgoingSessions`).
        let key = if self.sessions.contains_key(&dest) {
            Some(dest)
        } else {
            self.by_endpoint.get(&from).copied()
        };
        if let Some(key) = key {
            self.deliver(key, &mut buf[..len], from, out);
        } else {
            // i2pd (`SSU2.cpp:767`) до создания сессии проверяет
            // banned-адрес: остальные датаграммы от него молча
            // отбрасываются.
            if self.ban.is_banned(from.ip(), unix_now().0) {
                warn!(%from, "on_datagram: пакет от забаненного адреса; игнорируем");
                return;
            }
            self.start_incoming(&mut buf[..len], from, out);
        }
    }

    /// Команда от вызывающего.
    fn on_command(&mut self, command: Command, out: &mut OutQueue) {
        match command {
            Command::Connect {
                ri_bytes,
                addr,
                reply,
            } => {
                let result = self.start_connect(&ri_bytes, addr, out);
                let _ = reply.send(result);
            }
            Command::Send {
                ident,
                message,
                reply,
            } => {
                let result = self.send_i2np(&ident, message, out);
                let _ = reply.send(result);
            }
            Command::Close { ident, reply } => {
                let _ = reply.send(self.close_session(&ident, out));
            }
            Command::Sessions { reply } => {
                let _ = reply.send(self.by_ident.keys().copied().collect());
            }
        }
    }

    /// Тик обслуживания: таймеры, повторы, очистка токенов.
    fn on_tick(&mut self, out: &mut OutQueue) {
        let now = now();
        self.tokens.cleanup(unix_now().1);
        let keys: Vec<ConnectionId> = self.sessions.keys().copied().collect();
        for key in keys {
            if self.sessions.contains_key(&key) {
                self.tick_session(key, now, out);
            }
        }
    }

    /// Тик «доигрывания» закрытой сессии (см.
    /// [`PoolState::close_session`]).
    ///
    /// Сессия уже убрана из `by_ident`, но по `conn_id` ещё живёт: так мы
    /// успеваем подтвердить пакеты, которые собеседник отправил, не зная о
    /// нашем `Termination`. i2pd держит `Closing` до тика терминации
    /// ([`SSU2_TERMINATION_CHECK_TIMEOUT`]).
    ///
    /// Возвращает `true`, если сессия доигрывается (или только что убрана):
    /// остальная часть тика ей не нужна.
    fn tick_drain(&mut self, key: ConnectionId, now: Duration) -> bool {
        let Some(until) = self.sessions.get(&key).and_then(|s| s.drain_until) else {
            return false;
        };
        if now >= until {
            debug!(conn_id = ?key, "tick_drain: close drain expired");
            self.remove_session(key);
        }
        true
    }

    /// Тик одного соединения.
    fn tick_session(&mut self, key: ConnectionId, now: Duration, out: &mut OutQueue) {
        // Connect-таймаут (i2pd `HandleConnectTimer`).
        let expired = self
            .sessions
            .get(&key)
            .is_some_and(|s| !s.established && s.conn.connect_expired(now));
        if expired {
            warn!(conn_id = ?key, "tick_session: connection timed out");
            self.remove_session(key);
            return;
        }

        // Сессию, которую мы закрыли (`close_session`), держим до срока
        // «доигрывания»: она уже не в `by_ident`, но по `conn_id` ещё
        // принимает и подтверждает чужие пакеты.
        if self.tick_drain(key, now) {
            return;
        }

        let policy = self.policy;
        let congestion = self.congestion;
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let mut rng = rand::rng();

        // Повтор handshake-пакетов (i2pd `ResendHandshakePacket`).
        let jitter = u64::from(rng.roll() & 0x0F);
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let remote = session.remote;
        let plan = session.conn.poll_resend(&policy, now, jitter);
        for packet in plan.handshake_packets {
            out.push((remote, packet));
        }

        // Data phase: повторы по RTO (i2pd `Resend`) и idle-таймаут
        // (`HandleTerminationTimer`).
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        if !session.established {
            return;
        }

        // i2pd `CleanUp` (`SSU2Session.cpp:3506`, зовётся раз в
        // `SSU2_CLEANUP_INTERVAL` = 72 с): `Path Challenge` так и не
        // подтвердили — закрываем сессию. У i2pd это не проверка срока, а
        // «попали в тик уборки с висящим челленджем», из-за чего свежий
        // челлендж может убить сессию почти сразу (см. `notes/i2pd-bugs.md`,
        // п. 9); у нас челлендж закрывает сессию ровно через 72 с.
        let stale_challenge = session
            .path_challenge
            .is_some_and(|(_, sent_at)| now.saturating_sub(sent_at) >= SSU2_CLEANUP_INTERVAL);
        if stale_challenge {
            warn!(conn_id = ?key, "tick_session: path challenge not answered; terminating");
            self.request_termination(key, Ssu2TerminationReason::NormalClose);
            self.send_termination(key, out);
            self.remove_session(key);
            return;
        }

        let mut terminate = false;
        let mut close = false;
        {
            let Some(data) = session.conn.data_mut() else {
                return;
            };
            let mut ctx = SendContext {
                now,
                now_ms,
                now_micros,
                rng: &mut rng,
            };
            // Плановая переотправка своего `RouterInfo` (i2pd `Resend`:
            // `ts > m_NextRouterInfoResendTime` → `SendLocalRouterInfo`).
            if plan.resend_router_info {
                match data.send_router_info(&policy, &mut ctx, &self.local.ri_bytes) {
                    Ok(packet) => {
                        debug!(conn_id = ?key, "tick_session: RouterInfo resent");
                        out.push((remote, packet));
                    }
                    Err(error) => {
                        warn!(%error, conn_id = ?key, "tick_session: RouterInfo resend failed");
                    }
                }
            }
            match data.resend(&policy, &congestion, &mut ctx) {
                Ok(report) => {
                    terminate = report.terminate;
                    if !report.packets.is_empty() {
                        debug!(
                            conn_id = ?key,
                            packets = report.packets.len(),
                            "tick_session: data packets resent"
                        );
                    }
                    for packet in report.packets {
                        out.push((remote, packet));
                    }
                }
                Err(error) => warn!(%error, conn_id = ?key, "tick_session: resend failed"),
            }
            if !terminate {
                let idle = now.saturating_sub(data.last_activity()) >= SSU2_TERMINATION_TIMEOUT;
                let closing = matches!(
                    data.state(),
                    Ssu2SessionState::Closing | Ssu2SessionState::ClosingConfirmed
                );
                close = idle || closing;
            }
        }
        if terminate {
            warn!(conn_id = ?key, "tick_session: resend limit; session terminated");
            self.remove_session(key);
        } else if close {
            debug!(conn_id = ?key, "tick_session: idle or closing; terminating");
            self.request_termination(key, Ssu2TerminationReason::IdleTimeout);
            self.send_termination(key, out);
            self.remove_session(key);
        }
    }

    /// i2pd `ProcessData` (`SSU2Session.cpp:1752`): data-пакет пришёл с
    /// адреса, отличного от текущего, и `Path Challenge` на этот адрес ещё не
    /// отправляли — значит, собеседник «переехал» (NAT rebinding) либо адрес
    /// подменён. Челлендж уходит **на новый** адрес, а `remote` до совпавшего
    /// `Path Response` не меняется (это делает
    /// [`PoolState::apply_data_report`]).
    ///
    /// Как и i2pd, повторно на тот же адрес челлендж не отправляется
    /// (`!m_PathChallenge || from != m_PathChallenge->second`).
    ///
    /// i2pd здесь ещё проверяет `transports.IsInReservedRange` — это часть
    /// опции `reservedrange`; наш пул reserved-адреса не фильтрует (ни здесь,
    /// ни при приёме новых сессий).
    fn maybe_send_path_challenge(
        &mut self,
        key: ConnectionId,
        packet: &[u8],
        from: SocketAddr,
        out: &mut OutQueue,
    ) {
        let Some(session) = self.sessions.get(&key) else {
            return;
        };
        if from == session.remote {
            return;
        }
        // Только настоящий data-пакет: i2pd зовёт `ProcessData` лишь для
        // состояний `Established`/`SessionConfirmedSent` (то есть когда
        // data-слой уже есть), а повторный handshake-пакет обрабатывает там же
        // (`ResendHandshakePacket`/`SendQuickAck`).
        let Some(data) = session.conn.data() else {
            return;
        };
        if data.peek_message_type(packet) != Some(Ssu2MessageType::Data) {
            return;
        }
        // Челлендж на этот адрес уже висит — второго не шлём.
        if session
            .path_challenge
            .is_some_and(|(endpoint, _)| endpoint == from)
        {
            return;
        }
        debug!(
            %from,
            remote = %session.remote,
            conn_id = ?key,
            "path: remote endpoint changed; sending Path Challenge"
        );
        self.send_path_challenge(key, from, out);
    }

    /// `SendPathChallenge` на новый адрес собеседника
    /// (`SSU2Session.cpp:3405`): `DateTime` + Address + `Path Challenge` + Ack +
    /// Padding.
    ///
    /// i2pd здесь же навсегда урезает себе `m_MaxPayloadSize` до
    /// `SSU2_MIN_PACKET_SIZE` и окно до `SSU2_MIN_WINDOW_SIZE`; мы этого не
    /// делаем — челлендж уходит обычным пакетом (см. `notes/i2pd-bugs.md`,
    /// п. 9).
    fn send_path_challenge(&mut self, key: ConnectionId, to: SocketAddr, out: &mut OutQueue) {
        let now = now();
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        // i2pd: `RAND_bytes(&challenge, 8)` — у нас два броска по 32 бита.
        let challenge = (u64::from(rng.roll()) << 32) | u64::from(rng.roll());
        let address = address_block(to);
        let result = {
            let Some(session) = self.sessions.get_mut(&key) else {
                return;
            };
            let Some(data) = session.conn.data_mut() else {
                return;
            };
            let mut ctx = SendContext {
                now,
                now_ms,
                now_micros,
                rng: &mut rng,
            };
            data.send_path_challenge(&policy, &mut ctx, &address, challenge)
        };
        match result {
            Ok(packet) => {
                if let Some(session) = self.sessions.get_mut(&key) {
                    session.path_challenge = Some((to, now));
                }
                out.push((to, packet));
            }
            Err(error) => warn!(%error, conn_id = ?key, "send_path_challenge: failed"),
        }
    }

    /// `SendPathResponse` на принятый `Path Challenge` (`:3375`): `DateTime` +
    /// Address + `Path Response` + Ack + Padding.
    ///
    /// Адресный блок и адрес отправки — текущий `remote`, как и в i2pd
    /// (`SendData` внутри `SendPathResponse` шлёт на `m_RemoteEndpoint`).
    fn send_path_response(&mut self, key: ConnectionId, data: &[u8], out: &mut OutQueue) {
        let now = now();
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let remote = session.remote;
        let address = address_block(remote);
        let Some(data_session) = session.conn.data_mut() else {
            return;
        };
        let mut ctx = SendContext {
            now,
            now_ms,
            now_micros,
            rng: &mut rng,
        };
        match data_session.send_path_response(&policy, &mut ctx, &address, data) {
            Ok(packet) => out.push((remote, packet)),
            Err(error) => warn!(%error, conn_id = ?key, "send_path_response: failed"),
        }
    }

    /// Обрабатывает пакет для известного соединения.
    fn deliver(
        &mut self,
        key: ConnectionId,
        packet: &mut [u8],
        from: SocketAddr,
        out: &mut OutQueue,
    ) {
        // i2pd `ProcessSessionConfirmed` (`SSU2Session.cpp:1223`): ответчик в
        // `SessionCreatedSent`, получивший не `SessionConfirmed` (например,
        // повторный `SessionRequest`), сессию **не** завершает.
        if let Some(session) = self.sessions.get(&key)
            && session.conn.role() == HandshakeRole::Responder
            && session.conn.state() == Ssu2SessionState::SessionCreatedSent
        {
            let confirmed = session
                .conn
                .session_confirmed_header_key()
                .is_some_and(|kh2| {
                    peek_message_type_with(packet, &kh2) == Some(Ssu2MessageType::SessionConfirmed)
                });
            if !confirmed {
                trace!(%from, conn_id = ?key, "deliver: not SessionConfirmed; ignored");
                return;
            }
        }

        // i2pd `ProcessData` (`SSU2Session.cpp:1752`): data-пакет пришёл с
        // адреса, отличного от текущего, — значит собеседник «переехал»
        // (NAT rebinding) либо адрес подменён. Адрес собеседника при этом
        // сразу **не** меняется: сначала туда уходит `Path Challenge`, и
        // только совпавший `Path Response` разрешает переезд
        // (`apply_data_report`).
        self.maybe_send_path_challenge(key, packet, from, out);

        let now = now();
        let now_micros = micros(now);
        let (now_ms, now_secs) = unix_now();
        let policy = self.policy;
        let congestion = self.congestion;
        let mut rng = rand::rng();
        // `GetIncomingToken` i2pd зовёт только там, где токен нужен:
        // `SendRetry` (для `TokenRequest`) и `ProcessSessionRequest`; для
        // data-пакетов входящий токен не читается.
        let msg_type = peek_message_type_with(packet, self.local.intro_key());
        let is_session_request = msg_type == Some(Ssu2MessageType::SessionRequest);
        let needs_token = is_session_request || msg_type == Some(Ssu2MessageType::TokenRequest);
        let expected_token = if needs_token {
            self.tokens.incoming_token(from, now_secs, &mut rng)
        } else {
            0
        };
        let address = address_block(from);
        // `New Token` в `SessionCreated` i2pd добавляет только в
        // `SendSessionCreated` (`SSU2Session.cpp:1020`), то есть лишь когда
        // `SessionRequest` принят с верным токеном. Если выдавать новый токен
        // на каждом пакете, предъявленный собеседником токен «сгорает»
        // раньше, чем он им воспользуется, — получается бесконечный
        // `Retry`/`SessionRequest`. Поэтому блоки готовим заранее только под
        // подходящий `SessionRequest` с ожидаемым токеном.
        let will_send_session_created = is_session_request
            && peek_long_header_ids(packet, self.local.intro_key())
                .is_some_and(|(_, token)| token == expected_token);
        let extra = if will_send_session_created {
            self.session_created_extra(from, now_secs, &mut rng)
        } else {
            Vec::new()
        };

        let Some(mut session) = self.sessions.remove(&key) else {
            return;
        };
        // i2pd `SSU2Server::ProcessNextPacket` (`SSU2.cpp:758-763`) держит
        // исходящую сессию в `m_PendingOutgoingSessions` по адресу ровно до
        // успешного `ProcessSessionCreated`: тот добавляет сессию в
        // `m_Sessions` (по `destConnID`, `SSU2Session.cpp:1125`), а запись по
        // адресу сразу стирается («we are done with that endpoint»).
        // У нас `sessions` ключуется нашим `sourceConnID` с самого начала, так
        // что `by_endpoint` — только тот же «адрес до `SessionCreated`».
        let awaiting_session_created = session.conn.role() == HandshakeRole::Initiator
            && session.conn.state() == Ssu2SessionState::SessionRequestSent;
        let env = ResponderEnv {
            expected_token,
            address: Some(address),
            extra_blocks: &extra,
        };
        let mut ctx = ConnContext {
            now,
            now_ms,
            now_secs,
            now_micros,
            rng: &mut rng,
        };
        match session
            .conn
            .recv(&policy, &congestion, packet, &mut ctx, &env)
        {
            Ok(report) => {
                // Переход из `SessionRequestSent` в следующее состояние — это и
                // есть принятый `SessionCreated` (`Retry` возвращает сессию в
                // `SessionRequestSent` после `send_session_request`).
                let session_created = awaiting_session_created
                    && session.conn.state() != Ssu2SessionState::SessionRequestSent;
                self.sessions.insert(key, session);
                if session_created && self.by_endpoint.get(&from) == Some(&key) {
                    self.by_endpoint.remove(&from);
                    debug!(
                        %from,
                        conn_id = ?key,
                        "deliver: SessionCreated accepted; endpoint entry dropped"
                    );
                }
                self.apply_report(key, report, out);
            }
            Err(error) => {
                // i2pd `ProcessNextPacket`: `ProcessSessionConfirmed` вернул
                // `false` -> `Done()`. Для остальных состояний — только лог
                // (инициатора добьёт connect-таймаут).
                let terminate = session.conn.state() == Ssu2SessionState::SessionCreatedSent;
                warn!(
                    %error,
                    %from,
                    conn_id = ?key,
                    state = session.conn.state().name(),
                    "deliver: packet rejected"
                );
                self.sessions.insert(key, session);
                if terminate {
                    self.remove_session(key);
                }
            }
        }
    }

    /// Новое входящее соединение (i2pd `ProcessFirstIncomingMessage`).
    fn start_incoming(&mut self, packet: &mut [u8], from: SocketAddr, out: &mut OutQueue) {
        // i2pd `SSU2Server::ProcessFirstIncomingMessage` (`SSU2.cpp:475`)
        // разбирает только `SessionRequest` и `TokenRequest` — остальные типы
        // (в том числе короткие пакеты) игнорирует.
        let msg_type = peek_message_type_with(packet, self.local.intro_key());
        if !matches!(
            msg_type,
            Some(Ssu2MessageType::SessionRequest | Ssu2MessageType::TokenRequest)
        ) {
            trace!(?msg_type, %from, "start_incoming: unexpected packet; ignored");
            return;
        }
        let Some((peer_source, _token)) = peek_long_header_ids(packet, self.local.intro_key())
        else {
            trace!(%from, "start_incoming: short packet; ignored");
            return;
        };
        let Some(source_conn_id) = peek_dest_conn_id(packet, self.local.intro_key()) else {
            return;
        };
        let ipv6 = from.is_ipv6();
        let handshake = ResponderHandshake::new(
            self.local.static_keys_copy(),
            *self.local.intro_key(),
            self.local.handshake_config(ipv6),
        );
        let params = ConnParams {
            config: self.local.handshake_config(ipv6),
            local_intro_key: *self.local.intro_key(),
            // Intro-ключ инициатора узнаем из `RouterInfo` в
            // `SessionConfirmed` (i2pd `m_Address->i`, `:1394`).
            remote_intro_key: [0u8; 32],
            max_payload: Ssu2Local::max_payload(ipv6),
            relay_tag_requested: false,
            local_router_info: Vec::new(),
            testing: self.local.testing,
            sync_clock_from_peers: self.local.sync_clock_from_peers,
        };
        // i2pd: `m_SourceConnID` — `destConnID` пакета, `m_DestConnID` — его
        // `sourceConnID` (оба выбраны стороной-инициатором).
        let conn = Ssu2Connection::responder(params, handshake, source_conn_id, peer_source);
        debug!(
            %from,
            conn_id = ?source_conn_id,
            peer_conn_id = ?peer_source,
            "start_incoming: new incoming session"
        );
        self.sessions.insert(
            source_conn_id,
            Session {
                conn,
                remote: from,
                ident: None,
                established: false,
                outgoing: false,
                queue: VecDeque::new(),
                path_challenge: None,
                drain_until: None,
                disconnected: false,
            },
        );
        self.deliver(source_conn_id, packet, from, out);
        // i2pd держит сессию только после `SendSessionCreated`
        // (`AddSession` внутри `ProcessSessionRequest`); после `Retry`
        // (`TokenRequest`, неверный токен, неподдерживаемая версия) сессия
        // не нужна.
        let keep = self
            .sessions
            .get(&source_conn_id)
            .is_some_and(|s| s.conn.state() == Ssu2SessionState::SessionCreatedSent);
        if !keep {
            trace!(%from, "start_incoming: no SessionCreated; session dropped");
            self.remove_session(source_conn_id);
        }
    }

    /// Начинает исходящее соединение (i2pd `SSU2Session::Connect`).
    ///
    /// `addr_override` — адрес вместо опубликованного в `RouterInfo` (см.
    /// [`Ssu2Pool::connect_to`]); ключи всегда берутся из `RouterInfo`.
    fn start_connect(
        &mut self,
        ri_bytes: &[u8],
        addr_override: Option<SocketAddr>,
        out: &mut OutQueue,
    ) -> Result<IdentHash> {
        let remote_ri = FullRouterInfo::from_buffer(ri_bytes)?;
        let ident = *remote_ri.ident_hash();
        if let Some(key) = self.by_ident.get(&ident) {
            debug!(ident = %ident.to_base64(), conn_id = ?key, "start_connect: session already exists");
            return Ok(ident);
        }
        let published = find_ssu2_address(&remote_ri, self.local.ipv6())?;
        let remote = match addr_override {
            Some(addr) => addr,
            None if is_reachable_address(published) => {
                SocketAddr::new(published.host, published.port)
            }
            None => {
                return Err(I2PError::Malformed(
                    "ssu2 pool: no published SSU2 address in remote RouterInfo",
                ));
            }
        };
        let addr = published;
        if self.by_endpoint.contains_key(&remote) {
            return Err(I2PError::Malformed(
                "ssu2 pool: connect to that endpoint is already pending",
            ));
        }
        let ipv6 = remote.is_ipv6();
        let handshake = InitiatorHandshake::new(
            self.local.static_keys_copy(),
            *addr.s.as_bytes(),
            *addr.i.as_bytes(),
            self.local.handshake_config(ipv6),
        );
        let params = ConnParams {
            config: self.local.handshake_config(ipv6),
            local_intro_key: *self.local.intro_key(),
            remote_intro_key: *addr.i.as_bytes(),
            max_payload: Ssu2Local::max_payload(ipv6),
            relay_tag_requested: false,
            local_router_info: self.local.ri_bytes.clone(),
            testing: self.local.testing,
            sync_clock_from_peers: self.local.sync_clock_from_peers,
        };
        let mut rng = rand::rng();
        let source_conn_id = ConnectionId::random(&mut rng);
        let dest_conn_id = ConnectionId::random(&mut rng);
        let mut conn = Ssu2Connection::initiator(params, handshake, source_conn_id, dest_conn_id);

        let now = now();
        let (now_ms, now_secs) = unix_now();
        let token = self.tokens.find_outgoing_token(remote, now_secs);
        let mut ctx = ConnContext {
            now,
            now_ms,
            now_secs,
            now_micros: micros(now),
            rng: &mut rng,
        };
        let packets = conn.connect(&self.policy, &mut ctx, token)?;
        debug!(
            ident = %ident.to_base64(),
            %remote,
            conn_id = ?source_conn_id,
            token = token.unwrap_or_default(),
            packets = packets.len(),
            "start_connect: handshake started"
        );
        self.sessions.insert(
            source_conn_id,
            Session {
                conn,
                remote,
                ident: Some(ident),
                established: false,
                outgoing: true,
                queue: VecDeque::new(),
                path_challenge: None,
                drain_until: None,
                disconnected: false,
            },
        );
        self.by_endpoint.insert(remote, source_conn_id);
        self.by_ident.insert(ident, source_conn_id);
        for packet in packets {
            out.push((remote, packet));
        }
        Ok(ident)
    }

    /// Отправка I2NP-сообщения (i2pd `SendI2NPMessages`).
    fn send_i2np(
        &mut self,
        ident: &IdentHash,
        message: I2npMessage,
        out: &mut OutQueue,
    ) -> Result<()> {
        let key = *self
            .by_ident
            .get(ident)
            .ok_or(I2PError::Malformed("ssu2 pool: no session for peer"))?;
        let now = now();
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        let Some(session) = self.sessions.get_mut(&key) else {
            return Err(I2PError::Malformed("ssu2 pool: no session for peer"));
        };
        if !session.established {
            debug!(ident = %ident.to_base64(), "send_i2np: queued until established");
            session.queue.push_back(message);
            return Ok(());
        }
        let remote = session.remote;
        let Some(data) = session.conn.data_mut() else {
            return Err(I2PError::Malformed("ssu2 pool: session has no data phase"));
        };
        data.enqueue_i2np(message, now_micros);
        let mut ctx = SendContext {
            now,
            now_ms,
            now_micros,
            rng: &mut rng,
        };
        let report = data.flush(&policy, &mut ctx)?;
        for message in report.dropped {
            debug!(
                msg_id = message.msg_id(),
                "send_i2np: dropped expired message"
            );
        }
        for packet in report.packets {
            out.push((remote, packet));
        }
        Ok(())
    }

    /// Завершает соединение по команде.
    fn close_session(&mut self, ident: &IdentHash, out: &mut OutQueue) -> bool {
        let Some(key) = self.by_ident.get(ident).copied() else {
            return false;
        };
        debug!(ident = %ident.to_base64(), conn_id = ?key, "close_session: closing");
        self.request_termination(key, Ssu2TerminationReason::NormalClose);
        self.send_termination(key, out);
        // Сессия больше не «сессия этого собеседника»: по ней нельзя
        // отправлять, новый `connect` её не увидит, а роутер узнаёт о
        // разрыве сразу. Сам `conn_id` ещё немного живёт
        // (`drain_until`), чтобы подтвердить чужие пакеты, — как i2pd,
        // который убирает `Closing`-сессию лишь на тике терминации.
        let now = now();
        let remote = self.sessions.get(&key).map(|s| s.remote);
        if let Some(session) = self.sessions.get_mut(&key) {
            session.drain_until = Some(now + SSU2_TERMINATION_CHECK_TIMEOUT);
            session.queue.clear();
        }
        self.by_ident.remove(ident);
        // Незавершённое рукопожатие больше не «занимает» адрес: новый
        // `connect` на тот же endpoint должен пройти (i2pd освобождает
        // `m_PendingOutgoingSessions` по таймауту, см. `notes/i2pd-bugs.md`,
        // п. 7).
        if let Some(remote) = remote
            && self.by_endpoint.get(&remote) == Some(&key)
        {
            self.by_endpoint.remove(&remote);
        }
        self.emit_disconnected(key);
        true
    }

    // --- применение отчётов ----------------------------------------------

    /// Применяет [`ConnReport`] драйвера.
    fn apply_report(&mut self, key: ConnectionId, report: ConnReport, out: &mut OutQueue) {
        let Some(remote) = self.sessions.get(&key).map(|s| s.remote) else {
            return;
        };

        // НОВЫЙ токен из `SessionCreated` (i2pd `HandlePayload` ->
        // `UpdateOutgoingToken`).
        if let Some((expires, token)) = report.new_token {
            debug!(token, %remote, "apply_report: NewToken from SessionCreated");
            self.tokens.update_outgoing_token(
                remote,
                Token {
                    value: token,
                    expires,
                },
            );
        }

        // Токен из `Retry` (i2pd `ProcessRetry`: `UpdateOutgoingToken`).
        if let Some(token) = report.token {
            let expires = unix_now()
                .1
                .saturating_add(secs_u32(SSU2_TOKEN_EXPIRATION_TIMEOUT));
            self.tokens.update_outgoing_token(
                remote,
                Token {
                    value: token,
                    expires,
                },
            );
            debug!(token, %remote, "apply_report: outgoing token stored");
        }

        // Наш внешний адрес из payload'а `Retry`/`SessionCreated` (i2pd
        // `HandleAddress` → `i2p::context.UpdateAddress`): пул только сообщает
        // наблюдение, публиковать адрес — решение роутера.
        if let Some(address) = report.external_address {
            let from = self.sessions.get(&key).and_then(|s| s.ident);
            debug!(
                port = address.port,
                ip = %address.ip,
                %remote,
                "apply_report: our external address as seen by the peer"
            );
            self.emit(Ssu2Event::ExternalAddress {
                addr: SocketAddr::new(address.ip, address.port),
                from,
            });
        }

        // Решение по блоку `DateTime` (i2pd `HandleDateTime`): сам блок сессию
        // не рвёт — в i2pd он лишь записывает причину завершения и правит
        // смещение часов (см. `notes/i2pd-bugs.md`, п. 8).
        if let Some(action) = report.datetime
            && action != DateTimeAction::Ignore
        {
            debug!(?action, %remote, "apply_report: datetime decision");
        }

        // `RouterInfo` инициатора из `SessionConfirmed` (ответчик).
        if let Some(ri_bytes) = report.remote_router_info {
            match self.accept_remote_router_info(key, &ri_bytes, report.remote_static_key) {
                Ok(ident) => {
                    debug!(ident = %ident.to_base64(), "apply_report: remote RouterInfo accepted");
                    self.emit(Ssu2Event::RouterInfo {
                        from: ident,
                        ri_bytes,
                    });
                }
                Err(error) => {
                    warn!(%error, %remote, "apply_report: remote RouterInfo rejected");
                    self.remove_session(key);
                    return;
                }
            }
        }

        // Ответчик: `QuickAck` (i2pd `SendQuickAck` в конце
        // `ProcessSessionConfirmed`) — сразу после установки intro-ключа.
        if report.quick_ack_pending {
            self.send_quick_ack(key, out);
        }

        if report.established {
            self.on_established(key, out);
        }

        if let Some(data) = report.data {
            self.apply_data_report(key, data, out);
        }

        for packet in report.packets {
            out.push((remote, packet));
        }
    }

    /// Проверяет `RouterInfo` из `SessionConfirmed` и запоминает собеседника.
    ///
    /// Сами проверки — в [`check_session_confirmed_router_info`]; здесь
    /// книговедение сессии: intro-ключ для исходящих заголовков и «на роутер
    /// одна сессия».
    ///
    /// # Errors
    ///
    /// Пробрасывает ошибки [`check_session_confirmed_router_info`], а также
    /// [`I2PError::Malformed`], если сессия успела исчезнуть.
    fn accept_remote_router_info(
        &mut self,
        key: ConnectionId,
        ri_bytes: &[u8],
        static_key: Option<[u8; 32]>,
    ) -> Result<IdentHash> {
        let Some(remote) = self.sessions.get(&key).map(|s| s.remote) else {
            return Err(I2PError::Malformed("ssu2 pool: session vanished"));
        };
        let (ident, intro_key, published) =
            match check_session_confirmed_router_info(ri_bytes, remote, static_key) {
                Ok(info) => info,
                Err(error) => {
                    // i2pd `SSU2Session.cpp:1428`: если у собеседника
                    // *опубликованный* адрес, а `s` в его RI не совпал с
                    // ключом рукопожатия — это подмена, баним адрес.
                    if published_static_key_mismatch(ri_bytes, remote, static_key) {
                        warn!(
                            ip = %remote.ip(),
                            "accept_remote_router_info: `s` не совпал с рукопожатием — баню адрес"
                        );
                        self.ban.ban(remote.ip(), unix_now().0);
                    }
                    return Err(error);
                }
            };
        let Some(session) = self.sessions.get_mut(&key) else {
            return Err(I2PError::Malformed("ssu2 pool: session vanished"));
        };
        session.ident = Some(ident);
        session.conn.set_remote_intro_key(intro_key);
        // i2pd `AddSessionByRouterHash`: на роутер — одна сессия, старая
        // завершается `ReplacedByNewSession`.
        if let Some(old) = self.by_ident.insert(ident, key)
            && old != key
        {
            warn!(
                ident = %ident.to_base64(),
                "accept_remote_router_info: replacing an existing session"
            );
            self.remove_session_reason(old, Ssu2TerminationReason::ReplacedByNewSession);
        }
        debug!(
            ident = %ident.to_base64(),
            published, "accept_remote_router_info: address and intro key accepted"
        );
        Ok(ident)
    }

    /// `Established` (i2pd `SSU2Session::Established` + `Transports::PeerConnected`).
    fn on_established(&mut self, key: ConnectionId, out: &mut OutQueue) {
        let now = now();
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        let (remote, ident, outgoing, queued) = {
            let Some(session) = self.sessions.get_mut(&key) else {
                return;
            };
            if session.established {
                return;
            }
            session.established = true;
            (
                session.remote,
                session.ident,
                session.outgoing,
                session.queue.drain(..).collect::<Vec<I2npMessage>>(),
            )
        };
        // `by_endpoint` уже очищен при приёме `SessionCreated` (см. `deliver`),
        // как в i2pd; `remove_session` вычистит запись, если сессия умерла
        // раньше.
        if let Some(ident) = ident {
            debug!(ident = %ident.to_base64(), conn_id = ?key, "on_established: established");
            self.emit(Ssu2Event::Established { ident });
        }
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let Some(data) = session.conn.data_mut() else {
            return;
        };
        let mut ctx = SendContext {
            now,
            now_ms,
            now_micros,
            rng: &mut rng,
        };
        for message in queued {
            data.enqueue_i2np(message, now_micros);
        }
        match data.flush(&policy, &mut ctx) {
            Ok(report) => {
                for packet in report.packets {
                    out.push((remote, packet));
                }
            }
            Err(error) => warn!(%error, "on_established: flush failed"),
        }
        // i2pd `Transports::PeerConnected`: ответчик шлёт свой `RouterInfo`
        // (`SendLocalRouterInfo`); инициатор — нет, его RI уже ушёл в
        // `SessionConfirmed`.
        if !outgoing {
            match data.send_router_info(&policy, &mut ctx, self.local.ri_bytes()) {
                Ok(packet) => out.push((remote, packet)),
                Err(error) => warn!(%error, "on_established: sending our RouterInfo failed"),
            }
        }
    }

    /// Применяет отчёт data-слоя (i2pd `HandlePayload` + `FlushData`).
    fn apply_data_report(&mut self, key: ConnectionId, report: RecvReport, out: &mut OutQueue) {
        let Some(session) = self.sessions.get(&key) else {
            return;
        };
        let remote = session.remote;
        let Some(ident) = session.ident else {
            return;
        };
        // i2pd 3.0: `Path Challenge`, `Relay*` и `PeerTest` из
        // не-установленной сессии не обрабатываются (`SSU2Session.cpp`
        // `HandlePayload`). У нас до этой точки доходит и data-пакет,
        // принятый в `SessionConfirmedSent`.
        let established = session.conn.is_established();
        // Сессия, которую мы уже закрыли: содержимое — не наше дело (роутеру
        // про неё сказано), но мы продолжаем подтверждать чужие пакеты, чтобы
        // окно отправки у собеседника не висло.
        let draining = session.drain_until.is_some();
        if report.invalid_message {
            warn!(ident = %ident.to_base64(), "apply_data_report: invalid block in payload");
        }
        if draining {
            if !report.i2np.is_empty() || !report.pending.is_empty() {
                trace!(
                    ident = %ident.to_base64(),
                    i2np = report.i2np.len(),
                    blocks = report.pending.len(),
                    "apply_data_report: session is closing; payload content ignored"
                );
            }
        } else {
            self.handle_payload_content(ident, report.i2np, report.pending, out);
        }
        if let Some((expires, token)) = report.new_token {
            debug!(token, %remote, "apply_data_report: new outgoing token");
            self.tokens.update_outgoing_token(
                remote,
                Token {
                    value: token,
                    expires,
                },
            );
        }
        if let Some(address) = report.external_address {
            debug!(?address, "apply_data_report: our external address");
        }

        // `Path Challenge` от собеседника — отвечаем `Path Response` (i2pd
        // `HandlePayload` → `SendPathResponse`); ответ уходит на текущий
        // `remote`. Только из установленной сессии (i2pd 3.0).
        if let Some(challenge) = report.path_challenge {
            if established {
                debug!(ident = %ident.to_base64(), "apply_data_report: Path Challenge received");
                self.send_path_response(key, &challenge, out);
            } else {
                warn!(
                    ident = %ident.to_base64(),
                    "apply_data_report: Path Challenge from non-established session; dropped"
                );
            }
        }

        // Наш `Path Challenge` подтверждён — только теперь меняем адрес
        // собеседника (i2pd: `m_RemoteEndpoint = m_PathChallenge->second`).
        if report.path_response_accepted
            && let Some(session) = self.sessions.get_mut(&key)
            && let Some((endpoint, sent_at)) = session.path_challenge.take()
        {
            debug!(
                from = %session.remote,
                to = %endpoint,
                elapsed_ms = now().saturating_sub(sent_at).as_millis(),
                conn_id = ?key,
                "apply_data_report: remote endpoint updated"
            );
            session.remote = endpoint;
        }

        match report.termination {
            Some(TerminationAction::ReplyAndClose) => {
                debug!(ident = %ident.to_base64(), "apply_data_report: answering with termination");
                self.send_termination(key, out);
            }
            Some(TerminationAction::CloseNow) => {
                debug!(ident = %ident.to_base64(), "apply_data_report: peer closed the session");
                // i2pd здесь просто `Done ()` — без Ack, из-за чего его
                // собственный `Termination` остаётся неподтверждённым и
                // переотправляется до лимита (`Resend`: «Packet was not
                // Acked after 6 attempts»). Отвечаем Ack'ом: собеседник
                // закрывает сессию спокойно. (`data_received` для блока
                // `Termination` не выставляется — подтверждаем всегда.)
                self.send_quick_ack(key, out);
                // Свою сессию (мы её закрыли первыми) не убираем сразу:
                // собеседник ещё в `Closing` и продолжает писать в неё —
                // пусть его пакеты будут подтверждены. Сессию доберёт
                // `tick_drain`.
                if !draining {
                    self.remove_session(key);
                }
                return;
            }
            Some(TerminationAction::RecordReason(reason)) => {
                debug!(ident = %ident.to_base64(), ?reason, "apply_data_report: termination recorded");
            }
            None => {}
        }

        // i2pd `FlushData`: если ничего не отправили, а данные пришли —
        // отдельный `QuickAck`; иначе ACK уехал бы «прицепом» в `flush`.
        let sent = self.flush_session(key, out);
        if report.data_received && !sent {
            self.send_quick_ack(key, out);
        }
    }

    /// Содержимое payload'а, которое обрабатывает вызывающий (в i2pd —
    /// уровень роутера): I2NP-сообщения и блоки вроде `RouterInfo`.
    fn handle_payload_content(
        &mut self,
        ident: IdentHash,
        i2np: Vec<I2npMessage>,
        pending: Vec<PendingBlock>,
        out: &mut OutQueue,
    ) {
        for message in i2np {
            self.emit(Ssu2Event::Message {
                from: ident,
                message,
            });
        }
        for block in pending {
            match block {
                PendingBlock::RouterInfo(body) => {
                    // i2pd `HandleRouterInfo` (`SSU2Session.cpp:2001`): тело
                    // блока = `flags` + `frag` + `RouterInfo` (возможно,
                    // gzip-сжатый) — снимаем их перед разбором; подпись
                    // проверяется, как при добавлении в netDb
                    // (`netdb.AddRouterInfo`).
                    match RouterInfoBlock::parse(&body).and_then(|block| block.body()) {
                        Ok(ri_bytes) => match FullRouterInfo::from_buffer(&ri_bytes)
                            .and_then(|ri| ri.verify(&ri_bytes))
                        {
                            Ok(()) => self.emit(Ssu2Event::RouterInfo {
                                from: ident,
                                ri_bytes: ri_bytes.into_owned(),
                            }),
                            Err(error) => {
                                warn!(ident = %ident.to_base64(), %error, "handle_payload_content: RouterInfo signature rejected");
                            }
                        },
                        Err(error) => {
                            warn!(ident = %ident.to_base64(), %error, "handle_payload_content: malformed RouterInfo block");
                        }
                    }
                }
                PendingBlock::PeerTest(body) => self.handle_peer_test(ident, &body, out),
                other => {
                    // TODO(suu2-pool-relay): `RelayRequest`/`RelayResponse`/
                    // `RelayIntro` (i2pd `HandlePayload`).
                    debug!(ident = %ident.to_base64(), block = ?other, "handle_payload_content: block not handled");
                }
            }
        }
    }

    /// `HandlePeerTest` (i2pd `SSU2Session.cpp:2548`): сообщения 1–4
    /// приходят внутри установленной data-сессии.
    ///
    /// Пока реализован ответ Боба «нет Charlie» (msg 4 с кодом
    /// [`Ssu2PeerTestCode::BobNoCharlieAvailable`]) — это единственное,
    /// что можно проверить в стенде с одним собеседником.
    fn handle_peer_test(&mut self, ident: IdentHash, body: &[u8], out: &mut OutQueue) {
        let block = match PeerTestBlock::parse(body) {
            Ok(block) => block,
            Err(error) => {
                warn!(ident = %ident.to_base64(), %error, "handle_peer_test: malformed PeerTest block");
                return;
            }
        };
        let Some(key) = self.by_ident.get(&ident).copied() else {
            return;
        };
        if !self
            .sessions
            .get(&key)
            .is_some_and(|session| session.established)
        {
            warn!(
                ident = %ident.to_base64(),
                msg = block.msg,
                "handle_peer_test: PeerTest from non-established session; dropped"
            );
            return;
        }
        match block.msg {
            1 => self.handle_peer_test_msg1(ident, key, &block, out),
            msg => {
                // TODO(peer-test): msg 2/3 (Charlie и Боб при живом Charlie)
                // и msg 4 (Alice). Для них нужны подпись
                // `PeerTestValidate` и выбор второго роутера.
                debug!(
                    ident = %ident.to_base64(),
                    msg,
                    code = block.code,
                    "handle_peer_test: message not implemented yet"
                );
            }
        }
    }

    /// `PeerTest` msg 1: Alice просит Боба проверить её адрес.
    ///
    /// i2pd выбирает Charlie среди сессий, поддерживающих peer test
    /// (`GetRandomPeerTestSession`), и шлёт ему msg 2. В стенде из одного
    /// собеседника Charlie нет, поэтому отвечаем msg 4 с ошибкой — ровно
    /// как i2pd в ветке `Charlie not found`.
    fn handle_peer_test_msg1(
        &mut self,
        ident: IdentHash,
        key: ConnectionId,
        block: &PeerTestBlock<'_>,
        out: &mut OutQueue,
    ) {
        let nonce = block
            .data
            .get(1..5)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_be_bytes);
        let charlie = self
            .sessions
            .iter()
            .find(|&(id, session)| *id != key && session.established)
            .map(|(id, _)| *id);
        if let Some(charlie) = charlie {
            // TODO(peer-test): переслать Charlie msg 2 с RI Алисы,
            // запомнить nonce → сессию Алисы и вернуть ей msg 4.
            warn!(
                ident = %ident.to_base64(),
                ?nonce,
                charlie = ?charlie,
                "handle_peer_test_msg1: forwarding to Charlie is not implemented"
            );
            return;
        }
        let reply = PeerTestBlock {
            msg: 4,
            code: Ssu2PeerTestCode::BobNoCharlieAvailable.as_u8(),
            flag: 0,
            router_hash: Some([0u8; 32]),
            data: block.data,
        };
        debug!(
            ident = %ident.to_base64(),
            ?nonce,
            "handle_peer_test_msg1: no Charlie; sending msg 4 error"
        );
        self.send_peer_test(key, &reply, out);
    }

    /// Отправляет `Peer Test`-блок в указанную сессию (i2pd `SendData`).
    fn send_peer_test(&mut self, key: ConnectionId, block: &PeerTestBlock<'_>, out: &mut OutQueue) {
        let now = now();
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let remote = session.remote;
        let Some(data) = session.conn.data_mut() else {
            return;
        };
        let mut ctx = SendContext {
            now,
            now_ms,
            now_micros,
            rng: &mut rng,
        };
        match data.send_peer_test(&policy, &mut ctx, block) {
            Ok(packet) => out.push((remote, packet)),
            Err(error) => warn!(%error, "send_peer_test: failed"),
        }
    }

    /// `SendQueue` для сессии. Возвращает `true`, если что-то отправлено.
    fn flush_session(&mut self, key: ConnectionId, out: &mut OutQueue) -> bool {
        let now = now();
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        let Some(session) = self.sessions.get_mut(&key) else {
            return false;
        };
        let remote = session.remote;
        let Some(data) = session.conn.data_mut() else {
            return false;
        };
        let mut ctx = SendContext {
            now,
            now_ms,
            now_micros,
            rng: &mut rng,
        };
        match data.flush(&policy, &mut ctx) {
            Ok(report) => {
                let sent = !report.packets.is_empty();
                for message in report.dropped {
                    debug!(
                        msg_id = message.msg_id(),
                        "flush_session: dropped expired message"
                    );
                }
                for packet in report.packets {
                    out.push((remote, packet));
                }
                sent
            }
            Err(error) => {
                warn!(%error, "flush_session: failed");
                false
            }
        }
    }

    /// `SendQuickAck` (i2pd `SSU2Session.cpp:3470`).
    fn send_quick_ack(&mut self, key: ConnectionId, out: &mut OutQueue) {
        let now = now();
        let (now_ms, now_secs) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        // `QuickAck` — data-пакет: до появления data-сессии его не собрать.
        if session.conn.data().is_none() {
            return;
        }
        let remote = session.remote;
        let mut ctx = ConnContext {
            now,
            now_ms,
            now_secs,
            now_micros,
            rng: &mut rng,
        };
        match session.conn.send_quick_ack(&policy, &mut ctx) {
            Ok(packet) => out.push((remote, packet)),
            Err(error) => warn!(%error, "send_quick_ack: failed"),
        }
    }

    /// `SendTermination` по текущей причине сессии.
    fn send_termination(&mut self, key: ConnectionId, out: &mut OutQueue) {
        let now = now();
        let (now_ms, _) = unix_now();
        let now_micros = micros(now);
        let policy = self.policy;
        let mut rng = rand::rng();
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let remote = session.remote;
        let Some(data) = session.conn.data_mut() else {
            return;
        };
        let mut ctx = SendContext {
            now,
            now_ms,
            now_micros,
            rng: &mut rng,
        };
        match data.send_termination(&policy, &mut ctx) {
            Ok(packet) => out.push((remote, packet)),
            Err(error) => warn!(%error, "send_termination: failed"),
        }
    }

    /// `RequestTermination` без отправки пакета (причина для `Termination`).
    fn request_termination(&mut self, key: ConnectionId, reason: Ssu2TerminationReason) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        if let Some(data) = session.conn.data_mut() {
            let _ = data.request_termination(reason);
        }
    }

    /// `New Token` и `Address` для `SessionCreated` (i2pd `SendSessionCreated`,
    /// `SSU2Session.cpp:1015-1028`).
    ///
    /// Блоки собираются заранее: `ResponderHandshake::build_session_created`
    /// пишет `DateTime`, а затем переданные `extra_blocks`.
    fn session_created_extra(
        &mut self,
        remote: SocketAddr,
        now_secs: u32,
        rng: &mut impl TokenSource,
    ) -> Vec<u8> {
        let mut extra = Vec::new();
        let max = Ssu2Local::max_payload(remote.is_ipv6());
        if let Err(error) = append_address(&mut extra, &address_block(remote), max) {
            warn!(%error, "session_created_extra: address block not written");
        }
        let token = self.tokens.new_incoming_token(remote, now_secs, rng);
        if now_secs.saturating_add(secs_u32(SSU2_TOKEN_EXPIRATION_THRESHOLD)) <= token.expires {
            let block = NewTokenBlock {
                expires: token
                    .expires
                    .saturating_sub(secs_u32(SSU2_TOKEN_EXPIRATION_THRESHOLD)),
                token: token.value,
            };
            if let Err(error) = block.write(&mut extra) {
                warn!(%error, "session_created_extra: NewToken block not written");
            }
        }
        trace!(
            %remote,
            extra_len = extra.len(),
            "session_created_extra: SessionCreated blocks"
        );
        extra
    }

    /// Убирает соединение и сообщает наружу (причина — для логов).
    fn remove_session(&mut self, key: ConnectionId) {
        self.remove_session_reason(key, Ssu2TerminationReason::NormalClose);
    }

    /// Убирает соединение с причиной и сообщает наружу.
    fn remove_session_reason(&mut self, key: ConnectionId, reason: Ssu2TerminationReason) {
        let Some(session) = self.sessions.get(&key) else {
            return;
        };
        let remote = session.remote;
        let ident = session.ident;
        let state = session.conn.state();
        let queued = session.queue.len();
        if queued > 0 {
            debug!(
                conn_id = ?key,
                queued, "remove_session: dropping queued messages"
            );
        }
        debug!(
            conn_id = ?key,
            ?reason,
            state = state.name(),
            "remove_session: session removed"
        );
        // Событие — до удаления: сессия нужна, чтобы знать `ident`.
        self.emit_disconnected(key);
        self.sessions.remove(&key);
        if self.by_endpoint.get(&remote) == Some(&key) {
            self.by_endpoint.remove(&remote);
        }
        if let Some(ident) = ident
            && self.by_ident.get(&ident) == Some(&key)
        {
            self.by_ident.remove(&ident);
        }
    }

    /// Сообщает наружу, что сессии больше нет (по одной сессии — один раз).
    fn emit_disconnected(&mut self, key: ConnectionId) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        if session.disconnected {
            return;
        }
        session.disconnected = true;
        if let Some(ident) = session.ident {
            self.emit(Ssu2Event::Disconnected { ident });
        }
    }
}

// --- задача и вспомогательное -------------------------------------------

/// Признак «у собеседника опубликованный SSU2-адрес, а `s` в его RI не
/// совпал с ключом рукопожатия» — за это i2pd банит адрес источника
/// (`SSU2Session.cpp:1428`).
///
/// Разбирает RI повторно: нужен только на пути ошибки
/// [`check_session_confirmed_router_info`], поэтому публичен для тестов, а
/// не как рабочий API пула.
#[must_use]
pub fn published_static_key_mismatch(
    ri_bytes: &[u8],
    remote: SocketAddr,
    static_key: Option<[u8; 32]>,
) -> bool {
    let Some(expected) = static_key else {
        return false;
    };
    let Ok(ri) = FullRouterInfo::from_buffer(ri_bytes) else {
        return false;
    };
    let Some(addr) = ri.body().ssu2_address(remote.is_ipv6()) else {
        return false;
    };
    addr.published && *addr.s.as_bytes() != expected
}

/// Проверяет `RouterInfo`, полученный в `SessionConfirmed` (ответчик).
///
/// Зеркалит `SSU2Session::ProcessSessionConfirmed`
/// (`SSU2Session.cpp:1353-1420`): подпись, свежесть (`timestamp`), версия,
/// SSU2-адрес семейства адреса пакета, совпадение опубликованного `host` с
/// адресом, откуда пришёл пакет, и `s=` со статическим ключом рукопожатия.
///
/// Возвращает `ident`, intro-ключ собеседника и признак «адрес опубликован»
/// (неопубликованный адрес — нормальный случай для NAT).
///
/// # Errors
///
/// [`I2PError::Malformed`] — RI не разбирается, подпись не сходится, RI
/// слишком старый или из будущего, версия слишком старая (и нет `caps=O`),
/// нет SSU2-адреса нужного семейства, не совпали `host` или `s=`.
pub fn check_session_confirmed_router_info(
    ri_bytes: &[u8],
    remote: SocketAddr,
    static_key: Option<[u8; 32]>,
) -> Result<(IdentHash, [u8; 32], bool)> {
    let ri = FullRouterInfo::from_buffer(ri_bytes)?;
    // i2pd проверяет подпись ещё при разборе RI (`ExtractRouterInfo` →
    // конструктор `RouterInfo`); непроверяемый RI не пускается дальше.
    ri.verify(ri_bytes)?;
    // Свежесть и версия (`:1355-1372`).
    let now_ms = unix_now().0;
    let ts = ri.body().timestamp;
    if now_ms > ts.saturating_add(millis(NETDB_MIN_EXPIRATION_TIMEOUT)) {
        return Err(I2PError::Malformed(
            "ssu2 pool: RouterInfo in SessionConfirmed is too old",
        ));
    }
    if ts > now_ms.saturating_add(millis(NETDB_EXPIRATION_TIMEOUT_THRESHOLD)) {
        return Err(I2PError::Malformed(
            "ssu2 pool: RouterInfo in SessionConfirmed is from the future",
        ));
    }
    if ri.body().version.unwrap_or(0) < NETDB_MIN_ALLOWED_VERSION
        && !ri.body().caps.is_high_bandwidth()
    {
        return Err(I2PError::Malformed(
            "ssu2 pool: RouterInfo version is too old",
        ));
    }
    let ident = *ri.ident_hash();
    let Some(addr) = ri.body().ssu2_address(remote.is_ipv6()) else {
        return Err(I2PError::Malformed(
            "ssu2 pool: no SSU2 address of that family in remote RouterInfo",
        ));
    };
    if addr.published && addr.host != remote.ip() {
        return Err(I2PError::Malformed(
            "ssu2 pool: published host mismatch (address spoofing?)",
        ));
    }
    if let Some(expected) = static_key
        && *addr.s.as_bytes() != expected
    {
        return Err(I2PError::Malformed(
            "ssu2 pool: static key mismatch in remote RouterInfo",
        ));
    }
    Ok((ident, *addr.i.as_bytes(), addr.published))
}

/// Задача пула: сокет, команды, тик.
async fn run(
    socket: UdpSocket,
    local: Ssu2Local,
    mut cmds: mpsc::Receiver<Command>,
    events: mpsc::Sender<Ssu2Event>,
    ban: Arc<BanList>,
) {
    let mut state = PoolState::new(local, events, ban);
    let mut buf = vec![0u8; 65536];
    let mut out: OutQueue = Vec::new();
    let mut tick = tokio::time::interval(SSU2_POOL_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                match received {
                    Ok((len, from)) => state.on_datagram(&mut buf, len, from, &mut out),
                    Err(error) => warn!(%error, "ssu2 pool: recv_from failed"),
                }
            }
            command = cmds.recv() => {
                let Some(command) = command else { break };
                state.on_command(command, &mut out);
            }
            _ = tick.tick() => state.on_tick(&mut out),
        }
        for (to, bytes) in std::mem::take(&mut out) {
            trace!(%to, len = bytes.len(), "ssu2 pool: sending packet");
            if let Err(error) = socket.send_to(&bytes, to).await {
                warn!(%error, %to, "ssu2 pool: send_to failed");
            }
        }
    }
    debug!("ssu2 pool: task stopped");
}

/// `AddressBlock` из адреса, каким его видит сервер (i2pd `CreateAddressBlock`).
const fn address_block(from: SocketAddr) -> AddressBlock {
    AddressBlock {
        port: from.port(),
        ip: from.ip(),
    }
}

/// Ищет SSU2-адрес в `RouterInfo` (сначала семейства `prefer_v6`, затем
/// другого).
///
/// Возвращает в том числе неопубликованный адрес — он всё равно несёт `s=`/`i=`
/// (нужны для рукопожатия), — поэтому проверку «есть куда подключаться» делает
/// вызывающий (см. [`is_reachable_address`]).
///
/// # Errors
///
/// [`I2PError::Malformed`], если SSU2-адреса нет вовсе.
fn find_ssu2_address(ri: &FullRouterInfo, prefer_v6: bool) -> Result<&I2PAddress> {
    let usable = |addr: &&I2PAddress| addr.is_ssu2();
    ri.body()
        .ssu2_address(prefer_v6)
        .filter(usable)
        .or_else(|| ri.body().ssu2_address(!prefer_v6).filter(usable))
        .ok_or(I2PError::Malformed(
            "ssu2 pool: no SSU2 address in remote RouterInfo",
        ))
}

/// Можно ли подключаться по этому адресу: опубликован, с хостом и портом.
const fn is_reachable_address(addr: &I2PAddress) -> bool {
    addr.published && !addr.host.is_unspecified() && addr.port != 0
}

/// Текущее время — миллисекунды since epoch (как i2pd
/// `GetMillisecondsSinceEpoch`).
///
/// Масштаб именно epoch, а не монотонное время с запуска: по нему сессия ведёт
/// `m_LastActivityTimestamp`, а [`crate::ssu2_engine`] сравнивает его с
/// expiration I2NP-сообщений (`SSU2Session::HandleI2NPMsg`).
fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Секунды и миллисекунды since epoch (i2pd `GetSecondsSinceEpoch` /
/// `GetMillisecondsSinceEpoch`).
fn unix_now() -> (u64, u32) {
    let elapsed = now();
    (
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX),
    )
}

/// Микросекунды (лаг очереди отправки).
fn micros(now: Duration) -> u64 {
    u64::try_from(now.as_micros()).unwrap_or(u64::MAX)
}

/// Миллисекунды из `Duration` (сверка `timestamp` `RouterInfo` с `now`).
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Секунды из `Duration` (для токенов).
fn secs_u32(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}
