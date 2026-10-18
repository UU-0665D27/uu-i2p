//! Пул NTCP2-сессий: исходящие, входящие и таймеры.
//!
//! Каждая сессия после handshake'а живёт в одной `tokio::spawn`-задаче:
//! она читает фреймы, отправляет I2NP/`RouterInfo` из канала и сама
//! убирает себя из пула, когда соединение кончилось. Пул хранит только
//! хэндл с `mpsc::Sender` — вызывающий не блокируется на I/O. Принятые
//! I2NP-сообщения и RI со всех сессий идут в общий `incoming_rx`.
//!
//! ## Разделение обязанностей
//!
//! - [`Ntcp2Pool`] — управление сессиями: `listen`, подключение, отправка,
//!   получение, закрытие. **Не** знает про netDb и I2NP-диспетчеризацию.
//! - [`crate::router::Router`] / [`crate::router_context::RouterContext`] —
//!   держат пул и netDb, обрабатывают `DatabaseStore` / `DatabaseLookup`.
//!
//! Зеркалит `NTCP2Server`/`NTCP2Session` из i2pd, включая разделение
//! «один listener — много сессий» и серверный таймер терминации.
//!
//! ## События
//!
//! [`PoolEvent`] — зеркало [`crate::ssu2_pool::Ssu2Event`]:
//! `Established` (handshake завершён), `Message`, `RouterInfo` (peer
//! прислал свой RI) и `Disconnected` (ровно один раз на сессию). Роутер по
//! ним ведёт свою карту `ident → транспорт` (i2pd `Transports::PeerConnected`
//! / `PeerDisconnected`).
//!
//! ## Закрытие
//!
//! [`Ntcp2Pool::remove_session`] не просто рвёт сокет: сессии уходит
//! команда отправить `Termination(NormalClose)` (i2pd
//! `NTCP2Session::SendTermination`), после чего TCP закрывается. Ждём
//! подтверждения отправки не дольше [`CLOSE_FLUSH_TIMEOUT`]: обрыв важнее
//! красивости. Приём `Termination` от peer'а — тоже `Disconnected`, без
//! ответного `Termination` (i2pd в `ProcessNextMessage` просто
//! терминирует сессию).
//!
//! ## Таймеры
//!
//! Их ведёт одна задача обслуживания (i2pd `NTCP2Server::HandleTerminationTimer`
//! раз в `NTCP2_TERMINATION_CHECK_TIMEOUT` ± вариант):
//!
//! - **idle** — если от peer'а ничего не приходило дольше
//!   `NTCP2_TERMINATION_TIMEOUT` ± вариант, сессия получает
//!   `Termination(IdleTimeout)` и завершается (i2pd
//!   `NTCP2Session::TerminateByTimeout`);
//! - **повтор своего `RouterInfo`** — раз в
//!   `NTCP2_ROUTERINFO_RESEND_INTERVAL` ± вариант (i2pd
//!   `NTCP2Session::SendLocalRouterInfo(update = true)`).
//!
//! Значения вынесены в [`Ntcp2Timers`], чтобы тесты не ждали 2 минуты.
//!
//! ## Приём (accept-loop)
//!
//! [`Ntcp2Pool::listen`] поднимает задачу-приёмник: `accept()` → проверка
//! источника (`IsInReservedRange`, i2pd `NTCP2Server::HandleAccept`) →
//! `Ntcp2Session::accept` с таймаутом `NTCP2_ESTABLISH_TIMEOUT` →
//! [`Ntcp2Pool`]-сессия. Одна `pending`-сессия на IP, как у i2pd.
//!
//! ## Модель многозадачности
//!
//! Все методы `Ntcp2Pool` берут `&self`. Состояние защищено `RwLock`, а
//! I/O сессии — в её собственной задаче. Пока идёт запись, чтение этой же
//! сессии ждёт (одна задача на сессию): для I2NP-сообщений это
//! микросекунды, зато нет гонки двух половин за закрытие и события. Это
//! осознанное отличие от SSU2-пула, где один таск владеет **всеми**
//! сессиями одного UDP-сокета.
//!
//! ## Что НЕ реализовано
//!
//! - **Post-quantum варианты** (v3/4/5): `Ntcp2Session` отвечает
//!   `Unsupported` на запрос ML-KEM — как i2pd с `ntcp2.version = 2`.
//! - **Бан-лист и лимиты** (`NTCP2Server::m_PendingIncomingSessions` по
//!   адресу у нас есть, общий `Transports::Ban` — нет).
//! - **Reconnect при разрыве**: следующий `send_to` вернёт ошибку,
//!   решение о переподключении — на роутере.

use crate::{
    IdentHash,
    error::{I2PError, Result},
    i2np_message::I2npMessage,
    ntcp2::{
        NTCP2_ESTABLISH_TIMEOUT_SECS, NTCP2_ROUTERINFO_RESEND_INTERVAL_SECS,
        NTCP2_ROUTERINFO_RESEND_INTERVAL_VARIANCE_SECS, NTCP2_TERMINATION_CHECK_TIMEOUT_SECS,
        NTCP2_TERMINATION_CHECK_TIMEOUT_VARIANCE_SECS, NTCP2_TERMINATION_TIMEOUT_SECS,
        NTCP2_TERMINATION_TIMEOUT_VARIANCE_SECS, Ntcp2Block, Ntcp2Local, Ntcp2LocalConfig,
        Ntcp2Session, Ntcp2SessionRead, Ntcp2SessionWrite, Ntcp2TerminationReason,
    },
    router_info::FullRouterInfo,
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex, RwLock as StdRwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock, mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, warn};

/// Размер буфера исходящих I2NP-сообщений на одну сессию.
const SESSION_OUTBOUND_QUEUE: usize = 64;
/// Размер общего буфера событий «пул → вызывающий».
const POOL_INCOMING_QUEUE: usize = 256;
/// Сколько ждём, пока write-половина вытолкнет `Termination` при закрытии.
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(3);

// --- тайминги ------------------------------------------------------------

/// Тайминги пула. Значения по умолчанию — из i2pd (`NTCP2.h`); вынесены
/// в структуру, чтобы тесты не ждали минутами.
#[derive(Debug, Clone, Copy)]
pub struct Ntcp2Timers {
    /// Сколько ждём handshake входящего соединения
    /// (`NTCP2_ESTABLISH_TIMEOUT`).
    pub establish_timeout: Duration,
    /// Таймаут бездействия установленной сессии
    /// (`NTCP2_TERMINATION_TIMEOUT`).
    pub termination_timeout: Duration,
    /// Разброс таймаута бездействия
    /// (`NTCP2_TERMINATION_TIMEOUT_VARIANCE`).
    pub termination_timeout_variance: Duration,
    /// Период фоновой проверки сессий
    /// (`NTCP2_TERMINATION_CHECK_TIMEOUT`).
    pub termination_check_interval: Duration,
    /// Разброс периода проверки
    /// (`NTCP2_TERMINATION_CHECK_TIMEOUT_VARIANCE`).
    pub termination_check_interval_variance: Duration,
    /// Интервал повтора своего `RouterInfo`
    /// (`NTCP2_ROUTERINFO_RESEND_INTERVAL`).
    pub router_info_resend_interval: Duration,
    /// Разброс интервала повтора `RouterInfo`
    /// (`NTCP2_ROUTERINFO_RESEND_INTERVAL_VARIANCE`).
    pub router_info_resend_variance: Duration,
}

impl Default for Ntcp2Timers {
    fn default() -> Self {
        Self {
            establish_timeout: Duration::from_secs(NTCP2_ESTABLISH_TIMEOUT_SECS),
            termination_timeout: Duration::from_secs(NTCP2_TERMINATION_TIMEOUT_SECS),
            termination_timeout_variance: Duration::from_secs(
                NTCP2_TERMINATION_TIMEOUT_VARIANCE_SECS,
            ),
            termination_check_interval: Duration::from_secs(NTCP2_TERMINATION_CHECK_TIMEOUT_SECS),
            termination_check_interval_variance: Duration::from_secs(
                NTCP2_TERMINATION_CHECK_TIMEOUT_VARIANCE_SECS,
            ),
            router_info_resend_interval: Duration::from_secs(NTCP2_ROUTERINFO_RESEND_INTERVAL_SECS),
            router_info_resend_variance: Duration::from_secs(
                NTCP2_ROUTERINFO_RESEND_INTERVAL_VARIANCE_SECS,
            ),
        }
    }
}

// --- команды и хэндлы ----------------------------------------------------

/// Команда задаче сессии.
enum SessionCommand {
    /// Отправить I2NP-сообщение.
    Message(I2npMessage),
    /// Отправить (или повторить) свой `RouterInfo` из
    /// [`Shared::local_ri`]; i2pd `SendLocalRouterInfo(true)`.
    SendRouterInfo,
    /// Отправить `Termination(reason)` и завершиться. `ack` — сигнал,
    /// что кадр ушёл в сокет (или отправка провалилась).
    Close {
        /// Подтверждение отправки `Termination`.
        ack: oneshot::Sender<()>,
        /// Причина терминации.
        reason: Ntcp2TerminationReason,
    },
}

/// Хэндл одной активной сессии.
struct SessionHandle {
    /// Уникальный номер сессии: по нему задача при выходе понимает, что
    /// в карте всё ещё **её** запись, а не вытеснившая её новая.
    token: u64,
    /// Канал команд задаче сессии.
    tx: mpsc::Sender<SessionCommand>,
    /// Задача сессии (для abort при удалении).
    join: JoinHandle<()>,
    /// Время последней активности (мс с epoch) — для idle-таймаута.
    last_activity_ms: Arc<AtomicU64>,
    /// Когда снова отправить свой `RouterInfo` (мс с epoch).
    next_router_info_ms: Arc<AtomicU64>,
    /// Персональный таймаут бездействия этой сессии (i2pd ставит его при
    /// установлении: `NTCP2_TERMINATION_TIMEOUT` + вариант).
    termination_timeout_ms: u64,
}

/// Событие от peer'а или о состоянии сессии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolEvent {
    /// Handshake завершён, data phase готова.
    Established {
        /// С кем.
        ident: IdentHash,
    },
    /// Принято I2NP-сообщение.
    Message {
        /// От кого.
        from: IdentHash,
        /// Само сообщение.
        message: I2npMessage,
    },
    /// Peer прислал свой `RouterInfo`. Caller может положить его в netDb.
    RouterInfo {
        /// От кого.
        from: IdentHash,
        /// Сырые байты RI.
        ri_bytes: Vec<u8>,
    },
    /// Сессия завершена (ровно одно событие на сессию).
    Disconnected {
        /// С кем.
        ident: IdentHash,
    },
}

// --- общее состояние пула ------------------------------------------------

/// Состояние, разделяемое пулом и задачами сессий.
struct Shared {
    /// Активные сессии.
    sessions: RwLock<HashMap<IdentHash, SessionHandle>>,
    /// Общий канал событий «пул → вызывающий».
    events: mpsc::Sender<PoolEvent>,
    /// Локальная идентичность NTCP2 (ключи, IV, `netId`); задаётся
    /// транспортом через [`Ntcp2Pool::set_local`] и не меняется.
    /// `std`-блокировка: её держат только на время клонирования `Arc`.
    local: StdMutex<Option<Arc<Ntcp2Local>>>,
    /// Текущий свой `RouterInfo` (обновляется
    /// [`Ntcp2Pool::set_router_info`]). `std`-блокировка: её держат только
    /// на время копирования байтов.
    local_ri: StdRwLock<Vec<u8>>,
    /// Счётчик номеров сессий.
    next_token: AtomicU64,
}

/// Пул NTCP2-сессий.
pub struct Ntcp2Pool {
    shared: Arc<Shared>,
    incoming_rx: Mutex<mpsc::Receiver<PoolEvent>>,
    /// Задача-приёмник (если поднят `listen`).
    listener: StdMutex<Option<JoinHandle<()>>>,
    /// Задача таймеров (idle, повтор RI).
    maintenance: StdMutex<Option<JoinHandle<()>>>,
    timers: Ntcp2Timers,
}

impl Ntcp2Pool {
    /// Создаёт пустой пул с таймингами i2pd.
    #[must_use]
    pub fn new() -> Self {
        Self::with_timers(Ntcp2Timers::default())
    }

    /// Пул с нестандартными таймингами (тесты).
    #[must_use]
    pub fn with_timers(timers: Ntcp2Timers) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(POOL_INCOMING_QUEUE);
        Self {
            shared: Arc::new(Shared {
                sessions: RwLock::new(HashMap::new()),
                events: incoming_tx,
                local: StdMutex::new(None),
                local_ri: StdRwLock::new(Vec::new()),
                next_token: AtomicU64::new(1),
            }),
            incoming_rx: Mutex::new(incoming_rx),
            listener: StdMutex::new(None),
            maintenance: StdMutex::new(None),
            timers,
        }
    }

    /// Задаёт локальную идентичность NTCP2 (ключи, IV, `netId`).
    ///
    /// Свой `RouterInfo` берётся из самой [`Ntcp2Local`] лишь пока не
    /// задан [`Self::set_router_info`].
    pub fn set_local(&self, local: Arc<Ntcp2Local>) {
        self.set_router_info_if_empty(local.router_info().to_vec());
        *lock(&self.shared.local) = Some(local);
    }

    /// Текущая локальная идентичность.
    #[must_use]
    pub fn local(&self) -> Option<Arc<Ntcp2Local>> {
        lock(&self.shared.local).clone()
    }

    /// Обновляет свой `RouterInfo` (после пересборки в `RouterContext`).
    ///
    /// Сессиям его доставит ближайший плановый повтор
    /// ([`Self::timers`] → `SendRouterInfo`); в i2pd то же
    /// `NTCP2Session::SendLocalRouterInfo(update = true)`.
    pub fn set_router_info(&self, ri_bytes: Vec<u8>) {
        *write_guard(&self.shared.local_ri) = ri_bytes;
    }

    /// Кладёт RI, только если ещё ничего не положили.
    fn set_router_info_if_empty(&self, ri_bytes: Vec<u8>) {
        let mut guard = write_guard(&self.shared.local_ri);
        if guard.is_empty() {
            *guard = ri_bytes;
        }
    }

    /// Число активных сессий.
    pub async fn len(&self) -> usize {
        self.shared.sessions.read().await.len()
    }

    /// Пул пуст?
    pub async fn is_empty(&self) -> bool {
        self.shared.sessions.read().await.is_empty()
    }

    /// Есть ли сессия с `ident`.
    pub async fn has_session(&self, ident: &IdentHash) -> bool {
        self.shared.sessions.read().await.contains_key(ident)
    }

    /// Поднимает приём входящих соединений на уже открытом listener'е.
    ///
    /// i2pd `NTCP2Server::Start` + `HandleAccept`: источник проверяется на
    /// `IsInReservedRange` (если [`Ntcp2Local::accept_reserved`] выключен),
    /// handshake ограничен `establish_timeout`, на один IP — не больше
    /// одной «ожидающей» сессии.
    ///
    /// # Errors
    ///
    /// - [`I2PError::Unsupported`] — локальная идентичность не задана
    ///   ([`Self::set_local`]);
    /// - [`I2PError::Malformed`] — приём уже поднят.
    pub fn listen(&self, listener: TcpListener) -> Result<()> {
        let local = self.local().ok_or(I2PError::Unsupported(
            "ntcp2 pool: listen без локальной идентичности (Ntcp2Local)",
        ))?;
        {
            let mut slot = lock(&self.listener);
            if slot.is_some() {
                return Err(I2PError::Malformed("ntcp2 pool: приём уже поднят"));
            }
            let shared = Arc::clone(&self.shared);
            let timers = self.timers;
            *slot = Some(tokio::spawn(run_listener(listener, local, shared, timers)));
        }
        self.ensure_maintenance();
        Ok(())
    }

    /// Устанавливает NTCP2-сессию с удалённым роутером по адресу из его RI.
    ///
    /// Если сессия с таким `IdentHash` уже есть — возвращает её
    /// `IdentHash` без переустановки.
    ///
    /// # Errors
    ///
    /// - [`I2PError::Unsupported`] — локальная идентичность не задана;
    /// - [`I2PError::Malformed`] — в `remote_ri_bytes` нет NTCP2-адреса;
    /// - [`I2PError::Io`] — ошибка TCP;
    /// - ошибки handshake'а.
    pub async fn connect(&self, remote_ri_bytes: &[u8]) -> Result<IdentHash> {
        let remote_ri = FullRouterInfo::from_buffer(remote_ri_bytes)?;
        let addr = find_ntcp2_address(&remote_ri)?;
        let socket_addr = SocketAddr::new(addr.host, addr.port);
        self.connect_to(remote_ri_bytes, socket_addr).await
    }

    /// То же, но TCP-адрес задан явно (тесты, localhost, NAT).
    ///
    /// Handshake по-прежнему берёт `s`/`i`/`ident` из `remote_ri_bytes`:
    /// подменяется только точка подключения, как и у
    /// [`crate::ssu2_pool::Ssu2Pool::connect_to`].
    ///
    /// # Errors
    ///
    /// См. [`Self::connect`].
    pub async fn connect_to(&self, remote_ri_bytes: &[u8], addr: SocketAddr) -> Result<IdentHash> {
        let remote_ri = FullRouterInfo::from_buffer(remote_ri_bytes)?;
        let remote_ident = *remote_ri.ident_hash();

        // Ранний выход: сессия уже открыта (i2pd `AddNTCP2Session` для
        // исходящей отвергает новую — у нас просто не звоним).
        if self
            .shared
            .sessions
            .read()
            .await
            .contains_key(&remote_ident)
        {
            debug!(peer = %remote_ident.to_base64(), "ntcp2 pool: сессия уже есть");
            return Ok(remote_ident);
        }

        let local = self.local().ok_or(I2PError::Unsupported(
            "ntcp2 pool: connect без локальной идентичности (Ntcp2Local)",
        ))?;
        let ri = read_guard(&self.shared.local_ri).clone();
        let cfg = local_config(&local, &ri);

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| I2PError::Io(format!("ntcp2 pool: connect {addr}: {e}")))?;
        let session = Ntcp2Session::connect(stream, &cfg, remote_ri_bytes).await?;
        let ident = IdentHash::from_array(*session.remote_ident_hash());
        debug_assert_eq!(ident, remote_ident);
        debug!(peer = %ident.to_base64(), %addr, "ntcp2 pool: сессия установлена (Alice)");

        self.ensure_maintenance();
        Ok(install_session(&self.shared, self.timers, session).await)
    }

    /// Отправляет I2NP-сообщение пиру. Требует существующей сессии.
    ///
    /// # Errors
    ///
    /// - [`I2PError::Malformed`] — нет сессии с таким `IdentHash`;
    /// - [`I2PError::Io`] — задача сессии уже остановлена.
    pub async fn send_to(&self, ident: &IdentHash, msg: I2npMessage) -> Result<()> {
        let tx = {
            let sessions = self.shared.sessions.read().await;
            sessions
                .get(ident)
                .map(|h| h.tx.clone())
                .ok_or(I2PError::Malformed("ntcp2 pool: no session for peer"))?
        };
        tx.send(SessionCommand::Message(msg))
            .await
            .map_err(|_| I2PError::Io("ntcp2 pool: session write channel closed".into()))
    }

    /// Ждёт следующего события от **любой** сессии.
    ///
    /// # Errors
    ///
    /// [`I2PError::Io`], если канал приёма закрыт (это значит, что все
    /// sender'ы дропнуты — обычно потому что [`Self`] дропнут).
    pub async fn next_event(&self) -> Result<PoolEvent> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| I2PError::Io("ntcp2 pool: incoming channel closed".into()))
    }

    /// Закрывает сессию: `Termination(NormalClose)`, затем обрыв.
    ///
    /// `false` — сессии не было (или она уже завершилась сама, и событие
    /// `Disconnected` пришло раньше). Событие `Disconnected` отправляется
    /// ровно один раз — либо задачей сессии, либо здесь.
    pub async fn remove_session(&self, ident: &IdentHash) -> bool {
        let Some(handle) = self.shared.sessions.write().await.remove(ident) else {
            return false;
        };

        // Просим отправить Termination и ждём подтверждения с таймаутом.
        let (ack_tx, ack_rx) = oneshot::channel();
        if handle
            .tx
            .send(SessionCommand::Close {
                ack: ack_tx,
                reason: Ntcp2TerminationReason::NormalClose,
            })
            .await
            .is_ok()
            && tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, ack_rx)
                .await
                .is_err()
        {
            debug!(peer = %ident.to_base64(), "ntcp2 pool: Termination не успел уйти");
        }
        handle.join.abort();

        let _ = self
            .shared
            .events
            .send(PoolEvent::Disconnected { ident: *ident })
            .await;
        true
    }

    /// Удаляет сессии, чьи задачи завершились, но почему-то остались в
    /// карте (например, задача паниковала). Обычно сессия убирает себя
    /// сама.
    pub async fn cleanup_dead(&self) {
        let mut sessions = self.shared.sessions.write().await;
        let stale: Vec<IdentHash> = sessions
            .iter()
            .filter(|(_, h)| h.join.is_finished())
            .map(|(ident, _)| *ident)
            .collect();
        for ident in stale {
            sessions.remove(&ident);
            debug!(peer = %ident.to_base64(), "ntcp2 pool: убрана завершившаяся сессия");
        }
        drop(sessions);
    }

    /// Список `IdentHash` активных сессий.
    pub async fn session_idents(&self) -> Vec<IdentHash> {
        self.shared.sessions.read().await.keys().copied().collect()
    }

    /// Запускает задачу таймеров, если её ещё нет.
    fn ensure_maintenance(&self) {
        let mut slot = lock(&self.maintenance);
        if slot.is_none() {
            *slot = Some(tokio::spawn(run_maintenance(
                Arc::clone(&self.shared),
                self.timers,
            )));
        }
    }
}

impl Default for Ntcp2Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Ntcp2Pool {
    fn drop(&mut self) {
        // `abort` не блокирует; `JoinHandle` сам почистит ресурсы
        // при следующей попытке `poll`. `OwnedWriteHalf`/`OwnedReadHalf`
        // закроют сокет при drop.
        let listener = lock(&self.listener).take();
        if let Some(listener) = listener {
            listener.abort();
        }
        let maintenance = lock(&self.maintenance).take();
        if let Some(maintenance) = maintenance {
            maintenance.abort();
        }
        if let Ok(mut sessions) = self.shared.sessions.try_write() {
            for (_, h) in sessions.drain() {
                h.join.abort();
            }
        }
    }
}

impl std::fmt::Debug for Ntcp2Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ntcp2Pool")
            .field("sessions", &"<async>")
            .field("timers", &self.timers)
            .finish_non_exhaustive()
    }
}

// --- приём входящих ------------------------------------------------------

/// Задача-приёмник: `accept()` → handshake → [`install_session`].
async fn run_listener(
    listener: TcpListener,
    local: Arc<Ntcp2Local>,
    shared: Arc<Shared>,
    timers: Ntcp2Timers,
) {
    // i2pd `m_PendingIncomingSessions`: не больше одной «ожидающей»
    // сессии на IP-адрес.
    let pending: Arc<Mutex<HashSet<IpAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                warn!(%error, "ntcp2 pool: ошибка accept");
                continue;
            }
        };
        if !local.accept_reserved() && is_reserved_range(peer.ip()) {
            debug!(%peer, "ntcp2 pool: входящее с reserved-адреса отвергнуто");
            continue;
        }
        if !pending.lock().await.insert(peer.ip()) {
            debug!(%peer, "ntcp2 pool: входящее с этого адреса уже устанавливается");
            continue;
        }

        let local = Arc::clone(&local);
        let shared = Arc::clone(&shared);
        let pending = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Err(error) = stream.set_nodelay(true) {
                debug!(%peer, %error, "ntcp2 pool: не удалось выставить TCP_NODELAY");
            }
            let session = {
                let ri = read_guard(&shared.local_ri).clone();
                let cfg = local_config(&local, &ri);
                tokio::time::timeout(timers.establish_timeout, Ntcp2Session::accept(stream, &cfg))
                    .await
            };
            pending.lock().await.remove(&peer.ip());
            match session {
                Ok(Ok(session)) => {
                    debug!(%peer, "ntcp2 pool: входящая сессия установлена (Bob)");
                    install_session(&shared, timers, session).await;
                }
                Ok(Err(error)) => {
                    debug!(%peer, %error, "ntcp2 pool: handshake входящей сессии не сошёлся");
                }
                Err(_) => {
                    debug!(%peer, "ntcp2 pool: таймаут handshake входящей сессии");
                }
            }
        });
    }
}

/// Собирает [`Ntcp2LocalConfig`] из идентичности и текущего RI.
const fn local_config<'a>(local: &'a Ntcp2Local, ri: &'a [u8]) -> Ntcp2LocalConfig<'a> {
    Ntcp2LocalConfig {
        static_keys: local.static_keys(),
        ident_hash: *local.ident_hash(),
        iv: *local.iv(),
        ri_bytes: ri,
        net_id: local.net_id(),
    }
}

// --- установка и обслуживание сессий -------------------------------------

/// Регистрирует установленную сессию и запускает её задачу.
///
/// Если сессия с таким `ident` уже есть — вытесняет её (i2pd
/// `AddNTCP2Session` для входящей: «Replaced»; наш `connect_to` до этого
/// не доходит, если сессия уже есть).
async fn install_session(
    shared: &Arc<Shared>,
    timers: Ntcp2Timers,
    session: Ntcp2Session,
) -> IdentHash {
    let ident = IdentHash::from_array(*session.remote_ident_hash());
    let previous = shared.sessions.write().await.remove(&ident);
    if let Some(previous) = previous {
        debug!(peer = %ident.to_base64(), "ntcp2 pool: прежняя сессия вытеснена");
        previous.join.abort();
        let _ = shared.events.send(PoolEvent::Disconnected { ident }).await;
    }

    let token = shared.next_token.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel::<SessionCommand>(SESSION_OUTBOUND_QUEUE);
    let (read, write) = session.split();
    let now = now_ms();
    let last_activity_ms = Arc::new(AtomicU64::new(now));
    let next_router_info_ms = Arc::new(AtomicU64::new(
        now.saturating_add(millis(timers.router_info_resend_interval)),
    ));
    let termination_timeout_ms = millis(timers.termination_timeout)
        .saturating_add(random_below(millis(timers.termination_timeout_variance)));

    // Задача не должна успеть убрать запись раньше, чем мы её вставим.
    let (start_tx, start_rx) = oneshot::channel::<()>();
    let join = tokio::spawn(run_session(
        ident,
        token,
        Arc::clone(shared),
        read,
        write,
        rx,
        Arc::clone(&last_activity_ms),
        start_rx,
    ));

    shared.sessions.write().await.insert(
        ident,
        SessionHandle {
            token,
            tx,
            join,
            last_activity_ms,
            next_router_info_ms,
            termination_timeout_ms,
        },
    );
    let _ = shared.events.send(PoolEvent::Established { ident }).await;
    let _ = start_tx.send(());
    ident
}

/// Тело задачи сессии: читает фреймы, отправляет команды, выходит на
/// `Termination`/ошибке/закрытии канала.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    ident: IdentHash,
    token: u64,
    shared: Arc<Shared>,
    mut read: Ntcp2SessionRead,
    mut write: Ntcp2SessionWrite,
    mut rx: mpsc::Receiver<SessionCommand>,
    last_activity_ms: Arc<AtomicU64>,
    start_rx: oneshot::Receiver<()>,
) {
    let _ = start_rx.await;
    loop {
        tokio::select! {
            frame = read.read_frame() => {
                let blocks = match frame {
                    Ok(blocks) => blocks,
                    Err(error) => {
                        debug!(peer = %ident.to_base64(), %error, "ntcp2 pool: чтение завершено");
                        break;
                    }
                };
                last_activity_ms.store(now_ms(), Ordering::Relaxed);
                let mut stop = false;
                for block in blocks {
                    let event = match block {
                        Ntcp2Block::I2npMessage(bytes) => match I2npMessage::from_ntcp2_bytes(&bytes) {
                            Ok(message) => Some(PoolEvent::Message { from: ident, message }),
                            Err(error) => {
                                warn!(peer = %ident.to_base64(), %error, "ntcp2 pool: I2NP не разобрался");
                                None
                            }
                        },
                        Ntcp2Block::RouterInfo { ri_bytes, .. } => {
                            Some(PoolEvent::RouterInfo { from: ident, ri_bytes })
                        }
                        Ntcp2Block::Termination { reason, seqn } => {
                            debug!(
                                peer = %ident.to_base64(),
                                ?reason,
                                seqn,
                                "ntcp2 pool: peer terminated"
                            );
                            stop = true;
                            None
                        }
                        Ntcp2Block::DateTime { .. }
                        | Ntcp2Block::Options(_)
                        | Ntcp2Block::Padding(_) => None,
                    };
                    if let Some(event) = event
                        && shared.events.send(event).await.is_err()
                    {
                        debug!(peer = %ident.to_base64(), "ntcp2 pool: канал событий закрыт");
                        stop = true;
                    }
                }
                if stop {
                    break;
                }
            }
            command = rx.recv() => match command {
                Some(SessionCommand::Message(message)) => {
                    if let Err(error) = write.send_i2np(&message).await {
                        debug!(peer = %ident.to_base64(), %error, "ntcp2 pool: запись завершена");
                        break;
                    }
                }
                Some(SessionCommand::SendRouterInfo) => {
                    let ri = read_guard(&shared.local_ri).clone();
                    if ri.is_empty() {
                        debug!(peer = %ident.to_base64(), "ntcp2 pool: свой RI ещё не задан");
                    } else if let Err(error) = write.send_router_info(&ri).await {
                        debug!(peer = %ident.to_base64(), %error, "ntcp2 pool: повтор RI не ушёл");
                        break;
                    }
                }
                Some(SessionCommand::Close { ack, reason }) => {
                    if let Err(error) = write.send_termination(reason).await {
                        debug!(peer = %ident.to_base64(), %error, "ntcp2 pool: Termination не ушёл");
                    }
                    let _ = ack.send(());
                    debug!(peer = %ident.to_base64(), ?reason, "ntcp2 pool: сессия закрыта локально");
                    break;
                }
                None => {
                    debug!(peer = %ident.to_base64(), "ntcp2 pool: пул отпустил сессию");
                    break;
                }
            },
        }
    }
    finish_session(&shared, ident, token).await;
}

/// Убирает свою запись из карты и сообщает `Disconnected`.
///
/// Запись убирается, только если она всё ещё «наша» (`token`): сессию
/// могло вытеснить новое входящее соединение с тем же `ident`.
async fn finish_session(shared: &Shared, ident: IdentHash, token: u64) {
    let mut sessions = shared.sessions.write().await;
    let ours = sessions.get(&ident).is_some_and(|h| h.token == token);
    if ours {
        sessions.remove(&ident);
    }
    drop(sessions);
    if ours {
        let _ = shared.events.send(PoolEvent::Disconnected { ident }).await;
    }
}

/// Задача таймеров: idle-терминация и повтор своего `RouterInfo`.
///
/// i2pd `NTCP2Server::HandleTerminationTimer` + `ScheduleTermination`.
async fn run_maintenance(shared: Arc<Shared>, timers: Ntcp2Timers) {
    loop {
        let interval = millis(timers.termination_check_interval).saturating_add(random_below(
            millis(timers.termination_check_interval_variance),
        ));
        tokio::time::sleep(Duration::from_millis(interval)).await;

        let now = now_ms();
        let entries: Vec<MaintenanceEntry> = {
            let sessions = shared.sessions.read().await;
            sessions
                .iter()
                .map(|(ident, handle)| MaintenanceEntry {
                    ident: *ident,
                    tx: handle.tx.clone(),
                    last_activity_ms: Arc::clone(&handle.last_activity_ms),
                    next_router_info_ms: Arc::clone(&handle.next_router_info_ms),
                    termination_timeout_ms: handle.termination_timeout_ms,
                })
                .collect()
        };

        for entry in entries {
            let idle = now.saturating_sub(entry.last_activity_ms.load(Ordering::Relaxed));
            if idle >= entry.termination_timeout_ms {
                debug!(
                    peer = %entry.ident.to_base64(),
                    timeout_ms = entry.termination_timeout_ms,
                    "ntcp2 pool: нет активности — Termination"
                );
                let (ack, _rx) = oneshot::channel();
                let _ = entry
                    .tx
                    .send(SessionCommand::Close {
                        ack,
                        reason: Ntcp2TerminationReason::IdleTimeout,
                    })
                    .await;
            } else if now >= entry.next_router_info_ms.load(Ordering::Relaxed) {
                debug!(peer = %entry.ident.to_base64(), "ntcp2 pool: повтор своего RouterInfo");
                let _ = entry.tx.send(SessionCommand::SendRouterInfo).await;
                entry.next_router_info_ms.store(
                    now.saturating_add(
                        millis(timers.router_info_resend_interval).saturating_add(random_below(
                            millis(timers.router_info_resend_variance),
                        )),
                    ),
                    Ordering::Relaxed,
                );
            }
        }
    }
}

/// Снимок таймеров сессии для задачи обслуживания.
struct MaintenanceEntry {
    ident: IdentHash,
    tx: mpsc::Sender<SessionCommand>,
    last_activity_ms: Arc<AtomicU64>,
    next_router_info_ms: Arc<AtomicU64>,
    termination_timeout_ms: u64,
}

// --- утилиты -------------------------------------------------------------

/// Ищет опубликованный NTCP2-адрес в RI. Дублирует логику из
/// `ntcp2.rs`, но здесь нужен именно `Result`, а не `Option` — чтобы
/// дать точную ошибку.
fn find_ntcp2_address(ri: &FullRouterInfo) -> Result<&crate::router_info_address::I2PAddress> {
    ri.body()
        .addresses
        .iter()
        .find(|a| a.is_ntcp2() && a.published && !a.host.is_unspecified() && a.port != 0)
        .ok_or(I2PError::Malformed(
            "ntcp2 pool: no published NTCP2 address in remote RI",
        ))
}

/// Адрес из reserved-диапазона (i2pd `i2p::util::net::IsInReservedRange`).
///
/// Отличие от i2pd одно: у него опечатка в границе диапазона
/// `198.18.0.0/15` — верхняя граница `192.19.255.255` меньше нижней, из-за
/// чего диапазон не срабатывает никогда (см. `notes/i2pd-bugs.md`). Здесь
/// граница правильная (`198.19.255.255`).
fn is_reserved_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_reserved_v4(v4),
        IpAddr::V6(v6) => is_reserved_v6(v6),
    }
}

/// IPv4-диапазоны, которые i2pd считает reserved.
fn is_reserved_v4(ip: Ipv4Addr) -> bool {
    const RANGES: &[(&[u8; 4], &[u8; 4])] = &[
        (b"\x00\x00\x00\x00", b"\x00\xff\xff\xff"),
        (b"\x0a\x00\x00\x00", b"\x0a\xff\xff\xff"),
        (b"\x64\x40\x00\x00", b"\x64\x7f\xff\xff"),
        (b"\x7f\x00\x00\x00", b"\x7f\xff\xff\xff"),
        (b"\xa9\xfe\x00\x00", b"\xa9\xfe\xff\xff"),
        (b"\xac\x10\x00\x00", b"\xac\x1f\xff\xff"),
        (b"\xc0\x00\x00\x00", b"\xc0\x00\x00\xff"),
        (b"\xc0\x00\x02\x00", b"\xc0\x00\x02\xff"),
        (b"\xc0\x58\x63\x00", b"\xc0\x58\x63\xff"),
        (b"\xc0\xa8\x00\x00", b"\xc0\xa8\xff\xff"),
        (b"\xc6\x12\x00\x00", b"\xc6\x13\xff\xff"),
        (b"\xc6\x33\x64\x00", b"\xc6\x33\x64\xff"),
        (b"\xcb\x00\x71\x00", b"\xcb\x00\x71\xff"),
        (b"\xe0\x00\x00\x00", b"\xff\xff\xff\xff"),
    ];
    if ip.is_unspecified() {
        return false;
    }
    let bytes = ip.octets();
    RANGES.iter().any(|(lo, hi)| bytes >= **lo && bytes <= **hi)
}

/// IPv6-диапазоны, которые i2pd считает reserved.
fn is_reserved_v6(ip: Ipv6Addr) -> bool {
    const RANGES: &[(&[u8; 16], &[u8; 16])] = &[
        // NAT64
        (
            b"\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x64\xff\x9b\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ),
        // документация
        (
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x20\x01\x0d\xb8\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ),
        // unique local
        (
            b"\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ),
        // link-local
        (
            b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\xfe\xbf\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ),
        // multicast
        (
            b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ),
        // unspecified и loopback
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        ),
        // IPv4-mapped
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff",
        ),
    ];
    let bytes = ip.octets();
    RANGES.iter().any(|(lo, hi)| bytes >= **lo && bytes <= **hi)
}

/// Миллисекунды с epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Длительность в миллисекундах (насыщением).
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Случайное число меньше `bound` (0 — если граница нулевая).
fn random_below(bound: u64) -> u64 {
    if bound == 0 {
        0
    } else {
        rand::random::<u64>() % bound
    }
}

/// Блокировка без паники при отравлении.
fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Чтение без паники при отравлении.
fn read_guard<T>(rwlock: &StdRwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    rwlock
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Запись без паники при отравлении.
fn write_guard<T>(rwlock: &StdRwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    rwlock
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
