//! Пул активных NTCP2-сессий.
//!
//! Каждая сессия после handshake'а живёт в одной `tokio::spawn`-задаче:
//! она читает фреймы, отправляет I2NP из канала и сама убирает себя из
//! пула, когда соединение кончилось. Пул хранит только хэндл с
//! `mpsc::Sender` — вызывающий не блокируется на I/O. Принятые
//! I2NP-сообщения и RI со всех сессий идут в общий `incoming_rx`.
//!
//! ## Разделение обязанностей
//!
//! - [`Ntcp2Pool`] — управление сессиями: подключение, отправка,
//!   получение, закрытие. **Не** знает про netDb и I2NP-диспетчеризацию.
//! - [`crate::router::Router`] / [`crate::router_context::RouterContext`] —
//!   держат пул и netDb, обрабатывают `DatabaseStore` / `DatabaseLookup`.
//!
//! ## События
//!
//! [`PoolEvent`] — зеркало [`crate::ssu2_pool::Ssu2Event`]:
//! `Established` (handshake завершён, у нас — сразу после
//! `SessionConfirmed`), `Message`, `RouterInfo` (peer прислал свой RI) и
//! `Disconnected` (ровно один раз на сессию). Роутер по ним ведёт свою
//! карту `ident → транспорт` (i2pd `Transports::PeerConnected` /
//! `PeerDisconnected`).
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
//! ## Модель многозадачности
//!
//! Все методы `Ntcp2Pool` берут `&self`. Состояние защищено
//! `tokio::sync::RwLock`, а I/O сессии — в её собственной задаче. Пока
//! идёт запись, чтение этой же сессии ждёт (одна задача на сессию): для
//! I2NP-сообщений это микросекунды, зато нет гонки двух половин за
//! закрытие и события. Это осознанное отличие от SSU2-пула, где один
//! таск владеет **всеми** сессиями одного UDP-сокета.
//!
//! ## Что НЕ реализовано
//!
//! - **Входящие сессии** (accept-loop): нужен шаг 3a-5 — listener и
//!   `Ntcp2Session::accept` в пуле.
//! - **Reconnect при разрыве**: следующий `send_to` вернёт ошибку,
//!   решение о переподключении — на роутере.
//! - **Ограничение размера пула**: см. `Ntcp2Server` в i2pd; здесь
//!   вызывающий сам чистит через [`Ntcp2Pool::remove_session`].

use crate::{
    IdentHash,
    error::{I2PError, Result},
    i2np_message::I2npMessage,
    ntcp2::{
        Ntcp2Block, Ntcp2LocalConfig, Ntcp2Session, Ntcp2SessionRead, Ntcp2SessionWrite,
        Ntcp2TerminationReason,
    },
    router_info::FullRouterInfo,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
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

/// Команда задаче сессии.
enum SessionCommand {
    /// Отправить I2NP-сообщение.
    Message(I2npMessage),
    /// Отправить `Termination(NormalClose)` и завершиться. `ack` — сигнал,
    /// что кадр ушёл в сокет (или отправка провалилась).
    Close {
        /// Подтверждение отправки `Termination`.
        ack: oneshot::Sender<()>,
    },
}

/// Хэндл одной активной сессии.
struct SessionHandle {
    /// Канал команд задаче сессии.
    tx: mpsc::Sender<SessionCommand>,
    /// Задача сессии (для abort при удалении).
    join: JoinHandle<()>,
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

/// Пул NTCP2-сессий.
pub struct Ntcp2Pool {
    sessions: Arc<RwLock<HashMap<IdentHash, SessionHandle>>>,
    incoming_tx: mpsc::Sender<PoolEvent>,
    incoming_rx: Mutex<mpsc::Receiver<PoolEvent>>,
}

impl Ntcp2Pool {
    /// Создаёт пустой пул.
    #[must_use]
    pub fn new() -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(POOL_INCOMING_QUEUE);
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
        }
    }

    /// Число активных сессий.
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Пул пуст?
    pub async fn is_empty(&self) -> bool {
        self.sessions.read().await.is_empty()
    }

    /// Есть ли сессия с `ident`.
    pub async fn has_session(&self, ident: &IdentHash) -> bool {
        self.sessions.read().await.contains_key(ident)
    }

    /// Устанавливает NTCP2-сессию с удалённым роутером по адресу из его RI.
    ///
    /// Если сессия с таким `IdentHash` уже есть — возвращает её
    /// `IdentHash` без переустановки.
    ///
    /// # Errors
    ///
    /// - [`I2PError::Malformed`] — в `remote_ri_bytes` нет NTCP2-адреса;
    /// - [`I2PError::Io`] — ошибка TCP;
    /// - ошибки handshake'а.
    pub async fn connect(
        &self,
        local: &Ntcp2LocalConfig<'_>,
        remote_ri_bytes: &[u8],
    ) -> Result<IdentHash> {
        let remote_ri = FullRouterInfo::from_buffer(remote_ri_bytes)?;
        let addr = find_ntcp2_address(&remote_ri)?;
        let socket_addr = SocketAddr::new(addr.host, addr.port);
        self.connect_to(local, remote_ri_bytes, socket_addr).await
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
    pub async fn connect_to(
        &self,
        local: &Ntcp2LocalConfig<'_>,
        remote_ri_bytes: &[u8],
        addr: SocketAddr,
    ) -> Result<IdentHash> {
        let remote_ri = FullRouterInfo::from_buffer(remote_ri_bytes)?;
        let remote_ident = *remote_ri.ident_hash();

        // Ранний выход: сессия уже открыта.
        if self.sessions.read().await.contains_key(&remote_ident) {
            debug!(peer = %remote_ident.to_base64(), "ntcp2 pool: сессия уже есть");
            return Ok(remote_ident);
        }

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| I2PError::Io(format!("ntcp2 pool: connect {addr}: {e}")))?;
        let session = Ntcp2Session::connect(stream, local, remote_ri_bytes).await?;
        let ident = IdentHash::from_array(*session.remote_ident_hash());
        debug_assert_eq!(ident, remote_ident);
        debug!(peer = %ident.to_base64(), %addr, "ntcp2 pool: сессия установлена (Alice)");

        self.spawn_session(session).await;
        Ok(ident)
    }

    /// Отправляет I2NP-сообщение пиру. Требует существующей сессии.
    ///
    /// # Errors
    ///
    /// - [`I2PError::Malformed`] — нет сессии с таким `IdentHash`;
    /// - [`I2PError::Io`] — задача сессии уже остановлена.
    pub async fn send_to(&self, ident: &IdentHash, msg: I2npMessage) -> Result<()> {
        let tx = {
            let sessions = self.sessions.read().await;
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
        let Some(handle) = self.sessions.write().await.remove(ident) else {
            return false;
        };

        // Просим отправить Termination и ждём подтверждения с таймаутом.
        let (ack_tx, ack_rx) = oneshot::channel();
        if handle
            .tx
            .send(SessionCommand::Close { ack: ack_tx })
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
            .incoming_tx
            .send(PoolEvent::Disconnected { ident: *ident })
            .await;
        true
    }

    /// Удаляет сессии, чьи задачи завершились, но почему-то остались в
    /// карте (например, задача паниковала). Обычно сессия убирает себя
    /// сама.
    pub async fn cleanup_dead(&self) {
        let mut sessions = self.sessions.write().await;
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
        self.sessions.read().await.keys().copied().collect()
    }

    /// Внутренний метод: запускает задачу сессии и регистрирует её.
    async fn spawn_session(&self, session: Ntcp2Session) {
        let ident = IdentHash::from_array(*session.remote_ident_hash());
        let (read, write) = session.split();
        let (tx, rx) = mpsc::channel::<SessionCommand>(SESSION_OUTBOUND_QUEUE);
        // Задача не должна успеть убрать запись раньше, чем мы её вставим.
        let (start_tx, start_rx) = oneshot::channel::<()>();
        let sessions = Arc::clone(&self.sessions);
        let events = self.incoming_tx.clone();

        let join = tokio::spawn(async move {
            let _ = start_rx.await;
            run_session(ident, read, write, rx, &events).await;
            if sessions.write().await.remove(&ident).is_some() {
                let _ = events.send(PoolEvent::Disconnected { ident }).await;
            }
        });

        self.sessions
            .write()
            .await
            .insert(ident, SessionHandle { tx, join });
        let _ = self
            .incoming_tx
            .send(PoolEvent::Established { ident })
            .await;
        let _ = start_tx.send(());
    }
}

/// Тело задачи сессии: читает фреймы, отправляет команды, выходит на
/// `Termination`/ошибке/закрытии канала.
async fn run_session(
    ident: IdentHash,
    mut read: Ntcp2SessionRead,
    mut write: Ntcp2SessionWrite,
    mut rx: mpsc::Receiver<SessionCommand>,
    events: &mpsc::Sender<PoolEvent>,
) {
    loop {
        tokio::select! {
            frame = read.read_frame() => {
                let blocks = match frame {
                    Ok(blocks) => blocks,
                    Err(error) => {
                        debug!(peer = %ident.to_base64(), %error, "ntcp2 pool: чтение завершено");
                        return;
                    }
                };
                for block in blocks {
                    let event = match block {
                        Ntcp2Block::I2npMessage(bytes) => match I2npMessage::from_ntcp2_bytes(&bytes) {
                            Ok(message) => PoolEvent::Message { from: ident, message },
                            Err(error) => {
                                warn!(peer = %ident.to_base64(), %error, "ntcp2 pool: I2NP не разобрался");
                                continue;
                            }
                        },
                        Ntcp2Block::RouterInfo { ri_bytes, .. } => {
                            PoolEvent::RouterInfo { from: ident, ri_bytes }
                        }
                        Ntcp2Block::Termination { reason, seqn } => {
                            debug!(
                                peer = %ident.to_base64(),
                                ?reason,
                                seqn,
                                "ntcp2 pool: peer terminated"
                            );
                            return;
                        }
                        Ntcp2Block::DateTime { .. }
                        | Ntcp2Block::Options(_)
                        | Ntcp2Block::Padding(_) => continue,
                    };
                    if events.send(event).await.is_err() {
                        debug!(peer = %ident.to_base64(), "ntcp2 pool: канал событий закрыт");
                        return;
                    }
                }
            }
            command = rx.recv() => match command {
                Some(SessionCommand::Message(message)) => {
                    if let Err(error) = write.send_i2np(&message).await {
                        debug!(peer = %ident.to_base64(), %error, "ntcp2 pool: запись завершена");
                        return;
                    }
                }
                Some(SessionCommand::Close { ack }) => {
                    if let Err(error) = write
                        .send_termination(Ntcp2TerminationReason::NormalClose)
                        .await
                    {
                        debug!(peer = %ident.to_base64(), %error, "ntcp2 pool: Termination не ушёл");
                    }
                    let _ = ack.send(());
                    debug!(peer = %ident.to_base64(), "ntcp2 pool: сессия закрыта локально");
                    return;
                }
                None => {
                    debug!(peer = %ident.to_base64(), "ntcp2 pool: пул отпустил сессию");
                    return;
                }
            },
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
        if let Ok(mut sessions) = self.sessions.try_write() {
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
            .finish()
    }
}

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
