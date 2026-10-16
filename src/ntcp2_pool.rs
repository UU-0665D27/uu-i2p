//! Пул активных NTCP2-сессий.
//!
//! Каждая сессия после handshake'а разделяется на read- и write-половины
//! (см. [`crate::ntcp2::Ntcp2Session::split`]) и запускается в двух
//! `tokio::spawn`. Пул хранит только «write-конец» сессии (`mpsc::Sender`),
//! чтобы вызывающий код мог положить I2NP-сообщение и не блокироваться на
//! I/O. Принятые I2NP-сообщения со всех сессий идут в общий
//! `incoming_rx`.
//!
//! ## Разделение обязанностей
//!
//! - [`Ntcp2Pool`] — управление сессиями: подключение, отправка,
//!   получение. **Не** знает про netDb и I2NP-диспетчеризацию.
//! - [`crate::router_context::RouterContext`] — держит pool и netDb,
//!   обрабатывает `DatabaseStore` / `DatabaseLookup` / и т.д.
//!
//! ## Модель многозадачности
//!
//! Все методы `Ntcp2Pool` берут `&self`. Внутреннее состояние защищено
//! `tokio::sync::Mutex`/`RwLock`, а I/O сессий живёт в отдельных тасках.
//! Это позволяет вызывать `next_message()` и `send_to()` из разных
//! мест без `Arc<Mutex<Pool>>` снаружи.
//!
//! ## Что НЕ реализовано
//!
//! - **Reconnect при разрыве**: если write-канал закрылся, сессия
//!   удаляется, следующий `send_to` вернёт ошибку. Логика retry —
//!   на `RouterContext`.
//! - **Broadcast I2NP в несколько сессий** (flood): одна сессия —
//!   один получатель.
//! - **Ограничение размера пула**: если открыть сотни сессий, память
//!   вырастет. Caller сам чистит через [`Ntcp2Pool::remove_session`].

use crate::{
    IdentHash,
    error::{I2PError, Result},
    i2np_message::I2npMessage,
    ntcp2::{Ntcp2Block, Ntcp2LocalConfig, Ntcp2Session},
    router_info::FullRouterInfo,
};
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock, mpsc},
    task::JoinHandle,
};

/// Размер буфера исходящих I2NP-сообщений на одну сессию.
const SESSION_OUTBOUND_QUEUE: usize = 64;
/// Размер общего буфера принятых I2NP-сообщений.
const POOL_INCOMING_QUEUE: usize = 256;

/// Хэндл одной активной сессии.
struct SessionHandle {
    /// Sender в write-таск сессии.
    tx: mpsc::Sender<I2npMessage>,
    /// Хэндл read-таска (для abort при удалении).
    read_join: JoinHandle<()>,
    /// Хэндл write-таска.
    write_join: JoinHandle<()>,
}

/// Событие от peer'а.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolEvent {
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
}

/// Пул NTCP2-сессий.
pub struct Ntcp2Pool {
    sessions: RwLock<HashMap<IdentHash, SessionHandle>>,
    incoming_tx: mpsc::Sender<PoolEvent>,
    incoming_rx: Mutex<mpsc::Receiver<PoolEvent>>,
}

impl Ntcp2Pool {
    /// Создаёт пустой пул.
    #[must_use]
    pub fn new() -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(POOL_INCOMING_QUEUE);
        Self {
            sessions: RwLock::new(HashMap::new()),
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

    /// Устанавливает NTCP2-сессию с удалённым роутером.
    ///
    /// Если сессия с таким `IdentHash` уже есть — возвращает её
    /// `IdentHash` без переустановки.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — в `remote_ri_bytes` нет NTCP2-адреса;
    /// - [`Error::Io`] — ошибка TCP;
    /// - ошибки handshake'а.
    pub async fn connect(
        &self,
        local_cfg: &Ntcp2LocalConfig<'_>,
        remote_ri_bytes: &[u8],
    ) -> Result<IdentHash> {
        let remote_ri = FullRouterInfo::from_buffer(remote_ri_bytes)?;
        let remote_ident = *remote_ri.ident_hash();

        // Ранний выход: сессия уже открыта.
        if self.sessions.read().await.contains_key(&remote_ident) {
            return Ok(remote_ident);
        }

        let addr = find_ntcp2_address(&remote_ri)?;
        let socket_addr = SocketAddr::new(addr.host, addr.port);

        let stream = TcpStream::connect(socket_addr)
            .await
            .map_err(|e| I2PError::Io(format!("ntcp2 pool: connect: {e}")))?;
        let session = Ntcp2Session::connect(stream, local_cfg, remote_ri_bytes).await?;
        // `remote_ident_hash()` возвращает `&[u8; 32]`; `sessions`
        // и весь остальной код работают с `IdentHash` (`Tag<32>`).
        let ident = IdentHash::from_array(*session.remote_ident_hash());
        debug_assert_eq!(ident, remote_ident);

        self.spawn_session(session).await;
        Ok(ident)
    }

    /// Отправляет I2NP-сообщение пиру. Требует существующей сессии.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — нет сессии с таким `IdentHash`;
    /// - [`Error::Io`] — write-таск уже остановлен.
    pub async fn send_to(&self, ident: &IdentHash, msg: I2npMessage) -> Result<()> {
        let tx = {
            let sessions = self.sessions.read().await;
            sessions
                .get(ident)
                .map(|h| h.tx.clone())
                .ok_or(I2PError::Malformed("ntcp2 pool: no session for peer"))?
        };
        tx.send(msg)
            .await
            .map_err(|_| I2PError::Io("ntcp2 pool: session write channel closed".into()))
    }

    /// Ждёт следующего события (I2NP-сообщение или RI-обновление)
    /// от **любой** сессии.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], если канал приёма закрыт (это значит, что все
    /// sender'ы дропнуты — обычно потому что [`Self`] дропнут).
    pub async fn next_event(&self) -> Result<PoolEvent> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| I2PError::Io("ntcp2 pool: incoming channel closed".into()))
    }

    /// Удаляет сессию. Если её не было — no-op.
    pub async fn remove_session(&self, ident: &IdentHash) -> bool {
        let handle = self.sessions.write().await.remove(ident);
        if let Some(h) = handle {
            h.read_join.abort();
            h.write_join.abort();
            true
        } else {
            false
        }
    }

    /// Удаляет сессии, чьи write- или read-таски завершились.
    pub async fn cleanup_dead(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, h| !h.write_join.is_finished() && !h.read_join.is_finished());
    }

    /// Список `IdentHash` активных сессий.
    pub async fn session_idents(&self) -> Vec<IdentHash> {
        self.sessions.read().await.keys().copied().collect()
    }

    /// Внутренний метод: разбивает сессию на половинки и запускает
    /// read/write таски.
    async fn spawn_session(&self, session: Ntcp2Session) {
        // `remote_ident_hash()` возвращает `&[u8; 32]`, а `sessions`
        // ключуется по `IdentHash` (`Tag<32>`); конвертируем один раз.
        let ident = IdentHash::from_array(*session.remote_ident_hash());
        let (read, write) = session.split();
        let (tx, rx) = mpsc::channel::<I2npMessage>(SESSION_OUTBOUND_QUEUE);
        let incoming_tx = self.incoming_tx.clone();

        // Read-таск: читает блоки, шлёт `PoolEvent`-ы в общий канал.
        let read_join = tokio::spawn(async move {
            let mut read = read;
            loop {
                match read.read_frame().await {
                    Ok(blocks) => {
                        for block in blocks {
                            let event = match block {
                                Ntcp2Block::I2npMessage(bytes) => {
                                    match I2npMessage::from_ntcp2_bytes(&bytes) {
                                        Ok(message) => PoolEvent::Message {
                                            from: ident,
                                            message,
                                        },
                                        Err(_) => continue,
                                    }
                                }
                                Ntcp2Block::RouterInfo { ri_bytes, .. } => PoolEvent::RouterInfo {
                                    from: ident,
                                    ri_bytes,
                                },
                                Ntcp2Block::Termination { .. } => return,
                                Ntcp2Block::DateTime { .. }
                                | Ntcp2Block::Options(_)
                                | Ntcp2Block::Padding(_) => continue,
                            };
                            if incoming_tx.send(event).await.is_err() {
                                return; // pool дропнут
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        });

        // Write-таск: получает I2NP из `rx`, шлёт в сокет.
        let write_join = tokio::spawn(async move {
            let mut write = write;
            let mut rx = rx;
            while let Some(msg) = rx.recv().await {
                if write.send_i2np(&msg).await.is_err() {
                    return;
                }
            }
        });

        self.sessions.write().await.insert(
            ident,
            SessionHandle {
                tx,
                read_join,
                write_join,
            },
        );
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
                h.read_join.abort();
                h.write_join.abort();
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
