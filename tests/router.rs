//! Тесты объединённого роутера ([`uu_i2p::Router`]).
//!
//! Роутер проверяется без сети. Всё, что может подменяться, подменено:
//!
//! | Что | Чем |
//! |-----|-----|
//! | сеть | [`FakeTransport`] — записывает, что роутер отправляет |
//! | время | [`FakeClock`] — двигаем руками |
//! | политика | [`TestPolicy`] — интервалы и ответы на `DatabaseLookup` |
//! | наблюдения | [`RecordingObserver`] |
//!
//! Результат работы роутера виден в двух местах: в его
//! [`RouterContext`] (netDb, активные запросы) и в том, что ушло в
//! транспорт.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::sync::{mpsc, oneshot};
use uu_i2p::{
    Clock, DatabaseLookup, DatabaseSearchReply, DatabaseStore, I2PError, I2PTag, I2PX25519Keys,
    I2npBody, I2npMessage, I2npMessageType, IdentHash, Result, Router, RouterConfig, RouterContext,
    RouterObserver, RouterPolicy, StoreHandling, TransportEvent, TransportPool,
    config::Transport,
    private_keys::I2PPrivateKeys,
    router_info::{FullRouterInfo, RouterInfo, RouterInfoCaps},
    router_info_address::I2PAddress,
    tunnel_messages::TunnelDataBody,
};

/// Начальное время тестов: не ноль, чтобы «время не задано» (`0` в
/// таймерах запросов) не путалось с «сейчас».
const NOW_MS: u64 = 1_700_000_000_000;

/// «Не публиковать» в тестах, которым публикация только мешает.
const NEVER_PUBLISH: Duration = Duration::from_hours(24);

// --- поддельные часы -------------------------------------------------------

/// Часы, которые двигает тест.
#[derive(Debug, Clone)]
struct FakeClock {
    now_ms: Arc<AtomicU64>,
}

impl FakeClock {
    fn new(now_ms: u64) -> Self {
        Self {
            now_ms: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    /// Сдвигает время вперёд.
    fn advance(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

// --- поддельный транспорт --------------------------------------------------

/// Транспорт-подделка.
///
/// `send_to`/`connect` ничего не делают по сети, а записывают вызов;
/// события роутер получает через [`FakeTransport::enqueue`].
struct FakeTransport {
    kind: Transport,
    /// Что роутер отправил: `(кому, сообщение)`.
    sent: Mutex<Vec<(IdentHash, I2npMessage)>>,
    /// Кого роутер пытался набрать: `(ident, адрес вместо RI)`.
    connects: Mutex<Vec<(IdentHash, Option<SocketAddr>)>>,
    /// Очередь событий для роутера; её читает pump-таска.
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<Result<TransportEvent>>>,
    incoming_tx: mpsc::UnboundedSender<Result<TransportEvent>>,
    /// Если поднят — `next_event` отвечает ошибкой (транспорт «умер»).
    stopped: AtomicBool,
}

impl FakeTransport {
    fn new(kind: Transport) -> Self {
        let (incoming_tx, incoming) = mpsc::unbounded_channel();
        Self {
            kind,
            sent: Mutex::new(Vec::new()),
            connects: Mutex::new(Vec::new()),
            incoming: tokio::sync::Mutex::new(incoming),
            incoming_tx,
            stopped: AtomicBool::new(false),
        }
    }

    /// Кладёт событие так, как если бы его отдал настоящий транспорт.
    fn enqueue(&self, event: TransportEvent) {
        self.incoming_tx.send(Ok(event)).expect("fake: очередь");
    }

    /// Что роутер отправил.
    fn sent(&self) -> Vec<(IdentHash, I2npMessage)> {
        self.sent.lock().expect("fake: sent").clone()
    }

    /// Кого роутер пытался набрать.
    fn connects(&self) -> Vec<(IdentHash, Option<SocketAddr>)> {
        self.connects.lock().expect("fake: connects").clone()
    }

    /// Сообщает роутеру, что транспорт больше не работает.
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
}

impl TransportPool for FakeTransport {
    fn kind(&self) -> Transport {
        self.kind
    }

    fn connect<'a>(
        &'a self,
        remote_ri_bytes: &'a [u8],
        addr: Option<SocketAddr>,
    ) -> uu_i2p::BoxFuture<'a, Result<IdentHash>> {
        Box::pin(async move {
            let ident = *FullRouterInfo::from_buffer(remote_ri_bytes)?.ident_hash();
            self.connects
                .lock()
                .expect("fake: connects")
                .push((ident, addr));
            Ok(ident)
        })
    }

    fn send_to<'a>(
        &'a self,
        ident: &'a IdentHash,
        message: I2npMessage,
    ) -> uu_i2p::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.sent
                .lock()
                .expect("fake: sent")
                .push((*ident, message));
            Ok(())
        })
    }

    fn close<'a>(&'a self, _ident: &'a IdentHash) -> uu_i2p::BoxFuture<'a, Result<bool>> {
        Box::pin(async move { Ok(true) })
    }

    fn next_event(&self) -> uu_i2p::BoxFuture<'_, Result<TransportEvent>> {
        Box::pin(async move {
            if self.stopped.load(Ordering::SeqCst) {
                return Err(I2PError::Malformed("fake: транспорт остановлен"));
            }
            let mut incoming = self.incoming.lock().await;
            incoming
                .recv()
                .await
                .unwrap_or(Err(I2PError::Malformed("fake: канал событий закрыт")))
        })
    }

    fn session_idents(&self) -> uu_i2p::BoxFuture<'_, Vec<IdentHash>> {
        Box::pin(async move {
            self.sent
                .lock()
                .expect("fake: sent")
                .iter()
                .map(|(ident, _)| *ident)
                .collect()
        })
    }
}

/// Подключает [`FakeTransport`] к роутеру и возвращает его для проверок.
fn attach_fake(router: &mut Router, kind: Transport) -> Arc<FakeTransport> {
    let transport = Arc::new(FakeTransport::new(kind));
    let handle: Arc<dyn TransportPool> = transport.clone();
    router.attach(handle).expect("attach");
    transport
}

// --- тестовая политика -----------------------------------------------------

/// Политика теста: интервалы публикации и ответ на `DatabaseLookup`.
#[derive(Debug, Clone, Copy)]
struct TestPolicy {
    /// Отвечать ли на `DatabaseLookup` (в i2pd — только флудфилл).
    answer_lookup: bool,
    /// Интервал публикации своего `RouterInfo` (и первый, и обычный).
    publish_interval: Duration,
}

impl TestPolicy {
    /// Отвечаем на lookup, публиковаться не спешим.
    fn answering() -> Self {
        Self {
            answer_lookup: true,
            publish_interval: NEVER_PUBLISH,
        }
    }

    /// Не отвечаем, публикуемся через `publish_interval`.
    fn publishing(publish_interval: Duration) -> Self {
        Self {
            answer_lookup: false,
            publish_interval,
        }
    }
}

impl RouterPolicy for TestPolicy {
    fn initial_ri_publish_interval(&self) -> Duration {
        self.publish_interval
    }

    fn ri_publish_interval(&self) -> Duration {
        self.publish_interval
    }

    fn answer_database_lookup(&self, _ctx: &RouterContext) -> bool {
        self.answer_lookup
    }
}

// --- наблюдатель -----------------------------------------------------------

/// Наблюдатель, который всё записывает.
#[derive(Debug, Clone, Default)]
struct RecordingObserver {
    /// `IdentHash`'и, о попадании которых в netDb нам сообщили.
    stored: Arc<Mutex<Vec<IdentHash>>>,
    /// Необработанные сообщения: `(от кого, тип)`.
    unhandled: Arc<Mutex<Vec<(IdentHash, I2npMessageType)>>>,
}

impl RouterObserver for RecordingObserver {
    fn on_transport_event(&mut self, _kind: Transport, _event: &TransportEvent) {}

    fn on_store(&mut self, handling: &StoreHandling) {
        if let StoreHandling::Inserted(ident) = handling {
            self.stored.lock().expect("observer: stored").push(*ident);
        }
    }

    fn on_unhandled_message(&mut self, from: &IdentHash, message: &I2npMessage) {
        self.unhandled
            .lock()
            .expect("observer: unhandled")
            .push((*from, message.message_type()));
    }
}

// --- данные ----------------------------------------------------------------

fn test_config(floodfill: bool) -> RouterConfig {
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let ntcp2 = I2PX25519Keys::generate();
    RouterConfig::builder()
        .keys(keys)
        .ntcp2_keys(ntcp2, [0x42; 16])
        .listen_unpublished("127.0.0.1:0".parse().unwrap())
        .floodfill(floodfill)
        .build()
        .expect("config")
}

fn context(floodfill: bool) -> RouterContext {
    RouterContext::new(test_config(floodfill)).expect("ctx")
}

/// Собирает RI чужого роутера с SSU2-адресом.
///
/// Возвращает `(ident, байты RI)`. В netDb **не** кладёт: тесты сами
/// решают, попадает ли он туда через сообщение или через событие
/// транспорта.
fn foreign_ri(floodfill: bool) -> (IdentHash, Vec<u8>) {
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let addr = I2PAddress::ssu2_published(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1234,
        I2PTag::from_array([0x11; 32]),
        I2PTag::from_array([0x22; 32]),
    );
    let caps: &[u8] = if floodfill { b"fR" } else { b"R" };
    let body = RouterInfo::builder()
        .timestamp(NOW_MS)
        .caps(RouterInfoCaps::parse(caps))
        .add_address(addr)
        .build();
    let ri = FullRouterInfo::from_keys(&keys, body).expect("ri");
    (*ri.ident_hash(), ri.to_buffer().expect("buffer"))
}

/// То же, но сразу в netDb; возвращает `IdentHash`.
fn add_foreign_ri(ctx: &mut RouterContext, floodfill: bool) -> IdentHash {
    let (ident, ri_bytes) = foreign_ri(floodfill);
    let ri = FullRouterInfo::from_buffer(&ri_bytes).expect("ri");
    ctx.netdb_mut().insert(ri);
    ident
}

/// Роутер с `FakeClock`, тестовой политикой и записывающим наблюдателем.
fn new_router(
    ctx: RouterContext,
    clock: &FakeClock,
    policy: TestPolicy,
) -> (Router, RecordingObserver) {
    let observer = RecordingObserver::default();
    let router = Router::new(ctx)
        .with_clock(Box::new(clock.clone()))
        .with_policy(Box::new(policy))
        .with_observer(Box::new(observer.clone()));
    (router, observer)
}

fn store_message(ident: IdentHash, ri_bytes: &[u8]) -> I2npMessage {
    let store = DatabaseStore::new_router_info(ident, ri_bytes, 0, None).expect("store");
    I2npMessage::from_body(I2npBody::DatabaseStore(store)).expect("message")
}

fn lookup_message(target: IdentHash, from: IdentHash) -> I2npMessage {
    let lookup = DatabaseLookup::new_router_info(target, from, None, Vec::new());
    I2npMessage::from_body(I2npBody::DatabaseLookup(lookup)).expect("message")
}

fn search_reply_message(key: IdentHash, peers: Vec<IdentHash>, from: IdentHash) -> I2npMessage {
    let reply = DatabaseSearchReply::with_from(key, peers, from);
    I2npMessage::from_body(I2npBody::DatabaseSearchReply(reply)).expect("message")
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("expected 32 bytes")
}

/// Оборачивает I2NP-сообщение в роутерный garlic (`Noise_N`), как i2pd
/// `WrapECIESX25519MessageForRouter`.
fn wrap_router_garlic(router_static_public: &[u8; 32], message: &I2npMessage) -> I2npMessage {
    use uu_i2p::{
        crypto::{NoiseSymmetricState, init_noise_n_state},
        garlic_block::{EciesGarlicClove, GarlicBlock, serialize_blocks},
    };

    let blocks = serialize_blocks(
        &[GarlicBlock::EciesGarlicClove(EciesGarlicClove::wrap_local(
            message,
        ))],
    )
    .expect("serialize blocks");

    let ephemeral = I2PX25519Keys::generate();
    let mut noise = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], router_static_public);
    init_noise_n_state(&mut noise, router_static_public);
    noise.mix_hash(ephemeral.public_key());
    let shared = ephemeral.agree(router_static_public).expect("x25519 agree");
    noise.mix_key(&shared);

    let mut ciphertext = vec![0u8; blocks.len() + 16];
    noise
        .encrypt(&blocks, &mut ciphertext)
        .expect("noise encrypt");

    let mut wire = ephemeral.public_key().to_vec();
    wire.extend_from_slice(&ciphertext);
    I2npMessage::from_body(I2npBody::Garlic(uu_i2p::garlic_body::GarlicBody::new(wire)))
        .expect("garlic message")
}

// --- RouterInfo попадает в netDb -------------------------------------------

#[tokio::test]
async fn router_info_event_fills_netdb() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, observer) = new_router(context(false), &clock, TestPolicy::answering());
    attach_fake(&mut router, Transport::Ssu2);
    let (ident, ri_bytes) = foreign_ri(false);

    router
        .handle_event(
            Transport::Ssu2,
            TransportEvent::RouterInfo {
                from: ident,
                ri_bytes,
            },
        )
        .await
        .expect("event");

    assert!(router.context().netdb().contains(&ident));
    assert_eq!(*observer.stored.lock().unwrap(), vec![ident]);
}

#[tokio::test]
async fn router_info_from_other_peer_is_rejected() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    attach_fake(&mut router, Transport::Ssu2);
    let (ident, ri_bytes) = foreign_ri(false);
    let (other, _) = foreign_ri(false);

    // RI подписан одним роутером, а пришёл «от» другого: ключ
    // сообщения не совпадёт с identity — это отбой.
    let error = router
        .handle_event(
            Transport::Ssu2,
            TransportEvent::RouterInfo {
                from: other,
                ri_bytes,
            },
        )
        .await
        .expect_err("должно быть отвергнуто");

    assert!(matches!(error, I2PError::Malformed(_)), "{error:?}");
    assert!(!router.context().netdb().contains(&ident));
}

#[tokio::test]
async fn database_store_message_fills_netdb() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, observer) = new_router(context(false), &clock, TestPolicy::answering());
    attach_fake(&mut router, Transport::Ssu2);
    let (ident, ri_bytes) = foreign_ri(false);

    router
        .handle_message(Transport::Ssu2, &ident, store_message(ident, &ri_bytes))
        .await
        .expect("message");

    assert!(router.context().netdb().contains(&ident));
    assert_eq!(*observer.stored.lock().unwrap(), vec![ident]);
}

// --- DatabaseLookup --------------------------------------------------------

#[tokio::test]
async fn database_lookup_is_answered_when_policy_allows() {
    let clock = FakeClock::new(NOW_MS);
    let mut ctx = context(false);
    let target = add_foreign_ri(&mut ctx, false);
    let (mut router, _observer) = new_router(ctx, &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (asker, _) = foreign_ri(false);

    router
        .handle_message(Transport::Ssu2, &asker, lookup_message(target, asker))
        .await
        .expect("lookup");

    let sent = fake.sent();
    assert_eq!(sent.len(), 1, "ожидался один ответ");
    assert_eq!(sent[0].0, asker, "ответ тому, кто спросил");
    assert_eq!(sent[0].1.message_type(), I2npMessageType::DatabaseStore);
    let store = DatabaseStore::from_buffer(sent[0].1.payload()).expect("DatabaseStore");
    assert_eq!(store.key, target, "отдаём именно запрошенный RI");
}

#[tokio::test]
async fn database_lookup_is_ignored_off_floodfill() {
    // Политика i2pd по умолчанию: отвечает только флудфилл.
    let clock = FakeClock::new(NOW_MS);
    let mut ctx = context(false);
    let target = add_foreign_ri(&mut ctx, false);
    let router = Router::new(ctx).with_clock(Box::new(clock.clone()));
    let mut router = router;
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (asker, _) = foreign_ri(false);

    router
        .handle_message(Transport::Ssu2, &asker, lookup_message(target, asker))
        .await
        .expect("lookup");

    assert!(fake.sent().is_empty(), "не флудфилл молчит");
}

#[tokio::test]
async fn database_lookup_is_answered_by_floodfill() {
    // Тот же путь, но с политикой по умолчанию и caps `f`.
    let clock = FakeClock::new(NOW_MS);
    let mut ctx = context(true);
    let target = add_foreign_ri(&mut ctx, false);
    let mut router = Router::new(ctx).with_clock(Box::new(clock.clone()));
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (asker, _) = foreign_ri(false);

    router
        .handle_message(Transport::Ssu2, &asker, lookup_message(target, asker))
        .await
        .expect("lookup");

    let sent = fake.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1.message_type(), I2npMessageType::DatabaseStore);
}

// --- DatabaseSearchReply ---------------------------------------------------

#[tokio::test]
async fn search_reply_makes_router_ask_for_new_routers() {
    let clock = FakeClock::new(NOW_MS);
    let mut ctx = context(false);
    let floodfill = add_foreign_ri(&mut ctx, true);
    let (mut router, _observer) = new_router(ctx, &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (from, _) = foreign_ri(false);
    let (wanted, _) = foreign_ri(false);
    let (also_wanted, _) = foreign_ri(false);

    router
        .handle_message(
            Transport::Ssu2,
            &from,
            search_reply_message(wanted, vec![wanted, also_wanted], from),
        )
        .await
        .expect("search reply");

    // Само сообщение ничего не отправляет: запросы уходят на тике.
    assert!(fake.sent().is_empty(), "до тика ничего не уходит");
    assert!(!router.context().netdb().contains(&wanted));

    router.tick().await.expect("tick");

    let sent = fake.sent();
    assert!(!sent.is_empty(), "после тика ждём DatabaseLookup");
    for (to, message) in &sent {
        assert_eq!(*to, floodfill, "спрашиваем ближайший флудфилл");
        assert_eq!(message.message_type(), I2npMessageType::DatabaseLookup);
    }
}

// --- публикация своего RouterInfo -----------------------------------------

#[tokio::test]
async fn own_router_info_is_published_after_initial_interval() {
    let clock = FakeClock::new(NOW_MS);
    let mut ctx = context(false);
    let floodfill = add_foreign_ri(&mut ctx, true);
    let own = *ctx.own_ident_hash();
    let (mut router, _observer) =
        new_router(ctx, &clock, TestPolicy::publishing(Duration::from_secs(10)));
    let fake = attach_fake(&mut router, Transport::Ssu2);

    clock.advance(9_000);
    router.tick().await.expect("tick");
    assert!(fake.sent().is_empty(), "9 секунд — ещё рано");

    clock.advance(1_000);
    router.tick().await.expect("tick");

    let sent = fake.sent();
    assert_eq!(sent.len(), 1, "публикуем одному флудфиллу");
    assert_eq!(sent[0].0, floodfill);
    assert_eq!(sent[0].1.message_type(), I2npMessageType::DatabaseStore);
    let store = DatabaseStore::from_buffer(sent[0].1.payload()).expect("DatabaseStore");
    assert_eq!(store.key, own, "публикуем свой RI");
}

#[tokio::test]
async fn own_router_info_is_not_republished_too_soon() {
    let clock = FakeClock::new(NOW_MS);
    let mut ctx = context(false);
    add_foreign_ri(&mut ctx, true);
    let (mut router, _observer) = new_router(
        ctx,
        &clock,
        TestPolicy::publishing(Duration::from_secs(600)),
    );
    let fake = attach_fake(&mut router, Transport::Ssu2);

    clock.advance(600_000);
    router.tick().await.expect("tick");
    assert_eq!(fake.sent().len(), 1, "первая публикация");

    clock.advance(599_000);
    router.tick().await.expect("tick");
    assert_eq!(fake.sent().len(), 1, "через 599 с повторять рано");

    clock.advance(1_000);
    router.tick().await.expect("tick");
    assert_eq!(fake.sent().len(), 2, "через 600 с публикуем снова");
}

#[tokio::test]
async fn own_router_info_is_not_published_without_floodfills() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(
        context(false),
        &clock,
        TestPolicy::publishing(Duration::from_secs(1)),
    );
    let fake = attach_fake(&mut router, Transport::Ssu2);

    clock.advance(60_000);
    router.tick().await.expect("tick");

    assert!(
        fake.sent().is_empty(),
        "флудфиллов нет — публиковать некому"
    );
}

// --- соединения ------------------------------------------------------------

#[tokio::test]
async fn established_and_disconnected_update_session_map() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    attach_fake(&mut router, Transport::Ntcp2);
    let (ident, _) = foreign_ri(false);

    assert_eq!(router.session_transport(&ident), None);

    router
        .handle_event(Transport::Ntcp2, TransportEvent::Established { ident })
        .await
        .expect("established");
    assert_eq!(router.session_transport(&ident), Some(Transport::Ntcp2));

    router
        .handle_event(Transport::Ntcp2, TransportEvent::Disconnected { ident })
        .await
        .expect("disconnected");
    assert_eq!(router.session_transport(&ident), None);
}

#[tokio::test]
async fn dial_uses_policy_transport_and_remembers_session() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (ident, ri_bytes) = foreign_ri(false);

    // У RI есть SSU2-адрес — политика по умолчанию выберет SSU2.
    let dialed = router.dial(&ri_bytes, None, None).await.expect("dial");

    assert_eq!(dialed, ident);
    assert_eq!(router.session_transport(&ident), Some(Transport::Ssu2));
    assert_eq!(fake.connects(), vec![(ident, None)]);
}

#[tokio::test]
async fn dial_without_transport_fails() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    let (_ident, ri_bytes) = foreign_ri(false);

    let error = router
        .dial(&ri_bytes, None, None)
        .await
        .expect_err("нет транспорта — нет соединения");
    assert!(matches!(error, I2PError::Malformed(_)), "{error:?}");
}

#[tokio::test]
async fn attach_rejects_second_transport_of_same_kind() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    attach_fake(&mut router, Transport::Ssu2);

    let extra: Arc<dyn TransportPool> = Arc::new(FakeTransport::new(Transport::Ssu2));
    let error = router.attach(extra).expect_err("дубликат типа");
    assert!(matches!(error, I2PError::Malformed(_)), "{error:?}");
}

#[tokio::test]
async fn send_uses_session_transport() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (ident, _) = foreign_ri(false);
    let (other, ri_bytes) = foreign_ri(false);

    router
        .handle_event(Transport::Ssu2, TransportEvent::Established { ident })
        .await
        .expect("established");
    router
        .send(&ident, store_message(other, &ri_bytes))
        .await
        .expect("send");

    assert_eq!(fake.sent().len(), 1);
    assert_eq!(fake.sent()[0].0, ident);
}

// --- роутерный garlic ------------------------------------------------------

#[tokio::test]
async fn router_garlic_dispatches_inner_message() {
    let clock = FakeClock::new(NOW_MS);
    let ctx = context(false);
    let router_pub = array32(
        ctx.config()
            .keys()
            .public()
            .encryption_public_key()
            .expect("router encryption key"),
    );
    let (mut router, observer) = new_router(ctx, &clock, TestPolicy::answering());
    attach_fake(&mut router, Transport::Ssu2);
    let (from, _) = foreign_ri(false);
    let (ident, ri_bytes) = foreign_ri(false);

    // i2pd так публикует свой RI флудфиллу и так шлёт ему
    // `DatabaseLookup`. Внутреннее сообщение должно попасть в тот же
    // диспетчер, что и обычное: для `DatabaseStore` это netDb.
    let garlic = wrap_router_garlic(&router_pub, &store_message(ident, &ri_bytes));
    router
        .handle_message(Transport::Ssu2, &from, garlic)
        .await
        .expect("garlic");

    assert!(router.context().netdb().contains(&ident));
    assert_eq!(*observer.stored.lock().unwrap(), vec![ident]);
}

#[tokio::test]
async fn router_garlic_answers_inner_database_lookup() {
    let clock = FakeClock::new(NOW_MS);
    let mut ctx = context(false);
    let target = add_foreign_ri(&mut ctx, false);
    let router_pub = array32(
        ctx.config()
            .keys()
            .public()
            .encryption_public_key()
            .expect("router encryption key"),
    );
    let (mut router, _observer) = new_router(ctx, &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (asker, _) = foreign_ri(false);

    let garlic = wrap_router_garlic(&router_pub, &lookup_message(target, asker));
    router
        .handle_message(Transport::Ssu2, &asker, garlic)
        .await
        .expect("garlic");

    let sent = fake.sent();
    assert_eq!(sent.len(), 1, "ответ на вложенный DatabaseLookup");
    assert_eq!(sent[0].0, asker);
    assert_eq!(sent[0].1.message_type(), I2npMessageType::DatabaseStore);
}

#[tokio::test]
async fn garbage_garlic_does_not_stop_the_loop() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (from, _) = foreign_ri(false);

    // Никому не адресованный garlic: раньше ошибка расшифровки
    // вылетала из цикла и убивала роутер.
    let garbage = I2npMessage::from_body(I2npBody::Garlic(uu_i2p::garlic_body::GarlicBody::new(
        vec![0xab; 200],
    )))
    .expect("garlic");
    fake.enqueue(TransportEvent::Message {
        from,
        message: garbage,
    });

    // Цикл должен дождаться остановки, а не выйти сам с ошибкой.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        router.run_until(async {
            // Ждём, пока мусорный garlic не будет обработан, затем
            // останавливаемся: событие уже в очереди.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }),
    )
    .await
    .expect("цикл не должен висеть");
    assert!(
        result.is_ok(),
        "мусорный garlic — не ошибка роутера: {result:?}"
    );
}

// --- необрабатываемые сообщения -------------------------------------------

#[tokio::test]
async fn tunnel_message_reaches_observer() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, observer) = new_router(context(false), &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (from, _) = foreign_ri(false);
    let body = TunnelDataBody {
        tunnel_id: 7,
        iv: [0; uu_i2p::tunnel_messages::TUNNEL_DATA_IV_SIZE],
        encrypted: Box::new([0; uu_i2p::tunnel_messages::TUNNEL_DATA_ENCRYPTED_SIZE]),
    };
    let message = I2npMessage::from_body(I2npBody::TunnelData(body)).expect("message");

    router
        .handle_message(Transport::Ssu2, &from, message)
        .await
        .expect("tunnel data");

    assert_eq!(
        *observer.unhandled.lock().unwrap(),
        vec![(from, I2npMessageType::TunnelData)]
    );
    assert!(fake.sent().is_empty(), "туннелей у нас пока нет");
}

// --- цикл событий ----------------------------------------------------------

#[tokio::test]
async fn pump_delivers_transport_events_until_shutdown() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, observer) = new_router(context(false), &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (ident, ri_bytes) = foreign_ri(false);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let loop_task = tokio::spawn(async move {
        router
            .run_until(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("run_until");
        router
    });

    // Событие из транспорта должно доехать до netDb через pump-таску
    // и `run_until`.
    fake.enqueue(TransportEvent::RouterInfo {
        from: ident,
        ri_bytes,
    });
    wait_until(|| !observer.stored.lock().unwrap().is_empty()).await;

    shutdown_tx.send(()).expect("shutdown");
    let router = loop_task.await.expect("join");

    assert!(router.context().netdb().contains(&ident));
}

#[tokio::test]
async fn broken_transport_stops_the_loop() {
    let clock = FakeClock::new(NOW_MS);
    let (mut router, _observer) = new_router(context(false), &clock, TestPolicy::answering());
    let fake = attach_fake(&mut router, Transport::Ssu2);
    let (ident, _) = foreign_ri(false);

    router
        .handle_event(Transport::Ssu2, TransportEvent::Established { ident })
        .await
        .expect("established");

    // Транспорт «умер»: pump сообщит роутеру, и цикл сам завершится.
    fake.stop();
    let never = std::future::pending::<()>();
    tokio::time::timeout(Duration::from_secs(5), router.run_until(never))
        .await
        .expect("цикл должен завершиться сам")
        .expect("run_until");

    assert!(router.all_transports_closed());
    assert_eq!(router.session_transport(&ident), None, "сессии забыты");
}

/// Ждёт выполнения условия, но не дольше пяти секунд.
async fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !ready() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "условие не наступило"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
