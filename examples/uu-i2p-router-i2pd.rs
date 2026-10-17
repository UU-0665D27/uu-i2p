//! Демонстрация: объединённый [`uu_i2p::Router`] работает против
//! настоящего i2pd по SSU2.
//!
//! Это первый прогон собранного роутера (`src/router.rs`): состояние
//! (`RouterContext`) + транспорт ([`Ssu2Pool`]) + цикл событий, ничего
//! руками не диспетчеризуется. Что делает пример:
//!
//! 1. поднимает свой SSU2-сокет на `127.0.0.1:0` и собирает
//!    [`RouterContext`] так, что в своём `RouterInfo` мы публикуем
//!    loopback и caps `f` (флудфилл) — иначе i2pd не станет спрашивать
//!    у нас `LeaseSet`/RI, а без loopback-адреса порвёт сессию
//!    (`SSU2: Host mismatch`, `SSU2Session.cpp:1400`);
//! 2. `Router::dial` — исходящая SSU2-сессия к i2pd (её события
//!    разбирает `Router`, включая `Established`);
//! 3. `Router::send` — публикуем свой `RouterInfo` (`DatabaseStore`) и
//!    спрашиваем RI собеседника (`DatabaseLookup`); ответ i2pd кладёт в
//!    netDb уже сам роутер;
//! 4. дёргаем HTTP-прокси i2pd (`127.0.0.1:4445`) случайным b32-адресом:
//!    i2pd идёт за `LeaseSet` к ближайшему флудфиллу — к нам, — и наш
//!    `Router` отвечает `DatabaseSearchReply` (LS у нас нет);
//! 5. крутит `Router::run_until` (тик = запросы netDb + публикация RI +
//!    обслуживание транспорта) заданное время и печатает счётчики.
//!
//! ## `--accept`: входящая сессия
//!
//! С флагом `--accept` пример дополнительно проверяет **входящий** путь:
//! после размена он закрывает свою сессию (`Router::close`) и ждёт, чтобы
//! i2pd позвонил сам. i2pd так и делает, когда ему есть что отправить
//! (`Transports::PostMessages` → `ConnectToPeer`), а адрес берёт из нашего
//! RI в своём netDb (туда он попал из `SessionConfirmed`). Дальше всё
//! делает тот же `Router`: пул принимает `SessionRequest`, поднимает
//! сессию в роли ответчика, а события `Established`/`Message` идут в общий
//! цикл.
//!
//! Признак успеха: в логе наблюдателя второй `Established` (`nth=2`) —
//! значит сессию начал он, а не мы; следом на эту сессию приходят его
//! сообщения (`ShortTunnelBuild`, `PeerTest`), хотя мы ничего не слали.
//!
//! ## Запуск
//!
//! Нужен запущенный тестовый i2pd (`~/.local/opt/i2pd-uu/run-ssu2.sh`:
//! SSU2 на `127.0.0.1:12345`, `reservedrange = false`, httpproxy на
//! `127.0.0.1:4445`, `netDb` очищен).
//!
//! ```text
//! RUST_LOG=uu_i2p=debug cargo run --example uu-i2p-router-i2pd -- \
//!     ~/.local/opt/i2pd-uu/datadir/router.info 127.0.0.1:12345
//! ```
//!
//! (или `UU_I2P_LIVE_RI` / `UU_I2P_LIVE_SSU2` / `UU_I2P_SECS` /
//! `UU_I2P_LIVE_PROXY`).
//!
//! ## Что смотреть
//!
//! Прогон и разбор логов — в `notes/router-live-i2pd.md`.
//!
//! В нашем выводе — `SSU2: сессия установлена`, счётчики принятых I2NP и
//! «в netDb добавлен RI». В логе i2pd (`/tmp/opencode/i2pd-ssu2.log`):
//!
//! ```text
//! SSU2: SessionCreated --> SessionConfirmed --> Established
//! NetDb: DatabaseLookup for ... received
//! NetDb: Database search reply ...
//! ```
//!
//! ## Ограничения
//!
//! - NTCP2-плечо в трейте [`uu_i2p::TransportPool`] пока не умеет
//!   `connect` (`// TODO(step-3a-4)` в `src/router.rs`), поэтому
//!   соединение идёт только по SSU2;
//! - туннелей нет (шаг 3b): `TunnelData`/`TunnelGateway` только
//!   логируются, доставка I2NP — напрямую по сессии;
//! - loopback в RI и caps `f` — обманка для локального теста: настоящим
//!   флудфиллом мы не являемся, нам нужен ровно один путь
//!   `GetClosestFloodfill` из i2pd.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use uu_i2p::{
    DatabaseLookup, I2PTag, I2PX25519Keys, I2npBody, I2npMessage, I2npMessageType, IdentHash,
    Router, RouterConfig, RouterContext, RouterObserver, Ssu2Local, Ssu2Pool, TransportEvent,
    TransportPool,
    config::{DEFAULT_NET_ID, Transport},
    private_keys::I2PPrivateKeys,
    router_info::FullRouterInfo,
};

/// Сколько секунд работаем после установки сессии, если не задано иное.
const DEFAULT_SECS: u64 = 60;

/// Адрес HTTP-прокси тестового i2pd.
const DEFAULT_PROXY: &str = "127.0.0.1:4445";

/// Сколько ждём установки сессии, прежде чем считать прогон неудачным.
const ESTABLISH_TIMEOUT_SECS: u64 = 20;

/// Сколько ждём после оправки RI/lookup, прежде чем закрыть свою сессию и
/// ждать входящую (`--accept`).
///
/// Пул разбирает пакеты своей задачей, так что рукопожатие завершается
/// независимо от того, читает ли роутер свои события; пауза нужна лишь
/// чтобы i2pd успел положить наш RI в свой netDb.
const INBOUND_SETTLE_SECS: u64 = 5;

/// Сколько ещё раз дёрнуть прокси (и с каким периодом), когда мы ждём
/// входящую сессию.
const POKE_ATTEMPTS: usize = 3;
const POKE_PERIOD: Duration = Duration::from_secs(15);

fn init_tracing() {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

// --- наблюдатель -----------------------------------------------------------

/// Счётчики того, что роутер увидел.
#[derive(Debug, Default)]
struct Counters {
    /// Сколько раз сессия доходила до `Established`.
    established: AtomicUsize,
    /// Принятых `DatabaseLookup` (на них роутер отвечает сам).
    lookups: AtomicUsize,
    /// Принятых `DatabaseStore`.
    stores: AtomicUsize,
    /// RI, попавших в netDb (событием транспорта или `DatabaseStore`).
    inserted: AtomicUsize,
    /// Прочих I2NP-сообщений.
    other: AtomicUsize,
    /// Сообщений, которые роутер не обработал (нет слоя туннелей).
    unhandled: AtomicUsize,
}

impl Counters {
    fn print(&self) {
        println!(
            "Сессий установлено: {}",
            self.established.load(Ordering::Relaxed)
        );
        println!(
            "I2NP принято: DatabaseLookup={} DatabaseStore={} прочих={} | RI в netDb={} | необработано={}",
            self.lookups.load(Ordering::Relaxed),
            self.stores.load(Ordering::Relaxed),
            self.other.load(Ordering::Relaxed),
            self.inserted.load(Ordering::Relaxed),
            self.unhandled.load(Ordering::Relaxed),
        );
    }
}

/// Наблюдатель: сигналит об `Established` и считает сообщения.
///
/// Это тот самый шов [`RouterObserver`]: роутер не печатает счётчики сам
/// и не знает про `main`.
#[derive(Clone)]
struct DemoObserver {
    established: Arc<Mutex<Option<oneshot::Sender<IdentHash>>>>,
    counters: Arc<Counters>,
}

impl RouterObserver for DemoObserver {
    fn on_transport_event(&mut self, kind: Transport, event: &TransportEvent) {
        match event {
            TransportEvent::Established { ident } => {
                let nth = self.counters.established.fetch_add(1, Ordering::Relaxed) + 1;
                info!(transport = %kind, peer = %ident.to_base64(), nth, "demo: соединение установлено");
                let sender = {
                    let mut slot = self.established.lock().expect("demo: established");
                    slot.take()
                };
                if let Some(tx) = sender {
                    let _ = tx.send(*ident);
                }
            }
            TransportEvent::Message { from, message } => {
                let counter = match message.message_type() {
                    I2npMessageType::DatabaseLookup => &self.counters.lookups,
                    I2npMessageType::DatabaseStore => &self.counters.stores,
                    _ => &self.counters.other,
                };
                counter.fetch_add(1, Ordering::Relaxed);
                info!(
                    transport = %kind,
                    peer = %from.to_base64(),
                    msg_type = message.message_type().name(),
                    len = message.payload().len(),
                    "demo: принято I2NP"
                );
            }
            _ => {}
        }
    }

    fn on_store(&mut self, handling: &uu_i2p::StoreHandling) {
        if let uu_i2p::StoreHandling::Inserted(ident) = handling {
            self.counters.inserted.fetch_add(1, Ordering::Relaxed);
            info!(peer = %ident.to_base64(), "demo: RouterInfo добавлен в netDb");
        }
    }

    fn on_unhandled_message(&mut self, from: &IdentHash, message: &I2npMessage) {
        self.counters.unhandled.fetch_add(1, Ordering::Relaxed);
        warn!(
            peer = %from.to_base64(),
            msg_type = message.message_type().name(),
            "demo: сообщение без обработчика (туннелей пока нет)"
        );
    }
}

// --- аргументы -------------------------------------------------------------

struct Args {
    ri_path: String,
    addr: SocketAddr,
    proxy: SocketAddr,
    secs: u64,
    /// После размена закрыть свою сессию и ждать, чтобы i2pd позвонил сам
    /// (проверка входящего пути — мы в роли ответчика).
    accept: bool,
}

fn parse_args() -> Args {
    let mut positional = Vec::new();
    let mut secs = None;
    let mut proxy = None;
    let mut accept = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--secs" => secs = args.next().and_then(|s| s.parse().ok()),
            "--proxy" => proxy = args.next().and_then(|s| s.parse().ok()),
            "--accept" => accept = Some(true),
            _ => positional.push(arg),
        }
    }

    let ri_path = positional
        .first()
        .cloned()
        .or_else(|| std::env::var("UU_I2P_LIVE_RI").ok());
    let Some(ri_path) = ri_path else {
        eprintln!(
            "usage: uu-i2p-router-i2pd <router.info> [host:port] [--secs N] [--proxy host:port] [--accept]\n\
             \n\
             env: UU_I2P_LIVE_RI, UU_I2P_LIVE_SSU2, UU_I2P_LIVE_PROXY, UU_I2P_SECS, UU_I2P_ACCEPT"
        );
        std::process::exit(1);
    };
    let addr = positional
        .get(1)
        .cloned()
        .or_else(|| std::env::var("UU_I2P_LIVE_SSU2").ok())
        .unwrap_or_else(|| "127.0.0.1:12345".to_owned())
        .parse()
        .expect("host:port");
    let proxy = proxy
        .or_else(|| std::env::var("UU_I2P_LIVE_PROXY").ok())
        .unwrap_or_else(|| DEFAULT_PROXY.to_owned())
        .parse()
        .expect("host:port");
    let secs = secs
        .or_else(|| {
            std::env::var("UU_I2P_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(DEFAULT_SECS);

    Args {
        ri_path,
        addr,
        proxy,
        secs,
        accept: accept
            .or_else(|| std::env::var("UU_I2P_ACCEPT").ok().map(|v| v != "0"))
            .unwrap_or(false),
    }
}

// --- триггер через прокси --------------------------------------------------

/// Просит HTTP-прокси i2pd сходить на `host` — этого достаточно, чтобы
/// i2pd пошёл за `LeaseSet` к ближайшему флудфиллу (к нам).
///
/// Возвращает строку статуса ответа (или `None`, если прокси не ответил).
async fn poke_proxy(proxy: SocketAddr, host: &str) -> Option<String> {
    let mut stream = TcpStream::connect(proxy).await.ok()?;
    let request =
        format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut buf)).await;
    Some(String::from_utf8_lossy(&buf).lines().next()?.to_owned())
}

/// Один заход через прокси случайным b32-адресом.
async fn poke_once(proxy: SocketAddr) {
    let b32 = I2PTag::from_array(rand::random::<[u8; 32]>()).to_base32();
    let host = format!("{b32}.b32.i2p");
    println!("Триггер: GET http://{host}/ через прокси i2pd {proxy}");
    match poke_proxy(proxy, &host).await {
        Some(status) => println!("Прокси ответил: {status}"),
        None => println!("Прокси не ответил (для этой демонстрации это не смертельно)"),
    }
}

/// Дёргает прокси ещё `attempts` раз с периодом `period`.
///
/// Нужно, когда мы уже закрыли свою сессию: i2pd может не сразу собраться
/// пойти за `LeaseSet` к флудфиллу, а нам важно, чтобы это случилось, пока
/// сессии нет — тогда он обязан позвонить сам.
fn spawn_pokes(proxy: SocketAddr, attempts: usize, period: Duration) {
    tokio::spawn(async move {
        for _ in 0..attempts {
            tokio::time::sleep(period).await;
            poke_once(proxy).await;
        }
    });
}

// --- сборка локального роутера ---------------------------------------------

/// Локальный роутер во всём, что нужно `main` до и после прогона.
struct LocalRouter {
    router: Router,
    pool: Arc<dyn TransportPool>,
    counters: Arc<Counters>,
    /// Приходит `Established` из цикла роутера.
    established: oneshot::Receiver<IdentHash>,
    own: IdentHash,
    addr: SocketAddr,
}

impl LocalRouter {
    /// Собирает сокет, конфиг, контекст, пул и роутер.
    ///
    /// RI публикует loopback, потому что i2pd проверяет `Host mismatch`
    /// в `SessionConfirmed` (`SSU2Session.cpp:1400`); caps `f` — чтобы
    /// i2pd выбрал нас ближайшим флудфиллом и спросил `LeaseSet`.
    async fn build() -> Self {
        // Свой UDP-сокет: порт нужен до сборки RI (его публикуем).
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let addr = socket.local_addr().expect("local_addr");

        // Ключи: identity роутера и статик транспортов (в i2pd у NTCP2 и
        // SSU2 одна пара — `s` в RI берётся из неё же).
        let router_keys = I2PPrivateKeys::generate_default().expect("router keys");
        let static_keys = I2PX25519Keys::generate();
        let ntcp2_static =
            I2PX25519Keys::from_private(&static_keys.private_key(), Some(static_keys.public_key()));
        let intro: [u8; 32] = rand::random();

        let config = RouterConfig::builder()
            .keys(router_keys)
            .ntcp2_keys(ntcp2_static, [0x42; 16])
            .listen_ssu2_published(addr, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .ssu2_intro_key(intro)
            .floodfill(true)
            .allow_reserved_advertise(true)
            .build()
            .expect("RouterConfig");

        let ctx = RouterContext::new(config).expect("RouterContext");
        let own = *ctx.own_ident_hash();
        let own_ri = ctx.own_ri().to_buffer().expect("own RouterInfo");
        let local =
            Ssu2Local::new(static_keys, intro, own_ri, DEFAULT_NET_ID, false).expect("Ssu2Local");
        let pool: Arc<dyn TransportPool> =
            Arc::new(Ssu2Pool::with_socket(socket, local).expect("Ssu2Pool"));

        let counters = Arc::new(Counters::default());
        let (established_tx, established) = oneshot::channel();
        let observer = DemoObserver {
            established: Arc::new(Mutex::new(Some(established_tx))),
            counters: Arc::clone(&counters),
        };

        Self {
            router: Router::new(ctx).with_observer(Box::new(observer)),
            pool,
            counters,
            established,
            own,
            addr,
        }
    }
}

/// Параметры прогона из аргументов командной строки.
#[derive(Clone, Copy, Debug)]
struct RunOptions {
    addr: SocketAddr,
    proxy: SocketAddr,
    secs: u64,
    accept: bool,
}

impl RunOptions {
    const fn from_args(args: &Args) -> Self {
        Self {
            addr: args.addr,
            proxy: args.proxy,
            secs: args.secs,
            accept: args.accept,
        }
    }
}

/// Тело задачи с роутером: подключить пул, позвонить i2pd, отправить
/// пару I2NP и крутить цикл.
///
/// Возвращает роутер обратно — `main` печатает по нему итог, а `run_until`
/// владеет им монопольно.
async fn run_router(
    mut router: Router,
    pool: Arc<dyn TransportPool>,
    ri_bytes: &[u8],
    own: IdentHash,
    options: RunOptions,
    script: impl Future<Output = ()> + Send,
) -> uu_i2p::Result<Router> {
    router.attach(pool)?;
    let i2pd = router
        .dial(ri_bytes, Some(options.addr), Some(Transport::Ssu2))
        .await?;
    info!(peer = %i2pd.to_base64(), "demo: dial");

    // Публикуем себя — путь `Router::send` (сессия уже в карте).
    let store = router.context().build_own_database_store()?;
    router
        .send(
            &i2pd,
            I2npMessage::from_body(I2npBody::DatabaseStore(store))?,
        )
        .await?;
    println!("Свой RouterInfo отправлен i2pd (DatabaseStore)");

    // Просим RI собеседника: i2pd отвечает на RI-lookup'ы, даже если сам
    // не флудфилл. (Тик роутера отправил бы это ближайшему флудфиллу из
    // netDb, а там сейчас никого нет.)
    let lookup = DatabaseLookup::new_router_info(i2pd, own, None, Vec::new());
    router
        .send(
            &i2pd,
            I2npMessage::from_body(I2npBody::DatabaseLookup(lookup))?,
        )
        .await?;
    println!("Запрошен RouterInfo i2pd (DatabaseLookup)");

    if options.accept {
        // Проверка входящего пути: рвём свою сессию и ждём, чтобы i2pd
        // позвонил сам. Он это делает по необходимости
        // (`Transports::PostMessages` → `ConnectToPeer`), а адрес берёт из
        // нашего RI в своём netDb — туда он попал из `SessionConfirmed`.
        //
        // События (`Established`/`Disconnected`) пока копятся в канале
        // роутера: их разберёт `run_until` ниже — потому и `nth=1`
        // (наша сессия) с `nth=2` (входящая) видны уже в цикле.
        tokio::time::sleep(Duration::from_secs(INBOUND_SETTLE_SECS)).await;
        println!();
        println!("--- Рвём свою сессию (её события разберёт цикл ниже) ---");
        let closed = router.close(&i2pd).await?;
        println!("Свою сессию закрыли ({closed}); дальше ждём входящую: i2pd должен позвонить сам");
    }

    // Сценарий прогона — отдельная футура: она живёт, пока роутер крутит
    // цикл (`run_until`), и делает то, что не является обработкой событий:
    // дёргает прокси и ждёт отведённое время.
    router.run_until(script).await?;
    Ok(router)
}

/// Что делает демонстрация, пока роутер крутит цикл.
///
/// Прокси дёргаем уже внутри цикла: i2pd должен пойти за `LeaseSet` к
/// ближайшему флудфиллу (к нам) — так он либо пишет нам в готовую сессию,
/// либо, если мы её закрыли, звонит сам.
async fn run_script(counters: Arc<Counters>, options: RunOptions) {
    poke_once(options.proxy).await;
    if options.accept {
        spawn_pokes(options.proxy, POKE_ATTEMPTS, POKE_PERIOD);
    }
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(options.secs)) => {
            println!();
            println!("--- Итог по счётчикам (на момент остановки) ---");
            counters.print();
        }
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// Итог прогона: что осталось в состоянии роутера.
fn print_summary(router: &Router, i2pd: &IdentHash, counters: &Counters, local_addr: SocketAddr) {
    println!("=== Итог ===");
    println!("Наш SSU2:           {local_addr}");
    println!("Пир в карте сессий: {:?}", router.session_transport(i2pd));
    println!("Записей в netDb:    {}", router.context().netdb().len());
    counters.print();
    println!();
    println!(
        "Лог i2pd: grep -a \"SessionConfirmed\\|DatabaseLookup\\|search reply\\|RouterInfo\" \
         /tmp/opencode/i2pd-ssu2.log | tail -30"
    );
    println!(
        "Подсказка: пустой 'RI в netDb' при живом DatabaseLookup — смотрим, что i2pd ответил \
         (RUST_LOG=uu_i2p=trace)."
    );
    println!("Горячие клавиши прогона: RUST_LOG=uu_i2p=debug UU_I2P_SECS=120.");
}

// --- main ------------------------------------------------------------------

#[tokio::main]
async fn main() {
    init_tracing();
    let args = parse_args();

    println!("=== Демонстрация: объединённый Router против i2pd (SSU2) ===");
    println!("RouterInfo i2pd: {}", args.ri_path);
    println!("i2pd SSU2:       {}", args.addr);
    println!("i2pd httpproxy:  {}", args.proxy);
    println!();

    let ri_bytes = std::fs::read(&args.ri_path).expect("read i2pd RouterInfo");
    let remote_ri = FullRouterInfo::from_buffer(&ri_bytes).expect("parse i2pd RouterInfo");
    let i2pd = *remote_ri.ident_hash();

    let local = LocalRouter::build().await;
    println!("Наш роутер:      {}", local.own.to_base64());
    println!("Наш SSU2:        {}", local.addr);
    println!();

    let LocalRouter {
        router,
        pool,
        counters,
        established,
        own,
        addr: local_addr,
    } = local;
    let options = RunOptions::from_args(&args);
    let script = run_script(Arc::clone(&counters), options);
    let loop_task =
        tokio::spawn(
            async move { run_router(router, pool, &ri_bytes, own, options, script).await },
        );

    // Ждём `Established`: его приносит наблюдатель из цикла роутера.
    match tokio::time::timeout(Duration::from_secs(ESTABLISH_TIMEOUT_SECS), established).await {
        Ok(Ok(ident)) => println!("SSU2: сессия с i2pd установлена ({})", ident.to_base64()),
        _ => eprintln!("SSU2: сессия не установилась за {ESTABLISH_TIMEOUT_SECS} с — смотрим логи"),
    }
    println!();

    match loop_task.await {
        Ok(Ok(router)) => print_summary(&router, &i2pd, &counters, local_addr),
        Ok(Err(error)) => eprintln!("Цикл роутера завершился с ошибкой: {error}"),
        Err(join) => eprintln!("Задача роутера упала: {join}"),
    }
}
