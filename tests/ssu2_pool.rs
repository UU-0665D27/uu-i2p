//! Пул SSU2: interop двух пулов в одном процессе (реальный UDP на 127.0.0.1).
//!
//! Проверяем весь путь транспорта: рукопожатие (Alice → Bob), обмен
//! `RouterInfo`, I2NP в обе стороны, очередь до установления и закрытие.
//! Внешний i2pd не нужен — оба конца наши.

use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use uu_i2p::{
    I2PTag, IdentHash,
    config::{DEFAULT_NET_ID, DEFAULT_VERSION},
    crypto::I2PX25519Keys,
    i2np::{I2npHeader, I2npMessageType},
    i2np_message::I2npMessage,
    private_keys::I2PPrivateKeys,
    router_info::{FullRouterInfo, RouterInfo, RouterInfoBuilder, RouterInfoCaps},
    router_info_address::I2PAddress,
    ssu2_pool::{Ssu2Event, Ssu2Local, Ssu2Pool, check_session_confirmed_router_info},
};

fn init_tracing() {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_millis(),
    )
    .expect("milliseconds since epoch exceeds u64")
}

/// Узел: пул, его `RouterInfo` (для передачи собеседнику) и адрес сокета.
struct Node {
    pool: Ssu2Pool,
    ri: Vec<u8>,
    addr: SocketAddr,
}

/// Поднимает узел, публикующий в `RouterInfo` настоящий порт сокета.
async fn make_node() -> Node {
    make_node_advertising(None).await
}

/// Поднимает узел: сокет на эфемерном порту 127.0.0.1 и **опубликованный**
/// SSU2-адрес (иначе инициатор не найдёт, куда подключаться).
///
/// `advertised_port` позволяет опубликовать заведомо недостижимый порт —
/// так проверяется [`Ssu2Pool::connect_to`].
///
/// `RouterInfo` собирается вручную: `RouterConfig` запрещает публиковать
/// loopback-адрес (в реальном роутере это бессмысленно), а тесту нужен именно
/// локальный адрес с настоящим портом сокета.
async fn make_node_advertising(advertised_port: Option<u16>) -> Node {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = socket.local_addr().expect("local_addr");
    let port = advertised_port.unwrap_or_else(|| addr.port());
    let keys = I2PPrivateKeys::generate_default().expect("generate keys");
    let static_keys = I2PX25519Keys::generate();
    let mut intro = [0u8; 32];
    rand::rng().fill_bytes(&mut intro);

    let body = RouterInfo::builder()
        .timestamp(now_ms())
        .add_address(I2PAddress::ssu2_published(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            I2PTag::from_array(*static_keys.public_key()),
            I2PTag::from_array(intro),
        ))
        .caps(RouterInfoCaps::parse(b"L"))
        .version(DEFAULT_VERSION)
        .net_id(i32::from(DEFAULT_NET_ID))
        .build();
    let ri = FullRouterInfo::from_keys(&keys, body).expect("own RouterInfo");
    let ri_bytes = ri.to_buffer().expect("serialize own RouterInfo");
    let local = Ssu2Local::new(static_keys, intro, ri_bytes.clone(), DEFAULT_NET_ID, false)
        .expect("Ssu2Local");
    info!(
        %addr,
        published_port = port,
        ri_len = ri_bytes.len(),
        ident = %ri.ident_hash().to_base64(),
        "node ready"
    );
    let pool = Ssu2Pool::with_socket(socket, local).expect("Ssu2Pool");
    Node {
        pool,
        ri: ri_bytes,
        addr,
    }
}

/// Ждёт событие по предикату, сохраняя все прочие (их можно искать позже).
async fn wait_event(
    pool: &Ssu2Pool,
    log: &mut Vec<Ssu2Event>,
    what: &str,
    pred: impl Fn(&Ssu2Event) -> bool,
) -> Ssu2Event {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(pos) = log.iter().position(&pred) {
            return log.remove(pos);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = timeout(remaining, pool.next_event())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {what}"))
            .expect("next_event");
        info!(?event, "event");
        log.push(event);
    }
}

/// I2NP-сообщение с заданным `msg_id` и payload.
///
/// Expiration — на целую секунду вперёд: короткий формат I2NP хранит секунды,
/// поэтому только такие значения переживают round-trip байт-в-байт.
fn message(msg_id: u32, payload: &[u8]) -> I2npMessage {
    let header = I2npHeader {
        message_type: I2npMessageType::Data,
        msg_id,
        expiration_ms: (now_ms() / 1000 + 60) * 1000,
        size: u16::try_from(payload.len()).expect("payload fits"),
        checksum: None,
    };
    I2npMessage::with_header(header, payload.to_vec())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn two_pools_handshake_router_info_and_i2np() {
    init_tracing();
    let alice = make_node().await;
    let bob = make_node().await;
    let alice_ident = *alice.pool.ident();
    let bob_ident = *bob.pool.ident();
    assert_ne!(alice_ident, bob_ident, "identities must differ");

    let mut alice_events: Vec<Ssu2Event> = Vec::new();
    let mut bob_events: Vec<Ssu2Event> = Vec::new();

    // --- рукопожатие -----------------------------------------------------

    let connected = alice.pool.connect(&bob.ri).await.expect("connect");
    assert_eq!(connected, bob_ident, "connect returns the remote ident");

    let established = wait_event(&alice.pool, &mut alice_events, "alice Established", |e| {
        matches!(e, Ssu2Event::Established { .. })
    })
    .await;
    assert_eq!(
        established,
        Ssu2Event::Established { ident: bob_ident },
        "alice sees bob"
    );
    let established = wait_event(&bob.pool, &mut bob_events, "bob Established", |e| {
        matches!(e, Ssu2Event::Established { .. })
    })
    .await;
    assert_eq!(
        established,
        Ssu2Event::Established { ident: alice_ident },
        "bob sees alice"
    );

    // Bob получает RI Alice в SessionConfirmed, Alice — RI Bob'а data-пакетом.
    let ri = wait_event(&bob.pool, &mut bob_events, "bob RouterInfo", |e| {
        matches!(e, Ssu2Event::RouterInfo { .. })
    })
    .await;
    match ri {
        Ssu2Event::RouterInfo { from, ri_bytes } => {
            assert_eq!(from, alice_ident);
            assert_eq!(
                ri_bytes, alice.ri,
                "bob stores exactly the RouterInfo alice sent"
            );
        }
        _ => unreachable!(),
    }
    let ri = wait_event(&alice.pool, &mut alice_events, "alice RouterInfo", |e| {
        matches!(e, Ssu2Event::RouterInfo { .. })
    })
    .await;
    match ri {
        Ssu2Event::RouterInfo { from, ri_bytes } => {
            assert_eq!(from, bob_ident);
            assert_eq!(ri_bytes, bob.ri);
        }
        _ => unreachable!(),
    }

    // --- I2NP в обе стороны ----------------------------------------------

    let ping = message(0x1111_0001, b"alice -> bob");
    alice
        .pool
        .send_to(&bob_ident, ping.clone())
        .await
        .expect("send to bob");
    let event = wait_event(&bob.pool, &mut bob_events, "bob message", |e| {
        matches!(e, Ssu2Event::Message { .. })
    })
    .await;
    match event {
        Ssu2Event::Message { from, message } => {
            assert_eq!(from, alice_ident);
            assert_eq!(message, ping);
        }
        _ => unreachable!(),
    }

    let reply = message(0x2222_0002, b"bob -> alice");
    bob.pool
        .send_to(&alice_ident, reply.clone())
        .await
        .expect("send to alice");
    let event = wait_event(&alice.pool, &mut alice_events, "alice message", |e| {
        matches!(e, Ssu2Event::Message { .. })
    })
    .await;
    match event {
        Ssu2Event::Message { from, message } => {
            assert_eq!(from, bob_ident);
            assert_eq!(message, reply);
        }
        _ => unreachable!(),
    }

    // --- закрытие --------------------------------------------------------

    assert!(alice.pool.close(&bob_ident).await.expect("close"));
    let event = wait_event(&bob.pool, &mut bob_events, "bob Disconnected", |e| {
        matches!(e, Ssu2Event::Disconnected { .. })
    })
    .await;
    assert_eq!(event, Ssu2Event::Disconnected { ident: alice_ident });
    assert!(
        alice
            .pool
            .session_idents()
            .await
            .expect("sessions")
            .is_empty(),
        "alice closed the session"
    );
}

#[tokio::test]
async fn i2np_queued_until_established() {
    init_tracing();
    let alice = make_node().await;
    let bob = make_node().await;
    let bob_ident = *bob.pool.ident();
    let mut bob_events: Vec<Ssu2Event> = Vec::new();

    // Отправляем сразу после `connect`, не дожидаясь `Established`: сообщение
    // должно ждать в очереди сессии (i2pd `m_IntermediateQueue`).
    alice.pool.connect(&bob.ri).await.expect("connect");
    let msg = message(0x3333_0003, b"queued before established");
    alice
        .pool
        .send_to(&bob_ident, msg.clone())
        .await
        .expect("send before established");

    let event = wait_event(&bob.pool, &mut bob_events, "bob message", |e| {
        matches!(e, Ssu2Event::Message { .. })
    })
    .await;
    match event {
        Ssu2Event::Message { message, .. } => assert_eq!(message, msg),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn reconnect_after_close() {
    init_tracing();
    let alice = make_node().await;
    let bob = make_node().await;
    let alice_ident = *alice.pool.ident();
    let bob_ident = *bob.pool.ident();
    let mut alice_events: Vec<Ssu2Event> = Vec::new();
    let mut bob_events: Vec<Ssu2Event> = Vec::new();

    for round in 0..2 {
        alice.pool.connect(&bob.ri).await.expect("connect");
        wait_event(&alice.pool, &mut alice_events, "alice Established", |e| {
            matches!(e, Ssu2Event::Established { .. })
        })
        .await;
        wait_event(&bob.pool, &mut bob_events, "bob Established", |e| {
            matches!(e, Ssu2Event::Established { .. })
        })
        .await;
        info!(round, "session established");

        assert!(alice.pool.close(&bob_ident).await.expect("close"));
        assert!(
            alice
                .pool
                .session_idents()
                .await
                .expect("sessions")
                .is_empty(),
            "alice forgot the session"
        );
        // Bob узнаёт о закрытии (Termination или таймаут) — вторая итерация
        // проверяет, что пул умеет поднять соединение заново.
        if round == 0 {
            wait_event(&bob.pool, &mut bob_events, "bob Disconnected", |e| {
                matches!(e, Ssu2Event::Disconnected { .. })
            })
            .await;
        }
    }
    assert_ne!(alice_ident, bob_ident);
}

#[tokio::test]
async fn connect_to_explicit_address() {
    init_tracing();
    let alice = make_node().await;
    // Bob публикует недостижимый порт: обычный `connect` по `RouterInfo` до
    // него не дошёл бы, а `connect_to` использует настоящий адрес сокета.
    let bob = make_node_advertising(Some(1)).await;
    let bob_ident = *bob.pool.ident();
    let mut alice_events: Vec<Ssu2Event> = Vec::new();

    let ident = alice
        .pool
        .connect_to(&bob.ri, bob.addr)
        .await
        .expect("connect_to");
    assert_eq!(ident, bob_ident);

    let established = wait_event(&alice.pool, &mut alice_events, "alice Established", |e| {
        matches!(e, Ssu2Event::Established { .. })
    })
    .await;
    assert_eq!(established, Ssu2Event::Established { ident: bob_ident });

    // Блок `Address` приходит и в `Retry`, и в `SessionCreated`: пул сообщает,
    // каким видит нас собеседник (i2pd `HandleAddress` →
    // `i2p::context.UpdateAddress`). Оба раза это наш сокет.
    let external: Vec<SocketAddr> = alice_events
        .iter()
        .filter_map(|e| match e {
            Ssu2Event::ExternalAddress { addr, from } => {
                assert_eq!(*from, Some(bob_ident), "событие не от собеседника");
                Some(*addr)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        external.len(),
        2,
        "ожидали адрес из `Retry` и из `SessionCreated`: {external:?}"
    );
    assert!(
        external.iter().all(|addr| *addr == alice.addr),
        "собеседник видит нас не по нашему сокету: {external:?}"
    );
}

/// `RouterInfo` собеседника из `SessionConfirmed` — проверки ответчика
/// (i2pd `SSU2Session::ProcessSessionConfirmed`, `SSU2Session.cpp:1353-1420`).
///
/// Проверяем функцию напрямую: подделывать эти случаи по сети долго
/// (у каждой ошибки — свой таймаут рукопожатия).
#[test]
fn session_confirmed_router_info_checks() {
    let remote: SocketAddr = "127.0.0.1:12345".parse().expect("addr");
    let other: SocketAddr = "127.0.0.2:12345".parse().expect("addr");

    // Подпись, свежесть и версия в порядке — RI принимается.
    let (bytes, static_key) = peer_router_info(|body| body);
    let (ident, intro_key, published) =
        check_session_confirmed_router_info(&bytes, remote, Some(static_key)).expect("valid RI");
    let ri = FullRouterInfo::from_buffer(&bytes).expect("parse RI");
    let addr = ri.body().ssu2_address(false).expect("SSU2 address");
    assert!(published, "тестовый RI публикует SSU2-адрес");
    assert_eq!(&ident, ri.ident_hash(), "ident должен быть из RI");
    assert_eq!(
        &intro_key,
        addr.i.as_bytes(),
        "intro-ключ должен быть из RI"
    );

    // Подпись испорчена (последний байт — часть подписи).
    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        check_session_confirmed_router_info(&tampered, remote, Some(static_key)).is_err(),
        "испорченная подпись должна отвергаться"
    );

    // Слишком старый: 91 минута.
    let (bytes, static_key) = peer_router_info(|body| body.timestamp(now_ms() - 91 * 60 * 1000));
    assert!(
        check_session_confirmed_router_info(&bytes, remote, Some(static_key)).is_err(),
        "RI старше 90 минут должен отвергаться"
    );

    // Из будущего: +3 минуты.
    let (bytes, static_key) = peer_router_info(|body| body.timestamp(now_ms() + 3 * 60 * 1000));
    assert!(
        check_session_confirmed_router_info(&bytes, remote, Some(static_key)).is_err(),
        "RI из будущего должен отвергаться"
    );

    // Старая версия (0.9.0) без `caps=O`.
    let (bytes, static_key) = peer_router_info(|body| body.version(900));
    assert!(
        check_session_confirmed_router_info(&bytes, remote, Some(static_key)).is_err(),
        "старая версия без high-bandwidth должна отвергаться"
    );

    // Та же версия, но `caps=O` — принимается (i2pd `:1372`).
    let (bytes, static_key) =
        peer_router_info(|body| body.version(900).caps(RouterInfoCaps::parse(b"O")));
    assert!(
        check_session_confirmed_router_info(&bytes, remote, Some(static_key)).is_ok(),
        "старая версия с high-bandwidth принимается"
    );

    // Опубликованный адрес не совпал с адресом пакета.
    let (bytes, static_key) = peer_router_info(|body| body);
    assert!(
        check_session_confirmed_router_info(&bytes, other, Some(static_key)).is_err(),
        "чужой адрес пакета должен отвергаться"
    );

    // Другой статический ключ (не тот, что был в рукопожатии).
    let mut wrong = static_key;
    wrong[0] ^= 0x01;
    assert!(
        check_session_confirmed_router_info(&bytes, remote, Some(wrong)).is_err(),
        "чужой статический ключ должен отвергаться"
    );
}

/// `RouterInfo` собеседника для проверок: байты и статический ключ из его
/// SSU2-адреса. `fix` позволяет подпортить body (timestamp, версию) — подпись
/// пересчитывается, как в настоящем роутере.
fn peer_router_info(
    fix: impl FnOnce(RouterInfoBuilder) -> RouterInfoBuilder,
) -> (Vec<u8>, [u8; 32]) {
    let keys = I2PPrivateKeys::generate_default().expect("generate keys");
    let static_keys = I2PX25519Keys::generate();
    let mut intro = [0u8; 32];
    rand::rng().fill_bytes(&mut intro);
    let body = fix(RouterInfo::builder()
        .timestamp(now_ms())
        .add_address(I2PAddress::ssu2_published(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12345,
            I2PTag::from_array(*static_keys.public_key()),
            I2PTag::from_array(intro),
        ))
        .caps(RouterInfoCaps::parse(b"L"))
        .version(DEFAULT_VERSION)
        .net_id(i32::from(DEFAULT_NET_ID)))
    .build();
    let ri = FullRouterInfo::from_keys(&keys, body).expect("own RouterInfo");
    (
        ri.to_buffer().expect("serialize RouterInfo"),
        *static_keys.public_key(),
    )
}

/// Пока `SessionCreated` не принят, endpoint занят исходящей сессией
/// (i2pd `m_PendingOutgoingSessions` + `CheckPendingOutgoingSession`,
/// `SSU2.cpp:865`), а после смерти сессии — освобождается.
///
/// Второй конец здесь — сокет, который никогда не отвечает: так сессия
/// детерминированно остаётся в `SessionRequestSent`.
#[tokio::test]
async fn pending_endpoint_blocks_duplicate_connect_until_session_dies() {
    init_tracing();
    let alice = make_node().await;
    let peer1 = make_node_advertising(None).await;
    let peer2 = make_node_advertising(None).await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind silent");
    let silent_addr = silent.local_addr().expect("local_addr");

    let ident1 = alice
        .pool
        .connect_to(&peer1.ri, silent_addr)
        .await
        .expect("first connect_to");
    assert_eq!(ident1, *peer1.pool.ident());

    let error = alice
        .pool
        .connect_to(&peer2.ri, silent_addr)
        .await
        .expect_err("endpoint is already pending");
    assert!(
        error.to_string().contains("already pending"),
        "unexpected error: {error}"
    );

    // Сессия умерла до `SessionCreated` — запись освобождается
    // (`remove_session`; i2pd так не делает, см. `notes/i2pd-bugs.md`, п. 7).
    assert!(alice.pool.close(&ident1).await.expect("close"));
    let ident2 = alice
        .pool
        .connect_to(&peer2.ri, silent_addr)
        .await
        .expect("second connect_to");
    assert_eq!(ident2, *peer2.pool.ident());
}

// --- смена адреса собеседника (`Path Challenge`) -------------------------

/// Наблюдение прокси: с какого из своих адресов пришёл пакет от Alice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Старый адрес собеседника (`proxy.front`).
    Front,
    /// Новый адрес (`proxy.new`) — с него Bob'овы пакеты уходят после
    /// «переезда», и туда же Alice шлёт `Path Challenge`.
    New,
}

/// Прокси между двумя пулами: Alice думает, что Bob живёт на `front`, а Bob
/// видит `back` — то есть адрес собеседника меняется только у Alice, как при
/// NAT rebinding.
///
/// Пакеты Bob → Alice уходят с `front` (до переключения) или с `new` (после);
/// всё, что Alice шлёт на `new` (челлендж, а затем обычный трафик), уходит
/// Bob'у с `back`.
struct Proxy {
    /// Адрес, по которому Alice знает Bob'а.
    front: SocketAddr,
    /// «Новый» адрес собеседника.
    new: SocketAddr,
    /// Начать отправлять Bob'овы пакеты Alice с `new`.
    switched: Arc<AtomicBool>,
    /// Не доставлять Bob'у то, что приходит на `new` (потерянный челлендж).
    drop_new: Arc<AtomicBool>,
    /// С какого адреса пришёл очередной пакет от Alice.
    seen: mpsc::UnboundedReceiver<Seen>,
}

impl Proxy {
    /// Дожидается следующего пакета от Alice.
    async fn next_seen(&mut self) -> Seen {
        timeout(Duration::from_secs(5), self.seen.recv())
            .await
            .expect("timeout waiting for a packet from alice")
            .expect("proxy channel closed")
    }

    /// Забывает накопленные наблюдения (перед переключением).
    fn drain(&mut self) {
        while self.seen.try_recv().is_ok() {}
    }
}

/// Поднимает прокси к настоящему сокету `bob`.
async fn start_proxy(bob: SocketAddr) -> Proxy {
    let front = UdpSocket::bind("127.0.0.1:0").await.expect("bind front");
    let new = UdpSocket::bind("127.0.0.1:0").await.expect("bind new");
    let back = UdpSocket::bind("127.0.0.1:0").await.expect("bind back");
    let front_addr = front.local_addr().expect("front addr");
    let new_addr = new.local_addr().expect("new addr");
    let switched = Arc::new(AtomicBool::new(false));
    let drop_new = Arc::new(AtomicBool::new(false));
    let (tx, seen) = mpsc::unbounded_channel();
    let switch_flag = Arc::clone(&switched);
    let drop_flag = Arc::clone(&drop_new);
    tokio::spawn(async move {
        let mut alice: Option<SocketAddr> = None;
        let mut from_front = [0u8; 2048];
        let mut from_new = [0u8; 2048];
        let mut from_bob = [0u8; 2048];
        loop {
            tokio::select! {
                received = front.recv_from(&mut from_front) => {
                    let (n, addr) = received.expect("front recv");
                    alice = Some(addr);
                    let _ = tx.send(Seen::Front);
                    let _ = back.send_to(&from_front[..n], bob).await;
                }
                received = new.recv_from(&mut from_new) => {
                    let (n, _) = received.expect("new recv");
                    let _ = tx.send(Seen::New);
                    if !drop_flag.load(Ordering::Relaxed) {
                        let _ = back.send_to(&from_new[..n], bob).await;
                    }
                }
                received = back.recv_from(&mut from_bob) => {
                    let (n, _) = received.expect("back recv");
                    let source = if switch_flag.load(Ordering::Relaxed) { &new } else { &front };
                    if let Some(addr) = alice {
                        let _ = source.send_to(&from_bob[..n], addr).await;
                    }
                }
            }
        }
    });
    Proxy {
        front: front_addr,
        new: new_addr,
        switched,
        drop_new,
        seen,
    }
}

/// Поднимает пару через прокси и доводит рукопожатие с обменом `RouterInfo` до
/// конца — переключать адрес раньше нельзя, иначе развалится рукопожатие.
async fn proxy_pair() -> (Node, Node, Proxy, IdentHash, IdentHash) {
    let bob = make_node().await;
    let proxy = start_proxy(bob.addr).await;
    let alice = make_node().await;
    let alice_ident = *alice.pool.ident();
    let bob_ident = *bob.pool.ident();
    info!(
        front = %proxy.front,
        new = %proxy.new,
        "proxy ready: Alice знает Bob'а по адресу `front`, `new` — адрес после переезда"
    );

    assert_eq!(
        alice
            .pool
            .connect_to(&bob.ri, proxy.front)
            .await
            .expect("connect through proxy"),
        bob_ident,
        "Alice подключается к адресу прокси"
    );

    let mut alice_events = Vec::new();
    let mut bob_events = Vec::new();
    let _ = wait_event(&alice.pool, &mut alice_events, "alice Established", |e| {
        matches!(e, Ssu2Event::Established { .. })
    })
    .await;
    let _ = wait_event(&bob.pool, &mut bob_events, "bob Established", |e| {
        matches!(e, Ssu2Event::Established { .. })
    })
    .await;
    let _ = wait_event(&bob.pool, &mut bob_events, "bob RouterInfo", |e| {
        matches!(e, Ssu2Event::RouterInfo { .. })
    })
    .await;
    let _ = wait_event(&alice.pool, &mut alice_events, "alice RouterInfo", |e| {
        matches!(e, Ssu2Event::RouterInfo { .. })
    })
    .await;
    (alice, bob, proxy, alice_ident, bob_ident)
}

/// Смена адреса собеседника: на первый же пакет с нового адреса Alice шлёт
/// `Path Challenge` туда, а адрес (`remote`) меняет только после совпавшего
/// `Path Response` (i2pd `ProcessData`, `SSU2Session.cpp:1752`).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn path_response_updates_remote_endpoint() {
    init_tracing();
    let (alice, bob, mut proxy, _alice_ident, bob_ident) = proxy_pair().await;
    let mut bob_events = Vec::new();

    proxy.drain();
    proxy.switched.store(true, Ordering::Relaxed);

    // Пока путь не подтверждён, трафик идёт на старый адрес.
    alice
        .pool
        .send_to(&bob_ident, message(0x1111_0001, b"via front"))
        .await
        .expect("send");
    assert_eq!(
        proxy.next_seen().await,
        Seen::Front,
        "пакет от Alice идёт на старый адрес"
    );
    let _ = wait_event(&bob.pool, &mut bob_events, "bob message", |e| {
        matches!(e, Ssu2Event::Message { .. })
    })
    .await;

    // Ответ Bob'а приходит от нового адреса: Alice шлёт туда `Path Challenge`,
    // Bob отвечает `Path Response`, и только потом путь переключается.
    // Дожидаемся **двух** пакетов на новом адресе: челленджа и трафика после
    // подтверждения.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut on_new = 0u32;
    let mut probes = 0u32;
    while on_new < 2 && Instant::now() < deadline {
        alice
            .pool
            .send_to(&bob_ident, message(0x1111_0100 + probes, b"probe"))
            .await
            .expect("send probe");
        probes += 1;
        if proxy.next_seen().await == Seen::New {
            on_new += 1;
        }
    }
    assert!(
        on_new >= 2,
        "после `Path Response` пакеты идут на новый адрес (пакетов на новом адресе: {on_new})"
    );
}

/// Без `Path Response` адрес собеседника не меняется: `Path Challenge` уходит,
/// но трафик продолжает идти на прежний адрес, и повторно челлендж не шлётся
/// (i2pd: `from != m_PathChallenge->second`).
#[tokio::test]
async fn path_challenge_without_response_keeps_endpoint() {
    init_tracing();
    let (alice, bob, mut proxy, _alice_ident, bob_ident) = proxy_pair().await;
    let mut bob_events = Vec::new();

    proxy.drain();
    proxy.switched.store(true, Ordering::Relaxed);
    // Челлендж «теряется» на пути к Bob'у — `Path Response` не придёт.
    proxy.drop_new.store(true, Ordering::Relaxed);

    alice
        .pool
        .send_to(&bob_ident, message(0x2222_0001, b"via front"))
        .await
        .expect("send");
    assert_eq!(
        proxy.next_seen().await,
        Seen::Front,
        "пакет от Alice идёт на старый адрес"
    );
    let _ = wait_event(&bob.pool, &mut bob_events, "bob message", |e| {
        matches!(e, Ssu2Event::Message { .. })
    })
    .await;
    assert_eq!(
        proxy.next_seen().await,
        Seen::New,
        "на пакет с нового адреса Alice отвечает `Path Challenge`"
    );

    // Челлендж не подтверждён — путь не меняется, и второго челленджа нет.
    for probe in 0..5u32 {
        alice
            .pool
            .send_to(&bob_ident, message(0x2222_0100 + probe, b"probe"))
            .await
            .expect("send probe");
        assert_eq!(
            proxy.next_seen().await,
            Seen::Front,
            "без `Path Response` трафик идёт на старый адрес (проба {probe})"
        );
    }
}
