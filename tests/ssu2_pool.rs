//! Пул SSU2: interop двух пулов в одном процессе (реальный UDP на 127.0.0.1).
//!
//! Проверяем весь путь транспорта: рукопожатие (Alice → Bob), обмен
//! `RouterInfo`, I2NP в обе стороны, очередь до установления и закрытие.
//! Внешний i2pd не нужен — оба конца наши.

use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use uu_i2p::{
    I2PTag,
    config::{DEFAULT_NET_ID, DEFAULT_VERSION},
    crypto::I2PX25519Keys,
    i2np::{I2npHeader, I2npMessageType},
    i2np_message::I2npMessage,
    private_keys::I2PPrivateKeys,
    router_info::{FullRouterInfo, RouterInfo, RouterInfoCaps},
    router_info_address::I2PAddress,
    ssu2_pool::{Ssu2Event, Ssu2Local, Ssu2Pool},
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
