//! Live interop: соединение с запущенным i2pd по SSU2 и проверка обмена
//! `RouterInfo`.
//!
//! Нужен запущенный i2pd (любая свежая версия) с включённым SSU2 и путь к его
//! `RouterInfo` в переменной `UU_I2P_LIVE_RI` (файл `router.info` или
//! `routerInfo-*.dat` из netDb).
//!
//! Если опубликованный SSU2-адрес i2pd недостижим с этой машины (например,
//! публикуется внешний адрес, а i2pd слушает только localhost), адрес можно
//! переопределить переменной `UU_I2P_LIVE_SSU2=host:port`: ключи (`s=`/`i=`)
//! всё равно берутся из `RouterInfo`.
//!
//! Тест `#[ignore]` по умолчанию, чтобы обычный `cargo test` не зависел от
//! внешнего состояния.
//!
//! Запуск:
//!
//!     UU_I2P_LIVE_RI=~/.i2pd/router.info \
//!         cargo test --test live_i2pd_ssu2 -- --ignored --nocapture

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use uu_i2p::{
    config::RouterConfig,
    crypto::I2PX25519Keys,
    private_keys::I2PPrivateKeys,
    router_info::FullRouterInfo,
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

#[tokio::test]
#[ignore = "requires a live i2pd instance; set UU_I2P_LIVE_RI to its router.info"]
#[allow(clippy::too_many_lines)]
async fn connect_to_live_i2pd_ssu2_and_receive_router_info() {
    init_tracing();
    let Ok(ri_path) = std::env::var("UU_I2P_LIVE_RI") else {
        warn!("skipping: UU_I2P_LIVE_RI not set");
        return;
    };

    // --- 1. Разбираем `RouterInfo` собеседника --------------------------

    let remote_ri_bytes = std::fs::read(&ri_path).expect("read remote RI");
    let remote_ri = FullRouterInfo::from_buffer(&remote_ri_bytes).expect("parse remote RouterInfo");
    info!("remote ident: {}", remote_ri.ident_hash().to_base64());
    for a in &remote_ri.body().addresses {
        info!(
            "  {} host={} port={} published={} v={}",
            a.transport_style, a.host, a.port, a.published, a.v,
        );
    }
    let remote_ident = *remote_ri.ident_hash();

    // --- 2. Свои ключи, адрес сокета и `RouterInfo` ----------------------

    // Сокет нужен до сборки своего RI: SSU2-адрес публикуем с реальным портом
    // (i2pd требует SSU2-адрес в `SessionConfirmed`, `SSU2Session.cpp:1394`).
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let local_addr = socket.local_addr().expect("local_addr");
    let our_static = I2PX25519Keys::generate();
    let our_intro: [u8; 32] = {
        let mut intro = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut intro);
        intro
    };
    let our_iv: [u8; 16] = {
        let mut iv = [0u8; 16];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut iv);
        iv
    };
    let cfg = RouterConfig::builder()
        .keys(I2PPrivateKeys::generate_default().expect("generate keys"))
        .ntcp2_keys(our_static, our_iv)
        .ssu2_intro_key(our_intro)
        .listen_ssu2_unpublished(local_addr)
        .build()
        .expect("build RouterConfig");
    let local = Ssu2Local::from_router_config(&cfg, now_ms()).expect("Ssu2Local");
    info!(
        "our ident:  {} (socket {local_addr})",
        local.ident().to_base64()
    );
    let pool = Ssu2Pool::with_socket(socket, local).expect("Ssu2Pool");

    // --- 3. Соединение --------------------------------------------------

    let override_addr = std::env::var("UU_I2P_LIVE_SSU2")
        .ok()
        .map(|s| s.parse::<SocketAddr>().expect("UU_I2P_LIVE_SSU2 host:port"));
    let ident = timeout(Duration::from_secs(20), async {
        match override_addr {
            Some(addr) => {
                info!("connecting (address override) to {addr}");
                pool.connect_to(&remote_ri_bytes, addr).await
            }
            None => pool.connect(&remote_ri_bytes).await,
        }
    })
    .await
    .expect("connect timeout")
    .expect("connect failed");
    assert_eq!(
        ident, remote_ident,
        "connect must resolve the remote router"
    );

    // --- 4. Ждём Established и `RouterInfo` от i2pd ---------------------
    //
    // Ответчик i2pd шлёт свой `RouterInfo` сразу после установления
    // (`Transports::PeerConnected`). Он отправляется только когда i2pd уже
    // принял и сохранил наш `RouterInfo` в netdb, поэтому получение его
    // доказывает двусторонний interop: наш Noise/обфускация/AEAD корректны,
    // наш RI подписан и разобран i2pd, а наш приём data-фазы работает.

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut established = false;
    let mut got_ri = false;
    while !got_ri {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = timeout(remaining, pool.next_event())
            .await
            .expect("timeout waiting for i2pd's RouterInfo")
            .expect("pool event");
        match event {
            Ssu2Event::Established { ident } => {
                info!("SSU2 established with {}", ident.to_base64());
                assert_eq!(ident, remote_ident);
                established = true;
            }
            Ssu2Event::RouterInfo { from, ri_bytes } => {
                info!("received RouterInfo: {} bytes", ri_bytes.len());
                assert_eq!(from, remote_ident, "RI for a different router");
                let ri = FullRouterInfo::from_buffer(&ri_bytes).expect("i2pd's RI did not parse");
                assert_eq!(ri.ident_hash(), &remote_ident);
                ri.verify(&ri_bytes)
                    .expect("i2pd's RI signature did not verify");
                got_ri = true;
            }
            Ssu2Event::Message { from, message } => {
                info!(
                    "I2NP from {}: msg_id={:#x}",
                    from.to_base64(),
                    message.msg_id()
                );
            }
            Ssu2Event::Disconnected { ident } => {
                warn!("disconnected from {}", ident.to_base64());
                break;
            }
            Ssu2Event::ExternalAddress { addr, .. } => {
                info!("i2pd sees us as {addr}");
            }
            Ssu2Event::PeerTestResult { addr, .. } => {
                info!("PeerTest result: {addr:?}");
            }
        }
    }
    assert!(established, "session never reached Established");
    assert!(
        got_ri,
        "i2pd did not send its RouterInfo after establishment"
    );

    // --- 5. Закрываем соединение ----------------------------------------

    let closed = pool.close(&remote_ident).await.expect("close");
    info!("session closed: {closed}");
}
