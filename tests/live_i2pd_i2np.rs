//! Живой interop-тест I2NP: подключение к i2pd по NTCP2,
//! отправка `DatabaseStore` с `reply_token` и получение
//! `DeliveryStatus` в ответ.
//!
//! Требует запущенного i2pd (любая свежая версия) с включённым
//! NTCP2, слушающего на loopback / local-адресе, и пути к его
//! `RouterInfo` в переменной окружения `UU_I2P_LIVE_RI`.
//!
//! По умолчанию `#[ignore]` — обычный `cargo test` от него не
//! зависит.
//!
//! Запуск:
//!
//! ```text
//! UU_I2P_LIVE_RI=/tmp/i2pd-debug.ri \
//! RUST_LOG=trace \
//! cargo test --test live_i2pd_i2np -- --ignored --nocapture
//!
//!
//!
//! ```

use rand::Rng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{net::TcpStream, time::timeout};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};
use uu_i2p::{
    config::{ListenEndpoint, RouterConfig},
    crypto::I2PX25519Keys,
    database_store::{DatabaseStore, ReplyInstruction},
    delivery_status::{DELIVERY_STATUS_SIZE, DeliveryStatus},
    i2np::I2npMessageType,
    i2np_message::I2npMessage,
    ntcp2::{Ntcp2LocalConfig, Ntcp2Session},
    private_keys::I2PPrivateKeys,
    router_info::FullRouterInfo,
};

fn init_tracing() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .init();
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[tokio::test]
#[ignore = "requires a live i2pd instance; set UU_I2P_LIVE_RI to its routerInfo-*.dat"]
#[allow(clippy::too_many_lines)]
async fn send_database_store_and_receive_delivery_status() {
    init_tracing();

    // --- 1. Разбор чужого RI ---------------------------------------------

    let Ok(ri_path) = std::env::var("UU_I2P_LIVE_RI") else {
        warn!("skipping: UU_I2P_LIVE_RI not set");
        return;
    };
    let remote_ri_bytes = std::fs::read(&ri_path).expect("read remote RI");
    let remote_ri = FullRouterInfo::from_buffer(&remote_ri_bytes).expect("parse remote RI");
    let remote_addr = remote_ri
        .body()
        .addresses
        .iter()
        .find(|a| a.is_ntcp2() && a.published && !a.host.is_unspecified() && a.port != 0)
        .expect("remote RI has no published NTCP2 address")
        .clone();
    let socket_addr = std::net::SocketAddr::new(remote_addr.host, remote_addr.port);
    info!("will connect to {socket_addr}");

    // --- 2. Наши ключи и RI ----------------------------------------------

    let our_keys = I2PPrivateKeys::generate_default().expect("generate keys");
    let our_ntcp2_static = I2PX25519Keys::generate();
    let our_ntcp2_iv: [u8; 16] = {
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        iv
    };
    let cfg = RouterConfig::builder()
        .keys(our_keys)
        .ntcp2_keys(our_ntcp2_static, our_ntcp2_iv)
        .listen(ListenEndpoint::unpublished("127.0.0.1:0".parse().unwrap()))
        .build()
        .expect("build RouterConfig");
    let our_ri = cfg.build_router_info(now_ms()).expect("build own RI");
    let our_ri_bytes = our_ri.to_buffer().expect("serialize own RI");
    let our_ident_hash = *our_ri.ident_hash();
    info!("our ident: {}", our_ident_hash.to_base64());
    info!("our RI len: {}", our_ri_bytes.len());

    // --- 3. TCP + NTCP2 handshake ----------------------------------------

    let stream = TcpStream::connect(socket_addr).await.expect("TCP connect");
    let local_cfg = Ntcp2LocalConfig {
        static_keys: cfg.ntcp2_static(),
        ident_hash: *cfg.keys().public().ident_hash().as_bytes(),
        iv: *cfg.ntcp2_iv(),
        ri_bytes: &our_ri_bytes,
        net_id: cfg.net_id(),
    };
    let mut session = timeout(
        Duration::from_secs(15),
        Ntcp2Session::connect(stream, &local_cfg, &remote_ri_bytes),
    )
    .await
    .expect("NTCP2 handshake timeout")
    .expect("NTCP2 handshake failed");
    info!("handshake OK");

    // --- 4. i2pd как responder шлёт свой RI первым data-фреймом -----
    //
    // Явно читать его не надо: `recv_i2np` в цикле пропускает
    // не-I2NP блоки (`RouterInfo`, `DateTime`, `Padding`) и вернёт
    // только когда дойдёт до `I2npMessage`. Он же сохранит RI
    // в `session.remote_router_info()` на будущее.

    // --- 5. Собираем DatabaseStore с reply_token и reply_instruction ----

    // ReplyInstruction: tunnel_id = 0 (значит «слать напрямую»),
    // gateway = наш ident_hash. i2pd положит это в
    // `handle_database_store` и через `CreateDeliveryStatusMsg(replyToken)`
    // отправит DeliveryStatus нам.
    let reply_token: u32 = 0xDEAD_BEEF;
    let reply_instruction = ReplyInstruction {
        tunnel_id: 0,
        gateway: our_ident_hash,
    };
    let ds = DatabaseStore::new_router_info(
        our_ident_hash,
        &our_ri_bytes,
        reply_token,
        Some(reply_instruction),
    )
    .expect("build DatabaseStore");
    let ds_payload = ds.to_buffer().expect("serialize DatabaseStore");
    let ds_msg = I2npMessage::new(I2npMessageType::DatabaseStore, ds_payload);
    info!(
        "sending DatabaseStore, size={}, msg_id={}",
        ds_msg.payload().len(),
        ds_msg.msg_id()
    );

    // --- 6. Отправляем и ждём DeliveryStatus ----------------------------

    session
        .send_i2np(&ds_msg)
        .await
        .expect("send DatabaseStore");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut attempts = 0;
    loop {
        attempts += 1;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timeout waiting for DeliveryStatus (attempts={attempts})"
        );
        let reply = match timeout(remaining, session.recv_i2np()).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => panic!("recv_i2np failed: {e}"),
            Err(e) => panic!("timeout waiting for DeliveryStatus: {e}"),
        };
        info!(
            "received I2NP: type={}, msg_id=0x{:08X}, payload_len={}",
            reply.message_type(),
            reply.msg_id(),
            reply.payload().len(),
        );
        if reply.message_type() != I2npMessageType::DeliveryStatus {
            // i2pd мог прислать что-то ещё (например, DeliveryStatus
            // для другого сообщения или иное). Читаем дальше.
            continue;
        }
        assert!(
            reply.payload().len() >= DELIVERY_STATUS_SIZE,
            "DeliveryStatus payload too short: {} < {}",
            reply.payload().len(),
            DELIVERY_STATUS_SIZE,
        );
        let ds = DeliveryStatus::from_buffer(reply.payload()).expect("parse DeliveryStatus");
        info!(
            "DeliveryStatus: confirmed_msg_id=0x{:08X}, timestamp_ms={}",
            ds.msg_id, ds.timestamp_ms,
        );
        assert_eq!(
            ds.msg_id, reply_token,
            "DeliveryStatus пришёл для другого msg_id: \
             ожидали 0x{:08X}, получили 0x{:08X}",
            reply_token, ds.msg_id,
        );
        assert_ne!(ds.timestamp_ms, 0, "у DeliveryStatus timestamp_ms = 0");
        info!("OK: i2pd подтвердил наш DatabaseStore через DeliveryStatus");
        return;
    }
}
