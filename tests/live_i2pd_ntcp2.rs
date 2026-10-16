//! Live interop test: connect to a running i2pd instance over NTCP2 and
//! verify the handshake + `RouterInfo` exchange against a real peer.
//!
//! Requires a running i2pd (any recent version) with NTCP2 enabled,
//! listening on a loopback / local address, and the path to its
//! `RouterInfo` file exported as `UU_I2P_LIVE_RI`.
//!
//! The test is `#[ignore]` by default so a normal `cargo test` doesn't
//! depend on external state.
//!
//! Run:
//!
//!     UU_I2P_LIVE_RI=/tmp/i2pd-debug.ri \
//!         cargo test --test live_i2pd_ntcp2 -- --ignored --nocapture

use rand::Rng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{net::TcpStream, time::timeout};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};
use uu_i2p::{
    config::{ListenEndpoint, RouterConfig},
    crypto::I2PX25519Keys,
    ntcp2::{Ntcp2Block, Ntcp2LocalConfig, Ntcp2Session},
    private_keys::I2PPrivateKeys,
    router_info::FullRouterInfo,
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
#[ignore = "requires a live i2pd instance; set UU_I2P_LIVE_RI to its routerInfo-*.dat"]
#[allow(clippy::too_many_lines)]
async fn connect_to_live_i2pd_and_receive_router_info() {
    init_tracing();
    let Ok(ri_path) = std::env::var("UU_I2P_LIVE_RI") else {
        warn!("skipping: UU_I2P_LIVE_RI not set");
        return;
    };

    // --- 1. Parse the remote RouterInfo ----------------------------------

    let remote_ri_bytes = std::fs::read(&ri_path).expect("read remote RI");
    let remote_ri = FullRouterInfo::from_buffer(&remote_ri_bytes).expect("parse remote RouterInfo");

    info!("remote ident:   {}", remote_ri.ident_hash().to_base64());
    info!(
        "remote signing: {:?}",
        remote_ri.identity().signing_key_type()
    );
    info!(
        "remote crypto:  {:?}",
        remote_ri.identity().crypto_key_type()
    );
    info!("remote addr count: {}", remote_ri.body().addresses.len());
    for a in &remote_ri.body().addresses {
        info!(
            "  {} host={} port={} published={} v={}",
            a.transport_style, a.host, a.port, a.published, a.v,
        );
    }

    let remote_addr = remote_ri
        .body()
        .addresses
        .iter()
        .find(|a| a.is_ntcp2() && a.published && !a.host.is_unspecified() && a.port != 0)
        .expect("remote RI has no published NTCP2 address")
        .clone();
    let socket_addr = std::net::SocketAddr::new(remote_addr.host, remote_addr.port);
    info!("will connect to {socket_addr}");

    // --- 2. Generate our own keys and RouterInfo -------------------------

    let our_keys = I2PPrivateKeys::generate_default().expect("generate keys");
    let our_ntcp2_static = I2PX25519Keys::generate();
    let our_ntcp2_iv: [u8; 16] = {
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        iv
    };

    // IMPORTANT: unpublished endpoint.  A published NTCP2 address with a
    // host that does not match the observed TCP source address is rejected
    // by i2pd (`NTCP2Session::EstablishSessionAfterSessionConfirmed`).
    // Loopback cannot satisfy that check.
    let cfg = RouterConfig::builder()
        .keys(our_keys)
        .ntcp2_keys(our_ntcp2_static, our_ntcp2_iv)
        .listen(ListenEndpoint::unpublished("127.0.0.1:0".parse().unwrap()))
        .build()
        .expect("build RouterConfig");

    let our_ri = cfg.build_router_info(now_ms()).expect("build own RI");
    let our_ri_bytes = our_ri.to_buffer().expect("serialize own RI");
    info!("our ident:      {}", our_ri.ident_hash().to_base64());
    info!("our RI len:     {}", our_ri_bytes.len());

    // --- 3. TCP + NTCP2 handshake ---------------------------------------

    let stream = TcpStream::connect(socket_addr).await.expect("TCP connect");

    let local_cfg = Ntcp2LocalConfig {
        static_keys: cfg.ntcp2_static(),
        ident_hash: *cfg.keys().public().ident_hash().as_bytes(),
        iv: *cfg.ntcp2_iv(),
        ri_bytes: &our_ri_bytes,
        net_id: cfg.net_id(),
    };

    let session = timeout(
        Duration::from_secs(15),
        Ntcp2Session::connect(stream, &local_cfg, &remote_ri_bytes),
    )
    .await
    .expect("NTCP2 handshake timeout")
    .expect("NTCP2 handshake failed");

    info!("handshake OK, is_alice={}", session.is_alice());
    assert!(session.is_alice(), "we are the initiator");

    // --- 4. Wait for i2pd's RouterInfo frame -----------------------------
    //
    // As responder i2pd sends its RI in the very first post-handshake frame.
    // That frame is only sent after `EstablishSessionAfterSessionConfirmed`,
    // i.e. after i2pd has accepted and stored *our* RI.  Receiving it
    // therefore proves bidirectional interop:
    //
    //   * our crypto (Noise XK, obfuscation, AEAD framing) is correct
    //     -> i2pd decrypted SessionRequest / SessionConfirmed;
    //   * our RouterInfo is well-formed and signed correctly
    //     -> i2pd accepted it in its netdb;
    //   * our AEAD receive path works
    //     -> we correctly decrypt i2pd's data-phase frame.

    let (mut read, _write) = session.split();

    let blocks = timeout(Duration::from_secs(10), read.read_frame())
        .await
        .expect("timeout waiting for i2pd's first post-handshake frame")
        .expect("read_frame failed");

    let mut got_ri = false;
    let mut got_datetime = false;
    for block in &blocks {
        match block {
            Ntcp2Block::RouterInfo { ri_bytes, flag } => {
                info!(
                    "received RouterInfo block: {} bytes, flag={}",
                    ri_bytes.len(),
                    flag
                );
                let ri = FullRouterInfo::from_buffer(ri_bytes).expect("i2pd's RI did not parse");
                info!("  their ident: {}", ri.ident_hash().to_base64());
                assert_eq!(
                    ri.ident_hash(),
                    remote_ri.ident_hash(),
                    "i2pd sent a RI for a different router than we connected to",
                );
                // Their signature must verify against their own bytes.
                ri.verify(ri_bytes)
                    .expect("i2pd's RI signature did not verify");
                got_ri = true;
            }
            Ntcp2Block::DateTime { ts } => {
                info!("received DateTime block: ts={ts}");
                got_datetime = true;
            }
            other => warn!("received block: {other:?}"),
        }
    }

    assert!(
        got_ri,
        "i2pd's first post-handshake frame did not contain a RouterInfo block"
    );
    info!("all checks passed (got_datetime={got_datetime})");
}
