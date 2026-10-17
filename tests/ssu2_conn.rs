//! Тесты драйвера рукопожатия SSU2 ([`uu_i2p::ssu2_conn`]).
//!
//! Инициатор и ответчик — два [`Ssu2Connection`] в одном процессе: байты
//! пакетов передаются напрямую, как это делал бы UDP-транспорт. Проверяются
//! состояния, содержимое пакетов, обмен токеном и переход в data phase.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use uu_i2p::{
    crypto::I2PX25519Keys,
    i2np::I2npMessageType,
    i2np_message::I2npMessage,
    ssu2_block::{RouterInfoBlock, Ssu2Block, Ssu2TerminationReason},
    ssu2_conn::{
        ConnContext, ConnParams, ConnReport, HandshakeRole, ResponderEnv, Ssu2Connection,
        peek_dest_conn_id, peek_long_header_ids,
    },
    ssu2_engine::SendContext,
    ssu2_handshake::{
        HandshakeConfig, InitiatorHandshake, ResponderHandshake, RetryParams, build_retry,
    },
    ssu2_header::ConnectionId,
    ssu2_lifecycle::Ssu2SessionState,
    ssu2_policy::{I2pdCongestionPolicy, I2pdPolicy, Ssu2Policy},
    ssu2_send::RandomSource,
};

const NOW_SECS: u32 = 1_700_000_000;
const ALICE_ID: ConnectionId = ConnectionId::from_u64(0x1122_3344_5566_7788);
const BOB_ID: ConnectionId = ConnectionId::from_u64(0x8877_6655_4433_2211);
/// Intro-ключ Alice (её публикует `RouterInfo`).
const ALICE_INTRO: [u8; 32] = [0x22; 32];
/// Intro-ключ Bob (его публикует `RouterInfo`).
const BOB_INTRO: [u8; 32] = [0x11; 32];
const TOKEN: u64 = 0x0123_4567_89AB_CDEF;
const OTHER_TOKEN: u64 = 0x0FED_CBA9_8765_4321;
const MAX_PAYLOAD: usize = 1200;
const RI_LEN: usize = 400;
const NO_EXTRA: &[u8] = &[];

/// Детерминированный генератор (xorshift32) — вместо `m_Server.GetRng()`.
struct Rng {
    state: u32,
}

impl Rng {
    const fn new(seed: u32) -> Self {
        Self { state: seed | 1 }
    }
}

impl RandomSource for Rng {
    fn roll(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }
}

/// База времени — миллисекунды эпохи: тогда `expiration` I2NP-сообщений
/// (`I2npMessage::new`) согласован с `now` движка.
fn base_time() -> Duration {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX))
}

fn now_ms_of(now: Duration) -> u64 {
    u64::try_from(now.as_millis()).unwrap_or(u64::MAX)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn env(token: u64) -> ResponderEnv<'static> {
    ResponderEnv {
        expected_token: token,
        address: None,
        extra_blocks: NO_EXTRA,
    }
}

fn alice_params(local_router_info: Vec<u8>) -> ConnParams {
    ConnParams {
        config: HandshakeConfig::default(),
        local_intro_key: ALICE_INTRO,
        remote_intro_key: BOB_INTRO,
        max_payload: MAX_PAYLOAD,
        relay_tag_requested: false,
        local_router_info,
        testing: false,
        sync_clock_from_peers: false,
    }
}

fn bob_params() -> ConnParams {
    ConnParams {
        config: HandshakeConfig::default(),
        local_intro_key: BOB_INTRO,
        // Intro-ключ инициатора станет известен из RouterInfo в
        // SessionConfirmed — до этого его знать неоткуда.
        remote_intro_key: [0u8; 32],
        max_payload: MAX_PAYLOAD,
        relay_tag_requested: false,
        local_router_info: Vec::new(),
        testing: false,
        sync_clock_from_peers: false,
    }
}

/// Две стороны одного соединения плюс их генераторы.
struct World {
    alice: Ssu2Connection,
    bob: Ssu2Connection,
    rng_a: Rng,
    rng_b: Rng,
}

impl World {
    fn new(alice_ri: Vec<u8>) -> Self {
        let config = HandshakeConfig::default();
        let bob_static = I2PX25519Keys::generate();
        let alice_static = I2PX25519Keys::generate();
        let alice =
            InitiatorHandshake::new(alice_static, *bob_static.public_key(), BOB_INTRO, config);
        let bob = ResponderHandshake::new(bob_static, BOB_INTRO, config);
        Self {
            alice: Ssu2Connection::initiator(alice_params(alice_ri), alice, ALICE_ID, BOB_ID),
            bob: Ssu2Connection::responder(bob_params(), bob, BOB_ID, ALICE_ID),
            rng_a: Rng::new(0xA1),
            rng_b: Rng::new(0xB2),
        }
    }

    fn connect(&mut self, now: Duration, token: Option<u64>) -> Vec<Vec<u8>> {
        let mut ctx = ConnContext {
            now,
            now_ms: now_ms_of(now),
            now_secs: NOW_SECS,
            now_micros: 0,
            rng: &mut self.rng_a,
        };
        self.alice
            .connect(&I2pdPolicy, &mut ctx, token)
            .expect("connect")
    }

    fn alice_recv(&mut self, now: Duration, packet: &mut [u8], token: u64) -> ConnReport {
        recv(&mut self.alice, &mut self.rng_a, now, packet, &env(token))
    }

    fn bob_recv(&mut self, now: Duration, packet: &mut [u8], token: u64) -> ConnReport {
        recv(&mut self.bob, &mut self.rng_b, now, packet, &env(token))
    }

    // --- только шаги, общие для многих тестов ---------------------------

    /// Connect без токена и `TokenRequest` → `Retry`: возвращает `Retry`.
    fn through_retry(&mut self, now: Duration) -> Vec<u8> {
        let packets = self.connect(now, None);
        let mut request = packets[0].clone();
        let report = self.bob_recv(now + ms(10), &mut request, TOKEN);
        assert_eq!(self.bob.state(), Ssu2SessionState::TokenRequestReceived);
        report.packets[0].clone()
    }

    /// `Retry` → `SessionRequest`, возвращает `SessionRequest`.
    fn through_session_request(&mut self, now: Duration) -> Vec<u8> {
        let mut retry = self.through_retry(now);
        let report = self.alice_recv(now + ms(20), &mut retry, 0);
        assert_eq!(report.token, Some(TOKEN));
        assert_eq!(self.alice.state(), Ssu2SessionState::SessionRequestSent);
        report.packets[0].clone()
    }

    /// `SessionRequest` → `SessionCreated`, возвращает `SessionCreated`.
    fn through_session_created(&mut self, now: Duration) -> Vec<u8> {
        let mut request = self.through_session_request(now);
        let report = self.bob_recv(now + ms(30), &mut request, TOKEN);
        assert_eq!(self.bob.state(), Ssu2SessionState::SessionCreatedSent);
        report.packets[0].clone()
    }

    /// Полное рукопожатие до `Established` с обеих сторон.
    fn through_established(&mut self, now: Duration) -> ConnReport {
        let (report, _created) = self.through_established_full(now);
        report
    }

    /// Как [`Self::through_established`], но возвращает ещё и `SessionCreated`
    /// ответчика: тестам он нужен, чтобы повторить handshake-пакет, когда
    /// сессия уже в data-состоянии.
    fn through_established_full(&mut self, now: Duration) -> (ConnReport, Vec<u8>) {
        let created_original = self.through_session_created(now);
        let mut created = created_original.clone();
        let confirmed = self.alice_recv(now + ms(40), &mut created, 0);
        assert_eq!(
            self.alice.state(),
            Ssu2SessionState::SessionConfirmedSent,
            "инициатор ждёт Ack"
        );

        let mut first = confirmed.packets[0].clone();
        let report = if let Some(second) = confirmed.packets.get(1) {
            let mut second = second.clone();
            self.bob_recv(now + ms(51), &mut second, TOKEN)
        } else {
            self.bob_recv(now + ms(50), &mut first, TOKEN)
        };
        assert!(report.established, "ответчик установил сессию");
        assert!(report.quick_ack_pending);
        // Ответчик узнаёт intro-ключ инициатора из RouterInfo.
        self.bob.set_remote_intro_key(ALICE_INTRO);

        let quick_ack = {
            let mut ctx = ConnContext {
                now: now + ms(52),
                now_ms: now_ms_of(now + ms(52)),
                now_secs: NOW_SECS,
                now_micros: 0,
                rng: &mut self.rng_b,
            };
            self.bob
                .send_quick_ack(&I2pdPolicy, &mut ctx)
                .expect("quick ack")
        };
        let mut quick_ack = quick_ack;
        let report = self.alice_recv(now + ms(60), &mut quick_ack, 0);
        assert!(report.established, "инициатор установил сессию по Ack");
        assert_eq!(self.alice.state(), Ssu2SessionState::Established);
        assert_eq!(self.bob.state(), Ssu2SessionState::Established);
        (report, created_original)
    }
}

fn recv(
    conn: &mut Ssu2Connection,
    rng: &mut Rng,
    now: Duration,
    packet: &mut [u8],
    env: &ResponderEnv<'_>,
) -> ConnReport {
    let mut ctx = ConnContext {
        now,
        now_ms: now_ms_of(now),
        now_secs: NOW_SECS,
        now_micros: 0,
        rng,
    };
    conn.recv(&I2pdPolicy, &I2pdCongestionPolicy, packet, &mut ctx, env)
        .expect("recv")
}

// ---- вспомогательные peek'и ---------------------------------------------

#[test]
fn peek_helpers_read_ids_without_mutating() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let packets = w.connect(base_time(), None);
    let original = packets[0].clone();

    assert_eq!(
        peek_dest_conn_id(&packets[0], &BOB_INTRO),
        Some(BOB_ID),
        "destConnID замаскирован intro-ключом получателя"
    );
    let (source, token) = peek_long_header_ids(&packets[0], &BOB_INTRO).expect("ids");
    assert_eq!(source, ALICE_ID);
    assert_eq!(token, 0, "в TokenRequest токен нулевой");

    assert_eq!(packets[0], original, "peek не меняет пакет");
    assert_eq!(peek_dest_conn_id(&[0u8; 10], &BOB_INTRO), None);
    assert_eq!(peek_long_header_ids(&[0u8; 10], &BOB_INTRO), None);
}

#[test]
fn connect_without_token_sends_token_request() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let packets = w.connect(base_time(), None);
    assert_eq!(w.alice.role(), HandshakeRole::Initiator);
    assert_eq!(packets.len(), 1);
    assert_eq!(w.alice.state(), Ssu2SessionState::Unknown);
    assert_eq!(w.alice.token(), 0);
}

#[test]
fn connect_with_cached_token_sends_session_request() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let packets = w.connect(base_time(), Some(TOKEN));
    assert_eq!(w.alice.state(), Ssu2SessionState::SessionRequestSent);
    assert_eq!(w.alice.token(), TOKEN);
    let (_, token) = peek_long_header_ids(&packets[0], &BOB_INTRO).expect("ids");
    assert_eq!(token, TOKEN, "SessionRequest несёт предъявляемый токен");
}

// ---- полное рукопожатие -------------------------------------------------

#[test]
fn token_request_retry_and_full_handshake() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let report = w.through_established(base_time());

    // Инициатор получил RouterInfo ответчика? Нет — RouterInfo Bob'а в этом
    // рукопожатии не передаётся (Bob узнаёт RI Alice из SessionConfirmed, а
    // свой отдаёт уже в data phase).
    assert!(report.data.is_some());
    assert!(w.alice.data().is_some());
    assert!(w.alice.is_established());
    assert!(w.bob.is_established());
    assert!(w.alice.data().expect("data").is_established());

    // Номер первого data-пакета инициатора — 1 (i2pd делает `m_SendPacketNum++`
    // в `SendSessionConfirmed`), у ответчика — 0 (им ушёл QuickAck).
    assert_eq!(w.alice.data().expect("data").send_packet_num(), 1);
    assert_eq!(w.bob.data().expect("data").send_packet_num(), 1);
}

#[test]
fn responder_learns_initiator_router_info() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let mut created = w.through_session_created(base_time());
    let confirmed = w.alice_recv(base_time() + ms(40), &mut created, 0);

    let mut first = confirmed.packets[0].clone();
    let report = w.bob_recv(base_time() + ms(50), &mut first, TOKEN);
    let router_info = report.remote_router_info.expect("RouterInfo");
    assert_eq!(router_info.len(), RI_LEN);
    assert!(router_info.iter().all(|b| *b == 0xAB));
}

#[test]
fn fragmented_session_confirmed_establishes_on_second_fragment() {
    // RouterInfo в 2000 байт не влезает в один фрагмент.
    let mut w = World::new(vec![0x5A; 2000]);
    let mut created = w.through_session_created(base_time());
    let confirmed = w.alice_recv(base_time() + ms(40), &mut created, 0);
    assert_eq!(confirmed.packets.len(), 2, "два фрагмента");

    let mut first = confirmed.packets[0].clone();
    let report = w.bob_recv(base_time() + ms(50), &mut first, TOKEN);
    assert!(!report.established, "первый фрагмент — ещё не всё");
    assert_eq!(w.bob.state(), Ssu2SessionState::SessionCreatedSent);

    let mut second = confirmed.packets[1].clone();
    let report = w.bob_recv(base_time() + ms(51), &mut second, TOKEN);
    assert!(report.established);
    assert!(report.quick_ack_pending);
    assert_eq!(w.bob.state(), Ssu2SessionState::Established);
    assert_eq!(report.remote_router_info.expect("RouterInfo").len(), 2000);
}

// ---- токены -------------------------------------------------------------

#[test]
fn retry_from_session_request_sent_updates_token_and_resends() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    // Инициатор уверен в устаревшем токене.
    let packets = w.connect(base_time(), Some(OTHER_TOKEN));

    // Bob знает другой токен — отвечает Retry.
    let mut request = packets[0].clone();
    let report = w.bob_recv(base_time() + ms(10), &mut request, TOKEN);
    assert_eq!(report.packets.len(), 1, "Retry");
    assert_eq!(report.token, None);
    // Токен не совпал — Noise-состояние Bob'а не тронуто, сессия ждёт снова.
    assert_eq!(w.bob.state(), Ssu2SessionState::Unknown);

    // Alice различает Retry и SessionCreated и повторяет SessionRequest.
    let mut retry = report.packets[0].clone();
    let report = w.alice_recv(base_time() + ms(20), &mut retry, 0);
    assert_eq!(report.token, Some(TOKEN));
    assert_eq!(w.alice.token(), TOKEN);
    assert_eq!(w.alice.state(), Ssu2SessionState::SessionRequestSent);

    // Теперь токен верный — Bob продолжает с чистым Noise-состоянием.
    let mut request = report.packets[0].clone();
    let report = w.bob_recv(base_time() + ms(30), &mut request, TOKEN);
    assert_eq!(report.packets.len(), 1, "SessionCreated");
    assert_eq!(w.bob.state(), Ssu2SessionState::SessionCreatedSent);
}

#[test]
fn retry_with_zero_token_rejects_connection() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    // Отказ: `Retry` с нулевым токеном (i2pd `SendRetry` без токена).
    let params = RetryParams {
        dest_conn_id: ALICE_ID,
        source_conn_id: BOB_ID,
        packet_num: 5,
        token: 0,
        now_secs: NOW_SECS,
        valid_packets: 0,
        address: None,
        reason: Some(Ssu2TerminationReason::IncompatibleVersion),
        pad_roll: 0xFF,
    };
    let mut retry = build_retry(
        &I2pdPolicy,
        &HandshakeConfig::default(),
        &BOB_INTRO,
        &params,
    )
    .expect("retry");

    let report = w.alice_recv(base_time(), &mut retry, 0);
    assert!(report.rejected);
    assert_eq!(report.packets.len(), 0);
    assert_eq!(w.alice.state(), Ssu2SessionState::Failed);
}

// ---- таймеры ------------------------------------------------------------

#[test]
fn handshake_resend_repeats_last_packet() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let now = base_time();
    let packets = w.connect(now, None);

    // Сразу после отправки повтор не нужен.
    assert_eq!(
        w.alice.poll_resend(&I2pdPolicy, now, 0).len(),
        0,
        "сразу после отправки повтор не нужен"
    );

    let due = now + I2pdPolicy.handshake_resend_interval() + ms(1);
    let resent = w.alice.poll_resend(&I2pdPolicy, due, 0);
    assert_eq!(resent.len(), 1);
    assert_eq!(
        resent[0], packets[0],
        "шлём те же байты (i2pd держит пакет)"
    );
}

#[test]
fn connect_timer_expires() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let now = base_time();
    let _ = w.connect(now, None);

    let deadline = now + I2pdPolicy.connect_timeout();
    assert!(
        !w.alice
            .connect_expired(deadline.checked_sub(ms(1)).expect("внутри диапазона"))
    );
    assert!(w.alice.connect_expired(deadline));

    // После установления connect-таймер снят.
    let report = w.through_established(now);
    assert!(report.established);
    assert!(
        !w.alice
            .connect_expired(now + I2pdPolicy.connect_timeout() * 4)
    );
}

#[test]
fn repeated_session_created_resends_session_confirmed() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let now = base_time();
    let created = w.through_session_created(now);
    let mut first = created.clone();
    let confirmed = w.alice_recv(now + ms(40), &mut first, 0);
    assert_eq!(w.alice.state(), Ssu2SessionState::SessionConfirmedSent);

    // Наш `SessionConfirmed` потерялся, Bob повторяет `SessionCreated`
    // (i2pd `ProcessData`: тип не `Data` → `ResendHandshakePacket`).
    let mut repeat = created;
    let report = w.alice_recv(now + ms(50), &mut repeat, 0);
    assert_eq!(
        report.packets, confirmed.packets,
        "инициатор повторяет те же `SessionConfirmed`"
    );
    assert!(
        report.data.is_none(),
        "повтор не разбирается как data-пакет"
    );
    assert_eq!(w.alice.state(), Ssu2SessionState::SessionConfirmedSent);
}

#[test]
fn non_data_packet_after_established_requests_quick_ack() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let now = base_time();
    let (report, created) = w.through_established_full(now);
    assert!(report.established);

    // Не-data пакет в `Established`: i2pd шлёт `QuickAck`
    // («in case it was SessionConfirmed»).
    let mut repeat = created;
    let report = w.alice_recv(now + ms(70), &mut repeat, 0);
    assert!(report.quick_ack_pending);
    assert!(!report.established);
    assert_eq!(report.packets, Vec::<Vec<u8>>::new());
    assert_eq!(w.alice.state(), Ssu2SessionState::Established);
}

// ---- data phase ---------------------------------------------------------

#[test]
fn data_phase_transfers_i2np_and_acks() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let now = base_time();
    w.through_established(now);
    let t = now + ms(100);

    // Alice отправляет I2NP-сообщение.
    let message = I2npMessage::new(I2npMessageType::DatabaseStore, vec![0x42; 32]);
    let msg_id = message.msg_id();
    let data = w.alice.data_mut().expect("data");
    data.enqueue_i2np(message, 0);
    let sent = {
        let mut ctx = SendContext {
            now: t,
            now_ms: now_ms_of(t),
            now_micros: 0,
            rng: &mut w.rng_a,
        };
        data.flush(&I2pdPolicy, &mut ctx).expect("flush")
    };
    assert_eq!(sent.packets.len(), 1);
    assert_eq!(w.alice.data().expect("data").send().in_flight(), 1);

    // Bob принимает сообщение и подтверждает его.
    let mut packet = sent.packets[0].clone();
    let report = w.bob_recv(t, &mut packet, 0);
    let received = report.data.expect("data report");
    assert_eq!(received.i2np.len(), 1);
    assert_eq!(received.i2np[0].msg_id(), msg_id);
    assert_eq!(received.i2np[0].payload(), &[0x42; 32][..]);
    assert_eq!(
        w.bob.data().expect("data").receive().receive_packet_num(),
        1
    );

    let ack = {
        let data = w.bob.data_mut().expect("data");
        let mut ctx = SendContext {
            now: t + ms(5),
            now_ms: now_ms_of(t + ms(5)),
            now_micros: 0,
            rng: &mut w.rng_b,
        };
        data.send_quick_ack(&I2pdPolicy, &mut ctx).expect("ack")
    };
    let mut ack = ack;
    let report = w.alice_recv(t + ms(10), &mut ack, 0);
    let acked = report.data.expect("data report");
    assert!(acked.ack_received, "пришёл блок Ack");
    assert_eq!(
        w.alice.data().expect("data").send().in_flight(),
        0,
        "пакет снят с окна"
    );
}

#[test]
fn router_info_sent_as_data_packet() {
    let mut w = World::new(vec![0xAB; RI_LEN]);
    let now = base_time();
    w.through_established(now);
    let t = now + ms(100);

    // Ответчик сразу отдаёт свой RouterInfo отдельным пакетом
    // (i2pd `SendLocalRouterInfo`).
    let local_ri = vec![0x77u8; 300];
    let packet = {
        let data = w.bob.data_mut().expect("data");
        let mut ctx = SendContext {
            now: t,
            now_ms: now_ms_of(t),
            now_micros: 0,
            rng: &mut w.rng_b,
        };
        data.send_router_info(&I2pdPolicy, &mut ctx, &local_ri)
            .expect("router info")
    };

    let mut packet = packet;
    let report = w.alice_recv(t, &mut packet, 0);
    let received = report.data.expect("data report");
    // Вызывающему блок отдаётся телом (без `type`+`size`) — как в i2pd
    // `HandleRouterInfo`; разбор `RouterInfo` (флаги gzip, проверки) — его дело.
    let body = received
        .pending
        .iter()
        .find_map(|b| match b {
            uu_i2p::ssu2_engine::PendingBlock::RouterInfo(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("RouterInfo приходит вызывающему");
    let ri = RouterInfoBlock::parse(&body).expect("RouterInfo block");
    assert!(!ri.gzip_compressed());
    assert!(!ri.flood_requested());
    assert_eq!(ri.router_info, &local_ri[..]);
}
