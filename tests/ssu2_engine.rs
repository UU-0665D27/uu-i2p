//! Тесты приёмного движка SSU2 ([`uu_i2p::ssu2_engine`]).
//!
//! Пакеты собираются вручную (`encode_data_packet`) с ключом приёма сессии:
//! сессия играет роль Alice (инициатора), поэтому «от собеседника» ключ —
//! `ba`, а intro-ключ — локальный intro-ключ сессии (i2pd `m_Address->i`).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use uu_i2p::{
    ssu2_ack::Ssu2AckBlock,
    ssu2_block::{
        AddressBlock, NewTokenBlock, PathChallengeBlock, PathResponseBlock, RelayTagBlock,
        Ssu2Block, Ssu2BlockType, Ssu2TerminationReason, TerminationBlock, follow_on_frag_byte,
        write_block,
    },
    ssu2_crypto::DataPhaseKeys,
    ssu2_data::{SSU2_DATA_OVERHEAD, encode_data_packet},
    ssu2_engine::{
        DataSessionParams, DataSessionRole, PendingBlock, SendContext, Ssu2DataSession,
        TerminationAction,
    },
    ssu2_header::{ConnectionId, ShortHeader, Ssu2MessageType},
    ssu2_lifecycle::Ssu2SessionState,
    ssu2_policy::{DateTimeAction, I2pdCongestionPolicy, I2pdPolicy},
};

const INTRO: [u8; 32] = [0x11; 32];
const DEST: ConnectionId = ConnectionId([1, 2, 3, 4, 5, 6, 7, 8]);
const NOW_SECS: u64 = 1_700_000_000;
const MAX_PAYLOAD: usize = 1200;
const MSG_ID: u32 = 0xdead_beef;
const TYPE_DATABASE_STORE: u8 = 1;

fn keys() -> DataPhaseKeys {
    DataPhaseKeys {
        ab: uu_i2p::ssu2_crypto::DataPhaseKey {
            k_data: [0xAA; 32],
            k_header_2: [0xAB; 32],
        },
        ba: uu_i2p::ssu2_crypto::DataPhaseKey {
            k_data: [0xBA; 32],
            k_header_2: [0xBB; 32],
        },
    }
}

fn params() -> DataSessionParams {
    DataSessionParams {
        role: DataSessionRole::Initiator,
        source_conn_id: DEST,
        dest_conn_id: ConnectionId([8, 7, 6, 5, 4, 3, 2, 1]),
        data_keys: keys(),
        local_intro_key: INTRO,
        remote_intro_key: [0x22; 32],
        max_payload: MAX_PAYLOAD,
        testing: false,
        sync_clock_from_peers: false,
    }
}

fn session() -> Ssu2DataSession {
    Ssu2DataSession::new(params(), &I2pdCongestionPolicy)
}

/// Кодирует data-пакет «от собеседника» ключом приёма сессии (`ba`).
///
/// Payload дополняется `Padding`-блоком до минимального размера пакета
/// (`decode_data_packet` требует не короче `SSU2_MIN_PACKET_SIZE`; i2pd тоже
/// шлёт только паддированные пакеты).
fn packet(packet_num: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let header = ShortHeader {
        dest_conn_id: DEST,
        packet_num,
        msg_type: Ssu2MessageType::Data,
        flags: [flags, 0, 0],
    };
    let mut payload = payload.to_vec();
    while payload.len() < 8 {
        write_block(&mut payload, Ssu2BlockType::Padding, &[0u8; 1]).expect("padding");
    }
    let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
    let n = encode_data_packet(&header, &INTRO, &keys().ba, &payload, &mut out).expect("encode");
    out.truncate(n);
    out
}

fn recv(
    session: &mut Ssu2DataSession,
    packet_num: u32,
    payload: &[u8],
    now: Duration,
) -> uu_i2p::ssu2_engine::RecvReport {
    let mut wire = packet(packet_num, 0, payload);
    session
        .recv(&mut wire, &I2pdPolicy, &I2pdCongestionPolicy, now, NOW_SECS)
        .expect("recv")
}

/// NTCP2-поток I2NP-сообщения: тип(1) + `msg_id`(4) + expiration(4, сек) + payload.
fn ntcp2(type_id: u8, msg_id: u32, expiration_secs: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(type_id);
    out.extend_from_slice(&msg_id.to_be_bytes());
    out.extend_from_slice(&expiration_secs.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn i2np_payload(msg_id: u32, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    write_block(
        &mut payload,
        Ssu2BlockType::I2npMessage,
        &ntcp2(TYPE_DATABASE_STORE, msg_id, 0, body),
    )
    .expect("write i2np block");
    payload
}

fn body(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from(i % 256).expect("fits"))
        .collect()
}

// ---- I2NP ---------------------------------------------------------------

#[test]
fn recv_delivers_i2np_once_and_dedups() {
    let mut session = session();
    let report = recv(
        &mut session,
        1,
        &i2np_payload(MSG_ID, &body(4)),
        Duration::ZERO,
    );
    assert!(report.data_received);
    assert!(!report.invalid_message);
    assert_eq!(report.i2np.len(), 1);
    assert_eq!(report.i2np[0].msg_id(), MSG_ID);
    assert_eq!(report.i2np[0].payload(), body(4).as_slice());

    // Повтор того же msgID — дубликат, не отдаётся.
    let report = recv(
        &mut session,
        2,
        &i2np_payload(MSG_ID, &body(4)),
        Duration::ZERO,
    );
    assert!(report.i2np.is_empty(), "дубликат не должен отдаваться");
}

#[test]
fn recv_drops_expired_i2np() {
    let mut session = session();
    let payload = {
        let mut payload = Vec::new();
        write_block(
            &mut payload,
            Ssu2BlockType::I2npMessage,
            &ntcp2(TYPE_DATABASE_STORE, MSG_ID, 5, &body(4)),
        )
        .expect("write");
        payload
    };
    // Время последней активности (10_000 с) заведомо позже expiration (5 мс).
    let report = recv(&mut session, 1, &payload, Duration::from_secs(10_000));
    assert!(report.data_received);
    assert!(report.i2np.is_empty(), "истёкшее сообщение не отдаётся");
}

#[test]
fn recv_reassembles_fragmented_i2np() {
    let mut session = session();
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, 0, &body(60));

    let mut first = Vec::new();
    write_block(&mut first, Ssu2BlockType::FirstFragment, &data[..20]).expect("first");
    let report = recv(&mut session, 1, &first, Duration::ZERO);
    assert!(report.i2np.is_empty(), "первый фрагмент ещё не сообщение");

    let mut rest = Vec::new();
    let mut rest_body = vec![follow_on_frag_byte(1, true)];
    rest_body.extend_from_slice(&MSG_ID.to_be_bytes());
    rest_body.extend_from_slice(&data[20..]);
    write_block(&mut rest, Ssu2BlockType::FollowOnFragment, &rest_body).expect("follow-on");
    let report = recv(&mut session, 2, &rest, Duration::ZERO);
    assert_eq!(report.i2np.len(), 1);
    assert_eq!(report.i2np[0].msg_id(), MSG_ID);
    assert_eq!(report.i2np[0].payload(), body(60).as_slice());
}

// ---- ACK ----------------------------------------------------------------

#[test]
fn recv_applies_ack_and_clears_in_flight() {
    let mut session = session();
    let t0 = Duration::from_secs(1000);
    session.register_sent(1, t0);
    assert_eq!(session.send().in_flight(), 1);

    let ack = Ssu2AckBlock {
        ack_through: 1,
        acnt: 0,
        ranges: Vec::new(),
    };
    let mut payload = Vec::new();
    ack.write(&mut payload).expect("ack block");

    let report = recv(&mut session, 10, &payload, t0 + Duration::from_secs(1));
    assert_eq!(report.i2np.len(), 0);
    assert_eq!(session.send().in_flight(), 0);
    // RTT измерен по acnt-диапазону.
    assert_eq!(session.send().rtt(), Some(Duration::from_secs(1)));
}

#[test]
fn recv_ack_with_empty_window_is_ignored() {
    let mut session = session();
    let ack = Ssu2AckBlock {
        ack_through: 1,
        acnt: 0,
        ranges: Vec::new(),
    };
    let mut payload = Vec::new();
    ack.write(&mut payload).expect("ack block");
    // Ничего не отправляли (m_SentPackets.empty).
    let report = recv(&mut session, 1, &payload, Duration::ZERO);
    assert_eq!(session.send().in_flight(), 0);
    assert_eq!(report.i2np.len(), 0);
}

// ---- Termination --------------------------------------------------------

fn termination(reason: Ssu2TerminationReason) -> Vec<u8> {
    let mut payload = Vec::new();
    TerminationBlock {
        valid_packets: 0,
        reason: reason.as_u8(),
        additional: &[],
    }
    .write(&mut payload)
    .expect("termination block");
    payload
}

#[test]
fn recv_termination_while_established_requests_reply() {
    let mut session = session();
    session.establish();
    let report = recv(
        &mut session,
        1,
        &termination(Ssu2TerminationReason::NormalClose),
        Duration::ZERO,
    );
    assert_eq!(report.termination, Some(TerminationAction::ReplyAndClose));
    assert_eq!(session.state(), Ssu2SessionState::Closing);
}

#[test]
fn recv_termination_reply_while_closing_confirms() {
    let mut session = session();
    session.establish();
    // Локальное завершение: сессия в Closing, ждём ответного Termination.
    let plan = session.request_termination(Ssu2TerminationReason::NormalClose);
    assert!(plan.send_termination);
    assert_eq!(session.state(), Ssu2SessionState::Closing);
    let report = recv(
        &mut session,
        1,
        &termination(Ssu2TerminationReason::TerminationReceived),
        Duration::ZERO,
    );
    assert_eq!(report.termination, Some(TerminationAction::CloseNow));
    assert_eq!(session.state(), Ssu2SessionState::ClosingConfirmed);
}

#[test]
fn recv_termination_after_terminated_records_reason() {
    let mut session = session();
    session.establish();
    assert!(session.terminate());
    assert_eq!(session.state(), Ssu2SessionState::Terminated);
    let report = recv(
        &mut session,
        1,
        &termination(Ssu2TerminationReason::Timeout),
        Duration::ZERO,
    );
    assert_eq!(
        report.termination,
        Some(TerminationAction::RecordReason(
            Ssu2TerminationReason::Timeout
        ))
    );
    assert_eq!(
        session.remote_termination(),
        Some(Ssu2TerminationReason::Timeout)
    );
}

// ---- DateTime -----------------------------------------------------------

#[test]
fn recv_datetime_clock_skew_terminates() {
    let mut session = session();
    session.establish();
    let remote = u32::try_from(NOW_SECS - 3600).expect("fits");
    let mut payload = Vec::new();
    write_block(&mut payload, Ssu2BlockType::DateTime, &remote.to_be_bytes()).expect("datetime");
    let report = recv(&mut session, 1, &payload, Duration::ZERO);
    assert_eq!(report.datetime, Some(DateTimeAction::Terminate));
}

// ---- Path challenge / response ------------------------------------------

#[test]
fn recv_path_challenge_is_reported() {
    let mut session = session();
    let challenge = [0x42u8; 8];
    let mut payload = Vec::new();
    PathChallengeBlock { data: &challenge }
        .write(&mut payload)
        .expect("challenge");
    let report = recv(&mut session, 1, &payload, Duration::ZERO);
    assert_eq!(report.path_challenge.as_deref(), Some(challenge.as_slice()));
}

#[test]
fn recv_path_response_validates_sent_challenge() {
    let mut session = session();
    let sent = 0x0102_0304_0506_0708u64;
    session.set_path_challenge_sent(sent);
    let mut payload = Vec::new();
    PathResponseBlock {
        data: &sent.to_be_bytes(),
    }
    .write(&mut payload)
    .expect("response");
    let report = recv(&mut session, 1, &payload, Duration::ZERO);
    assert!(report.path_response_accepted);
    assert!(session.path_validated());
}

// ---- Прочие блоки -------------------------------------------------------

#[test]
fn recv_relay_tag_and_request_are_recorded() {
    let mut session = session();
    let mut payload = Vec::new();
    RelayTagBlock {
        relay_tag: 0x1234_5678,
    }
    .write(&mut payload)
    .expect("relay tag");
    write_block(&mut payload, Ssu2BlockType::RelayTagRequest, &[]).expect("request");
    let _ = recv(&mut session, 1, &payload, Duration::ZERO);
    assert_eq!(session.relay_tag(), Some(0x1234_5678));
    assert!(session.relay_tag_requested());
}

#[test]
fn recv_address_and_new_token_are_reported() {
    let mut session = session();
    let mut body = Vec::new();
    body.extend_from_slice(&12345u16.to_be_bytes());
    body.extend_from_slice(&[10, 0, 0, 1]);
    let mut payload = Vec::new();
    write_block(&mut payload, Ssu2BlockType::Address, &body).expect("address");
    NewTokenBlock {
        expires: 0x1111_2222,
        token: 0x3333_4444_5555_6666,
    }
    .write(&mut payload)
    .expect("token");

    let report = recv(&mut session, 1, &payload, Duration::ZERO);
    assert_eq!(
        report.external_address,
        Some(AddressBlock {
            port: 12345,
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        })
    );
    assert_eq!(report.new_token, Some((0x1111_2222, 0x3333_4444_5555_6666)));
}

#[test]
fn recv_router_info_and_relay_go_to_pending() {
    let mut session = session();
    let mut payload = Vec::new();
    write_block(&mut payload, Ssu2BlockType::RouterInfo, &body(20)).expect("router info");
    write_block(&mut payload, Ssu2BlockType::PeerTest, &body(4)).expect("peer test");
    let report = recv(&mut session, 1, &payload, Duration::ZERO);
    assert_eq!(report.pending.len(), 2);
    assert_eq!(report.pending[0], PendingBlock::RouterInfo(body(20)));
    assert_eq!(report.pending[1], PendingBlock::PeerTest(body(4)));
}

// ---- Ошибки -------------------------------------------------------------

#[test]
fn recv_tampered_packet_fails_to_decrypt() {
    let mut wire = packet(1, 0, &i2np_payload(MSG_ID, &body(4)));
    let last = wire.len() - 1;
    wire[last] ^= 0xFF; // ломаем MAC
    assert!(
        session()
            .recv(
                &mut wire,
                &I2pdPolicy,
                &I2pdCongestionPolicy,
                Duration::ZERO,
                NOW_SECS
            )
            .is_err()
    );
}

#[test]
fn recv_updates_last_activity() {
    let mut session = session();
    let now = Duration::from_secs(1234);
    let _ = recv(&mut session, 1, &i2np_payload(MSG_ID, &body(4)), now);
    assert_eq!(session.last_activity(), now);
}

// ---- Отправка -----------------------------------------------------------

/// Постоянный «бросок» для паддинга (i2pd `GetRng` в тестах).
struct Rolls(u32);

impl uu_i2p::ssu2_send::RandomSource for Rolls {
    fn roll(&mut self) -> u32 {
        self.0
    }
}

const INTRO_A: [u8; 32] = [0x11; 32];
const INTRO_B: [u8; 32] = [0x22; 32];
const CONN_A: ConnectionId = ConnectionId([1; 8]);
const CONN_B: ConnectionId = ConnectionId([2; 8]);

fn side(role: DataSessionRole, source: ConnectionId, dest: ConnectionId) -> Ssu2DataSession {
    let (local, remote) = match role {
        DataSessionRole::Initiator => (INTRO_A, INTRO_B),
        DataSessionRole::Responder => (INTRO_B, INTRO_A),
    };
    Ssu2DataSession::new(
        DataSessionParams {
            role,
            source_conn_id: source,
            dest_conn_id: dest,
            data_keys: keys(),
            local_intro_key: local,
            remote_intro_key: remote,
            max_payload: MAX_PAYLOAD,
            testing: false,
            sync_clock_from_peers: false,
        },
        &I2pdCongestionPolicy,
    )
}

/// Пара сессий: Alice (инициатор) и Bob (ответчик) с общими ключами.
fn pair() -> (Ssu2DataSession, Ssu2DataSession) {
    (
        side(DataSessionRole::Initiator, CONN_A, CONN_B),
        side(DataSessionRole::Responder, CONN_B, CONN_A),
    )
}

fn message(msg_id: u32, body_len: usize) -> uu_i2p::i2np_message::I2npMessage {
    uu_i2p::i2np_message::I2npMessage::from_ntcp2_bytes(&ntcp2(
        TYPE_DATABASE_STORE,
        msg_id,
        0,
        &body(body_len),
    ))
    .expect("message")
}

fn recv_all(session: &mut Ssu2DataSession, packets: &[Vec<u8>], now: Duration) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    for packet in packets {
        let mut wire = packet.clone();
        let report = session
            .recv(&mut wire, &I2pdPolicy, &I2pdCongestionPolicy, now, NOW_SECS)
            .expect("recv");
        for msg in report.i2np {
            got.push(msg.payload().to_vec());
        }
    }
    got
}

#[test]
fn flush_delivers_i2np_end_to_end() {
    let (mut alice, mut bob) = pair();
    alice.establish();
    alice.enqueue_i2np(message(MSG_ID, 4), 1);
    let mut rng = Rolls(0);
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let report = alice.flush(&I2pdPolicy, &mut ctx).expect("flush");
    assert_ne!(report.packets.len(), 0);
    assert_eq!(alice.send().in_flight(), report.packets.len());
    assert_eq!(alice.queue_len(), 0);

    let got = recv_all(&mut bob, &report.packets, Duration::from_secs(1));
    assert_eq!(got, vec![body(4)]);
}

#[test]
fn flush_without_queue_sends_nothing() {
    let (mut alice, _bob) = pair();
    alice.establish();
    let mut rng = Rolls(0);
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let report = alice.flush(&I2pdPolicy, &mut ctx).expect("flush");
    assert_eq!(report.packets.len(), 0);
    assert!(!report.ack_block_sent);
}

#[test]
fn flush_requires_established() {
    let (mut alice, _bob) = pair();
    alice.enqueue_i2np(message(MSG_ID, 4), 1);
    let mut rng = Rolls(0);
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let report = alice.flush(&I2pdPolicy, &mut ctx).expect("flush");
    assert_eq!(report.packets.len(), 0);
    assert_eq!(alice.queue_len(), 1, "сообщение остаётся в очереди");
}

#[test]
fn flush_drops_stale_message() {
    let (mut alice, _bob) = pair();
    alice.establish();
    alice.enqueue_i2np(message(MSG_ID, 4), 1);
    let mut rng = Rolls(0);
    // Лаг очереди заведомо больше I2NP_MESSAGE_LOCAL_EXPIRATION_TIMEOUT_TRANSIT.
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: u64::MAX / 2,
        rng: &mut rng,
    };
    let report = alice.flush(&I2pdPolicy, &mut ctx).expect("flush");
    assert_eq!(report.packets.len(), 0);
    assert_eq!(report.dropped.len(), 1);
    assert_eq!(report.dropped[0].msg_id(), MSG_ID);
}

#[test]
fn keep_alive_is_received_as_data() {
    let (mut alice, mut bob) = pair();
    alice.establish();
    let mut rng = Rolls(0);
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let packet = alice
        .send_keep_alive(&I2pdPolicy, &mut ctx)
        .expect("keep alive");
    assert!(packet.len() >= uu_i2p::ssu2_header::SSU2_MIN_PACKET_SIZE);
    let mut wire = packet;
    let report = bob
        .recv(
            &mut wire,
            &I2pdPolicy,
            &I2pdCongestionPolicy,
            Duration::from_secs(1),
            NOW_SECS,
        )
        .expect("recv");
    assert!(report.data_received, "IMMEDIATE_ACK_REQUESTED выставлен");
    assert_eq!(report.i2np.len(), 0);
}

#[test]
fn termination_packet_closes_peer() {
    let (mut alice, mut bob) = pair();
    alice.establish();
    let plan = alice.request_termination(Ssu2TerminationReason::NormalClose);
    assert!(plan.send_termination);
    let mut rng = Rolls(0);
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let packet = alice
        .send_termination(&I2pdPolicy, &mut ctx)
        .expect("termination");
    let mut wire = packet;
    let report = bob
        .recv(
            &mut wire,
            &I2pdPolicy,
            &I2pdCongestionPolicy,
            Duration::from_secs(1),
            NOW_SECS,
        )
        .expect("recv");
    assert_eq!(report.termination, Some(TerminationAction::CloseNow));
}

#[test]
fn path_challenge_and_response_roundtrip() {
    let (mut alice, mut bob) = pair();
    let address = AddressBlock {
        port: 12345,
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    };
    let challenge = 0x0102_0304_0506_0708u64;
    let mut rng = Rolls(0);
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let packet = alice
        .send_path_challenge(&I2pdPolicy, &mut ctx, &address, challenge)
        .expect("challenge");
    let mut wire = packet;
    let report = bob
        .recv(
            &mut wire,
            &I2pdPolicy,
            &I2pdCongestionPolicy,
            Duration::from_secs(1),
            NOW_SECS,
        )
        .expect("recv");
    let data = report.path_challenge.expect("challenge reported");
    assert_eq!(data, challenge.to_be_bytes());

    let response = bob
        .send_path_response(&I2pdPolicy, &mut ctx, &address, &data)
        .expect("response");
    let mut wire = response;
    let report = alice
        .recv(
            &mut wire,
            &I2pdPolicy,
            &I2pdCongestionPolicy,
            Duration::from_secs(1),
            NOW_SECS,
        )
        .expect("recv");
    assert!(report.path_response_accepted);
    assert!(alice.path_validated());
}

#[test]
fn resend_after_rto_reissues_packet() {
    let (mut alice, mut bob) = pair();
    alice.establish();
    alice.enqueue_i2np(message(MSG_ID, 4), 1);
    let mut rng = Rolls(0);
    let t0 = Duration::from_secs(1);
    let mut ctx = SendContext {
        now: t0,
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let report = alice.flush(&I2pdPolicy, &mut ctx).expect("flush");
    assert_eq!(report.packets.len(), 1);
    let first_num = alice.send_packet_num() - 1;

    // Раньше RTO повтор не выдается.
    ctx.now = t0 + alice.send().rto() / 2;
    let report = alice
        .resend(&I2pdPolicy, &I2pdCongestionPolicy, &mut ctx)
        .expect("resend");
    assert_eq!(report.packets.len(), 0);

    // После RTO — повтор с новым номером.
    ctx.now = t0 + alice.send().rto() * 2;
    let report = alice
        .resend(&I2pdPolicy, &I2pdCongestionPolicy, &mut ctx)
        .expect("resend");
    assert_eq!(report.resent, vec![first_num]);
    assert_eq!(report.packets.len(), 1);
    assert_eq!(alice.send().in_flight(), 1);
    let sent = alice.send().sent_packets();
    let (num, packet) = sent.iter().next().expect("resent packet tracked");
    assert_eq!(*num, first_num + 1);
    assert_eq!(packet.num_resends, 1);

    let got = recv_all(&mut bob, &report.packets, ctx.now);
    assert_eq!(got, vec![body(4)], "повтор доходит до собеседника");
}

#[test]
fn resend_beyond_limit_terminates_session() {
    let (mut alice, _bob) = pair();
    alice.establish();
    alice.enqueue_i2np(message(MSG_ID, 4), 1);
    let mut rng = Rolls(0);
    let mut ctx = SendContext {
        now: Duration::from_secs(1),
        now_ms: 1000,
        now_micros: 1,
        rng: &mut rng,
    };
    let _ = alice.flush(&I2pdPolicy, &mut ctx).expect("flush");

    let mut terminated = false;
    for _ in 0..10 {
        ctx.now += alice.send().rto() * 4;
        let report = alice
            .resend(&I2pdPolicy, &I2pdCongestionPolicy, &mut ctx)
            .expect("resend");
        if report.terminate {
            terminated = true;
            break;
        }
    }
    assert!(terminated, "предел повторов должен завершить сессию");
    assert_eq!(alice.send().in_flight(), 0);
    assert_eq!(alice.queue_len(), 0);
    assert_eq!(alice.termination_reason(), Ssu2TerminationReason::Timeout);
}
