use uu_i2p::{
    ssu2_block::Ssu2BlockType,
    ssu2_header::SSU2_FLAG_IMMEDIATE_ACK_REQUESTED,
    ssu2_policy::{DateTimeAction, DateTimeSession, HandshakePhase, I2pdPolicy},
    ssu2_recv::{self, PayloadSink},
    ssu2_session::ReceiveState,
};

/// События, записанные `Rec`.
#[derive(Debug, PartialEq, Eq)]
enum Ev {
    DateTime(Vec<u8>),
    RouterInfo(Vec<u8>),
    I2np(Vec<u8>),
    FirstFragment(Vec<u8>),
    FollowOnFragment(Vec<u8>),
    Termination(Vec<u8>),
    RelayRequest(Vec<u8>),
    RelayResponse(Vec<u8>),
    RelayIntro(Vec<u8>),
    PeerTest(Vec<u8>),
    Ack(Vec<u8>),
    Address(Vec<u8>),
    RelayTagRequest,
    RelayTag(Vec<u8>),
    NewToken(Vec<u8>),
    PathChallenge(Vec<u8>),
    PathResponse(Vec<u8>),
    Ignored(Ssu2BlockType, Vec<u8>),
    Unknown(u8, Vec<u8>),
}

/// Приёмник, складывающий все вызовы в список.
#[derive(Default)]
struct Rec(Vec<Ev>);

impl PayloadSink for Rec {
    fn on_datetime(&mut self, body: &[u8]) {
        self.0.push(Ev::DateTime(body.to_vec()));
    }
    fn on_router_info(&mut self, body: &[u8]) {
        self.0.push(Ev::RouterInfo(body.to_vec()));
    }
    fn on_i2np_message(&mut self, body: &[u8]) {
        self.0.push(Ev::I2np(body.to_vec()));
    }
    fn on_first_fragment(&mut self, body: &[u8]) {
        self.0.push(Ev::FirstFragment(body.to_vec()));
    }
    fn on_follow_on_fragment(&mut self, body: &[u8]) {
        self.0.push(Ev::FollowOnFragment(body.to_vec()));
    }
    fn on_termination(&mut self, body: &[u8]) {
        self.0.push(Ev::Termination(body.to_vec()));
    }
    fn on_relay_request(&mut self, body: &[u8]) {
        self.0.push(Ev::RelayRequest(body.to_vec()));
    }
    fn on_relay_response(&mut self, body: &[u8]) {
        self.0.push(Ev::RelayResponse(body.to_vec()));
    }
    fn on_relay_intro(&mut self, body: &[u8]) {
        self.0.push(Ev::RelayIntro(body.to_vec()));
    }
    fn on_peer_test(&mut self, body: &[u8]) {
        self.0.push(Ev::PeerTest(body.to_vec()));
    }
    fn on_ack(&mut self, body: &[u8]) {
        self.0.push(Ev::Ack(body.to_vec()));
    }
    fn on_address(&mut self, body: &[u8]) {
        self.0.push(Ev::Address(body.to_vec()));
    }
    fn on_relay_tag_request(&mut self) {
        self.0.push(Ev::RelayTagRequest);
    }
    fn on_relay_tag(&mut self, body: &[u8]) {
        self.0.push(Ev::RelayTag(body.to_vec()));
    }
    fn on_new_token(&mut self, body: &[u8]) {
        self.0.push(Ev::NewToken(body.to_vec()));
    }
    fn on_path_challenge(&mut self, body: &[u8]) {
        self.0.push(Ev::PathChallenge(body.to_vec()));
    }
    fn on_path_response(&mut self, body: &[u8]) {
        self.0.push(Ev::PathResponse(body.to_vec()));
    }
    fn on_ignored_block(&mut self, kind: Ssu2BlockType, body: &[u8]) {
        self.0.push(Ev::Ignored(kind, body.to_vec()));
    }
    fn on_unknown_block(&mut self, raw_type: u8, body: &[u8]) {
        self.0.push(Ev::Unknown(raw_type, body.to_vec()));
    }
}

/// Один блок: тип (1) + размер (2, BE) + тело.
fn block(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn payload(blocks: &[Vec<u8>]) -> Vec<u8> {
    blocks.concat()
}

const ACK: u8 = 12;
const I2NP: u8 = 3;
const TERMINATION: u8 = 6;
const PEER_TEST: u8 = 10;
const DATE_TIME: u8 = 0;
const OPTIONS: u8 = 1;
const ADDRESS: u8 = 13;
const RELAY_TAG: u8 = 16;
const NEW_TOKEN: u8 = 17;
const PATH_RESPONSE: u8 = 19;
const PADDING: u8 = 254;

#[test]
fn handle_payload_empty_payload() {
    let mut sink = Rec::default();
    let result = ssu2_recv::handle_payload(&[], &mut sink);
    assert_eq!(result, ssu2_recv::HandlePayloadResult::default());
    assert_eq!(sink.0, Vec::new());
}

#[test]
fn handle_payload_dispatches_in_order() {
    let mut sink = Rec::default();
    let p = payload(&[
        block(DATE_TIME, &1u32.to_be_bytes()),
        block(ACK, &[0, 0, 0, 1, 0]),
        block(ADDRESS, &[1, 2, 3]),
    ]);
    let result = ssu2_recv::handle_payload(&p, &mut sink);
    assert_eq!(
        sink.0,
        vec![
            Ev::DateTime(1u32.to_be_bytes().to_vec()),
            Ev::Ack(vec![0, 0, 0, 1, 0]),
            Ev::Address(vec![1, 2, 3]),
        ]
    );
    assert!(!result.data_received, "эти блоки не «значимые»");
}

#[test]
fn handle_payload_reports_ignored_and_unknown_blocks() {
    let mut sink = Rec::default();
    let p = payload(&[
        block(OPTIONS, &[1]),
        block(11, &[]), // Next Nonce
        block(14, &[]), // Intro Key
        block(20, &[]), // First Packet Number
        block(PADDING, &[0, 0, 0]),
        block(99, &[7]), // незарегистрированный
    ]);
    let _ = ssu2_recv::handle_payload(&p, &mut sink);
    assert_eq!(
        sink.0,
        vec![
            Ev::Ignored(Ssu2BlockType::Options, vec![1]),
            Ev::Ignored(Ssu2BlockType::NextNonce, Vec::new()),
            Ev::Ignored(Ssu2BlockType::IntroKey, Vec::new()),
            Ev::Ignored(Ssu2BlockType::FirstPacketNumber, Vec::new()),
            Ev::Ignored(Ssu2BlockType::Padding, vec![0, 0, 0]),
            Ev::Unknown(99, vec![7]),
        ]
    );
}

#[test]
fn handle_payload_stops_on_oversized_block() {
    let mut sink = Rec::default();
    // валидный ACK, затем блок, чьё тело выходит за payload
    let mut p = block(ACK, &[0, 0, 0, 1, 0]);
    p.extend_from_slice(&[I2NP, 0, 10, 1, 2, 3]); // size 10, а тела 3
    let result = ssu2_recv::handle_payload(&p, &mut sink);
    assert_eq!(sink.0, vec![Ev::Ack(vec![0, 0, 0, 1, 0])]);
    assert!(!result.data_received);
}

#[test]
fn handle_payload_ignores_short_trailing_bytes() {
    let mut sink = Rec::default();
    let mut p = block(ACK, &[0, 0, 0, 1, 0]);
    p.extend_from_slice(&[1, 2]); // меньше 3 байт заголовка
    let _ = ssu2_recv::handle_payload(&p, &mut sink);
    assert_eq!(sink.0, vec![Ev::Ack(vec![0, 0, 0, 1, 0])]);
}

#[test]
fn handle_payload_i2np_too_short_is_invalid() {
    let mut sink = Rec::default();
    let result = ssu2_recv::handle_payload(&block(I2NP, &[0; 8]), &mut sink);
    assert!(result.invalid_message);
    assert!(!result.data_received);
    assert_eq!(sink.0, Vec::new());
}

#[test]
fn handle_payload_i2np_ok_sets_data_received() {
    let mut sink = Rec::default();
    let body = vec![0u8; 9];
    let result = ssu2_recv::handle_payload(&block(I2NP, &body), &mut sink);
    assert!(!result.invalid_message);
    assert!(result.data_received);
    assert_eq!(sink.0, vec![Ev::I2np(body)]);
}

#[test]
fn handle_payload_i2np_over_buffer_is_invalid() {
    let mut sink = Rec::default();
    // не TunnelData: предел — короткое сообщение (4096), size + 9 > 4096
    let body = vec![0u8; 4088];
    let result = ssu2_recv::handle_payload(&block(I2NP, &body), &mut sink);
    assert!(result.invalid_message);
    assert_eq!(sink.0, Vec::new());
}

#[test]
fn handle_payload_termination_requires_nine_bytes() {
    let mut sink = Rec::default();
    let _ = ssu2_recv::handle_payload(&block(TERMINATION, &[0; 8]), &mut sink);
    assert_eq!(sink.0, Vec::new());
    let _ = ssu2_recv::handle_payload(&block(TERMINATION, &[0; 9]), &mut sink);
    assert_eq!(sink.0, vec![Ev::Termination(vec![0; 9])]);
}

#[test]
fn handle_payload_relay_tag_and_new_token_guards() {
    let mut sink = Rec::default();
    let _ = ssu2_recv::handle_payload(&block(RELAY_TAG, &[0; 3]), &mut sink);
    let _ = ssu2_recv::handle_payload(&block(RELAY_TAG, &[0; 4]), &mut sink);
    let _ = ssu2_recv::handle_payload(&block(NEW_TOKEN, &[0; 11]), &mut sink);
    let _ = ssu2_recv::handle_payload(&block(NEW_TOKEN, &[0; 12]), &mut sink);
    assert_eq!(
        sink.0,
        vec![Ev::RelayTag(vec![0; 4]), Ev::NewToken(vec![0; 12])]
    );
}

#[test]
fn handle_payload_path_response_requires_eight_bytes() {
    let mut sink = Rec::default();
    let _ = ssu2_recv::handle_payload(&block(PATH_RESPONSE, &[0; 7]), &mut sink);
    let _ = ssu2_recv::handle_payload(&block(PATH_RESPONSE, &[0; 8]), &mut sink);
    assert_eq!(sink.0, vec![Ev::PathResponse(vec![0; 8])]);
}

#[test]
fn handle_payload_peer_test_data_received_rule() {
    let mut sink = Rec::default();
    // msg < 5 -> значимый блок
    let r = ssu2_recv::handle_payload(&block(PEER_TEST, &[4]), &mut sink);
    assert!(r.data_received);
    // msg >= 5 -> нет
    let r = ssu2_recv::handle_payload(&block(PEER_TEST, &[5]), &mut sink);
    assert!(!r.data_received);
    // пустое тело -> нет
    let r = ssu2_recv::handle_payload(&block(PEER_TEST, &[]), &mut sink);
    assert!(!r.data_received);
    assert_eq!(
        sink.0,
        vec![
            Ev::PeerTest(vec![4]),
            Ev::PeerTest(vec![5]),
            Ev::PeerTest(Vec::new()),
        ]
    );
}

#[test]
fn handle_payload_fragments_set_data_received() {
    let mut sink = Rec::default();
    let r = ssu2_recv::handle_payload(&block(4, &[0; 10]), &mut sink);
    assert!(r.data_received);
    let r = ssu2_recv::handle_payload(&block(5, &[0; 8]), &mut sink);
    assert!(r.data_received);
    assert_eq!(
        sink.0,
        vec![
            Ev::FirstFragment(vec![0; 10]),
            Ev::FollowOnFragment(vec![0; 8])
        ]
    );
}

#[test]
fn process_data_immediate_ack_flag_counts_as_data() {
    let mut sink = Rec::default();
    let mut state = ReceiveState::new();
    let r = ssu2_recv::process_data(
        SSU2_FLAG_IMMEDIATE_ACK_REQUESTED,
        1,
        &[],
        &mut state,
        &mut sink,
    );
    assert!(r.data_received);
    assert_eq!(state.receive_packet_num(), 1);
}

#[test]
fn process_data_ignores_duplicate_packet() {
    let mut sink = Rec::default();
    let mut state = ReceiveState::new();
    let body = block(ACK, &[0, 0, 0, 1, 0]);
    let first = ssu2_recv::process_data(0, 1, &body, &mut state, &mut sink);
    assert!(!first.data_received);
    assert_eq!(sink.0.len(), 1);
    // повторный номер 1 — дубликат, payload не обрабатывается
    ssu2_recv::process_data(0, 1, &body, &mut state, &mut sink);
    assert_eq!(sink.0.len(), 1);
}

#[test]
fn process_data_packet_zero_is_always_processed() {
    let mut sink = Rec::default();
    let mut state = ReceiveState::new();
    ssu2_recv::process_data(0, 0, &block(ACK, &[0, 0, 0, 1, 0]), &mut state, &mut sink);
    ssu2_recv::process_data(0, 0, &block(ACK, &[0, 0, 0, 2, 0]), &mut state, &mut sink);
    assert_eq!(sink.0.len(), 2);
    assert_eq!(state.receive_packet_num(), 0, "номер 0 не учитывается");
}

#[test]
fn handle_datetime_short_body_is_ignored() {
    let session = DateTimeSession {
        phase: HandshakePhase::Established,
        testing: false,
        sync_clock_from_peers: false,
    };
    assert_eq!(
        ssu2_recv::handle_datetime(&I2pdPolicy, &[0, 0, 0], 1000, &session),
        DateTimeAction::Ignore
    );
    assert_eq!(
        ssu2_recv::handle_datetime(&I2pdPolicy, &[], 1000, &session),
        DateTimeAction::Ignore
    );
}

#[test]
fn handle_datetime_computes_offset_from_now() {
    let session = DateTimeSession {
        phase: HandshakePhase::Established,
        testing: false,
        sync_clock_from_peers: false,
    };
    // now - remote = 100 -> вне допуска -> Terminate.
    assert_eq!(
        ssu2_recv::handle_datetime(&I2pdPolicy, &900u32.to_be_bytes(), 1000, &session),
        DateTimeAction::Terminate
    );
    // now - remote = 60 = ровно допуск -> ничего.
    assert_eq!(
        ssu2_recv::handle_datetime(&I2pdPolicy, &940u32.to_be_bytes(), 1000, &session),
        DateTimeAction::Ignore
    );
    // remote впереди: offset = -610 -> тоже Terminate.
    assert_eq!(
        ssu2_recv::handle_datetime(&I2pdPolicy, &1610u32.to_be_bytes(), 1000, &session),
        DateTimeAction::Terminate
    );
}
