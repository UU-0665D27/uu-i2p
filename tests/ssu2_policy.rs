use std::time::Duration;
use uu_i2p::{
    ssu2_ack::AckLimits,
    ssu2_policy::{
        HandshakePhase, I2pdPolicy, Ssu2Policy, SSU2_CLOCK_SKEW, SSU2_CLOCK_THRESHOLD,
        SSU2_CONNECT_TIMEOUT, SSU2_HANDSHAKE_RESEND_INTERVAL, SSU2_IPV4_HEADER_SIZE,
        SSU2_MAX_NUM_FRAGMENTS, SSU2_MAX_NUM_RESENDS, SSU2_MAX_PACKET_SIZE, SSU2_MIN_PACKET_SIZE,
        SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT, SSU2_PACKET_OVERHEAD, SSU2_PADDING_ROLL_MASK,
        SSU2_RESEND_ATTEMPT_MIN_INTERVAL, SSU2_SEND_DATETIME_NUM_PACKETS,
        SSU2_TOKEN_EXPIRATION_THRESHOLD, SSU2_TOKEN_EXPIRATION_TIMEOUT, SSU2_UDP_HEADER_SIZE,
    },
};

#[test]
fn i2pd_defaults_match_constants() {
    let p = I2pdPolicy;
    assert_eq!(p.max_packet_size(), SSU2_MAX_PACKET_SIZE);
    assert_eq!(p.min_packet_size(), SSU2_MIN_PACKET_SIZE);
    assert_eq!(p.connect_timeout(), SSU2_CONNECT_TIMEOUT);
    assert_eq!(
        p.handshake_resend_interval(),
        SSU2_HANDSHAKE_RESEND_INTERVAL
    );
    assert_eq!(p.max_num_resends(), SSU2_MAX_NUM_RESENDS);
    assert_eq!(
        p.resend_attempt_min_interval(),
        SSU2_RESEND_ATTEMPT_MIN_INTERVAL
    );
    assert_eq!(p.retry_token_lifetime(), SSU2_TOKEN_EXPIRATION_TIMEOUT);
    assert_eq!(p.next_token_lifetime(), SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT);
    assert_eq!(
        p.token_expiration_threshold(),
        SSU2_TOKEN_EXPIRATION_THRESHOLD
    );
    assert_eq!(p.clock_skew_tolerance(), SSU2_CLOCK_SKEW);
    assert_eq!(p.clock_adjust_threshold(), SSU2_CLOCK_THRESHOLD);
    assert_eq!(p.padding_roll_mask(), SSU2_PADDING_ROLL_MASK);
    assert_eq!(p.send_datetime_every(), SSU2_SEND_DATETIME_NUM_PACKETS);
    assert_eq!(p.max_num_fragments(), SSU2_MAX_NUM_FRAGMENTS);
    assert_eq!(p.ack_limits(), AckLimits::default());
}

#[test]
fn max_payload_size_matches_spec() {
    let p = I2pdPolicy;
    // IPv4: MTU - 20 - 8 - 32 = MTU - 60.
    assert_eq!(
        p.max_payload_size(false, SSU2_MAX_PACKET_SIZE),
        SSU2_MAX_PACKET_SIZE - SSU2_IPV4_HEADER_SIZE - SSU2_UDP_HEADER_SIZE - SSU2_PACKET_OVERHEAD
    );
    assert_eq!(p.max_payload_size(false, 1500), 1440);
    // IPv6: MTU - 40 - 8 - 32 = MTU - 80.
    assert_eq!(p.max_payload_size(true, 1500), 1420);
    // Не уходит в минус.
    assert_eq!(p.max_payload_size(true, 0), 0);
}

#[test]
fn token_validity() {
    let p = I2pdPolicy;
    assert!(p.token_is_valid(0xABCD, 0xABCD));
    assert!(!p.token_is_valid(0, 0xABCD));
    assert!(!p.token_is_valid(0, 0));
    assert!(!p.token_is_valid(0x1234, 0xABCD));
}

#[test]
fn padding_bounds() {
    let p = I2pdPolicy;
    // roll & 0x1F.
    assert_eq!(p.padding_size(0x00, 100, 0), Some(0));
    assert_eq!(p.padding_size(0x1F, 100, 0), Some(31));
    assert_eq!(p.padding_size(0xFF, 100, 0), Some(31));
    // Обрезка по длине буфера: size + 3 > len -> len - 3.
    assert_eq!(p.padding_size(0xFF, 10, 1), Some(7));
    // Подъём до минимального размера блока: size + 3 < min -> min - 3.
    assert_eq!(p.padding_size(0x00, 100, 8), Some(5));
    // Не помещается.
    assert_eq!(p.padding_size(0x00, 2, 0), None);
    assert_eq!(p.padding_size(0x00, 4, 8), None);
}

#[test]
fn clock_skew_terminates_by_phase() {
    let p = I2pdPolicy;
    // Фазы запроса: расхождение сверх допуска -> Terminate.
    assert!(p.clock_skew_terminates(HandshakePhase::SessionRequestReceived, 61));
    assert!(p.clock_skew_terminates(HandshakePhase::TokenRequestReceived, -61));
    assert!(p.clock_skew_terminates(HandshakePhase::Established, 61));
    // Ровно допуск — ещё не Terminate.
    assert!(!p.clock_skew_terminates(HandshakePhase::SessionRequestReceived, 60));
    assert!(!p.clock_skew_terminates(HandshakePhase::SessionRequestReceived, -60));
    // Фазы ответа: расхождение ведёт к коррекции, а не к Terminate.
    assert!(!p.clock_skew_terminates(HandshakePhase::SessionCreatedReceived, 61));
    assert!(!p.clock_skew_terminates(HandshakePhase::TokenReceived, 61));
    assert!(!p.clock_skew_terminates(HandshakePhase::Other, 9999));
}

// ---- POC-подмена политики ------------------------------------------------

/// Пример «своей» политики: имитируем отклоняющееся поведение,
/// не трогая корректную [`I2pdPolicy`].
#[derive(Debug, Clone, Copy)]
struct PocPolicy;

impl Ssu2Policy for PocPolicy {
    fn max_num_resends(&self) -> u32 {
        0
    }

    fn clock_skew_tolerance(&self) -> Duration {
        Duration::from_secs(0)
    }

    fn padding_size(&self, _roll: u8, _len: usize, _min_size: usize) -> Option<usize> {
        Some(0)
    }
}

fn padding_for(policy: &dyn Ssu2Policy, roll: u8, len: usize, min_size: usize) -> Option<usize> {
    policy.padding_size(roll, len, min_size)
}

#[test]
fn policy_is_object_safe_and_swappable() {
    // Эталон через dyn.
    let i2pd: Box<dyn Ssu2Policy> = Box::new(I2pdPolicy);
    assert_eq!(i2pd.max_num_resends(), SSU2_MAX_NUM_RESENDS);
    assert_eq!(padding_for(i2pd.as_ref(), 0xFF, 100, 0), Some(31));
    assert!(i2pd.clock_skew_terminates(HandshakePhase::SessionRequestReceived, 61));

    // Подменённая политика — остальные методы берутся по умолчанию.
    let poc: Box<dyn Ssu2Policy> = Box::new(PocPolicy);
    assert_eq!(poc.max_num_resends(), 0);
    assert_eq!(padding_for(poc.as_ref(), 0xFF, 100, 0), Some(0));
    assert!(poc.clock_skew_terminates(HandshakePhase::SessionRequestReceived, 1));
    // Значения по умолчанию, которые не переопределяли, не изменились.
    assert_eq!(poc.max_packet_size(), SSU2_MAX_PACKET_SIZE);
    assert_eq!(poc.ack_limits(), AckLimits::default());
}
