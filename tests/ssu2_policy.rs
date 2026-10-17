use std::time::Duration;
use uu_i2p::{
    ssu2_ack::AckLimits,
    ssu2_block::Ssu2TerminationReason,
    ssu2_policy::{
        DateTimeAction, DateTimeSession, HandshakePhase, I2pdCongestionPolicy, I2pdPolicy,
        SSU2_CLOCK_SKEW, SSU2_CLOCK_THRESHOLD, SSU2_CONNECT_TIMEOUT,
        SSU2_HANDSHAKE_RESEND_INTERVAL, SSU2_INITIAL_RTO, SSU2_IPV4_HEADER_SIZE,
        SSU2_MAX_NUM_FRAGMENTS, SSU2_MAX_NUM_RESENDS, SSU2_MAX_PACKET_SIZE, SSU2_MAX_RTO,
        SSU2_MAX_WINDOW_SIZE, SSU2_MIN_PACKET_SIZE, SSU2_MIN_RTO, SSU2_MIN_WINDOW_SIZE,
        SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT, SSU2_PACKET_OVERHEAD, SSU2_PADDING_ROLL_MASK,
        SSU2_RESEND_ATTEMPT_MIN_INTERVAL, SSU2_RTO_KAPPA, SSU2_RTT_EWMA_ALPHA,
        SSU2_SEND_DATETIME_NUM_PACKETS, SSU2_TOKEN_EXPIRATION_THRESHOLD,
        SSU2_TOKEN_EXPIRATION_TIMEOUT, SSU2_UDP_HEADER_SIZE, Ssu2CloseReason, Ssu2CongestionPolicy,
        Ssu2Policy,
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

// ---- DateTime ------------------------------------------------------------

/// Контекст `DateTime` (фаза, тестовый режим, синхронизация от пиров).
fn dt(phase: HandshakePhase, testing: bool, sync_clock_from_peers: bool) -> DateTimeSession {
    DateTimeSession {
        phase,
        testing,
        sync_clock_from_peers,
    }
}

#[test]
fn datetime_terminates_in_request_phases() {
    let p = I2pdPolicy;
    for phase in [
        HandshakePhase::SessionRequestReceived,
        HandshakePhase::TokenRequestReceived,
        HandshakePhase::Established,
    ] {
        let s = dt(phase, false, false);
        assert_eq!(p.datetime_action(&s, 61), DateTimeAction::Terminate);
        assert_eq!(p.datetime_action(&s, -61), DateTimeAction::Terminate);
        // Ровно допуск — ещё не Terminate.
        assert_eq!(p.datetime_action(&s, 60), DateTimeAction::Ignore);
    }
}

#[test]
fn datetime_response_phase_needs_testing() {
    let p = I2pdPolicy;
    // Не тестовый режим — молчим даже при огромном расхождении.
    let s = dt(HandshakePhase::SessionCreatedReceived, false, true);
    assert_eq!(p.datetime_action(&s, 9999), DateTimeAction::Ignore);
}

#[test]
fn datetime_adjusts_when_syncing_from_peers() {
    let p = I2pdPolicy;
    let s = dt(HandshakePhase::SessionCreatedReceived, true, true);
    // Сверх порога (15) — коррекция на -offset.
    assert_eq!(
        p.datetime_action(&s, 20),
        DateTimeAction::AdjustTimeOffset(-20)
    );
    assert_eq!(
        p.datetime_action(&s, -20),
        DateTimeAction::AdjustTimeOffset(20)
    );
    // В пределах порога — сброс коррекции.
    assert_eq!(
        p.datetime_action(&s, 15),
        DateTimeAction::AdjustTimeOffset(0)
    );
    assert_eq!(
        p.datetime_action(&s, 0),
        DateTimeAction::AdjustTimeOffset(0)
    );
}

#[test]
fn datetime_errors_without_sync_in_testing() {
    let p = I2pdPolicy;
    let s = dt(HandshakePhase::TokenReceived, true, false);
    assert_eq!(p.datetime_action(&s, 61), DateTimeAction::ClockSkewError);
    // Ровно допуск — ещё не ошибка.
    assert_eq!(p.datetime_action(&s, 60), DateTimeAction::Ignore);
}

#[test]
fn datetime_ignores_other_phases() {
    let p = I2pdPolicy;
    let s = dt(HandshakePhase::Other, true, true);
    assert_eq!(p.datetime_action(&s, 9999), DateTimeAction::Ignore);
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

// ---- причины завершения --------------------------------------------------

#[test]
fn termination_reason_mapping_matches_i2pd() {
    use Ssu2CloseReason::{
        ClockSkew, Idle, IncompatibleVersion, Normal, ReplacedByNewSession, Shutdown,
        TerminationReceived, UnackedData,
    };
    let p = I2pdPolicy;
    assert_eq!(
        p.termination_reason(Normal),
        Ssu2TerminationReason::NormalClose
    );
    assert_eq!(
        p.termination_reason(TerminationReceived),
        Ssu2TerminationReason::TerminationReceived
    );
    assert_eq!(
        p.termination_reason(Idle),
        Ssu2TerminationReason::IdleTimeout
    );
    assert_eq!(
        p.termination_reason(Shutdown),
        Ssu2TerminationReason::RouterShutdown
    );
    assert_eq!(
        p.termination_reason(ReplacedByNewSession),
        Ssu2TerminationReason::ReplacedByNewSession
    );
    assert_eq!(
        p.termination_reason(ClockSkew),
        Ssu2TerminationReason::ClockSkew
    );
    assert_eq!(
        p.termination_reason(UnackedData),
        Ssu2TerminationReason::Timeout
    );
    assert_eq!(
        p.termination_reason(IncompatibleVersion),
        Ssu2TerminationReason::IncompatibleVersion
    );

    // Проводные коды (проверяем пару «неочевидных»).
    assert_eq!(p.termination_reason(UnackedData).as_u8(), 14);
    assert_eq!(p.termination_reason(ClockSkew).as_u8(), 7);
    assert_eq!(p.termination_reason(Shutdown).as_u8(), 3);

    // Имена непустые.
    for r in [
        Normal,
        TerminationReceived,
        Idle,
        Shutdown,
        ReplacedByNewSession,
        ClockSkew,
        UnackedData,
        IncompatibleVersion,
    ] {
        assert_ne!(r.name(), "");
    }
}

// ---- перегрузка ----------------------------------------------------------

#[test]
fn congestion_defaults_match_i2pd() {
    let c = I2pdCongestionPolicy;
    assert_eq!(c.min_window_size(), SSU2_MIN_WINDOW_SIZE);
    assert_eq!(c.max_window_size(), SSU2_MAX_WINDOW_SIZE);
    assert_eq!(c.initial_window_size(), SSU2_MIN_WINDOW_SIZE);
    assert_eq!(c.initial_rto(), SSU2_INITIAL_RTO);
    assert_eq!(c.min_rto(), SSU2_MIN_RTO);
    assert_eq!(c.max_rto(), SSU2_MAX_RTO);
    assert_eq!(c.rtt_ewma_alpha(), SSU2_RTT_EWMA_ALPHA);
    assert_eq!(c.rto_kappa(), SSU2_RTO_KAPPA);
}

#[test]
fn rtt_ewma_and_rto() {
    let c = I2pdCongestionPolicy;
    // Первый замер берётся как есть.
    assert_eq!(
        c.update_rtt(None, Duration::from_millis(200)),
        Duration::from_millis(200)
    );
    // Второй: 0.125*100 + 0.875*200 = 187.5 мс.
    let rtt = c.update_rtt(Some(Duration::from_millis(200)), Duration::from_millis(100));
    assert!(
        rtt.abs_diff(Duration::from_micros(187_500)) < Duration::from_micros(1),
        "{rtt:?}"
    );
    // Новый замер тянет сглаженное значение вниз, но не до самого замера.
    assert!(rtt > Duration::from_millis(100));
    assert!(rtt < Duration::from_millis(200));

    // RTO = rtt * kappa c зажимом в [100, 2500] мс.
    assert_eq!(
        c.rto_from_rtt(Duration::from_millis(200)),
        Duration::from_millis(360)
    );
    assert_eq!(c.rto_from_rtt(Duration::from_millis(10)), SSU2_MIN_RTO); // 18 мс -> 100
    assert_eq!(c.rto_from_rtt(Duration::from_secs(10)), SSU2_MAX_RTO);
}

#[test]
fn window_growth_and_backoff() {
    let c = I2pdCongestionPolicy;
    // ACK расширяет окно, но не выше максимума.
    assert_eq!(c.window_on_ack(16, 4), 20);
    assert_eq!(c.window_on_ack(250, 100), SSU2_MAX_WINDOW_SIZE);
    // Потеря делит окно вдвое, но не ниже минимума.
    assert_eq!(c.window_on_loss(100), 50);
    assert_eq!(c.window_on_loss(40), 20);
    assert_eq!(c.window_on_loss(20), SSU2_MIN_WINDOW_SIZE); // 10 -> 16
    assert_eq!(c.window_on_loss(16), SSU2_MIN_WINDOW_SIZE);
    // can_send: на границе i2pd шлёт (<=).
    assert!(c.can_send(16, 0));
    assert!(c.can_send(16, 16));
    assert!(!c.can_send(16, 17));
}

/// Пример «своей» политики перегрузки — не трогая эталонную.
#[derive(Debug, Clone, Copy)]
struct PocCongestion;

impl Ssu2CongestionPolicy for PocCongestion {
    fn max_window_size(&self) -> usize {
        32
    }

    fn rto_kappa(&self) -> f64 {
        1.0
    }
}

#[test]
fn congestion_policy_is_object_safe_and_swappable() {
    let i2pd: Box<dyn Ssu2CongestionPolicy> = Box::new(I2pdCongestionPolicy);
    assert_eq!(i2pd.window_on_ack(16, 100), 116);

    let poc: Box<dyn Ssu2CongestionPolicy> = Box::new(PocCongestion);
    // Переопределённый максимум окна.
    assert_eq!(poc.window_on_ack(16, 100), 32);
    // Переопределённый kappa: RTO = RTT.
    assert_eq!(
        poc.rto_from_rtt(Duration::from_millis(200)),
        Duration::from_millis(200)
    );
    // Значения по умолчанию не изменились.
    assert_eq!(poc.min_window_size(), SSU2_MIN_WINDOW_SIZE);
    assert_eq!(poc.initial_rto(), SSU2_INITIAL_RTO);
}
