use std::collections::BTreeSet;
use std::time::Duration;
use uu_i2p::{
    ssu2_ack::{AckLimits, AckRange, Ssu2AckBlock},
    ssu2_block::Ssu2Block,
    ssu2_policy::{
        I2pdCongestionPolicy, SSU2_INITIAL_RTO, SSU2_MAX_NUM_RESENDS, SSU2_MIN_WINDOW_SIZE,
        Ssu2CongestionPolicy,
    },
    ssu2_session::{ReceiveState, ResendPlan, SendState, SentPacket},
};

// ---- hex helper ---------------------------------------------------------

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string length mismatch");
    (0..s.len() / 2)
        .map(|i| (hex_digit(s.as_bytes()[2 * i]) << 4) | hex_digit(s.as_bytes()[2 * i + 1]))
        .collect()
}

fn ack(ack_through: u32, acnt: u8, ranges: Vec<AckRange>) -> Ssu2AckBlock {
    Ssu2AckBlock {
        ack_through,
        acnt,
        ranges,
    }
}

// ---- приём --------------------------------------------------------------

#[test]
fn receive_starts_with_packet_zero_received() {
    let s = ReceiveState::new();
    assert_eq!(s.receive_packet_num(), 0);
    assert!(s.out_of_sequence().is_empty());
    assert_eq!(s.highest_received(), 0);
}

#[test]
fn accept_zero_always_true_and_not_counted() {
    let mut s = ReceiveState::new();
    assert!(s.accept(0));
    assert!(s.accept(0)); // повторный 0 тоже «принимается», как в i2pd
    assert_eq!(s.receive_packet_num(), 0);
    assert!(s.out_of_sequence().is_empty());
}

#[test]
fn update_in_order_then_duplicates() {
    let mut s = ReceiveState::new();
    assert!(s.update(1));
    assert!(s.update(2));
    assert_eq!(s.receive_packet_num(), 2);
    assert!(!s.update(2)); // дубликат
    assert!(!s.update(1)); // старый
    assert!(!s.update(0)); // уже принят начальным состоянием
    assert_eq!(s.receive_packet_num(), 2);
}

#[test]
fn update_out_of_sequence() {
    let mut s = ReceiveState::new();
    assert!(s.update(5));
    assert!(s.update(7));
    assert_eq!(s.receive_packet_num(), 0);
    assert_eq!(s.highest_received(), 7);
    assert_eq!(s.out_of_sequence(), &BTreeSet::from([5, 7]));
}

#[test]
fn update_fills_gap_and_merges_out_of_sequence() {
    let mut s = ReceiveState::new();
    s.update(5);
    s.update(7);
    for n in 1..=4 {
        assert!(s.update(n));
    }
    assert_eq!(s.receive_packet_num(), 5);
    assert_eq!(s.highest_received(), 7);
    assert!(s.update(6)); // смыкается с 5..=7
    assert_eq!(s.receive_packet_num(), 7);
    assert!(s.out_of_sequence().is_empty());
}

#[test]
fn accept_sequence() {
    let mut s = ReceiveState::new();
    for n in 1..=10 {
        assert!(s.accept(n));
    }
    assert_eq!(s.receive_packet_num(), 10);
    assert!(!s.accept(10));
}

// ---- сборка ACK ---------------------------------------------------------

#[test]
fn ack_block_contiguous() {
    let mut s = ReceiveState::new();
    for n in 1..=5 {
        s.update(n);
    }
    let a = s.to_ack_block(AckLimits::default());
    assert_eq!(a.ack_through, 5);
    assert_eq!(a.acnt, 5);
    assert_eq!(a.ranges, Vec::new());
    for p in 0..=5 {
        assert!(a.contains(p), "missing {p}");
    }
    assert!(!a.contains(6));
}

#[test]
fn ack_block_only_packet_zero() {
    let a = ReceiveState::new().to_ack_block(AckLimits::default());
    assert_eq!(a.ack_through, 0);
    assert_eq!(a.acnt, 0);
    assert!(a.contains(0));
    assert!(!a.contains(1));
}

#[test]
fn ack_block_with_gap_matches_i2pd_encoding() {
    let mut s = ReceiveState::new();
    for n in 1..=5 {
        s.update(n);
    }
    s.update(7);
    s.update(8);
    let a = s.to_ack_block(AckLimits::default());
    assert_eq!(a.ack_through, 8);
    assert_eq!(a.acnt, 1);
    assert_eq!(a.ranges, vec![AckRange { nack: 1, ack: 6 }]);
    // ackThrough=8, acnt=1, диапазон (1, 6).
    assert_eq!(a.to_body(), hex("00000008010106"));
    for p in [0, 1, 2, 3, 4, 5, 7, 8] {
        assert!(a.contains(p), "missing {p}");
    }
    assert!(!a.contains(6));
}

#[test]
fn ack_block_ack_through_is_highest_out_of_sequence() {
    let mut s = ReceiveState::new();
    s.update(3);
    s.update(9);
    let a = s.to_ack_block(AckLimits::default());
    assert_eq!(a.ack_through, 9);
    for p in [0, 3, 9] {
        assert!(a.contains(p), "missing {p}");
    }
    for p in [1, 2, 4, 5, 6, 7, 8] {
        assert!(!a.contains(p), "unexpected {p}");
    }
}

#[test]
fn ack_block_window_drops_old_numbers() {
    let mut s = ReceiveState::new();
    for n in 1..=100 {
        s.update(n);
    }
    let limits = AckLimits {
        max_packets: 10,
        ..AckLimits::default()
    };
    let a = s.to_ack_block(limits);
    assert_eq!(a.ack_through, 100);
    assert!(a.contains(100));
    assert!(!a.contains(50));
    assert!(!a.contains(0));
}

// ---- отправка: начальные значения ---------------------------------------

#[test]
fn send_state_defaults_from_policy() {
    let p = I2pdCongestionPolicy;
    let s = SendState::new(&p);
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE);
    assert_eq!(s.rto(), SSU2_INITIAL_RTO);
    assert_eq!(s.rtt(), None);
    assert_eq!(s.in_flight(), 0);
    assert!(s.can_send(&p));
}

#[test]
fn can_send_respects_window() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    for n in 0..16 {
        s.register_sent(n, Duration::ZERO);
    }
    assert_eq!(s.in_flight(), 16);
    assert!(s.can_send(&p)); // in_flight <= window
    s.register_sent(16, Duration::ZERO);
    assert!(!s.can_send(&p));
}

// ---- отправка: обработка ACK --------------------------------------------

#[test]
fn handle_ack_updates_rtt_rto_and_window() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    let t0 = Duration::from_secs(1000);
    s.register_sent(0, t0);
    let acked = s.handle_ack(&ack(0, 0, vec![]), t0 + Duration::from_millis(100), &p);
    assert_eq!(acked, vec![0]);
    assert_eq!(s.rtt(), Some(Duration::from_millis(100)));
    assert_eq!(s.rto(), Duration::from_millis(180)); // 100 * 1.8
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE + 1);
    assert_eq!(s.in_flight(), 0);
}

#[test]
fn handle_ack_range_acks_multiple_packets() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    for n in 1..=3 {
        s.register_sent(n, Duration::ZERO);
    }
    // acnt = 2 -> подтверждены [1, 3].
    let acked = s.handle_ack(&ack(3, 2, vec![]), Duration::from_millis(50), &p);
    assert_eq!(acked, vec![1, 2, 3]);
    assert_eq!(s.in_flight(), 0);
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE + 3);
}

#[test]
fn handle_ack_ignores_unknown_packets() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    s.register_sent(5, Duration::ZERO);
    // Подтверждается только 10, которого мы не отправляли.
    assert_eq!(
        s.handle_ack(&ack(10, 0, vec![]), Duration::from_millis(10), &p),
        Vec::new()
    );
    assert_eq!(s.in_flight(), 1);
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE);
}

#[test]
fn handle_ack_range_below_acnt_not_sampled_for_rtt_twice() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    let t0 = Duration::ZERO;
    // 10 и 20 подтверждаются двумя диапазонами; RTT берётся только с 10.
    s.register_sent(10, t0);
    s.register_sent(20, t0 + Duration::from_millis(5));
    let a = ack(20, 0, vec![AckRange { nack: 9, ack: 1 }]); // acks [20,20] и [10,10]
    let mut acked = s.handle_ack(&a, Duration::from_millis(100), &p);
    acked.sort_unstable();
    assert_eq!(acked, vec![10, 20]);
    // RTT — по верхнему диапазону (20, отправлен в 5ms): 100 - 5 = 95ms.
    assert_eq!(s.rtt(), Some(Duration::from_millis(95)));
}

#[test]
fn handle_ack_skips_rtt_for_resent_packets() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    s.register_sent(0, Duration::ZERO);
    s.apply_resends(&[(0, 100)], Duration::from_millis(200), &p);
    assert_eq!(s.rtt(), None);
    let acked = s.handle_ack(&ack(100, 0, vec![]), Duration::from_millis(300), &p);
    assert_eq!(acked, vec![100]);
    assert_eq!(s.rtt(), None); // переотправленный пакет в RTT не идёт
}

// ---- отправка: переотправка ---------------------------------------------

#[test]
fn plan_resend_respects_rto() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    let t0 = Duration::from_secs(10);
    s.register_sent(0, t0);
    assert_eq!(
        s.plan_resend(t0 + Duration::from_millis(539), SSU2_MAX_NUM_RESENDS),
        ResendPlan::default()
    );
    assert_eq!(
        s.plan_resend(t0 + Duration::from_millis(540), SSU2_MAX_NUM_RESENDS),
        ResendPlan {
            resend: vec![0],
            terminate: false,
        }
    );
}

#[test]
fn plan_resend_skips_acked_packet() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    s.register_sent(0, Duration::ZERO);
    s.handle_ack(&ack(0, 0, vec![]), Duration::from_millis(10), &p);
    assert_eq!(
        s.plan_resend(Duration::from_secs(10), SSU2_MAX_NUM_RESENDS),
        ResendPlan::default()
    );
}

#[test]
fn apply_resends_moves_packet_and_halves_window_clamped() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    for n in 1..=4 {
        s.register_sent(n, Duration::ZERO);
    }
    s.handle_ack(&ack(4, 3, vec![]), Duration::from_millis(10), &p);
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE + 4); // 20
    s.register_sent(5, Duration::ZERO);
    s.apply_resends(&[(5, 100)], Duration::from_millis(500), &p);
    // 20 / 2 = 10, но не ниже минимума.
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE);
    assert!(!s.sent_packets().contains_key(&5));
    assert_eq!(
        s.sent_packets().get(&100),
        Some(&SentPacket {
            send_time: Duration::from_millis(500),
            num_resends: 1,
        })
    );
}

#[test]
fn apply_resends_halves_window_above_min() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    for n in 1..=24 {
        s.register_sent(n, Duration::ZERO);
    }
    s.handle_ack(&ack(24, 23, vec![]), Duration::from_millis(10), &p);
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE + 24); // 40
    s.apply_resends(&[(24, 500)], Duration::from_millis(500), &p);
    assert_eq!(s.window(), 20);
}

#[test]
fn apply_resends_empty_is_noop() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    s.register_sent(0, Duration::ZERO);
    s.apply_resends(&[], Duration::from_secs(1), &p);
    assert_eq!(s.window(), SSU2_MIN_WINDOW_SIZE);
    assert_eq!(s.in_flight(), 1);
}

#[test]
fn plan_resend_not_terminate_within_max_attempts() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    s.register_sent(0, Duration::ZERO);
    assert_eq!(
        s.plan_resend(Duration::from_secs(1), SSU2_MAX_NUM_RESENDS),
        ResendPlan {
            resend: vec![0],
            terminate: false,
        }
    );
}

#[test]
fn plan_resend_terminates_after_max_attempts() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    s.register_sent(0, Duration::ZERO);
    // max_num_resends = 5; 6 переотправок -> num_resends = 6.
    let mut cur = 0u32;
    for i in 0..6u32 {
        let new = 1000 + i;
        s.apply_resends(&[(cur, new)], Duration::ZERO, &p);
        cur = new;
    }
    let plan = s.plan_resend(Duration::from_secs(60), SSU2_MAX_NUM_RESENDS);
    assert!(plan.terminate);
    assert_eq!(plan.resend, Vec::new());
}

#[test]
fn clear_drops_in_flight() {
    let p = I2pdCongestionPolicy;
    let mut s = SendState::new(&p);
    s.register_sent(0, Duration::ZERO);
    s.register_sent(1, Duration::ZERO);
    s.clear();
    assert_eq!(s.in_flight(), 0);
}

// ---- подменяемая политика (POC) -----------------------------------------

/// Политика с «игрушечными» значениями — проверяет, что `SendState`
/// действительно берёт параметры из политики, а не из констант i2pd.
struct PocPolicy;

impl Ssu2CongestionPolicy for PocPolicy {
    fn initial_window_size(&self) -> usize {
        4
    }

    fn initial_rto(&self) -> Duration {
        Duration::from_millis(100)
    }

    fn window_on_loss(&self, _window: usize) -> usize {
        1
    }
}

#[test]
fn send_state_uses_injected_policy() {
    let mut s = SendState::new(&PocPolicy);
    assert_eq!(s.window(), 4);
    assert_eq!(s.rto(), Duration::from_millis(100));

    s.register_sent(0, Duration::ZERO);
    s.apply_resends(&[(0, 1)], Duration::ZERO, &PocPolicy);
    s.apply_resends(&[(1, 2)], Duration::ZERO, &PocPolicy);
    assert_eq!(s.window(), 1); // window_on_loss из POC

    // num_resends = 2 > max_num_resends = 1.
    assert!(s.plan_resend(Duration::from_secs(10), 1).terminate);
}
