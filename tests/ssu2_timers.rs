use std::time::Duration;
use uu_i2p::ssu2_policy::{I2pdPolicy, Ssu2Policy};
use uu_i2p::ssu2_timers::{ResendTimerPlan, SessionTimers};

const MS: Duration = Duration::from_millis(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_RESEND_INTERVAL: Duration = Duration::from_millis(1000);
const MIN_INTERVAL: Duration = Duration::from_millis(3);
const RI_INTERVAL: Duration = Duration::from_mins(20);
const RI_VARIANCE_MS: u64 = 1_800_000;

/// Политика с **исправленным** троттлингом: попытки не чаще, чем раз в
/// `resend_attempt_min_interval` (в отличие от фактического поведения i2pd,
/// где условие написано наоборот и троттлинга нет).
struct FixedThrottlePolicy;

impl Ssu2Policy for FixedThrottlePolicy {
    fn can_attempt_resend(&self, last_attempt: Option<Duration>, now: Duration) -> bool {
        last_attempt
            .is_none_or(|last| now >= last.saturating_add(self.resend_attempt_min_interval()))
    }
}

/// Пустой план (троттлинга нет, ничего не переотправляем).
const IDLE: ResendTimerPlan = ResendTimerPlan {
    throttled: false,
    resend_handshake: false,
    resend_router_info: false,
};

#[test]
fn new_timers_are_idle() {
    let t = SessionTimers::new();
    assert_eq!(t.connect_deadline(), None);
    assert!(!t.handshake_pending());
    assert!(!t.connect_expired(Duration::from_secs(1000)));
    assert_eq!(t.last_attempt(), None);
    assert_eq!(t.last_resend(), None);
    assert_eq!(t.next_router_info_resend(), None);
    assert!(!t.router_info_resend_due(Duration::from_secs(1_000_000)));
}

#[test]
fn connect_timer_expires_after_timeout() {
    let mut t = SessionTimers::new();
    let now = Duration::from_secs(100);
    t.schedule_connect(&I2pdPolicy, now);
    assert_eq!(t.connect_deadline(), Some(now + CONNECT_TIMEOUT));
    assert!(!t.connect_expired(now));
    assert!(!t.connect_expired((now + CONNECT_TIMEOUT).checked_sub(MS).unwrap()));
    assert!(t.connect_expired(now + CONNECT_TIMEOUT));
    t.cancel_connect();
    assert_eq!(t.connect_deadline(), None);
    assert!(!t.connect_expired(now + CONNECT_TIMEOUT));
}

#[test]
fn handshake_resend_due_after_interval() {
    let mut t = SessionTimers::new();
    let sent = Duration::from_millis(5000);
    t.note_handshake_sent(sent);
    assert!(t.handshake_pending());
    assert!(!t.handshake_resend_due(&I2pdPolicy, sent));
    assert!(!t.handshake_resend_due(
        &I2pdPolicy,
        (sent + HANDSHAKE_RESEND_INTERVAL).checked_sub(MS).unwrap(),
    ));
    assert!(t.handshake_resend_due(&I2pdPolicy, sent + HANDSHAKE_RESEND_INTERVAL));
    t.clear_handshake();
    assert!(!t.handshake_pending());
    assert!(!t.handshake_resend_due(&I2pdPolicy, sent + HANDSHAKE_RESEND_INTERVAL * 10));
}

#[test]
fn i2pd_throttle_never_blocks_attempts() {
    let mut t = SessionTimers::new();
    let now = Duration::from_secs(1000);
    // i2pd: условие `now + MIN < last_attempt` практически недостижимо.
    assert_eq!(t.resend_step(&I2pdPolicy, now, 0), IDLE);
    assert_eq!(t.resend_step(&I2pdPolicy, now, 0), IDLE);
    assert_eq!(t.last_attempt(), Some(now));
}

#[test]
fn fixed_throttle_limits_attempt_rate() {
    let mut t = SessionTimers::new();
    let now = Duration::from_secs(1000);
    assert_eq!(t.resend_step(&FixedThrottlePolicy, now, 0), IDLE);
    // Внутри минимального интервала — троттлинг.
    let throttled = ResendTimerPlan {
        throttled: true,
        ..IDLE
    };
    assert_eq!(
        t.resend_step(
            &FixedThrottlePolicy,
            (now + MIN_INTERVAL).checked_sub(MS).unwrap(),
            0
        ),
        throttled
    );
    // Как только интервал прошёл — снова можно.
    assert_eq!(
        t.resend_step(&FixedThrottlePolicy, now + MIN_INTERVAL, 0),
        IDLE
    );
}

#[test]
fn handshake_resend_takes_priority_over_router_info() {
    let mut t = SessionTimers::new();
    let handshake_sent = Duration::ZERO;
    t.note_handshake_sent(handshake_sent);
    t.schedule_router_info_resend(&I2pdPolicy, Duration::ZERO, 0);
    let ri_deadline = t.next_router_info_resend().unwrap();
    assert_eq!(ri_deadline, RI_INTERVAL);

    // Оба срока наступили: i2pd делает `return 0` на handshake.
    let now = ri_deadline + MS;
    let plan = t.resend_step(&I2pdPolicy, now, 0);
    assert_eq!(
        plan,
        ResendTimerPlan {
            resend_handshake: true,
            ..IDLE
        }
    );
    // Время отправки handshake обновлено, RouterInfo ещё не перепланирован.
    assert!(!t.handshake_resend_due(&I2pdPolicy, now));
    assert_eq!(t.next_router_info_resend(), Some(ri_deadline));

    // Следующий тик: handshake не пора, RouterInfo — пора.
    let plan = t.resend_step(&I2pdPolicy, now, 0);
    assert_eq!(
        plan,
        ResendTimerPlan {
            resend_router_info: true,
            ..IDLE
        }
    );
    assert_eq!(t.next_router_info_resend(), Some(now + RI_INTERVAL));
}

#[test]
fn router_info_resend_scheduled_with_jitter() {
    let mut t = SessionTimers::new();
    let now = Duration::from_secs(1000);
    // jitter = interval_variance + 5 -> остаток 5 мс.
    t.schedule_router_info_resend(&I2pdPolicy, now, RI_VARIANCE_MS + 5);
    let deadline = now + RI_INTERVAL + Duration::from_millis(5);
    assert_eq!(t.next_router_info_resend(), Some(deadline));
    // Строго `now > deadline`.
    assert!(!t.router_info_resend_due(deadline));
    assert!(t.router_info_resend_due(deadline + MS));
}

#[test]
fn data_resend_time_tracked() {
    let mut t = SessionTimers::new();
    let now = Duration::from_secs(42);
    assert_eq!(t.last_resend(), None);
    t.note_data_resent(now);
    assert_eq!(t.last_resend(), Some(now));
}
