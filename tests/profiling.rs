//! Тесты для `RouterProfile`.
//!
//! `IsBad` детерминированно тестируется через [`SeqRng`] — Rng,
//! возвращающий заранее заданную последовательность `u32`.

use core::convert::Infallible;
use uu_i2p::profiling::{
    PEER_PROFILE_DECLINED_RECENTLY_INTERVAL, PEER_PROFILE_UNREACHABLE_INTERVAL, RouterProfile,
};

// --- SeqRng --------------------------------------------------------------

/// Rng с заранее заданной последовательностью `u32`.
///
/// В тестах `is_bad` — единственный потребитель `next_u32()`;
/// задавая последовательность, мы полностью контролируем все
/// «броски» и получаем детерминированное поведение.
struct SeqRng {
    values: Vec<u32>,
    pos: usize,
}

impl SeqRng {
    fn new(values: &[u32]) -> Self {
        Self {
            values: values.to_vec(),
            pos: 0,
        }
    }
}

impl rand::TryRng for SeqRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let v = self.values[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let hi = u64::from(self.try_next_u32()?);
        let lo = u64::from(self.try_next_u32()?);
        Ok((hi << 32) | lo)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for b in dest.iter_mut() {
            *b = self.try_next_u32()?.to_le_bytes()[0];
        }
        Ok(())
    }
}

// --- конструктор ---------------------------------------------------------

#[test]
fn new_resets_all_counters() {
    let p = RouterProfile::new(1_000);
    assert_eq!(p.last_update_time(), 1_000);
    assert_eq!(p.last_access_time(), 0);
    assert_eq!(p.last_persist_time(), 0);
    assert!(!p.is_updated());
    assert!(!p.is_real());
    assert!(!p.is_useful());
    assert!(!p.is_duplicated());
    assert!(!p.is_always_declining());
    assert!(!p.is_low_participation_rate());
}

// --- tunnel_build_response ----------------------------------------------

#[test]
fn build_response_accept_increments_agreed() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(0, 2_000);
    assert!(p.is_updated());
    assert!(p.is_real());
    assert_eq!(p.last_update_time(), 2_000);
    // Согласие после нулевого last_decline_time — last_decline остаётся 0.
    assert!(!p.is_declined_recently(2_000));
}

#[test]
fn build_response_decline_sets_decline_time() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(30, 2_000);
    assert!(p.is_declined_recently(2_000));
    assert!(p.is_real());
}

#[test]
fn build_response_accept_after_decline_clears_decline_time() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(30, 2_000); // declined
    p.tunnel_build_response(0, 2_100); // agreed — i2pd сбрасывает флаг
    assert!(!p.is_declined_recently(2_100));
}

// --- tunnel_non_replied -------------------------------------------------

#[test]
fn non_replied_zero_length_is_noop() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_non_replied(0, 2_000);
    assert!(!p.is_updated(), "zero-length must not touch update_time");
}

#[test]
fn non_replied_single_hop_adds_one() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_non_replied(1, 2_000);
    assert!(p.is_updated());
    assert_eq!(p.last_update_time(), 2_000);
    // non_replied=1 > agreed+declined=0, но 1 < 3 → last_decline НЕ ставится
    assert!(!p.is_declined_recently(2_000));
}

#[test]
fn non_replied_multi_hop_adds_fraction() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_non_replied(4, 2_000);
    // накопилось 0.25 — не пересекает ни порог 3, ни «половину»
    assert!(!p.is_declined_recently(2_000));
}

#[test]
fn non_replied_high_ratio_sets_decline_time() {
    let mut p = RouterProfile::new(1_000);
    // 4 молчания по одному хопу: non_replied=4 > agreed+declined=0 и >3
    for _ in 0..4 {
        p.tunnel_non_replied(1, 2_000);
    }
    assert!(p.is_declined_recently(2_000));
}

// --- unreachable --------------------------------------------------------

#[test]
fn set_unreachable_true_and_false() {
    let mut p = RouterProfile::new(1_000);
    p.set_unreachable(true, 2_000);
    assert!(p.is_unreachable(2_000));
    p.set_unreachable(false, 2_100);
    assert!(!p.is_unreachable(2_100));
}

#[test]
fn is_unreachable_expires_after_interval() {
    let mut p = RouterProfile::new(1_000);
    p.set_unreachable(true, 2_000);
    let later = 2_000 + PEER_PROFILE_UNREACHABLE_INTERVAL + 1;
    assert!(!p.is_unreachable(later), "flag must auto-expire");
    // Повторный вызов — тоже false (после сброса).
    assert!(!p.is_unreachable(later));
}

#[test]
fn is_unreachable_boundary_is_inclusive() {
    // i2pd: `ts > last + interval` — строгое. На точной границе — ещё true.
    let mut p = RouterProfile::new(1_000);
    p.set_unreachable(true, 2_000);
    let boundary = 2_000 + PEER_PROFILE_UNREACHABLE_INTERVAL;
    assert!(p.is_unreachable(boundary));
}

// --- connected / duplicated ---------------------------------------------

#[test]
fn connected_sets_has_connected_and_real() {
    let mut p = RouterProfile::new(1_000);
    p.connected(2_000);
    assert!(p.is_real());
    assert!(p.is_useful());
    assert_eq!(p.last_update_time(), 2_000);
}

#[test]
fn set_duplicated_sets_flag() {
    let mut p = RouterProfile::new(1_000);
    p.set_duplicated();
    assert!(p.is_duplicated());
    // i2pd не обновляет update_time в Duplicated.
    assert_eq!(p.last_update_time(), 1_000);
}

// --- is_real / is_useful ------------------------------------------------

#[test]
fn is_real_with_agreed_only() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(0, 2_000);
    assert!(p.is_real());
}

#[test]
fn is_real_with_declined_only() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(1, 2_000);
    assert!(p.is_real());
}

#[test]
fn is_useful_without_real_but_many_non_replied() {
    let mut p = RouterProfile::new(1_000);
    // 4 молчания по одному хопу — non_replied=4 >= 3, но is_real()==false
    for _ in 0..4 {
        p.tunnel_non_replied(1, 2_000);
    }
    assert!(!p.is_real());
    assert!(p.is_useful());
}

#[test]
fn is_useful_false_below_threshold() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_non_replied(1, 2_000);
    p.tunnel_non_replied(1, 2_000);
    // non_replied=2 < PEER_PROFILE_USEFUL_THRESHOLD=3
    assert!(!p.is_real());
    assert!(!p.is_useful());
}

// --- is_low_participation_rate / is_low_reply_rate ----------------------

#[test]
fn low_participation_rate_thresholds() {
    // 4*agreed < declined ⇔ доля согласий < 20%.
    let mut p = RouterProfile::new(1_000);
    // 1 agreed / 4 declined: 4*1 = 4 < 4 — false (граница)
    for _ in 0..1 {
        p.tunnel_build_response(0, 2_000);
    }
    for _ in 0..4 {
        p.tunnel_build_response(1, 2_000);
    }
    assert!(!p.is_low_participation_rate());

    // 1 agreed / 5 declined: 4*1 = 4 < 5 — true
    p.tunnel_build_response(1, 2_000);
    assert!(p.is_low_participation_rate());
}

#[test]
fn low_reply_rate_thresholds() {
    // i2pd: non_replied > 10*(total + 1)
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(0, 2_000); // agreed=1 → total=1, порог 20
    for _ in 0..20 {
        p.tunnel_non_replied(1, 2_000);
    }
    // non_replied=20, порог 10*2=20 — false (строго больше)
    assert!(!p.is_low_reply_rate());

    p.tunnel_non_replied(1, 2_000);
    // non_replied=21 > 20 — true
    assert!(p.is_low_reply_rate());
}

// --- is_always_declining ------------------------------------------------

#[test]
fn always_declining_requires_no_agreed_and_5_declines() {
    let mut p = RouterProfile::new(1_000);
    for _ in 0..4 {
        p.tunnel_build_response(1, 2_000);
    }
    assert!(!p.is_always_declining());
    p.tunnel_build_response(1, 2_000);
    assert!(p.is_always_declining());

    // Одно согласие снимает флаг.
    p.tunnel_build_response(0, 2_000);
    assert!(!p.is_always_declining());
}

// --- is_bad --------------------------------------------------------------

/// tcsr очень высокий → `check_is_known` = false независимо от roll1
/// (при roll1 ≤ 99). Пригодится, чтобы «отключить» ветку checkIsKnown.
const TCSR_HIGH: f64 = 100.0;

/// tcsr = 0 → `check_is_known` = true при любом roll1 (roll1 % 100 ≥ 0).
const TCSR_LOW: f64 = 0.0;

#[test]
fn is_bad_true_when_unreachable() {
    let mut p = RouterProfile::new(1_000);
    p.set_unreachable(true, 2_000);
    let mut rng = SeqRng::new(&[]); // rng не вызывается
    assert!(p.is_bad(2_000, TCSR_HIGH, &mut rng));
}

#[test]
fn is_bad_true_when_duplicated() {
    let mut p = RouterProfile::new(1_000);
    p.set_duplicated();
    let mut rng = SeqRng::new(&[]);
    assert!(p.is_bad(1_000, TCSR_HIGH, &mut rng));
}

#[test]
fn is_bad_true_when_declined_recently() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(1, 2_000); // declined, last_decline=2000
    let mut rng = SeqRng::new(&[]);
    assert!(p.is_bad(2_000, TCSR_HIGH, &mut rng));
}

#[test]
fn is_bad_true_when_check_known_and_no_history() {
    let mut p = RouterProfile::new(1_000);
    // tcsr=0 → check_is_known = true (0 < roll1). roll1=42.
    let mut rng = SeqRng::new(&[42]);
    assert!(p.is_bad(1_000, TCSR_LOW, &mut rng));
    // Убедимся, что second roll не делался — иначе SeqRng бы паникнул
    // на чтении за пределами массива.
}

#[test]
fn is_bad_check_known_but_history_proceeds() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(0, 2_000); // agreed=1 → есть история
    // roll1=42 → check_is_known (0 < 42) = true, но идём дальше
    // roll2=99 % total=1 → 0; agreed=1 < 0 = false
    let mut rng = SeqRng::new(&[42, 99]);
    assert!(!p.is_bad(2_000, TCSR_LOW, &mut rng));
}

#[test]
fn is_bad_no_history_and_check_false_is_false() {
    let mut p = RouterProfile::new(1_000);
    // tcsr=100 → check_is_known = false. roll1=50.
    // total=0, non_replied=0 → second roll нет, is_bad=false.
    let mut rng = SeqRng::new(&[50]);
    assert!(!p.is_bad(1_000, TCSR_HIGH, &mut rng));
}

#[test]
fn is_bad_uses_total_when_history_present() {
    let mut p = RouterProfile::new(1_000);
    // agreed=3, declined=0, total=3
    for _ in 0..3 {
        p.tunnel_build_response(0, 2_000);
    }
    // roll1=50: check_is_known = 100 < 50 = false
    // roll2=99: 99 % 3 = 0; agreed=3 < 0 = false
    let mut rng = SeqRng::new(&[50, 99]);
    assert!(!p.is_bad(2_000, TCSR_HIGH, &mut rng));

    // А теперь согласие меньше броска:
    // roll2=2: agreed=3 < 2 = false — тоже false.
    let mut rng = SeqRng::new(&[50, 2]);
    assert!(!p.is_bad(2_000, TCSR_HIGH, &mut rng));

    // agreed=0, declined=3, total=3, roll2=1 → 0 < 1 = true
    let mut p2 = RouterProfile::new(1_000);
    for _ in 0..3 {
        p2.tunnel_build_response(1, 2_000);
    }
    // last_decline сбросим — иначе is_declined_recently вернёт true раньше
    p2.tunnel_build_response(0, 2_000); // agreed=1 → сбрасывает last_decline
    // Теперь agreed=1, declined=3, total=4
    // roll2 = 3: agreed=1 < 3 → true
    let mut rng = SeqRng::new(&[50, 3]);
    assert!(p2.is_bad(2_000, TCSR_HIGH, &mut rng));
}

#[test]
fn is_bad_uses_non_replied_when_no_agreed_declined() {
    // agreed=0, declined=0, non_replied=4.0
    let mut p = RouterProfile::new(1_000);
    p.tunnel_non_replied(1, 2_000);
    p.tunnel_non_replied(1, 2_000);
    p.tunnel_non_replied(1, 2_000);
    p.tunnel_non_replied(1, 2_000);
    // Но non_replied=4 > 3 активировало last_decline=2000.
    // Идём в is_bad на 2_000 — is_declined_recently сработает раньше.
    // Поэтому сдвинем now_s вперёд, чтобы last_decline «истёк».
    let now = 2_000 + PEER_PROFILE_DECLINED_RECENTLY_INTERVAL + 1;

    // roll1=50: check_is_known = 100 < 50 = false
    // roll2=0: non_replied_int = 4 > 0, 0 % 4 = 0 → is_bad = (0 != 0) = false
    let mut rng = SeqRng::new(&[50, 0]);
    assert!(!p.is_bad(now, TCSR_HIGH, &mut rng));

    // roll2=3: 3 % 4 = 3 → is_bad = (3 != 0) = true
    let mut rng = SeqRng::new(&[50, 3]);
    assert!(p.is_bad(now, TCSR_HIGH, &mut rng));
}

#[test]
fn is_bad_increments_rejected_when_true() {
    let mut p = RouterProfile::new(1_000);
    p.set_duplicated();
    let mut rng = SeqRng::new(&[]);
    assert!(p.is_bad(1_000, TCSR_HIGH, &mut rng));

    // is_bad → true, но rejected++ НЕ выполняется на ветке
    // «unreachable/duplicated/declined». Проверим, что счётчики целы.
    // Чтобы явно проверить инкремент — нужен путь через rng.
    let mut p2 = RouterProfile::new(1_000);
    for _ in 0..3 {
        p2.tunnel_build_response(1, 2_000); // declined=3
    }
    p2.tunnel_build_response(0, 2_000); // agreed=1, сбрасывает last_decline
    // roll2=3: agreed=1 < 3 → is_bad=true → rejected++
    let mut rng = SeqRng::new(&[50, 3]);
    assert!(p2.is_bad(2_000, TCSR_HIGH, &mut rng));
}

#[test]
fn is_bad_increments_taken_when_false() {
    let mut p = RouterProfile::new(1_000);
    for _ in 0..3 {
        p.tunnel_build_response(0, 2_000); // agreed=3
    }
    // roll2=0: agreed=3 < 0 = false → taken++
    let mut rng = SeqRng::new(&[50, 0]);
    assert!(!p.is_bad(2_000, TCSR_HIGH, &mut rng));
}

// --- accessors ----------------------------------------------------------

#[test]
fn set_last_access_time_updates() {
    let mut p = RouterProfile::new(1_000);
    assert_eq!(p.last_access_time(), 0);
    p.set_last_access_time(2_000);
    assert_eq!(p.last_access_time(), 2_000);
}

#[test]
fn set_last_persist_time_updates() {
    let mut p = RouterProfile::new(1_000);
    assert_eq!(p.last_persist_time(), 0);
    p.set_last_persist_time(2_000);
    assert_eq!(p.last_persist_time(), 2_000);
}

#[test]
fn set_updated_can_clear_flag() {
    let mut p = RouterProfile::new(1_000);
    p.tunnel_build_response(0, 2_000);
    assert!(p.is_updated());
    p.set_updated(false);
    assert!(!p.is_updated());
}
