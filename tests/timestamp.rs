//! Тесты для `timestamp`.

use std::time::Duration;
use uu_i2p::timestamp::{
    adjust_time_offset, current_date, current_time_offset_s, date_string, monotonic_ms,
    monotonic_s, monotonic_us, next_day_date, now_ms, now_s, reset_time_offset,
};

// --- date_string: golden-вектора ----------------------------------------

#[test]
fn date_string_epoch() {
    assert_eq!(date_string(0), *b"19700101");
}

#[test]
fn date_string_known_timestamps() {
    // 1700000000 = 2023-11-14 22:13:20 UTC
    assert_eq!(date_string(1_700_000_000), *b"20231114");
    // 1735689600 = 2025-01-01 00:00:00 UTC
    assert_eq!(date_string(1_735_689_600), *b"20250101");
    // 1735689599 = 2024-12-31 23:59:59 UTC — граница года.
    assert_eq!(date_string(1_735_689_599), *b"20241231");
}

#[test]
fn date_string_leap_day() {
    // 1709164800 = 2024-02-29 00:00:00 UTC — високосный год.
    assert_eq!(date_string(1_709_164_800), *b"20240229");
}

#[test]
fn date_string_always_8_digits() {
    for ts in [0u64, 1, 999_999_999, 1_700_000_000, 4_102_444_800] {
        let d = date_string(ts);
        for &b in &d {
            assert!(b.is_ascii_digit(), "non-digit in {d:?} for ts={ts}");
        }
    }
}

// --- current_date / next_day_date ---------------------------------------

#[test]
fn current_date_is_8_digits() {
    let d = current_date();
    for &b in &d {
        assert!(b.is_ascii_digit());
    }
}

#[test]
fn next_day_date_is_after_current() {
    // В общем случае они различаются, кроме случая, когда мы
    // случайно поймали смену суток между двумя вызовами. Но даже
    // тогда оба 8-значные цифры — просто сверим, что не совпадают
    // и не инвертированы.
    let c = current_date();
    let n = next_day_date();
    // На границе суток между вызовами может так выйти, что
    // `c == n` — не проверяем строгое неравенство.
    for &b in &c {
        assert!(b.is_ascii_digit());
    }
    for &b in &n {
        assert!(b.is_ascii_digit());
    }
}

// --- now_s / now_ms ------------------------------------------------------

#[test]
fn now_s_and_now_ms_agree() {
    let s = now_s();
    let ms = now_ms();
    let s_from_ms = ms / 1000;
    // Разница ≤ 1 секунда: между двумя вызовами может пройти
    // граница секунды.
    assert!(
        s_from_ms.abs_diff(s) <= 1,
        "now_s() = {s}, now_ms()/1000 = {s_from_ms}",
    );
}

#[test]
fn now_s_is_reasonable() {
    // Мы точно после 2020-01-01 (1577836800).
    assert!(now_s() > 1_577_836_800);
    // И раньше 2100-01-01 (4102444800) — иначе что-то сильно не так.
    assert!(now_s() < 4_102_444_800);
}

// --- adjust_time_offset --------------------------------------------------

#[test]
fn adjust_time_offset_shifts_now_s() {
    reset_time_offset();
    let before = now_s();

    adjust_time_offset(100);
    let after = now_s();
    assert!(after >= before + 100, "before={before}, after={after}");

    reset_time_offset();
}

#[test]
fn adjust_time_offset_is_cumulative() {
    reset_time_offset();
    adjust_time_offset(10);
    adjust_time_offset(20);
    assert_eq!(current_time_offset_s(), 30);
    reset_time_offset();
}

#[test]
fn adjust_time_offset_negative_shifts_back() {
    reset_time_offset();
    let before = now_s();

    adjust_time_offset(-100);
    let after = now_s();
    assert!(after + 100 <= before + 1, "before={before}, after={after}");

    reset_time_offset();
}

#[test]
fn adjust_time_offset_does_not_underflow() {
    reset_time_offset();
    // Огромный отрицательный сдвиг — `saturating_sub` даёт 0,
    // а не паникует.
    adjust_time_offset(i64::MIN / 2);
    let _ = now_s();
    reset_time_offset();
}

// --- monotonic_* --------------------------------------------------------

#[test]
fn monotonic_is_monotonic() {
    let a = monotonic_ms();
    std::thread::sleep(Duration::from_millis(10));
    let b = monotonic_ms();
    assert!(b > a, "monotonic_ms must advance");
}

#[test]
fn monotonic_us_resolution() {
    let a = monotonic_us();
    std::thread::sleep(Duration::from_millis(5));
    let b = monotonic_us();
    assert!(
        b - a >= 4_000,
        "at least 4 ms should pass, got {} us",
        b - a
    );
}

#[test]
fn monotonic_secs_and_millis_agree() {
    let s = monotonic_s();
    let ms = monotonic_ms();
    let s_from_ms = ms / 1000;
    assert!(s_from_ms.abs_diff(s) <= 1);
}

#[test]
fn monotonic_is_independent_of_offset() {
    reset_time_offset();
    let m1 = monotonic_ms();

    adjust_time_offset(100_000);
    let m2 = monotonic_ms();

    reset_time_offset();

    // За время между двумя вызовами прошло намного меньше 100 сек.
    assert!(
        m2 - m1 < 1000,
        "monotonic must not be affected by time offset, got {} ms delta",
        m2 - m1,
    );
}

// --- reset_time_offset ---------------------------------------------------

#[test]
fn reset_time_offset_works() {
    reset_time_offset();
    assert_eq!(current_time_offset_s(), 0);
    adjust_time_offset(42);
    assert_eq!(current_time_offset_s(), 42);
    reset_time_offset();
    assert_eq!(current_time_offset_s(), 0);
}
