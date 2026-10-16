//! Время: unix-epoch, monotonic, UTC-дата.
//!
//! Соответствует `Timestamp.cpp` / `Timestamp.h` в i2pd.
//!
//! ## Что внутри
//!
//! - [`now_s`] / [`now_ms`] — секунды и миллисекунды since epoch
//!   **с учётом** глобального сдвига (см. [`adjust_time_offset`]);
//! - [`monotonic_s`] / [`monotonic_ms`] / [`monotonic_us`] —
//!   монотонное время, сдвиг **не** учитывается;
//! - [`date_string`] / [`current_date`] / [`next_day_date`] —
//!   UTC-дата в формате `YYYYMMDD` (`[u8; 8]`).
//!
//! ## Что НЕ внутри
//!
//! - `NTPTimeSync` (UDP-клиент к NTP-серверам): отдельный слой,
//!   который будет работать поверх tokio, когда появится сетевой
//!   runtime.
//!
//! ## Глобальный сдвиг
//!
//! i2pd держит `int64_t g_TimeOffset`, который меняется через
//! `AdjustTimeOffset()`. У нас — [`AtomicI64`], потому что роутер
//! многопоточный, а i2pd'шная неатомарная переменная тут дала бы
//! UB. API сохранён: `adjust_time_offset(+N)` / `adjust_time_offset(-N)`,
//! как в SSU2 peer test (`AdjustTimeOffset(-offset, from)`).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

// --- глобальный сдвиг ----------------------------------------------------

/// Глобальный сдвиг от системных часов, в секундах.
///
/// Значение по умолчанию — 0 (нет сдвига).
static TIME_OFFSET_SECS: AtomicI64 = AtomicI64::new(0);

/// Сдвинуть локальное представление времени относительно системных
/// часов на `delta_s` секунд. Знак учитывается: отрицательный —
/// «часы отстают», положительный — «часы спешат».
///
/// Соответствует `i2p::util::AdjustTimeOffset` в i2pd.
/// Идемпотентно складывается с предыдущими сдвигами.
pub fn adjust_time_offset(delta_s: i64) {
    TIME_OFFSET_SECS.fetch_add(delta_s, Ordering::Relaxed);
}

/// Сбросить сдвиг в ноль. Для тестов и при выключении NTP-синка.
pub fn reset_time_offset() {
    TIME_OFFSET_SECS.store(0, Ordering::Relaxed);
}

/// Текущий сдвиг в секундах. Для диагностики и тестов.
#[must_use]
pub fn current_time_offset_s() -> i64 {
    TIME_OFFSET_SECS.load(Ordering::Relaxed)
}

// --- unix-время ----------------------------------------------------------

/// Применяет сдвиг к значению `u64` со saturating-арифметикой.
///
/// Отдельная функция, чтобы `now_s` и `now_ms` не дублировали
/// логику: сдвиг может уводить и в минус, и в плюс.
const fn apply_offset(v: u64, offset_s: i64) -> u64 {
    if offset_s >= 0 {
        v.saturating_add(offset_s.unsigned_abs())
    } else {
        v.saturating_sub(offset_s.unsigned_abs())
    }
}

/// Текущее время в секундах since epoch с учётом сдвига.
///
/// Если системные часы раньше `UNIX_EPOCH` (что на практике
/// невозможно, но всё же), возвращает `0`.
#[must_use]
pub fn now_s() -> u64 {
    let sys = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    apply_offset(sys, current_time_offset_s())
}

/// Текущее время в миллисекундах since epoch с учётом сдвига.
#[must_use]
pub fn now_ms() -> u64 {
    let sys = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let offset_ms = current_time_offset_s().saturating_mul(1000);
    apply_offset(sys, offset_ms)
}

// --- монотонное время ----------------------------------------------------

/// Origin для монотонных измерений. Устанавливается при первом
/// вызове `monotonic_*`. В i2pd — `steady_clock`, тоже с
/// произвольным origin: важно только, что разница между двумя
/// точками не зависит от системных часов.
static MONOTONIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn origin() -> Instant {
    *MONOTONIC_ORIGIN.get_or_init(Instant::now)
}

/// Монотонное время в секундах от первого вызова `monotonic_*`.
///
/// Не зависит от [`adjust_time_offset`] и системных часов.
#[must_use]
pub fn monotonic_s() -> u64 {
    origin().elapsed().as_secs()
}

/// Монотонное время в миллисекундах от первого вызова `monotonic_*`.
#[must_use]
pub fn monotonic_ms() -> u64 {
    u64::try_from(origin().elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Монотонное время в микросекундах от первого вызова `monotonic_*`.
#[must_use]
pub fn monotonic_us() -> u64 {
    u64::try_from(origin().elapsed().as_micros()).unwrap_or(u64::MAX)
}

// --- UTC-дата ------------------------------------------------------------

/// Форматирует unix-время (секунды since epoch, UTC) как `YYYYMMDD`
/// в 8 ASCII-байт.
///
/// Совпадает с `i2p::util::GetDateString`, но без завершающего `\0`:
/// в Rust длина известна из типа.
///
/// Если `ts_s` больше `i64::MAX` (то есть уходит за 292 миллиарда
/// лет), берётся `i64::MAX` — на практике это недостижимо, но
/// `time::OffsetDateTime::from_unix_timestamp` требует `i64`.
#[must_use]
pub fn date_string(ts_s: u64) -> [u8; 8] {
    let ts = i64::try_from(ts_s).unwrap_or(i64::MAX);
    let dt = OffsetDateTime::from_unix_timestamp(ts).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let y = dt.year();
    let m = u8::from(dt.month());
    let d = dt.day();
    let mut out = [0u8; 8];
    let s = format!("{y:04}{m:02}{d:02}");
    out.copy_from_slice(s.as_bytes());
    out
}

/// Текущая UTC-дата с учётом сдвига.
#[must_use]
pub fn current_date() -> [u8; 8] {
    date_string(now_s())
}

/// Завтрашняя UTC-дата (now + 24 часа) с учётом сдвига.
///
/// Используется при публикации RI и LS: «положить в netdb на
/// текущий и следующий день».
#[must_use]
pub fn next_day_date() -> [u8; 8] {
    date_string(now_s().saturating_add(24 * 3600))
}
