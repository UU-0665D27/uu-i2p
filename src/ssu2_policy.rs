//! SSU2 — слой политик (решения) с эталонной реализацией по i2pd.
//!
//! Модуль отделяет **механику** протокола (форматы, крипта, состояние
//! сессии — `ssu2_header`, `ssu2_crypto`, `ssu2_block`, `ssu2_ack`) от
//! **решений** (что и как делать в конкретной ситуации). Решения собраны в
//! трейт [`Ssu2Policy`]: размеры, тайминги handshake, токены, clock skew,
//! padding, лимиты ACK.
//!
//! ## Зачем
//!
//! Эталонное поведение (i2pd) вынесено в [`I2pdPolicy`] — обычная связность
//! с сетью работает именно через него. Но сессия параметризуется трейтом
//! (`fn ... <P: Ssu2Policy>` / `&dyn Ssu2Policy`), поэтому можно подставить
//! другую реализацию и **точечно** изменить поведение — это нужно для
//! POC-комбайна, который демонстрирует ошибки C++-версии, не ломая при этом
//! корректный путь.
//!
//! У трейта есть дефолтные тела (значения i2pd), так что своя политика
//! переопределяет только то, что реально отличается.
//!
//! ## Что НЕ здесь
//!
//! - TODO(ssu2-policy-termination): выбор
//!   [`crate::ssu2_block::Ssu2TerminationReason`] под конкретный сбой
//!   handshake — появится вместе с логикой handshake (там известны точные
//!   места сбоя);
//! - TODO(ssu2-congestion): политика перегрузки/окна (RTO, окно) —
//!   отдельный трейт при реализации data phase.

use std::time::Duration;

use crate::{ssu2_ack::AckLimits, ssu2_block::SSU2_BLOCK_HEADER_SIZE};

// --- константы i2pd ------------------------------------------------------

/// Максимальный размер UDP-пакета SSU2.
pub const SSU2_MAX_PACKET_SIZE: usize = 1500;
/// Минимальный размер UDP-пакета SSU2 (для padding'а).
pub const SSU2_MIN_PACKET_SIZE: usize = 1280;
/// Размер IPv4-заголовка.
pub const SSU2_IPV4_HEADER_SIZE: usize = 20;
/// Размер IPv6-заголовка.
pub const SSU2_IPV6_HEADER_SIZE: usize = 40;
/// Размер UDP-заголовка.
pub const SSU2_UDP_HEADER_SIZE: usize = 8;
/// Накладные расходы SSU2 поверх MTU: 16-байтовый заголовок + 16-байтовый MAC.
pub const SSU2_PACKET_OVERHEAD: usize = 32;

/// Таймаут установления соединения.
pub const SSU2_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Таймаут ожидания Termination после его отправки.
pub const SSU2_TERMINATION_TIMEOUT: Duration = Duration::from_secs(165);
/// Допустимое расхождение часов (иначе — Terminate в некоторых фазах).
pub const SSU2_CLOCK_SKEW: Duration = Duration::from_secs(60);
/// Порог коррекции часов (если больше — корректируем).
pub const SSU2_CLOCK_THRESHOLD: Duration = Duration::from_secs(15);
/// Время жизни токена в Retry.
pub const SSU2_TOKEN_EXPIRATION_TIMEOUT: Duration = Duration::from_secs(9);
/// Время жизни токена в `NewToken`.
pub const SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT: Duration = Duration::from_mins(52);
/// Порог «почти истёк» для токенов.
pub const SSU2_TOKEN_EXPIRATION_THRESHOLD: Duration = Duration::from_secs(2);
/// Интервал повторной отправки handshake-сообщений.
pub const SSU2_HANDSHAKE_RESEND_INTERVAL: Duration = Duration::from_millis(1000);
/// Максимум повторов handshake-сообщений.
pub const SSU2_MAX_NUM_RESENDS: u32 = 5;
/// Минимальный интервал между попытками повтора.
pub const SSU2_RESEND_ATTEMPT_MIN_INTERVAL: Duration = Duration::from_millis(3);
/// Через сколько пакетов отправлять `DateTime`.
pub const SSU2_SEND_DATETIME_NUM_PACKETS: u32 = 256;
/// Максимум фрагментов I2NP-сообщения.
pub const SSU2_MAX_NUM_FRAGMENTS: u8 = 64;
/// Маска случайного байта для выбора размера padding'а (`0..=31`).
pub const SSU2_PADDING_ROLL_MASK: u8 = 0x1F;

// --- вспомогательные типы -----------------------------------------------

/// Фаза handshake — нужна для решений, зависящих от состояния сессии.
///
/// Соответствует подмножеству `SSU2SessionState` из i2pd, влияющему на
/// обработку `DateTime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakePhase {
    /// Получен `SessionRequest`.
    SessionRequestReceived,
    /// Получен `TokenRequest`.
    TokenRequestReceived,
    /// Получен `SessionCreated`.
    SessionCreatedReceived,
    /// Получен токен (Retry).
    TokenReceived,
    /// Сессия установлена.
    Established,
    /// Любая другая фаза.
    Other,
}

// --- трейт ---------------------------------------------------------------

/// Решения SSU2. Методы по умолчанию соответствуют i2pd.
///
/// Реализация не должна иметь побочных эффектов — это чистая политика;
/// случайность (например, байт для padding'а) передаётся вызывающим.
pub trait Ssu2Policy: Send + Sync {
    // --- размеры ---

    /// Максимальный размер UDP-пакета.
    fn max_packet_size(&self) -> usize {
        SSU2_MAX_PACKET_SIZE
    }

    /// Минимальный размер UDP-пакета.
    fn min_packet_size(&self) -> usize {
        SSU2_MIN_PACKET_SIZE
    }

    /// Максимальный размер AEAD-payload'а при данном MTU.
    fn max_payload_size(&self, ipv6: bool, mtu: usize) -> usize {
        let ip_header = if ipv6 {
            SSU2_IPV6_HEADER_SIZE
        } else {
            SSU2_IPV4_HEADER_SIZE
        };
        mtu.saturating_sub(ip_header + SSU2_UDP_HEADER_SIZE + SSU2_PACKET_OVERHEAD)
    }

    // --- тайминги handshake ---

    /// Таймаут установления соединения.
    fn connect_timeout(&self) -> Duration {
        SSU2_CONNECT_TIMEOUT
    }

    /// Интервал повторной отправки handshake-сообщений.
    fn handshake_resend_interval(&self) -> Duration {
        SSU2_HANDSHAKE_RESEND_INTERVAL
    }

    /// Максимум повторов.
    fn max_num_resends(&self) -> u32 {
        SSU2_MAX_NUM_RESENDS
    }

    /// Минимальный интервал между попытками повтора.
    fn resend_attempt_min_interval(&self) -> Duration {
        SSU2_RESEND_ATTEMPT_MIN_INTERVAL
    }

    // --- токены ---

    /// Время жизни токена, выданного в Retry.
    fn retry_token_lifetime(&self) -> Duration {
        SSU2_TOKEN_EXPIRATION_TIMEOUT
    }

    /// Время жизни токена, выданного в `NewToken`.
    fn next_token_lifetime(&self) -> Duration {
        SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT
    }

    /// Порог «почти истёк» для токенов.
    fn token_expiration_threshold(&self) -> Duration {
        SSU2_TOKEN_EXPIRATION_THRESHOLD
    }

    /// Валиден ли предъявленный токен (i2pd: ненулевой и совпадает с ожидаемым).
    fn token_is_valid(&self, provided: u64, expected: u64) -> bool {
        provided != 0 && provided == expected
    }

    // --- clock skew ---

    /// Допустимое расхождение часов.
    fn clock_skew_tolerance(&self) -> Duration {
        SSU2_CLOCK_SKEW
    }

    /// Порог коррекции часов.
    fn clock_adjust_threshold(&self) -> Duration {
        SSU2_CLOCK_THRESHOLD
    }

    /// Нужно ли завершать сессию из-за расхождения часов в этой фазе.
    ///
    /// Соответствует разбору `DateTime` в i2pd: в фазах запроса/установленной
    /// сессии расхождение больше допуска ведёт к Terminate; в фазах ответа —
    /// к коррекции часов, а не к завершению.
    fn clock_skew_terminates(&self, phase: HandshakePhase, offset_secs: i64) -> bool {
        matches!(
            phase,
            HandshakePhase::SessionRequestReceived
                | HandshakePhase::TokenRequestReceived
                | HandshakePhase::Established
        ) && offset_secs.unsigned_abs() > self.clock_skew_tolerance().as_secs()
    }

    // --- padding ---

    /// Маска случайного байта для размера padding'а (i2pd: `0x1F`).
    fn padding_roll_mask(&self) -> u8 {
        SSU2_PADDING_ROLL_MASK
    }

    /// Размер тела Padding-блока по «броску» `roll`.
    ///
    /// Полностью повторяет `CreatePaddingBlock` из i2pd: `roll & mask`
    /// (`0..=31`), затем обрезка по `len` (не влезть в буфер) и подъём до
    /// `min_size` (минимальный размер *блока*, т.е. с 3-байтовым заголовком).
    /// `None`, если блок не помещается (`len < 3` или `len < min_size`).
    fn padding_size(&self, roll: u8, len: usize, min_size: usize) -> Option<usize> {
        if len < SSU2_BLOCK_HEADER_SIZE || len < min_size {
            return None;
        }
        let mask = self.padding_roll_mask();
        let mut size = usize::from(roll & mask);
        if size + SSU2_BLOCK_HEADER_SIZE > len {
            size = len - SSU2_BLOCK_HEADER_SIZE;
        } else if size + SSU2_BLOCK_HEADER_SIZE < min_size {
            size = min_size - SSU2_BLOCK_HEADER_SIZE;
        }
        Some(size)
    }

    // --- data phase ---

    /// Лимиты сборки ACK-блоков.
    fn ack_limits(&self) -> AckLimits {
        AckLimits::default()
    }

    /// Через сколько отправленных пакетов включать `DateTime`.
    fn send_datetime_every(&self) -> u32 {
        SSU2_SEND_DATETIME_NUM_PACKETS
    }

    /// Максимум фрагментов I2NP-сообщения.
    fn max_num_fragments(&self) -> u8 {
        SSU2_MAX_NUM_FRAGMENTS
    }
}

/// Эталонная политика SSU2 — ровно поведение i2pd (все значения по умолчанию).
///
/// Именно её использует обычный роутер. Отклоняющееся поведение оформляется
/// отдельными реализациями [`Ssu2Policy`].
#[derive(Debug, Clone, Copy, Default)]
pub struct I2pdPolicy;

impl Ssu2Policy for I2pdPolicy {}
