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
//! ## Состав
//!
//! Помимо сетевых решений, [`Ssu2Policy`] отображает событие закрытия
//! ([`Ssu2CloseReason`]) в [`crate::ssu2_block::Ssu2TerminationReason`].
//! Политика перегрузки data phase (окно, RTO) вынесена в отдельный трейт
//! [`Ssu2CongestionPolicy`] с эталонной реализацией [`I2pdCongestionPolicy`].
//!
//! ## Что НЕ здесь
//!
//! - I2NP-очередь отправки и сборка payload пакета (`SendQueue`/`SendData`
//!   в i2pd): механика номеров, ACK и переотправки живёт в
//!   [`crate::ssu2_session`] (`ReceiveState` / `SendState`), а шифрование и
//!   сокеты — вне этого слоя.

use std::time::Duration;

use crate::{
    ssu2_ack::AckLimits,
    ssu2_block::{SSU2_BLOCK_HEADER_SIZE, Ssu2TerminationReason},
};

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
/// Через сколько секунд удаляется недособранное I2NP-сообщение (`CleanUp`).
pub const SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Маска случайного байта для выбора размера padding'а (`0..=31`).
pub const SSU2_PADDING_ROLL_MASK: u8 = 0x1F;

// --- константы перегрузки (i2pd) ----------------------------------------

/// Минимальный размер окна (в пакетах).
pub const SSU2_MIN_WINDOW_SIZE: usize = 16;
/// Максимальный размер окна (в пакетах).
pub const SSU2_MAX_WINDOW_SIZE: usize = 256;
/// Минимальный RTO.
pub const SSU2_MIN_RTO: Duration = Duration::from_millis(100);
/// Начальный RTO.
pub const SSU2_INITIAL_RTO: Duration = Duration::from_millis(540);
/// Максимальный RTO.
pub const SSU2_MAX_RTO: Duration = Duration::from_millis(2500);
/// Доля нового замера в сглаживании RTT (EWMA).
pub const SSU2_RTT_EWMA_ALPHA: f64 = 0.125;
/// Множитель RTO относительно сглаженного RTT (`kappa`).
pub const SSU2_RTO_KAPPA: f64 = 1.8;

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

/// Событие, из-за которого сессия завершается.
///
/// Перечислены только причины, которые i2pd реально выставляет в
/// `m_TerminationReason` (остальные коды из
/// [`crate::ssu2_block::Ssu2TerminationReason`] в его коде не используются).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ssu2CloseReason {
    /// Обычное закрытие.
    Normal,
    /// Получен Termination от peer при установленной сессии.
    TerminationReceived,
    /// Idle timeout.
    Idle,
    /// Выключение роутера.
    Shutdown,
    /// Сессия заменена новой.
    ReplacedByNewSession,
    /// Расхождение часов сверх допуска.
    ClockSkew,
    /// Пакет не подтверждён после всех повторов.
    UnackedData,
    /// Несовместимая версия (ответ Retry).
    IncompatibleVersion,
}

impl Ssu2CloseReason {
    /// Человекочитаемое имя.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::TerminationReceived => "TerminationReceived",
            Self::Idle => "Idle",
            Self::Shutdown => "Shutdown",
            Self::ReplacedByNewSession => "ReplacedByNewSession",
            Self::ClockSkew => "ClockSkew",
            Self::UnackedData => "UnackedData",
            Self::IncompatibleVersion => "IncompatibleVersion",
        }
    }
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

    /// Через сколько недособранное I2NP-сообщение удаляется.
    fn incomplete_messages_cleanup_timeout(&self) -> Duration {
        SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT
    }

    // --- завершение ---

    /// Код причины завершения для конкретного события.
    ///
    /// Соответствует тому, какие значения `m_TerminationReason` выставляет
    /// i2pd: `Timeout` — не дождались ACK; `ClockSkew` — `DateTime` вне
    /// допуска; `IncompatibleVersion` — ответ Retry; остальные — из
    /// shutdown/idle/замены сессии.
    fn termination_reason(&self, reason: Ssu2CloseReason) -> Ssu2TerminationReason {
        match reason {
            Ssu2CloseReason::Normal => Ssu2TerminationReason::NormalClose,
            Ssu2CloseReason::TerminationReceived => Ssu2TerminationReason::TerminationReceived,
            Ssu2CloseReason::Idle => Ssu2TerminationReason::IdleTimeout,
            Ssu2CloseReason::Shutdown => Ssu2TerminationReason::RouterShutdown,
            Ssu2CloseReason::ReplacedByNewSession => Ssu2TerminationReason::ReplacedByNewSession,
            Ssu2CloseReason::ClockSkew => Ssu2TerminationReason::ClockSkew,
            Ssu2CloseReason::UnackedData => Ssu2TerminationReason::Timeout,
            Ssu2CloseReason::IncompatibleVersion => Ssu2TerminationReason::IncompatibleVersion,
        }
    }
}

/// Эталонная политика SSU2 — ровно поведение i2pd (все значения по умолчанию).
///
/// Именно её использует обычный роутер. Отклоняющееся поведение оформляется
/// отдельными реализациями [`Ssu2Policy`].
#[derive(Debug, Clone, Copy, Default)]
pub struct I2pdPolicy;

impl Ssu2Policy for I2pdPolicy {}

// --- перегрузка (data phase) --------------------------------------------

/// Политика перегрузки data phase: размер окна и RTO.
///
/// Отдельный трейт от [`Ssu2Policy`]: перегрузка меняется независимо от
/// сетевых решений. Реализация чистая — состояние сессии (`rtt`, `window`)
/// передаётся вызывающим. Значения по умолчанию — i2pd.
pub trait Ssu2CongestionPolicy: Send + Sync {
    /// Минимальный размер окна (в пакетах).
    fn min_window_size(&self) -> usize {
        SSU2_MIN_WINDOW_SIZE
    }

    /// Максимальный размер окна (в пакетах).
    fn max_window_size(&self) -> usize {
        SSU2_MAX_WINDOW_SIZE
    }

    /// Начальный размер окна (i2pd — минимальный).
    fn initial_window_size(&self) -> usize {
        self.min_window_size()
    }

    /// Начальный RTO.
    fn initial_rto(&self) -> Duration {
        SSU2_INITIAL_RTO
    }

    /// Минимальный RTO.
    fn min_rto(&self) -> Duration {
        SSU2_MIN_RTO
    }

    /// Максимальный RTO.
    fn max_rto(&self) -> Duration {
        SSU2_MAX_RTO
    }

    /// Доля нового замера в EWMA RTT.
    fn rtt_ewma_alpha(&self) -> f64 {
        SSU2_RTT_EWMA_ALPHA
    }

    /// Множитель RTO относительно сглаженного RTT.
    fn rto_kappa(&self) -> f64 {
        SSU2_RTO_KAPPA
    }

    /// Обновляет сглаженный RTT новым замером. `None` — замеров ещё не было.
    ///
    /// i2pd: `rtt = alpha*sample + (1-alpha)*rtt`, при этом новое значение
    /// весит `alpha` (замеры сглаживаются медленно).
    fn update_rtt(&self, current: Option<Duration>, sample: Duration) -> Duration {
        current.map_or(sample, |prev| {
            let alpha = self.rtt_ewma_alpha();
            let ms = alpha.mul_add(sample.as_secs_f64(), (1.0 - alpha) * prev.as_secs_f64());
            Duration::from_secs_f64(ms)
        })
    }

    /// RTO из сглаженного RTT: `rtt * kappa`, зажатый в `[min, max]`.
    fn rto_from_rtt(&self, rtt: Duration) -> Duration {
        rtt.mul_f64(self.rto_kappa())
            .clamp(self.min_rto(), self.max_rto())
    }

    /// Окно после подтверждения `acked` пакетов (i2pd: `+=`, не выше максимума).
    fn window_on_ack(&self, window: usize, acked: usize) -> usize {
        window.saturating_add(acked).min(self.max_window_size())
    }

    /// Окно после потери (i2pd: вдвое, не ниже минимума).
    fn window_on_loss(&self, window: usize) -> usize {
        (window / 2).max(self.min_window_size())
    }

    /// Можно ли отправить пакет при `in_flight` неподтверждённых (i2pd: `<=`).
    fn can_send(&self, window: usize, in_flight: usize) -> bool {
        in_flight <= window
    }
}

/// Эталонная политика перегрузки — значения i2pd.
#[derive(Debug, Clone, Copy, Default)]
pub struct I2pdCongestionPolicy;

impl Ssu2CongestionPolicy for I2pdCongestionPolicy {}
