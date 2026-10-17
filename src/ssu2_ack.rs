//! SSU2 — ACK-блок (12).
//!
//! ACK-блок кодирует «битфилд» подтверждённых data-phase пакетов компактно:
//! старший подтверждённый номер (`ack through`), число подряд идущих
//! подтверждённых **ниже** него (`acnt`) и ноль или более диапазонов
//! `(nack, ack)`.
//!
//! ```text
//! 0..4     ack through (u32 big-endian)
//! 4        acnt (1 байт, 0..255)
//! 5..      диапазоны: пары (nack, ack), по 1 байту каждый
//! ```
//!
//! Семантика (совпадает с `SSU2Session::HandleAck` в i2pd):
//!
//! 1. Диапазон `[ack_through - acnt, ack_through]` подтверждён (нижняя
//!    граница не уходит ниже 0).
//! 2. Каждый следующий диапазон `(nack, ack)` отсчитывается вниз от текущей
//!    нижней подтверждённой границы: сначала `nack` пакетов **не**
//!    подтверждены, затем `ack` пакетов подтверждены.
//! 3. Пакеты ниже последнего диапазона — «ни подтверждены, ни нет».
//!
//! Модуль даёт:
//! - [`Ssu2AckBlock`] — разбор/сбор блока (реализует [`Ssu2Block`]);
//! - [`Ssu2AckBlock::acked_ranges`] / [`Ssu2AckBlock::contains`] — декодирование;
//! - [`Ssu2AckBlock::from_received`] — кодирование из множества полученных
//!   номеров пакетов с ограничениями [`AckLimits`].
//!
//! Стратегия выбора диапазонов при отправке спекой не фиксируется
//! («length ... is up to the sender»), поэтому [`Ssu2AckBlock::from_received`]
//! воспроизводит подход i2pd (`CreateAckBlock`): `acnt` до 255, диапазоны по
//! 255 пакетов, не более [`SSU2_MAX_NUM_ACK_RANGES`] диапазонов и не шире
//! [`SSU2_MAX_NUM_ACK_PACKETS`] номеров.

use crate::{
    endian::read_u32_be,
    error::{I2PError, Result},
    ssu2_block::{Ssu2Block, Ssu2BlockType},
};
use std::collections::BTreeSet;

/// Минимальный размер тела ACK-блока: `ack through` (4) + `acnt` (1).
pub const SSU2_ACK_MIN_BODY_SIZE: usize = 5;

/// Максимум `acnt` и значений `nack`/`ack` в одном диапазоне (1 байт).
pub const SSU2_MAX_NUM_ACNT: u8 = 255;

/// Максимальный охват ACK-блока в номерах пакетов (как в i2pd).
pub const SSU2_MAX_NUM_ACK_PACKETS: u32 = 511;

/// Максимум диапазонов, которые имеет смысл отправлять (как в i2pd).
pub const SSU2_MAX_NUM_ACK_RANGES: usize = 32;

/// Один диапазон `(nack, ack)` ACK-блока.
///
/// `nack` — сколько подряд идущих пакетов ниже текущей подтверждённой
/// границы **не** подтверждено, `ack` — сколько пакетов сразу под ними
/// подтверждено. Оба значения могут быть нулём, но не одновременно
/// (спецификация).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    /// Число неподтверждённых пакетов.
    pub nack: u8,
    /// Число подтверждённых пакетов ниже них.
    pub ack: u8,
}

/// Ограничения на кодирование ACK-блока в [`Ssu2AckBlock::from_received_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckLimits {
    /// Максимум `acnt` (сколько подряд подтверждённых влезает в `acnt`).
    pub max_acnt: u8,
    /// Максимум диапазонов `(nack, ack)`.
    pub max_ranges: usize,
    /// Максимальный охват в номерах пакетов ниже `ack through`.
    pub max_packets: u32,
}

impl Default for AckLimits {
    fn default() -> Self {
        Self {
            max_acnt: SSU2_MAX_NUM_ACNT,
            max_ranges: SSU2_MAX_NUM_ACK_RANGES,
            max_packets: SSU2_MAX_NUM_ACK_PACKETS,
        }
    }
}

/// ACK-блок (12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssu2AckBlock {
    /// Наибольший подтверждённый номер пакета.
    pub ack_through: u32,
    /// Сколько подряд идущих подтверждённых номеров ниже `ack_through`.
    pub acnt: u8,
    /// Диапазоны `(nack, ack)` ниже `acnt`-области.
    pub ranges: Vec<AckRange>,
}

/// Приводит значение к `u8`, насыщая на `255`.
fn clamp_u8(v: u64) -> u8 {
    u8::try_from(v).unwrap_or(u8::MAX)
}

impl Ssu2AckBlock {
    /// Декодирует подтверждённые диапазоны `[low, high]` (включительно),
    /// сверху вниз. Полностью повторяет `HandleAck` из i2pd, включая
    /// ограничение охвата [`SSU2_MAX_NUM_ACK_PACKETS`] и «пустые» диапазоны.
    #[must_use]
    pub fn acked_ranges(&self) -> Vec<(u32, u32)> {
        let low = self.ack_through.saturating_sub(u32::from(self.acnt));
        let mut result = vec![(low, self.ack_through)];
        let mut first = low;
        let mut idx = 0;
        while idx < self.ranges.len()
            && first != 0
            && self.ack_through - first < SSU2_MAX_NUM_ACK_PACKETS
        {
            let r = self.ranges[idx];
            idx += 1;
            let mut last = first - 1;
            if u32::from(r.nack) > last {
                break;
            }
            last -= u32::from(r.nack);
            if u32::from(r.ack) > last + 1 {
                break;
            }
            first = last + 1 - u32::from(r.ack);
            if first <= last {
                result.push((first, last));
            }
        }
        result
    }

    /// Подтверждён ли пакет `packet`.
    #[must_use]
    pub fn contains(&self, packet: u32) -> bool {
        self.acked_ranges()
            .iter()
            .any(|&(low, high)| packet >= low && packet <= high)
    }

    /// Кодирует ACK-блок из множества полученных номеров пакетов с
    /// ограничениями по умолчанию ([`AckLimits::default`]).
    ///
    /// Возвращает `None`, если множество пусто (подтверждать нечего).
    #[must_use]
    pub fn from_received(received: &BTreeSet<u32>) -> Option<Self> {
        Self::from_received_with(received, AckLimits::default())
    }

    /// Кодирует ACK-блок из множества полученных номеров пакетов.
    ///
    /// Подтверждает только номера из `received` в пределах `max_packets` ниже
    /// старшего полученного; остальные (более старые) «забываются». Возвращает
    /// `None`, если множество пусто.
    #[must_use]
    pub fn from_received_with(received: &BTreeSet<u32>, limits: AckLimits) -> Option<Self> {
        let ack_through = *received.iter().next_back()?;
        let window_low = ack_through.saturating_sub(limits.max_packets.saturating_sub(1));

        // Максимальные подряд идущие «run»-ы полученных номеров (сверху вниз).
        let mut runs: Vec<(u32, u32)> = Vec::new();
        for &n in received.range(window_low..=ack_through).rev() {
            match runs.last_mut() {
                Some((_, low)) if *low == n + 1 => *low = n,
                _ => runs.push((n, n)),
            }
        }
        let (top_high, top_low) = runs[0];

        // Верхний run кодируется через acnt (до `max_acnt`).
        let top_len = u64::from(top_high - top_low) + 1;
        let acnt = limits.max_acnt.min(clamp_u8(top_len - 1));
        let covered_low = u64::from(top_high) - u64::from(acnt);
        let rem_acked = covered_low - u64::from(top_low);

        // Чередующаяся последовательность (acked?, count) ниже acnt-области.
        let mut items: Vec<(bool, u64)> = Vec::new();
        if rem_acked > 0 {
            items.push((true, rem_acked));
        }
        for w in runs.windows(2) {
            let (_, prev_low) = w[0];
            let (high, low) = w[1];
            let gap = u64::from(prev_low - high - 1);
            items.push((false, gap));
            items.push((true, u64::from(high - low) + 1));
        }

        // Сборка диапазонов (nack, ack) с разбиением по 255.
        let mut ranges: Vec<AckRange> = Vec::new();
        let mut idx = 0;
        let mut nack = if items.first().is_some_and(|x| !x.0) {
            let v = items[0].1;
            idx = 1;
            v
        } else {
            0
        };
        while idx < items.len() {
            let mut ack = items[idx].1;
            idx += 1;

            let mut pair: Vec<AckRange> = Vec::new();
            let mut n = nack;
            while n > 255 {
                pair.push(AckRange { nack: 255, ack: 0 });
                n -= 255;
            }
            let first_ack = ack.min(255);
            pair.push(AckRange {
                nack: clamp_u8(n),
                ack: clamp_u8(first_ack),
            });
            ack -= first_ack;
            while ack > 255 {
                pair.push(AckRange { nack: 0, ack: 255 });
                ack -= 255;
            }
            if ack > 0 {
                pair.push(AckRange {
                    nack: 0,
                    ack: clamp_u8(ack),
                });
            }

            if ranges.len() + pair.len() > limits.max_ranges {
                break;
            }
            ranges.append(&mut pair);

            nack = 0;
            if idx < items.len() {
                nack = items[idx].1;
                idx += 1;
            }
        }

        Some(Self {
            ack_through,
            acnt,
            ranges,
        })
    }

    /// Тело ACK-блока с не более чем `max_ranges` диапазонами.
    ///
    /// Нужно для байтового бюджета: `CreateAckBlock(buf, len)` в i2pd обрезает
    /// число диапазонов по доступному месту (`maxNumRanges = (len - 8) / 2`).
    /// Формат тот же, что у [`Ssu2Block::write_body`], но хвостовые (самые
    /// старые) диапазоны отбрасываются.
    #[must_use]
    pub fn to_body_with_max_ranges(&self, max_ranges: usize) -> Vec<u8> {
        let keep = self.ranges.len().min(max_ranges);
        let mut out = Vec::with_capacity(SSU2_ACK_MIN_BODY_SIZE + keep * 2);
        out.extend_from_slice(&self.ack_through.to_be_bytes());
        out.push(self.acnt);
        for r in &self.ranges[..keep] {
            out.push(r.nack);
            out.push(r.ack);
        }
        out
    }
}

impl<'a> Ssu2Block<'a> for Ssu2AckBlock {
    const TYPE: Ssu2BlockType = Ssu2BlockType::Ack;

    fn parse(body: &'a [u8]) -> Result<Self> {
        if body.len() < SSU2_ACK_MIN_BODY_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SSU2_ACK_MIN_BODY_SIZE,
                got: body.len(),
            });
        }
        let ack_through = read_u32_be(body);
        let acnt = body[4];
        let rest = &body[SSU2_ACK_MIN_BODY_SIZE..];
        if rest.len() % 2 != 0 {
            return Err(I2PError::Malformed(
                "ssu2: ack ranges must come in (nack, ack) pairs",
            ));
        }
        let (pairs, _) = rest.as_chunks::<2>();
        let mut ranges = Vec::with_capacity(pairs.len());
        for pair in pairs {
            if pair[0] == 0 && pair[1] == 0 {
                return Err(I2PError::Malformed(
                    "ssu2: ack range may not have zero nack and ack",
                ));
            }
            ranges.push(AckRange {
                nack: pair[0],
                ack: pair[1],
            });
        }
        Ok(Self {
            ack_through,
            acnt,
            ranges,
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ack_through.to_be_bytes());
        out.push(self.acnt);
        for r in &self.ranges {
            out.push(r.nack);
            out.push(r.ack);
        }
    }
}
