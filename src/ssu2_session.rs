//! SSU2 — состояние data phase (учёт номеров пакетов и окно переотправки).
//!
//! Механика data phase из i2pd без привязки к вводу-выводу — только номера
//! пакетов, времена и счётчики:
//!
//! - приём — [`ReceiveState`]: `UpdateReceivePacketNum` и сборка ACK
//!   (`SSU2Session.cpp:3312` / `CreateAckBlock`, `:2987`);
//! - отправка — [`SendState`]: `HandleAck` / `HandleAckRange` (`:2035` /
//!   `:2064`) и переотправка по RTO (`:632`).
//!
//! Шифрование, I2NP-очереди и сокеты сюда не входят. Окно, RTT и RTO считает
//! [`Ssu2CongestionPolicy`] — состояние лишь хранит `window`/`rtt`/`rto` и
//! вызывает её методы, поэтому политику можно подменить.
//!
//! Время — монотонная [`Duration`] от вызывающего; сравнения идут ровно как
//! `uint64` миллисекунд у i2pd.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::ssu2_ack::{AckLimits, Ssu2AckBlock};
use crate::ssu2_policy::Ssu2CongestionPolicy;

// --- приём ---------------------------------------------------------------

/// Учёт принятых номеров data-phase пакетов.
///
/// Зеркалит `m_ReceivePacketNum` + `m_OutOfSequencePackets` из i2pd.
///
/// Начальное состояние совпадает с i2pd: `receive_packet_num == 0`, то есть
/// номер `0` считается уже принятым. В `ProcessData` i2pd обрабатывает
/// `packetNum == 0` в обход `UpdateReceivePacketNum`, поэтому вызывающему
/// следует пользоваться [`ReceiveState::accept`], а не [`ReceiveState::update`]
/// напрямую.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceiveState {
    receive_packet_num: u32,
    out_of_sequence: BTreeSet<u32>,
}

impl ReceiveState {
    /// Новое состояние (номер `0` уже принят, как в i2pd).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Наибольший принятый номер, идущий подряд от `0`.
    #[must_use]
    pub const fn receive_packet_num(&self) -> u32 {
        self.receive_packet_num
    }

    /// Принятые вне очереди номера (всегда больше [`Self::receive_packet_num`]).
    #[must_use]
    pub const fn out_of_sequence(&self) -> &BTreeSet<u32> {
        &self.out_of_sequence
    }

    /// Наибольший принятый номер вообще (`ack through` в i2pd).
    #[must_use]
    pub fn highest_received(&self) -> u32 {
        self.out_of_sequence
            .iter()
            .next_back()
            .copied()
            .unwrap_or(self.receive_packet_num)
    }

    /// Принимает data-phase пакет. `true` — payload нужно обработать.
    ///
    /// Точный аналог `if (!packetNum || UpdateReceivePacketNum (packetNum))`
    /// из `ProcessData`: номер `0` обрабатывается всегда, но в отпечатке
    /// пакетов не учитывается (он уже учтён начальным состоянием).
    pub fn accept(&mut self, packet_num: u32) -> bool {
        packet_num == 0 || self.update(packet_num)
    }

    /// Учитывает номер пакета. `false` — дубликат или слишком старый.
    ///
    /// Зеркалит `UpdateReceivePacketNum`: при `receive + 1` подтягивает
    /// подряд идущие внеочередные номера, иначе кладёт в `out_of_sequence`.
    pub fn update(&mut self, packet_num: u32) -> bool {
        if packet_num <= self.receive_packet_num {
            return false; // дубликат
        }
        if packet_num == self.receive_packet_num.wrapping_add(1) {
            let mut next = packet_num;
            while self.out_of_sequence.remove(&next.wrapping_add(1)) {
                next = next.wrapping_add(1);
            }
            self.receive_packet_num = next;
        } else {
            self.out_of_sequence.insert(packet_num);
        }
        true
    }

    /// Собирает ACK-блок, подтверждающий принятые номера (в окне `limits`).
    ///
    /// Соответствует `CreateAckBlock`. Полученные номера — это подряд идущие
    /// `0..=receive_packet_num` плюс `out_of_sequence`; кодирование делает
    /// [`Ssu2AckBlock::from_received_with`].
    ///
    /// Отличие от i2pd: `CreateAckBlock` держит кэш диапазонов (`m_Ranges`)
    /// и при разрыве больше 255 зажимает `nacks` до 255, из-за чего может
    /// подтвердить не полученный пакет. Мы всегда кодируем из фактического
    /// множества полученных номеров и такого зажима не имеем.
    #[must_use]
    pub fn to_ack_block(&self, limits: AckLimits) -> Ssu2AckBlock {
        let ack_through = self.highest_received();
        let window = limits.max_packets.max(1);
        let window_low = ack_through.saturating_sub(window - 1);

        let mut received = BTreeSet::new();
        let contiguous_hi = self.receive_packet_num.min(ack_through);
        received.extend(window_low..=contiguous_hi);
        received.extend(
            self.out_of_sequence
                .range(window_low..=ack_through)
                .copied(),
        );

        Ssu2AckBlock::from_received_with(&received, limits).unwrap_or(Ssu2AckBlock {
            ack_through,
            acnt: 0,
            ranges: Vec::new(),
        })
    }
}

// --- отправка ------------------------------------------------------------

/// Отправленный, но ещё не подтверждённый пакет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentPacket {
    /// Время отправки (монотонное).
    pub send_time: Duration,
    /// Сколько раз пакет уже переотправлялся.
    pub num_resends: u32,
}

/// Состояние отправки: неподтверждённые пакеты, RTT/RTO и окно.
///
/// Зеркалит `m_SentPackets`, `m_RTT`, `m_RTO` и `m_WindowSize` из i2pd.
#[derive(Debug, Clone)]
pub struct SendState {
    rtt: Option<Duration>,
    rto: Duration,
    window: usize,
    sent: BTreeMap<u32, SentPacket>,
}

impl SendState {
    /// Новое состояние с начальными `RTO`/окном из политики.
    #[must_use]
    pub fn new<P: Ssu2CongestionPolicy>(policy: &P) -> Self {
        Self {
            rtt: None,
            rto: policy.initial_rto(),
            window: policy.initial_window_size(),
            sent: BTreeMap::new(),
        }
    }

    /// Сглаженный RTT (`None`, пока не было ни одного замера).
    #[must_use]
    pub const fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Текущий RTO.
    #[must_use]
    pub const fn rto(&self) -> Duration {
        self.rto
    }

    /// Текущий размер окна (в пакетах).
    #[must_use]
    pub const fn window(&self) -> usize {
        self.window
    }

    /// Число неподтверждённых пакетов.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.sent.len()
    }

    /// Неподтверждённые пакеты (`номер -> метаданные`).
    #[must_use]
    pub const fn sent_packets(&self) -> &BTreeMap<u32, SentPacket> {
        &self.sent
    }

    /// Можно ли отправить ещё пакет при текущем окне.
    #[must_use]
    pub fn can_send<P: Ssu2CongestionPolicy>(&self, policy: &P) -> bool {
        policy.can_send(self.window, self.sent.len())
    }

    /// Регистрирует только что отправленный пакет (аналог `m_SentPackets.emplace`).
    pub fn register_sent(&mut self, packet_num: u32, now: Duration) {
        self.sent.insert(
            packet_num,
            SentPacket {
                send_time: now,
                num_resends: 0,
            },
        );
    }

    /// Обрабатывает принятый ACK-блок, возвращает подтверждённые номера.
    ///
    /// Зеркалит `HandleAck` + `HandleAckRange`: RTT замеряется только по
    /// первому диапазону (acnt) и только по непереотправленным пакетам,
    /// окно растёт на число подтверждённых.
    pub fn handle_ack<P: Ssu2CongestionPolicy>(
        &mut self,
        block: &Ssu2AckBlock,
        now: Duration,
        policy: &P,
    ) -> Vec<u32> {
        if self.sent.is_empty() {
            return Vec::new();
        }
        let mut acked = Vec::new();
        for (i, &(first, last)) in block.acked_ranges().iter().enumerate() {
            // RTT считается только по верхнему (acnt) диапазону.
            let ts = if i == 0 { Some(now) } else { None };
            acked.extend(self.handle_ack_range(first, last, ts, policy));
        }
        acked
    }

    /// Подтверждает диапазон `[first, last]`, возвращает подтверждённые номера.
    fn handle_ack_range<P: Ssu2CongestionPolicy>(
        &mut self,
        first: u32,
        last: u32,
        mut ts: Option<Duration>,
        policy: &P,
    ) -> Vec<u32> {
        if first > last {
            return Vec::new();
        }
        let nums: Vec<u32> = self.sent.range(first..=last).map(|(&n, _)| n).collect();
        if nums.is_empty() {
            return Vec::new();
        }

        for &n in &nums {
            if let Some(t) = ts
                && let Some(&p) = self.sent.get(&n)
                && p.num_resends == 0
                && t > p.send_time
            {
                let rtt = policy.update_rtt(self.rtt, t.saturating_sub(p.send_time));
                self.rtt = Some(rtt);
                self.rto = policy.rto_from_rtt(rtt);
                ts = None; // один замер на диапазон, как в i2pd
            }
        }

        for &n in &nums {
            self.sent.remove(&n);
        }
        self.window = policy.window_on_ack(self.window, nums.len());
        nums
    }

    /// Строит план переотправки: кому по RTO пора и не пора ли завершать.
    ///
    /// Зеркалит цикл переотправки i2pd: пакет переотправляется, когда
    /// `now >= send_time + (num_resends + 1) * rto`; если `num_resends`
    /// уже больше `max_num_resends` — сессию нужно завершить (`Timeout`).
    ///
    /// Предел повторов — `SSU2_MAX_NUM_RESENDS` в i2pd (на `Ssu2Policy` он
    /// вынесен как `max_num_resends`, здесь передаётся явно, чтобы не
    /// дублировать метод трейта).
    #[must_use]
    pub fn plan_resend(&self, now: Duration, max_num_resends: u32) -> ResendPlan {
        let mut resend = Vec::new();
        for (&n, p) in &self.sent {
            let deadline = p
                .send_time
                .saturating_add(self.rto.saturating_mul(p.num_resends.saturating_add(1)));
            if now >= deadline {
                if p.num_resends > max_num_resends {
                    return ResendPlan {
                        resend,
                        terminate: true,
                    };
                }
                resend.push(n);
            }
        }
        ResendPlan {
            resend,
            terminate: false,
        }
    }

    /// Применяет переотправку: `resent` — пары (старый номер, новый номер).
    ///
    /// i2pd на переотправку выдаёт пакету новый номер (`SendData`) и один раз
    /// вдвое уменьшает окно; это и воспроизводится. Пустой список — no-op.
    pub fn apply_resends<P: Ssu2CongestionPolicy>(
        &mut self,
        resent: &[(u32, u32)],
        now: Duration,
        policy: &P,
    ) {
        if resent.is_empty() {
            return;
        }
        for &(old, new) in resent {
            if let Some(p) = self.sent.remove(&old) {
                self.sent.insert(
                    new,
                    SentPacket {
                        send_time: now,
                        num_resends: p.num_resends.saturating_add(1),
                    },
                );
            }
        }
        self.window = policy.window_on_loss(self.window);
    }

    /// Сбрасывает неподтверждённые пакеты (завершение сессии).
    pub fn clear(&mut self) {
        self.sent.clear();
    }
}

/// План переотправки из [`SendState::plan_resend`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResendPlan {
    /// Номера пакетов, которым пора переотправиться (по возрастанию).
    pub resend: Vec<u32>,
    /// Превышен предел попыток — сессию нужно завершить (`Timeout`).
    pub terminate: bool,
}
