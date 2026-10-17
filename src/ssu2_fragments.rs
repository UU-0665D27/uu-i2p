//! SSU2 — сборка I2NP-сообщений из фрагментов data phase.
//!
//! Зеркалит `SSU2IncompleteMessage` и обработчики `HandleFirstFragment` /
//! `HandleFollowOnFragment` / `CleanUp` из i2pd (`SSU2Session.cpp:2170`,
//! `:2214`, `:3440`).
//!
//! Фрагменты приходят блоками `First Fragment` (4) и `Follow-on Fragment` (5)
//! (см. [`crate::ssu2_block`]). Первый несёт NTCP2-заголовок I2NP (9 байт) и
//! начало `payload`'а, продолжения — только байты `payload`'а. Собранное
//! сообщение — это склеенный NTCP2-поток; вызывающий превращает его в
//! [`I2npMessage`] через [`I2npMessage::from_ntcp2_bytes`].
//!
//! ## Внеочередные фрагменты
//!
//! Продолжения могут прийти раньше предыдущих (даже до первого фрагмента):
//! они складываются в отсортированный по номеру набор и «приклеиваются», как
//! только подходит очередь. Дубликаты и уже обработанные номера игнорируются.
//!
//! ## Что НЕ здесь
//!
//! - Отправка: нарезка сообщения на фрагменты (`SendFragmentedMessage` в
//!   i2pd) и упаковка в пакеты — уровень сессии (там нужны очередь, RNG и
//!   `SendData`).

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::time::Duration;

use crate::i2np_message::I2npMessage;
use crate::ssu2_block::{FirstFragmentBlock, FollowOnFragmentBlock};

/// Один отложенный (внеочередной) фрагмент.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutOfSequenceFragment {
    data: Vec<u8>,
    is_last: bool,
}

/// Состояние сборки одного I2NP-сообщения (зеркало `SSU2IncompleteMessage`).
#[derive(Debug, Clone)]
struct IncompleteMessage {
    /// Накопленные NTCP2-байты; `None`, пока не пришёл первый фрагмент
    /// (в i2pd это `msg == null`).
    ntcp2: Option<Vec<u8>>,
    /// Номер следующего ожидаемого продолжения (`nextFragmentNum`).
    next_fragment_num: u16,
    /// Время последнего добавленного фрагмента (монотонное).
    last_insert_time: Duration,
    /// Отложенные фрагменты, отсортированные по номеру (`outOfSequenceFragments`).
    out_of_sequence: BTreeMap<u16, OutOfSequenceFragment>,
}

impl IncompleteMessage {
    const fn new(now: Duration) -> Self {
        Self {
            ntcp2: None,
            next_fragment_num: 0,
            last_insert_time: now,
            out_of_sequence: BTreeMap::new(),
        }
    }

    /// `AttachNextFragment`: дописывает данные и увеличивает счётчик.
    fn attach_next_fragment(&mut self, data: &[u8]) {
        if let Some(buf) = self.ntcp2.as_mut() {
            buf.extend_from_slice(data);
            self.next_fragment_num += 1;
        }
    }

    /// `ConcatOutOfSequenceFragments`: `true` — сообщение собрано.
    fn concat_out_of_sequence(&mut self) -> bool {
        while let Some(num) = self.out_of_sequence.keys().next().copied() {
            if num != self.next_fragment_num {
                return false;
            }
            let Some(fragment) = self.out_of_sequence.remove(&num) else {
                return false;
            };
            self.attach_next_fragment(&fragment.data);
            if fragment.is_last {
                // фрагмент после последнего не клеим
                return true;
            }
        }
        false
    }

    /// `AddOutOfSequenceFragment`: кладёт фрагмент в набор (с дедупликацией).
    fn add_out_of_sequence(
        &mut self,
        fragment_num: u16,
        data: &[u8],
        is_last: bool,
        now: Duration,
    ) {
        if fragment_num == 0 || fragment_num < self.next_fragment_num {
            return; // нулевой или уже обработанный
        }
        let inserted = if let Entry::Vacant(slot) = self.out_of_sequence.entry(fragment_num) {
            slot.insert(OutOfSequenceFragment {
                data: data.to_vec(),
                is_last,
            });
            true
        } else {
            false
        };
        if inserted {
            self.last_insert_time = now;
        }
    }
}

/// Набор недособранных I2NP-сообщений (зеркало `m_IncompleteMessages`).
#[derive(Debug, Clone, Default)]
pub struct IncompleteMessages {
    incomplete: BTreeMap<u32, IncompleteMessage>,
}

impl IncompleteMessages {
    /// Пустой набор.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Число недособранных сообщений.
    #[must_use]
    pub fn len(&self) -> usize {
        self.incomplete.len()
    }

    /// Нет ли недособранных сообщений.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.incomplete.is_empty()
    }

    /// Есть ли недособранное сообщение с таким `msg_id`.
    #[must_use]
    pub fn contains(&self, msg_id: u32) -> bool {
        self.incomplete.contains_key(&msg_id)
    }

    /// `HandleFirstFragment`.
    ///
    /// `Some` — сборка завершилась сразу: сообщение уже было в наборе и всех
    /// недостающих продолжений хватило (это перезапись первого фрагмента, в
    /// i2pd `msg` заменяется целиком).
    pub fn handle_first_fragment(
        &mut self,
        block: &FirstFragmentBlock,
        now: Duration,
    ) -> Option<I2npMessage> {
        let msg_id = block.0.msg_id();
        let ntcp2 = block.0.to_ntcp2_bytes();
        let found = self.incomplete.contains_key(&msg_id);
        let entry = self
            .incomplete
            .entry(msg_id)
            .or_insert_with(|| IncompleteMessage::new(now));
        entry.ntcp2 = Some(ntcp2);
        entry.next_fragment_num = 1;
        entry.last_insert_time = now;
        let complete = found && entry.concat_out_of_sequence();
        if complete {
            self.take_complete(msg_id)
        } else {
            None
        }
    }

    /// `HandleFollowOnFragment`.
    ///
    /// `Some` — этот фрагмент завершил сборку. `max_num_fragments` — предел
    /// номера фрагмента (`Ssu2Policy::max_num_fragments`); нулевой и
    /// выходящие за предел номера отбрасываются.
    pub fn handle_follow_on_fragment(
        &mut self,
        block: &FollowOnFragmentBlock<'_>,
        now: Duration,
        max_num_fragments: u8,
    ) -> Option<I2npMessage> {
        let fragment_num = u16::from(block.fragment_number());
        if fragment_num == 0 || fragment_num >= u16::from(max_num_fragments) {
            return None; // невалидный номер продолжения
        }
        let msg_id = block.msg_id;
        let entry = self
            .incomplete
            .entry(msg_id)
            .or_insert_with(|| IncompleteMessage::new(now));
        if fragment_num < entry.next_fragment_num {
            return None; // дубликат
        }
        let complete = if entry.next_fragment_num == fragment_num && entry.ntcp2.is_some() {
            entry.attach_next_fragment(block.data);
            // последовательный фрагмент; последний завершает сразу, без склейки
            let done = block.is_last() || entry.concat_out_of_sequence();
            if !done {
                entry.last_insert_time = now;
            }
            done
        } else {
            // фрагмент не по порядку (или первый ещё не пришёл)
            entry.add_out_of_sequence(fragment_num, block.data, block.is_last(), now);
            false
        };
        if complete {
            self.take_complete(msg_id)
        } else {
            None
        }
    }

    /// `CleanUp`: удаляет сообщения, не завершённые дольше `timeout`.
    ///
    /// i2pd считает секунды since epoch и удаляет при `now > last + timeout`.
    pub fn cleanup(&mut self, now: Duration, timeout: Duration) {
        self.incomplete
            .retain(|_, m| now <= m.last_insert_time + timeout);
    }

    /// Забирает и разбирает собранное сообщение.
    ///
    /// `None`, если сообщения нет или склеенный `payload` превысил предел
    /// I2NP (64 `КиБ`) — тогда оно отбрасывается.
    fn take_complete(&mut self, msg_id: u32) -> Option<I2npMessage> {
        let entry = self.incomplete.remove(&msg_id)?;
        let bytes = entry.ntcp2?;
        I2npMessage::from_ntcp2_bytes(&bytes).ok()
    }
}
