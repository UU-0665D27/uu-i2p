//! Сборка I2NP-сообщений из фрагментов tunnel-сообщения.
//!
//! Соответствует `FragmentsSet` и разбору в
//! `TunnelEndpoint::HandleDecryptedTunnelDataMsg` (`TunnelEndpoint.cpp`)
//! и `IBGWHandler::HandleTunnelDataMsg` (`IBGWHandler.cpp`) из i2pd.
//! Отправляющая часть — [`crate::tunnel_gateway`], wire-формат
//! фрагментов — [`crate::tunnel_fragments`].
//!
//! ## Зачем нужен отдельный объект
//!
//! Одно tunnel-сообщение несёт не больше
//! [`TUNNEL_DATA_MAX_PAYLOAD_SIZE`] байт полезной нагрузки, а
//! I2NP-сообщение может быть до [`I2NP_MAX_MESSAGE_SIZE`] байт и
//! разбито на несколько фрагментов, причём пришедших в **разных**
//! tunnel-сообщениях и вообще не по порядку. Поэтому получатель
//! (gateway или endpoint) держит состояние: первый фрагмент запоминает
//! `delivery`, остальные копятся по `msg_id`.
//!
//! ## Состояние
//!
//! ```text
//!   msg_id -> { delivery, first, parts[1..], last_num, size, started_ms }
//! ```
//!
//! Сообщение считается собранным, когда известен `last_num` и пришли
//! все фрагменты `1..=last_num`.
//!
//! ## Ограничения
//!
//! - не больше [`MAX_PARTIAL_MESSAGES`] незавершённых сообщений;
//! - суммарный размер собираемого сообщения не больше
//!   [`MAX_REASSEMBLED_MESSAGE_SIZE`];
//! - незавершённое сообщение живёт [`PARTIAL_MESSAGE_EXPIRATION_MS`]
//!   миллисекунд, дальше вычищается через [`FragmentReassembler::cleanup`].
//!
//! ## Отличия от i2pd
//!
//! - фрагменты с повторяющимся номером и «сиротские» продолжения
//!   (без первого фрагмента) **молча игнорируются**, а не считаются
//!   ошибкой: в сети такие пакеты обычное дело;
//! - время приходит параметром `now_ms`, а не читается с часов.

use std::collections::{BTreeMap, HashMap, VecDeque};

use tracing::{debug, trace, warn};

use crate::error::Result;
use crate::i2np::I2NP_MAX_MESSAGE_SIZE;
use crate::tunnel_fragments::{
    Delivery, Fragment, FragmentKind, MAX_FRAGMENT_NUMBER, TunnelMessageBlock, parse_tunnel_message,
};
use crate::tunnel_messages::TunnelDataBody;

/// Максимум незавершённых сообщений, которые держим одновременно.
///
/// Как `MAX_PARTIAL_MESSAGES` в i2pd: ограничение на память, а не на
/// протокол. При переполнении новые сообщения отбрасываются.
pub const MAX_PARTIAL_MESSAGES: usize = 64;

/// Время жизни незавершённого сообщения (мс).
///
/// Фрагменты одного сообщения идут подряд, минута с большим запасом.
pub const PARTIAL_MESSAGE_EXPIRATION_MS: u64 = 60_000;

/// Максимальный размер собираемого I2NP-сообщения.
///
/// 63 фрагмента по 1003 байта дают ~63 КБ, поэтому ограничение
/// фактически неактивно, но защищает от выделения памяти по
/// злонамеренно составленным фрагментам.
pub const MAX_REASSEMBLED_MESSAGE_SIZE: usize = I2NP_MAX_MESSAGE_SIZE;

/// Сообщение, у которого уже есть первый фрагмент, но ещё нет последнего.
#[derive(Debug)]
struct PartialMessage {
    /// Способ доставки из первого фрагмента.
    delivery: Delivery,
    /// Данные первого фрагмента.
    first: Vec<u8>,
    /// Данные продолжений по номеру фрагмента.
    parts: BTreeMap<u8, Vec<u8>>,
    /// Номер последнего фрагмента, если он уже пришёл.
    last_num: Option<u8>,
    /// Суммарный размер собранных данных.
    size: usize,
    /// Когда пришёл первый фрагмент (мс).
    started_ms: u64,
}

impl PartialMessage {
    /// Все ли фрагменты `1..=last` на месте.
    fn is_complete(&self, last: u8) -> bool {
        (1..=last).all(|n| self.parts.contains_key(&n))
    }

    /// Склеивает сообщение из первого фрагмента и продолжений.
    fn assemble(&self, last: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size);
        out.extend_from_slice(&self.first);
        for n in 1..=last {
            if let Some(data) = self.parts.get(&n) {
                out.extend_from_slice(data);
            }
        }
        out
    }
}

/// Принимает фрагменты tunnel-сообщений и отдаёт собранные
/// I2NP-сообщения.
///
/// Один такой объект живёт на каждый туннель, в котором мы являемся
/// gateway'ем или endpoint'ом: фрагменты разных туннелей смешивать
/// нельзя. Для транзитного хопа сборка не нужна вовсе.
#[derive(Debug, Default)]
pub struct FragmentReassembler {
    /// Незавершённые сообщения по `msg_id`.
    partial: HashMap<u32, PartialMessage>,
    /// Готовые сообщения, ждущие выдачи.
    ready: VecDeque<TunnelMessageBlock>,
}

impl FragmentReassembler {
    /// Пустой сборщик.
    #[must_use]
    pub fn new() -> Self {
        Self {
            partial: HashMap::new(),
            ready: VecDeque::new(),
        }
    }

    /// Разбирает tunnel-сообщение, скармливает его фрагменты и
    /// возвращает всё, что удалось полностью собрать.
    ///
    /// Сообщение должно быть уже расшифровано слоями туннеля.
    ///
    /// # Errors
    ///
    /// Ошибки [`parse_tunnel_message`]: не сошлась контрольная сумма
    /// либо нет нулевого разделителя. Прерванный на середине разбор
    /// фрагментов — не ошибка: уже разобранные фрагменты обрабатываются,
    /// а причина попадает в лог.
    pub fn accept(&mut self, msg: &TunnelDataBody, now_ms: u64) -> Result<Vec<TunnelMessageBlock>> {
        let parsed = parse_tunnel_message(msg)?;
        if let Some(err) = &parsed.error {
            debug!(
                error = %err,
                fragments = parsed.fragments.len(),
                "fragment reassembly: parsing stopped early"
            );
        }
        for fragment in &parsed.fragments {
            self.push_fragment(fragment, now_ms);
        }
        Ok(self.drain_ready())
    }

    /// Скармливает один фрагмент.
    fn push_fragment(&mut self, fragment: &Fragment, now_ms: u64) {
        match &fragment.kind {
            FragmentKind::First {
                delivery,
                msg_id: None,
            } => {
                // Сообщение не фрагментировано — принимаем сразу,
                // если влезает в лимит.
                if fragment.data.len() > MAX_REASSEMBLED_MESSAGE_SIZE {
                    warn!(
                        len = fragment.data.len(),
                        limit = MAX_REASSEMBLED_MESSAGE_SIZE,
                        "fragment reassembly: unfragmented message too large; dropped"
                    );
                    return;
                }
                let block = TunnelMessageBlock {
                    delivery: delivery.clone(),
                    message: fragment.data.clone(),
                };
                trace!(
                    delivery = ?delivery,
                    len = block.message.len(),
                    "fragment reassembly: unfragmented message accepted"
                );
                self.ready.push_back(block);
            }

            FragmentKind::First {
                delivery,
                msg_id: Some(msg_id),
            } => {
                if self.partial.contains_key(msg_id) {
                    trace!(msg_id, "fragment reassembly: duplicate first fragment; ignored");
                    return;
                }
                if self.partial.len() >= MAX_PARTIAL_MESSAGES {
                    warn!(
                        msg_id,
                        limit = MAX_PARTIAL_MESSAGES,
                        "fragment reassembly: too many partial messages; new one dropped"
                    );
                    return;
                }
                if fragment.data.len() > MAX_REASSEMBLED_MESSAGE_SIZE {
                    warn!(
                        msg_id,
                        len = fragment.data.len(),
                        limit = MAX_REASSEMBLED_MESSAGE_SIZE,
                        "fragment reassembly: first fragment too large; dropped"
                    );
                    return;
                }
                self.partial.insert(
                    *msg_id,
                    PartialMessage {
                        delivery: delivery.clone(),
                        first: fragment.data.clone(),
                        parts: BTreeMap::new(),
                        last_num: None,
                        size: fragment.data.len(),
                        started_ms: now_ms,
                    },
                );
            }

            FragmentKind::FollowOn {
                msg_id,
                fragment_num,
                is_last,
            } => self.push_follow_on(*msg_id, *fragment_num, *is_last, &fragment.data, now_ms),
        }
    }

    /// Продолжение сообщения: дописываем фрагмент и проверяем готовность.
    fn push_follow_on(
        &mut self,
        msg_id: u32,
        fragment_num: u8,
        is_last: bool,
        data: &[u8],
        now_ms: u64,
    ) {
        if fragment_num == 0 || fragment_num > MAX_FRAGMENT_NUMBER {
            trace!(
                msg_id,
                fragment_num,
                "fragment reassembly: invalid fragment number; ignored"
            );
            return;
        }
        if !self.partial.contains_key(&msg_id) {
            trace!(msg_id, fragment_num, "fragment reassembly: orphan follow-on; ignored");
            return;
        }

        let oversize = {
            let Some(partial) = self.partial.get_mut(&msg_id) else {
                return;
            };
            if partial.parts.contains_key(&fragment_num) {
                trace!(
                    msg_id,
                    fragment_num,
                    "fragment reassembly: duplicate fragment; ignored"
                );
                return;
            }
            partial.size += data.len();
            if partial.size > MAX_REASSEMBLED_MESSAGE_SIZE {
                true
            } else {
                partial.parts.insert(fragment_num, data.to_vec());
                if is_last {
                    partial.last_num = Some(fragment_num);
                }
                false
            }
        };

        if oversize {
            warn!(
                msg_id,
                limit = MAX_REASSEMBLED_MESSAGE_SIZE,
                "fragment reassembly: reassembled message too large; dropped"
            );
            self.partial.remove(&msg_id);
            return;
        }

        self.complete_if_ready(msg_id, now_ms);
    }

    /// Если сообщение собрано целиком — отдаёт его в `ready`.
    fn complete_if_ready(&mut self, msg_id: u32, now_ms: u64) {
        let Some(complete) = self.partial.get(&msg_id).and_then(|p| {
            let last = p.last_num?;
            p.is_complete(last).then_some(last)
        }) else {
            return;
        };
        let Some(partial) = self.partial.remove(&msg_id) else {
            return;
        };
        let len = partial.size;
        let delivery = partial.delivery.clone();
        self.ready.push_back(TunnelMessageBlock {
            delivery,
            message: partial.assemble(complete),
        });
        trace!(
            msg_id,
            len,
            fragments = usize::from(complete) + 1,
            started_ms = partial.started_ms,
            elapsed_ms = now_ms.saturating_sub(partial.started_ms),
            "fragment reassembly: message assembled"
        );
    }

    /// Забирает все собранные сообщения.
    #[must_use]
    pub fn drain_ready(&mut self) -> Vec<TunnelMessageBlock> {
        self.ready.drain(..).collect()
    }

    /// Сколько сообщений ждут выдачи.
    #[must_use]
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    /// Сколько сообщений в работе.
    #[must_use]
    pub fn partial_len(&self) -> usize {
        self.partial.len()
    }

    /// Есть ли незавершённое сообщение с таким `msg_id`.
    #[must_use]
    pub fn has_partial(&self, msg_id: u32) -> bool {
        self.partial.contains_key(&msg_id)
    }

    /// Забывает незавершённое сообщение.
    ///
    /// # Returns
    ///
    /// `true`, если такое сообщение было.
    pub fn drop_partial(&mut self, msg_id: u32) -> bool {
        self.partial.remove(&msg_id).is_some()
    }

    /// Вычищает сообщения, простоявшие дольше
    /// [`PARTIAL_MESSAGE_EXPIRATION_MS`].
    ///
    /// # Returns
    ///
    /// Сколько сообщений выброшено.
    pub fn cleanup(&mut self, now_ms: u64) -> usize {
        let before = self.partial.len();
        self.partial
            .retain(|_, p| now_ms.saturating_sub(p.started_ms) <= PARTIAL_MESSAGE_EXPIRATION_MS);
        let removed = before - self.partial.len();
        if removed > 0 {
            debug!(removed, "fragment reassembly: expired partial messages dropped");
        }
        removed
    }
}
