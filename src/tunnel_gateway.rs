//! Буфер gateway туннеля: упаковка и фрагментация I2NP-сообщений в
//! tunnel-сообщения.
//!
//! Соответствует `TunnelGatewayBuffer` и `TunnelGateway::SendBuffer`
//! из `TunnelGateway.cpp`. Формат — в [`crate::tunnel_fragments`].
//!
//! ## Алгоритм ([`TunnelGatewayBuffer::put_message`])
//!
//! Сообщения кладутся в «текущее» tunnel-сообщение (payload до 1003
//! байт). Если сообщение целиком (delivery instructions + 2 байта
//! длины + данные) не помещается:
//!
//! 1. сначала решается, закрыть ли текущее сообщение и начать новое
//!    (эвристика i2pd: закрываем, если «хвост» последнего фрагмента
//!    не лезет в остаток, либо остаток меньше 1/5 сообщения);
//! 2. затем сообщение режется: первый фрагмент добивает текущее
//!    tunnel-сообщение, остальные (по 996 байт) идут в новых.
//!
//! Если tunnel-сообщение заполнено ровно, оно закрывается сразу.
//!
//! ## Отправка ([`TunnelGatewayBuffer::flush`])
//!
//! Закрывает текущее сообщение, шифрует каждое переданной функцией
//! (`outbound`: [`crate::TunnelLayerChain::decrypt_tunnel_data`],
//! транзитный gateway: [`crate::TunnelEncryption::encrypt_tunnel_data`])
//! и проставляет `tunnel_id` следующего хопа.
//!
//! ## Отличия от i2pd
//!
//! - ГСЧ передаётся параметром;
//! - padding генерируется заново для каждого сообщения (в i2pd —
//!   срез из заранее заполненного буфера);
//! - `onDrop`-колбэки не переносятся (нет сетевого слоя);
//! - слишком короткое (меньше I2NP-заголовка) или слишком длинное
//!   (больше `I2NP_MAX_MESSAGE_SIZE`) сообщение — ошибка, а не
//!   тихая отправка.

use rand::Rng;

use crate::endian::read_u32_be;
use crate::error::{I2PError, Result};
use crate::i2np::{I2NP_HEADER_MSGID_OFFSET, I2NP_HEADER_SIZE, I2NP_MAX_MESSAGE_SIZE};
use crate::tunnel_fragments::{
    FLAG_FOLLOW_ON, FLAG_FRAGMENTED, FLAG_LAST_FRAGMENT, FOLLOW_ON_HEADER_SIZE,
    MAX_FRAGMENT_NUMBER, TUNNEL_DATA_MAX_PAYLOAD_SIZE, TunnelMessageBlock,
    build_plain_tunnel_message,
};
use crate::tunnel_messages::TunnelDataBody;

/// Размер заголовка первого фрагмента сверх delivery instructions:
/// `msg_id(4) + size(2)`.
const FIRST_FRAGMENT_EXTRA: usize = 6;

/// Буфер gateway: накапливает tunnel-сообщения.
#[derive(Debug, Default)]
pub struct TunnelGatewayBuffer {
    completed: Vec<TunnelDataBody>,
    current: Option<Vec<u8>>,
}

impl TunnelGatewayBuffer {
    /// Пустой буфер.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            completed: Vec::new(),
            current: None,
        }
    }

    /// Число закрытых (готовых к шифрованию) tunnel-сообщений.
    #[must_use]
    pub const fn completed_len(&self) -> usize {
        self.completed.len()
    }

    /// Есть ли открытое сообщение с данными.
    #[must_use]
    pub const fn has_open_message(&self) -> bool {
        self.current.is_some()
    }

    fn remaining(&self) -> usize {
        self.current
            .as_ref()
            .map_or(0, |c| TUNNEL_DATA_MAX_PAYLOAD_SIZE - c.len())
    }

    /// Закрывает текущее tunnel-сообщение (если есть).
    ///
    /// # Errors
    ///
    /// Ошибки [`build_plain_tunnel_message`].
    pub fn complete_current(&mut self, rng: &mut impl Rng) -> Result<()> {
        if let Some(data) = self.current.take() {
            self.completed.push(build_plain_tunnel_message(&data, rng)?);
        }
        Ok(())
    }

    /// Кладёт I2NP-сообщение в буфер, при необходимости фрагментируя.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если сообщение короче I2NP-заголовка,
    /// длиннее `I2NP_MAX_MESSAGE_SIZE` или не режется на 63 фрагмента.
    /// При ошибке валидации буфер не меняется.
    pub fn put_message(&mut self, block: &TunnelMessageBlock, rng: &mut impl Rng) -> Result<()> {
        let msg = &block.message;
        if msg.len() < I2NP_HEADER_SIZE {
            return Err(I2PError::Malformed("tunnel gateway: message too short"));
        }
        if msg.len() > I2NP_MAX_MESSAGE_SIZE {
            return Err(I2PError::Malformed("tunnel gateway: message too long"));
        }
        let msg_id = read_u32_be(&msg[I2NP_HEADER_MSGID_OFFSET..]);
        let mut di = Vec::with_capacity(block.delivery.instructions_len() + FIRST_FRAGMENT_EXTRA);

        loop {
            let created = self.current.is_none();
            if created {
                self.current = Some(Vec::new());
            }
            di.clear();
            block.delivery.write_instructions(&mut di);
            let full = di.len() + msg.len() + 2; // instructions + длина + данные
            let mut remaining = self.remaining();

            if !created && full > remaining {
                let followers = full / TUNNEL_DATA_MAX_PAYLOAD_SIZE;
                let non_fit =
                    (full + followers * FOLLOW_ON_HEADER_SIZE) % TUNNEL_DATA_MAX_PAYLOAD_SIZE;
                if non_fit == 0 || non_fit > remaining || remaining < full / 5 {
                    self.complete_current(rng)?;
                    self.current = Some(Vec::new());
                    remaining = TUNNEL_DATA_MAX_PAYLOAD_SIZE;
                }
            }

            if full <= remaining {
                // целиком: первый и последний фрагмент
                let len = u16::try_from(msg.len())
                    .map_err(|_| I2PError::Malformed("tunnel gateway: message too long"))?;
                let cur = self.current.get_or_insert_with(Vec::new);
                cur.extend_from_slice(&di);
                cur.extend_from_slice(&len.to_be_bytes());
                cur.extend_from_slice(msg);
                if full == remaining {
                    self.complete_current(rng)?;
                }
                return Ok(());
            }

            if di.len() + FIRST_FRAGMENT_EXTRA <= remaining {
                return self.put_fragmented(&mut di, msg, msg_id, remaining, rng);
            }
            // delivery instructions не влезают — начинаем новое сообщение
            self.complete_current(rng)?;
        }
    }

    /// Первый фрагмент добивает текущее сообщение, остальные идут в
    /// новых. `remaining` — остаток текущего сообщения.
    fn put_fragmented(
        &mut self,
        di: &mut Vec<u8>,
        msg: &[u8],
        msg_id: u32,
        remaining: usize,
        rng: &mut impl Rng,
    ) -> Result<()> {
        let first_size = remaining - di.len() - FIRST_FRAGMENT_EXTRA;
        let follow_capacity = TUNNEL_DATA_MAX_PAYLOAD_SIZE - FOLLOW_ON_HEADER_SIZE;
        let followers = (msg.len() - first_size).div_ceil(follow_capacity);
        if followers > usize::from(MAX_FRAGMENT_NUMBER) {
            return Err(I2PError::Malformed("tunnel gateway: too many fragments"));
        }

        // первый фрагмент
        di[0] |= FLAG_FRAGMENTED;
        di.extend_from_slice(&msg_id.to_be_bytes());
        di.extend_from_slice(&u16::try_from(first_size).unwrap_or(u16::MAX).to_be_bytes());
        let cur = self.current.get_or_insert_with(Vec::new);
        cur.extend_from_slice(di);
        cur.extend_from_slice(&msg[..first_size]);
        self.complete_current(rng)?;

        // продолжения
        let mut sent = first_size;
        let mut fragment_num: u8 = 1;
        while sent < msg.len() {
            let left = msg.len() - sent;
            let is_last = left <= follow_capacity;
            let size = left.min(follow_capacity);
            let mut flag = FLAG_FOLLOW_ON | (fragment_num << 1);
            if is_last {
                flag |= FLAG_LAST_FRAGMENT;
            }
            let mut cur = Vec::with_capacity(size + FOLLOW_ON_HEADER_SIZE);
            cur.push(flag);
            cur.extend_from_slice(&msg_id.to_be_bytes());
            cur.extend_from_slice(&u16::try_from(size).unwrap_or(u16::MAX).to_be_bytes());
            cur.extend_from_slice(&msg[sent..sent + size]);
            self.current = Some(cur);
            if !is_last || self.remaining() == 0 {
                self.complete_current(rng)?;
            }
            sent += size;
            fragment_num += 1;
        }
        Ok(())
    }

    /// Закрывает текущее сообщение, шифрует все готовые функцией
    /// `encrypt` и проставляет `next_tunnel_id`. Буфер после вызова
    /// пуст.
    ///
    /// # Errors
    ///
    /// Ошибки [`build_plain_tunnel_message`] и `encrypt`.
    pub fn flush(
        &mut self,
        rng: &mut impl Rng,
        next_tunnel_id: u32,
        mut encrypt: impl FnMut(&TunnelDataBody) -> Result<TunnelDataBody>,
    ) -> Result<Vec<TunnelDataBody>> {
        self.complete_current(rng)?;
        let plain = std::mem::take(&mut self.completed);
        let mut out = Vec::with_capacity(plain.len());
        for msg in &plain {
            let mut enc = encrypt(msg)?;
            enc.tunnel_id = next_tunnel_id;
            out.push(enc);
        }
        Ok(out)
    }
}
