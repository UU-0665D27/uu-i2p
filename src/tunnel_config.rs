//! `TunnelConfig` — описание цепочки хопов строящегося туннеля.
//!
//! Соответствует `TunnelHopConfig` / `TunnelConfig` из `TunnelConfig.cpp`,
//! но без связного списка с сырыми указателями: хопы лежат в `Vec`
//! в порядке построения (первый хоп — ближайший к нам для outbound и
//! gateway для inbound).
//!
//! ## Что здесь есть
//!
//! - выбор `tunnel_id` для каждого хопа (случайный, **никогда не 0**);
//! - связывание хопов: `next_ident` / `next_tunnel_id`, флаги
//!   `is_gateway` / `is_endpoint`;
//! - inbound-конфиг (последний хоп отдаёт нам) и outbound-конфиг
//!   (последний хоп отдаёт в reply-туннель);
//! - назначение `record_index` (место записи в build-сообщении).
//!
//! ## Чего здесь пока нет
//!
//! - ключей `layer_key` / `iv_key` / `reply_key`: поля есть, но
//!   заполняются криптографическим слоем при создании записи;
//! - phony hop (padding до фиксированного числа записей);
//! - `ZeroHopsTunnelConfig`.
//!
//! ## Отличия от i2pd
//!
//! Больше [`NUM_TUNNEL_BUILD_RECORDS`] хопов — ошибка (в i2pd лимит
//! проверяется выше по стеку).

use rand::RngCore;

use crate::error::{I2PError, Result};
use crate::tag::IdentHash;
use crate::tunnel_build_record::NUM_TUNNEL_BUILD_RECORDS;

/// Конфигурация одного хопа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelHopConfig {
    /// Ident роутера-хопа.
    pub ident: IdentHash,
    /// Ident следующего узла (следующий хоп, мы сами или reply-роутер).
    pub next_ident: IdentHash,
    /// Tunnel ID, на котором хоп принимает сообщения (не 0).
    pub tunnel_id: u32,
    /// Tunnel ID на следующем узле (0, пока не задан).
    pub next_tunnel_id: u32,
    /// Ключ слоя (заполняется криптослоем).
    pub layer_key: [u8; 32],
    /// IV-ключ (заполняется криптослоем).
    pub iv_key: [u8; 32],
    /// Ключ ответа (заполняется криптослоем).
    pub reply_key: [u8; 32],
    /// Хоп — gateway.
    pub is_gateway: bool,
    /// Хоп — endpoint.
    pub is_endpoint: bool,
    /// Номер записи в build-сообщении.
    pub record_index: usize,
}

/// Случайный tunnel ID; 0 заменяется на 1 — как в i2pd.
fn random_tunnel_id(rng: &mut impl RngCore) -> u32 {
    match rng.next_u32() {
        0 => 1,
        id => id,
    }
}

impl TunnelHopConfig {
    /// Новый хоп: одиночный (и gateway, и endpoint), со случайным
    /// `tunnel_id`.
    #[must_use]
    pub fn new(ident: IdentHash, rng: &mut impl RngCore) -> Self {
        Self {
            ident,
            next_ident: IdentHash::from_array([0; 32]),
            tunnel_id: random_tunnel_id(rng),
            next_tunnel_id: 0,
            layer_key: [0; 32],
            iv_key: [0; 32],
            reply_key: [0; 32],
            is_gateway: true,
            is_endpoint: true,
            record_index: 0,
        }
    }

    /// Следующий узел вне туннеля: хоп перестаёт быть endpoint, для
    /// него выбирается случайный `next_tunnel_id`.
    pub fn set_next_ident(&mut self, ident: IdentHash, rng: &mut impl RngCore) {
        self.next_ident = ident;
        self.is_endpoint = false;
        self.next_tunnel_id = random_tunnel_id(rng);
    }

    /// Reply-хоп: хоп — endpoint и отдаёт в заданный туннель.
    pub const fn set_reply_hop(&mut self, reply_tunnel_id: u32, reply_ident: IdentHash) {
        self.next_ident = reply_ident;
        self.next_tunnel_id = reply_tunnel_id;
        self.is_endpoint = true;
    }
}

/// Конфигурация туннеля: непустая цепочка хопов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    hops: Vec<TunnelHopConfig>,
}

impl TunnelConfig {
    /// Inbound: сообщения идут через `peers` к нам (`our_ident`).
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если `peers` пуст или хопов больше
    /// [`NUM_TUNNEL_BUILD_RECORDS`].
    pub fn inbound(
        peers: &[IdentHash],
        our_ident: IdentHash,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        let mut hops = Self::create_hops(peers, rng)?;
        if let Some(last) = hops.last_mut() {
            last.set_next_ident(our_ident, rng);
        }
        Ok(Self { hops })
    }

    /// Outbound: сообщения идут от нас через `peers` в reply-туннель.
    ///
    /// # Errors
    ///
    /// Как у [`TunnelConfig::inbound`].
    pub fn outbound(
        peers: &[IdentHash],
        reply_tunnel_id: u32,
        reply_ident: IdentHash,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        let mut hops = Self::create_hops(peers, rng)?;
        if let Some(first) = hops.first_mut() {
            first.is_gateway = false;
        }
        if let Some(last) = hops.last_mut() {
            last.set_reply_hop(reply_tunnel_id, reply_ident);
        }
        Ok(Self { hops })
    }

    fn create_hops(peers: &[IdentHash], rng: &mut impl RngCore) -> Result<Vec<TunnelHopConfig>> {
        if peers.is_empty() {
            return Err(I2PError::Malformed("tunnel config: no peers"));
        }
        if peers.len() > NUM_TUNNEL_BUILD_RECORDS {
            return Err(I2PError::Malformed("tunnel config: too many hops"));
        }
        let mut hops: Vec<TunnelHopConfig> = peers
            .iter()
            .map(|p| TunnelHopConfig::new(*p, rng))
            .collect();
        for i in 1..hops.len() {
            let (head, tail) = hops.split_at_mut(i);
            let prev = &mut head[i - 1];
            let cur = &mut tail[0];
            prev.next_ident = cur.ident;
            prev.next_tunnel_id = cur.tunnel_id;
            prev.is_endpoint = false;
            cur.is_gateway = false;
        }
        Ok(hops)
    }

    /// Хопы по порядку.
    #[must_use]
    pub fn hops(&self) -> &[TunnelHopConfig] {
        &self.hops
    }

    /// Хопы по порядку, изменяемые (для заполнения ключей).
    pub fn hops_mut(&mut self) -> &mut [TunnelHopConfig] {
        &mut self.hops
    }

    /// Число хопов.
    #[must_use]
    pub const fn num_hops(&self) -> usize {
        self.hops.len()
    }

    /// Первый хоп.
    #[must_use]
    pub fn first_hop(&self) -> &TunnelHopConfig {
        &self.hops[0]
    }

    /// Последний хоп.
    #[must_use]
    pub fn last_hop(&self) -> &TunnelHopConfig {
        &self.hops[self.hops.len() - 1]
    }

    /// Inbound ли туннель (первый хоп — gateway).
    #[must_use]
    pub fn is_inbound(&self) -> bool {
        self.first_hop().is_gateway
    }

    /// ID туннеля: для inbound — ID на нашей стороне, для outbound —
    /// ID первого хопа.
    #[must_use]
    pub fn tunnel_id(&self) -> u32 {
        if self.is_inbound() {
            self.last_hop().next_tunnel_id
        } else {
            self.first_hop().tunnel_id
        }
    }

    /// Tunnel ID первого хопа (`GetNextTunnelID` в i2pd).
    #[must_use]
    pub fn first_hop_tunnel_id(&self) -> u32 {
        self.first_hop().tunnel_id
    }

    /// Ident первого хопа.
    #[must_use]
    pub fn next_ident_hash(&self) -> &IdentHash {
        &self.first_hop().ident
    }

    /// Ident последнего хопа.
    #[must_use]
    pub fn last_ident_hash(&self) -> &IdentHash {
        &self.last_hop().ident
    }

    /// Идентификаторы хопов по порядку.
    #[must_use]
    pub fn peers(&self) -> Vec<IdentHash> {
        self.hops.iter().map(|h| h.ident).collect()
    }

    /// Назначает `record_index` хопам: `order[i]` — индекс записи для
    /// хопа `i`. Должна быть длины `num_hops`, значения уникальны и
    /// меньше [`NUM_TUNNEL_BUILD_RECORDS`].
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если условия нарушены; конфиг при этом
    /// не меняется.
    pub fn assign_record_indices(&mut self, order: &[usize]) -> Result<()> {
        if order.len() != self.hops.len() {
            return Err(I2PError::Malformed("record indices: wrong count"));
        }
        let mut seen = [false; NUM_TUNNEL_BUILD_RECORDS];
        for &idx in order {
            let slot = seen
                .get_mut(idx)
                .ok_or(I2PError::Malformed("record index out of range"))?;
            if *slot {
                return Err(I2PError::Malformed("duplicate record index"));
            }
            *slot = true;
        }
        for (hop, &idx) in self.hops.iter_mut().zip(order) {
            hop.record_index = idx;
        }
        Ok(())
    }
}
