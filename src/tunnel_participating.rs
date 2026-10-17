//! Участие в туннелях, построенных другими роутерами.
//!
//! Соответствует `TransitTunnels` / `TransitTunnel`
//! (`TransitTunnel.cpp`), `HandleShortTransitTunnelBuildMsg` и
//! обработке `TunnelData` в i2pd. Все криптографические примитивы
//! уже были в библиотеке, но не имели вызывающей стороны: этот модуль
//! их связывает.
//!
//! ## Три роли
//!
//! Роль выводится из флагов записи `ShortTunnelBuild`:
//!
//! | флаги | роль | что делаем с `TunnelData` |
//! |-------|------|---------------------------|
//! | `is_gateway` | [`TunnelRole::InboundGateway`] | снимаем свой слой, отдаём I2NP наружу |
//! | `is_endpoint` | [`TunnelRole::OutboundEndpoint`] | снимаем свой слой, отдаём I2NP себе |
//! | ни то, ни другое | [`TunnelRole::Transit`] | снимаем свой слой и **зашифровываем обратно** |
//!
//! Ключевой момент: транзитный хоп обязан снять слой и наложить его
//! заново ([`crate::TunnelLayerChain`] этого не умеет — она только
//! расшифровывает). Перешифровка заодно перемешивает IV, поэтому
//! хоп не может сопоставить входящее сообщение с исходящим.
//!
//! ## Порядок слоёв
//!
//! Отправитель накладывает слои в порядке `k_n, k_{n-1}, ..., k_1`
//! (последний хоп — самый внутренний). Хоп `i` снимает `k_i` и
//! накладывает `k_i` заново, поэтому наши действия симметричны для
//! всех трёх ролей и сводятся к одному `decrypt_tunnel_data`.
//!
//! ## Ответ на построение
//!
//! Запрос приходит по туннелю от предыдущего хопа, ответ уходит туда
//! же. Хоп помнит `send_msg_id` из своей записи и `reply_ident` —
//! ident отправителя (его знает транспортный слой, в wire-формате
//! его нет). Наш индекс записи (`record_index`) позволяет и при
//! запросе, и при ответе сразу попасть в свою запись, не перебирая
//! все.
//!
//! ## Чего здесь нет
//!
//! - variable (длинного) построения — только short;
//! - вложенных туннелей (`TunnelBuild` внутри `TunnelData`);
//! - учёта нагрузки и приоритетов при отказе — единственная причина
//!   отказа здесь «нет места» ([`BuildRetCode::Bandwidth`]);
//! - `IBGWHandler`-логики выбора, куда отдать локально доставленный
//!   I2NP: [`TunnelDataAction::Delivered`] отдаёт собранные сообщения
//!   вызывающему.
//!
//! ## Отличия от i2pd
//!
//! - причина отказа кодируется конкретным кодом из спецификации, а не
//!   всегда `Bandwidth`;
//! - время приходит параметром `now_ms`.

use std::collections::HashMap;

use tracing::{debug, trace};

use crate::crypto::I2PX25519Keys;
use crate::error::{I2PError, Result};
use crate::i2np::{I2npHeader, I2npMessageType};
use crate::i2np_message::I2npMessage;
use crate::short_tunnel_build::ShortTunnelBuildBody;
use crate::tag::IdentHash;
use crate::tunnel_build_crypto::{
    RecordKeys, apply_reply_layer, decrypt_reply_record, decrypt_short_request,
    encrypt_reply_records,
};
use crate::tunnel_build_record::{
    BuildOptions, BuildRetCode, OPTION_AVAILABLE_BANDWIDTH, ShortBuildRequestRecord,
    ShortBuildResponseRecord,
};
use crate::tunnel_fragments::TunnelMessageBlock;
use crate::tunnel_layer::{TunnelDecryption, TunnelEncryption};
use crate::tunnel_messages::TunnelDataBody;
use crate::tunnel_reassembly::FragmentReassembler;

/// Код ответа: у не-endpoint хопа не задан `next_tunnel`
/// (`eTunnelBuildRetCodeNoNextTunnelIDreq`).
pub const BUILD_RET_NO_NEXT_TUNNEL_IDREQ: u8 = 21;
/// Код ответа: `receive_tunnel` равен 0
/// (`eTunnelBuildRetCodeNoTunnelIDreq`).
pub const BUILD_RET_NO_TUNNEL_IDREQ: u8 = 23;
/// Код ответа: `receive_tunnel` уже занят (`eTunnelBuildRetCodeTunnelIDexists`).
pub const BUILD_RET_TUNNEL_ID_EXISTS: u8 = 25;
/// Код ответа: запрошенный срок уже истёк (`eTunnelBuildRetCodeExpired`).
pub const BUILD_RET_EXPIRED: u8 = 26;

/// Потолок туннелей, в которых мы участвуем (как `MAX_TRANSIT_TUNNELS`).
pub const MAX_PARTICIPATING_TUNNELS: usize = 2500;

/// Полоса, которую мы рапортуем в `options` ответа (КБ/с).
pub const DEFAULT_AVAILABLE_BANDWIDTH_KB: u32 = 1024;

/// Роль, которую мы играем в чужом туннеле.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelRole {
    /// Транзитный хоп: не gateway и не endpoint.
    Transit,
    /// `IBGW` — первый хоп, вход из сети.
    InboundGateway,
    /// `OBEP` — последний хоп, доставка к нам.
    OutboundEndpoint,
}

impl TunnelRole {
    /// Роль по флагам записи.
    ///
    /// Оба флага сразу (`is_gateway && is_endpoint`) — вырожденный
    /// туннель в один хоп, который создатель строит локально и не
    /// отправляет нам; такой случай сводится к
    /// [`TunnelRole::Transit`] и отсекается проверкой `next_tunnel`.
    #[must_use]
    pub const fn from_flags(is_gateway: bool, is_endpoint: bool) -> Self {
        if is_gateway && !is_endpoint {
            Self::InboundGateway
        } else if is_endpoint && !is_gateway {
            Self::OutboundEndpoint
        } else {
            Self::Transit
        }
    }

    /// Надо ли перешифровывать сообщение обратно своим слоем.
    #[must_use]
    pub const fn re_encrypts(&self) -> bool {
        matches!(self, Self::Transit)
    }
}

/// Что делать с принятым `TunnelData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelDataAction {
    /// Транзитный хоп: переслать роутеру `ident`.
    Forward {
        /// Кому пересылать.
        ident: IdentHash,
        /// Готовое I2NP-сообщение с `TunnelData`.
        message: I2npMessage,
    },
    /// Gateway/endpoint: сообщения собраны и адресованы нам.
    Delivered(Vec<TunnelMessageBlock>),
    /// Фрагменты ждут продолжения.
    Pending,
}

/// Результат [`TunnelParticipation::handle_build_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildHandling {
    /// Записи для нас в сообщении нет — его нужно переслать как есть.
    NotOurs,
    /// Туннель принят, ответ зашифрован на месте.
    Accepted {
        /// Тело ответа.
        reply: ShortTunnelBuildBody,
        /// `msg_id`, под которым уходит ответ (из нашей записи).
        send_msg_id: u32,
        /// Tunnel ID, на котором мы принимаем.
        receive_tunnel: u32,
        /// Наша роль в этом туннеле.
        role: TunnelRole,
    },
    /// Отказ, ответ тоже зашифрован на месте.
    Rejected {
        /// Тело ответа.
        reply: ShortTunnelBuildBody,
        /// `msg_id`, под которым уходит ответ.
        send_msg_id: u32,
        /// Причина отказа.
        code: BuildRetCode,
    },
}

/// Результат [`TunnelParticipation::handle_build_reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyHandling {
    /// Ответ не наш.
    NotOurs,
    /// Мы — последний хоп: ответ наш, запись расшифрована.
    Delivered {
        /// Tunnel ID, на котором мы работаем.
        receive_tunnel: u32,
        /// Содержимое ответа.
        response: ShortBuildResponseRecord,
    },
    /// Мы — промежуточный хоп: ответ переслан создателю.
    Forward {
        /// Кому пересылать (`reply_ident`).
        ident: IdentHash,
        /// Готовое I2NP-сообщение с `ShortTunnelBuildReply`.
        message: I2npMessage,
    },
}

/// Один туннель, в котором мы участвуем.
#[derive(Debug)]
pub struct ParticipatingTunnel {
    receive_tunnel: u32,
    next_tunnel: u32,
    next_ident: IdentHash,
    record_index: usize,
    reply_ident: IdentHash,
    send_msg_id: u32,
    role: TunnelRole,
    created_ms: u64,
    expires_ms: u64,
    keys: RecordKeys,
    decryption: TunnelDecryption,
    encryption: TunnelEncryption,
    reassembler: FragmentReassembler,
}

impl ParticipatingTunnel {
    /// Собирает туннель из расшифрованной записи и её ключей.
    fn new(
        request: &ShortBuildRequestRecord,
        keys: RecordKeys,
        record_index: usize,
        reply_ident: IdentHash,
        role: TunnelRole,
        now_ms: u64,
    ) -> Self {
        Self {
            receive_tunnel: request.receive_tunnel,
            next_tunnel: request.next_tunnel,
            next_ident: request.next_ident,
            record_index,
            reply_ident,
            send_msg_id: request.send_msg_id,
            role,
            created_ms: now_ms,
            expires_ms: tunnel_expiry_ms(request),
            decryption: TunnelDecryption::new(&keys.layer_key, &keys.iv_key),
            encryption: TunnelEncryption::new(&keys.layer_key, &keys.iv_key),
            keys,
            reassembler: FragmentReassembler::new(),
        }
    }

    /// Tunnel ID, на котором мы принимаем сообщения.
    #[must_use]
    pub const fn receive_tunnel(&self) -> u32 {
        self.receive_tunnel
    }

    /// Tunnel ID следующего хопа (0, если мы endpoint).
    #[must_use]
    pub const fn next_tunnel(&self) -> u32 {
        self.next_tunnel
    }

    /// Ident следующего роутера.
    #[must_use]
    pub const fn next_ident(&self) -> IdentHash {
        self.next_ident
    }

    /// Ident создателя туннеля (кому уходит ответ на построение).
    #[must_use]
    pub const fn reply_ident(&self) -> IdentHash {
        self.reply_ident
    }

    /// `msg_id` нашего ответа на построение.
    #[must_use]
    pub const fn send_msg_id(&self) -> u32 {
        self.send_msg_id
    }

    /// Индекс нашей записи в build-сообщении.
    #[must_use]
    pub const fn record_index(&self) -> usize {
        self.record_index
    }

    /// Роль в этом туннеле.
    #[must_use]
    pub const fn role(&self) -> TunnelRole {
        self.role
    }

    /// Когда истекает туннель (мс).
    #[must_use]
    pub const fn expires_ms(&self) -> u64 {
        self.expires_ms
    }

    /// Момент создания туннеля (мс).
    #[must_use]
    pub const fn created_ms(&self) -> u64 {
        self.created_ms
    }

    /// Истёк ли туннель.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_ms
    }

    /// Сколько фрагментов ждут продолжения.
    #[must_use]
    pub fn partial_messages(&self) -> usize {
        self.reassembler.partial_len()
    }

    /// Обрабатывает `TunnelData` на нашем receive tunnel.
    ///
    /// Для всех ролей сначала снимается наш слой. Дальше:
    /// транзитный хоп накладывает слой заново и подставляет
    /// `next_tunnel`, gateway и endpoint собирают фрагменты в
    /// I2NP-сообщения.
    ///
    /// # Errors
    ///
    /// Ошибки AES-слоя и разбора tunnel-сообщения
    /// (контрольная сумма, нулевой разделитель).
    pub fn handle_tunnel_data(
        &mut self,
        msg: &TunnelDataBody,
        now_ms: u64,
    ) -> Result<TunnelDataAction> {
        if msg.tunnel_id != self.receive_tunnel {
            return Err(I2PError::Malformed("tunnel data: wrong receive tunnel"));
        }
        let plain = self.decryption.decrypt_tunnel_data(msg)?;
        if self.role.re_encrypts() {
            let mut out = self.encryption.encrypt_tunnel_data(&plain)?;
            out.tunnel_id = self.next_tunnel;
            let message = I2npMessage::new(I2npMessageType::TunnelData, out.to_buffer());
            trace!(
                receive_tunnel = self.receive_tunnel,
                next_tunnel = self.next_tunnel,
                next_ident = %self.next_ident.to_base64(),
                "transit tunnel: message forwarded"
            );
            Ok(TunnelDataAction::Forward {
                ident: self.next_ident,
                message,
            })
        } else {
            let blocks = self.reassembler.accept(&plain, now_ms)?;
            if blocks.is_empty() {
                trace!(
                    receive_tunnel = self.receive_tunnel,
                    partial = self.reassembler.partial_len(),
                    "endpoint tunnel: fragments pending"
                );
                Ok(TunnelDataAction::Pending)
            } else {
                debug!(
                    receive_tunnel = self.receive_tunnel,
                    role = ?self.role,
                    messages = blocks.len(),
                    "endpoint tunnel: messages assembled"
                );
                Ok(TunnelDataAction::Delivered(blocks))
            }
        }
    }

    /// Читает нашу запись из тела ответа и возвращает её в
    /// «слоёном» виде, чтобы предыдущий хоп её снял.
    fn read_reply(&self, body: &mut ShortTunnelBuildBody) -> Result<ShortBuildResponseRecord> {
        let record = body
            .records
            .get_mut(self.record_index)
            .ok_or(I2PError::Malformed(
                "tunnel build reply: record index out of range",
            ))?;
        let response = decrypt_reply_record(&self.keys, self.record_index, record)?;
        apply_reply_layer(&self.keys.reply_key, self.record_index, record)?;
        Ok(response)
    }
}

/// Абсолютный момент истечения туннеля из полей записи.
///
/// `request_time_minutes` — это время запроса в минутах since epoch,
/// поэтому складываем с `request_expiration_secs` без привязки к
/// локальным часам.
fn tunnel_expiry_ms(request: &ShortBuildRequestRecord) -> u64 {
    u64::from(request.request_time_minutes) * 60_000
        + u64::from(request.request_expiration_secs) * 1_000
}

/// Завернулывает тело ответа в I2NP-сообщение с заданным `msg_id`.
fn reply_message(msg_id: u32, body: &ShortTunnelBuildBody) -> Result<I2npMessage> {
    let payload = body.to_buffer()?;
    let size = u16::try_from(payload.len())
        .map_err(|_| I2PError::Malformed("tunnel build reply: payload too large"))?;
    let header = I2npHeader::new(I2npMessageType::ShortTunnelBuildReply, msg_id, size);
    Ok(I2npMessage::with_header(header, payload))
}

/// Реестр туннелей, в которых мы участвуем.
///
/// Соответствует `TransitTunnels` в i2pd: хранит туннели по
/// `receive_tunnel` и, дополнительно, индекс по `send_msg_id`
/// (`m_BuildRecordIdx` + `m_SendMsgID` в `TunnelInfo`), чтобы ответ
/// находился за `O(1)`.
pub struct TunnelParticipation {
    our_ident: IdentHash,
    static_keys: I2PX25519Keys,
    tunnels: HashMap<u32, ParticipatingTunnel>,
    by_msg_id: HashMap<u32, u32>,
    available_bandwidth_kb: u32,
    max_tunnels: usize,
}

impl TunnelParticipation {
    /// Новый реестр.
    ///
    /// `static_keys` — наш X25519-ключ шифрования роутера (тот же, что
    /// в NTCP2). [`I2PX25519Keys`] не клонируется, поэтому если он
    /// уже лежит в конфиге, пересоздайте его из
    /// `private_key()` / `public_key()`.
    #[must_use]
    pub fn new(our_ident: IdentHash, static_keys: I2PX25519Keys) -> Self {
        Self {
            our_ident,
            static_keys,
            tunnels: HashMap::new(),
            by_msg_id: HashMap::new(),
            available_bandwidth_kb: DEFAULT_AVAILABLE_BANDWIDTH_KB,
            max_tunnels: MAX_PARTICIPATING_TUNNELS,
        }
    }

    /// Задаёт полосу, рапортуемую в ответе на построение.
    pub const fn set_available_bandwidth_kb(&mut self, kb: u32) {
        self.available_bandwidth_kb = kb;
    }

    /// Задаёт потолок одновременных туннелей.
    pub const fn set_max_tunnels(&mut self, max: usize) {
        self.max_tunnels = max;
    }

    /// Сколько туннелей в реестре.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    /// Пуст ли реестр.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }

    /// Туннель по `receive_tunnel`.
    #[must_use]
    pub fn tunnel(&self, receive_tunnel: u32) -> Option<&ParticipatingTunnel> {
        self.tunnels.get(&receive_tunnel)
    }

    /// Обрабатывает входящее `ShortTunnelBuild`.
    ///
    /// `from` — ident отправителя: в wire-формате его нет, но он нужен
    /// для возврата ответа. Если записи для нас нет, тело не
    /// изменяется и возвращается [`BuildHandling::NotOurs`] — вызывающий
    /// пересылает сообщение дальше.
    ///
    /// Ответ (принять или отказать) всегда зашифрован на месте, даже
    /// при отказе: создатель должен узнать причину.
    ///
    /// # Errors
    ///
    /// Ошибки [`decrypt_short_request`] (запись адресована нам, но не
    /// расшифровывается — это атака или битое сообщение) и
    /// [`encrypt_reply_records`].
    pub fn handle_build_request(
        &mut self,
        from: &IdentHash,
        body: &mut ShortTunnelBuildBody,
        now_ms: u64,
    ) -> Result<BuildHandling> {
        let Some(index) = body.find_record_for(&self.our_ident).map(|(i, _)| i) else {
            trace!("participation: no record addressed to us; message untouched");
            return Ok(BuildHandling::NotOurs);
        };

        let (request, keys) = decrypt_short_request(&body.records[index], &self.static_keys)?;
        let send_msg_id = request.send_msg_id;
        let role = TunnelRole::from_flags(request.is_gateway, request.is_endpoint);
        let reject = self.check_admission(&request, role, now_ms);

        let response = match reject {
            None => {
                let mut options = BuildOptions::new();
                options.insert(
                    OPTION_AVAILABLE_BANDWIDTH,
                    &self.available_bandwidth_kb.to_string(),
                );
                ShortBuildResponseRecord {
                    options,
                    ret: BuildRetCode::Accept,
                }
            }
            Some(code) => ShortBuildResponseRecord {
                options: BuildOptions::new(),
                ret: code,
            },
        };
        encrypt_reply_records(&keys, index, &response, &mut body.records)?;

        if let Some(code) = reject {
            debug!(
                receive_tunnel = request.receive_tunnel,
                ?code,
                "participation: build request rejected"
            );
            return Ok(BuildHandling::Rejected {
                reply: body.clone(),
                send_msg_id,
                code,
            });
        }

        let receive_tunnel = request.receive_tunnel;
        let tunnel = ParticipatingTunnel::new(&request, keys, index, *from, role, now_ms);
        self.tunnels.insert(receive_tunnel, tunnel);
        self.by_msg_id.insert(send_msg_id, receive_tunnel);
        log_accepted(role, receive_tunnel, request.next_tunnel);
        Ok(BuildHandling::Accepted {
            reply: body.clone(),
            send_msg_id,
            receive_tunnel,
            role,
        })
    }

    /// Проверки перед принятием туннеля.
    fn check_admission(
        &self,
        request: &ShortBuildRequestRecord,
        role: TunnelRole,
        now_ms: u64,
    ) -> Option<BuildRetCode> {
        if request.receive_tunnel == 0 {
            return Some(BuildRetCode::Other(BUILD_RET_NO_TUNNEL_IDREQ));
        }
        // У endpoint'а `next_tunnel` может быть 0 (сообщение уходит
        // создателю напрямую); у всех остальных — обязан быть задан.
        // Заодно отсекается вырожденный «gateway + endpoint»: такой
        // туннель сводится к транзитной роли, а `next_tunnel` там
        // обязателен.
        if role != TunnelRole::OutboundEndpoint && request.next_tunnel == 0 {
            return Some(BuildRetCode::Other(BUILD_RET_NO_NEXT_TUNNEL_IDREQ));
        }
        if tunnel_expiry_ms(request) <= now_ms {
            return Some(BuildRetCode::Other(BUILD_RET_EXPIRED));
        }
        if self.tunnels.contains_key(&request.receive_tunnel) {
            return Some(BuildRetCode::Other(BUILD_RET_TUNNEL_ID_EXISTS));
        }
        if self.tunnels.len() >= self.max_tunnels {
            return Some(BuildRetCode::Bandwidth);
        }
        None
    }

    /// Обрабатывает `TunnelData`: находит туннель по `tunnel_id` и
    /// прогоняет через него сообщение.
    ///
    /// # Errors
    ///
    /// См. [`ParticipatingTunnel::handle_tunnel_data`].
    pub fn handle_tunnel_data(
        &mut self,
        msg: &TunnelDataBody,
        now_ms: u64,
    ) -> Result<Option<TunnelDataAction>> {
        let Some(tunnel) = self.tunnels.get_mut(&msg.tunnel_id) else {
            trace!(
                tunnel_id = msg.tunnel_id,
                known = self.tunnels.len(),
                "participation: TunnelData for unknown tunnel; dropped"
            );
            return Ok(None);
        };
        tunnel.handle_tunnel_data(msg, now_ms).map(Some)
    }

    /// Обрабатывает `ShortTunnelBuildReply`.
    ///
    /// `from` — ident отправителя ответа. Если это мы сами, значит мы
    /// были последним хопом и ответ наш; иначе ответ пересылается
    /// создателю туннеля.
    ///
    /// # Errors
    ///
    /// Ошибки [`ShortBuildResponseRecord::from_plaintext`] и
    /// [`apply_reply_layer`].
    pub fn handle_build_reply(
        &mut self,
        from: &IdentHash,
        body: &mut ShortTunnelBuildBody,
        msg_id: u32,
    ) -> Result<ReplyHandling> {
        let Some(receive_tunnel) = self.by_msg_id.get(&msg_id).copied() else {
            trace!(msg_id, "participation: build reply is not ours");
            return Ok(ReplyHandling::NotOurs);
        };
        let Some(tunnel) = self.tunnels.get(&receive_tunnel) else {
            // by_msg_id мог остаться от вычищенного туннеля.
            self.by_msg_id.remove(&msg_id);
            return Ok(ReplyHandling::NotOurs);
        };
        let response = tunnel.read_reply(body)?;

        if from == &self.our_ident {
            debug!(
                receive_tunnel,
                ret = ?response.ret,
                "participation: build reply reached the last hop"
            );
            return Ok(ReplyHandling::Delivered {
                receive_tunnel,
                response,
            });
        }

        let ident = tunnel.reply_ident();
        let message = reply_message(msg_id, body)?;
        trace!(
            receive_tunnel,
            reply_ident = %ident.to_base64(),
            "participation: build reply forwarded to creator"
        );
        Ok(ReplyHandling::Forward { ident, message })
    }

    /// Вычищает истёкшие туннели.
    ///
    /// # Returns
    ///
    /// `receive_tunnel` ID удалённых туннелей.
    pub fn cleanup(&mut self, now_ms: u64) -> Vec<u32> {
        let expired: Vec<u32> = self
            .tunnels
            .iter()
            .filter(|(_, t)| t.is_expired(now_ms))
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return Vec::new();
        }
        for id in &expired {
            if let Some(tunnel) = self.tunnels.remove(id) {
                self.by_msg_id.remove(&tunnel.send_msg_id);
            }
        }
        debug!(
            removed = expired.len(),
            live = self.tunnels.len(),
            "participation: expired tunnels dropped"
        );
        expired
    }
}

/// Логирует принятый туннель.
fn log_accepted(role: TunnelRole, receive_tunnel: u32, next_tunnel: u32) {
    debug!(
        role = ?role,
        receive_tunnel,
        next_tunnel,
        "participation: tunnel accepted"
    );
}
