//! `RouterContext` — состояние одного роутера в сети I2P.
//!
//! Соответствует `i2p::RouterContext` в i2pd, но содержит только то,
//! что уже реализовано в библиотеке:
//!
//! - [`RouterConfig`] — статическая конфигурация (ключи, адреса, caps);
//! - `own_ri` — собственный `RouterInfo`, подписанный Ed25519;
//! - [`NetDb`] — хранилище чужих `RouterInfo`;
//! - [`EciesGarlicDestination`] — сессии ECIES-X25519-AEAD-Ratchet
//!   (garlic);
//! - диспетчер I2NP-сообщений `DatabaseStore` / `DatabaseLookup` /
//!   `DatabaseSearchReply` (см. [`Self::handle_database_store`] и др.).
//!
//! ## Что НЕ реализовано (отдельные шаги)
//!
//! - **Пул NTCP2-сессий** (`connect_to`, `send_to`) — шаг 3a-4;
//! - **Accept-loop** на несколько listeners — шаг 3a-5;
//! - **Туннели** (`TunnelData`, `TunnelGateway`, `ShortTunnelBuild`) —
//!   шаг 3b;
//! - **`LeaseSet`'ы destination'ов** (`DatabaseStore` типа `LeaseSet`) —
//!   шаг 3c; сейчас такие сообщения просто отбрасываются;
//! - **Floodfill-логика** — мы отвечаем только на запросы про
//!   собственный RI; логику `GetClosestFloodfills` для сети не
//!   реализуем, пока не появится реальная сеть и floodfill-роутеры.
//!
//! ## Синхронность
//!
//! `RouterContext` **не** async и не привязан к tokio runtime. Это
//! позволяет тестировать его в обычных `#[test]`. Асинхронные операции
//! (сетевой ввод-вывод, accept-loop) живут в отдельном слое (3a-4/3a-5)
//! и работают с `RouterContext` как с общим состоянием.

use crate::{
    EciesDelivery, EciesGarlicClove, IdentHash,
    config::RouterConfig,
    crypto::{I2PX25519Keys, NoiseSymmetricState, init_noise_n_state},
    database_lookup::{DatabaseLookup, LookupType},
    database_search_reply::DatabaseSearchReply,
    database_store::{DatabaseStore, StoreType},
    delivery_status::DeliveryStatus,
    ecies_destination::EciesGarlicDestination,
    error::{I2PError, Result},
    garlic_block::{GarlicBlock, parse_blocks},
    garlic_body::GarlicBody,
    i2np::I2npMessageType,
    i2np_message::{I2npBody, I2npMessage},
    netdb::NetDb,
    netdb_requests::{NetDbRequests, SendAction},
    router_info::FullRouterInfo,
};
use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, info, trace, warn};

/// Результат [`RouterContext::handle_database_store`].
///
/// Позволяет caller'у различать «RI был новым / обновлён» и «RI уже
/// есть более свежий», а также «это не RI» (`LeaseSet`, `EncryptedLeaseSet`
/// — обрабатываются на уровне destination, не здесь).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreHandling {
    /// RI был добавлен в netDb (не было раньше).
    Inserted(IdentHash),
    /// RI был обновлён (timestamp новее, чем в netDb).
    Updated(IdentHash),
    /// RI уже был, и сохранённый timestamp не меньше нового.
    Stale(IdentHash),
    /// Не `RouterInfo` — `store_type` другой. Caller решает,
    /// обрабатывать ли (`LeaseSet` — на уровне destination).
    NotRouterInfo(StoreType),
}
/// Что caller должен сделать после успешного [`RouterContext::handle_garlic`].
///
/// Сейчас это только ответ на garlic-NS (Bob → Alice): мы получили
/// `New Session`, `EciesGarlicDestination` уже собрал NSR, надо
/// отправить его обратно по тому же каналу, откуда пришёл
/// исходный garlic.
///
/// `GarlicReply::message` — полностью собранный I2NP-`Garlic`,
/// включая `GarlicBody`-обёртку. Caller просто делает
/// `session.send_i2np(&reply.message).await?`; выбирать транспорт
/// и оборачивать байты — не его забота.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarlicReply {
    /// Готовое I2NP-сообщение типа `Garlic`, уже с `GarlicBody`-обёрткой.
    ///
    /// Обычно это NSR (Bob отвечает на NS от Alice). Может быть и
    /// пустой ответ, если [`EciesGarlicDestination`] решил
    /// что-то послать инициативно.
    pub message: I2npMessage,
}
/// Состояние роутера.
///
/// Инварианты:
///
/// - `own_ri.ident_hash() == config.keys().public().ident_hash()`;
/// - `ecies.local_static_public() == config.keys().public().encryption_public_key()`;
/// - `own_ri` в `netdb` **не** кладётся — он живёт отдельно.
pub struct RouterContext {
    config: RouterConfig,
    own_ri: FullRouterInfo,
    netdb: NetDb,
    ecies: EciesGarlicDestination,
    netdb_requests: NetDbRequests,
}

impl RouterContext {
    // --- Garlic ----------------------------------------------------------

    /// Обрабатывает входящее I2NP-сообщение типа `Garlic` (type=11).
    ///
    /// `i2np_payload` — это байты после 16-байтового I2NP-заголовка,
    /// то есть то, что возвращает [`I2npMessage::payload`] для
    /// сообщения типа [`I2npMessageType::Garlic`]. Внутри —
    /// 4-байтовый BE `length` и зашифрованный garlic payload.
    ///
    /// ## Что делает
    ///
    /// 1. Разбирает [`GarlicBody`] — читает 4-байтовый префикс
    ///    длины и берёт payload.
    /// 2. Отдаёт payload в [`EciesGarlicDestination::handle_message`]:
    ///    тот находит сессию по session-tag (или создаёт новую,
    ///    если это NS от Alice) и расшифровывает garlic-blocks.
    /// 3. Для каждого полученного [`GarlicClove`] вызывает
    ///    [`Self::process_clove`] — тот в зависимости от `delivery`
    ///    либо обрабатывает I2NP у себя (Local), либо игнорирует
    ///    (Destination/Tunnel/Router — пока не реализованы).
    /// 4. Если сессия требует ответа (`handle_message` вернул
    ///    `needs_reply = true`, это означает, что Bob только что
    ///    обработал NS от Alice), собирает NSR через
    ///    [`EciesGarlicDestination::send_blocks`] с пустым списком
    ///    cloves и возвращает [`GarlicReply`] с готовым wire.
    ///
    /// Caller обязан отправить [`GarlicReply::wire`] обратно тому же
    /// peer'у **в том же соединении**, откуда пришёл исходный garlic:
    /// [`EciesGarlicDestination`] не хранит адреса, только ключ сессии.
    ///
    /// ## Что НЕ делает
    ///
    /// - не отправляет `DeliveryStatus` на входящие `DatabaseStore`
    ///   внутри garlic (в i2pd это делает `LocalDestination`, у нас
    ///   `RouterContext` — только netdb-уровень);
    /// - не обрабатывает NS от **роутеров** (это отдельная сессия
    ///   `RouterIncomingRatchetSession` в i2pd, у нас пока не нужна);
    /// - не учитывает `HandleResult::terminated` — сессия уже
    ///   удалена из пула `EciesGarlicDestination`, возвращать
    ///   нечего.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — `i2np_payload` короче 4 байт
    ///   (не помещается length-префикс) или объявленная длина
    ///   payload'а больше доступного буфера;
    /// - ошибки [`EciesGarlicDestination::handle_message`] и
    ///   [`EciesGarlicDestination::send_blocks`] — битый session-tag,
    ///   провал AEAD-аутентификации, и т.п.
    pub fn handle_garlic(&mut self, i2np_payload: &[u8]) -> Result<Option<GarlicReply>> {
        trace!(payload_len = i2np_payload.len(), "handle_garlic: enter");

        // 1. Разбор внешнего конверта (4-байтовый length + payload).
        let body = GarlicBody::from_buffer(i2np_payload)?;
        debug!(
            garlic_payload_len = body.payload_len(),
            "handle_garlic: parsed GarlicBody"
        );

        // 2. Расшифровка и разбор cloves на уровне destination.
        let result = self.ecies.handle_message(&body.payload)?;
        debug!(
            remote_static = %hex8(&result.remote_static),
            num_blocks = result.blocks.len(),
            needs_reply = result.needs_reply,
            terminated = result.terminated,
            "handle_garlic: EciesGarlicDestination handled message"
        );

        // 3. Обработка каждого clove.
        for clove in result.blocks {
            if let Err(e) = self.process_clove(&clove) {
                warn!(
                    error = %e,
                    "handle_garlic: process_clove failed; continuing"
                );
            }
        }

        // 3a. Подтверждения (`Ack`-блоки) наших сообщений этой сессии.
        //     В i2pd на них завязана доставка `LeaseSet`
        //     (`GarlicRoutingSession::MessageConfirmed`); у нас пока
        //     только видимость — сам `LeaseSet` в garlic не уходит.
        let confirmed = self.ecies.take_confirmed_msg_ids(&result.remote_static);
        if !confirmed.is_empty() {
            debug!(
                remote_static = %hex8(&result.remote_static),
                confirmed = ?confirmed,
                "handle_garlic: peer confirmed our messages"
            );
        }

        // 4. Если Bob получил NS и должен ответить NSR — собираем
        //    пустой ответ, оборачиваем его в GarlicBody + I2npMessage
        //    и возвращаем наружу. Caller отправит как обычное I2NP.
        if result.needs_reply {
            let ecies_wire = self
                .ecies
                .send_blocks(result.remote_static, now_ms(), &[])?;
            let i2np_payload = GarlicBody::new(ecies_wire).to_buffer()?;
            let message = I2npMessage::new(I2npMessageType::Garlic, i2np_payload);
            info!(
                to = %hex8(&result.remote_static),
                i2np_len = message.total_len(),
                "handle_garlic: NSR I2NP message prepared"
            );
            Ok(Some(GarlicReply { message }))
        } else {
            Ok(None)
        }
    }

    /// Разбирает **роутерный** garlic: одноразовый `Noise_N`
    /// (`i2pd::garlic::WrapECIESX25519MessageForRouter`) на наш
    /// identity-ключ.
    ///
    /// ## Зачем отдельно от [`Self::handle_garlic`]
    ///
    /// У i2pd два разных способа доставить роутеру garlic:
    ///
    /// - **destination-сессия** ([`EciesGarlicDestination`]): session-tag
    ///   в начале, NS/NSR, ratchet — это [`Self::handle_garlic`];
    /// - **роутерный `Noise_N`** (`Garlic.cpp:752`,
    ///   `WrapECIESX25519MessageForRouter`): `aepk(32) || AEAD(blocks)`,
    ///   зашифровано на статический ключ получателя, без состояния и
    ///   без тега. Так i2pd посылает `DatabaseLookup` флудфиллу
    ///   (`NetDbRequests.cpp:304`), публикует свой RI
    ///   (`RouterContext.cpp:1541`) и `LeaseSet` (`Destination.cpp:711`).
    ///
    /// В i2pd обе ветки сводит `RouterContext::PostGarlicMessage`:
    /// сначала теги (`HandleECIESx25519TagMessage`), затем
    /// `Noise_N`-расшифровка. У нас ветки разделены, потому что вторая
    /// возвращает внутренние I2NP-сообщения наружу: ответить на
    /// `DatabaseLookup` можно только зная транспорт, а транспорт знает
    /// слой [`crate::router::Router`].
    ///
    /// ## Что возвращает
    ///
    /// I2NP-сообщения из cloves с delivery `Local` — **необработанными**
    /// (как i2pd `HandleCloveI2NPMessage`: он лишь пересобирает
    /// `I2NPMessage` и отдаёт глобальному диспетчеру).
    ///
    /// Если payload не расшифровывается (это не наш роутерный garlic,
    /// например чужая destination-сессия) — возвращается пустой список:
    /// это не ошибка, а «не нам».
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] — payload не является `GarlicBody`;
    /// ошибки разбора garlic-blocks ([`parse_blocks`]).
    pub fn handle_router_garlic(&self, i2np_payload: &[u8]) -> Result<Vec<I2npMessage>> {
        let body = GarlicBody::from_buffer(i2np_payload)?;
        let Some(plain) = self.unwrap_router_garlic(&body.payload) else {
            trace!("handle_router_garlic: не Noise_N на наш ключ");
            return Ok(Vec::new());
        };

        let mut messages = Vec::new();
        for block in parse_blocks(&plain)? {
            let GarlicBlock::EciesGarlicClove(clove) = block else {
                continue;
            };
            match clove.delivery {
                EciesDelivery::Local => messages.push(clove.to_i2np_message()),
                ref other => debug!(
                    msg_type = %clove.message_type,
                    delivery = ?other,
                    "handle_router_garlic: не Local; пропускаем"
                ),
            }
        }
        debug!(count = messages.len(), "handle_router_garlic: разобран");
        Ok(messages)
    }

    /// Одноразовая `Noise_N`-расшифровка роутерного garlic.
    ///
    /// `None` — шифртекст не наш (AEAD не сходится). У i2pd это
    /// `m_ECIESSession->HandleNextMessage` на свежей сессии: результат
    /// нигде не сохраняется, ключи одноразовые.
    fn unwrap_router_garlic(&self, wire: &[u8]) -> Option<Vec<u8>> {
        /// `aepk(32)` + минимум 16 байт тега Poly1305.
        const MIN_LEN: usize = 32 + 16;
        if wire.len() < MIN_LEN {
            debug!(len = wire.len(), "unwrap_router_garlic: слишком коротко");
            return None;
        }
        let keys = Self::ecies_static(&self.config).ok()?;
        let mut aepk = [0u8; 32];
        aepk.copy_from_slice(&wire[..32]);

        // Первый `new` — заглушка: `init_noise_n_state` целиком
        // перезаписывает состояние (так же, как в `tunnel_build_crypto`).
        let mut noise = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], keys.public_key());
        init_noise_n_state(&mut noise, keys.public_key());
        noise.mix_hash(&aepk);
        let shared = keys.agree(&aepk)?;
        noise.mix_key(&shared);

        let mut plain = vec![0u8; wire.len() - MIN_LEN];
        let len = noise.decrypt(&wire[32..], &mut plain).ok()?;
        plain.truncate(len);
        Some(plain)
    }

    /// Диспетчер одного [`EciesGarlicClove`] по его `delivery`.
    ///
    /// Соответствует части `GarlicDestination::HandleECIESx25519GarlicClove`
    /// в i2pd — switch по `deliveryType`. Обрабатываются только
    /// cloves, адресованные **нам** (`Local`). Остальные типы
    /// возвращаются как `Ok(())` с debug-логом: они либо требуют
    /// туннельного слоя (`Tunnel`), либо это не наша цель
    /// (`Destination`/`Router`).
    ///
    /// # Errors
    ///
    /// См. [`Self::process_local_clove`]. Ошибки от `Destination`/
    /// `Tunnel`/`Router` веток не возвращаются — они не реализованы,
    /// но и не считаются ошибкой.
    fn process_clove(&mut self, clove: &EciesGarlicClove) -> Result<()> {
        trace!(
            msg_type = %clove.message_type,
            msg_id = clove.message_id,
            "process_clove: enter"
        );

        match &clove.delivery {
            EciesDelivery::Local => self.process_local_clove(clove),
            EciesDelivery::Destination(ident) => {
                debug!(
                    dest = %ident.to_base64(),
                    "process_clove: destination delivery is not for router; skipped"
                );
                Ok(())
            }
            EciesDelivery::Tunnel { gateway, tunnel_id } => {
                debug!(
                    gateway = %gateway.to_base64(),
                    tunnel_id,
                    "process_clove: tunnel delivery requires tunnel layer; skipped"
                );
                Ok(())
            }
            EciesDelivery::Router(ident) => {
                debug!(
                    router = %ident.to_base64(),
                    "process_clove: router delivery requires forward path; skipped"
                );
                Ok(())
            }
        }
    }

    /// Обрабатывает clove с delivery `Local`.
    ///
    /// Разбирает тип I2NP внутри clove'а и вызывает соответствующую
    /// логику [`RouterContext`]:
    ///
    /// - `DatabaseStore` → [`Self::handle_database_store`] (кладёт
    ///   RI в netdb);
    /// - `DatabaseSearchReply` → [`Self::process_database_search_reply`]
    ///   (обновляет `excluded` активных поисков);
    /// - `DeliveryStatus` → фиксируется в логе (трекинга отправленных
    ///   сообщений в `RouterContext` пока нет);
    /// - `Garlic` → рекурсивный [`Self::handle_garlic`] (вложенный
    ///   garlic, бывает при forwarding через роутеры);
    /// - всё остальное → `debug!` и возврат `Ok(())`.
    ///
    /// # Errors
    ///
    /// См. [`Self::handle_database_store`],
    /// [`Self::process_database_search_reply`], [`Self::handle_garlic`].
    fn process_local_clove(&mut self, clove: &EciesGarlicClove) -> Result<()> {
        let payload: &[u8] = &clove.payload;
        match clove.message_type {
            I2npMessageType::DatabaseStore => {
                let handling = self.handle_database_store(payload)?;
                debug!(
                    msg_id = clove.message_id,
                    handling = ?handling,
                    "process_local_clove: DatabaseStore handled"
                );
            }
            I2npMessageType::DatabaseSearchReply => {
                self.process_database_search_reply(payload)?;
                debug!(
                    msg_id = clove.message_id,
                    "process_local_clove: DatabaseSearchReply handled"
                );
            }
            I2npMessageType::DeliveryStatus => {
                let ds = DeliveryStatus::from_buffer(payload)?;
                debug!(
                    msg_id = clove.message_id,
                    confirmed_msg_id = ds.msg_id,
                    "process_local_clove: DeliveryStatus received; no pending sender tracking yet"
                );
                // У RouterContext сейчас нет трекинга отправленных
                // сообщений; DeliveryStatus просто фиксируется в логе.
                // Когда появится `RouterContext::send_to_peer` с
                // ожиданием подтверждения — здесь надо будет дёрнуть
                // `complete_sent_msg(ds.msg_id)`.
            }
            I2npMessageType::Garlic => {
                // Вложенный garlic — рекурсивная обработка.
                // Ответ, если потребуется, уйдёт наружу из
                // внутреннего `handle_garlic`; внешний caller
                // его не увидит — но и не должен. NSR на вложенный
                // garlic отправляется инициатору garlic'а, который
                // отдельная сессия.
                let reply = self.handle_garlic(payload)?;
                if let Some(r) = reply {
                    warn!(
                        msg_id = clove.message_id,
                        i2np_len = r.message.total_len(),
                        "process_local_clove: nested garlic wants a reply, \
                         but RouterContext cannot route it back to the \
                         outer peer; dropping. This is a design gap that \
                         will be closed when a tunnel/garlic forwarder \
                         is available."
                    );
                }
            }
            other => {
                debug!(
                    msg_id = clove.message_id,
                    msg_type = %other,
                    "process_local_clove: unhandled I2NP type; skipped"
                );
            }
        }
        Ok(())
    }

    /// Создаёт контекст с указанной конфигурацией.
    ///
    /// Собственный RI собирается сразу с текущим timestamp'ом; для
    /// пересборки (обновление timestamp'а, смена адресов) — см.
    /// [`Self::rebuild_own_ri`].
    ///
    /// # Errors
    ///
    /// - ошибки [`RouterConfig::build_router_info`];
    /// - [`Error::InvalidLength`], если приватный crypto key не 32 байта
    ///   или encryption public key не 32 байта (не должно случаться
    ///   для `EdDSA` + ECIES-X25519, но проверяем);
    /// - [`Error::Unsupported`], если `crypto_key_type()` не ECIES-X25519.
    pub fn new(config: RouterConfig) -> Result<Self> {
        let own_ri = config.build_router_info(now_ms())?;
        let ecies = EciesGarlicDestination::new(Self::ecies_static(&config)?);

        Ok(Self {
            config,
            netdb_requests: NetDbRequests::new(),
            own_ri,
            netdb: NetDb::new(),
            ecies,
        })
    }

    /// X25519-пара из **router encryption key** — того же ключа, что
    /// опубликован в RI.
    ///
    /// По нему другие роутеры шифруют нам свой garlic: и как
    /// destination-сессию ([`EciesGarlicDestination`]), и как
    /// одноразовый `Noise_N` (см. [`Self::handle_router_garlic`]).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`], если приватный или публичный
    ///   crypto-ключ короче 32 байт (для `EdDSA` + ECIES-X25519 не
    ///   должно случаться, но проверяем);
    /// - [`Error::Unsupported`], если `crypto_key_type()` не ECIES-X25519.
    fn ecies_static(config: &RouterConfig) -> Result<I2PX25519Keys> {
        let crypto_priv = config.keys().crypto_private();
        let crypto_pub = config.keys().public().encryption_public_key()?;
        if crypto_priv.len() < 32 || crypto_pub.len() < 32 {
            return Err(I2PError::InvalidLength {
                expected: 32,
                got: crypto_priv.len().min(crypto_pub.len()),
            });
        }
        let mut priv_arr = [0u8; 32];
        priv_arr.copy_from_slice(&crypto_priv[..32]);
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&crypto_pub[..32]);
        Ok(I2PX25519Keys::from_private(&priv_arr, Some(&pub_arr)))
    }
    /// Пул активных поисков RI. Для тестов и диагностики.
    #[must_use]
    pub const fn netdb_requests(&self) -> &NetDbRequests {
        &self.netdb_requests
    }
    /// Конфигурация.
    #[must_use]
    pub const fn config(&self) -> &RouterConfig {
        &self.config
    }

    /// Собственный `RouterInfo`.
    #[must_use]
    pub const fn own_ri(&self) -> &FullRouterInfo {
        &self.own_ri
    }

    /// `IdentHash` собственного RI.
    #[must_use]
    pub const fn own_ident_hash(&self) -> &IdentHash {
        self.own_ri.ident_hash()
    }

    /// `NetDb`.
    #[must_use]
    pub const fn netdb(&self) -> &NetDb {
        &self.netdb
    }

    /// `NetDb`, изменяемо.
    pub const fn netdb_mut(&mut self) -> &mut NetDb {
        &mut self.netdb
    }

    /// ECIES garlic destination.
    #[must_use]
    pub const fn ecies(&self) -> &EciesGarlicDestination {
        &self.ecies
    }

    /// ECIES garlic destination, изменяемо.
    pub const fn ecies_mut(&mut self) -> &mut EciesGarlicDestination {
        &mut self.ecies
    }

    /// Пересобирает собственный RI с текущим timestamp'ом.
    ///
    /// В i2pd вызывается периодически (`RouterInfo::Update`), чтобы
    /// peer'ы видели свежий timestamp и не считали нас offline.
    /// Возвращает `Err`, если подпись/сборка не удались (не должно
    /// случаться для валидного `RouterConfig`).
    ///
    /// # Errors
    ///
    /// См. [`RouterConfig::build_router_info`].
    pub fn rebuild_own_ri(&mut self) -> Result<()> {
        self.own_ri = self.config.build_router_info(now_ms())?;
        Ok(())
    }

    /// Находит RI роутера по `IdentHash`.
    ///
    /// Сначала смотрит **свой** RI (если `ident` совпадает с нашим),
    /// затем — `netdb`. Это соответствует поведению i2pd: свой RI
    /// всегда доступен, даже если его нет в netDb.
    #[must_use]
    pub fn find_router(&self, ident: &IdentHash) -> Option<&FullRouterInfo> {
        if ident == self.own_ident_hash() {
            Some(&self.own_ri)
        } else {
            self.netdb.get(ident)
        }
    }

    /// Строит `DatabaseStore` с собственным RI.
    ///
    /// `reply_token` = 0 → `DeliveryStatus` не запрашивается. Для
    /// публикации в floodfill'ы обычно используется ненулевой token
    /// и `reply_instruction` с inbound-туннелем, но это уровень
    /// `RouterContext`-обвязки (шаг 3a-4), здесь только строитель.
    ///
    /// # Errors
    ///
    /// Ошибки [`FullRouterInfo::to_buffer`] и
    /// [`DatabaseStore::new_router_info`].
    pub fn build_own_database_store(&self) -> Result<DatabaseStore> {
        let ri_bytes = self.own_ri.to_buffer()?;
        DatabaseStore::new_router_info(*self.own_ident_hash(), &ri_bytes, 0, None)
    }

    /// Обрабатывает payload I2NP-сообщения типа `DatabaseStore`.
    ///
    /// `payload` — байты после 16-байтового I2NP-заголовка (то, что
    /// `I2npMessage::payload()` возвращает).
    ///
    /// ## Что делает
    ///
    /// - `store_type == RouterInfo` → распаковывает gzip, парсит
    ///   [`FullRouterInfo`], кладёт в `netdb` (с учётом timestamp'а);
    /// - остальные типы (`LeaseSet`, `EncryptedLeaseSet`, `MetaLeaseSet`)
    ///   возвращает как [`StoreHandling::NotRouterInfo`] — caller сам
    ///   решает (обычно destination-уровень).
    ///
    /// # Errors
    ///
    /// - ошибки [`DatabaseStore::from_buffer`] — payload не парсится;
    /// - [`Error::Malformed`] — gzip не распаковывается, или
    ///   `FullRouterInfo` не парсится;
    /// - [`Error::Malformed`] — `store_type` `RouterInfo`, но key
    ///   в сообщении не совпадает с `ident_hash` разобранного RI
    ///   (защита от подмены).
    pub fn handle_database_store(&mut self, payload: &[u8]) -> Result<StoreHandling> {
        let ds = DatabaseStore::from_buffer(payload)?;
        if ds.store_type != StoreType::RouterInfo {
            return Ok(StoreHandling::NotRouterInfo(ds.store_type));
        }
        let ri_bytes = ds.payload_decoded()?;
        let ri = FullRouterInfo::from_buffer(&ri_bytes)?;
        let ident = *ri.ident_hash();
        // `key` в DatabaseStore — это хеш RI, который должен совпадать
        // с identity. Если нет — злоумышленник или битый RI.
        if ds.key != ident {
            return Err(I2PError::Malformed(
                "router_context: DatabaseStore key != RI ident_hash",
            ));
        }

        let existed_before = self.netdb.contains(&ident);
        let replaced = self.netdb.insert(ri);

        // Кто-то мог ждать именно этот RI — снимаем ожидание.
        // В i2pd `RequestComplete` вызывается в конце `AddRouterInfo`
        // для всех веток (включая «уже есть более свежий»): то, что
        // у нас лежит новее, не отменяет того, что запрос найден.
        self.complete_lookup(&ident);

        if !existed_before {
            Ok(StoreHandling::Inserted(ident))
        } else if replaced {
            Ok(StoreHandling::Updated(ident))
        } else {
            Ok(StoreHandling::Stale(ident))
        }
    }

    /// Начать поиск `RouterInfo` по `ident`.
    ///
    /// Возвращает `true`, если запрос зарегистрирован; `false` —
    /// если такой уже активен. Сама отправка — в
    /// [`Self::tick_netdb_requests`].
    ///
    /// Пока всегда `direct = true`: туннелей у нас нет, всё идёт
    /// через прямой NTCP2. Когда появятся туннели, сюда добавится
    /// параметр `prefer_tunnels`.
    pub fn request_router(&mut self, ident: IdentHash, now_ms: u64) -> bool {
        self.netdb_requests.new_request(ident, false, true, now_ms)
    }

    /// Начать exploratory-поиск (расширение netdb).
    ///
    /// Отличие от [`Self::request_router`]: ищем любые роутеры,
    /// не конкретный RI, и живёт такой запрос дольше.
    pub fn request_exploratory(&mut self, target: IdentHash, now_ms: u64) -> bool {
        self.netdb_requests.new_request(target, true, true, now_ms)
    }

    /// Обработать входящий `DatabaseSearchReply`.
    ///
    /// Пир, которому мы слали `DatabaseLookup`, вернул список
    /// известных ему роутеров. Записываем их в `excluded`, чтобы
    /// в следующей попытке спросить других. Никаких действий
    /// наружу не возвращаем.
    ///
    /// # Errors
    ///
    /// См. [`Self::handle_database_search_reply`].
    pub fn process_database_search_reply(&mut self, payload: &[u8]) -> Result<()> {
        let reply = self.handle_database_search_reply(payload)?;
        self.netdb_requests.handle_search_reply(&reply);
        Ok(())
    }

    /// Пометить поиск RI завершённым — вызывается из
    /// [`Self::handle_database_store`] при получении валидного RI
    /// с нужным `IdentHash`.
    ///
    /// Возвращает `true`, если был активный запрос по этому хэшу.
    pub fn complete_lookup(&mut self, ident: &IdentHash) -> bool {
        self.netdb_requests.complete(ident)
    }

    /// Прокрутить тайминги всех активных поисков, вернуть действия
    /// для отправки.
    ///
    /// Caller (обычно транспортный слой) сам решает, как доставить
    /// [`SendAction::message`] до [`SendAction::to`]: сейчас —
    /// через [`crate::ntcp2_pool::Ntcp2Pool::send_to`], в будущем —
    /// через туннели.
    ///
    /// Вызывать периодически (в i2pd — раз в 400–700 мс,
    /// `MANAGE_REQUESTS_INTERVAL`).
    #[must_use]
    pub fn tick_netdb_requests(&mut self, now_ms: u64) -> Vec<SendAction> {
        let our_hash = *self.own_ident_hash();
        // Замыкание читает `&self.netdb`, `tick` берёт `&mut self.netdb_requests`.
        // Разделяем поля вручную, чтобы борроучекер пропустил.
        let netdb = &self.netdb;
        self.netdb_requests
            .tick(&our_hash, now_ms, |target, excluded, our| {
                // Сначала floodfill'ы (в i2pd всегда так).
                let candidates = netdb.closest_floodfills(target, 8);
                for ri in candidates {
                    let h = ri.ident_hash();
                    if h != our && !excluded.contains(h) {
                        return Some(*h);
                    }
                }
                None
            })
    }

    /// Разбирает payload `DatabaseLookup`.
    ///
    /// Возвращает разобранную структуру; решение о том, что и куда
    /// отвечать — задача вызывающего кода. У нас пока нет туннельного
    /// слоя, чтобы доставить ответ; когда появится (шаг 3b), здесь
    /// будет логика «посмотреть в netdb, если есть — ответить
    /// `DatabaseStore`, если нет — `DatabaseSearchReply` с ближайшими
    /// floodfill'ами».
    ///
    /// # Errors
    ///
    /// См. [`DatabaseLookup::from_buffer`].
    pub fn handle_database_lookup(&self, payload: &[u8]) -> Result<DatabaseLookup> {
        DatabaseLookup::from_buffer(payload)
    }

    /// Разбирает payload `DatabaseSearchReply`.
    ///
    /// Аналогично: разбираем и возвращаем; логика «попросить у
    /// указанных роутеров RI» — в слое запросов (шаг 3a-4).
    ///
    /// # Errors
    ///
    /// См. [`DatabaseSearchReply::from_buffer`].
    pub fn handle_database_search_reply(&self, payload: &[u8]) -> Result<DatabaseSearchReply> {
        DatabaseSearchReply::from_buffer(payload)
    }

    /// Сколько хешей класть в `DatabaseSearchReply`.
    ///
    /// i2pd использует `3` и в `GetClosestFloodfills`, и в
    /// `GetExploratoryNonFloodfill`. Не выдумываем.
    const LOOKUP_REPLY_PEER_COUNT: usize = 3;

    /// Собирает ответ на `DatabaseLookup`.
    ///
    /// Не ходит по сети и не пишет в netdb — чистая функция от
    /// состояния. Вызывающий сам решает, куда деть `I2npMessage`.
    ///
    /// Соответствует `NetDb::HandleDatabaseLookupMsg` в части
    /// построения `replyMsg` (без части отправки).
    ///
    /// # Errors
    ///
    /// - [`I2PError::Malformed`] — если не удалось собрать
    ///   `DatabaseStore` (RI больше 64 КБ, что для валидного RI
    ///   невозможно);
    /// - ошибки [`I2npMessage::from_body`].
    pub fn build_lookup_reply(&self, lookup: &DatabaseLookup) -> Result<I2npMessage> {
        let our_hash = *self.own_ident_hash();

        // Исключаем: то, что пир сам попросил исключить, плюс себя —
        // отвечать «спроси у меня же» бессмысленно.
        let mut excluded: HashSet<IdentHash> = lookup.excluded.iter().copied().collect();
        excluded.insert(our_hash);

        // Exploratory: пир ищет любые роутеры для расширения netdb.
        // Отдаём не-floodfill'ы, ближайшие к его ключу.
        if lookup.lookup_type == LookupType::Exploratory {
            let hashes = self.exploratory_non_floodfills(&lookup.key, &excluded);
            let reply = DatabaseSearchReply::with_from(lookup.key, hashes, our_hash);
            return I2npMessage::from_body(I2npBody::DatabaseSearchReply(reply));
        }

        // RI-ветка (для RouterInfo и Normal).
        if matches!(
            lookup.lookup_type,
            LookupType::RouterInfo | LookupType::Normal
        ) && let Some(ri) = self.netdb.get(&lookup.key)
        {
            let ri_bytes = ri.to_buffer()?;
            let ds = DatabaseStore::new_router_info(lookup.key, &ri_bytes, 0, None)?;
            return I2npMessage::from_body(I2npBody::DatabaseStore(ds));
        }

        // LeaseSet-ветка: LS-хранилища в netdb у нас пока нет
        // (отдельный шаг 3c). Падать не падаем — отдаём
        // SearchReply, как i2pd, когда ничего не нашёл.

        // Ничего не нашли — ближайшие floodfill'ы.
        let hashes = self.closest_floodfills_for(&lookup.key, &excluded);
        let reply = DatabaseSearchReply::with_from(lookup.key, hashes, our_hash);
        I2npMessage::from_body(I2npBody::DatabaseSearchReply(reply))
    }

    /// Полный цикл обработки входящего `DatabaseLookup`.
    ///
    /// `payload` — байты после I2NP-заголовка (то, что даёт
    /// [`I2npMessage::payload`]).
    ///
    /// Возвращает `Some(reply)` — готовый `I2npMessage` для отправки
    /// отправителю; `None` — если по какой-то причине отвечать не
    /// нужно (сейчас такого нет, но API оставляем расширяемым).
    ///
    /// # Errors
    ///
    /// - ошибки [`Self::handle_database_lookup`];
    /// - ошибки [`Self::build_lookup_reply`].
    pub fn process_database_lookup(&mut self, payload: &[u8]) -> Result<Option<I2npMessage>> {
        let lookup = self.handle_database_lookup(payload)?;
        let reply = self.build_lookup_reply(&lookup)?;
        Ok(Some(reply))
    }

    // --- приватные хелперы -----------------------------------------------

    /// Ближайшие floodfill'ы к `target`, кроме `excluded`.
    ///
    /// Обёртка над [`NetDb::closest_floodfills`] с фильтром
    /// исключений — так же, как i2pd делает в
    /// `NetDb::HandleDatabaseLookupMsg`.
    fn closest_floodfills_for(
        &self,
        target: &IdentHash,
        excluded: &HashSet<IdentHash>,
    ) -> Vec<IdentHash> {
        self.netdb
            .closest_floodfills(target, Self::LOOKUP_REPLY_PEER_COUNT)
            .into_iter()
            .filter(|ri| !excluded.contains(ri.ident_hash()))
            .map(|ri| *ri.ident_hash())
            .collect()
    }

    /// Ближайшие **не**-floodfill'ы к `target`, кроме `excluded`.
    ///
    /// i2pd поддерживает для этого отдельный индекс
    /// (`m_ExploratorySelection`), обновляемый раз в сутки по
    /// расписанию. У нас пока netdb небольшой — делаем напрямую
    /// через `closest_to` с фильтром. Когда роутеров станет много,
    /// переделаем по образцу i2pd.
    fn exploratory_non_floodfills(
        &self,
        target: &IdentHash,
        excluded: &HashSet<IdentHash>,
    ) -> Vec<IdentHash> {
        self.netdb
            .closest_to(target, Self::LOOKUP_REPLY_PEER_COUNT, |ri| {
                !ri.body().caps.is_floodfill()
            })
            .into_iter()
            .filter(|ri| !excluded.contains(ri.ident_hash()))
            .map(|ri| *ri.ident_hash())
            .collect()
    }
}

impl std::fmt::Debug for RouterContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterContext")
            .field("own_ident_hash", self.own_ident_hash())
            .field("netdb_size", &self.netdb.len())
            .field("ecies_sessions", &self.ecies.session_count())
            .finish_non_exhaustive()
    }
}

/// Текущее время в миллисекундах since epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
/// Форматирует первые 8 байт ключа/хеша в hex-строку для логов.
///
/// Отдельная функция, а не inline-замыкание, потому что `format_args!`
/// в `tracing` не умеет вызывать методы на `[u8; 32]` через `%`
/// (нет `Display`). Возврат `String` — аллокация только на
/// время лога, что нормально: `tracing` при выключенном уровне
/// не вызовет её, потому что аргументы `trace!` вычисляются
/// лениво.
#[must_use]
fn hex8(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        // Запись в String не может провалиться; игнорируем результат.
        let _ = write!(s, "{b:02x}");
    }
    s
}
