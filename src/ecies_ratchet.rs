//! `ECIES-X25519-AEAD-Ratchet` — установление сессии (NS/NSR) и
//! existing session messages.
//!
//! Реализованы все три фазы: **New Session** (Alice → Bob), **New
//! Session Reply** (Bob → Alice) и обмен сообщениями под session tag
//! (шаг 2x-3b), включая DH-ratchet (`NextKey`) и подтверждения
//! (`Ack`/`AckRequest`, см. ниже).
//!
//! ## `Ack` / `AckRequest`
//!
//! Копия `CreatePayload`/`HandlePayload` из i2pd
//! (`ECIESX25519AEADRatchetSession.cpp`):
//!
//! - принятый `AckRequest` запоминает **то** сообщение, в котором он
//!   пришёл (`(tagset_id, index)`) — на него уйдёт `Ack`
//!   (`MessageConfirmed` наоборот, `:442`);
//! - принятый `Ack` подтверждает наши `msgID`
//!   `(tagset_id << 16) | index` — см. [`RatchetSession::take_confirmed_msg_ids`]
//!   (`:420`, `MessageConfirmed`, `:242`);
//! - свой `AckRequest` шлём не чаще `DEFAULT_ACK_REQUEST_INTERVAL_MS`,
//!   неподтверждённый повторяем через `ACK_REQUEST_RETRY_TIMEOUT_MS`
//!   (`CreatePayload`, `:1186`).
//!
//! `msgID` сообщения совпадает с парой `(tagset_id, index)`, которую
//! видит получатель: обе стороны считают `index` как номер тега в
//! tag-set'е ([`RatchetTagSet::msg_id`]).
//!
//! ## Что не реализовано
//!
//! - **ML-KEM hybrid** — i2pd поддерживает ML-KEM-512/768/1024 в NS
//!   как второй слой. Мы только X25519.
//! - **Подтверждение доставки `LeaseSet`** — в i2pd `AckRequest` для
//!   `LeaseSet` ставит `GetLeaseSetUpdateStatus() == eLeaseSetUpdated`
//!   (`CreatePayload`, `:1176`); наши сессии LeaseSet-блок не носят
//!   (публикация lease set'ов в garlic пока не сделана), поэтому
//!   работает только «обычная» ветка запроса.
//!
//! ## Wire-формат
//!
//! ```text
//!   NS:  aepk(32) || enc_fs(48) || enc_payload(N+16)
//!   NSR: tag(8) || bepk(32) || enc_reply_key(16) || enc_payload(N+16)
//! ```
//!
//! `enc_fs` — 32 байта (static pub Alice или нули) + 16 Poly1305.

use crate::{
    EciesGarlicClove,
    crypto::{AeadChaCha20Poly1305, I2PX25519Keys, NoiseSymmetricState, hkdf, init_noise_ik_state},
    elligator,
    error::{I2PError, Result},
    garlic_block::{GarlicBlock, NextKeyBlock, parse_blocks, serialize_blocks},
    ratchet_tagset::RatchetTagSet,
};
use std::collections::HashMap;
use tracing::debug;

/// Интервал обычных `AckRequest`, мс — i2pd
/// `ECIESX25519_DEFAULT_ACK_REQUEST_INTERVAL`
/// (`ECIESX25519AEADRatchetSession.h:38`).
pub const DEFAULT_ACK_REQUEST_INTERVAL_MS: u64 = 33_000;

/// Если подтверждение не пришло за это время, `AckRequest` повторяем
/// (i2pd `LEASESET_CONFIRMATION_TIMEOUT`, `Garlic.h:56`).
pub const ACK_REQUEST_RETRY_TIMEOUT_MS: u64 = 4000;

/// Сколько раз повторять `AckRequest` для одного `msgID` (i2pd
/// `ECIESX25519_ACK_REQUEST_MAX_NUM_ATTEMPTS`, `:39`).
pub const ACK_REQUEST_MAX_NUM_ATTEMPTS: u32 = 3;

/// Сколько подтверждённых `msgID` держим до вычитывания вызывающим.
///
/// i2pd не хранит их вовсе (только чистит свой `m_AckRequestMsgID`);
/// список нужен, чтобы отдать подтверждение наружу, и ограничен, чтобы
/// поток `Ack` не рос неограниченно.
const CONFIRMED_MSG_IDS_CAP: usize = 64;

/// Состояние сессии на этапе установления.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Только создана.
    New,
    /// Alice отправила NS, ждёт NSR.
    NewSent,
    /// Bob принял NS, готов отправить NSR.
    NewReceived,
    /// Bob отправил NSR.
    NewReplySent,
    /// Сессия установлена, можно обмениваться existing session messages.
    Established,
}
/// Сколько receive-tag'ов держать "заряженными".
pub const MIN_RECEIVE_TAGS: usize = 24;
/// Верхняя граница генерации.
pub const MAX_RECEIVE_TAGS: usize = 800;
/// Максимальный `key_id` в `NextKey`-блоке.
///
/// Достигли — следующий ratchet уже не влезает в wire-формат,
/// нужен новый NS (новый сеанс).
pub const MAX_KEY_ID: u16 = 32_767;

/// Порог, после которого инициатор `send_tagset`'а запускает DH-ratchet.
///
/// В i2pd — `ECIESX25519_TAGSET_MAX_NUM_TAGS`. Меньше, чем
/// [`MAX_TAG_INDEX`](crate::ratchet_tagset::MAX_TAG_INDEX), чтобы
/// старый и новый tagset успели перекрыться.
pub const TAGSET_MAX_NUM_TAGS: u16 = 8192;

/// Diffie-Hellman ratchet — один шаг.a
pub struct DHRatchet {
    pub key_id: u16,
    /// Локальный X25519-ключ. `None` до первой генерации.
    pub key: Option<I2PX25519Keys>,
    /// Последний публичный ключ противоположной стороны.
    ///
    /// Заполняется при обработке forward/reverse `NextKey`.
    remote: [u8; 32],
    /// `true` — этот ключ ещё не использован в DH.
    pub new_key: bool,
}
impl Default for DHRatchet {
    fn default() -> Self {
        Self::new()
    }
}

impl DHRatchet {
    /// Новый ratchet в исходном состоянии (`new_key = true`, `key_id = 0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            key_id: 0,
            key: None,
            remote: [0u8; 32],
            new_key: true,
        }
    }

    /// ID tagset'а для приёма, ассоциированного с этим ratchet'ом.
    ///
    /// Точная формула из i2pd:
    /// `newKey ? 2*keyID + 1 : 2*keyID`.
    #[must_use]
    pub const fn receive_tagset_id(&self) -> u16 {
        if self.new_key {
            2 * self.key_id + 1
        } else {
            2 * self.key_id
        }
    }
}
/// ECIES-X25519-AEAD-Ratchet сессия (NS/NSR).
pub struct RatchetSession {
    local_static: I2PX25519Keys,
    remote_static: Option<[u8; 32]>,
    /// aesk для Alice, besk для Bob.
    ephemeral: Option<I2PX25519Keys>,
    /// aepk, полученный Bob'ом в NS — нужен для NSR.
    remote_ephemeral_aepk: Option<[u8; 32]>,
    noise: NoiseSymmetricState,
    state: SessionState,
    /// Только у Alice: tagset для проверки NSR.
    nsr_receive_tagset: Option<RatchetTagSet>,
    send_tagset: Option<RatchetTagSet>,
    /// Все активные receive-tagset'ы, старейший первым.
    ///
    /// Индекс в `Vec` — это `tagset_id`; он же используется в
    /// `NextKey`-блоке и Ack-сообщениях. Обычно один элемент;
    /// два — короткое окно сразу после DH-ratchet'а.
    receive_tagsets: Vec<RatchetTagSet>,

    /// Карта `tag → (tagset_id, index)`.
    ///
    /// `tagset_id` — индекс в [`Self::receive_tagsets`].
    receive_tags: HashMap<u64, (u16, u32)>,

    /// Текущий send-ratchet: локальный эфемерный ключ + `key_id`.
    /// `Some`, когда мы инициировали forward-key и ждём reverse.
    pub next_send_ratchet: Option<DHRatchet>,
    /// Текущий receive-ratchet: последний принятый forward-key.
    /// `Some`, когда мы приняли forward-key и должны ответить reverse.
    pub next_receive_ratchet: Option<DHRatchet>,
    /// Нужно отправить forward-key в следующем existing-session сообщении.
    pub send_forward_key: bool,
    /// Нужно отправить reverse-key в следующем existing-session сообщении.
    pub send_reverse_key: bool,
    /// Сессия закрыта: либо peer прислал `Termination`, либо мы сами
    /// вызвали [`Self::send_termination`]. Caller должен удалить такую
    /// сессию — она больше не принимает и не отправляет существующие
    /// сессионные сообщения (кроме Termination-блока).
    is_terminated: bool,

    /// Пары `(tagset_id, index)` принятых сообщений, на которые пир
    /// просил `Ack` — i2pd `m_AckRequests`.
    ///
    /// Опустошается при сборке очередного сообщения: блок `Ack` уходит
    /// один раз (`CreatePayload`, `:1246`).
    ack_requests: Vec<(u16, u16)>,
    /// `msgID` (`(tagset_id << 16) | index`) сообщения, подтверждение
    /// которого мы ждём — i2pd `m_AckRequestMsgID`. `0` — не ждём.
    ack_request_msg_id: u32,
    /// Сколько раз мы просили подтверждение для текущего `msgID` —
    /// i2pd `m_AckRequestNumAttempts`.
    ack_request_attempts: u32,
    /// Когда отправили `AckRequest` в последний раз, мс since epoch —
    /// i2pd `m_LastAckRequestSendTime`.
    last_ack_request_sent_ms: u64,
    /// Интервал обычных `AckRequest`, мс — i2pd `m_AckRequestInterval`.
    ack_request_interval_ms: u64,
    /// `(tagset_id, index)` последнего принятого existing-session
    /// сообщения — из него собирается пара для `Ack` (i2pd
    /// `HandlePayload` кладёт `receiveTagset->GetTagSetID (), index`).
    last_received: Option<(u16, u16)>,
    /// `msgID`, подтверждённые пришедшими `Ack` — i2pd
    /// `MessageConfirmed`. Отдаются наружу через
    /// [`Self::take_confirmed_msg_ids`].
    confirmed_msg_ids: Vec<u32>,
}

impl RatchetSession {
    /// Генерирует X25519-пару, публичный ключ которой представим
    /// через Elligator2, и сразу возвращает её encoded-форму.
    ///
    /// Соответствует циклу в
    /// `ECIESX25519AEADRatchetSession::GenerateEphemeralKeysAndEncode`:
    /// до 25 попыток генерации; между попытками в i2pd есть ещё пул
    /// ключей, отмеченных как «ineligible», но у нас генерация X25519
    /// дешёвая, и смысл пула теряется.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если за 25 попыток не нашлось
    /// Elligator-eligible ключа. Вероятность ≈ 2⁻²⁵, на практике
    /// недостижимо, но оставляем ошибкой, а не `panic`.
    fn generate_elligator_ephemeral() -> Result<(I2PX25519Keys, [u8; 32])> {
        let mut rng = rand::rng();
        for _ in 0..25 {
            let sk = I2PX25519Keys::generate();
            if let Some(encoded) = elligator::encode_random(sk.public_key(), &mut rng) {
                return Ok((sk, encoded));
            }
        }
        Err(I2PError::Malformed(
            "ecies_ratchet: no Elligator-eligible key in 25 tries",
        ))
    }
    /// Alice: знает свою static и static Bob'а. Инициирует NS.
    #[must_use]
    pub fn new_initiator(local_static: I2PX25519Keys, remote_static: [u8; 32]) -> Self {
        Self {
            local_static,
            remote_static: Some(remote_static),
            ephemeral: None,
            remote_ephemeral_aepk: None,
            noise: NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]),
            state: SessionState::New,
            nsr_receive_tagset: None,
            send_tagset: None,
            receive_tags: HashMap::new(),
            receive_tagsets: Vec::new(),
            next_send_ratchet: None,
            next_receive_ratchet: None,
            send_forward_key: false,
            send_reverse_key: false,
            is_terminated: false,
            ack_requests: Vec::new(),
            ack_request_msg_id: 0,
            ack_request_attempts: 0,
            last_ack_request_sent_ms: 0,
            ack_request_interval_ms: DEFAULT_ACK_REQUEST_INTERVAL_MS,
            last_received: None,
            confirmed_msg_ids: Vec::new(),
        }
    }

    /// Bob: знает только свою static. Ждёт NS.
    #[must_use]
    pub fn new_responder(local_static: I2PX25519Keys) -> Self {
        Self {
            local_static,
            remote_static: None,
            ephemeral: None,
            remote_ephemeral_aepk: None,
            noise: NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]),
            state: SessionState::New,
            nsr_receive_tagset: None,
            send_tagset: None,
            receive_tagsets: Vec::new(),
            receive_tags: HashMap::new(),
            next_send_ratchet: None,
            next_receive_ratchet: None,
            send_forward_key: false,
            send_reverse_key: false,
            is_terminated: false,
            ack_requests: Vec::new(),
            ack_request_msg_id: 0,
            ack_request_attempts: 0,
            last_ack_request_sent_ms: 0,
            ack_request_interval_ms: DEFAULT_ACK_REQUEST_INTERVAL_MS,
            last_received: None,
            confirmed_msg_ids: Vec::new(),
        }
    }

    /// Текущее состояние.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Static public key Bob'а (если известен).
    #[must_use]
    pub const fn remote_static(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }

    /// Наш static public key.
    #[must_use]
    pub fn local_static_public(&self) -> &[u8; 32] {
        self.local_static.public_key()
    }

    // --- NS (Alice) ------------------------------------------------------

    /// Создаёт New Session message (Alice).
    ///
    /// `payload` — garlic payload (serialized blocks).
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — не в состоянии `New`;
    /// - [`Error::Malformed`] — нет `remote_static` или DH вернул
    ///   all-zero shared secret;
    /// - [`Error::Malformed`] — не удалось сгенерировать
    ///   Elligator-eligible эфемерный ключ.
    pub fn create_new_session_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.state != SessionState::New {
            return Err(I2PError::Malformed(
                "ecies_ratchet: create NS not in New state",
            ));
        }
        let remote_static = self
            .remote_static
            .ok_or(I2PError::Malformed("ecies_ratchet: no remote static"))?;

        // 1. Ephemeral aesk/aepk с Elligator-кодированием.
        //    В wire уходит `aepk_encoded`, MixHash/DH работают
        //    с raw `aepk` — так в i2pd.
        let (ephemeral, aepk_encoded) = Self::generate_elligator_ephemeral()?;
        let aepk = *ephemeral.public_key();

        // 2. Noise IK init + KDF1.
        init_noise_ik_state(&mut self.noise, &remote_static);
        self.noise.mix_hash(&aepk);
        let shared1 = ephemeral
            .agree(&remote_static)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH1 failed"))?;
        self.noise.mix_key(&shared1);

        // 3. Encrypt static (32 + 16 MAC = 48).
        let our_static_pub = *self.local_static.public_key();
        let mut enc_fs = [0u8; 48];
        self.noise.encrypt(&our_static_pub, &mut enc_fs)?;
        self.noise.mix_hash(&enc_fs);

        // 4. KDF2: DH(ask, bpk).
        let shared2 = self
            .local_static
            .agree(&remote_static)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH2 failed"))?;
        self.noise.mix_key(&shared2);

        // 5. Encrypt payload.
        let mut enc_payload = vec![0u8; payload.len() + 16];
        let n = self.noise.encrypt(payload, &mut enc_payload)?;
        enc_payload.truncate(n);
        self.noise.mix_hash(&enc_payload);

        // 6. tagset_nsr: DH_INITIALIZE(ck, HKDF(ck, "", "SessionReplyTags", 32)).
        let mut tagset_key = [0u8; 32];
        hkdf(&self.noise.ck, &[], b"SessionReplyTags", &mut tagset_key);
        let mut tagset = RatchetTagSet::new();
        tagset.dh_initialize(&self.noise.ck, &tagset_key);
        tagset.next_session_tag_ratchet();
        self.nsr_receive_tagset = Some(tagset);

        // 7. Wire.
        let mut out = Vec::with_capacity(32 + 48 + enc_payload.len());
        out.extend_from_slice(&aepk_encoded);
        out.extend_from_slice(&enc_fs);
        out.extend_from_slice(&enc_payload);

        self.ephemeral = Some(ephemeral);
        self.state = SessionState::NewSent;
        Ok(out)
    }

    // --- NS (Bob) --------------------------------------------------------

    /// Принимает New Session message (Bob).
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — не в состоянии `New`;
    /// - [`Error::InvalidLength`] — буфер короче 96 байт;
    /// - [`Error::Malformed`] — `aepk` не проходит Elligator decode;
    /// - [`Error::Unsupported`] — Alice не static (все нули в fs);
    /// - AEAD-ошибки.
    pub fn handle_new_session_message(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        if self.state != SessionState::New {
            return Err(I2PError::Malformed(
                "ecies_ratchet: handle NS not in New state",
            ));
        }
        if buf.len() < 96 {
            return Err(I2PError::InvalidLength {
                expected: 96,
                got: buf.len(),
            });
        }

        // aepk приходит Elligator-encoded. Внутри работаем с raw.
        let mut aepk_encoded = [0u8; 32];
        aepk_encoded.copy_from_slice(&buf[0..32]);
        let aepk = elligator::decode(&aepk_encoded)
            .ok_or(I2PError::Malformed("ecies_ratchet: elligator decode aepk"))?;

        let enc_fs = &buf[32..80];
        let enc_payload = &buf[80..];

        // 1. Noise IK init + KDF1.
        let our_static_pub = *self.local_static.public_key();
        init_noise_ik_state(&mut self.noise, &our_static_pub);
        self.noise.mix_hash(&aepk);
        let shared1 = self
            .local_static
            .agree(&aepk)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH1 failed"))?;
        self.noise.mix_key(&shared1);

        // 2. Decrypt static.
        let mut fs = [0u8; 32];
        self.noise.decrypt(enc_fs, &mut fs)?;
        self.noise.mix_hash(enc_fs);

        if fs.iter().all(|&b| b == 0) {
            return Err(I2PError::Unsupported("ecies_ratchet: non-static Alice"));
        }
        self.remote_static = Some(fs);
        let shared2 = self
            .local_static
            .agree(&fs)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH2 failed"))?;
        self.noise.mix_key(&shared2);

        // 3. Decrypt payload.
        let mut payload = vec![0u8; enc_payload.len() - 16];
        let n = self.noise.decrypt(enc_payload, &mut payload)?;
        payload.truncate(n);
        self.noise.mix_hash(enc_payload);

        // 4. Эфемерный ключ Bob'а здесь **не** генерируется: i2pd
        //    делает это в `NewSessionReplyMessage` (см.
        //    `create_new_session_reply_message`). Сохраняем только
        //    raw aepk — он нужен для KDF в NSR.
        self.remote_ephemeral_aepk = Some(aepk);
        self.state = SessionState::NewReceived;
        Ok(payload)
    }

    // --- NSR (Bob) -------------------------------------------------------

    /// Создаёт New Session Reply message (Bob).
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — не в состоянии `NewReceived`,
    ///   нет `remote_ephemeral_aepk` или `remote_static`;
    /// - [`Error::Malformed`] — не удалось сгенерировать
    ///   Elligator-eligible эфемерный ключ.
    pub fn create_new_session_reply_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.state != SessionState::NewReceived {
            return Err(I2PError::Malformed(
                "ecies_ratchet: create NSR not in NewReceived state",
            ));
        }
        let aepk = self
            .remote_ephemeral_aepk
            .ok_or(I2PError::Malformed("ecies_ratchet: aepk not saved"))?;
        let alice_static = self
            .remote_static
            .ok_or(I2PError::Malformed("ecies_ratchet: no apk"))?;

        // 1. tagset_nsr.
        let mut tagset_key = [0u8; 32];
        hkdf(&self.noise.ck, &[], b"SessionReplyTags", &mut tagset_key);
        let mut tagset = RatchetTagSet::new();
        tagset.dh_initialize(&self.noise.ck, &tagset_key);
        tagset.next_session_tag_ratchet();
        let tag = tagset
            .get_next_session_tag()
            .ok_or(I2PError::Malformed("ecies_ratchet: tag exhausted"))?;
        let tag_bytes = tag.to_le_bytes();

        // 2. bepk — генерируем здесь, как i2pd в
        //    `NewSessionReplyMessage`. В wire уходит encoded,
        //    MixHash/DH работают с raw.
        let (ephemeral, bepk_encoded) = Self::generate_elligator_ephemeral()?;
        let bepk = *ephemeral.public_key();

        // 3. KDF for Reply Key Section.
        self.noise.mix_hash(&tag_bytes);
        self.noise.mix_hash(&bepk);

        let shared1 = ephemeral
            .agree(&aepk)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH bes k/aepk failed"))?;
        self.noise.mix_key(&shared1);

        let shared2 = ephemeral
            .agree(&alice_static)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH besk/apk failed"))?;
        self.noise.mix_key(&shared2);

        // 4. Encrypt ZEROLEN (reply key section = 16 байт MAC).
        let mut reply_key_section = [0u8; 16];
        self.noise.encrypt(&[], &mut reply_key_section)?;
        self.noise.mix_hash(&reply_key_section);

        // 5. KDF для payload.
        let mut keydata = [0u8; 64];
        hkdf(&self.noise.ck, &[], b"", &mut keydata);
        let mut k_ab = [0u8; 32];
        let mut k_ba = [0u8; 32];
        k_ab.copy_from_slice(&keydata[..32]);
        k_ba.copy_from_slice(&keydata[32..64]);

        let mut send_tagset = RatchetTagSet::new();
        send_tagset.dh_initialize(&self.noise.ck, &k_ba);
        send_tagset.next_session_tag_ratchet();

        let mut receive_tagset = RatchetTagSet::new();
        receive_tagset.dh_initialize(&self.noise.ck, &k_ab);
        receive_tagset.next_session_tag_ratchet();

        let mut k = [0u8; 32];
        hkdf(&k_ba, &[], b"AttachPayloadKDF", &mut k);

        // 6. Encrypt payload с nonce=0, ad = h.
        let nonce = [0u8; 12];
        let aead = AeadChaCha20Poly1305::new();
        let mut enc_payload = vec![0u8; payload.len() + 16];
        let n = aead.encrypt(&k, &nonce, &self.noise.h, payload, &mut enc_payload)?;
        enc_payload.truncate(n);

        // 7. Wire.
        let mut out = Vec::with_capacity(8 + 32 + 16 + enc_payload.len());
        out.extend_from_slice(&tag_bytes);
        out.extend_from_slice(&bepk_encoded);
        out.extend_from_slice(&reply_key_section);
        out.extend_from_slice(&enc_payload);

        self.ephemeral = Some(ephemeral);
        self.send_tagset = Some(send_tagset);
        self.receive_tagsets.push(receive_tagset);
        self.state = SessionState::NewReplySent;
        self.refill_receive_tags()?;
        Ok(out)
    }

    // --- NSR (Alice) -----------------------------------------------------

    /// Принимает New Session Reply message (Alice).
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — не в состоянии `NewSent`;
    /// - [`Error::InvalidLength`] — буфер короче 72 байт;
    /// - [`Error::Malformed`] — `bepk` не проходит Elligator decode;
    /// - [`Error::Malformed`] — tag не совпал;
    /// - AEAD-ошибки.
    pub fn handle_new_session_reply_message(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        if self.state != SessionState::NewSent {
            return Err(I2PError::Malformed(
                "ecies_ratchet: handle NSR not in NewSent state",
            ));
        }
        if buf.len() < 72 {
            return Err(I2PError::InvalidLength {
                expected: 72,
                got: buf.len(),
            });
        }

        let mut tag_bytes = [0u8; 8];
        tag_bytes.copy_from_slice(&buf[0..8]);

        // bepk приходит Elligator-encoded. Внутри работаем с raw.
        let mut bepk_encoded = [0u8; 32];
        bepk_encoded.copy_from_slice(&buf[8..40]);
        let bepk = elligator::decode(&bepk_encoded)
            .ok_or(I2PError::Malformed("ecies_ratchet: elligator decode bepk"))?;

        let enc_reply_key = &buf[40..56];
        let enc_payload = &buf[56..];

        // 1. Проверка tag.
        let tagset = self
            .nsr_receive_tagset
            .as_mut()
            .ok_or(I2PError::Malformed("ecies_ratchet: no NSR tagset"))?;
        let expected = tagset
            .get_next_session_tag()
            .ok_or(I2PError::Malformed("ecies_ratchet: tag exhausted"))?;
        if expected.to_le_bytes() != tag_bytes {
            return Err(I2PError::Malformed("ecies_ratchet: NSR tag mismatch"));
        }

        // 2. KDF for Reply Key Section.
        self.noise.mix_hash(&tag_bytes);
        self.noise.mix_hash(&bepk);

        let aesk = self
            .ephemeral
            .as_ref()
            .ok_or(I2PError::Malformed("ecies_ratchet: no aesk"))?;

        let shared1 = aesk
            .agree(&bepk)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH aesk/bepk failed"))?;
        self.noise.mix_key(&shared1);

        let shared2 = self
            .local_static
            .agree(&bepk)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH ask/bepk failed"))?;
        self.noise.mix_key(&shared2);

        // 3. Decrypt ZEROLEN.
        let mut zero = [0u8; 0];
        self.noise.decrypt(enc_reply_key, &mut zero)?;
        self.noise.mix_hash(enc_reply_key);

        // 4. KDF для payload.
        let mut keydata = [0u8; 64];
        hkdf(&self.noise.ck, &[], b"", &mut keydata);
        let mut k_ab = [0u8; 32];
        let mut k_ba = [0u8; 32];
        k_ab.copy_from_slice(&keydata[..32]);
        k_ba.copy_from_slice(&keydata[32..64]);

        let mut send_tagset = RatchetTagSet::new();
        send_tagset.dh_initialize(&self.noise.ck, &k_ab);
        send_tagset.next_session_tag_ratchet();

        let mut receive_tagset = RatchetTagSet::new();
        receive_tagset.dh_initialize(&self.noise.ck, &k_ba);
        receive_tagset.next_session_tag_ratchet();

        let mut k = [0u8; 32];
        hkdf(&k_ba, &[], b"AttachPayloadKDF", &mut k);

        // 5. Decrypt payload.
        let nonce = [0u8; 12];
        let aead = AeadChaCha20Poly1305::new();
        let mut payload = vec![0u8; enc_payload.len() - 16];
        let n = aead.decrypt(&k, &nonce, &self.noise.h, enc_payload, &mut payload)?;
        payload.truncate(n);

        self.send_tagset = Some(send_tagset);
        self.receive_tagsets.push(receive_tagset);
        self.state = SessionState::Established;
        self.refill_receive_tags()?;
        Ok(payload)
    }

    // --- accessors для следующего шага -----------------------------------

    /// Tagset для отправки existing session messages.
    #[must_use]
    pub const fn send_tagset(&self) -> Option<&RatchetTagSet> {
        self.send_tagset.as_ref()
    }
    /// Refill'ит карту receive-tag'ов для **самого нового** tagset'а.
    ///
    /// Удобная обёртка над [`Self::refill_receive_tags_for`] с
    /// `target = None`: вызывается после NSR и после DH-ratchet'а.
    fn refill_receive_tags(&mut self) -> Result<()> {
        self.refill_receive_tags_for(None)
    }
    /// Refill'ит карту receive-tag'ов до `MIN_RECEIVE_TAGS` тегов,
    /// принадлежащих указанному tagset'у.
    ///
    /// `target` = `Some(id)` — пополнять именно этот tagset (например,
    /// тот, на котором пришло сообщение). `None` — взять самый новый.
    ///
    /// Считаются именно теги целевого tagset'а — иначе старые теги
    /// (с прежнего tagset'а после ratchet'а) блокировали бы пополнение
    /// нового.
    fn refill_receive_tags_for(&mut self, target: Option<u16>) -> Result<()> {
        let tagset_id = match target {
            Some(id) => usize::from(id),
            None => match self.receive_tagsets.len().checked_sub(1) {
                Some(id) => id,
                None => return Ok(()), // нет tagset'ов — нечего пополнять
            },
        };
        let tagset_id_u16 = u16::try_from(tagset_id)
            .map_err(|_| I2PError::Malformed("ecies_ratchet: too many receive tagsets"))?;

        let mut count = self
            .receive_tags
            .values()
            .filter(|(id, _)| *id == tagset_id_u16)
            .count();

        while count < MIN_RECEIVE_TAGS {
            let tagset = self
                .receive_tagsets
                .get_mut(tagset_id)
                .ok_or(I2PError::Malformed("ecies_ratchet: tagset_id out of range"))?;
            let index = u32::from(tagset.next_index());
            let Some(tag) = tagset.get_next_session_tag() else {
                break; // исчерпали — пусть следующий ratchet пополнит
            };
            self.receive_tags.insert(tag, (tagset_id_u16, index));
            count += 1;
        }
        Ok(())
    }

    /// Готовит следующий send-ratchet и взводит флаг forward-key.
    ///
    /// Вызывается, когда send-tagset исчерпал
    /// [`TAGSET_MAX_NUM_TAGS`]. Генерирует эфемерный X25519, выставляет
    /// `send_forward_key = true`; фактическая отправка произойдёт в
    /// ближайшем `wrap_blocks`.
    ///
    /// Если `key_id` уже достиг [`MAX_KEY_ID`], возвращает `Err` —
    /// сессию нужно пересоздать (у нас это не реализовано, шаг 2x-3e+).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `MAX_KEY_ID` исчерпан.
    pub fn new_next_send_ratchet(&mut self) -> Result<()> {
        match self.next_send_ratchet.as_mut() {
            Some(ratchet) => {
                // Точная копия i2pd `NewNextSendRatchet`:
                //   if (!newKey || !keyID) { keyID++; newKey = true; }
                //   else                   { newKey = false; }
                // Смысл: если ключ уже был использован (newKey == false)
                // или это ещё самая первая генерация (keyID == 0) —
                // двигаем keyID и помечаем ключ как свежий; иначе
                // переиспользуем keyID и старый ключ.
                if !ratchet.new_key || ratchet.key_id == 0 {
                    if ratchet.key_id >= MAX_KEY_ID {
                        return Err(I2PError::Malformed(
                            "ecies_ratchet: MAX_KEY_ID exhausted, session must be restarted",
                        ));
                    }
                    ratchet.key_id += 1;
                    ratchet.new_key = true;
                } else {
                    ratchet.new_key = false;
                }
            }
            None => self.next_send_ratchet = Some(DHRatchet::new()),
        }
        // Ключ генерируется **только** когда newKey == true. При первом
        // вызове (ветка `None`) `DHRatchet::new()` уже даёт newKey == true,
        // поэтому эта проверка корректно отрабатывает и для него.
        if let Some(ratchet) = self.next_send_ratchet.as_mut()
            && ratchet.new_key
        {
            ratchet.key = Some(I2PX25519Keys::generate());
        }
        self.send_forward_key = true;
        Ok(())
    }
    /// Обрабатывает входящий `NextKey`-блок.
    ///
    /// `tagset_id` — индекс receive-tagset'а, на котором пришло
    /// сообщение с этим блоком. Он нужен потому, что DH строится
    /// поверх `next_root_key()` **того** tagset'а (i2pd
    /// `HandleNextKey(buf, len, receiveTagset)`).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] на битом pub-key или провале DH
    /// (low-order point).
    fn handle_next_key_block(&mut self, tagset_id: u16, raw: &[u8]) -> Result<()> {
        let block = NextKeyBlock::parse(raw)?;
        if block.is_reverse_key() {
            self.handle_reverse_key(&block)
        } else {
            self.handle_forward_key(tagset_id, &block)
        }
    }

    /// Ветка forward (`else` в i2pd `HandleNextKey`): партнёр прислал
    /// свой эфемерный ключ, надо сделать DH и ответить reverse'ом.
    fn handle_forward_key(&mut self, tagset_id: u16, block: &NextKeyBlock) -> Result<()> {
        // На стороне получателя "новый ключ" = REQUEST_REVERSE на wire.
        let new_key_flag = block.requests_reverse_key();

        // 1. Обновляем или создаём `next_receive_ratchet`.
        let ratchet = self.next_receive_ratchet.get_or_insert_with(DHRatchet::new);
        // i2pd: duplicate-проверка только для **существующего**
        // ratchet'а. Свежесозданный (key=None) не может быть дубликатом.
        if ratchet.key.is_some()
            && ratchet.key_id == block.key_id
            && ratchet.new_key == new_key_flag
        {
            return Ok(());
        }
        ratchet.key_id = block.key_id;

        if new_key_flag {
            ratchet.key = Some(I2PX25519Keys::generate());
            ratchet.new_key = true;
        } else {
            if ratchet.key.is_none() {
                return Err(I2PError::Malformed(
                    "ecies_ratchet: forward key without local key",
                ));
            }
            ratchet.new_key = false;
        }
        if let Some(pk) = block.public_key {
            ratchet.remote = pk;
        }

        // 2. DH: наш локальный эфемерный × remote pub.
        let shared_secret = {
            let local_key = ratchet.key.as_ref().ok_or(I2PError::Malformed(
                "ecies_ratchet: forward key without local key",
            ))?;
            local_key
                .agree(&ratchet.remote)
                .ok_or(I2PError::Malformed("ecies_ratchet: DH agreement failed"))?
        };
        let mut tagset_key = [0u8; 32];
        hkdf(&shared_secret, &[], b"XDHRatchetTagSet", &mut tagset_key);

        // 3. `parent_root_key` — из tagset'а, на котором пришло
        //    сообщение. Копируем 32 байта, чтобы не держать borrow.
        let parent_root_key = *self
            .receive_tagsets
            .get(usize::from(tagset_id))
            .ok_or(I2PError::Malformed("ecies_ratchet: tagset_id out of range"))?
            .next_root_key();

        // 4. Создаём новый receive-tagset.
        let new_tagset_id = ratchet.receive_tagset_id();
        let mut new_tagset = RatchetTagSet::new();
        new_tagset.set_tagset_id(new_tagset_id);
        new_tagset.dh_initialize(&parent_root_key, &tagset_key);
        new_tagset.next_session_tag_ratchet();
        self.receive_tagsets.push(new_tagset);

        // 5. Заряжаем теги для нового tagset'а и планируем reverse.
        self.refill_receive_tags_for(Some(new_tagset_id))?;
        self.send_reverse_key = true;
        Ok(())
    }

    /// Ветка reverse (`if flag & REVERSE_KEY` в i2pd `HandleNextKey`):
    /// партнёр ответил на наш forward, надо сделать DH и заменить
    /// `send_tagset` на новый.
    fn handle_reverse_key(&mut self, block: &NextKeyBlock) -> Result<()> {
        if !self.send_forward_key {
            // i2pd: `if (!m_SendForwardKey || !m_NextSendRatchet) return;`
            return Ok(());
        }
        let Some(ratchet) = self.next_send_ratchet.as_ref() else {
            // i2pd: `if (!m_SendForwardKey || !m_NextSendRatchet) return;`
            // — молча игнорируем, это чужой/устаревший reverse.
            return Ok(());
        };

        // 1. Проверка keyID по i2pd:
        //    ((!new_key || key_id == 0) && keyID_rcv == key_id)
        // || (new_key && keyID_rcv == key_id - 1)
        let expected = if !ratchet.new_key || ratchet.key_id == 0 {
            ratchet.key_id
        } else {
            ratchet.key_id - 1 // safe: key_id > 0
        };
        if block.key_id != expected {
            return Ok(()); // чужой reverse
        }

        // 2. DH: наш эфемерный × remote pub (из reverse-блока).
        let remote_pub = block.public_key.ok_or(I2PError::Malformed(
            "ecies_ratchet: reverse key without public key",
        ))?;
        let shared_secret = ratchet
            .key
            .as_ref()
            .ok_or(I2PError::Malformed(
                "ecies_ratchet: reverse key without local key",
            ))?
            .agree(&remote_pub)
            .ok_or(I2PError::Malformed("ecies_ratchet: DH agreement failed"))?;
        let mut tagset_key = [0u8; 32];
        hkdf(&shared_secret, &[], b"XDHRatchetTagSet", &mut tagset_key);

        // 3. `parent_root_key` — из **send**-tagset'а (не receive),
        //    так в i2pd (`m_SendTagset->GetNextRootKey()`).
        let parent_root_key = *self
            .send_tagset
            .as_ref()
            .ok_or(I2PError::Malformed("ecies_ratchet: no send tagset"))?
            .next_root_key();

        // 4. Новый send-tagset. tagset_id = 1 + our_key_id + their_key_id.
        let new_tagset_id = 1u16.wrapping_add(ratchet.key_id).wrapping_add(block.key_id);
        let mut new_tagset = RatchetTagSet::new();
        new_tagset.set_tagset_id(new_tagset_id);
        new_tagset.dh_initialize(&parent_root_key, &tagset_key);
        new_tagset.next_session_tag_ratchet();
        self.send_tagset = Some(new_tagset);
        // i2pd: `m_SendForwardKey = false` — именно здесь, а не
        // в `CreatePayload`. Больше forward-key не отправляем.
        self.send_forward_key = false;
        Ok(())
    }

    /// Строит forward-key `NextKey`-блок для `next_send_ratchet`.
    ///
    /// Копия `CreatePayload` из i2pd, ветка `m_SendForwardKey`:
    ///   flags = `new_key` ? `KEY_PRESENT` : `REQUEST_REVERSE`
    ///   if `key_id` == 0: flags |= `REQUEST_REVERSE`
    ///   pubkey включён только когда `new_key`
    #[must_use]
    pub fn build_forward_key_block(&self) -> Option<GarlicBlock> {
        let ratchet = self.next_send_ratchet.as_ref()?;
        let mut flags = if ratchet.new_key {
            NextKeyBlock::KEY_PRESENT_FLAG
        } else {
            NextKeyBlock::REQUEST_REVERSE_KEY_FLAG
        };
        if ratchet.key_id == 0 {
            flags |= NextKeyBlock::REQUEST_REVERSE_KEY_FLAG;
        }
        let block = if ratchet.new_key {
            let key = ratchet.key.as_ref()?;
            NextKeyBlock::with_key(flags, ratchet.key_id, *key.public_key())
        } else {
            NextKeyBlock::without_key(flags, ratchet.key_id)
        };
        Some(GarlicBlock::NextKey(block.to_bytes()))
    }

    /// Строит reverse-key `NextKey`-блок для `next_receive_ratchet`.
    ///
    /// Копия `CreatePayload` из i2pd, ветка `m_SendReverseKey`:
    ///   `key_id_sent` = `new_key` ? `key_id` : `key_id` - 1
    ///   flags = REVERSE | (`new_key` ? `KEY_PRESENT` : 0)
    fn build_reverse_key_block(&self) -> Option<GarlicBlock> {
        let ratchet = self.next_receive_ratchet.as_ref()?;
        let (flags, key_id) = if ratchet.new_key {
            (
                NextKeyBlock::REVERSE_KEY_FLAG | NextKeyBlock::KEY_PRESENT_FLAG,
                ratchet.key_id,
            )
        } else {
            (
                NextKeyBlock::REVERSE_KEY_FLAG,
                ratchet.key_id.wrapping_sub(1),
            )
        };
        let block = if ratchet.new_key {
            let key = ratchet.key.as_ref()?;
            NextKeyBlock::with_key(flags, key_id, *key.public_key())
        } else {
            NextKeyBlock::without_key(flags, key_id)
        };
        Some(GarlicBlock::NextKey(block.to_bytes()))
    }

    /// Создаёт existing session message с данным garlic-payload'ом.
    ///
    /// Использует `send_tagset`. Nonce = `index` (LE u64 в bytes[4..12]),
    /// ad = tag, key = `symm_key(index)`.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — сессия не `Established`;
    /// - [`Error::Malformed`] — send tagset исчерпан (нужен ratchet advance);
    /// - AEAD-ошибки.
    pub fn create_existing_session_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        // Bob после NSR находится в `NewReplySent`, но уже может
        // отправлять существующие сессионные сообщения — так же, как
        // в i2pd `IsReadyToSend() != NewSessionSent`.
        if !matches!(
            self.state,
            SessionState::NewReplySent | SessionState::Established
        ) {
            return Err(I2PError::Malformed(
                "ecies_ratchet: existing session message not in Established/NewReplySent state",
            ));
        }
        // 1. Читаем index ДО генерации тега — так же, как i2pd.
        // 1. Проверяем триггер DH-ratchet'а, не держа borrow.
        let need_ratchet = {
            let tagset = self
                .send_tagset
                .as_ref()
                .ok_or(I2PError::Malformed("ecies_ratchet: no send tagset"))?;
            tagset.next_index() >= TAGSET_MAX_NUM_TAGS && self.next_send_ratchet.is_none()
        };
        if need_ratchet {
            self.new_next_send_ratchet()?;
        }
        // 2. Обычная генерация тега.
        let tagset = self
            .send_tagset
            .as_mut()
            .ok_or(I2PError::Malformed("ecies_ratchet: no send tagset"))?;
        let index = u32::from(tagset.next_index());
        let tag = tagset
            .get_next_session_tag()
            .ok_or(I2PError::Malformed("ecies_ratchet: send tagset exhausted"))?;
        let key = tagset
            .get_symm_key(index)
            .ok_or(I2PError::Malformed("ecies_ratchet: no symm key for index"))?;

        // 2. Nonce: 4 нуля + index LE u64.
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&u64::from(index).to_le_bytes());

        // 3. Encrypt.
        let tag_bytes = tag.to_le_bytes();
        let mut enc = vec![0u8; payload.len() + 16];
        let aead = AeadChaCha20Poly1305::new();
        let n = aead.encrypt(&key, &nonce, &tag_bytes, payload, &mut enc)?;
        enc.truncate(n);

        // 4. Wire.
        let mut out = Vec::with_capacity(8 + enc.len());
        out.extend_from_slice(&tag_bytes);
        out.extend_from_slice(&enc);
        Ok(out)
    }

    /// Принимает existing session message.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — сессия не `Established`;
    /// - [`Error::InvalidLength`] — буфер короче 24 байт;
    /// - [`Error::Malformed`] — tag неизвестен (нет в карте);
    /// - AEAD-ошибки (провал аутентификации).
    pub fn handle_existing_session_message(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        if !matches!(
            self.state,
            SessionState::NewReplySent | SessionState::Established
        ) {
            return Err(I2PError::Malformed(
                "ecies_ratchet: handle existing message not in Established/NewReplySent state",
            ));
        }
        if buf.len() < 8 + 16 {
            return Err(I2PError::InvalidLength {
                expected: 8 + 16,
                got: buf.len(),
            });
        }
        let mut tag_bytes = [0u8; 8];
        tag_bytes.copy_from_slice(&buf[0..8]);
        let tag = u64::from_le_bytes(tag_bytes);
        let enc_payload = &buf[8..];

        // 1. Ищем tag в карте.
        let (tagset_id, index) = self
            .receive_tags
            .remove(&tag)
            .ok_or(I2PError::Malformed("ecies_ratchet: unknown session tag"))?;

        // i2pd `HandleNextMessage`: если пришло сообщение на новом
        // receive-tagset'е — значит Alice сделала DH и уже использует
        // новый tagset для отправки. Это подтверждает, что reverse-key
        // дошёл; перестаём его ретранслировать.
        if self.send_reverse_key
            && let Some(ratchet) = self.next_receive_ratchet.as_ref()
            && tagset_id == ratchet.receive_tagset_id()
        {
            self.send_reverse_key = false;
        }
        let tagset = self
            .receive_tagsets
            .get_mut(usize::from(tagset_id))
            .ok_or(I2PError::Malformed("ecies_ratchet: tagset_id out of range"))?;
        let key = tagset
            .get_symm_key(index)
            .ok_or(I2PError::Malformed("ecies_ratchet: no symm key for index"))?;

        // 3. Nonce.
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&u64::from(index).to_le_bytes());

        // 4. Decrypt.
        let mut payload = vec![0u8; enc_payload.len() - 16];
        let aead = AeadChaCha20Poly1305::new();
        let n = aead.decrypt(&key, &nonce, &tag_bytes, enc_payload, &mut payload)?;
        payload.truncate(n);

        // 5. Bob переходит в Established при первом входящем сообщении
        //    (это подтверждение, что NSR дошёл до Alice).
        if self.state == SessionState::NewReplySent {
            self.state = SessionState::Established;
        }

        // 6. Запоминаем, на какое сообщение отвечать `Ack`, если в
        //    payload'е окажется `AckRequest` — i2pd кладёт в
        //    `m_AckRequests` ровно эту пару (`HandlePayload`,
        //    `:442`).
        let index_pair = u16::try_from(index)
            .map_err(|_| I2PError::Malformed("ecies_ratchet: tag index out of range"))?;
        self.last_received = Some((tagset_id, index_pair));

        // 7. Пополняем карту.
        self.refill_receive_tags()?;
        Ok(payload)
    }

    /// Число "заряженных" входящих тегов. Для тестов и диагностики.
    #[must_use]
    pub fn num_receive_tags(&self) -> usize {
        self.receive_tags.len()
    }
    /// Есть ли у сессии в карте `receive_tags` указанный тег.
    ///
    /// Используется [`crate::ecies_destination::EciesGarlicDestination`]
    /// для диспетчеризации входящих existing-session сообщений.
    #[must_use]
    pub fn has_receive_tag(&self, tag: u64) -> bool {
        self.receive_tags.contains_key(&tag)
    }

    /// Ждёт ли эта сессия NSR и совпадает ли `tag` с ожидаемым.
    ///
    /// Не потребляет тег — реальная обработка NSR сдвинет tag-set.
    /// Используется [`crate::ecies_destination::EciesGarlicDestination`]
    /// для диспетчеризации NSR на стороне Alice.
    #[must_use]
    pub fn matches_nsr_tag(&self, tag: u64) -> bool {
        if self.state != SessionState::NewSent {
            return false;
        }
        let Some(tagset) = &self.nsr_receive_tagset else {
            return false;
        };
        let Some(expected) = tagset.peek_next_session_tag() else {
            return false;
        };
        expected == tag
    }
    /// Bob должен ответить NSR'ом — вызывающий проверяет после
    /// [`Self::handle_blocks`].
    ///
    /// Соответствует `IsResponseRequired()` в i2pd, но только для
    /// фазы установления.
    #[must_use]
    pub const fn needs_reply(&self) -> bool {
        matches!(self.state, SessionState::NewReceived)
    }

    /// Оборачивает список clove'ов в wire-сообщение.
    ///
    /// Каждый clove превращается в `GarlicBlock::EciesGarlicClove`; кроме
    /// них, метод добавляет служебные блоки. Порядок — как в i2pd
    /// `CreatePayload`: `AckRequest`, cloves, `Ack`, `NextKey`
    /// (reverse, затем forward).
    ///
    /// `now_ms` нужен только для `AckRequest` (см. `plan_ack_request`);
    /// в NS/NSR он не используется.
    ///
    /// Тип сообщения выбирается по состоянию:
    /// - `New` — NS (Alice инициирует);
    /// - `NewReceived` — NSR (Bob отвечает);
    /// - `NewReplySent`, `Established` — existing session message;
    /// - `NewSent` — ошибка (Alice ждёт NSR).
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — состояние не позволяет отправить;
    /// - ошибки сериализации блоков и AEAD.
    pub fn wrap_blocks(&mut self, now_ms: u64, cloves: &[EciesGarlicClove]) -> Result<Vec<u8>> {
        self.wrap_blocks_extra(now_ms, cloves, &[])
    }

    /// То же, что [`Self::wrap_blocks`], но с дополнительными блоками
    /// `extra`, которые ставятся **сразу после clove'ов** и до
    /// служебных `Ack`/`NextKey`.
    ///
    /// Нужен для проверок на живом i2pd (POC вредоносных блоков):
    /// так можно гарантировать, что наш блок окажется первым блоком
    /// своего типа в payload'е, раньше автоматических `NextKey`.
    ///
    /// Порядок: `AckRequest`, cloves, `extra`, `Ack`, `NextKey`
    /// (reverse, затем forward) — та же схема, что в
    /// [`Self::wrap_blocks`], только с врезкой.
    ///
    /// # Errors
    ///
    /// См. [`Self::wrap_blocks`].
    pub fn wrap_blocks_extra(
        &mut self,
        now_ms: u64,
        cloves: &[EciesGarlicClove],
        extra: &[GarlicBlock],
    ) -> Result<Vec<u8>> {
        let mut blocks: Vec<GarlicBlock> = Vec::with_capacity(cloves.len() + extra.len() + 3);

        // `AckRequest` — i2pd пишет его **перед** clove'ом
        // (`CreatePayload`, `:1240`).
        if self.plan_ack_request(now_ms) {
            blocks.push(GarlicBlock::AckRequest);
        }

        for clove in cloves {
            blocks.push(GarlicBlock::EciesGarlicClove(clove.clone()));
        }
        blocks.extend_from_slice(extra);

        // `Ack` — после clove'а (`CreatePayload`, `:1246`); очередь пар
        // опустошается: повторять `Ack` без нового `AckRequest` не нужно.
        if !self.ack_requests.is_empty() {
            let pairs = std::mem::take(&mut self.ack_requests);
            debug!(
                pairs = pairs.len(),
                "ecies_ratchet: sending Ack for received messages"
            );
            blocks.push(GarlicBlock::Ack(pairs));
        }

        // `send_reverse_key` — аналогично, до момента, пока не
        // появится новый forward. Сбрасывать не надо: повторные
        // reverse-key-блоки peer игнорирует как дубликаты.
        if self.send_reverse_key
            && let Some(b) = self.build_reverse_key_block()
        {
            blocks.push(b);
        }
        // `send_forward_key` НЕ сбрасывается здесь: i2pd держит его,
        // пока не придёт reverse-key (см. `HandleNextKey`). Это даёт
        // ретрансмиссию — блок уходит в каждом outgoing-сообщении,
        // пока peer не ответит.
        if self.send_forward_key
            && let Some(b) = self.build_forward_key_block()
        {
            blocks.push(b);
        }

        let payload = serialize_blocks(&blocks)?;
        match self.state {
            SessionState::New => self.create_new_session_message(&payload),
            SessionState::NewReceived => self.create_new_session_reply_message(&payload),
            SessionState::NewReplySent | SessionState::Established => {
                self.create_existing_session_message(&payload)
            }
            SessionState::NewSent => Err(I2PError::Malformed(
                "ecies_ratchet: waiting for NSR, cannot send",
            )),
        }
    }

    /// Решает, добавлять ли `AckRequest` в это сообщение — i2pd
    /// `CreatePayload` (`:1186`).
    ///
    /// Запрос шлётся в двух случаях:
    ///
    /// - «обычный»: ничего не ждём и прошёл
    ///   [`Self::ack_request_interval_ms`];
    /// - «повтор»: ждём подтверждения дольше
    ///   [`ACK_REQUEST_RETRY_TIMEOUT_MS`] — тогда просим заново про
    ///   **новое** сообщение (i2pd тоже переписывает
    ///   `m_AckRequestMsgID`).
    ///
    /// В NS/NSR (`first` у i2pd) запрос не шлётся; в самых первых
    /// сообщениях сессии `msgID` равен `0`, что для i2pd означает
    /// «запроса нет» — такой `AckRequest` пропускаем.
    fn plan_ack_request(&mut self, now_ms: u64) -> bool {
        if self.state != SessionState::Established {
            return false;
        }
        let regular = self.ack_request_msg_id == 0
            && now_ms > self.last_ack_request_sent_ms + self.ack_request_interval_ms;
        let retry = self.ack_request_msg_id != 0
            && now_ms > self.last_ack_request_sent_ms + ACK_REQUEST_RETRY_TIMEOUT_MS;
        if !regular && !retry {
            return false;
        }
        let msg_id = self.send_tagset.as_ref().map_or(0, RatchetTagSet::msg_id);
        if msg_id == 0 {
            return false;
        }
        self.ack_request_msg_id = msg_id;
        self.ack_request_attempts = self.ack_request_attempts.saturating_add(1);
        self.last_ack_request_sent_ms = now_ms;
        debug!(
            msg_id,
            attempts = self.ack_request_attempts,
            retry,
            "ecies_ratchet: requesting Ack"
        );
        true
    }

    /// Принимает wire-сообщение и возвращает распарсенные garlic-cloves.
    ///
    /// Тип сообщения определяется по состоянию:
    /// - `New` — ожидаем NS (Bob);
    /// - `NewSent` — ожидаем NSR (Alice);
    /// - `NewReplySent`, `Established` — existing session message;
    /// - `NewReceived` — ошибка (Bob должен отправить NSR, а не принимать).
    ///
    /// Внутренние блоки (`NextKey`, `Termination`, `DateTime`, `Padding`,
    /// `SessionId`, `Options`, `Unknown`) обрабатываются самой сессией и
    /// **не** попадают в возвращаемый список. `AckRequest`, попавший в
    /// это сообщение, ставит его пару `(tagset_id, index)` в очередь на
    /// `Ack` (уйдёт в следующем [`Self::wrap_blocks`]); `Ack`
    /// подтверждает наши `msgID` и копится в
    /// [`Self::take_confirmed_msg_ids`]. Caller видит только те cloves,
    /// которые реально предназначены ему.
    ///
    /// После успеха, если [`Self::needs_reply`] вернёт `true`, caller
    /// должен вызвать [`Self::wrap_blocks`] с ответными clove'ами
    /// (возможно, пустыми) — так отправляется NSR.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — состояние не позволяет принять;
    /// - AEAD-ошибки, ошибки длины;
    /// - ошибки разбора блоков.
    pub fn handle_blocks(&mut self, buf: &[u8]) -> Result<Vec<EciesGarlicClove>> {
        if buf.len() < 8 {
            return Err(I2PError::InvalidLength {
                expected: 8,
                got: buf.len(),
            });
        }

        // Пары для `Ack` относятся только к тому сообщению, в котором
        // пришёл `AckRequest`; у NS/NSR такой пары быть не может.
        self.last_received = None;

        // Peek tagset_id до вызова `handle_existing_session_message`:
        // сама функция удаляет тег из карты, после чего информацию
        // о tagset'е уже не достать. Для NS/NSR NextKey не приходит,
        // поэтому `None`.
        let tagset_id_for_dispatch = if matches!(
            self.state,
            SessionState::NewReplySent | SessionState::Established
        ) {
            let mut tb = [0u8; 8];
            tb.copy_from_slice(&buf[..8]);
            let tag = u64::from_le_bytes(tb);
            self.receive_tags.get(&tag).map(|(id, _)| *id)
        } else {
            None
        };

        let payload = match self.state {
            SessionState::New => self.handle_new_session_message(buf)?,
            SessionState::NewSent => self.handle_new_session_reply_message(buf)?,
            SessionState::NewReplySent | SessionState::Established => {
                self.handle_existing_session_message(buf)?
            }
            SessionState::NewReceived => {
                return Err(I2PError::Malformed(
                    "ecies_ratchet: waiting to send NSR, cannot receive",
                ));
            }
        };
        let blocks = parse_blocks(&payload)?;
        let mut cloves = Vec::new();
        for block in blocks {
            match block {
                GarlicBlock::EciesGarlicClove(clove) => cloves.push(clove),
                GarlicBlock::NextKey(raw) => {
                    if let Some(id) = tagset_id_for_dispatch {
                        self.handle_next_key_block(id, &raw)?;
                    }
                    // NS/NSR не должны содержать NextKey; если пришло —
                    // игнорируем.
                }
                GarlicBlock::Ack(pairs) => {
                    for (tagset_id, index) in pairs {
                        let msg_id = (u32::from(tagset_id) << 16) | u32::from(index);
                        debug!(msg_id, "ecies_ratchet: Ack received");
                        self.confirm_msg_id(msg_id);
                    }
                }
                GarlicBlock::AckRequest => {
                    // i2pd `HandlePayload` (`:442`): подтверждаем то
                    // сообщение, в котором пришёл запрос.
                    if let Some(pair) = self.last_received {
                        debug!(
                            tagset_id = pair.0,
                            index = pair.1,
                            "ecies_ratchet: AckRequest received; will Ack"
                        );
                        self.ack_requests.push(pair);
                    }
                }
                GarlicBlock::Termination { .. } => {
                    // i2pd: `RemoveECIESx25519Session` + `receiveTagset->Expire()`.
                    // У нас владелец сессии — caller, поэтому только
                    // помечаем; удаление делает `EciesGarlicDestination`.
                    self.is_terminated = true;
                }
                GarlicBlock::DateTime(_)
                | GarlicBlock::Padding(_)
                | GarlicBlock::SessionId(_)
                | GarlicBlock::Options(_)
                | GarlicBlock::Unknown { .. } => {
                    // DateTime — clock-skew проверка отложена до
                    // момента, когда появится реальное системное время.
                    //
                    // Padding / SessionId / Options / Unknown —
                    // заполнители, обработки не требуют.
                }
            }
        }
        Ok(cloves)
    }

    /// Все активные receive-tagset'ы сессии, старейший первым.
    ///
    /// Индекс в срезе — это `tagset_id`. Обычно содержит один элемент;
    /// два — короткое окно сразу после DH-ratchet'а.
    #[must_use]
    pub fn receive_tagsets(&self) -> &[RatchetTagSet] {
        &self.receive_tagsets
    }
    /// Первый (самый старый) receive-tagset. Удобно для
    /// однозначных случаев — но при `receive_tagsets.len() > 1`
    /// используй [`Self::receive_tagsets`].
    #[must_use]
    pub fn receive_tagset(&self) -> Option<&RatchetTagSet> {
        self.receive_tagsets.first()
    }
    /// Количество активных receive-tagset'ов. Обычно 1; 2 — короткое
    /// окно сразу после DH-ratchet'а. Для тестов и диагностики.
    #[must_use]
    pub const fn num_receive_tagsets(&self) -> usize {
        self.receive_tagsets.len()
    }
    /// Сессия закрыта — `Termination` прислан peer'ом или отправлен
    /// нами. Такую сессию нужно удалить из [`crate::ecies_destination::EciesGarlicDestination`];
    /// повторное использование не предусмотрено.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.is_terminated
    }

    /// `msgID` сообщения, подтверждение которого мы ждём — i2pd
    /// `m_AckRequestMsgID`. `0` — не ждём.
    #[must_use]
    pub const fn ack_request_msg_id(&self) -> u32 {
        self.ack_request_msg_id
    }

    /// Сколько раз просили подтверждение для текущего `msgID` — i2pd
    /// `m_AckRequestNumAttempts`.
    #[must_use]
    pub const fn ack_request_attempts(&self) -> u32 {
        self.ack_request_attempts
    }

    /// Сколько пар ждёт отправки в ближайшем `Ack`. Для тестов и
    /// диагностики.
    #[must_use]
    pub const fn pending_ack_requests(&self) -> usize {
        self.ack_requests.len()
    }

    /// Забирает `msgID`, подтверждённые пришедшими `Ack` — i2pd
    /// `MessageConfirmed`. Порядок — как пришли.
    #[must_use]
    pub fn take_confirmed_msg_ids(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.confirmed_msg_ids)
    }

    /// Интервал обычных `AckRequest`, мс — i2pd
    /// `SetAckRequestInterval` (`:196`). В i2pd его уменьшает
    /// datagram-сессия (`DATAGRAM_SESSION_ACK_REQUEST_INTERVAL` = 5500).
    pub const fn set_ack_request_interval(&mut self, interval_ms: u64) {
        self.ack_request_interval_ms = interval_ms;
    }

    /// i2pd `CleanupUnconfirmedTags` (`:254`): подтверждение так и не
    /// пришло за [`ACK_REQUEST_MAX_NUM_ATTEMPTS`] попыток — забываем
    /// текущий `msgID`.
    ///
    /// Возвращает `true`, если запрос был забыт. В i2pd это зовётся
    /// периодически (`GarlicDestination::CleanupExpiredTags`); у нас
    /// момент выбирает владелец сессии.
    #[must_use]
    pub fn cleanup_unconfirmed_tags(&mut self) -> bool {
        if self.ack_request_msg_id != 0 && self.ack_request_attempts > ACK_REQUEST_MAX_NUM_ATTEMPTS
        {
            debug!(
                msg_id = self.ack_request_msg_id,
                attempts = self.ack_request_attempts,
                "ecies_ratchet: dropping unconfirmed Ack request"
            );
            self.ack_request_msg_id = 0;
            self.ack_request_attempts = 0;
            return true;
        }
        false
    }

    /// `MessageConfirmed(msgID)` — i2pd `:242`: принятый `Ack` снимает
    /// наш `AckRequest` и попадает в список подтверждённых.
    fn confirm_msg_id(&mut self, msg_id: u32) {
        if self.ack_request_msg_id != 0 && self.ack_request_msg_id == msg_id {
            self.ack_request_msg_id = 0;
            self.ack_request_attempts = 0;
        }
        if self.confirmed_msg_ids.len() >= CONFIRMED_MSG_IDS_CAP {
            self.confirmed_msg_ids.remove(0);
        }
        self.confirmed_msg_ids.push(msg_id);
    }

    /// Отправляет `Termination`-блок peer'у и помечает сессию закрытой.
    ///
    /// Возвращает wire-сообщение для отправки. После успешного вызова
    /// [`Self::is_terminated`] вернёт `true`; caller должен отправить
    /// wire и удалить сессию.
    ///
    /// # Errors
    ///
    /// См. [`Self::create_existing_session_message`].
    pub fn send_termination(&mut self) -> Result<Vec<u8>> {
        let blocks = vec![GarlicBlock::Termination { seqn: 0, reason: 0 }];
        let payload = serialize_blocks(&blocks)?;
        let wire = self.create_existing_session_message(&payload)?;
        self.is_terminated = true;
        Ok(wire)
    }
    /// Последний (самый новый) receive-tagset.
    #[must_use]
    pub fn current_receive_tagset(&self) -> Option<&RatchetTagSet> {
        self.receive_tagsets.last()
    }
}

/// Оборачивает garlic-clove'ы в «симметричное» ECIES-garlic сообщение —
/// ответ на `DatabaseLookup`, в котором запрашивающий заранее прислал
/// одноразовый симметричный ключ и тег (`replyKey` / `replyTag`).
///
/// Зеркало `WrapECIESX25519Message` из i2pd
/// (`ECIESX25519AEADRatchetSession.cpp`): так floodfill отвечает на
/// зашифрованный lookup, не устанавливая сессию:
///
/// ```text
///   tag(8) || AEAD_ChaCha20Poly1305(blocks, key, nonce = 0, AD = tag)
/// ```
///
/// `tag` пишется в host-порядке (i2pd делает `memcpy` из `uint64_t`,
/// т.е. little-endian на всех поддерживаемых платформах) — так же, как
/// его ищет `GarlicDestination::HandleECIESx25519TagMessage`.
///
/// Получатель (`SymmetricKeyTagSet::HandleNextMessage`) расшифровывает
/// payload тем же ключом и требует, чтобы **первым** блоком был clove;
/// `DateTime`/`Padding` i2pd сюда не пишет, не пишем и мы.
///
/// # Errors
///
/// Ошибки [`serialize_blocks`] и AEAD.
pub fn wrap_symmetric_message(
    key: &[u8; 32],
    tag: u64,
    cloves: &[EciesGarlicClove],
) -> Result<Vec<u8>> {
    let blocks: Vec<GarlicBlock> = cloves
        .iter()
        .map(|c| GarlicBlock::EciesGarlicClove(c.clone()))
        .collect();
    let plaintext = serialize_blocks(&blocks)?;

    let tag_bytes = tag.to_le_bytes();
    let nonce = [0u8; 12];
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let len = AeadChaCha20Poly1305::new().encrypt(
        key,
        &nonce,
        &tag_bytes,
        &plaintext,
        &mut ciphertext,
    )?;
    ciphertext.truncate(len);

    let mut wire = Vec::with_capacity(8 + ciphertext.len());
    wire.extend_from_slice(&tag_bytes);
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}
