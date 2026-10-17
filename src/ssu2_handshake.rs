//! SSU2 — handshake (Noise XK), первые два сообщения.
//!
//! Слой поверх [`crate::ssu2_header`] и [`crate::ssu2_crypto`]: он связывает
//! разбор/обфускацию заголовков, крипто-примитивы и блоки payload'а в
//! реальные пакеты handshake.
//!
//! Реализованы:
//!
//! - `SessionRequest` (Alice -> Bob): [`InitiatorHandshake::build_session_request`]
//!   и [`ResponderHandshake::handle_session_request`];
//! - `SessionCreated` (Bob -> Alice): [`ResponderHandshake::build_session_created`]
//!   и [`InitiatorHandshake::handle_session_created`].
//!
//! Функции повторяют i2pd (`SendSessionRequest` / `ProcessSessionRequest` /
//! `SendSessionCreated` / `ProcessSessionCreated`) с точностью до порядка
//! `MixHash` / `MixKey` / `Encrypt`.
//!
//! ## Разделение ответственности
//!
//! Модуль отвечает за **фрейминг и Noise-состояние**, а не за наполнение
//! payload'а: вызывающий передаёт уже собранные блоки (`extra_blocks`), а
//! `DateTime` и `Padding` добавляются внутри. Решение о размере padding'а
//! берётся из [`Ssu2Policy`], поэтому handshake параметризован политикой.
//!
//! ## Что дальше
//!
//! - TODO(ssu2-scf): `SessionConfirmed` (part 1 + part 2, фрагментация) —
//!   следующая итерация;
//! - TODO(ssu2-data-keys): вывод ключей data phase на стороне Bob'а — вместе
//!   с `SessionConfirmed` (у Alice
//!   [`derive_data_phase_keys`](crate::ssu2_crypto::derive_data_phase_keys)
//!   применим уже после `SessionCreated`).
//!
//! ## Замечание по длине
//!
//! [`crate::ssu2_header::obfuscate_header`] требует минимум
//! `SSU2_MIN_PACKET_SIZE + extended_header_len` байт (88 для
//! `SessionRequest` / `SessionCreated`): хвостовые IV не должны пересекаться
//! с обфусцируемым регионом. Реальные handshake-пакеты заведомо длиннее
//! (i2pd тоже требует >= 90 / >= 80), поэтому проверка не мешает.

use crate::crypto::{I2PX25519Keys, NoiseSymmetricState};
use crate::error::{I2PError, Result};
use crate::ssu2_block::{write_block, DateTimeBlock, Ssu2Block, Ssu2BlockType};
use crate::ssu2_crypto::{init_noise_ssu2_state, sess_create_header_key};
use crate::ssu2_header::{
    obfuscate_header, ConnectionId, LongHeader, Ssu2MessageType, SSU2_LONG_HEADER_SIZE,
    SSU2_VERSION,
};
use crate::ssu2_policy::{Ssu2Policy, SSU2_MAX_PACKET_SIZE};

/// Минимальная длина `SessionRequest` (i2pd: `len < 90`).
pub const SSU2_SESSION_REQUEST_MIN_LEN: usize = 90;
/// Минимальная длина `SessionCreated` (i2pd: `len < 80`).
pub const SSU2_SESSION_CREATED_MIN_LEN: usize = 80;
/// Размер extended-заголовка `SessionRequest` / `SessionCreated`:
/// source id (8) + token (8) + эфемерный ключ (32).
pub const SSU2_HANDSHAKE_EXT_HEADER_SIZE: usize = 48;
/// Накладные расходы handshake помимо `max_payload_size`: extended-заголовок.
const HANDSHAKE_EXTRA_OVERHEAD: usize = SSU2_HANDSHAKE_EXT_HEADER_SIZE;
/// Максимум padding'а в `SessionRequest`.
const SESSION_REQUEST_MAX_PADDING: usize = 32;
/// Максимум padding'а в `SessionCreated`.
const SESSION_CREATED_MAX_PADDING: usize = 64;

// --- параметры ----------------------------------------------------------

/// Общие параметры handshake для обеих сторон.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeConfig {
    /// Версия протокола (байт 13 заголовка).
    pub version: u8,
    /// Network ID (байт 14 заголовка).
    pub net_id: u8,
    /// Адрес IPv6 (влияет на `max_payload_size`).
    pub ipv6: bool,
    /// MTU пути.
    pub mtu: usize,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            version: SSU2_VERSION,
            net_id: 2, // I2P mainnet
            ipv6: false,
            mtu: SSU2_MAX_PACKET_SIZE,
        }
    }
}

/// Параметры сборки `SessionRequest`.
#[derive(Debug, Clone, Copy)]
pub struct SessionRequestParams {
    /// Destination connection id (id стороны-получателя, т.е. Bob'а).
    pub dest_conn_id: ConnectionId,
    /// Source connection id (id отправителя, т.е. Alice).
    pub source_conn_id: ConnectionId,
    /// Token, полученный ранее (0 — без токена).
    pub token: u64,
    /// Номер пакета (для handshake случаен).
    pub packet_num: u32,
    /// Текущее время, секунды Unix.
    pub now_secs: u32,
    /// Запросить ли `RelayTagRequest`.
    pub relay_tag_requested: bool,
    /// «Бросок» для выбора размера padding'а.
    pub pad_roll: u8,
}

/// Параметры сборки `SessionCreated`.
#[derive(Debug, Clone, Copy)]
pub struct SessionCreatedParams<'a> {
    /// Destination connection id (id Alice).
    pub dest_conn_id: ConnectionId,
    /// Source connection id (id Bob'а).
    pub source_conn_id: ConnectionId,
    /// Номер пакета (для handshake случаен).
    pub packet_num: u32,
    /// Текущее время, секунды Unix.
    pub now_secs: u32,
    /// Дополнительные блоки между `DateTime` и `Padding`
    /// (`Address`, `RelayTag`, `NewToken`, ...), уже с заголовками.
    pub extra_blocks: &'a [u8],
    /// «Бросок» для выбора размера padding'а.
    pub pad_roll: u8,
}

// --- результаты разбора -------------------------------------------------

/// Результат разбора `SessionRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSessionRequest {
    /// Destination connection id из заголовка.
    pub dest_conn_id: ConnectionId,
    /// Source connection id из заголовка (он же — id Alice).
    pub source_conn_id: ConnectionId,
    /// Token из заголовка.
    pub token: u64,
    /// Открытый эфемерный ключ X.
    pub ephemeral: [u8; 32],
    /// Расшифрованный payload.
    pub payload: Vec<u8>,
}

/// Результат разбора `SessionCreated`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSessionCreated {
    /// Destination connection id из заголовка.
    pub dest_conn_id: ConnectionId,
    /// Source connection id из заголовка (он же — id Bob'а).
    pub source_conn_id: ConnectionId,
    /// Открытый эфемерный ключ Y.
    pub ephemeral: [u8; 32],
    /// Расшифрованный payload.
    pub payload: Vec<u8>,
}

// --- вспомогательное ----------------------------------------------------

/// AEAD-шифрование с текущим [`NoiseSymmetricState`], возвращает ciphertext+тег.
fn encrypt_into(noise: &mut NoiseSymmetricState, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    let written = noise.encrypt(plaintext, &mut buf)?;
    buf.truncate(written);
    Ok(buf)
}

/// AEAD-расшифровка с текущим [`NoiseSymmetricState`].
fn decrypt_from(noise: &mut NoiseSymmetricState, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 16 {
        return Err(I2PError::Malformed("ssu2: handshake ciphertext too short"));
    }
    let mut buf = vec![0u8; ciphertext.len() - 16];
    let written = noise.decrypt(ciphertext, &mut buf)?;
    buf.truncate(written);
    Ok(buf)
}

/// Согласие X25519, `Malformed` при низкопорядковом ключе.
fn agree(keys: &I2PX25519Keys, peer: &[u8; 32]) -> Result<[u8; 32]> {
    keys.agree(peer)
        .ok_or(I2PError::Malformed("ssu2: invalid peer X25519 key"))
}

/// Дописывает `Padding` по политике, если он помещается.
fn append_padding<P: Ssu2Policy>(
    policy: &P,
    payload: &mut Vec<u8>,
    avail: usize,
    max_padding: usize,
    roll: u8,
) -> Result<()> {
    if payload.len() > avail {
        return Err(I2PError::Malformed(
            "ssu2: handshake payload exceeds max size",
        ));
    }
    let len = (avail - payload.len()).min(max_padding);
    if let Some(size) = policy.padding_size(roll, len, 0) {
        let zeros = vec![0u8; size];
        write_block(payload, Ssu2BlockType::Padding, &zeros)?;
    }
    Ok(())
}

// --- Alice (инициатор) --------------------------------------------------

/// Состояние handshake инициатора (Alice).
pub struct InitiatorHandshake {
    noise: NoiseSymmetricState,
    local_static: I2PX25519Keys,
    remote_static_pub: [u8; 32],
    intro_key: [u8; 32],
    config: HandshakeConfig,
    ephemeral: Option<I2PX25519Keys>,
    remote_ephemeral_pub: Option<[u8; 32]>,
}

impl InitiatorHandshake {
    /// Создаёт инициатора. `remote_static_pub` — статический ключ `s` Bob'а,
    /// `intro_key` — intro-ключ `i` Bob'а (для обфускации заголовков).
    #[must_use]
    pub fn new(
        local_static: I2PX25519Keys,
        remote_static_pub: [u8; 32],
        intro_key: [u8; 32],
        config: HandshakeConfig,
    ) -> Self {
        let mut noise = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        init_noise_ssu2_state(&mut noise, &remote_static_pub);
        Self {
            noise,
            local_static,
            remote_static_pub,
            intro_key,
            config,
            ephemeral: None,
            remote_ephemeral_pub: None,
        }
    }

    /// Текущий chaining key (для кросс-проверки с ответчиком).
    #[must_use]
    pub const fn chain_key(&self) -> &[u8; 32] {
        &self.noise.ck
    }

    /// Публичный статический ключ Alice.
    #[must_use]
    pub fn static_public(&self) -> &[u8; 32] {
        self.local_static.public_key()
    }

    /// Публичный эфемерный ключ Bob'а, полученный из `SessionCreated`.
    #[must_use]
    pub const fn remote_ephemeral_public(&self) -> Option<&[u8; 32]> {
        self.remote_ephemeral_pub.as_ref()
    }

    /// Собирает `SessionRequest`: генерирует эфемерный ключ, проходит шаги
    /// Noise XK и возвращает готовый пакет.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если payload не влезает или key agreement не
    /// удался; ошибки обфускации заголовка.
    pub fn build_session_request<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        params: &SessionRequestParams,
    ) -> Result<Vec<u8>> {
        let ephemeral = I2PX25519Keys::generate();

        let mut payload = Vec::new();
        DateTimeBlock {
            timestamp: params.now_secs,
        }
        .write(&mut payload)?;
        if params.relay_tag_requested {
            write_block(&mut payload, Ssu2BlockType::RelayTagRequest, &[])?;
        }
        let max_payload = policy.max_payload_size(self.config.ipv6, self.config.mtu);
        let avail = max_payload.saturating_sub(HANDSHAKE_EXTRA_OVERHEAD);
        append_padding(
            policy,
            &mut payload,
            avail,
            SESSION_REQUEST_MAX_PADDING,
            params.pad_roll,
        )?;

        let header = LongHeader {
            dest_conn_id: params.dest_conn_id,
            packet_num: params.packet_num,
            msg_type: Ssu2MessageType::SessionRequest,
            version: self.config.version,
            net_id: self.config.net_id,
            flag: 0,
            source_conn_id: params.source_conn_id,
            token: params.token,
        };
        let mut packet = Vec::with_capacity(SSU2_LONG_HEADER_SIZE + 32 + payload.len() + 16);
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(ephemeral.public_key());

        // Noise: h = SHA256(h || header || headerX[0..16]); h = SHA256(h || aepk);
        // ck = HKDF(ck, DH(a_e, b_s)).
        self.noise
            .mix_hash_multi(&[&packet[0..16], &packet[16..32]]);
        self.noise.mix_hash(ephemeral.public_key());
        let shared = agree(&ephemeral, &self.remote_static_pub)?;
        self.noise.mix_key(&shared);

        let ciphertext = encrypt_into(&mut self.noise, &payload)?;
        packet.extend_from_slice(&ciphertext);
        obfuscate_header(
            Ssu2MessageType::SessionRequest,
            &self.intro_key,
            &self.intro_key,
            &mut packet,
        )?;
        self.noise.mix_hash(&ciphertext);

        self.ephemeral = Some(ephemeral);
        Ok(packet)
    }

    /// Разбирает `SessionCreated`, проходит шаги Noise XK и возвращает payload.
    ///
    /// Пакет деобфусцируется **на месте**.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] при слишком коротком пакете;
    /// [`Error::Malformed`] при неверном типе/ключе/теге, [`Error::Unsupported`]
    /// при неподдерживаемой версии.
    pub fn handle_session_created<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        packet: &mut [u8],
    ) -> Result<ReceivedSessionCreated> {
        if packet.len() < SSU2_SESSION_CREATED_MIN_LEN {
            return Err(I2PError::InvalidLength {
                expected: SSU2_SESSION_CREATED_MIN_LEN,
                got: packet.len(),
            });
        }
        if packet.len() > policy.max_packet_size() {
            return Err(I2PError::Malformed("ssu2: SessionCreated too long"));
        }
        let kh2 = sess_create_header_key(&self.noise.ck);
        obfuscate_header(
            Ssu2MessageType::SessionCreated,
            &self.intro_key,
            &kh2,
            packet,
        )?;
        let header = LongHeader::parse(&packet[..SSU2_LONG_HEADER_SIZE])?;
        if header.msg_type != Ssu2MessageType::SessionCreated {
            return Err(I2PError::Malformed("ssu2: expected SessionCreated"));
        }
        if header.version != SSU2_VERSION {
            return Err(I2PError::Unsupported("ssu2: unsupported protocol version"));
        }

        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&packet[32..64]);
        self.noise
            .mix_hash_multi(&[&packet[0..16], &packet[16..32]]);
        self.noise.mix_hash(&ephemeral);
        let local = self.ephemeral.as_ref().ok_or(I2PError::Malformed(
            "ssu2: SessionCreated before SessionRequest",
        ))?;
        let shared = agree(local, &ephemeral)?;
        self.noise.mix_key(&shared);

        let ciphertext = &packet[64..];
        let payload = decrypt_from(&mut self.noise, ciphertext)?;
        self.noise.mix_hash(ciphertext);

        self.remote_ephemeral_pub = Some(ephemeral);
        Ok(ReceivedSessionCreated {
            dest_conn_id: header.dest_conn_id,
            source_conn_id: header.source_conn_id,
            ephemeral,
            payload,
        })
    }

    // TODO(ssu2-scf): `build_session_confirmed` — part 1 (зашифрованный
    // статический ключ Alice) + part 2 (RouterInfo + padding), KDF
    // `k_header_2 = HKDF(ck, "", "SessionConfirmed", 32)`, при нехватке места
    // разбиение на 2 фрагмента.
    // TODO(ssu2-data-keys): после `SessionCreated` сохранить
    // `derive_data_phase_keys(&self.noise.ck)` как ключи направления ab.
}

// --- Bob (ответчик) -----------------------------------------------------

/// Состояние handshake ответчика (Bob).
pub struct ResponderHandshake {
    noise: NoiseSymmetricState,
    local_static: I2PX25519Keys,
    intro_key: [u8; 32],
    config: HandshakeConfig,
    ephemeral: Option<I2PX25519Keys>,
    remote_ephemeral_pub: Option<[u8; 32]>,
}

impl ResponderHandshake {
    /// Создаёт ответчика. `intro_key` — собственный intro-ключ `i` Bob'а.
    #[must_use]
    pub fn new(local_static: I2PX25519Keys, intro_key: [u8; 32], config: HandshakeConfig) -> Self {
        let mut noise = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        init_noise_ssu2_state(&mut noise, local_static.public_key());
        Self {
            noise,
            local_static,
            intro_key,
            config,
            ephemeral: None,
            remote_ephemeral_pub: None,
        }
    }

    /// Текущий chaining key (для кросс-проверки с инициатором).
    #[must_use]
    pub const fn chain_key(&self) -> &[u8; 32] {
        &self.noise.ck
    }

    /// Публичный эфемерный ключ Bob'а (Y из `SessionCreated`).
    #[must_use]
    pub fn ephemeral_public(&self) -> Option<&[u8; 32]> {
        self.ephemeral.as_ref().map(I2PX25519Keys::public_key)
    }

    /// Разбирает `SessionRequest`: деобфусцирует заголовок, проходит шаги
    /// Noise XK и возвращает payload.
    ///
    /// Пакет деобфусцируется **на месте**. Token не проверяется — это
    /// решение уровня сессии/сервера.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] при слишком коротком пакете;
    /// [`Error::Malformed`] при неверном типе/ключе/теге, [`Error::Unsupported`]
    /// при неподдерживаемой версии.
    pub fn handle_session_request<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        packet: &mut [u8],
    ) -> Result<ReceivedSessionRequest> {
        if packet.len() < SSU2_SESSION_REQUEST_MIN_LEN {
            return Err(I2PError::InvalidLength {
                expected: SSU2_SESSION_REQUEST_MIN_LEN,
                got: packet.len(),
            });
        }
        if packet.len() > policy.max_packet_size() {
            return Err(I2PError::Malformed("ssu2: SessionRequest too long"));
        }
        obfuscate_header(
            Ssu2MessageType::SessionRequest,
            &self.intro_key,
            &self.intro_key,
            packet,
        )?;
        let header = LongHeader::parse(&packet[..SSU2_LONG_HEADER_SIZE])?;
        if header.msg_type != Ssu2MessageType::SessionRequest {
            return Err(I2PError::Malformed("ssu2: expected SessionRequest"));
        }
        if header.version != SSU2_VERSION {
            return Err(I2PError::Unsupported("ssu2: unsupported protocol version"));
        }

        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&packet[32..64]);
        self.noise
            .mix_hash_multi(&[&packet[0..16], &packet[16..32]]);
        self.noise.mix_hash(&ephemeral);
        let shared = agree(&self.local_static, &ephemeral)?;
        self.noise.mix_key(&shared);

        let ciphertext = &packet[64..];
        let payload = decrypt_from(&mut self.noise, ciphertext)?;
        self.noise.mix_hash(ciphertext);

        self.remote_ephemeral_pub = Some(ephemeral);
        Ok(ReceivedSessionRequest {
            dest_conn_id: header.dest_conn_id,
            source_conn_id: header.source_conn_id,
            token: header.token,
            ephemeral,
            payload,
        })
    }

    /// Собирает `SessionCreated`: генерирует эфемерный ключ, проходит шаги
    /// Noise XK и возвращает готовый пакет.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если payload не влезает, key agreement не удался
    /// или `SessionRequest` ещё не обработан; ошибки обфускации заголовка.
    pub fn build_session_created<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        params: &SessionCreatedParams<'_>,
    ) -> Result<Vec<u8>> {
        let ephemeral = I2PX25519Keys::generate();
        let kh2 = sess_create_header_key(&self.noise.ck);

        let mut payload = Vec::new();
        DateTimeBlock {
            timestamp: params.now_secs,
        }
        .write(&mut payload)?;
        payload.extend_from_slice(params.extra_blocks);
        let max_payload = policy.max_payload_size(self.config.ipv6, self.config.mtu);
        let avail = max_payload.saturating_sub(HANDSHAKE_EXTRA_OVERHEAD);
        append_padding(
            policy,
            &mut payload,
            avail,
            SESSION_CREATED_MAX_PADDING,
            params.pad_roll,
        )?;

        let header = LongHeader {
            dest_conn_id: params.dest_conn_id,
            packet_num: params.packet_num,
            msg_type: Ssu2MessageType::SessionCreated,
            version: self.config.version,
            net_id: self.config.net_id,
            flag: 0,
            source_conn_id: params.source_conn_id,
            token: 0,
        };
        let mut packet = Vec::with_capacity(SSU2_LONG_HEADER_SIZE + 32 + payload.len() + 16);
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(ephemeral.public_key());

        self.noise
            .mix_hash_multi(&[&packet[0..16], &packet[16..32]]);
        self.noise.mix_hash(ephemeral.public_key());
        let remote = self.remote_ephemeral_pub.ok_or(I2PError::Malformed(
            "ssu2: SessionCreated before SessionRequest",
        ))?;
        let shared = agree(&ephemeral, &remote)?;
        self.noise.mix_key(&shared);

        let ciphertext = encrypt_into(&mut self.noise, &payload)?;
        packet.extend_from_slice(&ciphertext);
        obfuscate_header(
            Ssu2MessageType::SessionCreated,
            &self.intro_key,
            &kh2,
            &mut packet,
        )?;
        self.noise.mix_hash(&ciphertext);

        self.ephemeral = Some(ephemeral);
        Ok(packet)
    }

    // TODO(ssu2-scf): `handle_session_confirmed` — разбор part 1 / part 2,
    // сборка фрагментов (frag/total в коротком заголовке), проверка
    // RouterInfo и статического ключа.
    // TODO(ssu2-data-keys): после part 2 сохранить
    // `derive_data_phase_keys(&self.noise.ck)` как ключи направления ba.
}
