//! SSU2 — handshake (Noise XK), три сообщения.
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
//!   и [`InitiatorHandshake::handle_session_created`];
//! - `SessionConfirmed` (Alice -> Bob, с фрагментацией на 2 пакета):
//!   [`InitiatorHandshake::build_session_confirmed`] и
//!   [`ResponderHandshake::handle_session_confirmed`].
//!
//! Функции повторяют i2pd (`SendSessionRequest` / `ProcessSessionRequest` /
//! `SendSessionCreated` / `ProcessSessionCreated` / `SendSessionConfirmed` /
//! `ProcessSessionConfirmed`) с точностью до порядка `MixHash` / `MixKey` /
//! `Encrypt`.
//!
//! ## Разделение ответственности
//!
//! Модуль отвечает за **фрейминг и Noise-состояние**, а не за наполнение
//! payload'а: вызывающий передаёт уже собранные блоки (`extra_blocks`), а
//! `DateTime` и `Padding` добавляются внутри. Решение о размере padding'а
//! берётся из [`Ssu2Policy`], поэтому handshake параметризован политикой.
//! `SessionConfirmed` принимает «сырой» `RouterInfo`: блок собирается внутри.
//!
//! ## Ключи data phase
//!
//! После завершения handshake обе стороны выводят ключи data phase
//! ([`derive_data_phase_keys`](crate::ssu2_crypto::derive_data_phase_keys)):
//! Alice — после сборки `SessionConfirmed`, Bob — после его разбора; доступны
//! через `data_keys()` обоих хэндшейков.
//!
//! ## Что дальше
//!
//! - TODO(ssu2-scf-multifrag): > 2 фрагментов `SessionConfirmed` (i2pd тоже
//!   ограничен двумя);
//! - [`RouterInfoBlock::verified_router_info`](crate::ssu2_block::RouterInfoBlock::verified_router_info)
//!   разбирает `RouterInfo` (в т.ч. gzip) и проверяет подпись; остальные
//!   проверки (timestamp, версия, совпадение адреса/статического ключа с
//!   рукопожатием) — уровень сессии;
//! - Механика data phase (номера пакетов, сборка/разбор ACK,
//!   переотправки) — [`crate::ssu2_session`].
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
use crate::ssu2_block::{DateTimeBlock, RouterInfoBlock, Ssu2Block, Ssu2BlockType, write_block};
use crate::ssu2_crypto::{
    DataPhaseKeys, derive_data_phase_keys, init_noise_ssu2_state, sess_create_header_key,
    session_confirmed_header_key,
};
use crate::ssu2_header::{
    ConnectionId, LongHeader, SSU2_HEADER_SIZE, SSU2_LONG_HEADER_SIZE, SSU2_MIN_PACKET_SIZE,
    SSU2_VERSION, ShortHeader, Ssu2MessageType, obfuscate_header,
};
use crate::ssu2_policy::{SSU2_MAX_PACKET_SIZE, Ssu2Policy};

/// Минимальная длина `SessionRequest` (i2pd: `len < 90`).
pub const SSU2_SESSION_REQUEST_MIN_LEN: usize = 90;
/// Минимальная длина `SessionCreated` (i2pd: `len < 80`).
pub const SSU2_SESSION_CREATED_MIN_LEN: usize = 80;
/// Минимальная длина собранного `SessionConfirmed` (i2pd: `len < 83`).
pub const SSU2_SESSION_CONFIRMED_MIN_LEN: usize = 83;
/// Минимальная длина одного фрагмента `SessionConfirmed` (i2pd: `len < 32`).
pub const SSU2_SESSION_CONFIRMED_FRAGMENT_MIN_LEN: usize = 32;
/// Размер extended-заголовка `SessionRequest` / `SessionCreated`:
/// source id (8) + token (8) + эфемерный ключ (32).
pub const SSU2_HANDSHAKE_EXT_HEADER_SIZE: usize = 48;
/// Накладные расходы handshake помимо `max_payload_size`: extended-заголовок.
const HANDSHAKE_EXTRA_OVERHEAD: usize = SSU2_HANDSHAKE_EXT_HEADER_SIZE;
/// Максимум padding'а в `SessionRequest`.
const SESSION_REQUEST_MAX_PADDING: usize = 32;
/// Максимум padding'а в `SessionCreated`.
const SESSION_CREATED_MAX_PADDING: usize = 64;
/// Размер зашифрованного статического ключа `SessionConfirmed` part 1: 32 + 16.
const SESSION_CONFIRMED_PART1_SIZE: usize = 48;
/// Флаг `SessionConfirmed`: один фрагмент.
const CONFIRMED_FLAG_SINGLE: u8 = 0x01;
/// Флаг `SessionConfirmed`: первый из двух фрагментов (frag 0, total 2).
const CONFIRMED_FLAG_FIRST: u8 = 0x02;
/// Флаг `SessionConfirmed`: второй из двух фрагментов (frag 1, total 2).
const CONFIRMED_FLAG_SECOND: u8 = 0x12;
/// Минимальный «хвост» второго фрагмента `SessionConfirmed` (i2pd: `>= 24`).
const CONFIRMED_SECOND_FRAGMENT_MIN: usize = 24;

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

/// Параметры сборки `SessionConfirmed`.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfirmedParams<'a> {
    /// Destination connection id (id Bob'а).
    pub dest_conn_id: ConnectionId,
    /// `RouterInfo` отправителя (не блок, а «сырой» `RouterInfo`).
    pub router_info: &'a [u8],
    /// «Бросок» для выбора размера padding'а.
    pub pad_roll: u8,
    /// «Бросок» для регулировки границы фрагментов (`% 16`).
    pub frag_roll: u8,
}

/// Пакеты `SessionConfirmed`: первый фрагмент и, при нехватке места, второй.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfirmedPackets {
    /// Первый фрагмент (содержит part 1 и начало part 2).
    pub first: Vec<u8>,
    /// Второй фрагмент (продолжение part 2), если `RouterInfo` не влез.
    pub second: Option<Vec<u8>>,
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

/// Результат разбора полного `SessionConfirmed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSessionConfirmed {
    /// Статический ключ Alice (S), расшифрованный из part 1.
    pub static_key: [u8; 32],
    /// Расшифрованный payload part 2 (начинается с блока `RouterInfo`).
    pub payload: Vec<u8>,
}

/// Итог обработки пакета `SessionConfirmed` ответчиком.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmedOutcome {
    /// Пакет собран полностью; handshake завершён на стороне Bob'а.
    Complete(ReceivedSessionConfirmed),
    /// Получен первый (или второй) фрагмент; ждём оставшийся.
    Incomplete,
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

/// Собирает блок `RouterInfo` (`flags`/`frag` = 0/1) в `out`.
///
/// `frag = 1` означает «frag 0 из 1» — блок никогда не фрагментируется на
/// уровне SSU2. Совпадает с `CreateRouterInfoBlock` из i2pd (без gzip).
fn write_router_info_block(out: &mut Vec<u8>, router_info: &[u8]) -> Result<()> {
    RouterInfoBlock {
        flags: 0,
        frag: 1,
        router_info,
    }
    .write(out)
}

/// Незавершённая сборка `SessionConfirmed` из фрагментов (сторона Bob'а).
struct PendingConfirmed {
    /// Заголовок первого фрагмента (уже деобфусцированный).
    header: [u8; SSU2_HEADER_SIZE],
    /// Байты после cover-заголовка (part 1 + часть part 2).
    data: Vec<u8>,
    /// `true`, если сохранён **второй** фрагмент (пришёл раньше первого).
    is_second: bool,
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
    data_keys: Option<DataPhaseKeys>,
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
            data_keys: None,
        }
    }

    /// Ключи data phase (доступны после `SessionCreated`/`SessionConfirmed`).
    #[must_use]
    pub const fn data_keys(&self) -> Option<&DataPhaseKeys> {
        self.data_keys.as_ref()
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

    /// Собирает `SessionConfirmed` (part 1 + part 2) и при нехватке места
    /// разбивает на два фрагмента.
    ///
    /// После вызова доступны [`InitiatorHandshake::data_keys`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `RouterInfo` не влезает даже в два
    /// фрагмента, key agreement не удался или `SessionCreated` не обработан;
    /// ошибки обфускации заголовка и сборки блоков.
    pub fn build_session_confirmed<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        params: &SessionConfirmedParams<'_>,
    ) -> Result<SessionConfirmedPackets> {
        let kh2 = session_confirmed_header_key(&self.noise.ck);
        let max_payload = policy.max_payload_size(self.config.ipv6, self.config.mtu);
        let max_single = max_payload.saturating_sub(HANDSHAKE_EXTRA_OVERHEAD);

        let mut block = Vec::new();
        write_router_info_block(&mut block, params.router_info)?;
        // i2pd: блок считается влезающим лишь при `size + 5 < len` (строго).
        let (max_used, flags0) = if block.len() < max_single {
            (max_single, CONFIRMED_FLAG_SINGLE)
        } else {
            (max_single + max_payload, CONFIRMED_FLAG_FIRST)
        };
        if block.len() >= max_used {
            // TODO(ssu2-scf-multifrag): i2pd тоже не умеет > 2 фрагментов
            // (там даже нет проверки — отправился бы пустой payload).
            return Err(I2PError::Malformed(
                "ssu2: RouterInfo does not fit in two SessionConfirmed fragments",
            ));
        }
        if let Some(size) = policy.padding_size(params.pad_roll, max_used - block.len(), 0) {
            let zeros = vec![0u8; size];
            write_block(&mut block, Ssu2BlockType::Padding, &zeros)?;
        }

        let header = ShortHeader {
            dest_conn_id: params.dest_conn_id,
            packet_num: 0,
            msg_type: Ssu2MessageType::SessionConfirmed,
            flags: [flags0, 0, 0],
        };
        self.noise.mix_hash(&header.to_bytes());

        // part 1: зашифрованный статический ключ Alice.
        let part1 = encrypt_into(&mut self.noise, self.local_static.public_key())?;
        self.noise.mix_hash(&part1);

        // part 2 KDF: DH(a_s, Y).
        let remote = self.remote_ephemeral_pub.ok_or(I2PError::Malformed(
            "ssu2: SessionConfirmed before SessionCreated",
        ))?;
        let shared = agree(&self.local_static, &remote)?;
        self.noise.mix_key(&shared);

        let ciphertext = encrypt_into(&mut self.noise, &block)?;
        self.noise.mix_hash(&ciphertext);

        // Граница двух фрагментов (i2pd: `max1 - rand%16`, хвост >= 24).
        let mut first_part2 = ciphertext.len();
        if flags0 == CONFIRMED_FLAG_FIRST && ciphertext.len() > max_single {
            first_part2 = max_single - usize::from(params.frag_roll % 16);
            if ciphertext.len().saturating_sub(first_part2) < CONFIRMED_SECOND_FRAGMENT_MIN {
                first_part2 = first_part2.saturating_sub(CONFIRMED_SECOND_FRAGMENT_MIN);
            }
        }

        let mut first = Vec::with_capacity(16 + SESSION_CONFIRMED_PART1_SIZE + first_part2);
        first.extend_from_slice(&header.to_bytes());
        first.extend_from_slice(&part1);
        first.extend_from_slice(&ciphertext[..first_part2]);
        obfuscate_header(
            Ssu2MessageType::SessionConfirmed,
            &self.intro_key,
            &kh2,
            &mut first,
        )?;

        let second = if first_part2 < ciphertext.len() {
            let header2 = ShortHeader {
                dest_conn_id: params.dest_conn_id,
                packet_num: 0,
                msg_type: Ssu2MessageType::SessionConfirmed,
                flags: [CONFIRMED_FLAG_SECOND, 0, 0],
            };
            let mut second =
                Vec::with_capacity(SSU2_HEADER_SIZE + (ciphertext.len() - first_part2));
            second.extend_from_slice(&header2.to_bytes());
            second.extend_from_slice(&ciphertext[first_part2..]);
            obfuscate_header(
                Ssu2MessageType::SessionConfirmed,
                &self.intro_key,
                &kh2,
                &mut second,
            )?;
            Some(second)
        } else {
            None
        };

        self.data_keys = Some(derive_data_phase_keys(&self.noise.ck));
        Ok(SessionConfirmedPackets { first, second })
    }
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
    data_keys: Option<DataPhaseKeys>,
    pending_confirmed: Option<PendingConfirmed>,
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
            data_keys: None,
            pending_confirmed: None,
        }
    }

    /// Текущий chaining key (для кросс-проверки с инициатором).
    #[must_use]
    pub const fn chain_key(&self) -> &[u8; 32] {
        &self.noise.ck
    }

    /// Ключи data phase (доступны после полного `SessionConfirmed`).
    #[must_use]
    pub const fn data_keys(&self) -> Option<&DataPhaseKeys> {
        self.data_keys.as_ref()
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

    /// Разбирает `SessionConfirmed` (в т.ч. из двух фрагментов).
    ///
    /// Возвращает [`ConfirmedOutcome::Incomplete`], если получен лишь один
    /// фрагмент. После [`ConfirmedOutcome::Complete`] доступны
    /// [`ResponderHandshake::data_keys`].
    ///
    /// Пакет деобфусцируется **на месте**. Проверка `RouterInfo` (подпись,
    /// адрес, статический ключ) — задача уровня сессии.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] при слишком коротком пакете/собранном
    /// сообщении; [`Error::Malformed`] при неверном типе, номере пакета,
    /// числе фрагментов, ключе или теге.
    pub fn handle_session_confirmed<P: Ssu2Policy>(
        &mut self,
        policy: &P,
        packet: &mut [u8],
    ) -> Result<ConfirmedOutcome> {
        if packet.len() < SSU2_MIN_PACKET_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SSU2_MIN_PACKET_SIZE,
                got: packet.len(),
            });
        }
        if packet.len() > policy.max_packet_size() {
            return Err(I2PError::Malformed("ssu2: SessionConfirmed too long"));
        }

        let kh2 = session_confirmed_header_key(&self.noise.ck);
        obfuscate_header(
            Ssu2MessageType::SessionConfirmed,
            &self.intro_key,
            &kh2,
            packet,
        )?;
        let header = ShortHeader::parse(&packet[..SSU2_HEADER_SIZE])?;
        if header.msg_type != Ssu2MessageType::SessionConfirmed {
            return Err(I2PError::Malformed("ssu2: expected SessionConfirmed"));
        }
        if header.packet_num != 0 {
            return Err(I2PError::Malformed(
                "ssu2: non-zero packet number in SessionConfirmed",
            ));
        }
        if header.num_fragments() > 2 {
            return Err(I2PError::Malformed(
                "ssu2: too many SessionConfirmed fragments",
            ));
        }

        let data = &packet[SSU2_HEADER_SIZE..];
        let assembled = if header.num_fragments() > 1 {
            self.assemble_fragment(&header, data)?
        } else {
            Some((header.to_bytes(), data.to_vec()))
        };
        let Some((header_bytes, data)) = assembled else {
            return Ok(ConfirmedOutcome::Incomplete);
        };

        self.finish_confirmed(&header_bytes, &data)
            .map(ConfirmedOutcome::Complete)
    }

    /// Собирает два фрагмента `SessionConfirmed`.
    ///
    /// Возвращает `None`, пока не хватает второго фрагмента; иначе —
    /// заголовок первого фрагмента и байты после cover (part 1 + part 2).
    fn assemble_fragment(
        &mut self,
        header: &ShortHeader,
        data: &[u8],
    ) -> Result<Option<([u8; SSU2_HEADER_SIZE], Vec<u8>)>> {
        let is_second = header.frag_number() != 0;
        match self.pending_confirmed.take() {
            None => {
                self.pending_confirmed = Some(PendingConfirmed {
                    header: header.to_bytes(),
                    data: data.to_vec(),
                    is_second,
                });
                Ok(None)
            }
            Some(pending) if pending.is_second == is_second => {
                // Дубликат фрагмента: игнорируем (в i2pd повтор второго
                // фрагмента ошибочно дописывается — здесь строже).
                self.pending_confirmed = Some(pending);
                Ok(None)
            }
            Some(pending) => {
                // Пришли оба фрагмента.
                let (head, tail) = if is_second {
                    (pending.data, data)
                } else {
                    (data.to_vec(), &pending.data[..])
                };
                if head.len() + tail.len() > SSU2_MAX_PACKET_SIZE * 2 {
                    return Err(I2PError::Malformed(
                        "ssu2: SessionConfirmed fragments too long",
                    ));
                }
                let mut combined = head;
                combined.extend_from_slice(tail);
                let header_bytes = if is_second {
                    pending.header
                } else {
                    header.to_bytes()
                };
                Ok(Some((header_bytes, combined)))
            }
        }
    }

    /// Завершает обработку собранного `SessionConfirmed`: part 1 + part 2.
    fn finish_confirmed(
        &mut self,
        header_bytes: &[u8; SSU2_HEADER_SIZE],
        data: &[u8],
    ) -> Result<ReceivedSessionConfirmed> {
        let len = SSU2_HEADER_SIZE + data.len();
        if len < SSU2_SESSION_CONFIRMED_MIN_LEN {
            return Err(I2PError::InvalidLength {
                expected: SSU2_SESSION_CONFIRMED_MIN_LEN,
                got: len,
            });
        }

        self.noise.mix_hash(header_bytes);
        // part 1: статический ключ Alice.
        let static_vec = decrypt_from(&mut self.noise, &data[..SESSION_CONFIRMED_PART1_SIZE])?;
        let mut static_key = [0u8; 32];
        static_key.copy_from_slice(&static_vec);
        self.noise.mix_hash(&data[..SESSION_CONFIRMED_PART1_SIZE]);

        // part 2 KDF: DH(b_s... b_e, S).
        let ephemeral = self.ephemeral.as_ref().ok_or(I2PError::Malformed(
            "ssu2: SessionConfirmed before SessionCreated",
        ))?;
        let shared = agree(ephemeral, &static_key)?;
        self.noise.mix_key(&shared);
        self.data_keys = Some(derive_data_phase_keys(&self.noise.ck));

        // part 2: payload.
        let payload = decrypt_from(&mut self.noise, &data[SESSION_CONFIRMED_PART1_SIZE..])?;
        self.noise.mix_hash(&data[SESSION_CONFIRMED_PART1_SIZE..]);

        Ok(ReceivedSessionConfirmed {
            static_key,
            payload,
        })
    }
}
