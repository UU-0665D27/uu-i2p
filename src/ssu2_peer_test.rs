//! Подписанные данные `PeerTest` (SSU2).
//!
//! `PeerTest` — единственный блок SSU2, который проверяет подлинность не через
//! ключи установленной сессии, а через подпись роутера по его identity.
//! Формат повторяет i2pd (`SSU2Session::CreatePeerTestBlock` и
//! `HandlePeerTest`, `SSU2Session.cpp:2610-2760`, `:3256-3306`):
//!
//! ```text
//! данные без подписи:
//!     ver (1) = 2 | nonce (4) | ts (4) | asz (1) | endpoint (asz)
//! подпись:
//!     "PeerTestValidate" (16) || bhash (32) || [ahash (32)] || данные без подписи
//! ```
//!
//! `bhash` — хеш Боба, `ahash` — хеш Алисы. Состав зависит от сообщения:
//!
//! - **msg 1** (Alice → Bob): подписывает Алиса, `bhash` = хеш Боба;
//! - **msg 2/3** (Bob → Charlie → Bob): подписывает Charlie,
//!   `bhash` = хеш Боба, `ahash` = хеш Алисы (из поля `router hash` блока);
//! - **msg 4** (Bob → Alice): Боб пересылает ту же подпись Charlie, что и в
//!   msg 2/3, поэтому проверка идёт с `bhash` = хеш Боба и `ahash` = хеш
//!   Алисы.
//!
//! Endpoint — `port (2, BE) || IPv4 (4)` или `|| IPv6 (16)`, как у i2pd
//! (`CreateEndpoint`/`ExtractEndpoint`, `SSU2Session.cpp:2845-2890`).
//!
//! Подпись поддерживает только `EdDSA` (через [`I2PPrivateKeys::sign`] и
//! [`IdentityEx::verify`]); для роутеров с другими типами ключей проверка
//! вернёт [`I2PError::Unsupported`] — это ограничение текущего
//! identity-слоя, а не формата `PeerTest`.
//!
//! ## Out-of-session сообщения (5–7)
//!
//! После msg 4 Алиса и Charlie общаются пакетами `PeerTest` без
//! data-сессии (`SSU2OutOfSession.cpp`). Формат:
//!
//! ```text
//! header (16) | headerX (16, `ChaCha20` intro-ключом получателя) | AEAD payload
//! ```
//!
//! Заголовок маскируется intro-ключом получателя теми же двумя половинами,
//! что и короткий заголовок SSU2; `AD` — 32 байта `header || headerX` **до**
//! `ChaCha20` над `headerX`. Payload — блоки `DateTime`, `Address` (только
//! msg 6/7), `PeerTest`, `Padding`; nonce — [`aead_nonce`] от номера пакета.
//! Состояние сессии (conn ID из nonce, повторы, истечение) — в
//! [`PeerTestSession`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::IdentHash;
use crate::crypto::AeadChaCha20Poly1305;
use crate::error::{I2PError, Result};
use crate::identity::IdentityEx;
use crate::private_keys::I2PPrivateKeys;
use crate::ssu2_block::{
    AddressBlock, PeerTestBlock, Ssu2Block, Ssu2BlockType, Ssu2PeerTestCode, write_block,
};
use crate::ssu2_crypto::aead_nonce;
use crate::ssu2_header::{ConnectionId, Ssu2MessageType, header_mask, obfuscate_extended_header};
use crate::ssu2_recv::{PayloadSink, handle_payload};

/// Пролог подписи `PeerTest` (i2pd `"PeerTestValidate"`, ровно 16 байт).
pub const PEER_TEST_PROLOGUE: &[u8] = b"PeerTestValidate";

/// Версия формата подписанных данных (`ver`).
pub const PEER_TEST_VERSION: u8 = 2;

/// Длина данных без подписи и без endpoint'а: `ver + nonce + ts + asz`.
const FIXED_LEN: usize = 10;

/// Разобранные подписанные данные `PeerTest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTestSignedData {
    /// Версия формата (i2pd пишет 2).
    pub version: u8,
    /// Nonce, по которому сопоставляются сообщения одного теста.
    pub nonce: u32,
    /// Время подписи, секунды с epoch.
    pub timestamp: u32,
    /// Проверяемый endpoint.
    pub endpoint: SocketAddr,
    /// Подпись (длина зависит от типа signing-ключа).
    pub signature: Vec<u8>,
}

impl PeerTestSignedData {
    /// Разбирает подписанные данные из тела блока (без `msg/code/flag` и без
    /// `router hash`).
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если буфер короче заголовка, размер endpoint'а
    /// не 6/18 байт или подписи нет.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < FIXED_LEN {
            return Err(I2PError::Malformed("peer test: signed data is too short"));
        }
        let endpoint_len = usize::from(buf[9]);
        let unsigned_len = FIXED_LEN + endpoint_len;
        if buf.len() < unsigned_len {
            return Err(I2PError::Malformed(
                "peer test: endpoint is shorter than asz",
            ));
        }
        let endpoint = decode_endpoint(&buf[10..unsigned_len])?;
        let signature = &buf[unsigned_len..];
        if signature.is_empty() {
            return Err(I2PError::Malformed("peer test: signature is missing"));
        }
        Ok(Self {
            version: buf[0],
            nonce: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            timestamp: u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]),
            endpoint,
            signature: signature.to_vec(),
        })
    }

    /// Данные без подписи: `ver || nonce || ts || asz || endpoint`.
    ///
    /// Их подписывают и пересылают как есть (i2pd копирует `asz + 10` байт).
    #[must_use]
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let endpoint = encode_endpoint(self.endpoint);
        let mut out = Vec::with_capacity(FIXED_LEN + endpoint.len());
        out.push(self.version);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        // `encode_endpoint` даёт ровно 6 или 18 байт.
        out.push(if self.endpoint.is_ipv4() { 6 } else { 18 });
        out.extend_from_slice(&endpoint);
        out
    }

    /// Полные данные вместе с подписью.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.unsigned_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Проверяет подпись по identity отправителя.
    ///
    /// # Errors
    ///
    /// [`I2PError::Unsupported`] для не-EdDSA identity, иначе ошибка проверки
    /// из [`IdentityEx::verify`].
    pub fn verify(
        &self,
        identity: &IdentityEx,
        bhash: &[u8; 32],
        ahash: Option<&[u8; 32]>,
    ) -> Result<()> {
        let signed = signed_input(bhash, ahash, &self.unsigned_bytes());
        identity.verify(&signed, &self.signature)
    }
}

/// Собирает и подписывает данные `PeerTest`.
///
/// `ahash` передаётся только для сообщений Charlie (msg 2/3/4), у msg 1 его
/// нет.
///
/// # Errors
///
/// Пробрасывает ошибки подписи [`I2PPrivateKeys::sign`].
pub fn sign(
    keys: &I2PPrivateKeys,
    bhash: &[u8; 32],
    ahash: Option<&[u8; 32]>,
    nonce: u32,
    timestamp: u32,
    endpoint: SocketAddr,
) -> Result<PeerTestSignedData> {
    let unsigned = PeerTestSignedData {
        version: PEER_TEST_VERSION,
        nonce,
        timestamp,
        endpoint,
        signature: Vec::new(),
    }
    .unsigned_bytes();
    let signed = signed_input(bhash, ahash, &unsigned);
    let signature = keys.sign(&signed)?;
    Ok(PeerTestSignedData {
        version: PEER_TEST_VERSION,
        nonce,
        timestamp,
        endpoint,
        signature,
    })
}

/// Конкатенация, которую подписывают: пролог + хеши + данные.
fn signed_input(bhash: &[u8; 32], ahash: Option<&[u8; 32]>, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEER_TEST_PROLOGUE.len() + 64 + data.len());
    out.extend_from_slice(PEER_TEST_PROLOGUE);
    out.extend_from_slice(bhash);
    if let Some(ahash) = ahash {
        out.extend_from_slice(ahash);
    }
    out.extend_from_slice(data);
    out
}

/// `port (BE) || адрес` — формат i2pd `CreateEndpoint`.
fn encode_endpoint(endpoint: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(&endpoint.port().to_be_bytes());
    match endpoint.ip() {
        IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
    out
}

/// Обратное к [`encode_endpoint`]; размер уже проверен разбором (`asz + 10`).
fn decode_endpoint(buf: &[u8]) -> Result<SocketAddr> {
    let port = match buf {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        _ => return Err(I2PError::Malformed("peer test: endpoint is too short")),
    };
    let ip = match buf.len() {
        6 => IpAddr::V4(Ipv4Addr::new(buf[2], buf[3], buf[4], buf[5])),
        18 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&buf[2..]);
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => {
            return Err(I2PError::Malformed(
                "peer test: endpoint size is not 6 or 18",
            ));
        }
    };
    Ok(SocketAddr::new(ip, port))
}

// --- out-of-session (msg 5-7) -------------------------------------------

/// Сколько живёт peer-test-сессия (i2pd `SSU2_PEER_TEST_EXPIRATION_TIMEOUT`).
pub const PEER_TEST_EXPIRATION: Duration = Duration::from_secs(60);

/// Интервал повтора msg 5/6 (i2pd `SSU2_PEER_TEST_RESEND_INTERVAL`).
pub const PEER_TEST_RESEND_INTERVAL: Duration = Duration::from_secs(3);

/// Разброс повтора, миллисекунды (i2pd `..._VARIANCE`).
pub const PEER_TEST_RESEND_VARIANCE_MS: u64 = 2000;

/// Сколько раз повторяем msg 5/6 (i2pd `SSU2_PEER_TEST_MAX_NUM_RESENDS`).
pub const PEER_TEST_MAX_RESENDS: u8 = 3;

/// Минимальная версия роутера для роли Charlie
/// (i2pd `NETDB_MIN_PEER_TEST_VERSION`, 0.9.62).
pub const PEER_TEST_MIN_VERSION: u32 = 962;

/// Роль в out-of-session части теста.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTestRole {
    /// Alice: ждёт msg 5, отвечает msg 6, принимает msg 7.
    Alice,
    /// Charlie: шлёт msg 5, ждёт msg 6, отвечает msg 7.
    Charlie,
}

/// Состояние out-of-session сессии (i2pd `SSU2PeerTestSession`).
#[derive(Debug, Clone)]
pub struct PeerTestSession {
    /// Роль.
    pub role: PeerTestRole,
    /// Наш `sourceConnID`.
    pub source: ConnectionId,
    /// `sourceConnID` собеседника (он же `destConnID` в его пакетах).
    pub dest: ConnectionId,
    /// `nonce` теста.
    pub nonce: u32,
    /// Адрес собеседника (из msg 4 / из `from` принятого пакета).
    pub remote: Option<SocketAddr>,
    /// `IdentHash` собеседника: у Alice — Charlie, у Charlie — Alice.
    pub remote_ident: Option<IdentHash>,
    /// Intro-ключ собеседника (из SSU2-адреса его `RouterInfo`).
    pub remote_intro_key: Option<[u8; 32]>,
    /// Подписанные данные, которые пересылаем в msg 6/7.
    pub signed_data: Vec<u8>,
    /// Наш endpoint, каким его увидел собеседник (блок `Address`).
    pub our_endpoint: Option<SocketAddr>,
    /// Наибольший принятый номер сообщения (0 — ещё ничего).
    pub msg_received: u8,
    /// Сообщение, которое ждёт отправки/повтора (5 или 6; 0 — нет).
    pub pending_msg: u8,
    /// Когда отправить `pending_msg`.
    pub resend_at: Option<Duration>,
    /// Сколько раз уже отправили `pending_msg`.
    pub resends: u8,
    /// Когда сессия истекает.
    pub expires_at: Duration,
    /// Известен ли адрес и intro-ключ Charlie (Alice узнаёт их из msg 4).
    pub address_known: bool,
}

impl PeerTestSession {
    /// Создаёт сессию; `nonce` задаёт оба conn ID
    /// (i2pd: `nonce << 32 | nonce`).
    #[must_use]
    pub fn new(role: PeerTestRole, nonce: u32, now: Duration) -> Self {
        let (nonce_id, inverse) = ConnectionId::relay_nonce_pair(nonce);
        // У Charlie source = ~nonce, dest = nonce; у Alice — наоборот.
        let (source, dest) = match role {
            PeerTestRole::Charlie => (inverse, nonce_id),
            PeerTestRole::Alice => (nonce_id, inverse),
        };
        Self {
            role,
            source,
            dest,
            nonce,
            remote: None,
            remote_ident: None,
            remote_intro_key: None,
            signed_data: Vec::new(),
            our_endpoint: None,
            msg_received: 0,
            pending_msg: 0,
            resend_at: None,
            resends: 0,
            expires_at: now + PEER_TEST_EXPIRATION,
            address_known: false,
        }
    }

    /// Сессия истекла.
    #[must_use]
    pub fn is_expired(&self, now: Duration) -> bool {
        now >= self.expires_at
    }

    /// Пора отправлять `pending_msg`.
    #[must_use]
    pub fn resend_due(&self, now: Duration) -> bool {
        self.resend_at.is_some_and(|at| now >= at)
    }

    /// Планирует отправку/повтор `msg` (i2pd `ScheduleResend`).
    pub fn schedule(&mut self, msg: u8, now: Duration, jitter_ms: u64) {
        self.pending_msg = msg;
        self.resends = 0;
        self.resend_at = Some(now + PEER_TEST_RESEND_INTERVAL + Duration::from_millis(jitter_ms));
    }

    /// Отмечает отправку и планирует следующий повтор.
    pub fn sent(&mut self, now: Duration, jitter_ms: u64) {
        self.resends = self.resends.saturating_add(1);
        self.resend_at = if self.resends >= PEER_TEST_MAX_RESENDS {
            None
        } else {
            Some(now + PEER_TEST_RESEND_INTERVAL + Duration::from_millis(jitter_ms))
        };
    }

    /// Принято сообщение `msg`; возвращает `false`, если оно уже было.
    pub const fn accept_msg(&mut self, msg: u8) -> bool {
        if msg <= self.msg_received {
            return false;
        }
        self.msg_received = msg;
        true
    }
}

/// Параметры сборки out-of-session пакета.
pub struct PeerTestPacket<'a> {
    /// Intro-ключ получателя.
    pub intro_key: &'a [u8; 32],
    /// `destConnID` получателя (наш `source`).
    pub dest: ConnectionId,
    /// Наш `sourceConnID`.
    pub source: ConnectionId,
    /// Номер сообщения 5/6/7.
    pub msg: u8,
    /// Подписанные данные.
    pub signed_data: &'a [u8],
    /// Endpoint для блока `Address` (только msg 6/7).
    pub address: Option<SocketAddr>,
    /// Номер пакета (BE u32 в заголовке).
    pub packet_num: u32,
    /// `netId`.
    pub net_id: u8,
    /// Время `DateTime`, секунды.
    pub timestamp_secs: u32,
    /// Полный размер payload'а (с padding'ом).
    pub max_payload: usize,
}

/// Собирает out-of-session пакет `PeerTest` (i2pd
/// `SSU2PeerTestSession::SendPeerTest`, `SSU2OutOfSession.cpp:170-205`).
///
/// # Errors
///
/// Ошибки сборки блоков и AEAD-шифрования.
pub fn build_packet(packet: &PeerTestPacket<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    write_block(
        &mut payload,
        Ssu2BlockType::DateTime,
        &packet.timestamp_secs.to_be_bytes(),
    )?;
    if let Some(address) = packet.address {
        AddressBlock {
            port: address.port(),
            ip: address.ip(),
        }
        .write(&mut payload)?;
    }
    PeerTestBlock {
        msg: packet.msg,
        code: Ssu2PeerTestCode::Accept.as_u8(),
        flag: 0,
        router_hash: None,
        data: packet.signed_data,
    }
    .write(&mut payload)?;
    if payload.len() + 3 <= packet.max_payload {
        let zeros = vec![0u8; packet.max_payload - payload.len() - 3];
        write_block(&mut payload, Ssu2BlockType::Padding, &zeros)?;
    }

    let mut header = [0u8; 16];
    header[..8].copy_from_slice(packet.dest.as_bytes());
    header[8..12].copy_from_slice(&packet.packet_num.to_be_bytes());
    header[12] = Ssu2MessageType::PeerTest as u8;
    header[13] = 2; // ver
    header[14] = packet.net_id;
    let mut header_x = [0u8; 16];
    header_x[..8].copy_from_slice(packet.source.as_bytes());
    // AD содержит **необфусцированный** `headerX` (i2pd строит `h` до
    // ChaCha20 над `h+16`).
    let mut ad = [0u8; 32];
    ad[..16].copy_from_slice(&header);
    ad[16..].copy_from_slice(&header_x);
    obfuscate_extended_header(packet.intro_key, &mut header_x);

    let nonce = aead_nonce(u64::from(packet.packet_num));
    let mut out = vec![0u8; 32 + payload.len() + 16];
    out[..16].copy_from_slice(&header);
    out[16..32].copy_from_slice(&header_x);
    let ciphertext_len = AeadChaCha20Poly1305::new().encrypt(
        packet.intro_key,
        &nonce,
        &ad,
        &payload,
        &mut out[32..],
    )?;
    out.truncate(32 + ciphertext_len);
    let len = out.len();
    if len < 48 {
        return Err(I2PError::Malformed("peer test: packet is too short"));
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&out[len - 24..len - 12]);
    let mask = header_mask(packet.intro_key, &iv);
    for (b, m) in out[..8].iter_mut().zip(mask) {
        *b ^= m;
    }
    iv.copy_from_slice(&out[len - 12..]);
    let mask = header_mask(packet.intro_key, &iv);
    for (b, m) in out[8..16].iter_mut().zip(mask) {
        *b ^= m;
    }
    Ok(out)
}

/// Расшифрованный out-of-session пакет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTestPacketData {
    /// Наш `sourceConnID` (из заголовка).
    pub dest: ConnectionId,
    /// `sourceConnID` собеседника (из расшифрованного `headerX`).
    pub source: ConnectionId,
    /// Номер пакета.
    pub packet_num: u32,
    /// Расшифрованный payload.
    pub payload: Vec<u8>,
}

/// Расшифровывает входящий out-of-session пакет (`&mut`, чтобы снять маски
/// заголовка на месте).
///
/// # Errors
///
/// [`I2PError::Malformed`] при коротком пакете, неверном типе или
/// несошедшемся AEAD-теге.
pub fn open_packet(intro_key: &[u8; 32], packet: &mut [u8]) -> Result<PeerTestPacketData> {
    let len = packet.len();
    if len < 48 {
        return Err(I2PError::Malformed("peer test: packet is too short"));
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&packet[len - 24..len - 12]);
    let mask = header_mask(intro_key, &iv);
    for (b, m) in packet[..8].iter_mut().zip(mask) {
        *b ^= m;
    }
    iv.copy_from_slice(&packet[len - 12..]);
    let mask = header_mask(intro_key, &iv);
    for (b, m) in packet[8..16].iter_mut().zip(mask) {
        *b ^= m;
    }
    if Ssu2MessageType::from_u8(packet[12]) != Ok(Ssu2MessageType::PeerTest) {
        return Err(I2PError::Malformed("peer test: unexpected message type"));
    }

    let mut header_x = [0u8; 16];
    header_x.copy_from_slice(&packet[16..32]);
    obfuscate_extended_header(intro_key, &mut header_x);
    let mut ad = [0u8; 32];
    ad[..16].copy_from_slice(&packet[..16]);
    ad[16..].copy_from_slice(&header_x);

    let packet_num = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
    let nonce = aead_nonce(u64::from(packet_num));
    let mut plaintext = vec![0u8; len - 48];
    let plaintext_len = AeadChaCha20Poly1305::new().decrypt(
        intro_key,
        &nonce,
        &ad,
        &packet[32..],
        &mut plaintext,
    )?;
    plaintext.truncate(plaintext_len);

    let mut dest = [0u8; 8];
    dest.copy_from_slice(&packet[..8]);
    let mut source = [0u8; 8];
    source.copy_from_slice(&header_x[..8]);
    Ok(PeerTestPacketData {
        dest: ConnectionId::new(dest),
        source: ConnectionId::new(source),
        packet_num,
        payload: plaintext,
    })
}

/// Блок `PeerTest` из payload'а.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTestMessage {
    /// Номер сообщения.
    pub msg: u8,
    /// Код.
    pub code: u8,
    /// Флаг.
    pub flag: u8,
    /// Подписанные данные с подписью.
    pub data: Vec<u8>,
}

/// Разобранное содержимое out-of-session пакета.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerTestPayload {
    /// Блок `Address` (msg 6/7).
    pub address: Option<SocketAddr>,
    /// Блок `PeerTest`.
    pub peer_test: Option<PeerTestMessage>,
}

#[derive(Default)]
struct PayloadCollector {
    payload: PeerTestPayload,
}

impl PayloadSink for PayloadCollector {
    fn on_address(&mut self, body: &[u8]) {
        if let Ok(address) = AddressBlock::parse(body) {
            self.payload.address = Some(SocketAddr::new(address.ip, address.port));
        }
    }

    fn on_peer_test(&mut self, body: &[u8]) {
        if let Ok(block) = PeerTestBlock::parse(body) {
            self.payload.peer_test = Some(PeerTestMessage {
                msg: block.msg,
                code: block.code,
                flag: block.flag,
                data: block.data.to_vec(),
            });
        }
    }
}

/// Разбирает блоки расшифрованного payload'а.
#[must_use]
pub fn parse_payload(payload: &[u8]) -> PeerTestPayload {
    let mut collector = PayloadCollector::default();
    let _ = handle_payload(payload, &mut collector);
    collector.payload
}
