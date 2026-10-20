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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{I2PError, Result};
use crate::identity::IdentityEx;
use crate::private_keys::I2PPrivateKeys;

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
