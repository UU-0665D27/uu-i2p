//! `I2npMessage` — I2NP header + payload.
//!
//! Оборачивает [`I2npHeader`] и сырой payload в единый объект.
//! Соответствует `I2NPMessage` из `I2NPProtocol.h` в i2pd.
//!
//! ## Что здесь
//!
//! - [`I2npMessage::from_buffer`] — парсит заголовок и payload;
//! - [`I2npMessage::to_buffer`] — сериализует обратно;
//! - [`I2npMessage::new`] — конструктор с random `msg_id` и
//!   expiration = now + 8 сек;
//! - проверка/запись checksum (SHA256(payload)[0], опционально).
//!
//! ## Что НЕ здесь
//!
//! - типизированные body (`DatabaseStore`, `DatabaseLookup`,
//!   `Garlic`, ...) — парсятся отдельными модулями через
//!   [`I2npMessage::payload`];
//! - `from`-контекст (входящий туннель, из которого пришло) — в
//!   i2pd это поле `I2NPMessage::from`, но оно нужно только для
//!   маршрутизации в роутере; на уровне wire-формата его нет.

use crate::{
    data_message::DataBody,
    database_lookup::DatabaseLookup,
    database_search_reply::DatabaseSearchReply,
    database_store::DatabaseStore,
    delivery_status::DeliveryStatus,
    error::{I2PError, Result},
    garlic_body::GarlicBody,
    hash::I2PHash,
    i2np::{I2NP_HEADER_SIZE, I2npHeader, I2npMessageType},
    short_tunnel_build::ShortTunnelBuildBody,
    tunnel_messages::{TunnelDataBody, TunnelGatewayBody, TunnelTestBody},
    variable_tunnel_build::VariableTunnelBuildBody,
};

/// I2NP-сообщение: заголовок + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2npMessage {
    header: I2npHeader,
    payload: Vec<u8>,
}

impl I2npMessage {
    /// Конструктор с random `msg_id` и `expiration = now + 8 сек`.
    ///
    /// # Panics
    ///
    /// Паникует, если `payload.len() > 65535` (не влезает в `u16`
    /// поля `size` I2NP-заголовка). Валидные I2NP-сообщения никогда
    /// не превышают этот предел — длина payload'а ограничена
    /// форматом. Паника сигналит о баге в caller'е, а не о
    /// проблеме входных данных.
    #[must_use]
    pub fn new(message_type: I2npMessageType, payload: Vec<u8>) -> Self {
        let size = u16::try_from(payload.len())
            .expect("i2np: payload > 64KB — не должно случаться на уровне I2NP");
        let mut msg_id_bytes = [0u8; 4];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut msg_id_bytes);
        let msg_id = u32::from_be_bytes(msg_id_bytes);
        let header = I2npHeader::new(message_type, msg_id, size);
        Self { header, payload }
    }

    /// Конструктор с явными `msg_id` и `expiration` — для тестов
    /// и для случаев, когда caller сам управляет временем.
    #[must_use]
    pub const fn with_header(header: I2npHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Разбирает I2NP-сообщение из `buf`.
    ///
    /// Читает заголовок (16 байт) и `header.size` байт payload.
    /// Trailing байты после payload'а игнорируются — они могут быть
    /// частью внешнего контейнера (например, следующий I2NP в
    /// NTCP2-фрейме).
    ///
    /// Если `header.checksum == Some(expected)`, вычисляет
    /// SHA256(payload)[0] и сверяет. Несовпадение — [`Error::Malformed`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `buf` короче заголовка или payload'а;
    /// - [`Error::UnknownI2npType`] — typeID не описан в спеке;
    /// - [`Error::Malformed`] — checksum не сходится.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        let header = I2npHeader::parse(buf)?;
        let payload_start = I2NP_HEADER_SIZE;
        let payload_end = payload_start + usize::from(header.size);
        if buf.len() < payload_end {
            return Err(I2PError::InvalidLength {
                expected: payload_end,
                got: buf.len(),
            });
        }
        let payload = buf[payload_start..payload_end].to_vec();

        if let Some(expected) = header.checksum {
            let actual = checksum(&payload);
            if actual != expected {
                return Err(I2PError::Malformed("i2np: checksum mismatch"));
            }
        }

        Ok(Self { header, payload })
    }

    /// Сериализует в wire-формат.
    ///
    /// `header.size` **не** доверяем — пишем `payload.len()`. Это
    /// защищает от рассинхронизации header'а и payload'а.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `payload.len() > u16::MAX`.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let size = u16::try_from(self.payload.len())
            .map_err(|_| I2PError::Malformed("i2np: payload > 64KB cannot be serialized"))?;

        // Собираем заголовок с актуальным size.
        let mut header = self.header;
        header.size = size;
        if header.checksum.is_some() {
            header.checksum = Some(checksum(&self.payload));
        }

        let mut out = Vec::with_capacity(I2NP_HEADER_SIZE + self.payload.len());
        let mut hdr_buf = [0u8; I2NP_HEADER_SIZE];
        header.serialize(&mut hdr_buf)?;
        out.extend_from_slice(&hdr_buf);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Заголовок.
    #[must_use]
    pub const fn header(&self) -> &I2npHeader {
        &self.header
    }

    /// Тип сообщения (сокращение для `header().message_type`).
    #[must_use]
    pub const fn message_type(&self) -> I2npMessageType {
        self.header.message_type
    }

    /// Уникальный ID сообщения.
    #[must_use]
    pub const fn msg_id(&self) -> u32 {
        self.header.msg_id
    }

    /// Момент истечения в миллисекундах since epoch.
    #[must_use]
    pub const fn expiration_ms(&self) -> u64 {
        self.header.expiration_ms
    }

    /// Payload (сырые байты, тип-specific).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Истекло ли сообщение на момент `now_ms` (с учётом clock skew).
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        self.header.is_expired(now_ms)
    }

    /// Общая длина в wire-формате.
    #[must_use]
    pub const fn total_len(&self) -> usize {
        I2NP_HEADER_SIZE + self.payload.len()
    }

    /// Сериализует в **короткий** NTCP2-формат.
    ///
    /// Формат: `typeid(1) | msgid(4 BE) | expiration(4 BE, secs)` + payload.
    /// Длина payload'а определяется размером блока-обёртки в NTCP2-фрейме,
    /// поэтому `size` в заголовке не передаётся.
    ///
    /// Соответствует `I2NPMessage::ToNTCP2()` в i2pd. `expiration`
    /// округляется вниз до секунд.
    #[must_use]
    pub fn to_ntcp2_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.payload.len());
        out.push(self.header.message_type.as_u8());
        out.extend_from_slice(&self.header.msg_id.to_be_bytes());
        let exp_secs = u32::try_from(self.header.expiration_ms / 1000).unwrap_or(u32::MAX);
        out.extend_from_slice(&exp_secs.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Разбирает I2NP из **короткого** NTCP2-формата.
    ///
    /// Обратная к [`Self::to_ntcp2_bytes`]. `expiration` умножается
    /// на 1000 (секунды → миллисекунды). `checksum` выставляется в
    /// `None` — в NTCP2-формате checksum'а нет.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `buf` короче 9 байт;
    /// - [`Error::UnknownI2npType`] — typeID не описан;
    /// - [`Error::Malformed`] — payload больше `u16::MAX`.
    pub fn from_ntcp2_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 9 {
            return Err(I2PError::InvalidLength {
                expected: 9,
                got: buf.len(),
            });
        }
        let message_type = I2npMessageType::from_u8(buf[0])?;
        let msg_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let exp_secs = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let expiration_ms = u64::from(exp_secs) * 1000;
        let payload = buf[9..].to_vec();
        let size = u16::try_from(payload.len())
            .map_err(|_| I2PError::Malformed("ntcp2 i2np: payload > 64KB"))?;
        Ok(Self {
            header: I2npHeader {
                message_type,
                msg_id,
                expiration_ms,
                size,
                checksum: None,
            },
            payload,
        })
    }

    /// Устанавливает checksum: `SHA256(payload)[0]`.
    ///
    /// После вызова [`Self::to_buffer`] запишет checksum в wire.
    /// Полезно, когда caller хочет явно попросить checksum'и —
    /// например, для совместимости со старыми роутерами.
    pub fn enable_checksum(&mut self) {
        self.header.checksum = Some(checksum(&self.payload));
    }

    /// Снимает checksum (по умолчанию в I2NP его нет).
    pub const fn disable_checksum(&mut self) {
        self.header.checksum = None;
    }
}
// --- I2npBody ------------------------------------------------------------

/// Разобранное тело I2NP-сообщения.
///
/// Для типов, у которых есть typed-парсер, возвращается
/// соответствующий вариант. Для остальных — [`Self::Raw`] с сырым
/// payload'ом, который caller может разобрать сам или проигнорировать.
///
/// Typed-парсеры есть для всех актуальных типов. Без парсера остаются
/// только устаревшие `TunnelBuild` (21) и `TunnelBuildReply` (22)
/// с ElGamal-записями.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I2npBody {
    /// `DatabaseStore` (type=1): RI или `LeaseSet`.
    DatabaseStore(DatabaseStore),
    /// `DatabaseLookup` (type=2): запрос RI/LS.
    DatabaseLookup(DatabaseLookup),
    /// `DatabaseSearchReply` (type=3): ответ на lookup — список
    /// ближайших известных роутеров.
    DatabaseSearchReply(DatabaseSearchReply),
    /// `DeliveryStatus` (type=10): подтверждение доставки.
    DeliveryStatus(DeliveryStatus),
    /// `Garlic` (type=11): зашифрованный garlic-payload.
    ///
    /// Расшифровка живёт в
    /// [`crate::ecies_destination::EciesGarlicDestination`]
    /// (ECIES-X25519-AEAD-Ratchet) или в ElGamal/AES-сессии;
    /// диспетчеризация — по session-tag. Этот вариант хранит
    /// только сырые байты с wire.
    Garlic(GarlicBody),
    /// `TunnelData` (type=18): зашифрованное tunnel-сообщение.
    TunnelData(TunnelDataBody),
    /// `TunnelGateway` (type=19): сообщение для gateway'я туннеля.
    TunnelGateway(TunnelGatewayBody),
    /// `Data` (type=20): длина и непрозрачные данные.
    Data(DataBody),
    /// `VariableTunnelBuild` (type=23): записи по 528 байт.
    VariableTunnelBuild(VariableTunnelBuildBody),
    /// `VariableTunnelBuildReply` (type=24): ответ на предыдущий.
    VariableTunnelBuildReply(VariableTunnelBuildBody),
    /// `ShortTunnelBuild` (type=25): записи по 218 байт.
    ShortTunnelBuild(ShortTunnelBuildBody),
    /// `ShortTunnelBuildReply` (type=26): ответ на предыдущий.
    ShortTunnelBuildReply(ShortTunnelBuildBody),
    /// `TunnelTest` (type=231): проверка туннеля.
    TunnelTest(TunnelTestBody),
    /// Тип без typed-парсера (в частности, устаревшие
    /// `TunnelBuild` / `TunnelBuildReply` с ElGamal-записями). Payload сохраняется как есть.
    Raw {
        /// Тип исходного I2NP-сообщения.
        type_id: I2npMessageType,
        /// Сырой payload.
        payload: Vec<u8>,
    },
}

impl I2npBody {
    /// Тип этого тела.
    #[must_use]
    pub const fn message_type(&self) -> I2npMessageType {
        match self {
            Self::DatabaseStore(_) => I2npMessageType::DatabaseStore,
            Self::DatabaseLookup(_) => I2npMessageType::DatabaseLookup,
            Self::DatabaseSearchReply(_) => I2npMessageType::DatabaseSearchReply,
            Self::DeliveryStatus(_) => I2npMessageType::DeliveryStatus,
            Self::Garlic(_) => I2npMessageType::Garlic,
            Self::TunnelData(_) => I2npMessageType::TunnelData,
            Self::TunnelGateway(_) => I2npMessageType::TunnelGateway,
            Self::Data(_) => I2npMessageType::Data,
            Self::VariableTunnelBuild(_) => I2npMessageType::VariableTunnelBuild,
            Self::VariableTunnelBuildReply(_) => I2npMessageType::VariableTunnelBuildReply,
            Self::ShortTunnelBuild(_) => I2npMessageType::ShortTunnelBuild,
            Self::ShortTunnelBuildReply(_) => I2npMessageType::ShortTunnelBuildReply,
            Self::TunnelTest(_) => I2npMessageType::TunnelTest,
            Self::Raw { type_id, .. } => *type_id,
        }
    }

    /// Кодирует тело в payload (без I2NP-заголовка), не потребляя
    /// `self`. Для [`Self::Raw`] клонирует payload.
    ///
    /// # Errors
    ///
    /// См. `to_buffer` соответствующего typed body.
    pub fn to_payload(&self) -> Result<Vec<u8>> {
        match self {
            Self::DatabaseStore(b) => b.to_buffer(),
            Self::DatabaseLookup(b) => b.to_buffer(),
            Self::DatabaseSearchReply(b) => b.to_buffer(),
            Self::DeliveryStatus(b) => Ok(b.to_buffer().to_vec()),
            Self::Garlic(b) => b.to_buffer(),
            Self::TunnelData(b) => Ok(b.to_buffer()),
            Self::TunnelGateway(b) => b.to_buffer(),
            Self::Data(b) => b.to_buffer(),
            Self::VariableTunnelBuild(b) | Self::VariableTunnelBuildReply(b) => b.to_buffer(),
            Self::ShortTunnelBuild(b) | Self::ShortTunnelBuildReply(b) => b.to_buffer(),
            Self::TunnelTest(b) => Ok(b.to_buffer().to_vec()),
            Self::Raw { payload, .. } => Ok(payload.clone()),
        }
    }

    /// Потребляет `self` и возвращает payload (без I2NP-заголовка).
    ///
    /// Отличие от [`Self::to_payload`]: для [`Self::Raw`] отдаёт
    /// владение буфером без копирования. Для typed body поведение
    /// идентично — там payload всё равно собирается заново.
    ///
    /// # Errors
    ///
    /// См. `to_buffer` соответствующего typed body.
    pub fn into_payload(self) -> Result<Vec<u8>> {
        match self {
            Self::DatabaseStore(b) => b.to_buffer(),
            Self::DatabaseLookup(b) => b.to_buffer(),
            Self::DatabaseSearchReply(b) => b.to_buffer(),
            Self::DeliveryStatus(b) => Ok(b.to_buffer().to_vec()),
            Self::Garlic(b) => b.to_buffer(),
            Self::TunnelData(b) => Ok(b.to_buffer()),
            Self::TunnelGateway(b) => b.to_buffer(),
            Self::Data(b) => b.to_buffer(),
            Self::VariableTunnelBuild(b) | Self::VariableTunnelBuildReply(b) => b.to_buffer(),
            Self::ShortTunnelBuild(b) | Self::ShortTunnelBuildReply(b) => b.to_buffer(),
            Self::TunnelTest(b) => Ok(b.to_buffer().to_vec()),
            Self::Raw { payload, .. } => Ok(payload),
        }
    }
}

impl I2npMessage {
    /// Разбирает тело по типу сообщения.
    ///
    /// Потребляет `self` — payload перемещается в typed body или в
    /// [`I2npBody::Raw`] без копирования. Для typed body клонирование
    /// неизбежно: `DatabaseStore::from_buffer` собирает свой `Vec` из
    /// входного среза.
    ///
    /// # Errors
    ///
    /// Ошибки парсинга конкретного body — см.
    /// [`DatabaseStore::from_buffer`] и
    /// [`DatabaseLookup::from_buffer`].
    pub fn parse_body(self) -> Result<I2npBody> {
        match self.message_type() {
            I2npMessageType::DatabaseStore => Ok(I2npBody::DatabaseStore(
                DatabaseStore::from_buffer(&self.payload)?,
            )),
            I2npMessageType::DatabaseLookup => Ok(I2npBody::DatabaseLookup(
                DatabaseLookup::from_buffer(&self.payload)?,
            )),
            I2npMessageType::DatabaseSearchReply => Ok(I2npBody::DatabaseSearchReply(
                DatabaseSearchReply::from_buffer(&self.payload)?,
            )),
            I2npMessageType::DeliveryStatus => Ok(I2npBody::DeliveryStatus(
                DeliveryStatus::from_buffer(&self.payload)?,
            )),
            I2npMessageType::Garlic => {
                Ok(I2npBody::Garlic(GarlicBody::from_buffer(&self.payload)?))
            }
            I2npMessageType::TunnelData => Ok(I2npBody::TunnelData(TunnelDataBody::from_buffer(
                &self.payload,
            )?)),
            I2npMessageType::TunnelGateway => Ok(I2npBody::TunnelGateway(
                TunnelGatewayBody::from_buffer(&self.payload)?,
            )),
            I2npMessageType::Data => Ok(I2npBody::Data(DataBody::from_buffer(&self.payload)?)),
            I2npMessageType::VariableTunnelBuild => Ok(I2npBody::VariableTunnelBuild(
                VariableTunnelBuildBody::from_buffer(&self.payload)?,
            )),
            I2npMessageType::VariableTunnelBuildReply => Ok(I2npBody::VariableTunnelBuildReply(
                VariableTunnelBuildBody::from_buffer(&self.payload)?,
            )),
            I2npMessageType::ShortTunnelBuild => Ok(I2npBody::ShortTunnelBuild(
                ShortTunnelBuildBody::from_buffer(&self.payload)?,
            )),
            I2npMessageType::ShortTunnelBuildReply => Ok(I2npBody::ShortTunnelBuildReply(
                ShortTunnelBuildBody::from_buffer(&self.payload)?,
            )),
            I2npMessageType::TunnelTest => Ok(I2npBody::TunnelTest(TunnelTestBody::from_buffer(
                &self.payload,
            )?)),
            other => Ok(I2npBody::Raw {
                type_id: other,
                payload: self.payload,
            }),
        }
    }

    /// Оборачивает [`I2npBody`] в новое I2NP-сообщение.
    ///
    /// `msg_id` случайный, `expiration = now + 8 сек`. Для явного
    /// управления используйте [`Self::with_header`] вместе с
    /// [`I2npBody::to_payload`].
    ///
    /// # Errors
    ///
    /// См. [`I2npBody::to_payload`].
    pub fn from_body(body: I2npBody) -> Result<Self> {
        let type_id = body.message_type();
        let payload = body.into_payload()?;
        Ok(Self::new(type_id, payload))
    }
}

/// `SHA256(payload)[0]` — как в i2pd `I2NPMessage::UpdateChks`.
#[must_use]
fn checksum(payload: &[u8]) -> u8 {
    I2PHash::of(payload).as_bytes()[0]
}
