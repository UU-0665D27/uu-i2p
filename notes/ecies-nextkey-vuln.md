# Баг от rotten_egg: детерминированный remote-crash i2pd в ECIES-X25519-AEAD-ратчете

Эта заметка — разбор для будущего POC (первый вариант атаки). Пока роутер не
готов работать в сети, POC не делаем; здесь только зафиксированы факты и
точные строки i2pd.

Референс: `/home/u_uu/FOR_LLM/libi2pd` (i2pd, HEAD `7ab983ac`, **уже с фиксом**).
Файл: `libi2pd/ECIESX25519AEADRatchetSession.cpp`.

## 1. Null-deref в `HandleNextKey` (forward-ветка)

Фикс: `e5621949` — «chech ratchets payload size and key» (2026-09-09).

До фикса, ветка forward-key (`else`, т.е. без `REVERSE_KEY_FLAG`), не проверяла,
что локальный ключ уже сгенерирован:

```cpp
else
    m_NextReceiveRatchet->newKey = false;      // <- key может быть nullptr
auto tagsetID = m_NextReceiveRatchet->GetReceiveTagSetID ();
if (flag & ECIESX25519_NEXT_KEY_KEY_PRESENT_FLAG)
    memcpy (m_NextReceiveRatchet->remote, buf, 32);

uint8_t sharedSecret[32], tagsetKey[32];
m_NextReceiveRatchet->key->Agree (m_NextReceiveRatchet->remote, sharedSecret); // line 529: NULL DEREF
```

После фикса:

```cpp
else
{
    if (!m_NextReceiveRatchet->key)
    {
        LogPrint (eLogError, "Garlic: Forward next key received, but key is not set");
        return;
    }
    m_NextReceiveRatchet->newKey = false;
}
```

`DHRatchet::key` — `std::shared_ptr<X25519Keys>`, у свежесозданного
(`new DHRatchet ()`) он `nullptr`. Крушение — на `i2p::crypto::X25519Keys::Agree`
(`Crypto.cpp:319`).

**Условия триггера:** установленная (`eSessionStateEstablished`) сессия; garlic-payload,
расшифрованный тегом, содержит блок `eECIESx25519BlkNextKey`, у которого
`flag` без `REVERSE_KEY_FLAG` и без `REQUEST_REVERSE_KEY_FLAG` (`newKey == false`),
при этом `m_NextReceiveRatchet->key == nullptr` (ратчета ещё нет либо его ключ не
сгенерирован, т.к. предыдущий forward-блок был преждевременным).

**Стек из репорта (uu):**

```
Crypto.cpp:319                                   X25519Keys::Agree
ECIESX25519AEADRatchetSession.cpp:529            HandleNextKey
ECIESX25519AEADRatchetSession.cpp:418            HandlePayload
ECIESX25519AEADRatchetSession.cpp:965            HandleExistingSessionMessage
ECIESX25519AEADRatchetSession.cpp:1016           HandleNextMessage
ECIESX25519AEADRatchetSession.cpp:128            ReceiveRatchetTagSet::HandleNextMessage
Garlic.cpp:567                                   GarlicDestination::HandleECIESx25519TagMessage
Garlic.cpp:504                                   GarlicDestination::HandleGarlicMessage
Destination.cpp:347                              LeaseSetDestination::ProcessGarlicMessage
```

Второй прогон под ASan даёт `SEGV ... READ` на адресе `0x20` — то же место.

## 2. OOB-чтение в `HandlePayload` (усечённый заголовок блока)

Фикс: `cc77898b` — «check the whole block header fits before reading block size in
ratchets payload» (2026-09-09, PobreGato). Ремарка rotten_egg: «very minor, OOB read
when the buffer has a truncated header (1 or 2 bytes) at the end of the payload».

До фикса:

```cpp
if (len < 3) return;          // добавлено e5621949
size_t offset = 0;
while (offset < len)          // <- при 1–2 байтах хвоста читаем за концом
{
    uint8_t blk = buf[offset];
    offset++;
    auto size = bufbe16toh (buf + offset);   // OOB READ
```

После `cc77898b`:

```cpp
// the block header is three bytes: without all of them the size field below
// would be read past the end of the payload
while (offset + 3 <= len)
```

## 3. Что у нас в `uu-i2p`

- `src/ecies_ratchet.rs::handle_forward_key` (стр. ~719–784) **уже содержит**
  safety-guard из фикса: при `ratchet.key.is_none()` возвращает
  `Err(I2PError::Malformed("... forward key without local key"))`, а не дереференсит.
  Т.е. наш порт повторяет **исправленный** i2pd.
- `src/garlic_block.rs::NextKeyBlock` уже умеет парсить блок (`key_id`,
  `public_key`, флаги `is_reverse_key()` / `requests_reverse_key()`).
- Лог-строки из фикса («Garlic: Unexpected next key block», «Garlic: Forward next
  key received, but key is not set») соответствуют веткам
  `eECIESx25519BlkNextKey` без `receiveTagset` и forward-key без локального ключа.

## 4. POC: `examples/uu-i2p-poc-i2pd-nextkey.rs`

POC есть и работает: собирает **роутерное** ECIES-X25519-AEAD-Ratchet
сообщение (Noise «N», статический ключ — ключ шифрования из `RouterInfo`)
и кладёт в payload вредоносный блок.

```text
cargo run --example uu-i2p-poc-i2pd-nextkey -- \
    ~/.local/opt/i2pd-uu/datadir/router.info 127.0.0.1:12345 nextkey
```

Что при этом пишет i2pd (проверено 2026-10-17 на тестовой сборке
`i2pd_fast_debug_2.61.0-822-g79ae673d`, т.е. **с фиксом**, `--loglevel=debug`):

```text
Garlic: Block type 0 of size 4
Garlic: Datetime
Garlic: Block type 7 of size 3
Garlic: Next key
Garlic: Unexpected next key block          (error)
Garlic: Block type 254 of size 16
Garlic: Padding
```

То есть вредоносный `NextKey` (`flags = 0`, `keyID = 0`, без ключа) доедет,
расшифруется и будет отбит — но не той строкой, которую добавил фикс.

Второй вариант, `truncated` (payload обрывается на 1 байте заголовка блока,
тип без `size`) — на исправленной сборке в логе только `Garlic: Datetime`,
дальше тишина. До фикса там было OOB-чтение `size` за концом буфера
(heap-buffer-overflow под ASan'ом) и/или `Garlic: Unexpected block length <мусор>`.

## 5. Почему на роутере строка из фикса недостижима

`HandleNextKey` вызывается только из `HandlePayload` и только когда
`receiveTagset != nullptr` (эта проверка была и **до** фикса):

```cpp
case eECIESx25519BlkNextKey:
    if (receiveTagset)
        HandleNextKey (buf + offset, size, receiveTagset);
    else
        LogPrint (eLogError, "Garlic: Unexpected next key block");
```

Garlic, адресованный **роутеру**, проходит ровно два пути
(`RouterContext::PostGarlicMessage`, `RouterContext.cpp:1299`):

1. поиск session-tag в `m_ECIESx25519Tags` — у роутера он всегда пуст: теги
   появляются только у сессий клиентских destination'ов
   (`AddECIESx25519Session` вызывается лишь из `HandleNewIncomingSession` /
   `HandleNewOutgoingSessionReply`, а они — только на пути
   `GarlicDestination::HandleGarlicMessage`, т.е. у destination'ов);
2. одноразовый Noise «N» (`RouterIncomingRatchetSession::HandleNextMessage`),
   который зовёт `HandlePayload (payload, len, nullptr, 0)`.

Значит, на N-пути блок `NextKey` **всегда** отбивается строкой
`Garlic: Unexpected next key block` — и на уязвимой сборке тоже; упасть здесь
нельзя. Это подтверждается и кодом до фикса (`git show e5621949^`): там та же
проверка `if (receiveTagset)`, отличие только в цикле
(`while (offset < len)` вместо `while (offset + 3 <= len)`).

Стек из репорта rotten_egg идёт другим путём:

```text
Destination.cpp:347   LeaseSetDestination::ProcessGarlicMessage
Garlic.cpp:504        GarlicDestination::HandleGarlicMessage
Garlic.cpp:567        GarlicDestination::HandleECIESx25519TagMessage   <- поиск по тегу
ECIESX25519AEADRatchetSession.cpp:128  ReceiveRatchetTagSet::HandleNextMessage
ECIESX25519AEADRatchetSession.cpp:965  HandleExistingSessionMessage
ECIESX25519AEADRatchetSession.cpp:418  HandlePayload (receiveTagset != nullptr)
```

То есть цель — **клиентский destination**, а не роутер: нужна установленная
ECIES-сессия, враждебный `NextKey` должен прийти тег-сообщением, а сам garlic —
через inbound-туннель destination'а (у роутера туннелей нет, а direct garlic
доходит только до `RouterContext`).

## 6. План: как увидеть строку фикса в логе тестового i2pd

Тестовый i2pd живёт без пиров, поэтому обычные (многохоповые) туннели он
построить не может — его destination будет недостижим. Но i2pd умеет
**zero-hop туннели**: для них gateway — сам роутер, слоёв шифрования нет,
и доставка `TunnelGateway{tunnelId, garlic}` уходит в
`ZeroHopsInboundTunnel::SendTunnelDataMsg`, где `msg->from` = этот туннель →
`TunnelPool::ProcessGarlicMessage` → `LeaseSetDestination` (ровно та ветка, что
нужна). Т.е. пиры для POC не нужны.

Что для этого нужно:

1. В `~/.local/opt/i2pd-uu/ssu2.conf` включить любой клиентский destination
   с нулевой длиной туннелей, например HTTP-прокси:

   ```ini
   [httpproxy]
   enabled = true
   address = 127.0.0.1
   port = 4445
   inbound.length = 0
   outbound.length = 0
   inbound.quantity = 1
   outbound.quantity = 1
   ```

   (клиентские туннели строятся сразу и без пиров: `ZeroHopsInboundTunnel`
   создаётся синхронно, `IsEstablished()` для него истинно).

2. POC нужно узнать **LeaseSet** этого destination'а — оттуда берутся и
   статический ключ шифрования, и `tunnelId` zero-hop inbound-туннеля.
   i2pd LeaseSet'ы на диск не пишет (в `datadir/netDb` только RouterInfo),
   но публикует их ближайшему фладфиллу. Приём: наш POC публикует свой
   `RouterInfo` с флагом floodfill (`caps` содержит `f`) — тогда единственный
   «фладфилл» в netdb i2pd — мы, и i2pd пришлёт `DatabaseStore` с LeaseSet
   прямо в нашу SSU2-сессию.

3. Далее: собрать NS (initiator-сессия ECIES к статическому ключу
   destination'а, clove с доставкой `Router(наш hash)`, чтобы NSR вернулся к
   нам), завернуть в I2NP `Garlic` и отправить
   `TunnelGateway{tunnelId, garlic}` на тестовый роутер. Ответный NSR (NSR
   шлётся через zero-hop outbound-туннель destination'а, т.е. напрямую нашему
   роутеру) придёт нам I2NP-сообщением в той же SSU2-сессии.

4. Когда сессия встанет (`Established`), отправить тег-сообщение с
   враждебным `NextKey` тем же путём. На исправленной сборке — строка
   `Garlic: Forward next key received, but key is not set`, на сборке до
   `e5621949` — SEGV в `X25519Keys::Agree`.

Пункты 1–2 требуют решения пользователя (правка конфига тестового i2pd).
План выполнен: destination-путь, строка фикса в логе i2pd — см. §7.

## 7. POC: destination-путь, строка фикса получена

Дата: 2026-10-17. Пример: `examples/uu-i2p-poc-i2pd-dest-nextkey.rs`
(тестовая сборка i2pd — `i2pd_fast_debug_2.61.0-822-g79ae673d`, т.е. **с**
фиксом `e5621949`, `--loglevel=debug`).

Кто есть кто: **мы — destination (Bob)**, тестовый i2pd — клиентский
destination (Alice, его httpproxy) и он же роутер. Сессию инициирует i2pd,
поэтому держатель сессии — i2pd, и строку фикса печатает его лог.

Цепочка целиком (одним прогоном, без правок на ходу):

1. Мы поднимаем SSU2-сессию к i2pd (initiator) и в `SessionConfirmed` отдаём
   свой `RouterInfo` — флудфилл с **published** SSU2v4-адресом на
   `127.0.0.1:<наш UDP-порт>`. i2pd: `NetDb: RouterInfo added: <мы>`.
   Публиковать надо именно loopback: i2pd рвёт сессию, если published-хост не
   равен адресу, с которого пришла сессия (`SSU2Session.cpp:1400`,
   `SSU2: Host mismatch between published address ... and actual endpoint ...`).
   Loopback допустим как published-адрес только потому, что в конфиге
   тестового i2pd `reservedrange = false` (`Transports::IsInReservedRange` =
   `IsCheckReserved() && ...`). Без published IPv4
   `RouterInfo::IsEligibleFloodfill` во флудфиллы не пустит, а нам нужно,
   чтобы i2pd спросил `LeaseSet` у нас.
2. `curl -x http://127.0.0.1:4445 http://<наш b32>.b32.i2p/` → httpproxy
   destination'а i2pd ищет наш `LeaseSet`: `DatabaseLookup` (key = наш dest
   hash, `replyTunnelID` = его нулевой inbound, ECIES-ключ + тег) приходит нам
   garlic'ом по SSU2.
3. Отвечаем симметричным garlic'ом (`tag(8) || AEAD(clove, key, nonce=0,
   AD=tag)`) с `DatabaseStore{LeaseSet2}` внутри и `TunnelGateway{replyTunnelID}`
   на `from`. i2pd: `Destination: New remote LeaseSet added`.
4. i2pd поднимает поток к нам и шлёт NS: `TunnelGateway{наш tunnelID}` с
   ECIES-NS, к которому приложен его собственный `LeaseSet` (для ответа).
5. Отвечаем NSR'ом и сразу за ним — existing-session сообщением с вредоносным
   блоком `NextKey` (`flags = 0`, `keyID = 0`, без ключа).

Лог i2pd:

```text
Tunnel: Gateway of 637 bytes for tunnel 1228491548, msg type 11
Destination: Remote LeaseSet
Destination: New remote LeaseSet added
HTTPProxy: Created new I2PTunnel stream, sSID=0, rSID=1306122360
Tunnel: Gateway of 92 bytes for tunnel 1228491548, msg type 11   (наш NSR)
Tunnel: Gateway of 50 bytes for tunnel 1228491548, msg type 11   (вредоносное)
Garlic: Next key
Garlic: Forward next key received, but key is not set            (error)
```

Последняя строка — ровно то, что добавил `e5621949`. До фикса управление из
этой точки уходило в `m_NextReceiveRatchet->key->Agree(...)` при
`key == nullptr`, т.е. в SEGV в `i2p::crypto::X25519Keys::Agree`: remote-crash
именно у destination'а (в репорте rotten_egg — `Destination.cpp:347`). Значит,
POC доказывает и достижимость уязвимого состояния, и его детерминированность.

Запуск (curl — обязательный триггер, пример сам запрос не делает):

```text
RUST_LOG=uu_i2p=debug ./target/debug/examples/uu-i2p-poc-i2pd-dest-nextkey \
    ~/.local/opt/i2pd-uu/datadir/router.info 127.0.0.1:12345
# в другом терминале, по напечатанному адресу:
curl -x http://127.0.0.1:4445 --max-time 30 http://<b32>.b32.i2p/
```

Подготовка тестового i2pd: `[httpproxy]` (127.0.0.1:4445) с нулевыми
длинами/quantity туннелей и `reservedrange = false`; `run-ssu2.sh` перед
стартом чистит `datadir/netDb` и `datadir/peerProfiles` — иначе в
`m_Floodfills` остаются чужие/устаревшие роутеры и `GetClosestFloodfill`
выбирает не нас.

Грабли, на которые POC уже наступал (чтобы не повторять):

- ответ на `DatabaseLookup` — **не** финал: цикл событий обязан продолжать
  работу, иначе мы рвём сессию до того, как i2pd отправит NS (в логе остаётся
  `Destination: New remote LeaseSet added` и больше ничего);
- published-адрес в RI не может отличаться от фактического endpoint'а сессии
  (§7.1);
- в `netDb` тестового i2pd не должно быть наших прошлых POC-роутеров: они
  остаются во флудфиллах и i2pd пытается строить через них туннели
  (`Can't select next hop for ...`).

