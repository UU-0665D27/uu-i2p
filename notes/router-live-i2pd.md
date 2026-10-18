# Живой прогон объединённого роутера против i2pd (SSU2 + NTCP2)

Первый прогон собранного роутера: `src/router.rs` (состояние +
транспорт + цикл событий), пример `examples/uu-i2p-router-i2pd.rs`.
До него «в сети» умели только POC'и, дёргавшие `Ssu2Pool` руками.
Позже к SSU2 добавилось NTCP2-плечо — раздел «Исходящая сессия по NTCP2».

## Как запускается

```bash
# тестовый i2pd (чистый netDb, reservedrange=false, httpproxy на 4445;
# в ssu2.conf также [ntcp2] enabled=true, port=12346, version=2 — для
# раздела про NTCP2 ниже)
~/.local/opt/i2pd-uu/run-ssu2.sh

RUST_LOG=uu_i2p=debug cargo run --example uu-i2p-router-i2pd -- \
    ~/.local/opt/i2pd-uu/datadir/router.info 127.0.0.1:12345 --secs 40
```

Пример делает ровно то, что делал бы роутер:

1. слушает UDP на `127.0.0.1:0`, собирает `RouterContext` с RI, где
   опубликован loopback и caps `f` (`RouterConfigBuilder::allow_reserved_advertise(true)`
   — аналог i2pd `reservedrange = false`);
2. `Router::dial` — исходящая SSU2-сессия;
3. `Router::send` — свой RI (`DatabaseStore`) и `DatabaseLookup` за RI
   собеседника;
4. `curl`-запрос через HTTP-прокси i2pd случайным `.b32.i2p`: i2pd идёт за
   `LeaseSet` к ближайшему флудфиллу — к нам;
5. `Router::run_until` крутит тик (запросы netDb, публикация RI,
   обслуживание транспорта).

## Что подтвердилось

Со стороны i2pd (`/tmp/opencode/i2pd-ssu2.log`):

```
SSU2: Session with 127.0.0.1:42453 (OlZ2) established
NetDb: RouterInfo added: OlZ2jzw0uxH2OKynsSkmdAVtMfg02g28PRKuFWFMqf4=   # наш RI из SessionConfirmed
NetDb: Got request with type 1
NetDb: Store request: RouterInfo OlZ2...                                  # наш DatabaseStore
NetDbReq: DatabaseSearchReply for QwU4xbkE137XtG7rrtFanvSlq36DVUQFab-...  # ответ на его LeaseSet-lookup
Router: Publishing our RouterInfo to OlZ2. reply token=3424883486        # его garlic нам
```

Из вывода примера:

```
demo: соединение установлено transport=SSU2
router: RouterInfo добавлен в netDb transport=SSU2        # ответ на наш DatabaseLookup
demo: принято I2NP msg_type="Garlic" len=220             # его RI роутерным garlic
router: DatabaseLookup ... lookup_type=LeaseSet           # его lookup к нам как флудфиллу
=== Итог ===
Пир в карте сессий: Some(Ssu2)
I2NP принято: DatabaseLookup=9 DatabaseStore=1 прочих=19 | RI в netDb=1 | необработано=17
```

То есть полный цикл: сессия → публикация RI → lookup туда и обратно →
`DatabaseLookup` от i2pd → наш `DatabaseSearchReply`. Прокси, разумеется,
отдаёт `500` (LeaseSet'а не существует), но это и есть ожидаемое поведение
флудфилла без LS.

## Входящая сессия (`--accept`)

Отдельный прогон (`--accept`, 60 с) проверяет **входящий** путь: после
размена пример рвёт свою сессию (`Router::close` → пул шлёт `Termination`)
и ждёт, чтобы i2pd позвонил сам. i2pd это и делает, когда ему есть что
отправить: `Transports::PostMessages` → `ConnectToPeer` (адрес — из нашего
RI в его netDb, куда тот попал из `SessionConfirmed`).

```
--- Рвём свою сессию (её события разберёт цикл ниже) ---
Свою сессию закрыли (true); дальше ждём входящую: i2pd должен позвонить сам
Триггер: GET http://<b32>.b32.i2p/ через прокси i2pd
demo: соединение установлено ... nth=1        # наша исходящая (события копятся до старта цикла)
demo: соединение установлено ... nth=2        # ← входящая: её начал i2pd
=== Итог ===
Пир в карте сессий: Some(Ssu2)
Сессий установлено: 2
I2NP принято: DatabaseLookup=18 DatabaseStore=0 прочих=13 | RI в netDb=1 | необработано=9
```

Со стороны i2pd:

```
SSU2: Session with 127.0.0.1:51240 (NsDL) terminated      # наша Termination
SSU2: Connecting to 127.0.0.1:51240 (NsDL)                # ← он звонит сам
SSU2: Session with 127.0.0.1:51240 (NsDL) established
NetDb: DatabaseLookup for ... received                    # его lookup'ы к нам как флудфиллу
```

То есть пул сам поднимает сессию в роли ответчика, а `Router` получает
обычные `Established`/`Message` и отвечает на них теми же путями, что и в
исходящей сессии: разницы нет — «направление» живёт только в пуле.

Заодно видно, как i2pd ведёт себя с нашими *старыми* RI: он продолжает
звонить на порты прошлых прогонов (`R0We`, `OlZ2`, `WLUn`, `aqCK`) и
ругается `Session ... was not established after 5 seconds`. Это не наш
баг, а цена того, что i2pd не чистит netDb: перед серией прогонов лучше
перезапустить тестовый i2pd (`run-ssu2.sh` чистит `datadir/netDb`).

## Исходящая сессия по NTCP2 (`--ntcp2`)

Тот же роутер, но соединение — TCP: `Ntcp2Transport` (обёртка над
`Ntcp2Pool`) с владеющим `Ntcp2Local` (ключи/IV/`netId` из `RouterConfig`,
свой RI — из `RouterContext`).

```bash
RUST_LOG=uu_i2p=debug cargo run --example uu-i2p-router-i2pd -- \
    ~/.local/opt/i2pd-uu/datadir/router.info 127.0.0.1:12345 --ntcp2 --secs 40
```

Наш вывод:

```
ntcp2 pool: сессия установлена (Alice) peer=dM7B... addr=127.0.0.1:12346
demo: dial transport=NTCP2
demo: соединение установлено transport=NTCP2 nth=1
demo: RouterInfo добавлен в netDb          # его RI пришёл блоком RouterInfo
=== Итог ===
Пир в карте сессий: Some(Ntcp2)
```

i2pd (`/tmp/opencode/i2pd-ssu2.log`):

```
NTCP2: Connected from 127.0.0.1:38988
NTCP2: SessionRequest received 64
NTCP2: SessionCreated sent
NTCP2: SessionConfirmed received
NTCP2: SessionConfirmed from 127.0.0.1:38988 (MXXA)
NetDb: RouterInfo added: MXXANd51Ca7-~Ra9T4kt5kh4hreA08bF6MEb91-qBoY=
Router: Publishing our RouterInfo to MXXA. reply token=2856562295
NTCP2: Sent length 764 | 983               # его garlic и DatabaseStore
```

Handshake (Noise XK) прошёл целиком, наш RI ушёл в `SessionConfirmed` и
i2pd его принял, дальше I2NP идёт по NTCP2 в обе стороны: он шлёт нам
garlic (`DatabaseLookup` за RI и `LeaseSet`, `DatabaseStore`), мы
отвечаем. Сессия прожила весь прогон (40 с) без переподключений.

Чего потребовал именно NTCP2:

- **NTCP2-адрес в своём RI.** i2pd в `EstablishSessionAfterSessionConfirmed`
  (`NTCP2.cpp:1053`) берёт `GetNTCP2V4Address()` из нашего RI и сверяет
  его `s` со статическим ключом handshake; нет адреса — «Address not
  found in SessionConfirmed» + термин, не тот `s` — «Wrong static key»,
  host не совпал с источником — `eNTCP2Banned`. Поэтому пример
  публикует `listen_published(ntcp2_addr, 127.0.0.1)`.
- **Свежий RI.** i2pd рвёт сессию на RI старше 90 минут и на RI «из
  будущего» (2 минуты). Наш timestamp — `now_ms()`, ок.

Закрытие: `Router::close` на NTCP2-сессии — это
`Termination(NormalClose)`, и i2pd его разбирает:

```
NTCP2: Received length 28
NTCP2: Termination. reason=0
NTCP2: Session with 127.0.0.1:33176 (hu3m) terminated
```

### Входящая сессия по NTCP2 (`--ntcp2 --accept`)

Пул NTCP2 теперь и принимает: `Ntcp2Pool::listen` (accept-loop, зеркало
`NTCP2Server::HandleAccept` — проверка `IsInReservedRange`, одна
«ожидающая» сессия на IP, таймаут `NTCP2_ESTABLISH_TIMEOUT`), сессия
живёт в своей задаче, а общий таймер (`run_maintenance`) следит за idle
(`NTCP2_TERMINATION_TIMEOUT` ± разброс) и раз в
`NTCP2_ROUTERINFO_RESEND_INTERVAL` повторяет наш RI
(`SendLocalRouterInfo(update = true)`).

```bash
RUST_LOG=uu_i2p=debug cargo run --example uu-i2p-router-i2pd -- \
    ~/.local/opt/i2pd-uu/datadir/router.info 127.0.0.1:12345 --ntcp2 --accept --secs 30
```

После нашего `Termination` i2pd звонит сам; транспорт выбирается
случайно (`Transports::SetPriority`, SSU2/NTCP2 — 1/2), так что
входящий NTCP2 ловится со второго-третьего прогона. Когда монетка
выпала на NTCP2, у нас:

```
ntcp2 pool: входящая сессия установлена (Bob) peer=127.0.0.1:53919
demo: соединение установлено transport=NTCP2 nth=2
```

а у i2pd:

```
NTCP2: Connecting to 127.0.0.1:37363 (ZmcK)
NTCP2: Connected to 127.0.0.1:37363 (ZmcK)
NTCP2: SessionCreated received 64           # наш SessionCreated (мы Bob)
NTCP2: SessionConfirmed sent
NTCP2: Received length 826
NTCP2: Block type 2 of size 800
NTCP2: RouterInfo flag=0                    # наш RI, отправленный пулом после установки
```

То есть входящий путь NTCP2 (accept-loop → Noise XK в роли Bob →
`SendLocalRouterInfo`) отработал против настоящего i2pd; раньше i2pd в
этом же месте получал «No activity for 50 seconds» и рвал сессию.

## Почему i2pd ругался на окно отправки (и что сделано)

В первых прогонах сразу после нашего закрытия сессии i2pd писал:

```
SSU2: Outgoing messages queue to NsDL is semi-full (size = 1, lag = 1499, rtt = 2)
SSU2: Packet was not Acked after 6 attempts. Terminate session
```

Это `SSU2Session::PostI2NPMessages` (`SSU2Session.cpp:407`): в очереди на
отправку висят I2NP-сообщения, а `SendQueue` их не отправляет, потому что
окно заполнено (`m_SentPackets.size () > m_WindowSize`) — i2pd считает
неподтверждёнными пакеты, которые он успел нам послать **до** того, как
узнал о нашем `Termination`.

Причина была на нашей стороне: `close_session` слал `Termination` и тут же
убирал сессию, поэтому весь «хвост» пакетов i2pd оставался без `Ack`. i2pd
же в `Closing` живёт ещё до одного тика терминации
(`SSU2Server::HandleTerminationTimer`, `SSU2.cpp:1109`;
`SSU2_TERMINATION_CHECK_TIMEOUT` = 23 с + разброс до 5 с, `SSU2.h:29-30`) и
продолжает писать в сессию.

Теперь закрытие «доигрывается» (см. `Session::drain_until` в
`src/ssu2_pool.rs`): сессия сразу исчезает из карт и наружу уходит
`Disconnected`, но по `conn_id` она ещё
`SSU2_TERMINATION_CHECK_TIMEOUT` принимает и **подтверждает** пакеты
собеседника (содержимое игнорируется). Прогон с `--accept` после правки:

```
[23:30:41] SSU2: Session with 127.0.0.1:54637 (CnAr) established
[23:30:46] ...  мы закрыли сессию (Termination)
[23:31:02] SSU2: Session with 127.0.0.1:54637 (CnAr) terminated   # тик терминации i2pd
[23:31:02] SSU2: Session with 127.0.0.1:54637 (CnAr) established  # и он сразу звонит сам
```

Ни одного `semi-full` (в прошлом прогоне их было 5 за 8 секунд) и ни одного
`not Acked after 6 attempts` для нашей сессии: i2pd спокойно доходит до
своего тика терминации, а не выбивает сессию исчерпанием повторов.
Последний `not Acked` в логе — уже после выхода примера (сессия к `CnAr`
осталась без нас), это ожидаемо.

Замечание: сами `semi-full` в `Closing` возможны и у i2pd с i2pd — в
`Closing` `IsEstablished ()` ложно, поэтому `SendQueue` не отправляет уже
поставленные в очередь сообщения; ругань идёт от верхнего слоя, который
продолжает их ставить. Наш `Ack` убирает только часть с неподтверждёнными
пакетами (и вместе с ней — выбивание сессии по `Resend`).

## Что пришлось доделать по ходу

1. **Роутерный garlic (`Noise_N`)** —
   `RouterContext::handle_router_garlic`. i2pd *каждое* роутерное
   сообщение (DatabaseLookup флудфиллу, публикация RI, публикация LS)
   шлёт как `WrapECIESX25519MessageForRouter`:
   `aepk(32) || AEAD(blocks)` на статический ключ получателя, без тега и
   без состояния (`Garlic.cpp:752`, `ECIESX25519AEADRatchetSession.cpp:1520`).
   Наш `handle_garlic` умел только destination-сессии (теги/NS), поэтому
   первый же garlic от i2pd падал в `aead: decrypt failed`. Теперь
   `Router::handle_garlic` пробует оба пути (как i2pd
   `PostGarlicMessage`), а I2NP из Local-clove'ов гоняет через **свой**
   диспетчер — иначе ответ на `DatabaseLookup` некуда отправить.
2. **Ошибка одного сообщения не должна ронять цикл.** В первом прогоне
   `run_until` вернул `Err` на кривом garlic, пример упал, сессия
   оборвалась (`SSU2: Packet was not Acked after 6 attempts`). Теперь
   `run_until` логирует ошибку события и продолжает — как i2pd, где
   исключение в `HandleI2NPMessage` не валит процесс.
3. **Флаг `allow_reserved_advertise`** в `RouterConfigBuilder` — чтобы
   вообще можно было собрать RI с loopback: i2pd рвёт `SessionConfirmed`
   на `Host mismatch` (`SSU2Session.cpp:1400`), не будь loopback
   разрешён в RI.
4. **«Доигрывание» закрытой сессии** — `Session::drain_until`: см.
   выше, «Почему i2pd ругался на окно отправки».
5. **Исходящий NTCP2** — `Ntcp2Local`/`Ntcp2Transport`, события
   `Established`/`Disconnected` и `Termination` при закрытии:
   см. выше, «Исходящая сессия по NTCP2».
6. **Входящий NTCP2 (accept-loop)** — `Ntcp2Pool::listen`, владение
   `Ntcp2Local`/`local_ri` в пуле, задача таймеров (idle + повтор RI) и
   `Ntcp2SessionWrite::send_router_info`: см. выше, «Входящая сессия по
   NTCP2».

## Флудфилл: что видно живьём

Режим флудфилла (`--floodfill`) — `lsdb` для `LeaseSet`'ов, ответы на
`DatabaseLookup`, `DeliveryStatus` на `DatabaseStore` с `reply_token`,
флуд вперёд. Ниже — что из этого удалось увидеть в прогоне против
одиночного i2pd, а что эта среда проверить не даёт.

**Что подтвердилось живьём.**

- i2pd (не флудфилл, `notransit = true`) **сам публикует нам свой
  `LeaseSet`**: в лог приходит роутерный garlic с `DatabaseStore`
  `store_type = LeaseSet2`, мы его разбираем и валидируем
  (`lsdb::insert`, `published_ms`, `expires_ms`, подпись) — весь путь
  приёма и разбора LS отработан на настоящем i2pd.
- Наши ответы на `DatabaseLookup` (i2pd регулярно шлёт нам RI-запросы,
  когда исследует netDb) уходят и принимаются: `sender` получает
  `DatabaseSearchReply`/`DatabaseStore` по нашим правилам
  (`build_lookup_reply`).
- `DeliveryStatus` на публикацию мы формируем и отправляем **через
  `TunnelGateway`** на `reply.gateway` (`DeliveryStatus` вложен в тело
  `TunnelGateway`, ID тела = `reply_token`) — так же, как i2pd
  (`NetDb.cpp`, `CreateTunnelGatewayMsg`). Формат проверен тестом
  `database_store_ack_goes_through_reply_tunnel`.

**Почему i2pd не подтверждает публикацию.**

i2pd в этой среде всё равно пишет `Destination: Publish confirmation was
not received` и `Can't publish LeaseSet`. Причины две, обе — на стороне
i2pd и on этой конфигурации:

1. **LeaseSet истёк.** i2pd публикует один и тот же `LeaseSet2` от
   00:06 (`published_ms = 1792281988000`, `expires_ms = ...
   1792282573000`), а прогон идёт в 00:45+. Мы его честно **отвергаем**:
   `lsdb::insert` пишет `unpublished или истёкший LeaseSet`. Свежий LS
   destination не строит: в синтетической сети из одного роутера его
   туннели (0 хопов) не работают (см. ниже), а без новых лиз `UpdateLeaseSet`
   не пересобирает LS.
2. **Входящие gateway-сообщения через SSU2 в i2pd не доходят до
   туннельного слоя.** Наш `TunnelGateway` (43 байта: `type = 19`,
   `tunnel_id`, вложенный `DeliveryStatus`) i2pd на уровне SSU2
   принимает (в логе `SSU2: Block type 3 of size 43` + `SSU2: I2NP
   message`), но **ни одной** записи туннельного слоя о нём нет: ни
   `Tunnel: Gateway of N bytes for tunnel ...`, ни `Tunnel: Tunnel not
   found`. Проверка сроком жизни не при чём: копия того же сообщения с
   `expiration +1 час` тоже исчезла молча. То же самое с собственным
   тестом i2pd: `Tunnels: Test of tunnel <id> failed` для его же
   0-hop inbound-туннеля вылетает с самого старта (00:06:28), задолго до
   нашего подключения (00:44).

Механика (по текущему master `79ae673d`, в 2.61.0 код тот же):
`Tunnels::Run` (`libi2pd/Tunnel.cpp:602`) разбирает очередь только если
`m_Queue.Wait (1,0)` вернул `true`; сам `Queue::Wait`
(`libi2pd/Queue.h:75`) — это `wait_for` без проверки `IsEmpty ()`.
Уведомление, пришедшее, пока поток занят, теряется, и сообщение ждёт
следующего `Put`. Плюс просроченные элементы очереди отбрасываются
молча (`Tunnel.cpp:612`: `if (!msg || msg->IsExpired (mts)) continue;` —
ни одного лога). В **гипотеза**, не подтверждённая отдельным репро:
нужен прогон с живым потоком через i2pd (два роутера) или повторная
отправка `TunnelGateway` в тот момент, когда туннельный поток i2pd
ждёт. Пока просто фиксируем: в одиночной конфигурации i2pd
`DeliveryStatus` через туннель до destination не доходит, и наш ответ
здесь ни при чём.

**Что ещё не проверяется в одиночном стенде.**

- Запрос `LeaseSet` у флудфилла: i2pd всегда просит LS через свой
  inbound-туннель (`Destination.cpp:SendLeaseSetRequest`), то есть ответ
  обязан идти `TunnelGateway` — тот же неработающий путь. Ответить
  напрямую нельзя, поэтому живьём эту ветку не увидеть.
- Зашифрованный ответ на lookup (`reply key` + тег →
  `WrapECIESX25519Message`): i2pd применяет шифрование, только когда ответ
  идёт в туннель, — по той же причине не увидеть.
- Флуд вперёд: нужен хотя бы один второй флудфилл в netDb (в стенде их
  ноль).
- Суточная выборка флудфиллов (`andNextDay`) — `TODO(floodfill)` в
  `router_context.rs`.

## Что в логе шумит и почему

- `ShortTunnelBuild` (17 «необработано») — i2pd строит туннели и выбрал
  нас хопом: слой туннелей — шаг 3b, поэтому просто логируем.
- `router: флудфиллов нет — свой RouterInfo не публикуем`: в netDb
  только i2pd, а он не флудфилл (`notransit = true`). Публикация в тик
  включится, когда в netDb появится настоящий флудфилл.
- `router: LeaseSet отвергнут (unpublished/истёк)`: i2pd публикует нам
  один и тот же истёкший `LeaseSet2` (см. выше) — правило верное, данные
  старые.
