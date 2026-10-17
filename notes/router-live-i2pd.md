# Живой прогон объединённого роутера против i2pd (SSU2)

Первый прогон собранного роутера: `src/router.rs` (состояние +
транспорт + цикл событий), пример `examples/uu-i2p-router-i2pd.rs`.
До него «в сети» умели только POC'и, дёргавшие `Ssu2Pool` руками.

## Как запускается

```bash
# тестовый i2pd (чистый netDb, reservedrange=false, httpproxy на 4445)
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

## Что в логе шумит и почему

- `ShortTunnelBuild` (17 «необработано») — i2pd строит туннели и выбрал
  нас хопом: слой туннелей — шаг 3b, поэтому просто логируем.
- `router: флудфиллов нет — свой RouterInfo не публикуем`: в netDb
  только i2pd, а он не флудфилл (`notransit = true`). Публикация в тик
  включится, когда в netDb появится настоящий флудфилл.
- `DatabaseStore не RouterInfo store_type=LeaseSet2` — i2pd опубликовал
  нам LeaseSet своего destination'а; хранилище LS — шаг 3c.
