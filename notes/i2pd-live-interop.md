# Live-проверка против настоящего i2pd

Как поднять локальный i2pd так, чтобы наши live-тесты (`tests/live_i2pd_*.rs`)
до него дошли, и что при этом важно.

## Почему просто `i2pd` не годится

1. **Loopback запрещён по умолчанию.** `reservedrange = true` (дефолт) означает,
   что i2pd
   - отбрасывает входящие SSU2 с reserved-адресов (`SSU2.cpp:767`),
   - отказывается исходящими идти на них (`SSU2.cpp:906`, `Transports.cpp:622`),
   - считает адрес с такой `host=` невалидным при разборе чужого RI
     (`RouterInfo.cpp:283`, адрес помечается `eTransportUnknown`).
   Поэтому для теста по `127.0.0.1` обязателен `reservedrange = false`.
2. **Reseed.** Опции `reseed = false` в 2.61 больше нет, reseed вызывается, если
   netDb меньше `reseed.threshold`, плюс отдельно, если не нашлось ни одного
   роутера (`NetDb.cpp:71-76`). Чтобы инстанс никуда не звонил:
   `--reseed.threshold=0` и `--reseed.file=<пустой .su3>`: файл не разберётся,
   `Bootstrap` на этом закончится.
3. **SSU2-версия.** `ssu2.version` по умолчанию `4`, если OpenSSL собран с PQ
   (`Config.cpp:364`). Мы реализуем классический SSU2 (Noise XK), поэтому
   ставим `ssu2.version = 2`; иначе i2pd публикует в RI `pq=4` и всё это лишний
   шум (сам v2-запрос он примет — версию сессии он берёт из запроса).

## Готовый запуск

`~/.local/opt/i2pd-uu/run-ssu2.sh` + `ssu2.conf` в том же каталоге: отдельный
datadir, только SSU2 на `127.0.0.1:12345`, все TCP-листенеры (webconsole,
HTTP/SOCKS-proxy, SAM) выключены — иначе они конфликтуют с основным роутером
на машине.

```sh
cd ~/.local/opt/i2pd-uu && ./run-ssu2.sh 2>&1 | tee /tmp/opencode/i2pd-ssu2.log
```

`router.info`, который нужен тестам, лежит в `<datadir>/router.info`.

## Прогон

```sh
UU_I2P_LIVE_RI=~/.local/opt/i2pd-uu/datadir/router.info \
UU_I2P_LIVE_SSU2=127.0.0.1:12345 \
RUST_LOG=debug \
cargo test --test live_i2pd_ssu2 -- --ignored --nocapture
```

`UU_I2P_LIVE_SSU2` нужен не всегда: при `reservedrange = false` и `--host=127.0.0.1`
i2pd публикует адрес как обычный (`host=`, `port=` в RI), и `connect` находит его
сам. Переменная остаётся для случая, когда i2pd сидит за NAT и адрес в RI
неопубликованный (тогда в RI есть только `s=`, `i=`, `v=2`, `caps=`).

## Что считается успехом

Со нашей стороны (`RUST_LOG=debug`):

```
connect: no cached token; sending TokenRequest
send_token_request: TokenRequest sent
recv_retry: token received token=...
send_session_request: SessionRequest sent
recv_session_created: SessionCreated ephemeral=...
recv_session_created: NewToken for outgoing requests expires=...
recv_session_created: SessionConfirmed sent
establish: session established
```

и от самого теста:

```
SSU2 established with ...
received RouterInfo: 682 bytes
session closed: true
```

Со стороны i2pd (`--loglevel=debug`):

```
SSU2: Session MTU=1280, max payload size=1220
SSU2: Datetime
SSU2: RouterInfo in SessionConfirmed
SSU2: Session with 127.0.0.1:<наш порт> (<4 буквы нашего ident>) established
SSU2: Termination reason=0        # наш NormalClose
```

`RouterInfo in SessionConfirmed` — самая важная строка: она значит, что i2pd
разобрал и принял наш RI (проверил подпись, нашёл SSU2-адрес с `s=`, и что `s=`
совпадает со статическим ключом из Noise; `SSU2Session.cpp:1394,1415`).

## Мелочи

- Ошибки `Tunnels: Can't create outbound tunnel, no peers available` в логе
  безвредны (netDb пуст), но их источник — сохранённые в `<datadir>/destinations/`
  ключи транзитных дестинейшенов, созданные при первом запуске с включёнными
  proxy. Чтобы шума не было совсем: `rm -rf <datadir>/destinations/*`.
- Порт SSU2 должен совпадать в `ssu2.conf` и в переменных теста.
- Инстанс держит `share = 0`, `notransit = true`, `[upnp] enabled = false`:
  тестовый роутер ничего не публикует и не пропускает.
