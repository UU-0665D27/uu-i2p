# PeerTest в SSU2: разбор и остаток работы

Статус на `f489825` (+ модуль `src/ssu2_peer_test.rs`): реализован и
проверен живьём только путь «Боб без Charlie». Ниже — что делает i2pd,
что уже есть у нас и что осталось, чтобы не разбирать это заново.

## Схема

- **msg 1**: Alice → Bob внутри установленной SSU2-сессии. Alice просит
  проверить свой внешний адрес. В подписанных данных — `ver = 2`,
  `nonce`, `ts`, её endpoint; подпись по
  `"PeerTestValidate" || bhash || данные` (`bhash` — хеш Боба).
- **msg 2**: Bob → Charlie внутри *другой* установленной сессии. Bob
  добавляет к пакету `RouterInfo` Алисы (блок `RouterInfo`, `frag = 1`)
  и блок PeerTest с `router hash` = хеш Алисы. Подписанные данные — те
  же, что в msg 1 (Боб их не трогает).
- **msg 3**: Charlie → Bob. Charlie проверяет подпись Алисы
  (`bhash` = Боб, без `ahash`), затем подписывает те же данные своим
  ключом: `"PeerTestValidate" || bhash(Боб) || ahash(Алиса) || данные`.
  Код `Accept` или ошибка Charlie.
- **msg 4**: Bob → Alice. Боб пересылает подпись Charlie из msg 3 и
  добавляет `RouterInfo` Charlie; `router hash` = хеш Charlie. Alice
  проверяет подпись Charlie с `bhash` = Боб и `ahash` = сама Алиса.
- **msg 5–7**: отдельная «out-of-session» сессия Alice ↔ Charlie
  (`SSU2PeerTestSession`). Нужна, чтобы Alice увидела *исходящий* адрес
  Charlie и сравнила его с тем, что видит Боб (NAT/symmetric NAT).
  Conn ID выводятся из nonce: `destConnID = (nonce << 32) | nonce`,
  `sourceConnID = ~destConnID`.

Точные места в i2pd:

- `SSU2Session::HandlePeerTest` — `libi2pd/SSU2Session.cpp:2548-2790`;
- `SSU2Session::CreatePeerTestBlock` — `:3256-3306` (сборка блока и
  подписанных данных msg 1 — `:3277-3306`);
- `SSU2PeerTestSession` (msg 5–7, крипта заголовка/payload) —
  `libi2pd/SSU2OutOfSession.cpp:16-236`;
- выбор Charlie — `SSU2Server::GetRandomPeerTestSession`,
  `libi2pd/SSU2.cpp:601-626` (установленная сессия, family, версия
  собеседника ≥ 0.9.62, `SSU2_TESTING`, не сам запросивший);
- таймауты/повторы — `SSU2Session.h:38` (60 с),
  `SSU2OutOfSession.h:19-21` (3 с ± 2 с, максимум 3 повтора);
- `AddConnectedRecently` — `SSU2.cpp:1130+`.

## Что реализовано

- `src/ssu2_peer_test.rs`: подписанные данные (`PeerTestValidate`,
  bhash/ahash, IPv4/IPv6), подпись/проверка, `PeerTestSession` (conn ID
  из nonce, повторы, истечение) и сборка/разбор out-of-session пакета
  (заголовок + `headerX` ChaCha20 + AEAD + `DateTime`/`Address`/
  `PeerTest`/`Padding`). Тесты — `tests/ssu2_peer_test.rs`.
- `Ssu2Local`: `keys: Option<I2PPrivateKeys>` (`with_private_keys`,
  `from_router_config` берёт из `RouterConfig::keys()`); `I2PPrivateKeys`
  теперь `Clone`.
- `Session.remote_ri` + `PoolState.ri_cache`: RI собеседника хранится в
  сессии, RI из блока кладётся в кеш **до** обработки PeerTest в том же
  payload'е. Это закрывает msg 2/3/4.
- Роли:
  - Боб (msg 1): выбор Charlie (`SSU2_TESTING`, версия ≥ 0.9.62,
    семейство из `asz`, не Алиса), `nonce → сессия Алисы`, msg 2 с RI
    Алисы; нет Charlie — msg 4 с `BobNoCharlieAvailable`.
  - Charlie (msg 2): проверка подписи Алисы по RI из кеша, подпись
    `bhash = Боб`, `ahash = Алиса`, msg 3 Бобу, msg 5 Алисе на endpoint
    из подписи.
  - Боб (msg 3 → 4): RI Charlie + подпись, `router hash` = Charlie.
  - Алиса (msg 4): проверка подписи Charlie (`ahash` = свой хеш), адрес
    и intro-ключ Charlie из RI; msg 6 сразу, если msg 5 уже пришёл, иначе
    с задержкой 3–5 с.
  - Out-of-session msg 5/6/7: повторы 3 с ± 2 с (максимум 3), ответы
    6/7 отменяют таймер, сессия живёт 60 с; msg 6/7 несут блок
    `Address`. Результат — событие `Ssu2Event::PeerTestResult`
    (`TransportEvent` в роутере), решение о статусе остаётся вызывающему
    (шов сознательный: пул не знает про `RouterContext`).
- Публичный запуск: `Ssu2Pool::start_peer_test(&IdentHash)` (роль Alice).
- Проверка: `tests/ssu2_pool.rs::peer_test_between_three_pools` —
  три наших пула A/B/C, весь путь msg 1 → 2 → 3 → 4 → 5 → 6 → 7,
  включая out-of-session и проверку подписей. Плюс round-trip пакета
  в `tests/ssu2_peer_test.rs`.

## Что осталось

1. **Статус роутера по результату.** i2pd в msg 4/5/7 меняет
   `RouterStatus`/`RouterError` (OK, Firewalled, SymmetricNAT). У нас
   событие `PeerTestResult` только сообщает endpoint; политику (и публикацию
   адреса) должен решать роутер. Отдельный шов `PeerTestPolicy` не заводили,
   пока нет потребителя.
2. **`IsConnectedRecently`.** i2pd не шлёт msg 5, если недавно был hole
   punch; у нас это состояние не ведётся, поэтому Charlie всегда отвечает
   msg 5. Для NAT-сценариев — TODO(`floodfill`/`suu2-pool-relay`).
3. **Лимиты.** Нет счётчика одновременных PeerTest на роутер
   (`BobLimitExceeded`/`CharlieLimitExceeded`); сейчас ограничение только
   по таймауту 60 с.
4. **Живой стенд.** С одним i2pd наблюдаема только ветка «Charlie нет»
   (i2pd — и Alice, и единственный роутер; второго роутера для Charlie
   нет). Полный сценарий проверяется тремя нашими пулами; живой
   трёхроутерный стенд по-прежнему нужен для interop msg 5–7.

## Живой стенд

Запуск прежний: i2pd пишет `PeerTest msg=4 code=2` и
`Peer test 4 error code 2 from ...` (см. `router-live-i2pd.md`) — это
ветка «нет Charlie». Для полного теста нужны два внешних роутера или
наши пулы A/B/C.
