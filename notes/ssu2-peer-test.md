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

## Что уже есть у нас

- `src/ssu2_peer_test.rs`: разбор/сборка подписанных данных, подпись и
  проверка `PeerTestValidate` (EdDSA), IPv4/IPv6 endpoint, тесты
  (`tests/ssu2_peer_test.rs`).
- `PoolState::handle_peer_test`: дроп из неустановленной сессии
  (как i2pd 3.0), разбор блока; msg 1 → `handle_peer_test_msg1`.
- `handle_peer_test_msg1`: если другой установленной сессии нет —
  msg 4 с `BobNoCharlieAvailable` и эхом подписанных данных Алисы.
  Живой прогон: i2pd пишет `PeerTest msg=4 code=2` и
  `Peer test 4 error code 2 from MmjO` (см. `router-live-i2pd.md`).

## Что осталось

1. **RI собеседника в сессии.** Bob'у нужен `RouterInfo` Алисы для msg 2,
   а Charlie — для проверки её подписи (в msg 2 он приходит блоком, но
   его надо сохранить до обработки PeerTest). Сейчас пул отдаёт RI
   наружу событием и не хранит. План: поле `remote_ri: Option<Vec<u8>>`
   в `Session` (заполнять в `accept_remote_router_info` и в
   `start_connect`) + маленький кеш `HashMap<IdentHash, Vec<u8>>` для
   RI, пришедших блоком.
2. **Ключи для подписи Charlie.** Нужен `I2PPrivateKeys` в `Ssu2Local`
   (сейчас там только X25519/intro/RI) — добавить `keys` из
   `RouterConfig::keys()`; `I2PPrivateKeys` сделать `Clone`.
3. **Bob, msg 1 с Charlie.** Выбрать Charlie: установленная сессия,
   семейство из `asz` Алисы, `SSU2_TESTING` в его RI, версия ≥ 0.9.62,
   не Алиса. Запомнить `nonce → сессия Алисы` (60 с), отправить msg 2
   с RI Алисы.
4. **Charlie, msg 2.** Взять RI Алисы (блок в том же payload'е), проверить
   подпись с `bhash` = Боб, подписать msg 3 (`bhash` = Боб,
   `ahash` = Алиса), отправить msg 3; затем out-of-session msg 5
   (см. п. 6). Коды ошибок: `CharlieAliceIsUnknown`,
   `CharlieSignatureFailure`, `CharlieUnsupportedAddress`,
   `CharlieAliceIsAlreadyConnected`.
5. **Bob, msg 3 → msg 4.** По nonce найти сессию Алисы, переслать
   подпись Charlie, приложить RI Charlie, `router hash` = Charlie.
   Если сессия пропала — молча дропнуть (`Unknown peer test 3 nonce`).
6. **Out-of-session msg 5–7.** Формат пакета:
   - 16-байтовый заголовок: `destConnID (8)`, случайный `packetNum (4)`,
     `type = PeerTest`, `ver = 2`, `netId`, `flag = 0`;
   - обе половины заголовка XOR с `header_mask(intro_key, last-24/-12)`;
   - 16 байт после заголовка: `sourceConnID (8) || 0 (8)`, зашифрованы
     ChaCha20 с intro-ключом и нулевым nonce;
   - payload — AEAD ChaCha20-Poly1305 с intro-ключом, nonce из
     `packetNum`, AD = 32-байтовый заголовок; внутри `DateTime`,
     `Address` (только msg 6/7), `PeerTest`, `Padding`;
   - повторы msg 5/6 через 3 с ± 2 с, не больше 3 раз; ответы 6/7
     отменяют таймер; сессия живёт 60 с.
7. **Alice, msg 4.** Проверить подпись Charlie (`bhash` = Боб,
   `ahash` = свой хеш), обновить `router status`/`error` по результату
   msg 5–7; для этого нужен шов политики состояния роутера, которого
   сейчас нет (пул не знает про `RouterContext`).
8. **Тест без второго хоста.** Поднять три пула A/B/C: A↔B и C↔B;
   A шлёт msg 1; B пересылает msg 2; C отвечает msg 3; B пересылает
   msg 4; A проверяет подпись. Для этого нужен публичный способ
   отправить PeerTest-блок из теста (сейчас есть только внутренние
   ответы), например `Ssu2Pool::send_peer_test_block(ident, body)`.
   Out-of-session 5–7 в такой тест не входят — их проверять отдельно.

## Живой стенд

С одним собеседником наблюдаем только ветку «Charlie нет»: i2pd —
и Alice, и единственный роутер, поэтому `GetRandomPeerTestSession`
выбирает только нас (Боба), а второго роутера для Charlie нет.
Полный сценарий требует трёх роутеров, поэтому TODO(peer-test) закрывать
нельзя — только держать код под тестами с фейками/тремя пулами.
