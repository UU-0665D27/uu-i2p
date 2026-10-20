# AGENTS.md

Rust-переписывание i2pd: SSU2, NTCP2, netDb/LSDB, флудфилл-ядро.
Эталон поведения — C++-клон в `/home/u_uu/FOR_LLM/libi2pd/`; при сомнениях
сверяться с ним и ссылаться на `File.cpp:line` в комментариях. Ветка — `gpt`.

`src/lib.rs` — библиотека, `src/main.rs` — только инициализация tracing.
Запускаемые демо лежат в `examples/`.

## Команды

```sh
cargo test                                     # всё
cargo test --test router -- database_store     # один файл / фильтр
cargo clippy --all-targets                     # линты в Cargo.toml, см. ниже
rustfmt --edition 2024 src/foo.rs              # форматировать ОДИН файл
```

- Нельзя `cargo fmt -- <file>`: путь уходит в rustfmt как аргумент, и cargo
  форматирует всё дерево. Только `rustfmt` напрямую.
- `cargo fmt --check` уже грязен в `tests/{base32,router_info_address,
  ssu2_ack,ssu2_block,ssu2_crypto,ssu2_header}.rs`; это старые diff'ы — не
  переформатировать чужие файлы.
- `all`/`pedantic`/`nursery`/`perf` = `deny` в `Cargo.toml` и действуют на
  тесты и примеры тоже. Чинить код, а не глушить линты общим `#[allow]`.
- `tests/timestamp.rs::adjust_time_offset_is_cumulative` изредка падает при
  параллельном прогоне (общий глобальный офсет) — перезапускать файл отдельно.

## Конвенции

- Док-комментарии, module-docs, обычные комментарии и тела коммитов — по-русски;
  идентификаторы и публичный API — по-английски.
- Новое поведение: сначала трейт-шов для решения, затем дефолтная реализация,
  повторяющая i2pd; швы описывать в module-docs.
- Нереализованное помечать `// TODO(имя): ...` (`floodfill`, `ban`,
  `suu2-pool-relay`). Найденные баги i2pd — в `notes/i2pd-bugs.md`,
  разборы живых прогонов — в `notes/router-live-i2pd.md` и
  `notes/i2pd-live-interop.md`.
- Тесты — только `tests/<модуль>.rs`; inline-модулей `#[cfg(test)]` в `src/`
  нет. Сетевые тесты строятся на подделках, см. `tests/router.rs`
  (`FakeTransport`, `FakeClock`, `TestPolicy`, `RecordingObserver`).
- Зависимости — pre-release RustCrypto (`chacha20` 0.10, `sha2` 0.11,
  `p256` 0.14, `rand` 0.10) и edition 2024 с let-chains. API брать из
  существующих модулей, а не из старых доков/примеров.
- Логи в стиле i2pd: `fn_name: message` + структурированные поля,
  `trace!`/`debug!`/`warn!`.

## Устройство

- `src/router.rs` — `Router`, склейка с транспортами, швы `TransportPool`,
  `RouterPolicy`, `Clock`, `RouterObserver`.
- `src/router_context.rs` — синхронное состояние: ключи, netDb, LSDB,
  garlic, обработка `DatabaseStore`/`DatabaseLookup`.
- `src/ssu2_*.rs` — примитивы SSU2; `src/ssu2_pool.rs` — UDP-транспорт
  (один сокет + одна задача, синхронный `PoolState`).
- `src/ntcp2.rs` / `src/ntcp2_pool.rs` — рукопожатие/сессия NTCP2 и TCP-пул.
- `src/netdb.rs` — RouterInfo, `src/lsdb.rs` — LeaseSet'ы флудфилла,
  `src/transport_ban.rs` — общий бан-лист SSU2+NTCP2.

## Живой стенд i2pd

Локальный i2pd: `~/.local/opt/i2pd-uu/run-ssu2.sh`, лог
`/tmp/opencode/i2pd-ssu2.log`; SSU2 `127.0.0.1:12345`, NTCP2 `:12346`,
HTTP-прокси `:4445`. В конфиге `reservedrange = false` и `ssu2.version = 2`.
Его RI — `~/.local/opt/i2pd-uu/datadir/router.info`.

Live-тесты помечены `#[ignore]` и читают `UU_I2P_LIVE_RI` (опционально
`UU_I2P_LIVE_SSU2=host:port`). Без переменной тест пишет `warn!` и просто
возвращается — «зелёный» прогон без стенда ничего не проверил:

```sh
UU_I2P_LIVE_RI=~/.local/opt/i2pd-uu/datadir/router.info \
UU_I2P_LIVE_SSU2=127.0.0.1:12345 RUST_LOG=debug \
cargo test --test live_i2pd_ssu2 -- --ignored --nocapture
```

Полное демо роутера (`--ntcp2`, `--accept` — дополнительные режимы):

```sh
RUST_LOG=uu_i2p=debug cargo run --example uu-i2p-router-i2pd -- \
    ~/.local/opt/i2pd-uu/datadir/router.info 127.0.0.1:12345 --secs 40
```

`./run_test_live_i2pd_ntcp2.sh` — то же для NTCP2 с RI `i2pd-debug.ri`
в корне репозитория.

Loopback-interop работает только потому, что стенд ставит
`reservedrange = false`; с нашей стороны нужны
`RouterConfigBuilder::allow_reserved_advertise(true)` и loopback-адрес в своём
RI (i2pd рвёт `SessionConfirmed` при `Host mismatch`).

## Git

Коммиты GPG-подписанные (`commit.gpgsign=true`): `git commit -S -F -`.
Заголовок по-английски, тело по-русски.
