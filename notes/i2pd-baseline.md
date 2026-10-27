# Зафиксированный базовый i2pd

Обновлено 2026-10-27: пользователь подтянул и рабочую копию, и зеркало
`/home/u_uu/FOR_LLM/libi2pd` до `bbfd3485` — там фикс #2617
(`Stream::SavePacket` обнуляет `packet->from`). Зеркало и источник снова
совпадают.

## Рабочая копия-источник

| поле | значение |
| --- | --- |
| путь | `/home/u_uu/Documents/o/code/c/i2pd` |
| remote | `origin` = `github.com:PurpleI2P/i2pd.git` (push — `uu/i2pd.git`) |
| ветка | `openssl` (== `origin/openssl`, `origin/HEAD`) |
| HEAD | `bbfd34856fd8ec8a4fd0b401a650a256aa05a617` |
| describe | `3.0.0-41-gbbfd3485` |
| дата коммита | 2026-10-27 10:31:04 -0400 |
| базовый тег | `3.0.0` = `137dde2f433b2142eec7a2307608d7d082be086f` |

Локальная незакоммиченная правка: `daemon/UnixDaemon.cpp` (+78 строк) —
подмена `std::__glibcxx_assert_fail` своей реализацией, которая печатает
сработавший assert и `boost::stacktrace`. Нужна, чтобы ловить стектрейс
в asan+ubsan-сборке. Копия — `notes/i2pd-baseline-UnixDaemon.patch`.

## Зеркало для справок

| поле | значение |
| --- | --- |
| каталог | `/home/u_uu/FOR_LLM/libi2pd` |
| корень git-репозитория | `/home/u_uu/FOR_LLM` (исходники i2pd лежат в подкаталоге `libi2pd/`; рядом `daemon/`, `libi2pd_client/`, `tests/`, …) |
| HEAD | `bbfd34856fd8ec8a4fd0b401a650a256aa05a617` |
| describe | `3.0.0-41-gbbfd3485` |
| дата коммита | 2026-10-27 10:31:04 -0400 |

Важно: `FOR_LLM` — это не отдельный git-клон, а корень репозитория, в
котором исходники разложены по подкаталогам, а бинарники
(`i2pd_asan_ubsan_*`, `i2pd_fast_debug_*`) — неотслеживаемые файлы в том
же корне. С `git pull` в `/home/u_uu/FOR_LLM/libi2pd` обновился весь
рабочий каталог, потому что каталог — лишь подпапка репозитория.

Бинарники рядом (`…_3.0.0-5-g9725b8b2`) теперь **устарели** — это сборки
прошлого снапшота; стенд их не использует.

Именно на это дерево ссылаются комментарии вида `File.cpp:line` в `src/`.
Пока нумерация совпадает с источником, но после каждого `git pull` её
надо перепроверять: в обновлении `9725b8b2..5bcf6101` `libi2pd/Signature.cpp`
прибавил 29 строк (правки ниже него съехали), а `SSU2Session.cpp`,
`SSU2.cpp`, `NetDb.cpp`, `Tunnel.cpp`, `RouterContext.cpp` не менялись —
поэтому 90 ссылок на `SSU2Session.cpp` и остальные остались валидными.

Что приехало в `9725b8b2..5bcf6101`: torrent-клиент (сохранение частей,
закрытие файлов, проверка применённого блока, datagram tracker на 6969,
`cancel`), UPnP-патч, `Makefile.linux` и фикс DSA-подписи в
`libi2pd/Signature.cpp` (`b31431ba`, см. `notes/i2pd-bugs.md` № 12).
Транспортов SSU2/NTCP2 и netDb эти коммиты не касались.

## Стенд

`~/.local/opt/i2pd-uu/run-ssu2.sh`:

```sh
I2PD=/home/u_uu/Documents/o/code/c/i2pd/i2pd_asan_ubsan_3.0.0-20-g5bcf6101
```

- собран 2026-10-25 10:28, размер 140 781 464 Б,
  `sha256` начинается на `09564419481c6cda0c7086fd2f6635d3`;
- т.е. стенд крутит 20-g, а не 5-g — старые логи `i2pd-ssu2.log`
  снимать/сравнивать с оглядкой на это;
- лог: `/tmp/opencode/i2pd-ssu2.log`, SSU2 `127.0.0.1:12345`,
  NTCP2 `:12346`, HTTP-прокси `:4445`.

## Как обновлять

```sh
cd /home/u_uu/Documents/o/code/c/i2pd
git pull
git rev-parse HEAD; git describe --tags --always
./uu_build.sh                       # тихая сборка, ждать ~4 с
cp i2pd_asan_ubsan_<describe> /home/u_uu/FOR_LLM/
# затем поправить I2PD= в run-ssu2.sh, kill -9 старого процесса
cd /home/u_uu/FOR_LLM/libi2pd && git pull   # зеркало для справок
```

После этого дописать строку в историю ниже и перепроверить grep'ом
комментарии с номерами строк по изменившимся `.cpp`/`.hpp`.

## История

| дата | наша ветка | источник (c/i2pd) | зеркало (FOR_LLM) | стенд |
| --- | --- | --- | --- | --- |
| 2026-10-25 | `928f217` | `5bcf6101` / 3.0.0-20-g | `9725b8b2` / 3.0.0-5-g | 3.0.0-20-g (asan+ubsan) |
| 2026-10-25 | `6ded7e9` | `5bcf6101` / 3.0.0-20-g | `5bcf6101` / 3.0.0-20-g | 3.0.0-20-g (asan+ubsan) |
