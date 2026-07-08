# DiscordObhod

Windows-инструмент на C++17 + WinDivert для локального обхода блокировок Discord на уровне сетевых пакетов.

Программа запускает один встроенный авто-профиль:

- находит исходящие TLS `ClientHello` к доменам Discord;
- отправляет fake ClientHello с плохой TCP checksum и маленьким TTL;
- режет реальный `ClientHello` внутри SNI;
- отправляет части в disorder-порядке.

Идея такая: обычный запуск `.exe` включает рабочий профиль, а `--debug` нужен только для диагностики.

## Зависимости

Нужен WinDivert x64:

```text
https://github.com/basil00/WinDivert/releases
```

Локальная структура:

```text
third_party/windivert/include/windivert.h
third_party/windivert/lib/WinDivert.lib
third_party/windivert/bin/WinDivert.dll
third_party/windivert/bin/WinDivert64.sys
```

## Сборка

```bat
build.bat
```

После сборки в `build/` появится:

```text
DiscordMiniBypass.exe
WinDivert.dll
WinDivert64.sys
```

`DiscordMiniBypass.exe` содержит manifest `requireAdministrator`, поэтому при обычном запуске Windows должна показать UAC-запрос.

## Запуск

Обычный запуск:

```bat
.\build\DiscordMiniBypass.exe
```

Отладочный запуск:

```bat
.\build\DiscordMiniBypass.exe --debug
```

В debug-режиме программа пишет подробный вывод в консоль и добавляет строки в `packets.csv`.

## Ограничения

Этот подход работает против DPI, который анализирует TLS/SNI. Если Discord у провайдера блокируется по IP, DNS, маршруту или на стороне updater/CDN, одного локального packet desync может быть недостаточно. В таком случае нужен другой слой: DNS/DoH, прокси или туннель.

## WinDivert

- Upstream: https://github.com/basil00/WinDivert
- License: LGPLv3/GPLv2 dual-license
