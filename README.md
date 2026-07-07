# DiscordObhod

Небольшой Windows-проект на C++17 и WinDivert для экспериментов с обработкой Discord-трафика на уровне пакетов.

Сейчас реализована одна простая стратегия: программа перехватывает исходящий `TCP/443`, ищет TLS `ClientHello` и отправляет его двумя TCP-сегментами. Остальные перехваченные пакеты пропускаются без изменений.

Это не полноценный аналог `zapret`, а компактный прототип, который удобно читать, менять и использовать как основу для дальнейших стратегий.

## Возможности

- режим `bypass` с TCP split для TLS `ClientHello`;
- режим `log` для пассивного наблюдения за TCP/UDP-трафиком;
- настройка точки split через аргумент командной строки;
- сборка через `build.bat`, VS Code task или CMake.

## Зависимости

Нужен WinDivert x64:

```text
https://github.com/basil00/WinDivert/releases
```

Ожидаемая структура локальных файлов:

```text
third_party/windivert/include/windivert.h
third_party/windivert/lib/WinDivert.lib
third_party/windivert/bin/WinDivert.dll
third_party/windivert/bin/WinDivert64.sys
```

Бинарники WinDivert не хранятся в репозитории. Их нужно положить локально перед сборкой.

## Сборка

Через VS Code можно запустить стандартную build task:

```text
Ctrl + Shift + B
```

Или собрать вручную:

```bat
build.bat
```

Также доступна сборка через CMake:

```bat
cmake -S . -B build
cmake --build build --config Release
```

После сборки исполняемый файл будет в `build/`. Скрипт также копирует рядом с ним `WinDivert.dll` и `WinDivert64.sys`.

## Запуск

Запускать нужно из консоли с правами администратора, иначе WinDivert не сможет открыть драйвер.

Обычный режим обхода:

```bat
.\build\DiscordMiniBypass.exe --mode bypass
```

То же самое с подробным выводом:

```bat
.\build\DiscordMiniBypass.exe --mode bypass --verbose
```

Можно менять точку split:

```bat
.\build\DiscordMiniBypass.exe --mode bypass --split 2
```

На практике имеет смысл пробовать небольшие значения вроде `1`, `2`, `5`, `16`, `32`.

Пассивный режим логирования:

```bat
.\build\DiscordMiniBypass.exe --mode log
```

В этом режиме пакеты не изменяются, а информация пишется в `packets.csv`.

## Ограничения

Текущая стратегия работает только с исходящим `TCP/443`. Если проблема связана с UDP, DNS, IP-блокировкой или особенностями конкретного провайдера, одного TLS split может быть недостаточно.

Проект пока сделан как минимальная база: дальше сюда можно добавлять профили, фильтры по хостам/IP, UDP-стратегии и более удобную конфигурацию.

## P.S

- Upstream: https://github.com/basil00/WinDivert
- License: LGPLv3/GPLv2 dual-license
