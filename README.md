# Hu Tao & Natsuki Lockscreen Player (.deb for iOS 16.7.x jailbreak)

Готовый **lock screen-only** аниме-плеер (Hu Tao + Natsuki) для jailbreak iPhone на iOS 16.7.x.

## Что сделано

- Плеер адаптирован **только под lock screen** (Xen HTML / LockHTML).
- Добавлены картинки персонажей (Hu Tao и Natsuki), обложка, плейлист и элементы управления.
- Репозиторий хранит только исходники (без бинарных `.deb` файлов).

## Сборка пакета (Linux/macOS/WSL)

```bash
./scripts/build_deb.sh
```

После сборки пакет будет в:

```text
build/com.anime.hutao-natsuki-lockscreen_2.0.0_iphoneos-arm64.deb
```

## Сборка `.deb` в Windows 11 (PowerShell)

Запуск из корня репозитория:

```powershell
.\scripts\build_deb.ps1
```

Скрипт для Windows 11 поддерживает 2 backend-режима:
- `wsl` (рекомендуется)
- `docker` (Docker Desktop)

Примеры:

```powershell
# Явно через WSL
.\scripts\build_deb.ps1 -Backend wsl

# Через конкретный дистрибутив WSL
.\scripts\build_deb.ps1 -Backend wsl -WslDistro Ubuntu

# Явно через Docker Desktop
.\scripts\build_deb.ps1 -Backend docker
```

> В PowerShell не нужно запускать `/usr/bin/env ...` — это Linux-путь, которого в Windows нет.

## Установка на iPhone (jailbreak)

```bash
dpkg -i com.anime.hutao-natsuki-lockscreen_2.0.0_iphoneos-arm64.deb
apt-get -f install
```

После установки:
1. Откройте **Xen HTML**.
2. Перейдите в **Lock Screen widgets**.
3. Выберите `HuTaoNatsukiPlayer`.
