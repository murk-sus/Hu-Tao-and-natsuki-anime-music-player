# Hu Tao & Natsuki Anime Music Player (.deb for iOS 16.7.x jailbreak)

Мини-плеер в аниме-стиле (Hu Tao + Natsuki), который ставится как `.deb` пакет на jailbreak-устройства с iOS 16.7.x.

## Что внутри

- Веб-плеер с обложкой в стиле Hu Tao и Natsuki.
- 3 трека (потоковые ссылки), кнопки play/pause/next/prev и таймлайн.
- CLI-лаунчер `huplayer`, который открывает плеер через `uiopen`.

## Сборка `.deb`

```bash
./scripts/build_deb.sh
```

После сборки пакет появится в:

```text
build/com.anime.hutao-natsuki-player_1.0.0_iphoneos-arm64.deb
```

## Установка на jailbreak iPhone

1. Передайте `.deb` на устройство (например, через `scp`).
2. Установите:
   ```bash
   dpkg -i com.anime.hutao-natsuki-player_1.0.0_iphoneos-arm64.deb
   apt-get -f install
   ```
3. Запустите в терминале на iPhone:
   ```bash
   huplayer
   ```

## Важно

- Целевая платформа: iOS 16.7.x (jailbreak).
- Для корректного запуска нужен `uiopen`.
- В текущей версии аудио берётся из публичных URL (нужен интернет).
