# Hu Tao & Natsuki Lockscreen Player (.deb for iOS 16.7.x jailbreak)

Готовый **lock screen-only** аниме-плеер (Hu Tao + Natsuki) для jailbreak iPhone на iOS 16.7.x.

## Установка (без локальной сборки)

Скачайте готовый `.deb` из **GitHub Releases** этого репозитория и установите на устройство:

```bash
dpkg -i com.anime.hutao-natsuki-lockscreen_<version>_iphoneos-arm64.deb
apt-get -f install
```

После установки:
1. Откройте **Xen HTML**.
2. Перейдите в **Lock Screen widgets**.
3. Выберите `HuTaoNatsukiPlayer`.

## Как публикуется `.deb` в Releases

При публикации Release (или вручную через `workflow_dispatch`) GitHub Actions автоматически:
- собирает пакет из `src/app`;
- создаёт `.deb`;
- прикрепляет его к Release.

Workflow: `.github/workflows/release-deb.yml`.
