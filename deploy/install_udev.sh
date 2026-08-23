#!/usr/bin/env bash
# Установка авто-запуска ghost-lock при подключении iPhone по USB.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Запусти с sudo: sudo ./deploy/install_udev.sh" >&2
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(dirname "$DEPLOY_DIR")"

sed -e "s/@USER@/$REAL_USER/g" -e "s|@PROJECT@|$PROJECT|g" \
    "$DEPLOY_DIR/ghost-lock-watch.sh" > /usr/local/bin/ghost-lock-watch.sh
chmod 755 /usr/local/bin/ghost-lock-watch.sh

cp "$DEPLOY_DIR/99-ghost-lock.rules" /etc/udev/rules.d/
udevadm control --reload-rules

echo "Готово."
echo "  • Правило: /etc/udev/rules.d/99-ghost-lock.rules"
echo "  • Скрипт : /usr/local/bin/ghost-lock-watch.sh (пользователь: $REAL_USER)"
echo "Теперь при подключении айфона кабелем аудит запустится сам,"
echo "логи и отчёты: ~/.local/share/ghost-lock/"
