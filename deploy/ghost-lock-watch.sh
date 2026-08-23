#!/usr/bin/env bash
# ghost-lock-watch: вызывается udev при подключении iPhone.
# Запускает аудит от имени обычного пользователя, пишет лог.
GHOST_USER="@USER@"
PROJECT="@PROJECT@"
LOG_DIR="$(getent passwd "$GHOST_USER" | cut -d: -f6)/.local/share/ghost-lock"
LOG="$LOG_DIR/udev.log"
mkdir -p "$LOG_DIR"

# Троттлинг: не чаще одного запуска в 90 секунд
STAMP="/tmp/.ghost-lock-last"
NOW="$(date +%s)"
LAST="$(cat "$STAMP" 2>/dev/null || echo 0)"
if (( NOW - LAST < 90 )); then
    exit 0
fi
echo "$NOW" > "$STAMP"

{
    echo "=== $(date '+%Y-%m-%d %H:%M:%S') iPhone подключён — авто-аудит ==="
    sudo -u "$GHOST_USER" python3 "$PROJECT/ghost_lock/ghost_lock.py" audit
    echo
} >> "$LOG" 2>&1
