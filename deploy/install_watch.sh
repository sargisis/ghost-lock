#!/usr/bin/env bash
# Установка glock-watch как пользовательского systemd-сервиса.
# Без sudo: сервис живёт в ~/.config/systemd/user/.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/4] Сборка glock-watch…"
(cd "$PROJECT/go" && go build -o bin/glock-watch ./cmd/glock-watch)

mkdir -p "$HOME/.local/bin" "$HOME/.config/systemd/user"

echo "[2/4] Установка бинарников…"
install -m 755 "$PROJECT/go/bin/glock-watch" "$HOME/.local/bin/"
cat > "$HOME/.local/bin/ghost-lock-audit" <<EOF
#!/usr/bin/env bash
cd "$PROJECT"
python3 ghost_lock/ghost_lock.py audit
EOF
chmod 755 "$HOME/.local/bin/ghost-lock-audit"

echo "[3/4] Юнит systemd…"
sed -e "s|%h|$HOME|g" \
    "$PROJECT/deploy/glock-watch.service" > "$HOME/.config/systemd/user/glock-watch.service"

echo "[4/4] Активация…"
systemctl --user daemon-reload
systemctl --user enable --now glock-watch.service

if command -v loginctl >/dev/null && ! loginctl show-user "$USER" 2>/dev/null | grep -q Linger=yes; then
    echo
    echo "Подсказка: чтобы сервис поднимался сразу при включении компа (до логина):"
    echo "  sudo loginctl enable-linger $USER"
fi

systemctl --user status glock-watch.service --no-pager | head -5 || true
