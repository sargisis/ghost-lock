#!/bin/sh
# ghost-lock: Proton VPN + Portmaster — весь DNS через Portmaster.
#
# Proton VPN при подключении вешает на туннель proton0 свои DNS-серверы
# (10.2.0.1, ~.). systemd-resolved начинает слать им запросы напрямую,
# Portmaster блокирует это как «обход DNS» («Blocked Bypass Attempt by System
# DNS Client») — и каждый запрос висит до таймаута. Скрипт убирает DNS
# туннеля из resolved: запросы идут в Portmaster (127.0.0.17), а он сам
# шифрует их (DoT) и отправляет через тот же туннель.
#
# Срабатывает только если Portmaster слушает 127.0.0.17:53 — иначе DNS
# остался бы без серверов.
#
# Установка:
#   sudo install -m 755 deploy/nm-dispatcher-vpn-dns.sh \
#        /etc/NetworkManager/dispatcher.d/90-ghost-lock-vpn-dns
# Удаление: sudo rm /etc/NetworkManager/dispatcher.d/90-ghost-lock-vpn-dns
#
# ghost-lock: Proton VPN + Portmaster — all DNS through Portmaster.
# On connect Proton VPN puts its DNS servers on proton0 (10.2.0.1, ~.);
# systemd-resolved queries them directly, Portmaster blocks that as a DNS
# bypass and every lookup hangs until timeout. This script removes the
# tunnel's DNS from resolved so lookups go to Portmaster (127.0.0.17), which
# encrypts them (DoT) and sends them through the same tunnel. It only acts
# when Portmaster listens on 127.0.0.17:53, otherwise DNS would be left with
# no servers.

IFACE="$1"
ACTION="$2"
VPN_IFACE="${GHOST_LOCK_VPN_IFACE:-proton0}"

[ "$IFACE" = "$VPN_IFACE" ] || exit 0
case "$ACTION" in
    up|vpn-up|dhcp4-change|dhcp6-change) ;;
    *) exit 0 ;;
esac

ss -lun 2>/dev/null | grep -q '127\.0\.0\.17:53 ' || exit 0

# NetworkManager применяет DNS туннеля чуть позже события up
# NetworkManager applies the tunnel DNS slightly after the up event
sleep 1
resolvectl dns "$VPN_IFACE" ""
resolvectl domain "$VPN_IFACE" ""
resolvectl default-route "$VPN_IFACE" false
resolvectl flush-caches
logger -t ghost-lock "DNS туннеля $VPN_IFACE убран: DNS идёт через Portmaster"
