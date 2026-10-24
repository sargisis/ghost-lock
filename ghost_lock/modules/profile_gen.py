"""Генератор DNS-профиля (dns_shield.mobileconfig) из пресета.

  • ServerAddresses — IP самого DoH-сервера: телефону не нужен обычный DNS,
    чтобы найти DoH-сервер (чужая сеть не увидит и не подменит этот запрос).
  • AllowFailover = false — фолбэка на открытый DNS нет: сеть, блокирующая
    DoH, не переведёт телефон на нешифрованный DNS тихо. Плата — без
    доступного DoH нет и интернета; какие пресеты проходят в текущей сети,
    показывает команда dns-check.
  • ProhibitDisablement = false — щит всегда можно выключить в настройках.

DNS profile generator (dns_shield.mobileconfig) built from a preset.

  • ServerAddresses — IPs of the DoH server itself: the phone needs no plain
    DNS to find it (a foreign network can neither see nor spoof that lookup).
  • AllowFailover = false — no fallback to plain DNS: a network blocking DoH
    cannot silently downgrade the phone. The price: no reachable DoH, no
    internet; the dns-check command shows which presets pass on this network.
  • ProhibitDisablement = false — the shield can always be toggled off in Settings.
"""

from __future__ import annotations

from pathlib import Path

from .. import config

# Фиксированные UUID и идентификатор БЕЗ имени пресета: iOS опознаёт профиль
# по PayloadIdentifier, и смена пресета должна ЗАМЕНЯТЬ профиль, а не ставить
# второй рядом (раньше в идентификаторе был пресет — получались дубли).
# Fixed UUIDs and an identifier WITHOUT the preset name: iOS recognizes a
# profile by PayloadIdentifier, and switching presets must REPLACE it rather
# than install a second one alongside (the preset used to be in the
# identifier, which produced duplicates).
PAYLOAD_UUID_DNS = "fc4fdd46-8662-42c1-aa22-e4637bcb2fcf"
PROFILE_UUID = "5285d060-b4a6-4801-a404-9b673a40dcaf"

TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!--
  ghost-lock :: DNS Shield (пресет: {{PRESET_NAME}})

  Блокирует на уровне DNS: {{DESC}}.

  ServerAddresses — IP самого DoH-сервера (без открытого DNS-запроса).
  Фолбэка на открытый DNS нет (AllowFailover=false): если сеть блокирует
  DoH, интернета не будет — проверь сеть командой dns-check.

  Отключить: Настройки → Основное → VPN и управление устройством → DNS.
-->
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>

      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>{{DOH_URL}}</string>
        <key>ServerAddresses</key>
        <array>{{ADDRESSES_XML}}
        </array>
        <key>AllowFailover</key>
        <false/>
      </dict>

      <!-- Без супервизии игнорируется; профиль всегда можно снять вручную -->
      <key>ProhibitDisablement</key>
      <false/>

      <key>PayloadDisplayName</key>
      <string>ghost-lock DNS Shield · {{PRESET_NAME}}</string>
      <key>PayloadIdentifier</key>
      <string>cc.ghostlock.dnsshield</string>
      <key>PayloadUUID</key>
      <string>{{PAYLOAD_UUID}}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>ghost-lock: зашифрованный DNS (DoH), блокировка {{DESC}}. Без фолбэка на открытый DNS.</string>
  <key>PayloadDisplayName</key>
  <string>ghost-lock DNS Shield ({{PRESET_NAME}})</string>
  <key>PayloadIdentifier</key>
  <string>cc.ghostlock.dnsshield.profile</string>
  <key>PayloadOrganization</key>
  <string>ghost-lock</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{{PROFILE_UUID}}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""


class PresetError(ValueError):
    pass


def resolve_doh_url(preset_name: str, nextdns_id: str | None = None) -> str:
    try:
        preset = config.RESOLVER_PRESETS[preset_name]
    except KeyError:
        raise PresetError(
            f"Неизвестный пресет {preset_name!r}. Доступны: {', '.join(config.RESOLVER_PRESETS)}"
        ) from None
    url = preset["doh"]
    if preset.get("needs_id"):
        if not nextdns_id:
            raise PresetError(
                "Для пресета 'nextdns' укажи --nextdns-id (ID конфига из my.nextdns.io)"
            )
        if not nextdns_id.replace("-", "").isalnum() or len(nextdns_id) < 6:
            raise PresetError(f"Подозрительный ID NextDNS: {nextdns_id!r}")
        url = url.format(config_id=nextdns_id)
    return url


def render_profile(preset_name: str, nextdns_id: str | None = None) -> str:
    try:
        preset = config.RESOLVER_PRESETS[preset_name]
    except KeyError:
        raise PresetError(
            f"Неизвестный пресет {preset_name!r}. Доступны: {', '.join(config.RESOLVER_PRESETS)}"
        ) from None

    addresses_xml = "".join(
        f"\n          <string>{ip}</string>" for ip in preset["addresses"]
    )
    out = TEMPLATE
    for key, val in {
        "{{PRESET_NAME}}": preset_name,
        "{{DOH_URL}}": resolve_doh_url(preset_name, nextdns_id),
        "{{ADDRESSES_XML}}": addresses_xml,
        "{{DESC}}": preset["desc"],
        "{{PAYLOAD_UUID}}": PAYLOAD_UUID_DNS,
        "{{PROFILE_UUID}}": PROFILE_UUID,
    }.items():
        out = out.replace(key, val)
    return out


def generate(preset_name: str | None = None, nextdns_id: str | None = None,
             dest: Path | None = None) -> Path:
    """Генерирует и записывает dns_shield.mobileconfig."""
    preset_name = preset_name or config.DEFAULT_RESOLVER_PRESET
    content = render_profile(preset_name, nextdns_id)
    dest = dest or config.DNS_SHIELD_PROFILE
    dest.write_text(content, encoding="utf-8")
    return dest


# ── Web Content Filter: блокировка доменов шпионов на уровне WebKit ─────────
# ── Web Content Filter: blocking spyware domains at the WebKit level ────────

# Фиксированные UUID для стабильности профиля между перегенерациями
# Fixed UUIDs to keep the profile stable across regenerations
PAYLOAD_UUID_WCF = "7e1a2c55-9f0b-4d3a-b8c1-2a6f5e4d9c11"
PROFILE_UUID_WCF = "3b9d8f02-51c7-4e88-a2d4-90c6f1b7e34a"
# Обязателен на несупервизируемых устройствах (iOS 16+)
# Required on unsupervised devices (iOS 16+)
CONTENT_FILTER_UUID_WCF = "a1e5f7c2-4b3d-4e8f-9c6a-7d2b1e0f8a44"

# Лимит разумного размера: тысячи доменов тормозят фильтр без пользы
# Sanity size limit: thousands of entries slow the filter for no real gain
WCF_MAX_DOMAINS = 500


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def select_wcf_domains(iocs: dict, cap: int = WCF_MAX_DOMAINS) -> list[str]:
    """Топ C2-доменов по весу, без allowlist-ложняков, отсортирован, уникален.

    Top C2 domains ranked by weight: allowlist false positives excluded,
    sorted and deduplicated.
    """
    import re as _re
    allow = [_re.compile(p) for p in iocs.get("allowlist", []) if isinstance(p, str)]
    seen: dict[str, int] = {}
    for entry in iocs.get("domains", []):
        if not isinstance(entry, dict):
            continue
        value = str(entry.get("value", "")).strip().lower()
        weight = int(entry.get("weight", 5))
        if not value or "." not in value:
            continue
        if any(rx.search(value) for rx in allow):
            continue
        # максимум по домену, если он встречается в нескольких секциях/фидах
        # keep the max weight per domain when it appears in several sections/feeds
        seen[value] = max(seen.get(value, 0), weight)
    ranked = sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))
    return [d for d, _ in ranked[:cap]]


def render_wcf_profile(domains: list[str]) -> str:
    items = "".join(f"\n        <string>{_esc(d)}</string>" for d in domains)
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!--
  ghost-lock :: Spyware Domain Wall

  Встроенный фильтр веб-контента iOS (без сторонних приложений):
  Safari и все WebKit-приложения не откроют домены известной шпионской
  инфраструктуры (C2 Pegasus/Predator/FinFisher/... из базы ghost-lock).

  Это ВТОРОЙ эшелон после DNS Shield: работает даже если телефон ушёл
  с нашего DNS (чужой Wi-Fi, сбой DoH).

  Обновление списка: перегенерируй профиль командой
    python3 ghost_lock/ghost_lock.py profiles
  и переустанови файл как обычно.
-->
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.webcontent-filter</string>
      <key>FilterType</key>
      <string>BuiltIn</string>
      <key>ContentFilterUUID</key>
      <string>{{CF_UUID}}</string>
      <key>DenyListURLs</key>
      <array>{{DOMAIN_ITEMS}}
      </array>
      <key>PayloadDisplayName</key>
      <string>ghost-lock Spyware Domain Wall</string>
      <key>PayloadIdentifier</key>
      <string>cc.ghostlock.wcf.spywarewall</string>
      <key>PayloadUUID</key>
      <string>{{PAYLOAD_UUID}}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>ghost-lock: блокировка {{N}} доменов шпионского ПО на уровне веб-движка iOS. Второй эшелон защиты поверх DNS Shield.</string>
  <key>PayloadDisplayName</key>
  <string>ghost-lock Spyware Domain Wall ({{N}})</string>
  <key>PayloadIdentifier</key>
  <string>cc.ghostlock.wcf.profile</string>
  <key>PayloadOrganization</key>
  <string>ghost-lock</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{{PROFILE_UUID}}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
""".replace("{{DOMAIN_ITEMS}}", items) \
       .replace("{{N}}", str(len(domains))) \
       .replace("{{CF_UUID}}", CONTENT_FILTER_UUID_WCF) \
       .replace("{{PAYLOAD_UUID}}", PAYLOAD_UUID_WCF) \
       .replace("{{PROFILE_UUID}}", PROFILE_UUID_WCF)


def generate_wcf(dest: Path | None = None, cap: int = WCF_MAX_DOMAINS,
                 ioc_path: Path | None = None) -> Path:
    """Собирает web_filter.mobileconfig из актуальной базы IOC.

    Builds web_filter.mobileconfig from the current IOC database.
    """
    import json
    path = ioc_path or config.IOC_PATH
    with open(path, encoding="utf-8") as fh:
        iocs = json.load(fh)
    domains = select_wcf_domains(iocs, cap=cap)
    dest = dest or config.WEB_FILTER_PROFILE
    dest.write_text(render_wcf_profile(domains), encoding="utf-8")
    return dest
