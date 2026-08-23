"""Генератор DNS-профиля (dns_shield.mobileconfig) из пресета.

Соблюдает главный принцип «не сломать интернет»:
  • ServerFallback — обычные IP того же фильтрующего вендора: если DoH
    недоступен, iOS продолжит резолвить через plain-DNS с той же политикой.
  • ProhibitDisablement = false — щит всегда можно выключить в настройках.
"""

from __future__ import annotations

from pathlib import Path

from .. import config

# Фиксированные UUID: стабильны между перегенерациями, iOS считает профиль тем же.
PAYLOAD_UUID_DNS = "fc4fdd46-8662-42c1-aa22-e4637bcb2fcf"
PROFILE_UUID = "5285d060-b4a6-4801-a404-9b673a40dcaf"

TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!--
  ghost-lock :: DNS Shield (пресет: {{PRESET_NAME}})

  Блокирует на уровне DNS: {{DESC}}.

  Защита от «сломанного интернета»: если DoH-сервер недоступен, iOS
  автоматически переходит на обычный DNS (ServerFallback) Того же вендора
  с той же фильтрующей политикой.

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
        <key>ServerFallback</key>
        <array>{{FALLBACK_XML}}
        </array>
      </dict>

      <!-- Без супервизии игнорируется; профиль всегда можно снять вручную -->
      <key>ProhibitDisablement</key>
      <false/>

      <key>PayloadDisplayName</key>
      <string>ghost-lock DNS Shield · {{PRESET_NAME}}</string>
      <key>PayloadIdentifier</key>
      <string>cc.ghostlock.dnsshield.{{PRESET_NAME}}</string>
      <key>PayloadUUID</key>
      <string>{{PAYLOAD_UUID}}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>ghost-lock: зашифрованный DNS (DoH), блокировка {{DESC}}. Фолбэк на plain-DNS того же вендора — интернет не пропадёт при сбое DoH.</string>
  <key>PayloadDisplayName</key>
  <string>ghost-lock DNS Shield ({{PRESET_NAME}})</string>
  <key>PayloadIdentifier</key>
  <string>cc.ghostlock.dnsshield.profile.{{PRESET_NAME}}</string>
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

    fallback_xml = "".join(
        f"\n          <string>{ip}</string>" for ip in preset["fallback"]
    )
    out = TEMPLATE
    for key, val in {
        "{{PRESET_NAME}}": preset_name,
        "{{DOH_URL}}": resolve_doh_url(preset_name, nextdns_id),
        "{{FALLBACK_XML}}": fallback_xml,
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
