"""Аудит конфигурационных профилей, сертификатов и действующих ограничений.

Сталкерware и «корпоративная» слежка часто приходят не приложением, а
профилем: MDM (удалённое управление), корневой сертификат (чтение HTTPS),
глобальный прокси или VPN (весь трафик через чужой сервер). Всё это видно
в расшифрованном бэкапе:

  ConfigurationProfiles/profile-*.stub     — установленные профили целиком
  ConfigurationProfiles/CloudConfigurationDetails.plist — супервизия
  UserConfigurationProfiles/EffectiveUserSettings.plist — ДЕЙСТВУЮЩИЕ ограничения
  trustd/private/TrustStore.sqlite3        — сертификаты, которым доверяет пользователь

Заодно проверяем собственную защиту: какие профили ghost-lock стоят, свеж
ли список Domain Wall и какие ключи hardened iOS применила на самом деле.

Audit of configuration profiles, certificates and effective restrictions.

Stalkerware and "corporate" surveillance often arrive not as an app but as a
profile: MDM (remote management), a root certificate (reading HTTPS), a
global proxy or VPN (all traffic through someone else's server). All of it is
visible in the decrypted backup (paths above). We also verify ghost-lock's
own protection: which of its profiles are installed, whether the Domain Wall
list is fresh, and which hardened keys iOS actually applied.
"""

from __future__ import annotations

import plistlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding

OWN_PROFILES = {
    "dnsshield": ("cc.ghostlock.dnsshield.profile.", "DNS Shield"),
    "wcf": ("cc.ghostlock.wcf.profile", "Spyware Domain Wall"),
    "hardened": ("cc.ghostlock.hardened.profile", "Hardened"),
}

OWN_PAYLOAD_TYPES = {
    "dnsshield": "com.apple.dnsSettings.managed",
    "wcf": "com.apple.webcontent-filter",
    "hardened": "com.apple.applicationaccess",
}


def _own_doh(payload: dict[str, Any]) -> bool:
    from .. import config
    url = str((payload.get("DNSSettings") or {}).get("ServerURL", ""))
    for preset in config.RESOLVER_PRESETS.values():
        base = preset["doh"].split("{")[0]
        if url == preset["doh"] or (preset.get("needs_id") and url.startswith(base)):
            return True
    return False


# Тип payload → (вес, что это значит). Чем больше власти над устройством
# или трафиком даёт payload, тем выше вес.
# Payload type → (weight, meaning). The more power over the device or the
# traffic a payload grants, the higher the weight.
PAYLOAD_RISK: dict[str, tuple[int, str]] = {
    "com.apple.mdm": (15, "MDM: удалённое управление телефоном"),
    "com.apple.security.root": (10, "корневой сертификат: возможно чтение HTTPS (MITM)"),
    "com.apple.security.pem": (10, "сертификат: возможно чтение HTTPS (MITM)"),
    "com.apple.security.pkcs1": (10, "сертификат: возможно чтение HTTPS (MITM)"),
    "com.apple.proxy.http.global": (10, "глобальный прокси: весь веб-трафик через чужой сервер"),
    "com.apple.vpn.managed": (8, "VPN: трафик через чужой сервер"),
    "com.apple.vpn.managed.applayer": (8, "VPN для приложений: трафик через чужой сервер"),
    "com.apple.vpn.managed.alwayson": (8, "Always-on VPN: трафик через чужой сервер"),
    "com.apple.dnsProxy.managed": (7, "DNS-прокси: чужой видит все запросы"),
    "com.apple.dnsSettings.managed": (7, "чужой DNS: видит все посещаемые домены"),
    "com.apple.webcontent-filter": (7, "чужой веб-фильтр: может видеть трафик"),
    "com.apple.app.lock": (5, "блокировка в одном приложении"),
}
UNKNOWN_PAYLOAD_WEIGHT = 2

_PROFILE_DIRS = ("ConfigurationProfiles", "UserConfigurationProfiles")


@dataclass
class InstalledProfile:
    identifier: str
    name: str
    organization: str
    install_date: str
    installed_by: str
    payloads: list[dict[str, Any]]

    @property
    def own(self) -> bool:
        """Профиль ghost-lock — только если и имя, И содержимое наши.

        Имя «cc.ghostlock.…» подделать легко, поэтому сверяем типы payload,
        а для DNS — что сервер из наших пресетов.

        A ghost-lock profile only if both the name AND the contents are ours.
        The "cc.ghostlock.…" name is trivial to fake, so payload types are
        checked too, and for DNS — that the server is one of our presets.
        """
        for key, (prefix, _) in OWN_PROFILES.items():
            if not self.identifier.startswith(prefix):
                continue
            if not self.payloads or set(self.payload_types) != {OWN_PAYLOAD_TYPES[key]}:
                return False
            if key == "dnsshield":
                return all(_own_doh(pl) for pl in self.payloads)
            return True
        return False

    @property
    def payload_types(self) -> list[str]:
        return [str(p.get("PayloadType", "?")) for p in self.payloads]


@dataclass
class ProfileAudit:
    profiles: list[InstalledProfile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    lines: list[tuple[bool | None, str]] = field(default_factory=list)  # (ok, text)
    recommendations: list[str] = field(default_factory=list)
    found_data: bool = False


def _load_plist(path: Path) -> Any:
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None


def _find(root: Path, pattern: str) -> list[Path]:
    return sorted(p for p in root.rglob(pattern)
                  if any(d in p.parts for d in _PROFILE_DIRS) or "trustd" in p.parts)


def load_profiles(root: Path) -> list[InstalledProfile]:
    out: dict[str, InstalledProfile] = {}
    for stub in _find(root, "profile-*.stub"):
        data = _load_plist(stub)
        if not isinstance(data, dict):
            continue
        ident = str(data.get("PayloadIdentifier", stub.stem))
        opts = data.get("InstallOptions") or {}
        date = data.get("InstallDate")
        payloads = [p for p in (data.get("PayloadContent") or []) if isinstance(p, dict)]
        out[ident] = InstalledProfile(
            identifier=ident,
            name=str(data.get("PayloadDisplayName", "")),
            organization=str(data.get("PayloadOrganization", "")),
            install_date=date.strftime("%Y-%m-%d") if hasattr(date, "strftime") else "",
            installed_by=str(opts.get("installedBy", "")) if isinstance(opts, dict) else "",
            payloads=payloads,
        )
    return sorted(out.values(), key=lambda p: p.identifier)


def count_user_trusted_certs(root: Path) -> int | None:
    stores = _find(root, "TrustStore.sqlite3")
    if not stores:
        return None
    total = 0
    for db in stores:
        try:
            # immutable=1: только чтение, без файлов -shm/-wal рядом
            # immutable=1: read-only, no -shm/-wal files next to it
            con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
            try:
                total += con.execute("SELECT count(*) FROM tsettings").fetchone()[0]
            finally:
                con.close()
        except sqlite3.Error:
            continue
    return total


def effective_restrictions(root: Path) -> dict[str, Any]:
    for path in _find(root, "EffectiveUserSettings.plist"):
        data = _load_plist(path)
        if isinstance(data, dict) and data.get("restrictedBool"):
            return data
    return {}


def hardened_keys(hardened_profile: Path) -> dict[str, bool]:
    data = _load_plist(hardened_profile)
    keys: dict[str, bool] = {}
    if not isinstance(data, dict):
        return keys
    for payload in data.get("PayloadContent") or []:
        if isinstance(payload, dict) and payload.get("PayloadType") == "com.apple.applicationaccess":
            keys.update({k: v for k, v in payload.items() if isinstance(v, bool)})
    return keys


def _profile_findings(p: InstalledProfile, stalker_prefixes: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    label = p.name or p.identifier
    org = f", организация «{p.organization}»" if p.organization else ""
    for ioc in stalker_prefixes:
        value = str(ioc.get("value", "")).lower()
        if "." in value and p.identifier.lower().startswith(value):
            out.append(Finding(
                ioc_type="stalkerware_profiles", value=p.identifier,
                weight=int(ioc.get("weight", 9)), source=str(ioc.get("source", "")),
                location=f"profile:{p.identifier}",
                context=f"профиль «{label}»{org}, установлен {p.install_date}",
            ))
    for ptype in sorted(set(p.payload_types)):
        weight, meaning = PAYLOAD_RISK.get(ptype, (UNKNOWN_PAYLOAD_WEIGHT, "прочие настройки"))
        out.append(Finding(
            ioc_type="profile", value=f"{label} · {ptype}", weight=weight,
            source=f"чужой профиль: {meaning}",
            location=f"profile:{p.identifier}",
            context=f"профиль «{label}»{org}, установлен {p.install_date} ({p.installed_by})",
        ))
    return out


def audit(root: Path, iocs: dict[str, Any], hardened_profile: Path | None = None,
          current_wcf_domains: list[str] | None = None) -> ProfileAudit:
    """Полный аудит профилей по расшифрованному бэкапу в root.

    Full profile audit over the decrypted backup at root.
    """
    rep = ProfileAudit()
    rep.profiles = load_profiles(root)
    cloud = next((_load_plist(p) for p in _find(root, "CloudConfigurationDetails.plist")), None)
    certs = count_user_trusted_certs(root)
    effective = effective_restrictions(root)
    rep.found_data = bool(rep.profiles or cloud or certs is not None or effective)
    if not rep.found_data:
        rep.lines.append((None, "Профили: данных в бэкапе не найдено"))
        return rep

    # 1. Чужие профили / Foreign profiles
    foreign = [p for p in rep.profiles if not p.own]
    stalker = [x for x in iocs.get("stalkerware_profiles", []) if isinstance(x, dict)]
    for p in foreign:
        rep.findings.extend(_profile_findings(p, stalker))
    if foreign:
        names = ", ".join(f"«{p.name or p.identifier}»" for p in foreign)
        rep.lines.append((False, f"Чужие профили ({len(foreign)}): {names}"))
        rep.recommendations.append(
            "На телефоне есть профили не от ghost-lock. Если не ставил их сам (работа, "
            "школа) — удали: Настройки → Основные → VPN и управление устройством.")
    else:
        rep.lines.append((True, f"Чужих профилей нет (установлено ghost-lock: {len(rep.profiles)})"))

    # 2. Супервизия / Supervision
    if isinstance(cloud, dict):
        if cloud.get("IsSupervised"):
            src = "Apple Business/School Manager" if cloud.get("ConfigurationSource") else "Apple Configurator"
            rep.lines.append((None, f"Телефон под супервизией ({src}) — "
                                    "это нормально, только если настраивал ты сам"))
        else:
            rep.lines.append((True, "Супервизии нет: телефоном никто не управляет удалённо"))

    # 3. Сертификаты / Certificates
    if certs is not None:
        if certs:
            rep.findings.append(Finding(
                ioc_type="certificate", value=f"доверенных пользователем сертификатов: {certs}",
                weight=10, source="TrustStore: сертификат с полным доверием позволяет читать HTTPS",
                location="trustd:TrustStore.sqlite3", context="",
            ))
            rep.lines.append((False, f"Пользовательские доверенные сертификаты: {certs}"))
            rep.recommendations.append(
                "Есть сертификаты с полным доверием — проверь: Настройки → Основные → "
                "Об этом устройстве → Доверие сертификатам. Незнакомые — выключи.")
        else:
            rep.lines.append((True, "Пользовательских доверенных сертификатов нет"))

    # 4. Покрытие ghost-lock / ghost-lock coverage
    own_ids = [p.identifier for p in rep.profiles if p.own]
    for key, (prefix, title) in OWN_PROFILES.items():
        installed = any(i.startswith(prefix) for i in own_ids)
        if installed:
            rep.lines.append((True, f"ghost-lock {title}: установлен"))
        else:
            rep.lines.append((None, f"ghost-lock {title}: НЕ установлен"))
            rep.recommendations.append(
                f"Профиль ghost-lock {title} не установлен — "
                "python3 ghost_lock/ghost_lock.py profiles")

    wall = next((p for p in rep.profiles if p.identifier.startswith(OWN_PROFILES["wcf"][0])), None)
    if wall is not None and current_wcf_domains is not None:
        installed_domains = {str(d).lower() for pl in wall.payloads
                             for d in (pl.get("DenyListURLs") or [])}
        missing = len(set(current_wcf_domains) - installed_domains)
        if missing:
            rep.lines.append((None, f"Domain Wall устарел: в текущей базе {missing} новых доменов"))
            rep.recommendations.append(
                "Список Spyware Domain Wall устарел — перегенерируй профили и "
                "переустанови web_filter.mobileconfig.")
        else:
            rep.lines.append((True, "Domain Wall актуален"))

    # 5. Что из hardened реально действует / What hardened actually enforces
    if effective and hardened_profile is not None:
        wanted = hardened_keys(hardened_profile)
        rb = effective.get("restrictedBool", {})
        applied = [k for k, v in wanted.items()
                   if isinstance(rb.get(k), dict) and rb[k].get("value") == v]
        if wanted:
            ok = len(applied) == len(wanted)
            rep.lines.append((ok if ok else None,
                              f"Ограничения hardened действуют: {len(applied)} из {len(wanted)}"))
            not_applied = sorted(set(wanted) - set(applied))
            if not_applied and any(i.startswith(OWN_PROFILES["hardened"][0]) for i in own_ids):
                rep.lines.append((None, "  iOS игнорирует (нужна супервизия): " + ", ".join(not_applied)))
    return rep
