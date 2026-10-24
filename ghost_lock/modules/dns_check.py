"""Проверка зашифрованного DNS из текущей сети: пресеты телефона и сам ПК.

Зачем: провайдер/роутер может блокировать DoH/DoT. Оговорка: Portmaster на
самом ПК тоже режет программам соединения с известными DNS-серверами (защита
от обхода) — на живой машине именно он «блокировал» Quad9, Cloudflare, Google
и порт 853, а не роутер. При запущенном Portmaster команда предупреждает. Профиль без
фолбэка в такой сети оставит телефон без интернета, а systemd-resolved на ПК
молча уйдёт на открытый DNS роутера. Здесь это видно заранее.

Проба: настоящий DoH-запрос (RFC 8484) прямо на IP из пресета, в обход DNS,
с проверкой TLS-сертификата по имени DoH-сервера — ровно то, что сделает
iOS с ServerAddresses.

Checking encrypted DNS from the current network: phone presets and the PC.

Why: an ISP/router may block DoH/DoT. Caveat: Portmaster on the PC itself also
blocks apps from reaching well-known DNS servers (bypass prevention) — on the
live machine it, not the router, "blocked" Quad9, Cloudflare, Google and port
853. The command warns when Portmaster is running. A no-fallback profile
leaves the phone offline on such a network, and systemd-resolved on the PC
silently falls back to the router's plain DNS. This makes it visible upfront.

Probe: a real DoH query (RFC 8484) straight to the preset's IP, bypassing
DNS, with the TLS certificate verified against the DoH host name — exactly
what iOS does with ServerAddresses.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .. import config

PROBE_TIMEOUT = 6
PROBE_NAME = "example.com"


def build_query(name: str = PROBE_NAME, qid: int | None = None) -> bytes:
    """DNS-запрос A-записи в wire-формате. / A-record DNS query in wire format."""
    qid = int.from_bytes(os.urandom(2), "big") if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


@dataclass
class Probe:
    preset: str
    address: str
    ok: bool
    detail: str
    ms: float = 0.0


def probe(url: str, address: str, timeout: float = PROBE_TIMEOUT) -> tuple[bool, str, float]:
    """DoH-проба: через curl (умеет HTTP/2 — часть серверов, напр. Mullvad,
    отвечают только по нему), иначе встроенная HTTP/1.1.

    DoH probe: via curl (speaks HTTP/2 — some servers, e.g. Mullvad, answer
    only over it), otherwise the built-in HTTP/1.1 one.
    """
    if shutil.which("curl"):
        return _probe_curl(url, address, timeout)
    return _probe_builtin(url, address, timeout)


def _probe_curl(url: str, address: str, timeout: float) -> tuple[bool, str, float]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    query = build_query()
    dns_param = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
    target = f"{url}{'&' if parts.query else '?'}dns={dns_param}"
    resolve = f"{host}:443:{address}"
    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout), "--resolve", resolve,
             "-H", "accept: application/dns-message", "-o", "-",
             "-w", "\n%{http_code}", target],
            capture_output=True, timeout=timeout + 5)
    except (OSError, subprocess.TimeoutExpired):
        return False, "нет соединения (таймаут)", 0.0
    ms = (time.monotonic() - started) * 1000
    body, _, code = proc.stdout.rpartition(b"\n")
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip().splitlines()
        reason = re.sub(r"^curl: \(\d+\) ", "", err[-1]) if err else f"curl exit {proc.returncode}"
        reason = re.sub(r" to \S+ port \d+ after \d+ ms", "", reason)
        if proc.returncode == 60:
            return False, f"сертификат не прошёл проверку ({reason})", 0.0
        return False, f"нет соединения ({reason})", 0.0
    if code.strip() != b"200":
        return False, f"ответ сервера: HTTP {code.decode(errors='replace').strip()}", ms
    if len(body) < 12 or body[:2] != query[:2]:
        return False, "ответ не похож на DNS", ms
    return True, "DoH работает", ms


def _probe_builtin(url: str, address: str, timeout: float) -> tuple[bool, str, float]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    path = parts.path or "/"
    query = build_query()
    dns_param = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
    request = (f"GET {path}?dns={dns_param} HTTP/1.1\r\nHost: {host}\r\n"
               "Accept: application/dns-message\r\nConnection: close\r\n\r\n").encode()
    ctx = ssl.create_default_context()
    started = time.monotonic()
    try:
        with socket.create_connection((address, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(request)
                data = b""
                while len(data) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
    except ssl.SSLCertVerificationError as e:
        return False, f"сертификат не прошёл проверку ({e.verify_message})", 0.0
    except (OSError, ssl.SSLError) as e:
        reason = getattr(e, "strerror", None) or str(e) or e.__class__.__name__
        return False, f"нет соединения ({reason})", 0.0
    ms = (time.monotonic() - started) * 1000

    if data[3:4] == b"\x04" and not data.startswith(b"HTTP/"):
        # кадр SETTINGS HTTP/2: сервер настоящий (сертификат проверен), но
        # говорит только по HTTP/2 — полный DNS-ответ проверит только curl
        # an HTTP/2 SETTINGS frame: the server is genuine (cert verified) but
        # speaks only HTTP/2 — only curl can verify a full DNS answer
        return True, "TLS ок, сервер HTTP/2 (для полной проверки нужен curl)", ms
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200 " not in f"{status} ":
        return False, f"ответ сервера: {status or 'пусто'}", ms
    if b"chunked" in head.lower():
        body = _dechunk(body)
    if len(body) < 12 or body[:2] != query[:2]:
        return False, "ответ не похож на DNS", ms
    return True, "DoH работает", ms


def _dechunk(body: bytes) -> bytes:
    out, rest = b"", body
    while rest:
        size_line, _, rest = rest.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out, rest = out + rest[:size], rest[size + 2:]
    return out


def check_presets(nextdns_id: str | None = None) -> list[Probe]:
    from .profile_gen import PresetError, resolve_doh_url

    results: list[Probe] = []
    for name, preset in config.RESOLVER_PRESETS.items():
        try:
            url = resolve_doh_url(name, nextdns_id or ("probe00" if preset.get("needs_id") else None))
        except PresetError:
            continue
        for addr in preset["addresses"]:
            ok, detail, ms = probe(url, addr)
            results.append(Probe(name, addr, ok, detail, ms))
    return results


# ── DNS самого ПК (systemd-resolved) / The PC's own DNS (systemd-resolved) ──

@dataclass
class ResolvedLink:
    name: str
    servers: list[str] = field(default_factory=list)
    current: str = ""
    dot: bool = False
    default_route: bool = False


def parse_resolvectl(text: str) -> list[ResolvedLink]:
    links: list[ResolvedLink] = []
    cur: ResolvedLink | None = None
    for line in text.splitlines():
        m = re.match(r"^(Global|Link \d+ \((.+)\))\s*$", line.strip())
        if m:
            cur = ResolvedLink(name=m.group(2) or "Global")
            links.append(cur)
            continue
        if cur is None or ":" not in line:
            continue
        key, _, val = line.strip().partition(":")
        val = val.strip()
        if key == "Protocols":
            cur.dot = "+DNSOverTLS" in val
            cur.default_route = "+DefaultRoute" in val or cur.name == "Global"
        elif key == "Current DNS Server":
            cur.current = val
        elif key == "DNS Servers":
            cur.servers = val.split()
    return links


def parse_dot_modes(text: str) -> dict[str, str]:
    """Вывод `resolvectl dnsovertls` → {интерфейс: yes|opportunistic|no}.

    `resolvectl dnsovertls` output → {interface: yes|opportunistic|no}.
    """
    modes: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(Global|Link \d+ \((.+)\)):\s*(\S+)", line)
        if m:
            modes[m.group(2) or "Global"] = m.group(3).lower()
    return modes


def dot_reachable(server: str, timeout: float = 3.0) -> bool:
    host = server.split("#", 1)[0].split("%", 1)[0]
    try:
        with socket.create_connection((host, 853), timeout=timeout):
            return True
    except OSError:
        return False


def _is_loopback(server: str) -> bool:
    import ipaddress
    host = server.split("#", 1)[0].split("%", 1)[0]
    if host.count(":") == 1:  # 127.0.2.1:53
        host = host.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def uses_local_proxy(links: list[ResolvedLink]) -> bool:
    return any(l.servers and all(_is_loopback(x) for x in l.servers) for l in links)


@dataclass
class PcDnsIssue:
    link: str
    kind: str      # "leak" — открытым текстом / plain text; "broken" — не работает / not working
    servers: list[str]
    note: str


def pc_dns_issues(links: list[ResolvedLink], modes: dict[str, str],
                  reachable=dot_reachable) -> list[PcDnsIssue]:
    """Где DNS компьютера уходит открытым текстом или не работает вовсе.

    Флаг +DNSOverTLS в `resolvectl status` не различает строгий и
    «оппортунистический» режим, поэтому режим берём из `resolvectl dnsovertls`,
    а для строгого проверяем, открыт ли у серверов порт 853.

    Where the PC's DNS leaves in plain text or does not work at all. The
    +DNSOverTLS flag in `resolvectl status` does not tell strict from
    opportunistic mode, so the mode comes from `resolvectl dnsovertls`, and
    for strict mode we check whether the servers' port 853 is open.
    """
    issues: list[PcDnsIssue] = []
    for l in links:
        # интерфейс без своих серверов DNS не получает; глобальные — отдельной строкой
        # a link without its own servers gets no DNS; global ones are checked as "Global"
        if not l.servers or (l.name != "Global" and not l.default_route):
            continue
        servers = l.servers
        if all(_is_loopback(x) for x in servers):
            # локальный прокси (dnscrypt-proxy): шифрует он сам, участок до него
            # не выходит из компьютера — это не утечка
            # a local proxy (dnscrypt-proxy) encrypts by itself; the hop to it
            # never leaves the computer — not a leak
            continue
        mode = modes.get(l.name, modes.get("Global", "no"))
        if mode in ("no", "opportunistic"):
            issues.append(PcDnsIssue(l.name, "leak", servers,
                                     f"DoT={mode}: запросы идут открытым текстом"))
        elif not any(reachable(s) for s in servers):
            issues.append(PcDnsIssue(l.name, "broken", servers,
                                     "DoT обязателен, но порт 853 серверов закрыт — DNS не отвечает"))
    return issues


def system_dns() -> tuple[list[ResolvedLink], dict[str, str]] | None:
    try:
        status = subprocess.run(["resolvectl", "status"], capture_output=True,
                                text=True, timeout=10)
        dot = subprocess.run(["resolvectl", "dnsovertls"], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if status.returncode != 0:
        return None
    return parse_resolvectl(status.stdout), parse_dot_modes(dot.stdout)


def dnscrypt_snippet(preset: str = config.DEFAULT_RESOLVER_PRESET) -> str:
    """Полный /etc/dnscrypt-proxy/dnscrypt-proxy.toml (DoH) под выбранный пресет.

    Отличия от штатного файла Debian/Ubuntu: сервер — пресет ghost-lock со
    вшитым IP (stamp), журналы запросов выключены (штатный пишет каждый
    запрос на диск), списки серверов не скачиваются (их зеркала и bootstrap-
    резолверы могут быть заблокированы так же, как DoH).

    A complete /etc/dnscrypt-proxy/dnscrypt-proxy.toml (DoH) for the preset.
    Unlike the stock Debian/Ubuntu file: the server is the ghost-lock preset
    with a pinned IP (stamp), query logs are off (the stock file writes every
    query to disk), and no server lists are downloaded (their mirrors and
    bootstrap resolvers may be blocked just like DoH).
    """
    p = config.RESOLVER_PRESETS[preset]
    stamp = doh_stamp(p["doh"], p["addresses"][0])
    return (
        f"# ghost-lock: DoH через пресет «{preset}» ({p['doh']})\n"
        "# Пустой listen_addresses: адрес 127.0.2.1:53 задаёт dnscrypt-proxy.socket\n"
        "listen_addresses = []\n"
        f"server_names = ['ghostlock-{preset}']\n"
        "doh_servers = true\n"
        "dnscrypt_servers = false\n"
        "require_nolog = true\n"
        "ignore_system_dns = true\n"
        "netprobe_timeout = 10\n"
        "\n"
        "# Журналы запросов ([query_log], [nx_log]) намеренно выключены.\n"
        "# [sources] нет: сервер задан ниже, списки скачивать не нужно.\n"
        "\n"
        "[static]\n"
        f"  [static.'ghostlock-{preset}']\n"
        f"  stamp = '{stamp}'\n"
    )


def doh_stamp(url: str, address: str) -> str:
    """DNS stamp (sdns://) для DoH-сервера по спецификации DNSCrypt.

    A DNS stamp (sdns://) for a DoH server per the DNSCrypt spec.
    """
    parts = urlsplit(url)

    def lp(b: bytes) -> bytes:
        return bytes([len(b)]) + b

    props = (2).to_bytes(8, "little")  # бит 1: без логов / bit 1: no logs
    blob = (b"\x02" + props + lp(address.encode()) + b"\x00"
            + lp((parts.hostname or "").encode()) + lp((parts.path or "/").encode()))
    return "sdns://" + base64.urlsafe_b64encode(blob).rstrip(b"=").decode()
