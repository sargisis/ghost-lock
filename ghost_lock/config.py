"""ghost-lock configuration: paths and tunables."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROJECT_ROOT.parent
WORKDIR = Path.home() / ".local" / "share" / "ghost-lock"
CRASH_DIR = WORKDIR / "crash_logs"
REPORTS_DIR = WORKDIR / "reports"

IOC_PATH = PROJECT_ROOT / "ioc" / "indicators.json"
TEMPLATE_PATH = PROJECT_ROOT / "report_template.html"
PROFILES_DIR = PROJECT_ROOT / "profiles"

DNS_SHIELD_PROFILE = PROFILES_DIR / "dns_shield.mobileconfig"
WEB_FILTER_PROFILE = PROFILES_DIR / "web_filter.mobileconfig"
HARDENED_PROFILE = PROFILES_DIR / "hardened.mobileconfig"

# ── Пресеты DNS-щита / DNS-shield presets ─────────────────────────────────────
# Каждый пресет: DoH-резолвер + addresses — IP САМОГО DoH-сервера
# (ключ ServerAddresses). С ними телефону не нужен обычный DNS, чтобы найти
# DoH-сервер: иначе чужая сеть видит и может подменить этот первый запрос.
# Фолбэка на открытый DNS НЕТ (AllowFailover=false): сеть, блокирующая DoH,
# не может тихо перевести телефон на нешифрованный DNS. Проверить, какие
# пресеты проходят в текущей сети: ghost_lock.py dns-check.
# (Ключа «ServerFallback» у Apple нет — прежние версии профиля его писали,
# iOS его игнорировала.)
#
# Each preset: a DoH resolver + addresses — IPs of the DoH server ITSELF
# (the ServerAddresses key). With them the phone needs no plain DNS to find
# the DoH server; otherwise a foreign network sees and can spoof that first
# lookup. There is NO fallback to plain DNS (AllowFailover=false): a network
# blocking DoH cannot silently downgrade the phone. Check which presets pass
# on the current network: ghost_lock.py dns-check.
# (Apple has no "ServerFallback" key — older profile versions wrote it and
# iOS ignored it.)
RESOLVER_PRESETS = {
    # Mullvad Base: малварь, реклама, трекеры. Швеция, без логов.
    # Mullvad Base: malware, ads, trackers. Sweden, no logs.
    "mullvad": {
        "doh": "https://base.dns.mullvad.net/dns-query",
        "addresses": ["194.242.2.4"],
        "desc": "малварь, реклама, трекеры · Mullvad, без логов",
    },
    # Quad9: малварь и фишинг, Швейцария, без логов IP.
    # Quad9: malware and phishing, Switzerland, no IP logging.
    "quad9": {
        "doh": "https://dns.quad9.net/dns-query",
        "addresses": ["9.9.9.9", "149.112.112.112"],
        "desc": "малварь и фишинг · Quad9, без логов IP",
    },
    # МАКСИМАЛЬНЫЙ семейный фильтр: 18+, малварь, фишинг, прокси/VPN-обход,
    # mixed-content, принудительный SafeSearch.
    # Maximum-strength family filter: adult content, malware, phishing,
    # proxy/VPN bypasses, mixed content, forced SafeSearch.
    "family": {
        "doh": "https://doh.cleanbrowsing.org/doh/family-filter/",
        "addresses": ["185.228.169.168", "185.228.168.168"],
        "desc": "18+, малварь, фишинг, proxy/VPN, SafeSearch",
    },
    # Cloudflare: малварь + 18+ (казино НЕ блокирует).
    # Cloudflare: malware + adult content (does NOT block gambling).
    "cf-family": {
        "doh": "https://family.cloudflare-dns.com/dns-query",
        "addresses": ["1.1.1.3", "1.0.0.3"],
        "desc": "малварь + 18+ (без казино)",
    },
    # Только защита от малвари/фишинга, контент не режет.
    # Malware/phishing protection only; no content filtering.
    "security": {
        "doh": "https://security.cloudflare-dns.com/dns-query",
        "addresses": ["1.1.1.2", "1.0.0.2"],
        "desc": "только малварь и фишинг",
    },
    # Свой конфиг NextDNS: категории включаются в панели my.nextdns.io,
    # сюда подставляется ID конфига. Anycast-адреса NextDNS.
    # Your own NextDNS config: categories are set at my.nextdns.io and the
    # config ID is substituted here. NextDNS anycast addresses.
    "nextdns": {
        "doh": "https://dns.nextdns.io/{config_id}",
        "addresses": ["45.90.28.0", "45.90.30.0"],
        "desc": "свой конфиг NextDNS (категории — в панели)",
        "needs_id": True,
    },
}
DEFAULT_RESOLVER_PRESET = "mullvad"

VERDICTS = {
    "clean": ("CLEAN", "Чисто"),
    "suspicious": ("SUSPICIOUS", "Подозрительно"),
    "critical": ("CRITICAL", "Критично"),
}

THRESHOLDS = {"suspicious": 3, "critical": 15}

# Файлы больше этого размера не сканируем построчно (гигантские analytics/tailspin
# блобы): IOC там не прячутся осмысленно, а регэксп по 50МБ занимает минуты.
# Files larger than this are not scanned line by line (giant analytics/tailspin
# blobs): IOCs can't hide meaningfully there, and a regex over 50MB takes minutes.
MAX_SCAN_FILE_BYTES = 8 * 1024 * 1024


def ensure_dirs() -> None:
    for d in (WORKDIR, CRASH_DIR, REPORTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
