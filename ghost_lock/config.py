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
# Каждый пресет: DoH-резолвер + ПЛАНОВЫЙ фолбэк того же вендора.
# Each preset: a DoH resolver plus a DELIBERATE plain-DNS fallback from the
# same filtering vendor.
# Фолбэк нужен, чтобы интернет не ломался, если DoH недоступен:
# iOS уйдёт на обычный DNS того же провайдера фильтрации (политика сохраняется),
# а не на «мёртвое» соединение.
# The fallback exists so the internet never breaks when DoH is unreachable:
# iOS silently switches to plain DNS from the same vendor (filtering policy
# preserved) instead of a dead connection.
RESOLVER_PRESETS = {
    # МАКСИМАЛЬНЫЙ семейный фильтр: 18+, малварь, фишинг, прокси/VPN-обход,
    # mixed-content, принудительный SafeSearch. Лучший дефолт против
    # «казино и левых сайтов» без своего сервера.
    # Maximum-strength family filter: adult content, malware, phishing,
    # proxy/VPN bypasses, mixed content, forced SafeSearch. Best default
    # against "gambling and shady sites" without running your own server.
    "family": {
        "doh": "https://doh.cleanbrowsing.org/doh/family-filter/",
        "fallback": ["185.228.168.168", "185.228.169.168"],
        "desc": "18+, малварь, фишинг, proxy/VPN, SafeSearch",
    },
    # Cloudflare: малварь + 18+ (казино НЕ блокирует).
    # Cloudflare: malware + adult content (does NOT block gambling).
    "cf-family": {
        "doh": "https://family.cloudflare-dns.com/dns-query",
        "fallback": ["1.1.1.3", "1.0.0.3"],
        "desc": "малварь + 18+ (без казино)",
    },
    # Только защита от малвари/фишинга, контент не режет.
    # Malware/phishing protection only; no content filtering.
    "security": {
        "doh": "https://security.cloudflare-dns.com/dns-query",
        "fallback": ["1.1.1.2", "1.0.0.2"],
        "desc": "только малварь и фишинг",
    },
    # Свой конфиг NextDNS: категории (в т.ч. Casino/Gambling) включаются
    # в панели my.nextdns.io, сюда подставляется ID конфига.
    "nextdns": {
        "doh": "https://dns.nextdns.io/{config_id}",
        "fallback": ["8.8.8.8", "8.8.4.4"],
        "desc": "свой конфиг NextDNS (казино и категории — в панели)",
        "needs_id": True,
    },
}
DEFAULT_RESOLVER_PRESET = "family"

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
