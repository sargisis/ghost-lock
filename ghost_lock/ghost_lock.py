#!/usr/bin/env python3
"""
ghost-lock — аудит и укрепление iPhone поверх Lockdown Mode.

Реальная архитектура без джейлбрейка:
  • ПК-часть: подключение по проводу, выгрузка краш-логов, IOC-скан
    на шпионское ПО (методика Amnesty MVT), HTML-отчёт.
  • Телефон: подписанные вручную профили — постоянный DoH DNS-щит
    (переживает перезагрузку) + жёсткие ограничения.

Использование:
  python3 ghost_lock/ghost_lock.py doctor      # проверка окружения
  python3 ghost_lock/ghost_lock.py devices     # список подключённых айфонов
  python3 ghost_lock/ghost_lock.py audit       # полный аудит + отчёт
  python3 ghost_lock/ghost_lock.py audit --udid <UDID>
  python3 ghost_lock/ghost_lock.py profiles    # как установить щит на телефон
  python3 ghost_lock/ghost_lock.py profiles --serve   # раздать профили по LAN
"""

from __future__ import annotations

import argparse
import functools
import os
import shutil
import socket
import subprocess
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ghost_lock import config  # noqa: E402
from ghost_lock.modules import connect, diagnostics, report as report_mod  # noqa: E402
from ghost_lock.modules.spyware_scan import load_iocs, render_findings_table, run_scan  # noqa: E402


# ── вывод ────────────────────────────────────────────────────────────────────
def _c(code: str) -> "functools.partial[str]":
    return functools.partial(lambda c, s: f"\033[{c}m{s}\033[0m" if sys.stdout.isatty() else str(s), code)

red = _c("91")
green = _c("92")
yellow = _c("93")
cyan = _c("96")
dim = _c("90")
bold = _c("1")


def banner() -> None:
    print(cyan(r"""
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██╗      ██████╗  ██████╗██╗  ██╗
  ██╔════╝ ██║ ██╔╝██╔═══██╗██╔════╝╚══██╔══╝    ██║     ██╔═══██╗██╔════╝██║ ██╔╝
  ██║  ███╗█████╔╝ ██║   ██║███████╗   ██║       ██║     ██║   ██║██║     █████╔╝
  ██║   ██║██╔═██╗ ██║   ██║╚════██║   ██║       ██║     ██║   ██║██║     ██╔═██╗
  ╚██████╔╝██║  ██╗╚██████╔╝███████║   ██║       ███████╗╚██████╔╝╚██████╗██║  ██╗
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝"""))
    print(dim("  аудит + укрепление iPhone поверх Lockdown Mode · работает локально\n"))


def die(msg: str, code: int = 1) -> None:
    print(red(f"[!] {msg}"))
    sys.exit(code)


def step(msg: str) -> None:
    print(f"{cyan('[*]')} {msg}")


def ok(msg: str) -> None:
    print(f"{green('[+]')} {msg}")


# ── команды ──────────────────────────────────────────────────────────────────
def cmd_doctor(_args: argparse.Namespace) -> None:
    banner()
    problems = 0

    step("Проверка окружения…")

    for tool in ("idevice_id", "ideviceinfo", "idevicecrashreport"):
        if shutil.which(tool):
            ok(f"{tool}: найден")
        else:
            print(red(f"[-] {tool}: НЕ НАЙДЕН → sudo apt install libimobiledevice-utils"))
            problems += 1

    try:
        iocs = load_iocs()
        n = sum(len(iocs.get(k, [])) for k in ("domains", "jailbreak_artifacts", "spyware_strings", "stalkerware_profiles"))
        ok(f"База IOC: {config.IOC_PATH.name} ({n} индикаторов)")
    except Exception as e:
        print(red(f"[-] База IOC повреждена: {e}"))
        problems += 1

    for p in (config.TEMPLATE_PATH, config.DNS_SHIELD_PROFILE, config.HARDENED_PROFILE):
        if p.exists():
            ok(f"{p.relative_to(PROJECT_ROOT)}: на месте")
        else:
            print(red(f"[-] {p}: отсутствует"))
            problems += 1

    try:
        config.ensure_dirs()
        probe = config.WORKDIR / ".probe"
        probe.write_text("x")
        probe.unlink()
        ok(f"Рабочая папка доступна для записи: {config.WORKDIR}")
    except OSError as e:
        print(red(f"[-] Рабочая папка недоступна: {e}"))
        problems += 1

    try:
        devs = connect.list_devices()
        if devs:
            ok(f"Устройства по USB: {len(devs)}")
        else:
            print(yellow("[~] Устройств не найдено — подключи айфон кабелем для аудита"))
    except connect.DeviceError as e:
        print(yellow(f"[~] {e}"))

    if problems:
        die(f"Найдено проблем: {problems}", 2)
    print(green("\nГотово к работе. Запусти: python3 ghost_lock/ghost_lock.py audit"))


def cmd_devices(_args: argparse.Namespace) -> None:
    banner()
    udids = connect.list_devices()
    if not udids:
        die("Нет подключённых устройств. Подключи айфон кабелем и подтверди «Доверять».")
    for udid in udids:
        info = connect.device_info(udid)
        print(green(f"\n[+] {info.get('DeviceName', 'iPhone')}"))
        rows = connect.summary(info)
        width = max(len(t) for t, _ in rows)
        for title, value in rows:
            print(f"    {title:<{width}} : {value}")


def _pick_udid(requested: str | None) -> str:
    udids = connect.list_devices()
    if not udids:
        die("Нет подключённых устройств. Подключи айфон кабелем и подтверди «Доверять».")
    if requested:
        if requested not in udids:
            die(f"Устройство {requested} не найдено среди подключённых: {udids}")
        return requested
    if len(udids) > 1:
        step(f"Найдено несколько устройств: {udids}; беру первое (укажи --udid для выбора)")
    return udids[0]


def cmd_audit(args: argparse.Namespace) -> None:
    banner()
    config.ensure_dirs()

    step("Подключение к устройству…")
    udid = _pick_udid(args.udid)
    info = connect.device_info(udid)
    ok(f"Подключено: {info.get('DeviceName')} · iOS {info.get('ProductVersion')} · UDID {udid[:12]}…")

    step("Выгрузка краш-логов (это основной источник следов шпионов)…")
    crash_dir, n_logs = diagnostics.export_crash_logs(udid)
    ok(f"Краш-логи в {crash_dir} ({n_logs} файлов)")
    crash_names = sorted(p.name for p in Path(crash_dir).iterdir() if p.is_file())

    step("IOC-скан (домены C2, джейлбрейк-артефакты, стalkerware-профили, фишинг-эвристики)…")
    result = run_scan(info, crash_dir)

    # ── Deep-режим: полный бэкап + скан всего содержимого ──────────────────
    if getattr(args, "deep", False):
        from ghost_lock.modules import deep_scan
        deep_result = deep_scan.run(udid, info)
        result.findings.extend(deep_result.findings)
        result.files_scanned += deep_result.files_scanned
        if deep_result.stats_note:
            print(yellow(f"[~] {deep_result.stats_note}"))

    step("Скан установленных приложений (stalkerware по bundle-id)…")
    apps_pairs: list[tuple[str, str]] = []
    try:
        from ghost_lock.modules import apps_scan
        apps = apps_scan.list_installed_apps(udid)
        apps_pairs = [(a.bundle_id, a.version) for a in apps]
        ok(f"Установленных приложений: {len(apps)}")
        app_findings = apps_scan.scan_apps(load_iocs(), apps)
        result.findings.extend(app_findings)
        if not app_findings:
            ok("Шпионских приложений не обнаружено.")
    except RuntimeError as e:
        print(yellow(f"[~] Пропускаю скан приложений: {e}"))

    step("Гигиена безопасности…")
    from ghost_lock.modules import hygiene
    hygiene_checks = hygiene.check_hygiene(info=info, udid=udid)
    for c in hygiene_checks:
        mark = green("[+]") if c.ok else (yellow("[~]") if c.ok is None else red("[!]"))
        line = f"{mark} {c.title}"
        if c.note and c.ok is not True:
            line += f" — {c.note}"
        print(line)
    if hygiene.hygiene_score(hygiene_checks):
        from ghost_lock.modules.models import Finding
        result.findings.append(Finding(
            ioc_type="hygiene", value="код-пароль выключен",
            weight=hygiene.hygiene_score(hygiene_checks),
            source="hygiene", location="device",
            context="Без код-пароля все профили и Lockdown Mode снимаются за секунды",
        ))

    step("Что изменилось с прошлого раза…")
    from ghost_lock.modules import history
    diff = history.diff_with_history(
        udid=udid, current_apps=apps_pairs, current_crash_names=crash_names)
    diff_lines = history.format_diff(diff)
    for ln in diff_lines:
        print(f"  {ln}")

    step("Проверка свежести iOS…")
    os_note = ""
    try:
        from ghost_lock.modules import os_check
        status = os_check.check_os(
            str(info.get("ProductType", "")), str(info.get("ProductVersion", ""))
        )
        if status.latest is None:
            print(yellow(f"[~] {status.note}"))
            os_note = status.note
        elif status.outdated:
            print(red(f"[!] iOS {status.installed} устарела, последняя: {status.latest}. {status.note}"))
            os_note = f"iOS {status.installed} устарела (актуальна {status.latest}). Обновись немедленно."
        else:
            ok(f"iOS {status.installed} актуальна.")
    except Exception as e:  # noqa: BLE001 - сеть может быть недоступна
        print(yellow(f"[~] Не удалось проверить версию iOS: {e}"))

    verdict_en, verdict_ru = result.verdict()
    color = {"clean": green, "suspicious": yellow, "critical": red}[verdict_en.lower()]
    print(color(f"\n=== ВЕРДИКТ: {verdict_en} / {verdict_ru}  (score {result.score}) ==="))

    if result.findings:
        print(yellow("\nНаходки:"))
        for f in result.findings[:20]:
            loc = Path(f.location).name
            print(f"  • [{f.weight:>2}] {bold(f.value)}  ← {loc}")
            print(dim(f"        {f.source}"))
    else:
        ok("Совпадений с базой IOC не найдено.")

    step("Формирование HTML-отчёта…")
    recommendations = list(report_mod.BASE_RECOMMENDATIONS)
    if os_note:
        recommendations.insert(0, os_note)
    html = report_mod.build_report(
        device_rows=connect.summary(info),
        findings_rows_html=render_findings_table(result.findings),
        findings_count=len(result.findings),
        files_scanned=result.files_scanned,
        ioc_meta=f"v{iocs_version()}",
        recommendations=recommendations,
        verdict_key=verdict_en.lower(),
        score=result.score,
    )
    path = report_mod.write_report(html)
    ok(f"Отчёт: {path}")

    step("Сохраняю аудит в историю…")
    from ghost_lock.modules import history as _hist
    _hist.save_audit(
        udid=udid, device=str(info.get("DeviceName", "")),
        ios_version=str(info.get("ProductVersion", "")),
        verdict=verdict_en, score=result.score,
        files_scanned=result.files_scanned, apps=apps_pairs,
        crash_names=crash_names, ioc_version=iocs_version(),
        deep=bool(getattr(args, "deep", False)),
    )
    ok("Готово.")

    step("Уведомление в Telegram…")
    from ghost_lock.modules import telegram_notify
    device_name = info.get("DeviceName") or "iPhone"
    top = [(f.weight, f.value, Path(f.location).name) for f in result.findings[:5]]
    if telegram_notify.notify_audit(
        verdict_en=verdict_en, verdict_ru=verdict_ru, score=result.score,
        device=device_name, files_scanned=result.files_scanned,
        findings_top=top, report_path=str(path), extra_lines=diff_lines[:3],
    ):
        ok("Отправлено.")
    else:
        print(dim("[~] Telegram не настроен (setup-telegram) или недоступен — пропускаю."))

    print(bold("\nДальше — закрепи защиту на самом телефоне:"))
    print(f"  {cyan('python3 ghost_lock/ghost_lock.py profiles')}          — инструкция")
    print(f"  {cyan('python3 ghost_lock/ghost_lock.py profiles --serve')}  — раздать профили по Wi-Fi")


def iocs_version() -> str:
    try:
        import json
        with open(config.IOC_PATH, encoding="utf-8") as fh:
            return json.load(fh).get("_meta", {}).get("version", "?")
    except Exception:
        return "?"


def cmd_setup_telegram(args: argparse.Namespace) -> None:
    banner()
    from ghost_lock.modules import telegram_notify
    step("Шаг 1. Проверяю токен у Telegram…")
    try:
        me = telegram_notify._call(args.token, "getMe")
    except Exception as e:  # noqa: BLE001
        die(f"Токен не работает: {e}")
    bot_name = me.get("username", "?")
    ok(f"Бот: @{bot_name}")

    step("Шаг 2. Открой Telegram, найди бота и отправь ему любое сообщение (например «привет»)…")
    print(dim("    Жду до 60 секунд…"))
    chat_id = None
    for attempt in range(4):
        try:
            chat_id = telegram_notify.extract_chat_id(telegram_notify.get_updates(args.token))
        except Exception as e:  # noqa: BLE001
            print(yellow(f"[~] Сбой связи ({e}), пробую ещё…"))
        if chat_id is not None:
            break
        print(dim(f"    Попытка {attempt + 1}/4: сообщений пока нет…"))
    if chat_id is None:
        die("Сообщение от тебя не пришло. Напиши боту в Telegram и запусти команду снова.")

    cfg_path = telegram_notify._save_config(args.token, chat_id)
    ok(f"Конфиг сохранён: {cfg_path} (права 600)")

    step("Шаг 3. Тестовое сообщение…")
    try:
        telegram_notify.send_message(
            "✅ <b>ghost-lock подключён</b>\nТеперь после каждого аудита ты будешь получать вердикт сюда.",
            token=args.token, chat_id=chat_id,
        )
        ok(f"Готово! Алерты будут приходить в чат с @{bot_name}.")
    except Exception as e:  # noqa: BLE001
        print(yellow(f"[~] Конфиг сохранён, но тест не ушёл: {e}"))


PROFILE_INSTRUCTIONS = """
Как поставить щит на телефон (2 минуты):

  1. Раздай профили по сети:
       python3 ghost_lock/ghost_lock.py profiles --serve [--preset family]
  2. На айфоне открой Safari: http://<IP_компа>:8808/dns_shield.mobileconfig
     (IP покажет команда --serve). Профиль скачается.
  3. Настройки → Загруженный профиль → Установить → код-пароль → Готово.
  4. Перезагрузи айфон. Проверка: Настройки → Основное → VPN и управление
     устройством → DNS = «ghost-lock DNS Shield».
  5. Повтори шаги 2–4 для hardened.mobileconfig (жёсткие ограничения).

Почему интернет не сломается:
  • В профиле прописан ServerFallback — обычные DNS-серверы ТОГО ЖЕ
    фильтрующего вендора. Если DoH-сервер ляжет, iOS молча перейдёт на них,
    политика фильтрации сохранится, сайты продолжат открываться.
  • Профиль можно снять в любой момент: Настройки → Основное → VPN и
    управление устройством.

Пресеты (--preset):
"""


def _lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        pass


def _preset_table() -> str:
    lines = []
    default = config.DEFAULT_RESOLVER_PRESET
    for name, p in config.RESOLVER_PRESETS.items():
        mark = " (по умолчанию)" if name == default else ""
        extra = " — нужен --nextdns-id" if p.get("needs_id") else ""
        lines.append(f"  {name}{mark}{extra}: {p['desc']}")
        lines.append(f"      DoH: {p['doh']}")
    return "\n".join(lines)


def cmd_profiles(args: argparse.Namespace) -> None:
    banner()

    from ghost_lock.modules import profile_gen

    preset = args.preset or config.DEFAULT_RESOLVER_PRESET
    try:
        path = profile_gen.generate(preset, args.nextdns_id)
        ok(f"DNS-профиль собран: {path.relative_to(PROJECT_ROOT)} · пресет {preset}")
    except profile_gen.PresetError as e:
        die(str(e))

    try:
        wcf_path = profile_gen.generate_wcf()
        import json as _json
        with open(config.IOC_PATH, encoding="utf-8") as fh:
            n_all = sum(len(_json.load(fh).get(s, [])) for s in ("domains",))
        ok(f"Профиль-стена собран: {wcf_path.relative_to(PROJECT_ROOT)} · топ-{profile_gen.WCF_MAX_DOMAINS} доменов из базы")
    except Exception as e:  # noqa: BLE001
        print(yellow(f"[~] Профиль-стену не собрали (база IOC?): {e}"))

    print(PROFILE_INSTRUCTIONS + _preset_table() + "\n")

    if not args.serve:
        return

    port = args.port
    ip = _lan_ip()
    handler = functools.partial(QuietHandler, directory=str(config.PROFILES_DIR))
    server = HTTPServer(("0.0.0.0", port), handler)
    url = f"http://{ip}:{port}/dns_shield.mobileconfig"
    url2 = f"http://{ip}:{port}/hardened.mobileconfig"

    ok(f"Раздача профилей: {config.PROFILES_DIR}")
    print(bold(f"\n  Открой на айфоне в Safari:\n    {cyan(url)}\n    {cyan(url2)}\n"))
    qr_url(url)
    print(dim("\nCtrl+C — остановить раздачу."))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Раздача остановлена.")
    finally:
        server.server_close()


def qr_url(url: str) -> None:
    """QR-код, если установлен пакет qrcode (pip install qrcode)."""
    try:
        import qrcode  # type: ignore
    except ImportError:
        print(dim("(подсказка: pip install qrcode — и здесь будет QR-код для камеры)"))
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(url)
    qr.print_ascii(invert=True)


def cmd_update_ioc(_args: argparse.Namespace) -> None:
    banner()
    from ghost_lock.modules import ioc_update
    step("Тяну все STIX-фиды AmnestyTech (+ текстовые списки)…")
    try:
        rep = ioc_update.update()
    except Exception as e:  # noqa: BLE001
        die(f"Обновление не удалось: {e}")

    for section, n in rep["added"].items():
        if n:
            ok(f"{section}: +{n} новых")
        else:
            print(dim(f"[~] {section}: без изменений"))
    for err in rep["errors"][:5]:
        print(yellow(f"[~] фид недоступен: {err}"))
    total = sum(rep["totals"].values())
    print(bold(f"\nИтого индикаторов в базе: {total}"))

    step("Проверка целостности базы…")
    try:
        load_iocs()
        ok("База валидна.")
    except Exception as e:  # noqa: BLE001
        die(f"База повреждена после обновления: {e}")


# ── точка входа ──────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ghost-lock",
        description="Аудит и укрепление iPhone поверх Lockdown Mode.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="проверка окружения").set_defaults(func=cmd_doctor)
    sub.add_parser("devices", help="список подключённых устройств").set_defaults(func=cmd_devices)

    p_audit = sub.add_parser("audit", help="полный аудит устройства")
    p_audit.add_argument("--udid", help="UDID конкретного устройства")
    p_audit.add_argument("--deep", action="store_true",
                         help="глубокий режим: полный бэкап телефона + скан всех файлов (долго!)")
    p_audit.set_defaults(func=cmd_audit)

    p_prof = sub.add_parser("profiles", help="инструкция по установке защиты на телефон")
    p_prof.add_argument("--serve", action="store_true", help="раздать профили по локальной сети")
    p_prof.add_argument("--port", type=int, default=8808, help="порт для --serve (по умолчанию 8808)")
    p_prof.add_argument("--preset", choices=sorted(config.RESOLVER_PRESETS), help=f"пресет DNS-щита (по умолчанию: {config.DEFAULT_RESOLVER_PRESET})")
    p_prof.add_argument("--nextdns-id", help="ID конфига NextDNS для пресета nextdns")
    p_prof.set_defaults(func=cmd_profiles)

    sub.add_parser("update-ioc", help="обновить базу индикаторов из публичных фидов").set_defaults(func=cmd_update_ioc)

    p_tg = sub.add_parser("setup-telegram", help="подключить Telegram-алерты (нужен токен от @BotFather)")
    p_tg.add_argument("--token", required=True, help="токен бота из @BotFather")
    p_tg.set_defaults(func=cmd_setup_telegram)

    args = parser.parse_args()
    try:
        args.func(args)
    except connect.DeviceError as e:
        die(str(e))
    except KeyboardInterrupt:
        print("\n[*] Прервано пользователем.")
        sys.exit(130)


if __name__ == "__main__":
    main()
