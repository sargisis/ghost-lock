# Установка по платформам (Linux · macOS · Windows)

Ядро ghost-lock — аудит, генерация профилей, Telegram-алерты, история аудитов,
глубокая форензика — работает везде, где есть [libimobiledevice](https://libimobiledevice.org)
и Python 3. Но один компонент платформозависимый:

> ⚠️ **Демон авто-аудита `glock-watch` — только Linux.** Он слушает события USB
> ядра через netlink (`AF_NETLINK`), которого не существует на macOS и Windows.
> Ниже — честные альтернативы для этих платформ.

## Матрица возможностей

| Фича | Linux | macOS | Windows |
|---|---|---|---|
| Полный аудит (`audit`, `--deep`) | ✅ | ✅ | ✅ * |
| Профили на телефон (`profiles`) | ✅ | ✅ | ✅ |
| Обновление базы IOC (STIX) | ✅ | ✅ | ✅ |
| Telegram-алерты | ✅ | ✅ | ✅ |
| История аудитов и diff | ✅ | ✅ | ✅ |
| Демон авто-аудита | ✅ netlink | ➖ скрипт-поллинг | ➖ PowerShell-событие |

\* Windows зависит от сторонних сборок libimobiledevice — см. заметки.

---

## Linux (основная платформа)

Всё работает из коробки, включая демон авто-аудита:

```bash
sudo apt install libimobiledevice-utils   # Debian/Ubuntu
# Fedora: sudo dnf install libimobiledevice-utils
# Arch:   sudo pacman -S libimobiledevice usbmuxd

python3 ghost_lock/ghost_lock.py doctor   # проверка
./deploy/install_watch.sh                 # опционально: демон авто-аудита
```

Нужен Python 3.10+. Go требуется только для пересборки сканера
(`cd go && go build ./...`) — иначе гибридный движок сам откатится
на чистый Python.

## macOS

libimobiledevice — первоклассный гражданин в Homebrew:

```bash
brew install libimobiledevice python go

python3 -m venv .venv && source .venv/bin/activate   # опционально
python3 ghost_lock/ghost_lock.py doctor
python3 ghost_lock/ghost_lock.py audit
```

Заметки:
- При первом подключении на телефоне появится стандартный диалог «Доверять
  этому компьютеру» — как и на Linux.
- Профили `.mobileconfig` устанавливаются в сам iPhone, поэтому вся работа с
  ними одинакова на любой ОС хоста. `profiles --serve` тоже работает.
- **Демон авто-аудита:** netlink здесь нет. Грубая, но рабочая замена — цикл
  опроса; сохрани как `watch_mac.sh` и запусти под любым менеджером процессов:

```bash
#!/bin/bash
# Простой USB-watcher для macOS: опрос каждые 15 сек, пауза 5 мин после аудита.
while true; do
  if system_profiler SPUSBDataType 2>/dev/null | grep -q "iPhone"; then
    python3 "$(dirname "$0")/ghost_lock/ghost_lock.py" audit || true
    sleep 300
  fi
  sleep 15
done
```

Продвинутая версия использовала бы IOKit-уведомления через PyObjC — pull request'ы приветствуются.

## Windows

Честная картина: libimobiledevice на Windows работает, но это не установка в
один клик, как на Linux/macOS. Два рабочих пути:

### Путь 1 — MSYS2 (рекомендуется, пакеты поддерживаются)

```powershell
winget install MSYS2.MSYS2
# в оболочке MSYS2 UCRT64:
pacman -S mingw-w64-ucrt-x86_64-libimobiledevice \
          mingw-w64-ucrt-x86_64-python \
          mingw-w64-ucrt-x86_64-go
```

Добавь `C:\msys64\ucrt64\bin` в PATH, затем проверь, что `ideviceinfo`
показывает данные подключённого и доверенного айфона.

### Путь 2 — обычный Python + готовые бинарники

Установи Python 3.10+ с python.org, затем возьми собранные утилиты
`idevice*.exe` из проверенного дистрибутива libimobiledevice для Windows
(актуальные ссылки смотри в официальной документации проекта — сборки иногда
переезжают). Положи их в каталог из PATH.

### Что работает одинаково, а что отличается

- Все команды CLI ведут себя идентично: `audit`, `--deep`, `profiles`,
  `setup-telegram`, `update-ioc`.
- Отличаются пути: данные складываются в пользовательский профиль
  (`Path.home() / ".local/share"` резолвится в папку пользователя).
- **Авто-аудит:** нет netlink. Используй Планировщик заданий или подписку на
  WMI-событие для устройств Apple (USB VID `05AC`). Набросок:

```powershell
Register-CimIndicationEvent -QueryName iPhonePlug -Query `
  "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.DeviceID LIKE '%VID_05AC%'" | ForEach-Object {
    & python C:\path\to\ghost_lock\ghost_lock.py audit
  }
```

Проверь набросок на своей машине прежде чем полагаться на него — тайминги WMI
различаются между версиями Windows.

---

## Одинаково на всех платформах

- **Укрепление на телефоне** (три профиля `.mobileconfig`) ставится в сам
  iPhone и никак не зависит от ОС компьютера.
- Установка новых профилей требует временно выключить Lockdown Mode на любой
  платформе — Apple принципиально требует ручного подтверждения.
- Сопряжение («Доверять») происходит один раз; дальше аудитам экран телефона
  не нужен.

---

English version: [INSTALL.md](INSTALL.md)
