# macOS Menu Bar App

Этот каталог содержит исходники menu bar приложения для macOS.

## Что внутри
- `menu_bar_app.py` — UI и управление worker.
- `build_macos_app.sh` — сборка `.app` из source.

## Сборка
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install pyinstaller rumps pynput

cd daemon_test/
./build_macos_app.sh
```

Результат сборки:
- `daemon_test/dist/ClipboardGuard.app`

## Запуск
```bash
open daemon_test/dist/ClipboardGuard.app
```
