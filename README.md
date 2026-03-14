# ClipboardGuard (MVP)

Локальный инструмент защиты буфера обмена.

## Что в репозитории
- `clipboard_guard/` — исходный код анализатора и worker.
- `daemon_test/macos/` — menu bar приложение для macOS + скрипт сборки `.app`.
- `requirements.txt` — зависимости для запуска/сборки.

## Режимы
- `watcher` — только уведомления.
- `sanitizer` — точечная маскировка чувствительных фрагментов.
- `balance` — уведомление + отложенное автоочищение буфера.

## Запуск из исходников
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m clipboard_guard.main --mode watcher
```

Смена режима:
```bash
python -m clipboard_guard.main --mode sanitizer
python -m clipboard_guard.main --mode balance
```

## Сборка macOS `.app` (без `.dmg`)
```bash
cd daemon_test/macos
./build_macos_app.sh
```

Результат сборки:
- `daemon_test/macos/dist/ClipboardGuard.app`

Запуск:
```bash
open daemon_test/macos/dist/ClipboardGuard.app
```
