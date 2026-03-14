#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_SCRIPT="$SCRIPT_DIR/menu_bar_app.py"

if [[ -f "$SCRIPT_DIR/python_bin" ]]; then
  PYTHON_BIN="$(tr -d '\r\n' < "$SCRIPT_DIR/python_bin")"
else
  PYTHON_BIN="$(command -v python3)"
fi

# Если выбранный python не видит pyinstaller, пробуем найти другой.
if ! "$PYTHON_BIN" -m PyInstaller --version >/dev/null 2>&1; then
  for py in "$HOME/.pyenv/versions"/*/bin/python3; do
    [[ -x "$py" ]] || continue
    if "$py" -m PyInstaller --version >/dev/null 2>&1; then
      PYTHON_BIN="$py"
      break
    fi
  done
fi

if ! "$PYTHON_BIN" -m PyInstaller --version >/dev/null 2>&1; then
  echo "[build] pyinstaller не найден"
  echo "[build] установи: $PYTHON_BIN -m pip install pyinstaller"
  exit 1
fi

"$PYTHON_BIN" -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name ClipboardGuard \
  --paths "$PROJECT_DIR" \
  --distpath "$SCRIPT_DIR/dist" \
  --workpath "$SCRIPT_DIR/build" \
  --specpath "$SCRIPT_DIR/build" \
  --hidden-import clipboard_guard.main \
  --hidden-import clipboard_guard.watcher \
  --hidden-import clipboard_guard.policy \
  --hidden-import clipboard_guard.analyzer \
  --hidden-import clipboard_guard.detectors \
  --hidden-import clipboard_guard.clipboard_io \
  --hidden-import clipboard_guard.script_analyzer \
  --hidden-import clipboard_guard.paste_hotkey \
  --add-data "$PROJECT_DIR/clipboard_guard/config.json:clipboard_guard" \
  "$APP_SCRIPT"

APP_PATH="$SCRIPT_DIR/dist/ClipboardGuard.app"

echo "[build] готово: $APP_PATH"
echo "[build] запуск: open \"$APP_PATH\""
