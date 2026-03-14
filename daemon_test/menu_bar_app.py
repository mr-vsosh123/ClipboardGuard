#!/usr/bin/env python3
import argparse
import atexit
import os
import signal
import subprocess
import sys
import time

VALID_MODES = ("watcher", "sanitizer", "balance")


def run_worker(mode=None, parent_pid=None):
    from clipboard_guard.main import load_config
    from clipboard_guard.policy import normalize_mode
    from clipboard_guard.watcher import run_loop

    config = load_config()
    if mode:
        config["mode"] = normalize_mode(mode)
    if parent_pid:
        config["parent_pid"] = int(parent_pid)
    run_loop(config)


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--mode", default=None)
    parser.add_argument("--parent-pid", type=int, default=None)
    args, _ = parser.parse_known_args()
    return args


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def build_worker_cmd(mode, parent_pid):
    if is_frozen():
        return [sys.executable, "--worker", "--mode", mode, "--parent-pid", str(parent_pid)]
    return [
        sys.executable,
        "-u",
        os.path.abspath(__file__),
        "--worker",
        "--mode",
        mode,
        "--parent-pid",
        str(parent_pid),
    ]


args = parse_args()
if args.worker:
    run_worker(args.mode, parent_pid=args.parent_pid)
    sys.exit(0)


try:
    import rumps
except Exception:
    print("[menu-bar] Не найден пакет rumps")
    print("[menu-bar] Установи: python3 -m pip install rumps")
    sys.exit(1)


class ClipboardGuardMenu(rumps.App):
    def __init__(self):
        super().__init__("⚪️ CG:balance", quit_button=None)

        if is_frozen():
            self.base_dir = os.path.expanduser("~/Library/Application Support/ClipboardGuard")
            self.project_dir = self.base_dir
        else:
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
            self.project_dir = os.path.abspath(os.path.join(self.base_dir, "../.."))
        self.mode_file = os.path.join(self.base_dir, "current_mode")
        self.log_dir = os.path.join(self.base_dir, "logs")
        self.out_log = os.path.join(self.log_dir, "menu_guard.out.log")
        self.err_log = os.path.join(self.log_dir, "menu_guard.err.log")
        self.worker_pid_file = os.path.join(self.base_dir, "worker.pid")

        self.proc = None
        self.out_handle = None
        self.err_handle = None

        os.makedirs(self.log_dir, exist_ok=True)

        self.mode = self.read_mode()

        self.mode_watcher = rumps.MenuItem("Режим: Watcher", callback=self.on_mode_watcher)
        self.mode_sanitizer = rumps.MenuItem("Режим: Sanitizer", callback=self.on_mode_sanitizer)
        self.mode_balance = rumps.MenuItem("Режим: Balance", callback=self.on_mode_balance)
        self.quit_item = rumps.MenuItem("Выход", callback=self.on_quit)

        self.menu = [
            self.mode_watcher,
            self.mode_sanitizer,
            self.mode_balance,
            None,
            self.quit_item,
        ]

        self.timer = rumps.Timer(self.refresh, 2)
        self.timer.start()

        atexit.register(self.stop_guard)
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)

        # Сразу запускаем worker при старте приложения.
        self.start_guard()
        self.refresh()

    def read_mode(self):
        if not os.path.exists(self.mode_file):
            self.write_mode("balance")
            return "balance"

        try:
            with open(self.mode_file, "r", encoding="utf-8") as f:
                value = f.read().strip().lower()
        except Exception:
            value = "balance"

        if value not in VALID_MODES:
            value = "balance"
            self.write_mode(value)

        return value

    def write_mode(self, mode):
        if mode not in VALID_MODES:
            mode = "balance"
        with open(self.mode_file, "w", encoding="utf-8") as f:
            f.write(mode)

    def is_running(self):
        if self.proc is not None and self.proc.poll() is None:
            return True
        pid = self._read_worker_pid()
        return self._pid_alive(pid)

    def _pid_alive(self, pid):
        if not pid or pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _read_worker_pid(self):
        if not os.path.exists(self.worker_pid_file):
            return None
        try:
            with open(self.worker_pid_file, "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except Exception:
            return None

    def _write_worker_pid(self, pid):
        try:
            with open(self.worker_pid_file, "w", encoding="utf-8") as f:
                f.write(str(pid))
        except Exception:
            pass

    def _remove_worker_pid(self):
        try:
            if os.path.exists(self.worker_pid_file):
                os.remove(self.worker_pid_file)
        except Exception:
            pass

    def _stop_pid(self, pid):
        if not self._pid_alive(pid):
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            return

        deadline = time.time() + 2.5
        while time.time() < deadline:
            if not self._pid_alive(pid):
                return
            time.sleep(0.1)

        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    def _stop_stale_worker_from_pidfile(self):
        pid = self._read_worker_pid()
        current_pid = self.proc.pid if self.proc else None
        if pid and current_pid and pid == current_pid:
            return
        if pid:
            self._stop_pid(pid)
            self._remove_worker_pid()

    def _kill_legacy_workers(self):
        # На случай старых версий без PID-файла:
        # убираем возможные "сиротские" worker-процессы.
        patterns = [
            "menu_bar_app.py --worker",
            "ClipboardGuard --worker",
        ]
        for pattern in patterns:
            try:
                subprocess.run(
                    ["/usr/bin/pkill", "-f", pattern],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

    def start_guard(self):
        if self.is_running():
            return

        self._stop_stale_worker_from_pidfile()
        self._kill_legacy_workers()

        with open(self.out_log, "a", encoding="utf-8") as f:
            f.write(
                f"\n--- [menu start {time.strftime('%Y-%m-%d %H:%M:%S')}] mode={self.mode} py={sys.executable} ---\n"
            )

        self.out_handle = open(self.out_log, "a", encoding="utf-8", buffering=1)
        self.err_handle = open(self.err_log, "a", encoding="utf-8", buffering=1)

        cmd = build_worker_cmd(self.mode, os.getpid())
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        self.proc = subprocess.Popen(
            cmd,
            cwd=self.project_dir,
            stdout=self.out_handle,
            stderr=self.err_handle,
            env=env,
        )
        self._write_worker_pid(self.proc.pid)

    def stop_guard(self):
        if self.proc is not None:
            pid = self.proc.pid
            if self.proc.poll() is None:
                self._stop_pid(pid)
            self.proc = None

        stale_pid = self._read_worker_pid()
        if stale_pid:
            self._stop_pid(stale_pid)
        self._remove_worker_pid()

        if self.out_handle:
            self.out_handle.close()
            self.out_handle = None
        if self.err_handle:
            self.err_handle.close()
            self.err_handle = None

    def _on_signal(self, *_):
        self.stop_guard()
        sys.exit(0)

    def set_mode(self, mode):
        if mode not in VALID_MODES:
            return

        if self.mode == mode:
            self.refresh()
            return

        self.mode = mode
        self.write_mode(mode)

        restart_needed = self.is_running()
        if restart_needed:
            self.stop_guard()
            self.start_guard()

        try:
            rumps.notification(
                "Защита буфера",
                "Режим изменен",
                f"Текущий режим: {mode}",
            )
        except Exception:
            # На некоторых python-сборках (например pyenv без Info.plist)
            # системные уведомления rumps могут падать. Это не критично.
            pass
        self.refresh()

    def refresh(self, _=None):
        running = self.is_running()
        icon = "🟢" if running else "⚪️"
        self.title = f"{icon} CG:{self.mode}"

        self.mode_watcher.state = 1 if self.mode == "watcher" else 0
        self.mode_sanitizer.state = 1 if self.mode == "sanitizer" else 0
        self.mode_balance.state = 1 if self.mode == "balance" else 0

    def on_mode_watcher(self, _):
        self.set_mode("watcher")

    def on_mode_sanitizer(self, _):
        self.set_mode("sanitizer")

    def on_mode_balance(self, _):
        self.set_mode("balance")

    def on_quit(self, _):
        try:
            self.timer.stop()
        except Exception:
            pass
        self.stop_guard()
        rumps.quit_application()


if __name__ == "__main__":
    ClipboardGuardMenu().run()
