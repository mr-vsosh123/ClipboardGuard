import platform
import time

try:
    from pynput import keyboard
except Exception:
    keyboard = None


class PasteHotkeyListener:
    def __init__(self, on_paste):
        self.on_paste = on_paste
        self.listener = None
        self.is_macos = "darwin" in platform.system().lower()
        self.cmd_pressed = False
        self.ctrl_pressed = False
        self.last_fire = 0.0

    def start(self):
        if keyboard is None:
            return False
        try:
            self.listener = keyboard.Listener(
                on_press=self._on_press,
                on_release=self._on_release,
            )
            self.listener.daemon = True
            self.listener.start()
            return True
        except Exception:
            return False

    def stop(self):
        if self.listener:
            try:
                self.listener.stop()
            except Exception:
                pass
            self.listener = None

    def _is_v(self, key):
        try:
            return getattr(key, "char", "").lower() == "v"
        except Exception:
            return False

    def _on_press(self, key):
        if key in (keyboard.Key.cmd, keyboard.Key.cmd_l, keyboard.Key.cmd_r):
            self.cmd_pressed = True
            return
        if key in (keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
            self.ctrl_pressed = True
            return

        if not self._is_v(key):
            return

        paste_combo = self.cmd_pressed if self.is_macos else self.ctrl_pressed
        if not paste_combo:
            return

        now = time.time()
        if now - self.last_fire < 0.25:
            return
        self.last_fire = now

        try:
            self.on_paste()
        except Exception:
            pass

    def _on_release(self, key):
        if key in (keyboard.Key.cmd, keyboard.Key.cmd_l, keyboard.Key.cmd_r):
            self.cmd_pressed = False
        elif key in (keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
            self.ctrl_pressed = False


def start_paste_listener(on_paste):
    listener = PasteHotkeyListener(on_paste)
    if not listener.start():
        return None
    return listener
