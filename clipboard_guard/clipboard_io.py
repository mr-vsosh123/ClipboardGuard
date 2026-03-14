import platform
import subprocess


class ClipboardBackend:
    def __init__(self):
        self.system = platform.system().lower()
        if "darwin" in self.system:
            self.kind = "macos_native"
        elif "windows" in self.system:
            self.kind = "windows_native"
        else:
            self.kind = "unsupported"

    def get_text(self):
        if self.kind == "macos_native":
            # 1) Быстрый путь через pbpaste.
            try:
                p = subprocess.run(["/usr/bin/pbpaste"], capture_output=True, check=False)
                if p.returncode != 0:
                    # 2) Fallback через osascript (иногда стабильнее для background-процессов).
                    p2 = subprocess.run(
                        ["/usr/bin/osascript", "-e", "the clipboard as text"],
                        capture_output=True,
                        check=False,
                    )
                    if p2.returncode != 0:
                        return ""
                    value = p2.stdout.decode("utf-8", errors="ignore")
                    # osascript часто добавляет \n в конец вывода.
                    if value.endswith("\n"):
                        value = value[:-1]
                    return value
                return p.stdout.decode("utf-8", errors="ignore")
            except Exception:
                return ""

        if self.kind == "windows_native":
            try:
                p = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                    capture_output=True,
                    check=False,
                )
                if p.returncode != 0:
                    return ""
                return p.stdout.decode("utf-8", errors="ignore")
            except Exception:
                return ""

        return ""

    def set_text(self, value):
        value = value if isinstance(value, str) else ""

        if self.kind == "macos_native":
            # 1) Быстрый путь через pbcopy.
            try:
                p = subprocess.run(
                    ["/usr/bin/pbcopy"],
                    input=value.encode("utf-8"),
                    check=False,
                )
                if p.returncode == 0:
                    return True

                # 2) Fallback через osascript.
                p2 = subprocess.run(
                    [
                        "/usr/bin/osascript",
                        "-e",
                        "on run argv",
                        "-e",
                        "set the clipboard to (item 1 of argv)",
                        "-e",
                        "end run",
                        value,
                    ],
                    check=False,
                )
                return p2.returncode == 0
            except Exception:
                return False

        if self.kind == "windows_native":
            try:
                p = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "Set-Clipboard"],
                    input=value.encode("utf-8"),
                    check=False,
                )
                return p.returncode == 0
            except Exception:
                return False

        return False
