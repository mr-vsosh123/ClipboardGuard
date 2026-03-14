import platform
import subprocess


def normalize_mode(mode):
    x = (mode or "").strip().lower()
    if x in ("wathcher", "watch", "monitor", "наблюдение", "монитор"):
        x = "watcher"
    if x in ("sanitize", "san", "защита", "санитайзер"):
        x = "sanitizer"
    if x in ("баланс", "подтверждение", "confirm"):
        x = "balance"
    if x not in ("watcher", "sanitizer", "balance"):
        return "watcher"
    return x


def build_decision(mode, analysis, auto_erase_seconds=15, erase_after_first_paste=True):
    mode = normalize_mode(mode)
    risky = analysis.get("is_risky", False)
    replaced = analysis.get("replaced_count", 0) > 0
    has_sensitive = analysis.get("sensitive_count", 0) > 0
    categories = analysis.get("categories", [])
    labels = analysis.get("summary_labels", [])

    notify = risky
    replace_clipboard = False
    arm_auto_erase = False

    if mode == "sanitizer" and risky and replaced:
        replace_clipboard = True
        arm_auto_erase = True
    elif mode == "balance" and risky and has_sensitive:
        arm_auto_erase = True

    message = "Проверка буфера: рискованный контент не найден."
    if risky:
        found_text = ", ".join(labels) if labels else ", ".join(categories)
        if replace_clipboard:
            if erase_after_first_paste:
                message = (
                    f"Чувствительные фрагменты скрыты: {found_text}. "
                    f"Буфер очистится после первой вставки или через {auto_erase_seconds} сек."
                )
            else:
                message = (
                    f"Чувствительные фрагменты скрыты: {found_text}. "
                    f"Автоочистка буфера через {auto_erase_seconds} сек."
                )
        elif arm_auto_erase:
            if erase_after_first_paste:
                message = (
                    f"Найдены чувствительные данные: {found_text}. "
                    f"Можно вставить 1 раз, потом очистка или через {auto_erase_seconds} сек."
                )
            else:
                message = (
                    f"Найдены чувствительные данные: {found_text}. "
                    f"Можно вставить сейчас, автоочистка через {auto_erase_seconds} сек."
                )
        else:
            message = f"Обнаружен рискованный контент в буфере: {found_text}"

    return {
        "mode": mode,
        "notify": notify,
        "replace_clipboard": replace_clipboard,
        "arm_auto_erase": arm_auto_erase,
        "message": message,
    }


def notify_user(message, title="Защита буфера обмена"):
    system = platform.system().lower()
    safe_title = title.replace('"', "'")
    safe_message = message.replace('"', "'")

    try:
        if "darwin" in system:
            subprocess.run(
                ["osascript", "-e", f'display notification "{safe_message}" with title "{safe_title}"'],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
    except Exception:
        pass

    print(f"[NOTIFY] {safe_title}: {safe_message}")
