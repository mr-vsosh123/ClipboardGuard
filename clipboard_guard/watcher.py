import hashlib
import os
import time

from .analyzer import analyze_text
from .clipboard_io import ClipboardBackend
from .paste_hotkey import start_paste_listener
from .policy import build_decision, notify_user


def _hash(text):
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()


def _fingerprint(text):
    # Стабилизируем текст для дедупликации событий:
    # одинаковый смысл -> одинаковый отпечаток.
    normalized = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    # Доп. стабилизация по пробелам, чтобы не триггерить ложные "новые" события.
    normalized = "\n".join(" ".join(line.split()) for line in normalized.split("\n"))
    return _hash(normalized)


def _pid_alive(pid):
    if not pid or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def run_loop(config):
    mode = config.get("mode", "watcher")
    poll = float(config.get("poll_interval_sec", 0.35))
    notify_enabled = bool(config.get("notify", True))
    notify_repeat_window_sec = float(config.get("notify_repeat_window_sec", 60))
    auto_erase_seconds = int(config.get("auto_erase_seconds", 15))
    erase_after_first_paste = bool(config.get("erase_after_first_paste", True))
    parent_pid = int(config.get("parent_pid", 0) or 0)
    clip = ClipboardBackend()

    last_hash = None
    skip_hash = None
    pending_auto_erase = None
    pending_one_paste = None
    recent_notified = {}
    paste_signal = False

    def _on_paste():
        nonlocal paste_signal
        paste_signal = True

    paste_listener = None
    first_paste_active = False
    if erase_after_first_paste:
        paste_listener = start_paste_listener(_on_paste)
        if paste_listener:
            print("[ЗащитаБуфера] затирание после 1-й вставки: включено")
            first_paste_active = True
        else:
            print("[ЗащитаБуфера] затирание после 1-й вставки недоступно (нет pynput/доступа)")

    print(f"[ЗащитаБуфера] режим={mode} интервал={poll}s backend={clip.kind}")
    try:
        while True:
            if parent_pid and not _pid_alive(parent_pid):
                print("[ЗащитаБуфера] родитель завершен, worker остановлен")
                break

            try:
                text = clip.get_text()
                if not isinstance(text, str):
                    time.sleep(poll)
                    continue
            except Exception:
                time.sleep(poll)
                continue

            h = _fingerprint(text)

            # Очистка буфера после первой вставки чувствительных данных.
            if paste_signal:
                paste_signal = False
                if pending_one_paste and h == pending_one_paste["hash"]:
                    ok = clip.set_text("")
                    if ok:
                        print("[ЗащитаБуфера] буфер очищен после первой вставки")
                        skip_hash = _fingerprint("")
                        last_hash = skip_hash
                    else:
                        print("[ЗащитаБуфера] не удалось очистить буфер после вставки")
                    pending_one_paste = None
                    pending_auto_erase = None
                    time.sleep(poll)
                    continue

            # Если пользователь скопировал другой текст, отменяем ранее запланированную очистку.
            if pending_auto_erase and h != pending_auto_erase["hash"]:
                pending_auto_erase = None
            if pending_one_paste and h != pending_one_paste["hash"]:
                pending_one_paste = None

            # Отложенная автоочистка через N секунд.
            if pending_auto_erase and time.time() >= pending_auto_erase["deadline"]:
                if h == pending_auto_erase["hash"]:
                    ok = clip.set_text("")
                    if ok:
                        print("[ЗащитаБуфера] буфер автоматически очищен")
                        skip_hash = _fingerprint("")
                        last_hash = skip_hash
                    else:
                        print("[ЗащитаБуфера] не удалось выполнить автоочистку буфера")
                pending_auto_erase = None
                pending_one_paste = None
                time.sleep(poll)
                continue

            if h == last_hash:
                time.sleep(poll)
                continue

            if skip_hash and h == skip_hash:
                last_hash = h
                skip_hash = None
                time.sleep(poll)
                continue

            analysis = analyze_text(text, config)
            decision = build_decision(
                mode,
                analysis,
                auto_erase_seconds=auto_erase_seconds,
                erase_after_first_paste=first_paste_active,
            )
            has_sensitive = analysis.get("sensitive_count", 0) > 0

            if analysis.get("is_risky", False):
                print(
                    "[ЗащитаБуфера] обнаружено",
                    f"categories={analysis.get('categories', [])}",
                    f"rules={analysis.get('rules', [])}",
                    f"replaced_count={analysis.get('replaced_count', 0)}",
                )

            if decision["replace_clipboard"]:
                new_text = analysis.get("sanitized_text", "")
                try:
                    ok = clip.set_text(new_text)
                    if ok:
                        skip_hash = _fingerprint(new_text)
                        print("[ЗащитаБуфера] чувствительные фрагменты скрыты")
                        if decision.get("arm_auto_erase"):
                            pending_auto_erase = {
                                "hash": skip_hash,
                                "deadline": time.time() + auto_erase_seconds,
                            }
                        if first_paste_active and has_sensitive:
                            pending_one_paste = {"hash": skip_hash}
                    else:
                        print("[ЗащитаБуфера] не удалось записать обработанный текст в буфер")
                except Exception:
                    print("[ЗащитаБуфера] ошибка при обработке буфера")
            elif decision.get("arm_auto_erase"):
                pending_auto_erase = {
                    "hash": h,
                    "deadline": time.time() + auto_erase_seconds,
                }
                if first_paste_active and has_sensitive:
                    pending_one_paste = {"hash": h}

            if decision["notify"] and notify_enabled:
                now = time.time()
                last_ts = recent_notified.get(h, 0.0)
                if now - last_ts >= notify_repeat_window_sec:
                    notify_user(decision["message"])
                    recent_notified[h] = now
                # Периодическая очистка кэша дедупликации.
                if len(recent_notified) > 256:
                    cutoff = now - (notify_repeat_window_sec * 2)
                    recent_notified = {k: v for k, v in recent_notified.items() if v >= cutoff}

            last_hash = skip_hash if skip_hash else h
            time.sleep(poll)
    finally:
        if paste_listener:
            paste_listener.stop()
