import json
import os

from .analyzer import analyze_text
from .clipboard_io import ClipboardBackend


def main():
    here = os.path.dirname(__file__)
    cfg = json.load(open(os.path.join(here, "config.json"), "r", encoding="utf-8"))

    sample = "паспорт - 2343 553123"
    res = analyze_text(sample, cfg)

    print("=== Проверка анализатора ===")
    print("найден риск:", res["is_risky"])
    print("правила:", res["rules"])
    print("число замен:", res["replaced_count"])
    print("санитизированный текст:", res["sanitized_text"])

    print("\n=== Проверка backend буфера ===")
    clip = ClipboardBackend()
    print("активный backend:", clip.kind)

    old = clip.get_text()
    ok = clip.set_text(sample)
    now = clip.get_text()

    print("запись успешна:", ok)
    print("прочитано как sample:", now == sample)

    if ok and res["sanitized_text"] != sample:
        ok2 = clip.set_text(res["sanitized_text"])
        now2 = clip.get_text()
        print("запись санитизированного успешна:", ok2)
        print("прочитано как санитизированный:", now2 == res["sanitized_text"])

    # restore previous clipboard
    clip.set_text(old)


if __name__ == "__main__":
    main()
