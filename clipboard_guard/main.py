import argparse
import json
import os

from .policy import normalize_mode
from .watcher import run_loop


def load_config():
    here = os.path.dirname(__file__)
    path = os.path.join(here, "config.json")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["mode"] = normalize_mode(cfg.get("mode", "watcher"))
    return cfg


def main():
    parser = argparse.ArgumentParser(description="Защита буфера обмена")
    parser.add_argument("--mode", default=None, help="watcher | sanitizer | balance")
    args = parser.parse_args()

    config = load_config()
    if args.mode:
        config["mode"] = normalize_mode(args.mode)

    try:
        run_loop(config)
    except KeyboardInterrupt:
        print("\n[ЗащитаБуфера] остановлено")


if __name__ == "__main__":
    main()
