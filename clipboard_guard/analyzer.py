from .detectors import run_all_detectors

def normalize_text(text):
    if not isinstance(text, str):
        return ""
    return text.strip()


def _apply_replacements(text, findings):
    items = [f for f in findings if f.get("replacement") and f.get("start") is not None]
    if not items:
        return text, 0

    # stable replace by spans, left to right, no overlap
    items.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))

    out = []
    last = 0
    replaced = 0
    for f in items:
        s = f["start"]
        e = f["end"]
        if s < last:
            continue
        out.append(text[last:s])
        out.append(f["replacement"])
        last = e
        replaced += 1

    out.append(text[last:])
    return "".join(out), replaced


def _short_summary(findings, limit=5):
    labels = []
    seen = set()
    for f in findings:
        x = f.get("label", "Match")
        if x in seen:
            continue
        labels.append(x)
        seen.add(x)
        if len(labels) >= limit:
            break
    return labels


def analyze_text(raw_text, config):
    text = normalize_text(raw_text)
    max_len = config.get("max_text_length", 64000)
    if len(text) > max_len:
        text = text[:max_len]

    sanitize_map = config.get("sanitize_map", {})
    findings = run_all_detectors(text, sanitize_map)

    sensitive = [f for f in findings if f["category"] in ("pii", "secret")]
    sanitized_text, replaced_count = _apply_replacements(text, sensitive)

    return {
        "input_len": len(text),
        "is_risky": len(findings) > 0,
        "findings": findings,
        "summary_labels": _short_summary(findings),
        "categories": sorted(list({x["category"] for x in findings})),
        "rules": sorted(list({x["rule_id"] for x in findings})),
        "sensitive_count": len(sensitive),
        "replaced_count": replaced_count,
        "sanitized_text": sanitized_text,
        "original_text": text,
    }
