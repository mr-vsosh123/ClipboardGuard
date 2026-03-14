import base64
import re


CMD_PATTERNS = [
    (re.compile(r"(curl|wget)[^\n]{0,120}\|\s*(bash|sh)\b", re.IGNORECASE), "CMD-BASH-001", "Команда через pipe в shell"),
    (re.compile(r"\b(?:IEX|Invoke-Expression)\b", re.IGNORECASE), "CMD-PS-001", "Выполнение PowerShell команды"),
    (re.compile(r"\beval\s*\(", re.IGNORECASE), "CMD-JS-001", "JavaScript eval"),
    (re.compile(r"\b-EncodedCommand\b", re.IGNORECASE), "CMD-PS-ENC-001", "PowerShell encoded команда"),
]

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])")
URLSAFE_B64_RE = re.compile(r"(?<![A-Za-z0-9\-_])([A-Za-z0-9\-_]{24,}={0,2})(?![A-Za-z0-9\-_])")

MAX_B64_CANDIDATES = 8
MAX_B64_TOKEN_LEN = 4096
MAX_DECODE_LEN = 4096


def _finding(start, end, text, rule_id, label, source):
    return {
        "category": "command",
        "kind": "command_suspicious",
        "start": start,
        "end": end,
        "text_preview": text[:40],
        "rule_id": rule_id,
        "label": label,
        "replacement": None,
        "source": source,
    }


def _maybe_decode_base64(token):
    raw_token = token.strip()
    if not raw_token:
        return None
    if len(raw_token) > MAX_B64_TOKEN_LEN:
        return None
    if len(raw_token) % 4 != 0:
        return None

    candidates = [raw_token]
    if "-" in raw_token or "_" in raw_token:
        candidates.append(raw_token.replace("-", "+").replace("_", "/"))

    for value in candidates:
        try:
            data = base64.b64decode(value, validate=True)
            if len(data) == 0 or len(data) > MAX_DECODE_LEN:
                continue
            text = data.decode("utf-8", errors="ignore")
            if not text.strip():
                continue
            printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
            if printable / max(len(text), 1) < 0.85:
                continue
            return text
        except Exception:
            continue
    return None


def _iter_base64_decoded_texts(text):
    count = 0
    seen = set()
    for regex in (BASE64_RE, URLSAFE_B64_RE):
        for m in regex.finditer(text):
            if count >= MAX_B64_CANDIDATES:
                return
            token = m.group(1)
            key = (m.start(), m.end(), token)
            if key in seen:
                continue
            seen.add(key)
            decoded = _maybe_decode_base64(token)
            if not decoded:
                continue
            count += 1
            yield m.start(), m.end(), token, decoded


def detect_suspicious_scripts(text):
    findings = []
    seen = set()

    for pattern, rule_id, label in CMD_PATTERNS:
        for m in pattern.finditer(text):
            key = (rule_id, m.start(), m.end(), "plain")
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding(m.start(), m.end(), m.group(0), rule_id, label, "plain"))

    for start, end, token, decoded in _iter_base64_decoded_texts(text):
        for pattern, rule_id, label in CMD_PATTERNS:
            if not pattern.search(decoded):
                continue
            key = (rule_id, start, end, "decoded_base64")
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _finding(
                    start,
                    end,
                    token,
                    f"{rule_id}-B64",
                    f"{label} (из base64)",
                    "decoded_base64",
                )
            )

    return findings
