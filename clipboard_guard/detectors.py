import re

from .script_analyzer import detect_suspicious_scripts


EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+7|8)\s*(?:\(\s*\d{3}\s*\)|\d{3})[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
SNILS_RE = re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b|\b\d{11}\b")
INN_RE = re.compile(r"\b\d{10}\b|\b\d{12}\b")
PASSPORT_RE = re.compile(r"\b\d{4}\s?\d{6}\b")

JWT_RE = re.compile(r"\b[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,8000}?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)

API_KEY_PATTERNS = [
    (re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"), "SEC-API-STRIPE"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "SEC-API-AWS"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "SEC-API-GH"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "SEC-API-SLACK"),
]

HARD_REPLACEMENTS = {
    "pii_email": "[СКРЫТО: ЭЛ.ПОЧТА]",
    "pii_phone": "[СКРЫТО: ТЕЛЕФОН]",
    "pii_card": "[СКРЫТО: БАНКОВСКАЯ КАРТА]",
    "pii_snils": "[СКРЫТО: СНИЛС]",
    "pii_inn": "[СКРЫТО: ИНН]",
    "pii_passport": "[СКРЫТО: ПАСПОРТ РФ]",
    "secret_jwt": "[СКРЫТО: JWT]",
    "secret_api_key": "[СКРЫТО: API КЛЮЧ]",
    "secret_private_key": "[СКРЫТО: ПРИВАТНЫЙ КЛЮЧ]",
}


def _finding(category, kind, start, end, text, rule_id, label, replacement=None):
    return {
        "category": category,
        "kind": kind,
        "start": start,
        "end": end,
        "text_preview": text[:40],
        "rule_id": rule_id,
        "label": label,
        "replacement": replacement,
    }


def _digits(value):
    return re.sub(r"\D", "", value)


def _luhn_ok(number):
    digits = [int(x) for x in number]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _snils_ok(raw):
    num = _digits(raw)
    if len(num) != 11:
        return False
    base = num[:9]
    control = int(num[9:])
    total = sum((9 - i) * int(base[i]) for i in range(9))
    if total < 100:
        expected = total
    elif total in (100, 101):
        expected = 0
    else:
        expected = total % 101
        if expected == 100:
            expected = 0
    return control == expected


def _phone_ok(raw):
    num = _digits(raw)
    if len(num) != 11:
        return False
    return num.startswith("7") or num.startswith("8")


def _inn10_ok(num):
    c = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    control = (sum(int(num[i]) * c[i] for i in range(9)) % 11) % 10
    return control == int(num[9])


def _inn12_ok(num):
    c11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    c12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    d11 = (sum(int(num[i]) * c11[i] for i in range(10)) % 11) % 10
    d12 = (sum(int(num[i]) * c12[i] for i in range(11)) % 11) % 10
    return d11 == int(num[10]) and d12 == int(num[11])


def detect_pii(text, sanitize_map):
    findings = []

    for m in EMAIL_RE.finditer(text):
        findings.append(
            _finding(
                "pii",
                "pii_email",
                m.start(),
                m.end(),
                m.group(0),
                "PII-EMAIL-01",
                "Эл. почта",
                HARD_REPLACEMENTS["pii_email"],
            )
        )

    for m in PHONE_RE.finditer(text):
        if _phone_ok(m.group(0)):
            findings.append(
                _finding(
                    "pii",
                    "pii_phone",
                    m.start(),
                    m.end(),
                    m.group(0),
                    "PII-PHONE-01",
                    "Телефон",
                    HARD_REPLACEMENTS["pii_phone"],
                )
            )

    for m in CARD_RE.finditer(text):
        d = _digits(m.group(0))
        if 13 <= len(d) <= 19 and _luhn_ok(d):
            findings.append(
                _finding(
                    "pii",
                    "pii_card",
                    m.start(),
                    m.end(),
                    m.group(0),
                    "PII-CARD-01",
                    "Банковская карта",
                    HARD_REPLACEMENTS["pii_card"],
                )
            )

    for m in SNILS_RE.finditer(text):
        if _snils_ok(m.group(0)):
            findings.append(
                _finding(
                    "pii",
                    "pii_snils",
                    m.start(),
                    m.end(),
                    m.group(0),
                    "PII-SNILS-01",
                    "СНИЛС",
                    HARD_REPLACEMENTS["pii_snils"],
                )
            )

    for m in INN_RE.finditer(text):
        num = m.group(0)
        ok = (len(num) == 10 and _inn10_ok(num)) or (len(num) == 12 and _inn12_ok(num))
        if ok:
            findings.append(
                _finding(
                    "pii",
                    "pii_inn",
                    m.start(),
                    m.end(),
                    num,
                    "PII-INN-01",
                    "ИНН",
                    HARD_REPLACEMENTS["pii_inn"],
                )
            )

    for m in PASSPORT_RE.finditer(text):
        findings.append(
            _finding(
                "pii",
                "pii_passport",
                m.start(),
                m.end(),
                m.group(0),
                "PII-PASSPORT-01",
                "Паспорт РФ",
                HARD_REPLACEMENTS["pii_passport"],
            )
        )

    return findings


def detect_secrets(text, sanitize_map):
    findings = []

    for m in JWT_RE.finditer(text):
        findings.append(
            _finding(
                "secret",
                "secret_jwt",
                m.start(),
                m.end(),
                m.group(0),
                "SEC-JWT-01",
                "JWT токен",
                HARD_REPLACEMENTS["secret_jwt"],
            )
        )

    for pattern, rule_id in API_KEY_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(
                _finding(
                    "secret",
                    "secret_api_key",
                    m.start(),
                    m.end(),
                    m.group(0),
                    rule_id,
                    "API ключ",
                    HARD_REPLACEMENTS["secret_api_key"],
                )
            )

    for m in PRIVATE_KEY_RE.finditer(text):
        findings.append(
            _finding(
                "secret",
                "secret_private_key",
                m.start(),
                m.end(),
                m.group(0),
                "SEC-PRIVKEY-01",
                "Блок приватного ключа",
                HARD_REPLACEMENTS["secret_private_key"],
            )
        )

    return findings


def run_all_detectors(text, sanitize_map):
    pii = detect_pii(text, sanitize_map)
    sec = detect_secrets(text, sanitize_map)
    cmd = detect_suspicious_scripts(text)
    return pii + sec + cmd
