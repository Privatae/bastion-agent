"""Deterministic PII detectors — the high-precision anchor pass.

Two jobs: (1) anchor the sterilizer with detections that never depend on
model behavior, and (2) re-scan sterilized output as the residual check
(pipeline.py loops until this pass finds nothing). Recall for contextual
PII — names, addresses, employers, "my daughter's school" — is the LLM
pass's job (llmclient.py); here precision is deliberately favored over
recall, because a miss still has two more passes to be caught while a
false positive burns a vault row forever.

Overlapping candidates are resolved by type priority then span length:
an IPv4 address must not be re-claimed as a dotted phone number, a MAC
must not be claimed as truncated IPv6.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import List

# Full type vocabulary — shared with the LLM extraction schema. Rules
# only ever emit the subset in _DETECTORS; the rest are LLM-only types.
PII_TYPES = [
    "PERSON", "EMAIL", "PHONE", "ADDRESS", "SSN", "DOB",
    "CREDIT_CARD", "BANK_ACCOUNT", "IP_ADDRESS", "MAC_ADDRESS",
    "USERNAME", "CREDENTIAL", "MEDICAL", "ID_NUMBER", "ORG",
    "LOCATION", "OTHER",
]


@dataclass(frozen=True)
class Finding:
    value: str
    type: str
    start: int
    end: int


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:.-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
    r"(?![0-9A-Fa-f:-])(?!\.[\w-])"
)

# A full stop after the address ends a sentence; one followed by a letter or
# digit makes it part of something longer (a dotted number, a file name).
# The same rule applies to phone numbers and MAC addresses.
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.[\w-])")

# Loose candidate; ipaddress.ip_address() is the validator (also rejects
# MAC-shaped hex, which has 6 groups and no '::').
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")

SSN_RE = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")

# 13–19 digits with optional single space/dash separators; Luhn decides.
CARD_RE = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")

# Digit-count and shape checks happen in code; this only shapes candidates.
PHONE_RE = re.compile(
    r"(?<![\w.])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]\d{2,4}){1,4}"
    r"(?![\w-])(?!\.[\w-])"   # a sentence-ending full stop is not part of the number
)


# ── checksum-validated account identifiers (borrowed from Presidio's
# recognizer list; only the ones a checksum can anchor are here) ──────────

# IBAN: country code + 2 check digits + 11-30 alphanumerics, optional
# spaces every 4. mod-97 == 1 decides (ISO 13616).
IBAN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?(?![A-Za-z0-9])")
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18,
    "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22,
    "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22,
    "IL": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LI": 21,
    "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27,
    "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25,
    "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "TN": 24, "TR": 26, "UA": 29, "VG": 24, "XK": 20,
}

# US ABA routing number: 9 digits with a weighted checksum. One in ten
# random 9-digit strings passes, so a routing/ABA/RTN cue within 40 chars
# before the number is required — same precision stance as Presidio.
ABA_RE = re.compile(r"(?<!\d)\d{9}(?!\d)")
ABA_CUE_RE = re.compile(r"(?i)\b(?:routing|aba|rtn|transit)\b")

# Bitcoin: legacy/P2SH base58check (1.../3...). Bech32 (bc1...) has its own
# checksum; kept out of v1.2 — its decode is more code than its recall buys.
BTC_RE = re.compile(r"(?<![A-Za-z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Secrets: vendor-prefixed tokens whose prefix alone is near-unambiguous,
# plus the two structural forms (PEM blocks, JWTs). Typed CREDENTIAL.
SECRET_RES = [
    re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),          # AWS access key id
    re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"),       # GitHub tokens
    re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,255}(?![A-Za-z0-9])"),    # GitHub fine-grained
    re.compile(r"(?<![A-Za-z0-9_])xox[abposr]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])"),       # Slack
    re.compile(r"(?<![A-Za-z0-9_])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),             # Google API key
    re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])"),  # Stripe
    re.compile(r"(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),          # GitLab PAT
    re.compile(r"(?<![A-Za-z0-9_])sk-(?:proj-)?[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"),   # OpenAI-style
    re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"),  # JWT
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----"),      # PEM
]


def _iban_ok(cand):
    s = cand.replace(" ", "").upper()
    if IBAN_LENGTHS.get(s[:2]) != len(s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(num) % 97 == 1


def _aba_ok(digits):
    w = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    return sum(int(d) * k for d, k in zip(digits, w)) % 10 == 0


def _b58check_ok(addr):
    n = 0
    for ch in addr:
        idx = _B58.find(ch)
        if idx < 0:
            return False
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * (len(addr) - len(addr.lstrip("1"))) + raw  # leading '1' = 0x00
    if len(raw) != 25:
        return False
    body, check = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == check


def _find_secrets(text):
    for rx in SECRET_RES:
        for m in rx.finditer(text):
            yield Finding(m.group(0), "CREDENTIAL", m.start(), m.end())


def _find_ibans(text):
    for m in IBAN_RE.finditer(text):
        if _iban_ok(m.group(0)):
            yield Finding(m.group(0), "BANK_ACCOUNT", m.start(), m.end())


def _find_abas(text):
    for m in ABA_RE.finditer(text):
        if not _aba_ok(m.group(0)):
            continue
        if not ABA_CUE_RE.search(text[max(0, m.start() - 40):m.start()]):
            continue
        yield Finding(m.group(0), "BANK_ACCOUNT", m.start(), m.end())


def _find_btc(text):
    for m in BTC_RE.finditer(text):
        if _b58check_ok(m.group(0)):
            yield Finding(m.group(0), "BANK_ACCOUNT", m.start(), m.end())


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _find_emails(text):
    for m in EMAIL_RE.finditer(text):
        yield Finding(m.group(0), "EMAIL", m.start(), m.end())


def _find_macs(text):
    for m in MAC_RE.finditer(text):
        yield Finding(m.group(0), "MAC_ADDRESS", m.start(), m.end())


def _find_ips(text):
    for m in IPV4_RE.finditer(text):
        try:
            ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        yield Finding(m.group(0), "IP_ADDRESS", m.start(), m.end())
    for m in IPV6_RE.finditer(text):
        cand = m.group(0)
        try:
            ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        yield Finding(cand, "IP_ADDRESS", m.start(), m.end())


def _find_ssns(text):
    for m in SSN_RE.finditer(text):
        area = int(m.group(1))
        if area == 0 or area == 666 or area >= 900:
            continue
        yield Finding(m.group(0), "SSN", m.start(), m.end())


def _find_cards(text):
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            yield Finding(m.group(0), "CREDIT_CARD", m.start(), m.end())


def _find_phones(text):
    for m in PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if not 10 <= len(digits) <= 15:
            continue
        yield Finding(m.group(0), "PHONE", m.start(), m.end())


# Priority order: earlier detectors own their spans outright. Secrets go
# first (a PEM block or JWT contains digit runs that would otherwise be
# claimed piecemeal); IBAN before cards (an IBAN's digits can pass Luhn).
_DETECTORS = [
    _find_secrets, _find_emails, _find_macs, _find_ips, _find_ibans, _find_btc,
    _find_ssns, _find_cards, _find_abas, _find_phones,
]


def detect(text: str) -> List[Finding]:
    """All rule findings, non-overlapping, priority- then position-ordered."""
    candidates = []
    for prio, fn in enumerate(_DETECTORS):
        for f in fn(text):
            candidates.append((prio, -(f.end - f.start), f.start, f))
    accepted = []  # type: List[Finding]
    for _, _, _, f in sorted(candidates, key=lambda c: (c[0], c[1], c[2])):
        if all(f.end <= a.start or f.start >= a.end for a in accepted):
            accepted.append(f)
    return sorted(accepted, key=lambda f: f.start)
