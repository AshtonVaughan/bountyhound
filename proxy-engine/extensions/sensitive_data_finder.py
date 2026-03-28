"""Sensitive Data Finder — PII detection with SSN, credit card (Luhn), phone, email, DOB, passport, and more."""

from __future__ import annotations

import logging
import re
from typing import Any

from models import Flow, PassiveFinding

log = logging.getLogger("proxy-engine.ext.sensitive-data-finder")

NAME = "sensitive-data-finder"
DESCRIPTION = "PII detection: SSN, credit cards (Luhn), phone numbers, emails, DOB, passport, national ID, MRN, bank accounts"
CHECK_TYPE = "passive"
ENABLED = False

_config: dict[str, Any] = {
    "max_body_size": 200000,
}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _validate_ssn(ssn: str) -> bool:
    """Validate US SSN format (reject known invalid ranges)."""
    digits = re.sub(r"[-\s]", "", ssn)
    if len(digits) != 9:
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])
    if area == 0 or group == 0 or serial == 0:
        return False
    if area == 666 or area >= 900:
        return False
    if digits in ("123456789", "111111111", "222222222", "333333333", "999999999"):
        return False
    return True


def _validate_email(email: str) -> bool:
    """Basic email validation -- skip common non-PII addresses."""
    lower = email.lower()
    skip_domains = [
        "example.com", "test.com", "localhost", "sentry.io",
        "w3.org", "schema.org", "json-schema.org",
    ]
    for domain in skip_domains:
        if lower.endswith("@" + domain):
            return False
    if "noreply" in lower or "no-reply" in lower:
        return False
    return True


def _validate_tfn(tfn: str) -> bool:
    """Validate Australian TFN using checksum algorithm."""
    digits = [int(d) for d in re.sub(r"[-\s]", "", tfn) if d.isdigit()]
    if len(digits) != 9:
        return False
    weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    total = sum(d * w for d, w in zip(digits, weights))
    return total % 11 == 0


def _validate_iban(iban: str) -> bool:
    """Validate IBAN using mod-97 check."""
    iban_clean = iban.replace(" ", "").upper()
    if len(iban_clean) < 15 or len(iban_clean) > 34:
        return False
    rearranged = iban_clean[4:] + iban_clean[:4]
    numeric = ""
    for c in rearranged:
        if c.isdigit():
            numeric += c
        elif c.isalpha():
            numeric += str(ord(c) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except (ValueError, OverflowError):
        return False


# PII patterns: (check_id, name, pattern, severity, validator_func_or_None)
PII_PATTERNS: list[tuple[str, str, str, str, Any]] = [
    # SSN (US)
    ("ssn-us", "US Social Security Number (SSN)",
     r"(?<!\d)(\d{3}[-\s]?\d{2}[-\s]?\d{4})(?!\d)",
     "critical", lambda m: _validate_ssn(m)),

    # Credit Cards
    ("cc-visa", "Credit Card (Visa)",
     r"(?<!\d)(4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})(?!\d)",
     "critical", lambda m: _luhn_check(re.sub(r"[-\s]", "", m))),

    ("cc-mastercard", "Credit Card (Mastercard)",
     r"(?<!\d)(5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})(?!\d)",
     "critical", lambda m: _luhn_check(re.sub(r"[-\s]", "", m))),

    ("cc-amex", "Credit Card (American Express)",
     r"(?<!\d)(3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5})(?!\d)",
     "critical", lambda m: _luhn_check(re.sub(r"[-\s]", "", m))),

    ("cc-discover", "Credit Card (Discover)",
     r"(?<!\d)(6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})(?!\d)",
     "critical", lambda m: _luhn_check(re.sub(r"[-\s]", "", m))),

    ("cc-diners", "Credit Card (Diners Club)",
     r"(?<!\d)(3(?:0[0-5]|[68]\d)\d[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2})(?!\d)",
     "critical", lambda m: _luhn_check(re.sub(r"[-\s]", "", m))),

    ("cc-jcb", "Credit Card (JCB)",
     r"(?<!\d)(35(?:2[89]|[3-8]\d)\d[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})(?!\d)",
     "critical", lambda m: _luhn_check(re.sub(r"[-\s]", "", m))),

    # Phone Numbers
    ("phone-us", "US Phone Number",
     r"(?<!\d)(\+?1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})(?!\d)",
     "medium", None),

    ("phone-international", "International Phone Number",
     r"(?<!\d)(\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4})(?!\d)",
     "medium", None),

    ("phone-au", "Australian Phone Number",
     r"(?<!\d)(\+?61[-.\s]?\d[-.\s]?\d{4}[-.\s]?\d{4}|0[2-478][-.\s]?\d{4}[-.\s]?\d{4})(?!\d)",
     "medium", None),

    # Email Addresses
    ("email", "Email Address",
     r"(?i)\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b",
     "low", lambda m: _validate_email(m)),

    # Date of Birth
    ("dob-iso", "Date of Birth (ISO format)",
     r'(?i)(?:dob|date_of_birth|birth_?date|birthday)["\s:=]+["\']?(\d{4}[-/]\d{2}[-/]\d{2})["\']?',
     "high", None),

    ("dob-us", "Date of Birth (US format)",
     r'(?i)(?:dob|date_of_birth|birth_?date|birthday)["\s:=]+["\']?(\d{2}[-/]\d{2}[-/]\d{4})["\']?',
     "high", None),

    # Passport Numbers
    ("passport-us", "US Passport Number",
     r"(?i)(?:passport)[_\-\s]*(?:number|num|no|#)?[\s:=\"']+([A-Z]\d{8})",
     "critical", None),

    ("passport-uk", "UK Passport Number",
     r"(?i)(?:passport)[_\-\s]*(?:number|num|no|#)?[\s:=\"']+(\d{9})",
     "high", None),

    ("passport-generic", "Passport Number (Generic)",
     r"(?i)passport[_\-\s]*(?:number|num|no|#)?[\s:=\"']+([A-Z0-9]{6,12})",
     "high", None),

    # National ID formats
    ("nid-uk-nino", "UK National Insurance Number (NINO)",
     r"(?<![A-Z])([A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D])(?![A-Z])",
     "high", None),

    ("nid-au-tfn", "Australian Tax File Number (TFN)",
     r"(?<!\d)(\d{3}[-\s]?\d{3}[-\s]?\d{3})(?!\d)",
     "high", lambda m: _validate_tfn(m)),

    ("nid-ca-sin", "Canadian Social Insurance Number (SIN)",
     r"(?<!\d)(\d{3}[-\s]?\d{3}[-\s]?\d{3})(?!\d)",
     "high", lambda m: _luhn_check(re.sub(r"[-\s]", "", m)) and len(re.sub(r"[-\s]", "", m)) == 9),

    # Medical Record Numbers
    ("mrn", "Medical Record Number (MRN)",
     r'(?i)(?:mrn|medical_record|patient_id|health_id)[_\-\s]*(?:number|num|no|#)?[\s:="\']+([A-Z0-9]{6,15})',
     "critical", None),

    # Bank Accounts
    ("iban", "International Bank Account Number (IBAN)",
     r"(?<![A-Z])([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?)(?![A-Z0-9])",
     "critical", lambda m: _validate_iban(m)),

    ("bank-routing", "US Bank Routing Number (ABA)",
     r'(?i)(?:routing|aba)[_\-\s]*(?:number|num|no|#)?[\s:="\']+(\d{9})',
     "high", None),

    ("bsb-au", "Australian BSB Number",
     r'(?i)(?:bsb)[_\-\s]*(?:number|num|no|#)?[\s:="\']+(\d{3}[-\s]?\d{3})',
     "high", None),

    # Crypto wallet addresses
    ("crypto-btc", "Bitcoin Address",
     r"(?<![A-Za-z0-9])([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})(?![A-Za-z0-9])",
     "medium", None),

    ("crypto-eth", "Ethereum Address",
     r"(?<![A-Za-z0-9])(0x[a-fA-F0-9]{40})(?![A-Za-z0-9])",
     "medium", None),

    # Internal IP Addresses
    ("ip-internal", "Internal IP Address",
     r"(?<!\d)((?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})(?!\d)",
     "low", None),
]

# Pre-compiled patterns
_compiled: list[tuple[str, str, re.Pattern, str, Any]] = []


def _ensure_compiled() -> None:
    global _compiled
    if not _compiled:
        for check_id, name, pattern, severity, validator in PII_PATTERNS:
            try:
                _compiled.append((check_id, name, re.compile(pattern), severity, validator))
            except re.error as e:
                log.debug("Failed to compile PII pattern '%s': %s", check_id, e)


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Scan response body for PII and sensitive data patterns."""
    if not flow.response or not flow.response.body:
        return []

    ct = flow.response.headers.get("content-type", "")
    if any(t in ct for t in ["image/", "video/", "audio/", "font/", "application/octet-stream"]):
        return []

    _ensure_compiled()

    findings: list[PassiveFinding] = []
    max_size = _config.get("max_body_size", 200000)
    body = flow.response.body[:max_size]
    seen: set[str] = set()

    for check_id, name, pattern, severity, validator in _compiled:
        try:
            matches = pattern.findall(body)
            for match in matches:
                if isinstance(match, tuple):
                    match_str = match[0]
                else:
                    match_str = match

                if validator:
                    try:
                        if not validator(match_str):
                            continue
                    except Exception:
                        continue

                dedup_key = check_id + ":" + match_str
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                clean = re.sub(r"[-\s]", "", match_str)
                if len(clean) > 6:
                    masked = clean[:3] + "*" * (len(clean) - 5) + clean[-2:]
                elif len(clean) > 3:
                    masked = clean[:2] + "*" * (len(clean) - 2)
                else:
                    masked = match_str

                findings.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id="pii-" + check_id,
                    name="PII Exposure: " + name,
                    severity=severity,
                    description=(
                        "Detected " + name + " in HTTP response body. "
                        "Exposure of personally identifiable information may violate privacy "
                        "regulations (GDPR, CCPA, HIPAA)."
                    ),
                    evidence="Type: " + name + " | Value: " + masked,
                    url=flow.request.url,
                ))

        except Exception as e:
            log.debug("PII pattern error (%s): %s", check_id, e)

    return findings
