#!/usr/bin/env python3
"""
main.py

ALU Regex Data Extraction & Secure Validation Assignment

Pipeline:
  1. Read input/raw-text.txt (a messy, support-ticket-style export).
  2. Sanitize it -- strip control chars, quarantine any line that matches
     a known injection pattern (script tags, SQLi, template injection,
     JNDI, path traversal) before extraction even starts.
  3. Extract six data types with regex: emails (incl. 3 ALU categories),
     credit cards, phone numbers, URLs, hashtags, currency amounts.
  4. Validate what got extracted -- a regex only tells you something
     *looks* like a card number; Luhn tells you if it's actually valid.
     Rejected items are kept (with a reason), not silently dropped.
  5. Mask sensitive fields before writing anything to console or disk.
     Full card numbers / emails never show up in the output.

Run with:
    python3 src/main.py

Run from the project root so the relative input/output paths resolve.
See README.md for details and for pointing this at a different file.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 0. PATHS
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
INPUT_PATH = os.path.join(BASE_DIR, "input", "raw-text.txt")
OUTPUT_PATH = os.path.join(BASE_DIR, "output", "sample-output.json")


# ---------------------------------------------------------------------------
# 1. SECURITY: SANITIZATION & THREAT DETECTION
# ---------------------------------------------------------------------------
#
# Two separate jobs here:
#   a) strip control/escape characters that shouldn't be in a text export
#      (null bytes, ANSI escapes -- used to spoof terminal/log output)
#   b) flag and quarantine any *whole line* that matches a known attack
#      signature, rather than trying to "clean" the line and keep going.
#
# Quarantining the whole line matters: a payload like
#   <script>alert('xss')document.location='http://evil.example/steal'</script>
# contains a URL-shaped string. If we only stripped the <script> tags and
# kept scanning, the URL extractor downstream could still pick up
# "http://evil.example/steal" as if it were a legitimate link. Dropping the
# entire line avoids that.

ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')  # e.g. "\x1b[31m", "\x1b[0m"
CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')  # keeps \n and \t

# Not a full WAF -- just signatures for the common cases (XSS, SQLi,
# template injection, log4j-style JNDI lookups, path traversal).
THREAT_SIGNATURES = {
    "html_script_tag": re.compile(r'<\s*script\b', re.IGNORECASE),
    "html_event_handler": re.compile(r'\bon\w+\s*=\s*["\']', re.IGNORECASE),
    # Only treat "--" as a SQL comment when it follows a statement
    # terminator (';--', ');--'). A bare trailing "--" also matches plain
    # text dividers like "----------" in log/ticket exports, which would
    # flood the results with false positives if matched on its own.
    "sql_injection": re.compile(
        r"('\s*;\s*--|\)\s*;\s*--|\bDROP\s+TABLE\b|\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1\b)",
        re.IGNORECASE,
    ),
    "template_injection": re.compile(r'\{\{.*?\}\}|\$\{.*?\}'),
    "jndi_log4shell": re.compile(r'jndi:\s*(?:ldap|rmi|dns)', re.IGNORECASE),
    "path_traversal": re.compile(r'\.\./'),
}


def sanitize_text(raw_text: str) -> str:
    """Strip null bytes, ANSI escapes, and other control characters."""
    text = raw_text.replace("\x00", "")
    text = ANSI_ESCAPE_RE.sub("", text)
    text = CONTROL_CHARS_RE.sub("", text)
    return text


def redact_preview(line: str, max_len: int = 60) -> str:
    """Short, truncated preview of a flagged line for the audit log --
    we don't want the full (potentially hostile) payload sitting in a log file."""
    stripped = line.strip()
    if len(stripped) > max_len:
        return stripped[:max_len] + "...[truncated]"
    return stripped


def quarantine_hostile_lines(text: str):
    """
    Scan line-by-line for threat signatures.

    Returns:
        clean_text  -- input with any flagged line blanked out, safe to
                        run the extraction regexes against.
        flagged_log -- list of dicts describing what was found and where,
                        without storing the raw hostile payload in full.
    """
    clean_lines = []
    flagged_log = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        hits = [name for name, pattern in THREAT_SIGNATURES.items() if pattern.search(line)]
        if hits:
            flagged_log.append({
                "line_number": line_number,
                "threats_detected": hits,
                "line_preview_redacted": redact_preview(line),
                "action": "line_excluded_from_extraction",
            })
            clean_lines.append("")  # line dropped, never parsed
        else:
            clean_lines.append(line)

    return "\n".join(clean_lines), flagged_log


# ---------------------------------------------------------------------------
# 2. EXTRACTION REGEX PATTERNS
# ---------------------------------------------------------------------------

# --- 2.1 EMAIL ADDRESSES ---------------------------------------------------
# Local part and every domain label must start/end with an alphanumeric
# char. That one rule is what rejects the common malformed cases without
# needing a blocklist: "john@@doe.com" (doubled @), "bad..domain.com"
# (double dot), "@missinglocal.com" (no local part).
EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?'   # local part
    r'@'
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'  # one or more sub-domains
    r'[A-Za-z]{2,}\b'                                        # TLD
)

# ALU domains, checked most-specific-first in classify_alu_email() since
# alumni/si are themselves sub-domains of alueducation.com.
ALU_OFFICIAL_SUFFIX = "@alueducation.com"
ALU_ALUMNI_SUFFIX = "@alumni.alueducation.com"
ALU_SI_SUFFIX = "@si.alueducation.com"


def classify_alu_email(email: str) -> str:
    """Which ALU category (if any) a validated email belongs to."""
    lowered = email.lower()
    if lowered.endswith(ALU_ALUMNI_SUFFIX):
        return "alu_alumni"
    if lowered.endswith(ALU_SI_SUFFIX):
        return "alu_si"
    if lowered.endswith(ALU_OFFICIAL_SUFFIX):
        return "alu_official"
    return "general"


def mask_email(email: str) -> str:
    """Mask the local part for safe display, e.g.
    'aline.uwase@gmail.com' -> 'a**********e@gmail.com'."""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*" * (len(local) - 1)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


# --- 2.2 CREDIT CARD NUMBERS -----------------------------------------------
# Two-step approach: find candidates first (13-19 digits, optionally
# grouped with a space or dash -- how people actually type them), then run
# each candidate through Luhn + a network-prefix check. The regex is
# allowed to over-match here; validation is what filters out garbage.
CARD_CANDIDATE_RE = re.compile(r'\b(?:\d[ -]?){13,19}\b')

CARD_NETWORK_PATTERNS = {
    "Visa": re.compile(r'^4\d{12}(?:\d{3})?$'),
    "Mastercard": re.compile(r'^(?:5[1-5]\d{14}|2(?:2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$'),
    "American Express": re.compile(r'^3[47]\d{13}$'),
    "Discover": re.compile(r'^6(?:011|5\d{2})\d{12}$'),
}


def luhn_is_valid(digits: str) -> bool:
    """Standard Luhn checksum used by all major card networks."""
    total = 0
    reversed_digits = digits[::-1]
    for i, ch in enumerate(reversed_digits):
        d = int(ch)
        if i % 2 == 1:  # every 2nd digit from the right is doubled
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_card_network(digits: str) -> str:
    for network, pattern in CARD_NETWORK_PATTERNS.items():
        if pattern.match(digits):
            return network
    return "Unknown"


def mask_card(digits: str) -> str:
    """Only show the last 4 digits, like a receipt (**** **** **** 4444)."""
    return "*" * (len(digits) - 4) + digits[-4:]


# --- 2.3 PHONE NUMBERS ------------------------------------------------------
# Two shapes: grouped/separated numbers ("+250 788 123 456") and
# unspaced digit runs ("0792887129" -- common when a number comes straight
# out of a database field with no formatting). Validation checks the total
# digit count falls in a realistic range (7-15, roughly E.164), which is
# what rejects both "12345" (too short) and "000-000-0000000000000"
# (way too long to be a real number).
PHONE_CANDIDATE_RE = re.compile(
    r'(?<!\d)'
    r'(?:'
        # Shape A: grouped/separated. The final digit group allows up to 7
        # digits, not just 4, because the trailing "local number" segment
        # isn't always split into neat chunks -- e.g. "...712 345678" ends
        # in an ungrouped 6-digit block.
        r'(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?(?:\d{2,4}[\s.-]){1,4}\d{2,7}'
        r'|'
        # Shape B: no separators at all.
        r'\+?\d{9,15}'
    r')'
    r'(?:\s?(?:ext\.?|x)\.?\s?\d{1,5})?'  # optional extension
    r'(?!\d)'
)


def digits_only(s: str) -> str:
    return re.sub(r'\D', '', s)


def validate_phone(candidate: str):
    """Returns (is_valid, cleaned_digit_count)."""
    # Drop any extension segment before counting -- an extension is a
    # separate internal routing number, not part of the phone number.
    main_part = re.split(r'(?:ext\.?|x)\.?\s?\d{1,5}$', candidate, flags=re.IGNORECASE)[0]
    n_digits = len(digits_only(main_part))
    return (7 <= n_digits <= 15), n_digits


# --- 2.4 URLs ----------------------------------------------------------------
# Only http/https links with an explicit scheme count as "verified".
# Trailing sentence punctuation ("...see https://x.com/a.") gets trimmed off.
URL_RE = re.compile(r'\bhttps?://[^\s<>"\'\)\]]+')

# Links typed without a scheme, e.g. "www.site.com". Reported separately as
# unverified -- we can't confirm the intended protocol, and dropping the
# scheme is also a common phishing trick to look more "casual".
INFORMAL_URL_RE = re.compile(r'\bwww\.[A-Za-z0-9-]+\.[A-Za-z]{2,}(?:/[^\s<>"\'\)\]]*)?')


def trim_trailing_punctuation(url: str) -> str:
    return url.rstrip('.,;:!?')


# --- 2.5 HASHTAGS -------------------------------------------------------------
# Real hashtags can start with a digit ("#250Tech"), so we can't just
# require a leading letter. Instead: no space between '#' and the tag, and
# at least one letter somewhere in it -- that second rule is what keeps a
# plain ticket reference like "#10231" (all digits) from being read as a
# hashtag while still allowing "#250Tech".
HASHTAG_RE = re.compile(r'(?<!\w)#(\d*[A-Za-z][A-Za-z0-9_]{0,49})\b')


# --- 2.6 CURRENCY AMOUNTS -----------------------------------------------------
# Three shapes: symbol-first ($1,250.00), code-first (RWF 45,000), and
# amount-first-with-suffix-code (1250 USD).
CURRENCY_CODES = r'USD|RWF|KES|EUR|GBP|JPY'
# `\d+` rather than `\d{1,3}` for the leading chunk -- a plain ungrouped
# number like "1250" should match just as well as "1,250". Requiring the
# comma grouping from the start would miss the ungrouped case entirely.
AMOUNT_RE = r'\d+(?:,\d{3})*(?:\.\d{1,2})?'
CURRENCY_RE = re.compile(
    r'(?:[$€¥£]\s?' + AMOUNT_RE + r'(?:\s?(?:' + CURRENCY_CODES + r'))?)'   # $1,250.00 / $12,000.00 USD
    r'|(?:\b(?:' + CURRENCY_CODES + r')\s?' + AMOUNT_RE + r')'              # RWF 45,000
    r'|(?:' + AMOUNT_RE + r'\s?(?:' + CURRENCY_CODES + r')\b)'              # 1250 USD
)


# ---------------------------------------------------------------------------
# 3. EXTRACTION + VALIDATION
# ---------------------------------------------------------------------------

def extract_emails(text: str) -> dict:
    result = {"alu_official": [], "alu_alumni": [], "alu_si": [], "general": []}
    seen = set()
    for match in EMAIL_RE.finditer(text):
        email = match.group(0)
        if email.lower() in seen:
            continue
        seen.add(email.lower())
        category = classify_alu_email(email)
        result[category].append({
            "masked": mask_email(email),
            "domain": email.split("@", 1)[1],
        })
    return result


def extract_credit_cards(text: str) -> dict:
    valid, rejected = [], []
    seen = set()
    for match in CARD_CANDIDATE_RE.finditer(text):
        raw_candidate = match.group(0)
        digits = digits_only(raw_candidate)
        if digits in seen:
            continue
        seen.add(digits)

        if len(digits) < 13 or len(digits) > 19:
            rejected.append({"masked": mask_card(digits) if len(digits) >= 4 else "N/A",
                              "reason": "invalid_length"})
            continue

        network = detect_card_network(digits)
        passes_luhn = luhn_is_valid(digits)

        if passes_luhn and network != "Unknown":
            valid.append({
                "masked": mask_card(digits),
                "network": network,
                "luhn_check": "passed",
            })
        else:
            reason = []
            if not passes_luhn:
                reason.append("failed_luhn_checksum")
            if network == "Unknown":
                reason.append("unrecognized_network_prefix")
            rejected.append({
                "masked": mask_card(digits),
                "reason": ", ".join(reason),
            })
    return {"valid": valid, "rejected": rejected}


# A plain ISO date ("2026-09-01"), or a date glued to a time fragment
# ("2026-09-01 09"), looks like a phone number if you only check
# digit-grouping. Exclude anything starting with YYYY-MM-DD.
ISO_DATE_PREFIX_RE = re.compile(r'^\d{4}-\d{2}-\d{2}')


def extract_phone_numbers(text: str) -> dict:
    # A digit run that's already part of a credit card or a URL (e.g. the
    # "192.168.1.42" in an IP-based URL) should never also get reported as
    # a phone number, even if the fragment alone looks phone-shaped. Build
    # the exclusion spans up front and skip anything that overlaps them.
    card_spans = [m.span() for m in CARD_CANDIDATE_RE.finditer(text)]
    url_spans = [m.span() for m in URL_RE.finditer(text)] + [m.span() for m in INFORMAL_URL_RE.finditer(text)]
    excluded_spans = card_spans + url_spans

    def overlaps_excluded(span):
        return any(span[0] < e_end and span[1] > e_start for e_start, e_end in excluded_spans)

    valid, rejected = [], []
    seen = set()
    for match in PHONE_CANDIDATE_RE.finditer(text):
        candidate = match.group(0).strip()

        if overlaps_excluded(match.span()):
            continue
        if ISO_DATE_PREFIX_RE.match(candidate):
            continue

        norm = digits_only(candidate)
        if not norm or norm in seen:
            continue
        if len(norm) < 6:  # too short to be anything but noise (dates, ticket ids)
            continue
        seen.add(norm)
        is_valid, n_digits = validate_phone(candidate)
        if is_valid:
            valid.append({"formatted": candidate, "digit_count": n_digits})
        else:
            rejected.append({"raw": candidate, "digit_count": n_digits, "reason": "digit_count_out_of_range"})
    return {"valid": valid, "rejected": rejected}


def extract_urls(text: str) -> dict:
    https_urls, http_urls, informal_urls = [], [], []
    seen = set()
    for match in URL_RE.finditer(text):
        url = trim_trailing_punctuation(match.group(0))
        if url in seen:
            continue
        seen.add(url)
        (https_urls if url.lower().startswith("https://") else http_urls).append(url)

    for match in INFORMAL_URL_RE.finditer(text):
        url = trim_trailing_punctuation(match.group(0))
        if url in seen:
            continue
        seen.add(url)
        informal_urls.append(url)

    return {
        "https_secure": https_urls,
        "http_insecure": http_urls,
        "informal_no_scheme_unverified": informal_urls,
    }


def extract_hashtags(text: str) -> list:
    seen, out = set(), []
    for match in HASHTAG_RE.finditer(text):
        tag = "#" + match.group(1)
        if tag.lower() not in seen:
            seen.add(tag.lower())
            out.append(tag)
    return out


def extract_currency(text: str) -> list:
    seen, out = set(), []
    for match in CURRENCY_RE.finditer(text):
        amount = match.group(0).strip()
        if amount not in seen:
            seen.add(amount)
            out.append(amount)
    return out


# ---------------------------------------------------------------------------
# 4. MAIN
# ---------------------------------------------------------------------------

def run(input_path: str = INPUT_PATH, output_path: str = OUTPUT_PATH) -> dict:
    if not os.path.exists(input_path):
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    sanitized_text = sanitize_text(raw_text)
    clean_text, security_log = quarantine_hostile_lines(sanitized_text)

    results = {
        "meta": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_file": os.path.relpath(input_path, BASE_DIR),
            "note": "Sensitive values (emails, card numbers) are masked. "
                    "Lines flagged as hostile were excluded from extraction.",
        },
        "security": {
            "flagged_lines_count": len(security_log),
            "flagged_lines": security_log,
        },
        "extracted_data": {
            "emails": extract_emails(clean_text),
            "credit_cards": extract_credit_cards(clean_text),
            "phone_numbers": extract_phone_numbers(clean_text),
            "urls": extract_urls(clean_text),
            "hashtags": extract_hashtags(clean_text),
            "currency_amounts": extract_currency(clean_text),
        },
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print_console_summary(results)
    print(f"\nFull JSON report written to: {os.path.relpath(output_path, BASE_DIR)}")
    return results


def print_console_summary(results: dict) -> None:
    sec = results["security"]
    data = results["extracted_data"]
    emails = data["emails"]
    cards = data["credit_cards"]
    phones = data["phone_numbers"]
    urls = data["urls"]

    print("=" * 65)
    print("ALU REGEX DATA EXTRACTION — SUMMARY")
    print("=" * 65)
    print(f"Security: {sec['flagged_lines_count']} line(s) quarantined as hostile/unsafe")
    print("-" * 65)
    print(f"Emails — ALU official : {len(emails['alu_official'])}")
    print(f"Emails — ALU alumni   : {len(emails['alu_alumni'])}")
    print(f"Emails — ALU SI       : {len(emails['alu_si'])}")
    print(f"Emails — general      : {len(emails['general'])}")
    print(f"Credit cards — valid   : {len(cards['valid'])}")
    print(f"Credit cards — rejected: {len(cards['rejected'])}")
    print(f"Phone numbers — valid   : {len(phones['valid'])}")
    print(f"Phone numbers — rejected: {len(phones['rejected'])}")
    print(f"URLs — https (secure)         : {len(urls['https_secure'])}")
    print(f"URLs — http (insecure)        : {len(urls['http_insecure'])}")
    print(f"URLs — informal / no scheme   : {len(urls['informal_no_scheme_unverified'])}")
    print(f"Hashtags found         : {len(data['hashtags'])}")
    print(f"Currency amounts found : {len(data['currency_amounts'])}")
    print("=" * 65)


if __name__ == "__main__":
    run()
