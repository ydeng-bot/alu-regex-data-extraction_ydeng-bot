# ALU Regex Data Extraction & Secure Validation

A regex-based tool for pulling structured data (emails, credit cards, phone
numbers, URLs, hashtags, currency amounts) out of messy, real-world-style
text, while treating that text as untrusted input than assuming it's
safe.



## Project Structure

```
alu-regex-data-extraction_ydeng-bot/
├── input/
│   └── raw-text.txt        # sample input: a messy support-ticket export
├── src/
│   └── main.py              # extraction, validation, and security logic
├── tests/
│   └── test_main.py         # unit test suite (57 tests)
├── output/
│   └── sample-output.json   # generated report from the sample input
└── README.md
```


## What It Does

1. Reads `input/raw-text.txt` — a simulated support-ticket export with a
   mix of emails, phone numbers, card numbers, URLs, hashtags, currency
   amounts, dates, and a handful of hostile/malformed lines mixed in for
   testing.
2. Sanitizes the text: strips null bytes, ANSI/terminal escape codes, and
   other control characters.
3. Quarantines any line that matches a known attack signature (`<script>`
   tags, SQL injection markers, `{{ }}` / `${ }` template injection,
   Log4Shell-style `jndi:` payloads, path traversal). Quarantined lines
   are dropped entirely before extraction runs, and only a short,
   truncated preview goes into the security log — never the full payload.
4. Extracts six data types with regex (details below).
5. Validates what it finds. A regex can tell you something *looks* like a
   credit card or phone number; a Luhn checksum or digit-count check tells
   you whether it actually is one. Anything that fails validation is
   reported as `"rejected"` with a reason, not just dropped.
6. Masks sensitive values before writing anything out. Full email
   addresses and full credit card numbers never hit the console or the
   JSON file — only masked versions (e.g. `a*********e@gmail.com`,
   `************6467`).
7. Writes `output/sample-output.json` and prints a console summary.

## Data Types Extracted

| # | Data type | Notes |
|---|-----------|-------|
| 1 | Email addresses (general) | Rejects double dots, missing local part, doubled `@`, etc. |
| 2 | ALU-specific emails | Classified as `alu_official` (`@alueducation.com`), `alu_alumni` (`@alumni.alueducation.com`), or `alu_si` (`@si.alueducation.com`) |
| 3 | Credit card numbers | Candidate regex + Luhn checksum + network-prefix detection (Visa/Mastercard/Amex/Discover) |
| 4 | Phone numbers | Local + international formats, extension support, validated by digit count (7–15) |
| 5 | URLs | Split into `https_secure`, `http_insecure`, and `informal_no_scheme_unverified` (bare `www.` links) |
| 6 | Hashtags | Requires at least one letter, so ticket IDs like `#10231` don't get mistaken for tags |
| 7 | Currency amounts | Symbol-based (`$`, `€`, `¥`, `£`) and code-based (`USD`, `RWF`, `KES`, `EUR`, `GBP`, `JPY`) |

The brief asked for a minimum of two types plus emails and credit cards
specifically. This implements six, covering both required types.

## How the Regex Patterns Work

Full comments are in `src/main.py`; short version here.

**Emails** match `local@domain.tld`, where both the local part and every
domain label have to start and end with an alphanumeric character. That
one rule handles most of the malformed cases without needing a blocklist:
consecutive dots, a missing local part, a doubled `@`.

**ALU classification** happens after an email has already passed general
validation. It just checks the domain suffix, most specific first (alumni
→ si → official), so a sub-domain like `si.alueducation.com` doesn't get
counted as a plain `alueducation.com` account.

**Credit cards** go through two steps: a broad regex finds any 13–19 digit
run (grouped with spaces or dashes, the way people actually type them),
then each candidate gets checked against the Luhn algorithm and matched
against known network prefixes. Only candidates that pass both end up in
`"valid"`; anything else lands in `"rejected"` with a reason attached.

**Phone numbers** use the same two-step idea: a permissive regex finds
grouped-digit candidates, then a digit-count check (7–15) filters out
obvious junk like `12345` or a 19-digit string. Candidates that overlap a
credit-card match, or that are plain ISO dates like `2026-09-01`, get
excluded so dates and card numbers don't turn into false phone numbers.

**URLs** need an explicit `http://` or `https://` scheme to count as
secure/insecure. A bare `www.` link with no scheme gets reported
separately as unverified — dropping the scheme is also a common trick in
phishing links.

**Hashtags** need no whitespace between `#` and the tag, and at least one
letter somewhere in it. That second rule is what keeps a reference number
like `#10231` from being read as a hashtag while still allowing something
like `#250Tech`.

**Currency amounts** match symbol-first (`$1,250.00`), code-first
(`RWF 45,000`), or amount-first-with-code (`1250 USD`), with optional
thousands separators and up to two decimal places.

## Security Considerations

See `src/main.py` section 1 for the implementation.

- The raw text is never trusted. Sanitization and threat-signature
  quarantine both run before any extraction regex touches the text.
- Quarantine works at the line level, not by trying to strip out just the
  "bad part" of a line. Partial sanitization that's later trusted is how a
  lot of real injection bugs happen. A URL embedded inside an XSS payload
  (`document.location='http://evil.example/steal'`) never reaches the URL
  extractor, because the whole line it's on gets dropped first.
- Nothing here executes extracted content. No `eval()`, no template
  rendering, no shell interpolation — so something like `{{7*7}}` or
  `${jndi:ldap://...}` can't actually run even if it slipped through. The
  quarantine step is on top of that, not instead of it.
- Sensitive data is masked before it's written anywhere. Full card numbers
  and full emails never show up in the console output or the JSON report.
  Real systems get fined for logging that stuff in plaintext (PCI-DSS,
  GDPR), so this follows the same rule even though it's just an
  assignment.
- Rejected items are reported, not silently dropped. A card that fails
  Luhn, a phone number with an unrealistic digit count — both show up in
  the output with a reason, so it's clear the bad data was caught rather
  than missed.
- What this doesn't do: it's not a WAF, and it's not an email
  deliverability or SMTP checker. It won't catch obfuscated or encoded
  injection attempts, and it doesn't verify a domain exists or a card is
  actually issued. That's outside what a regex-based tool can reasonably
  do.

## Known Edge Case: `4242-4242-4242`

The sample input includes `4242-4242-4242` (12 digits) as a deliberately
truncated card number. It's too short for the credit-card candidate regex
(13–19 digits required), so it falls through to the phone extractor and
comes back as a valid-looking 12-digit phone number instead of a rejected
card. That's called out here on purpose — a bare digit sequence like this
genuinely can't be told apart from a phone number without more context
than the regex has access to.

## Bugs Found & Fixed During Development

These came up by feeding the extractors harder, more realistic input and
checking whether they still worked. All four were fixed, not left as
known limitations:

- **Unspaced phone numbers** (`0792887129`) were missed completely — the
  original regex required a separator between digit groups. Fixed by
  adding a second "no separators" shape to the phone pattern.
- **Phone numbers with a one-digit trunk code** (`+254 (0) 712 345678`)
  were missed because the parens group only allowed 2–4 digits. Widened it
  to 1–4, and also widened the final digit group to allow up to 7 digits
  since real numbers don't always split neatly.
- **Digit fragments inside URLs** (`192.168` from an IP-based URL) were
  showing up as false rejected phone numbers. Fixed by excluding any phone
  candidate that overlaps a matched URL span, same idea as the existing
  card-number exclusion.
- **Currency amounts with no thousands separator** (`1250 USD`) were
  missed because the amount pattern assumed grouping started in blocks of
  3 digits. Loosened the leading digit group and added a third
  amount-then-code alternative to the currency regex.

Also checked and confirmed correct by design: `Ksh 2,500` is ignored
(unsupported currency code), `mailto:support@alueducation.com` isn't
treated as a web URL (though the email inside it still gets picked up),
and `#step-3` in a URL isn't read as a hashtag since it's glued directly
onto "setup" with nothing separating it.

## Test Suite

`tests/test_main.py` has 57 `unittest` tests covering the extractors, the
validators, and the security rules, including one regression test per bug
listed above so a future change can't quietly bring one back. There's also
an end-to-end test that runs `run()` against a temp file and checks the
resulting JSON never contains a full email or card number.

```bash
python3 -m unittest discover -s tests -v
```

or:

```bash
python3 tests/test_main.py
```

All 57 currently pass.

## How to Run

Requires Python 3.8+, standard library only.

```bash
cd alu-regex-data-extraction_ydeng-bot
python3 src/main.py
```

This reads `input/raw-text.txt`, prints a summary, and writes the full
report to `output/sample-output.json`.

### Using your own input file

Replace `input/raw-text.txt`, or call the function directly:

```python
from src.main import run
run(input_path="input/my-other-file.txt", output_path="output/my-report.json")
```

## Sample Output

`output/sample-output.json` is a full example report generated from
`input/raw-text.txt`, including the security log and the masked,
categorized results for every data type.
