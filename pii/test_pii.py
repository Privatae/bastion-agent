"""Unit + wire tests for the PII sterilization service.

Everything here is model-free: the LLM pass is either a fake callable
(pipeline tests) or a stub llama.cpp speaking the real chat-completions
wire format on loopback (service tests). Live recall quality against a
real model is verify-live.sh's job, against a running service.
"""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import detect, pipeline, service
from .vault import Vault


class DetectTests(unittest.TestCase):
    def find(self, text):
        return {(f.value, f.type) for f in detect.detect(text)}

    def test_email(self):
        self.assertIn(("sam.r@example.co.uk", "EMAIL"),
                      self.find("mail sam.r@example.co.uk today"))

    def test_phone_forms(self):
        for s in ["+1 415 555 0173", "(415) 555-0173", "415-555-0173", "415.555.0173"]:
            self.assertIn((s, "PHONE"), self.find(f"call {s} now"), s)

    def test_date_is_not_phone(self):
        self.assertEqual(self.find("released 2026-08-03 at noon"), set())

    def test_ssn_valid_and_invalid_area(self):
        self.assertIn(("123-45-6789", "SSN"), self.find("ssn 123-45-6789"))
        self.assertEqual(self.find("ssn 666-45-6789"), set())
        self.assertEqual(self.find("ssn 000-45-6789"), set())

    def test_credit_card_luhn(self):
        self.assertIn(("4111 1111 1111 1111", "CREDIT_CARD"),
                      self.find("card 4111 1111 1111 1111 exp 12/28"))
        # same shape, fails Luhn
        self.assertEqual(self.find("ref 4111 1111 1111 1112"), set())

    def test_ipv4_owns_dotted_span(self):
        found = self.find("host at 198.51.100.54 responded")
        self.assertIn(("198.51.100.54", "IP_ADDRESS"), found)
        self.assertNotIn(("198.51.100.54", "PHONE"), found)

    def test_ipv4_invalid_octet(self):
        self.assertNotIn(("999.51.100.541", "IP_ADDRESS"), self.find("x 999.51.100.541"))

    def test_ipv6_and_mac_disambiguation(self):
        found = self.find("fe80::1ff:fe23:4567:890a from aa:bb:cc:dd:ee:ff")
        self.assertIn(("fe80::1ff:fe23:4567:890a", "IP_ADDRESS"), found)
        self.assertIn(("aa:bb:cc:dd:ee:ff", "MAC_ADDRESS"), found)

    def test_sentence_ending_full_stop(self):
        self.assertIn(("415-555-0173", "PHONE"), self.find("Call me at 415-555-0173."))
        self.assertIn(("415.555.0173", "PHONE"), self.find("Call me at 415.555.0173."))
        self.assertIn(("10.1.2.3", "IP_ADDRESS"), self.find("the gateway was 10.1.2.3."))
        self.assertIn(("aa:bb:cc:dd:ee:ff", "MAC_ADDRESS"), self.find("from aa:bb:cc:dd:ee:ff."))

    def test_full_stop_inside_a_longer_number_still_refuses(self):
        self.assertEqual(self.find("version 10.1.2.3.4 shipped"), set())
        self.assertNotIn("PHONE", {t for _, t in self.find("ref 415-555-0173.5 end")})
        self.assertNotIn("PHONE", {t for _, t in self.find("file 415-555-0173.pdf")})

    def test_full_stop_rule_is_the_same_for_ip_phone_and_mac(self):
        # a full stop followed by a letter or digit is part of something longer
        self.assertEqual(self.find("open 10.1.2.3.txt now"), set())
        self.assertIn(("10.1.2.3", "IP_ADDRESS"), self.find("the host was 10.1.2.3."))
        self.assertEqual(self.find("saved aa:bb:cc:dd:ee:ff.bak"), set())
        self.assertEqual(self.find("saved aa:bb:cc:dd:ee:ff.txt"), set())
        self.assertIn(("aa:bb:cc:dd:ee:ff", "MAC_ADDRESS"), self.find("it was aa:bb:cc:dd:ee:ff."))

    # ── v1.2 checksum-anchored recognizers ──────────────────────────────
    def test_iban_mod97(self):
        for iban in ("GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"):
            self.assertIn((iban, "BANK_ACCOUNT"), self.find("pay to %s thanks" % iban), iban)
        for bad in ("GB82 WEST 1234 5698 7654 33",   # bad check digits
                    "ZZ82 WEST 1234 5698 7654 32"):  # unknown country
            self.assertNotIn("BANK_ACCOUNT", {t for _, t in self.find("pay to " + bad)}, bad)

    def test_iban_not_reclaimed_as_card(self):
        found = self.find("iban DE89370400440532013000")
        self.assertNotIn(("370400440532013000", "CREDIT_CARD"), found)
        self.assertEqual({t for _, t in found}, {"BANK_ACCOUNT"})

    def test_aba_needs_checksum_and_cue(self):
        self.assertIn(("021000021", "BANK_ACCOUNT"), self.find("routing number 021000021"))
        self.assertIn(("021000021", "BANK_ACCOUNT"), self.find("ABA: 021000021"))
        self.assertEqual(self.find("order 021000021 shipped"), set())      # no cue
        self.assertEqual(self.find("routing number 021000022"), set())     # bad checksum

    def test_bitcoin_base58check(self):
        good = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        self.assertIn((good, "BANK_ACCOUNT"), self.find("send to %s" % good))
        self.assertIn(("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BANK_ACCOUNT"),
                      self.find("genesis 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        self.assertEqual(self.find("send to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"), set())

    def test_secrets_are_credentials(self):
        cases = {
            "AKIAIOSFODNN7EXAMPLE": "aws key AKIAIOSFODNN7EXAMPLE",
            "ghp_" + "a" * 36: "token ghp_" + "a" * 36 + " end",
            "xoxb-1234567890-abcdefghij": "slack xoxb-1234567890-abcdefghij",
            "AIza" + "b" * 35: "gkey AIza" + "b" * 35,
            "sk_live_" + "c" * 24: "stripe sk_live_" + "c" * 24,
            "glpat-" + "d" * 20: "gl glpat-" + "d" * 20,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U":
                "bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        }
        for value, text in cases.items():
            self.assertIn((value, "CREDENTIAL"), self.find(text), value)

    def test_pem_block_is_one_credential(self):
        pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIF12 3456 7890 1234\n-----END EC PRIVATE KEY-----"
        found = self.find("key:\n" + pem + "\nok")
        self.assertEqual(found, {(pem, "CREDENTIAL")})

    def test_secrets_do_not_fire_on_prose(self):
        self.assertEqual(self.find("the skate park (AKA the bowl) opens at 9"), set())


class RulesOnlyFormatTests(unittest.TestCase):
    """The rules pass is all that flag mode runs, so each format here must be
    found with no recall model at all, and each lookalike must be left alone."""

    FOUND = [
        ("UK mobile, international", "Mobile: +44 7700 900123", "+44 7700 900123", "PHONE"),
        ("German, (0) trunk prefix", "Tel. +49 (0)30 1234567", "+49 (0)30 1234567", "PHONE"),
        ("international, no separators", "ring +442079460958 today", "+442079460958", "PHONE"),
        ("international, dots", "fax +33.6.39.98.12.34 now", "+33.6.39.98.12.34", "PHONE"),
        ("international, dashes", "cell +44-20-7946-0958.", "+44-20-7946-0958", "PHONE"),
        ("UK national, trunk 0", "call 07700 900123 later", "07700 900123", "PHONE"),
        ("German national, trunk 0", "Tel 030 1234567", "030 1234567", "PHONE"),
        ("German national, (0xx)", "Tel (030) 1234567", "(030) 1234567", "PHONE"),
        ("7-digit local after a phone word", "Ring 555-0142 for the gate code.", "555-0142", "PHONE"),
        ("7-digit local, call", "call me on 555 0199", "555 0199", "PHONE"),
        ("IBAN lowercase", "iban: gb82west12345698765432", "gb82west12345698765432", "BANK_ACCOUNT"),
        ("IBAN lowercase, spaced", "pay de89 3704 0044 0532 0130 00 now",
         "de89 3704 0044 0532 0130 00", "BANK_ACCOUNT"),
        ("IBAN followed by a four-letter word", "to BE68 5390 0754 7034 then",
         "BE68 5390 0754 7034", "BANK_ACCOUNT"),
        ("card with dots", "Card 4111.1111.1111.1111", "4111.1111.1111.1111", "CREDIT_CARD"),
        ("card with dashes", "card 5555-5555-5555-4444 ok", "5555-5555-5555-4444", "CREDIT_CARD"),
        ("card after no.", "card no.4111 1111 1111 1111", "4111 1111 1111 1111", "CREDIT_CARD"),
        ("card, 4-6-5 grouping", "amex 3782 822463 10005", "3782 822463 10005", "CREDIT_CARD"),
        ("SSN with spaces", "SSN 219 09 9999", "219 09 9999", "SSN"),
        ("SSN, no separators, keyword", "Social security number 219099999.", "219099999", "SSN"),
        ("SSN, no separators, SSN:", "ssn: 219099999", "219099999", "SSN"),
    ]

    LEFT_ALONE = [
        ("order number", "Order 555-0142 shipped"),
        ("order number, digits only", "order #20431877 is packed"),
        ("9-digit invoice id", "invoice 219099999 is due"),
        ("16 digits failing Luhn, spaces", "ref 4111 1111 1111 1112"),
        ("16 digits failing Luhn, dots", "ref 4111.1111.1111.1112"),
        ("IBAN shape, bad checksum, lowercase", "iban gb82west12345698765433"),
        ("IBAN shape, bad checksum, uppercase", "iban GB82WEST12345698765433 ok"),
        ("version string", "version 1.2.3.4 shipped"),
        ("version string, v", "upgrade to v1.2.3.4 today"),
        ("ISO date", "released 2026-08-03 at noon"),
        ("US date", "Date of birth: 03/14/1987"),
        ("dotted date", "seen on 14.03.1987 in the hall"),
        ("SSN shape, group 00", "ssn 219-00-9999"),
        ("short number after +", "add +12 345 to it"),
        ("spaced digits inside a longer run", "lot 4 219 09 9999 7"),
    ]

    def find(self, text):
        return {(f.value, f.type) for f in detect.detect(text)}

    def test_each_format_is_found(self):
        for label, text, value, typ in self.FOUND:
            with self.subTest(label):
                self.assertIn((value, typ), self.find(text))

    def test_lookalikes_are_left_alone(self):
        for label, text in self.LEFT_ALONE:
            with self.subTest(label):
                self.assertEqual(self.find(text), set())

    def test_rules_only_sterilize_leaves_no_value(self):
        # what flag mode does: the pipeline with no recall model
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(os.path.join(tmp, "v.db"))
            for label, text, value, _ in self.FOUND:
                with self.subTest(label):
                    out, _ = pipeline.sterilize(text, "s", vault, lambda t: [],
                                                escape_held_literals=True)
                    self.assertNotIn(value, out)
                    self.assertEqual(pipeline.rehydrate(out, "s", vault)[0], text)
            for label, text in self.LEFT_ALONE:
                with self.subTest(label):
                    out, _ = pipeline.sterilize(text, "s", vault, lambda t: [],
                                                escape_held_literals=True)
                    self.assertEqual(out, text)

    def test_ip_address_is_still_found_after_other_words(self):
        self.assertIn(("203.0.113.42", "IP_ADDRESS"), self.find("Server at 203.0.113.42 refused."))
        self.assertIn(("203.0.113.42", "IP_ADDRESS"), self.find("server 203.0.113.42 version 2"))


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = Vault(os.path.join(self.tmp.name, "v.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_stable_token_same_scope(self):
        t1 = self.vault.token_for("s1", "EMAIL", "a@b.com")
        t2 = self.vault.token_for("s1", "EMAIL", "a@b.com")
        self.assertEqual(t1, t2)
        self.assertEqual(t1, "[PII_EMAIL_1]")

    def test_scopes_isolated(self):
        self.vault.token_for("s1", "EMAIL", "a@b.com")
        self.vault.token_for("s1", "EMAIL", "c@d.com")
        t_other = self.vault.token_for("s2", "EMAIL", "c@d.com")
        self.assertEqual(t_other, "[PII_EMAIL_1]")  # own sequence
        self.assertIsNone(self.vault.value_for("s2", "[PII_EMAIL_2]"))

    def test_inventory_has_no_values(self):
        self.vault.token_for("s1", "PERSON", "Ada Lovelace")
        inv = json.dumps(self.vault.scope_tokens("s1"))
        self.assertNotIn("Ada", inv)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = Vault(os.path.join(self.tmp.name, "v.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_grounding_drops_hallucinated_span(self):
        text = "call me at 415-555-0173"
        fake = lambda t: [("415-555-0173", "PHONE"), ("Bob Jones", "PERSON")]
        out, res = pipeline.sterilize(text, "s", self.vault, fake)
        self.assertEqual(res["stats"]["llm_ungrounded"], 1)
        self.assertNotIn("Bob", out)
        self.assertNotIn("415-555-0173", out)

    def test_longest_value_wins(self):
        text = "John Smith emailed. John was brief."
        fake = lambda t: [("John Smith", "PERSON"), ("John", "PERSON")]
        out, _ = pipeline.sterilize(text, "s", self.vault, fake)
        self.assertEqual(out, "[PII_PERSON_1] emailed. [PII_PERSON_2] was brief.")

    def test_non_pii_bytes_identical(self):
        text = "The nftables ruleset,  with   odd spacing\tand café unicode, is fine."
        out, res = pipeline.sterilize(text, "s", self.vault, lambda t: [])
        self.assertEqual(out, text)
        self.assertEqual(res["findings"], [])

    def test_rules_catch_what_llm_missed(self):
        text = "ssn is 123-45-6789 ok"
        out, res = pipeline.sterilize(text, "s", self.vault, lambda t: [])
        self.assertEqual(out, "ssn is [PII_SSN_1] ok")
        self.assertEqual(res["stats"]["rules"], 1)

    def test_round_trip(self):
        text = "Sam Rivera (sam.r@example.com, 415-555-0173) lives at 4012 Maple Court."
        fake = lambda t: [("Sam Rivera", "PERSON"), ("4012 Maple Court", "ADDRESS")]
        out, _ = pipeline.sterilize(text, "s", self.vault, fake)
        self.assertNotIn("Maple", out)
        self.assertNotIn("sam.r", out)
        back, res = pipeline.rehydrate(out, "s", self.vault)
        self.assertEqual(back, text)
        self.assertEqual(res["unknown_tokens"], [])

    def test_rehydrate_unknown_token_left_alone(self):
        out, res = pipeline.rehydrate("hello [PII_EMAIL_9]", "s", self.vault)
        self.assertEqual(out, "hello [PII_EMAIL_9]")
        self.assertEqual(res["unknown_tokens"], ["[PII_EMAIL_9]"])

    def test_stable_across_calls(self):
        fake = lambda t: []
        out1, _ = pipeline.sterilize("mail a@b.com", "s", self.vault, fake)
        out2, _ = pipeline.sterilize("again a@b.com!", "s", self.vault, fake)
        self.assertIn("[PII_EMAIL_1]", out1)
        self.assertIn("[PII_EMAIL_1]", out2)

    def test_rules_type_wins_on_duplicate_value(self):
        # LLM mistyping a value the rules also caught must not change the
        # minted type — rules are the higher-precision typer.
        text = "reach me at 415-555-0173"
        fake = lambda t: [("415-555-0173", "ID_NUMBER")]
        _, res = pipeline.sterilize(text, "s", self.vault, fake)
        self.assertEqual(res["findings"], [{"token": "[PII_PHONE_1]", "type": "PHONE"}])

    def assertTokenizedAndRoundTrips(self, text, values, secret, verify=None, label=""):
        vault = Vault(os.path.join(self.tmp.name, "case-%d.db" % self._n))
        self._n += 1
        out, res = pipeline.sterilize(text, "s", vault, lambda t: list(values), verify)
        self.assertNotIn(secret, out, "%s leaked: %r" % (label, out))
        back, _ = pipeline.rehydrate(out, "s", vault)
        self.assertEqual(back, text, "%s round trip: %r" % (label, out))
        return out, res

    # A value is replaced as a plain substring, inside longer words too:
    # an inflection, a file name or a handle that keeps the value is still
    # the value. Each case must tokenize and rehydrate byte-identically.
    SUBSTRING_CASES = [
        ("possessive", "Marisol's file is here", [("Marisol", "PERSON")], "Marisol"),
        ("possessive curly", "Marisol\u2019s file", [("Marisol", "PERSON")], "Marisol"),
        ("hyphen", "Marisol-Garcia signed", [("Marisol", "PERSON")], "Marisol"),
        ("punctuation", "Ask Marisol. Then Marisol, Marisol!", [("Marisol", "PERSON")], "Marisol"),
        ("line start and end", "Marisol\nhi\nbye Marisol", [("Marisol", "PERSON")], "Marisol"),
        ("email local part", "write marisol.garcia@acme.org or Marisol", [("Marisol", "PERSON")], "Marisol"),
        ("url path", "see https://acme.org/team/Marisol/cv", [("Marisol", "PERSON")], "Marisol"),
        ("underscore file name", "attached Marisol_Garcia_resume.pdf", [("Marisol", "PERSON")], "Marisol"),
        ("underscore username", "login marisol_g from home", [("marisol", "USERNAME")], "marisol"),
        ("digit suffix username", "user jsmith42 logged in", [("jsmith", "USERNAME")], "jsmith"),
        ("camelCase", "folder MarisolGarcia/", [("Marisol", "PERSON")], "Marisol"),
        ("plural surname", "the Garcias came over", [("Garcia", "PERSON")], "Garcia"),
        ("inside another word", "Ann flew to Annapolis", [("Ann", "PERSON")], "Ann"),
        ("german genitive", "Annas Auto ist rot", [("Anna", "PERSON")], "Anna"),
        ("finnish case", "Kerro Marisolille", [("Marisol", "PERSON")], "Marisol"),
        ("hungarian case", "Marisolnak adtam", [("Marisol", "PERSON")], "Marisol"),
        ("hashtag and digits", "#Marisol2024 party", [("Marisol", "PERSON")], "Marisol"),
        ("diacritics", "Jos\u00e9 and Zo\u00eb's", [("Jos\u00e9", "PERSON"), ("Zo\u00eb", "PERSON")], "Jos\u00e9"),
        ("decomposed accent", "Jose\u0301 came", [("Jose", "PERSON")], "Jose"),
        ("apostrophe name", "O'Brien's O'Brien", [("O'Brien", "PERSON")], "O'Brien"),
        ("value with digit", "Room 101B and apt 101", [("101B", "ADDRESS")], "101B"),
        ("next to a placeholder", "m@x.com Marisol m@x.comMarisol", [("Marisol", "PERSON")], "Marisol"),
        ("chinese", "\u5f20\u4f1f\u4f4f\u5728\u5317\u4eac\uff0c\u5f20\u4f1f\u660e\u4e5f\u5728",
         [("\u5f20\u4f1f", "PERSON")], "\u5f20\u4f1f"),
        ("latin next to chinese", "Ann\u4f4f\u5728\u5317\u4eac Ann's", [("Ann", "PERSON")], "Ann"),
        ("halfwidth katakana", "\uff80\uff85\uff76\u3055\u3093 \uff80\uff85\uff76\uff80\uff9b\uff73",
         [("\uff80\uff85\uff76", "PERSON")], "\uff80\uff85\uff76"),
        ("thai", "\u0e2a\u0e21\u0e0a\u0e32\u0e22\u0e44\u0e1b\u0e1a\u0e49\u0e32\u0e19",
         [("\u0e2a\u0e21\u0e0a\u0e32\u0e22", "PERSON")], "\u0e2a\u0e21\u0e0a\u0e32\u0e22"),
        ("korean particle", "\ubbfc\uc218\ub294 \ud559\uad50\uc5d0", [("\ubbfc\uc218", "PERSON")], "\ubbfc\uc218"),
        ("devanagari suffix", "\u0930\u093e\u092e\u0915\u094b \u0918\u0930",
         [("\u0930\u093e\u092e", "PERSON")], "\u0930\u093e\u092e"),
        ("tai tham", "\u1a20\u1a21\u1a22\u1a23", [("\u1a20\u1a21", "PERSON")], "\u1a20\u1a21"),
        ("model value partly overlaps a rule hit", "call 415-555-0173 Main St",
         [("0173 Main St", "ADDRESS")], "Main St"),
        ("model value covers a rule hit", "Marisol <m@example.com>",
         [("Marisol <m@example.com>", "OTHER")], "m@example.com"),
        # rule findings: every copy of the value goes, not only the detected one
        ("repeated phone", "Call 415-555-0173 or text 415-555-0173.", [], "415-555-0173"),
        ("repeated ip, sentence end", "ip 10.1.2.3 and gateway was 10.1.2.3.", [], "10.1.2.3"),
        ("ssn copy with suffix", "ssn 123-45-6789 / ref 123-45-6789-A", [], "123-45-6789"),
        ("phone copy glued to a word", "tel:415-555-0173 ph415-555-0173", [], "415-555-0173"),
        ("phone at sentence end", "Call me at 415-555-0173.", [], "415-555-0173"),
    ]

    def test_substring_cases_tokenize_and_round_trip(self):
        self._n = 0
        for label, text, values, secret in self.SUBSTRING_CASES:
            with self.subTest(label):
                self.assertTokenizedAndRoundTrips(text, values, secret, label=label)

    def test_substring_match_is_counted_in_findings(self):
        self._n = 0
        _, res = self.assertTokenizedAndRoundTrips(
            "the Garcias came over", [("Garcia", "PERSON")], "Garcia")
        self.assertEqual(res["findings"], [{"token": "[PII_PERSON_1]", "type": "PERSON"}])

    def test_partial_overlap_becomes_one_token(self):
        # the model value overlaps the rule hit from the right, then from the
        # left; either way one token over the union, rehydrating to the bytes
        cases = [
            ("call 415-555-0173 Main St", [("0173 Main St", "ADDRESS")],
             "415-555-0173 Main St", "call [PII_PHONE_1]"),
            ("at Main St 415-555-0173 today", [("Main St 415", "ADDRESS")],
             "Main St 415-555-0173", "at [PII_PHONE_1] today"),
        ]
        for i, (text, values, merged, want) in enumerate(cases):
            with self.subTest(text):
                vault = Vault(os.path.join(self.tmp.name, "po-%d.db" % i))
                out, _ = pipeline.sterilize(text, "s", vault, lambda t, v=values: v)
                self.assertEqual(out, want)
                self.assertEqual(vault.value_for("s", "[PII_PHONE_1]"), merged)
                back, res = pipeline.rehydrate(out, "s", vault)
                self.assertEqual(back, text)
                self.assertEqual((res["restored"], res["unknown_tokens"]), (1, []))

    def test_self_overlapping_value_leaves_no_fragment(self):
        for text, value, want in (("x ababa x", "aba", "x [PII_PERSON_1] x"),
                                  ("id 121212 end", "1212", "id [PII_ID_NUMBER_1] end")):
            with self.subTest(text):
                vault = Vault(os.path.join(self.tmp.name, "so-%s.db" % value))
                typ = "ID_NUMBER" if value.isdigit() else "PERSON"
                out, _ = pipeline.sterilize(text, "s", vault, lambda t, v=value, ty=typ: [(v, ty)])
                self.assertEqual(out, want)
                back, _ = pipeline.rehydrate(out, "s", vault)
                self.assertEqual(back, text)

    def test_never_minted_placeholder_in_the_source_survives_the_round_trip(self):
        # placeholder-shaped text the vault does not hold is escaped, so it
        # comes back as written, card-like digits inside it included
        pipeline.sterilize("Marisol called", "s", self.vault, lambda t: [("Marisol", "PERSON")])
        text = "log: [PII_EMAIL_7], [PII_FOO_99] and [PII_A_4111111111111111], sent by Ana"
        out, res = pipeline.sterilize(text, "s", self.vault, lambda t: [("Ana", "PERSON")])
        for lit in ("[PII_EMAIL_7]", "[PII_FOO_99]", "[PII_A_4111111111111111]"):
            self.assertNotIn(lit, out)
        self.assertEqual(res["stats"]["literal_tokens_escaped"], 3)
        self.assertEqual(res["findings"], [{"token": "[PII_PERSON_2]", "type": "PERSON"}])
        back, info = pipeline.rehydrate(out, "s", self.vault)
        self.assertEqual(back, text)
        self.assertEqual(info["unknown_tokens"], [])

    def test_live_token_in_the_source_passes_through(self):
        # a placeholder the vault holds for this scope is treated as the token
        # it names: a quoted "[PII_PERSON_1]" rehydrates to the vault value.
        # That is the documented limit; it is what keeps re-sterilizing
        # already-sterilized text stable.
        pipeline.sterilize("Marisol called", "s", self.vault, lambda t: [("Marisol", "PERSON")])
        text = "the log shows [PII_PERSON_1]"
        out, res = pipeline.sterilize(text, "s", self.vault, lambda t: [])
        self.assertEqual(out, text)
        self.assertEqual(res["stats"]["literal_tokens_escaped"], 0)
        self.assertEqual(pipeline.rehydrate(out, "s", self.vault)[0], "the log shows Marisol")

    def test_escape_held_literals_escapes_a_live_placeholder(self):
        # raw documents: a quoted placeholder is never another text's value
        pipeline.sterilize("mail ana@x.org", "s", self.vault, lambda t: [])
        text = "quoted [PII_EMAIL_1] here"
        kept, _ = pipeline.sterilize(text, "s", self.vault, lambda t: [])
        self.assertEqual(kept, text)                         # default: the live token
        out, res = pipeline.sterilize(text, "s", self.vault, lambda t: [], escape_held_literals=True)
        self.assertNotIn("[PII_EMAIL_1]", out)
        self.assertEqual(res["stats"]["literal_tokens_escaped"], 1)
        self.assertEqual(pipeline.rehydrate(out, "s", self.vault)[0], text)

    def test_each_distinct_placeholder_is_looked_up_once(self):
        text = " ".join(["[PII_EMAIL_%d]" % (i % 3) for i in range(300)])
        calls = []
        real = self.vault.value_for

        def counting(scope, token):
            calls.append(token)
            return real(scope, token)

        with mock.patch.object(self.vault, "value_for", counting):
            pipeline.sterilize(text, "s", self.vault, lambda t: [])
        self.assertEqual(sorted(calls), ["[PII_EMAIL_0]", "[PII_EMAIL_1]", "[PII_EMAIL_2]"])

    def test_resterilizing_stored_text_is_stable(self):
        # a stored conversation is sent back to sterilize on every save:
        # three load/append/save rounds, then one rehydrate gives the original
        scope = "thread:abc"
        msgs = [{"role": "user", "content": "Email Marisol at marisol@acme.org"}]
        model = lambda t: [("Marisol", "PERSON")] if "Marisol" in t else []
        stored, _ = pipeline.sterilize(json.dumps(msgs), scope, self.vault, model)
        rows_after_first_save = len(self.vault.scope_tokens(scope))
        for i in range(3):
            loaded = json.loads(stored)
            loaded.append({"role": "assistant", "content": "ok %d" % i})
            msgs.append({"role": "assistant", "content": "ok %d" % i})
            stored, res = pipeline.sterilize(json.dumps(loaded), scope, self.vault, model)
            self.assertEqual(res["stats"]["literal_tokens_escaped"], 0)
        self.assertEqual(json.loads(stored)[0]["content"], "Email [PII_PERSON_1] at [PII_EMAIL_1]")
        self.assertEqual(len(self.vault.scope_tokens(scope)), rows_after_first_save)
        back, _ = pipeline.rehydrate(stored, scope, self.vault)
        self.assertEqual(json.loads(back), msgs)

    def test_touching_matches_stay_two_tokens(self):
        # adjacent is not overlapping: each value keeps its own token
        text = "MarisolLopez and LopezMarisol"
        out, res = pipeline.sterilize(text, "s", self.vault,
                                      lambda t: [("Marisol", "PERSON"), ("Lopez", "PERSON")])
        self.assertEqual(out, "[PII_PERSON_1][PII_PERSON_2] and [PII_PERSON_2][PII_PERSON_1]")
        self.assertEqual(len(res["findings"]), 2)
        back, _ = pipeline.rehydrate(out, "s", self.vault)
        self.assertEqual(back, text)

    def test_verify_value_cannot_break_a_token(self):
        # a verify pass reading sterilized text may propose pieces of a
        # placeholder; none may split one, and the round trip must hold
        self._n = 0
        for piece in ("PII_PERSON_1", "PERSON", "PII", "_1"):
            with self.subTest(piece):
                out, _ = self.assertTokenizedAndRoundTrips(
                    "Marisol called", [("Marisol", "PERSON")], "Marisol",
                    verify=lambda t, piece=piece: [(piece, "OTHER")], label=piece)
                self.assertEqual(out, "[PII_PERSON_1] called")

    def test_bare_token_name_is_not_usable(self):
        grounded, dropped = pipeline.ground([("PII_PERSON_1", "OTHER"), ("x PII_EMAIL_2 y", "OTHER")],
                                            "PII_PERSON_1 x PII_EMAIL_2 y")
        self.assertEqual((grounded, dropped), ([], 2))

    def test_residuals_are_counted(self):
        # the first rules pass misses the email; the residual loop must
        # tokenize it AND report it, even though the next round is clean
        real = detect.detect
        calls = []

        def first_pass_blind(text):
            calls.append(text)
            return [] if len(calls) == 1 else real(text)

        with mock.patch.object(detect, "detect", first_pass_blind):
            out, res = pipeline.sterilize("mail a@b.com and c@d.com", "s", self.vault, lambda t: [])
        self.assertEqual(out, "mail [PII_EMAIL_1] and [PII_EMAIL_2]")
        self.assertEqual(res["stats"]["residual_tokenized"], 2)
        self.assertEqual(res["stats"]["rules"], 0)

    def test_residuals_summed_across_rounds(self):
        # two residual rounds that each find something: the stat is their
        # sum, not the last round's count
        real = detect.detect
        calls = []

        def one_at_a_time(text):
            calls.append(text)
            if len(calls) == 1:
                return []
            return real(text)[:1]

        with mock.patch.object(detect, "detect", one_at_a_time):
            out, res = pipeline.sterilize("mail a@b.com and c@d.com", "s", self.vault, lambda t: [])
        self.assertEqual(out, "mail [PII_EMAIL_1] and [PII_EMAIL_2]")
        self.assertEqual(res["stats"]["residual_tokenized"], 2)

    def test_no_residuals_reports_zero(self):
        _, res = pipeline.sterilize("ssn 123-45-6789", "s", self.vault, lambda t: [])
        self.assertEqual(res["stats"]["residual_tokenized"], 0)

    def test_verify_pass_tokenizes_grounded_hits(self):
        text = "the patient is Marisol"
        fake_extract = lambda t: []
        fake_verify = lambda t: [("Marisol", "PERSON")]
        out, res = pipeline.sterilize(text, "s", self.vault, fake_extract, fake_verify)
        self.assertEqual(out, "the patient is [PII_PERSON_1]")
        self.assertEqual(res["stats"]["verify_tokenized"], 1)

    def test_verify_counts_only_what_it_replaced(self):
        # grounded but replacing nothing: a piece of an existing token, and a
        # value already tokenized by the first pass
        fake_verify = lambda t: [("PERSON", "OTHER"), ("Marisol", "PERSON"), ("Lopez", "PERSON")]
        out, res = pipeline.sterilize("Marisol Lopez called", "s", self.vault,
                                      lambda t: [("Marisol", "PERSON")], fake_verify)
        self.assertEqual(out, "[PII_PERSON_1] [PII_PERSON_2] called")
        self.assertEqual(res["stats"]["verify_tokenized"], 1)


class PromptContractTests(unittest.TestCase):
    def test_prompts_state_full_type_vocabulary(self):
        # The grammar prefix-coerces free-text labels to enum members
        # ("School" -> SSN, observed live). The prompts must therefore
        # state every legal label verbatim; this guards enum/prompt drift.
        from . import llmclient
        for prompt in (llmclient.EXTRACT_SYSTEM, llmclient.VERIFY_SYSTEM):
            for typ in detect.PII_TYPES:
                self.assertIn(typ, prompt)


class _FakeGliner:
    """Stands in for gliner.GLiNER: returns canned entities, records labels."""
    entities = []
    calls = []

    def predict_entities(self, text, labels, threshold=0.5):
        _FakeGliner.calls.append((labels, threshold))
        return list(self.entities)


class RecallBackendTests(unittest.TestCase):
    def setUp(self):
        from . import recall
        self.recall = recall
        _FakeGliner.entities, _FakeGliner.calls = [], []

    def test_default_is_llm(self):
        b = self.recall.build_backend({"LLM_URL": "http://x:1"})
        self.assertEqual(b.name, "llm")

    def test_unknown_backend_refused(self):
        with self.assertRaises(self.recall.RecallError):
            self.recall.build_backend({"PII_RECALL": "cloud"})

    def test_gliner_missing_package_fails_closed(self):
        def loader(_):
            raise ImportError("No module named 'gliner'")
        with self.assertRaises(self.recall.RecallError) as ctx:
            self.recall.build_backend({"PII_RECALL": "gliner"}, loader=loader)
        self.assertIn("pip install gliner", str(ctx.exception))

    def test_gliner_maps_labels_to_vocabulary_and_dedupes(self):
        _FakeGliner.entities = [
            {"text": "Marisol", "label": "person name", "score": 0.9},
            {"text": "Marisol", "label": "person name", "score": 0.8},
            {"text": "Lincoln Elementary", "label": "employer or school or organization"},
            {"text": "junk", "label": "not a label we asked for"},
        ]
        b = self.recall.build_backend(
            {"PII_RECALL": "gliner", "GLINER_THRESHOLD": "0.6"}, loader=lambda _: _FakeGliner())
        out = b.extract("Marisol goes to Lincoln Elementary")
        self.assertEqual(out, [("Marisol", "PERSON"), ("Lincoln Elementary", "ORG")])
        labels, threshold = _FakeGliner.calls[-1]
        self.assertEqual(set(labels), set(self.recall.GLINER_LABELS))
        self.assertEqual(threshold, 0.6)
        for typ in set(self.recall.GLINER_LABELS.values()):
            self.assertIn(typ, detect.PII_TYPES)

    def test_gliner_verify_uses_lower_threshold(self):
        b = self.recall.build_backend({"PII_RECALL": "gliner"}, loader=lambda _: _FakeGliner())
        b.verify("x")
        self.assertEqual(_FakeGliner.calls[-1][1], self.recall.DEFAULT_GLINER_VERIFY_THRESHOLD)

    def test_gliner_prediction_failure_is_recall_error(self):
        class Broken:
            def predict_entities(self, *a, **k):
                raise RuntimeError("cuda gone")
        b = self.recall.build_backend({"PII_RECALL": "gliner"}, loader=lambda _: Broken())
        with self.assertRaises(self.recall.RecallError):
            b.extract("x")

    def test_llm_error_is_a_recall_error(self):
        from . import llmclient
        self.assertTrue(issubclass(llmclient.LlmError, self.recall.RecallError))

    def test_gliner_backend_through_pipeline(self):
        _FakeGliner.entities = [{"text": "Marisol", "label": "person name"},
                                {"text": "Ghost", "label": "person name"}]
        b = self.recall.build_backend({"PII_RECALL": "gliner"}, loader=lambda _: _FakeGliner())
        tmp = tempfile.TemporaryDirectory()
        try:
            vault = Vault(os.path.join(tmp.name, "v.db"))
            out, res = pipeline.sterilize("Marisol called 415-555-0173", "s", vault, b.extract)
        finally:
            tmp.cleanup()
        self.assertEqual(out, "[PII_PERSON_1] called [PII_PHONE_1]")
        self.assertEqual(res["stats"]["llm_ungrounded"], 1)  # "Ghost" was not in the text


class _StubLlm(BaseHTTPRequestHandler):
    """Speaks llama.cpp's chat-completions shape; extraction canned per test."""
    findings = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        content = json.dumps({"findings": self.findings})
        body = json.dumps(
            {"choices": [{"message": {"content": content}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ServiceTests(unittest.TestCase):
    KEY = "test-key-123"

    @classmethod
    def setUpClass(cls):
        cls.stub = ThreadingHTTPServer(("127.0.0.1", 0), _StubLlm)
        threading.Thread(target=cls.stub.serve_forever, daemon=True).start()
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = service.Config({
            "PII_BIND": "127.0.0.1:0",
            "LLM_URL": f"http://127.0.0.1:{cls.stub.server_address[1]}",
            "PII_DB": os.path.join(cls.tmp.name, "v.db"),
            "PII_API_KEY": cls.KEY,
        })
        cls.srv = service.build_server(cfg)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.stub.shutdown()
        cls.tmp.cleanup()

    def call(self, path, payload=None, key=None, method=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if key:
            req.add_header("Authorization", f"Bearer {key}")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)

    def test_health_no_auth(self):
        status, body = self.call("/health")
        self.assertEqual((status, body["ok"]), (200, True))

    def test_auth_required(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.call("/sterilize", {"text": "x"}, key="wrong")
        self.assertEqual(ctx.exception.code, 401)

    def test_sterilize_rehydrate_over_http(self):
        _StubLlm.findings = [{"text": "Marisol", "type": "PERSON"}]
        original = "Marisol's ssn is 123-45-6789, mail her at m@example.com"
        _, st = self.call("/sterilize", {"text": original, "scope": "conv1"}, key=self.KEY)
        for leak in ("Marisol", "123-45-6789", "m@example.com"):
            self.assertNotIn(leak, st["text"])
        self.assertEqual(st["stats"]["rules"], 2)
        _, back = self.call("/rehydrate", {"text": st["text"], "scope": "conv1"}, key=self.KEY)
        self.assertEqual(back["text"], original)
        # wrong scope must not resolve
        _, other = self.call("/rehydrate", {"text": st["text"], "scope": "conv2"}, key=self.KEY)
        self.assertEqual(other["restored"], 0)

    def test_flag_rules_only_no_vault_rows(self):
        _StubLlm.findings = [{"text": "should never be called", "type": "PERSON"}]
        _, body = self.call("/flag", {"text": "ssn 123-45-6789 and a@b.com"}, key=self.KEY)
        self.assertTrue(body["flagged"])
        self.assertEqual(body["counts"], {"SSN": 1, "EMAIL": 1})
        _, clean = self.call("/flag", {"text": "nothing sensitive here"}, key=self.KEY)
        self.assertEqual((clean["flagged"], clean["counts"]), (False, {}))
        # no scope was touched, nothing minted
        _, inv = self.call("/scope/default", key=self.KEY)
        self.assertEqual(inv["tokens"], [])

    def test_escape_held_literals_over_http(self):
        _StubLlm.findings = []
        self.call("/sterilize", {"text": "mail a@b.com", "scope": "esc"}, key=self.KEY)
        quote = "quoted [PII_EMAIL_1]"
        _, kept = self.call("/sterilize", {"text": quote, "scope": "esc"}, key=self.KEY)
        self.assertEqual(kept["text"], quote)               # default: a re-save keeps the token
        _, esc = self.call("/sterilize", {"text": quote, "scope": "esc",
                                          "escape_held_literals": True}, key=self.KEY)
        self.assertNotIn("[PII_EMAIL_1]", esc["text"])
        _, back = self.call("/rehydrate", {"text": esc["text"], "scope": "esc"}, key=self.KEY)
        self.assertEqual(back["text"], quote)
        # the rule applied is echoed, so a caller can tell it was honoured
        self.assertIs(kept["stats"]["escape_held_literals"], False)
        self.assertIs(esc["stats"]["escape_held_literals"], True)

    def test_scope_inventory_no_values(self):
        _StubLlm.findings = []
        self.call("/sterilize", {"text": "a@b.com", "scope": "inv"}, key=self.KEY)
        _, body = self.call("/scope/inv", key=self.KEY)
        self.assertEqual(body["tokens"][0]["token"], "[PII_EMAIL_1]")
        self.assertNotIn("a@b.com", json.dumps(body))

    def test_fail_closed_without_key(self):
        with self.assertRaises(SystemExit):
            service.Config({"PII_DB": "x"})

    def test_default_bind_is_loopback(self):
        # /rehydrate returns real values over plain HTTP: only an explicit
        # setting may open the service beyond this machine
        self.assertEqual(service.Config({"PII_DB": "x", "PII_API_KEY": "k"}).bind,
                         "127.0.0.1:8091")
        self.assertEqual(service.Config({"PII_DB": "x", "PII_API_KEY": "k",
                                         "PII_BIND": "0.0.0.0:8091"}).bind, "0.0.0.0:8091")

    def test_fail_closed_on_unstartable_recall_backend(self):
        with self.assertRaises(SystemExit) as ctx:
            service.Config({"PII_DB": "x", "PII_API_KEY": "k", "PII_RECALL": "nope"})
        self.assertIn("PII_RECALL", str(ctx.exception))

    def test_sterilize_reports_recall_backend(self):
        _StubLlm.findings = []
        _, st = self.call("/sterilize", {"text": "a@b.com", "scope": "rb"}, key=self.KEY)
        self.assertEqual(st["stats"]["recall"], "llm")


if __name__ == "__main__":
    unittest.main()
