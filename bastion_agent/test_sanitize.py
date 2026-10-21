"""Unit tests for the sanitize stage. Run: python3 -m unittest discover .

The real pii pipeline and vault run in-process; the recall backend
is a fake (no model), the service path is a stub HTTP server speaking the
real /sterilize wire format. Nothing here needs a model or the network.
"""

import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from . import sanitize as sz
from .extract import extract
from .manifest import validate_document
from .walk import walk

IS_WINDOWS = os.name == "nt"


def manifest(root, mode="flag", verify=False, scope=None):
    san = {"mode": mode, "verify": verify}
    if scope:
        san["scope"] = scope
    return validate_document({
        "freeagent": 1, "id": "t", "owner": {"host": "h"},
        "scope": {"roots": [root]},
        "mask": ["read"], "stages": ["walk", "extract", "sanitize"], "sweep": "manual",
        "sanitize": san,
        "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"},
    })


def put(root, rel, text):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class FakeBackend:
    name = "fake"
    calls = 0

    def __init__(self, findings=(), fail=False):
        self.findings = list(findings)
        self.fail = fail

    def describe(self):
        return "fake"

    def extract(self, text):
        FakeBackend.calls += 1
        if self.fail:
            _, recall, _ = sz.pii_modules()
            raise recall.RecallError("model unreachable")
        return list(self.findings)  # proposes everything; grounding must drop the ghosts

    def verify(self, text):
        return []


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fa-sz-")
        self.out = tempfile.mkdtemp(prefix="fa-szout-")
        put(self.root, "note.txt", "Marisol's email is m@example.com, card 4111 1111 1111 1111.\n")
        put(self.root, "twin.txt", "Marisol's email is m@example.com, card 4111 1111 1111 1111.\n")
        put(self.root, "clean.txt", "nothing personal here\n")
        put(self.root, "blob.bin", "\x00\x01")
        FakeBackend.calls = 0

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    def prep(self, m):
        walk(m, self.out)
        extract(m, self.out, use_external=False)

    def run_stage(self, m, env=None, backend=None):
        self.prep(m)
        if backend is not None:
            with mock.patch.object(sz, "BUILD_BACKEND", lambda e: backend):
                s = sz.sanitize(m, self.out, env=env or {})
        else:
            s = sz.sanitize(m, self.out, env=env or {})
        with open(os.path.join(self.out, "sanitize.jsonl"), encoding="utf-8") as fh:
            idx = {json.loads(l)["path"]: json.loads(l) for l in fh}
        return s, idx

    def text_of(self, rec):
        with open(sz.store_path(self.out, rec["sha256"]), encoding="utf-8") as fh:
            return fh.read()


class FlagModeTests(Case):
    def test_rules_only_redaction(self):
        s, idx = self.run_stage(manifest(self.root, "flag"))
        out = self.text_of(idx["note.txt"])
        self.assertNotIn("m@example.com", out)
        self.assertNotIn("4111", out)
        self.assertIn("Marisol", out)  # contextual PII is NOT caught by flag mode
        self.assertIn("[PII_EMAIL_1]", out)
        self.assertIn("[PII_CREDIT_CARD_1]", out)
        self.assertEqual(idx["note.txt"]["types"], {"EMAIL": 1, "CREDIT_CARD": 1})
        self.assertEqual(s["sterilizer"], "flag:rules-only")
        self.assertEqual(s["types"], {"EMAIL": 1, "CREDIT_CARD": 1})
        # twin shares content -> deduped, counted once as ok
        self.assertEqual(idx["twin.txt"]["sha256"], idx["note.txt"]["sha256"])
        self.assertEqual(s["counts"]["ok"], 3)
        self.assertEqual(idx["blob.bin"]["status"], "skipped")
        self.assertEqual(s["counts"]["skipped"], 1)

    def test_index_and_summary_carry_no_values(self):
        s, idx = self.run_stage(manifest(self.root, "flag"))
        blob = json.dumps(idx) + json.dumps(s)
        self.assertNotIn("m@example.com", blob)
        self.assertNotIn("4111", blob)

    @unittest.skipIf(IS_WINDOWS, "POSIX permission bits")
    def test_vault_is_private(self):
        self.run_stage(manifest(self.root, "flag"))
        mode = stat.S_IMODE(os.stat(os.path.join(self.out, "sanitize", "vault.db")).st_mode)
        self.assertEqual(mode, 0o600)

    def test_reuse_and_invalidate(self):
        s1, _ = self.run_stage(manifest(self.root, "flag"))
        s2, idx = self.run_stage(manifest(self.root, "flag"))
        self.assertEqual(s2["counts"]["reused"], s1["counts"]["ok"])
        self.assertTrue(idx["note.txt"]["reused"])
        # a different scope is a different cache key -> redone
        s3, _ = self.run_stage(manifest(self.root, "flag", scope="other"))
        self.assertEqual(s3["counts"]["reused"], 0)
        # a changed file is redone
        put(self.root, "clean.txt", "now with a@b.co\n")
        s4, idx4 = self.run_stage(manifest(self.root, "flag"))
        self.assertIn("[PII_EMAIL_", self.text_of(idx4["clean.txt"]))

    def test_result_from_an_older_pipeline_version_is_not_reused(self):
        # the version is the only reuse-key part that changes with the
        # pipeline: output written by older code must be redone on upgrade
        with mock.patch.object(sz, "SANITIZE_VERSION", 1):
            s1, _ = self.run_stage(manifest(self.root, "flag"))
        self.assertGreaterEqual(sz.SANITIZE_VERSION, 2)
        s2, idx = self.run_stage(manifest(self.root, "flag"))
        self.assertEqual(s2["counts"]["reused"], 0)
        self.assertEqual(s2["counts"]["ok"], s1["counts"]["ok"])
        self.assertFalse(idx["note.txt"].get("reused", False))

    def test_tokens_stable_across_files_in_scope(self):
        put(self.root, "again.txt", "ping m@example.com again\n")
        _, idx = self.run_stage(manifest(self.root, "flag"))
        self.assertIn("[PII_EMAIL_1]", self.text_of(idx["again.txt"]))
        self.assertIn("[PII_EMAIL_1]", self.text_of(idx["note.txt"]))

    def test_vault_dir_env_keeps_vault_out_of_out(self):
        vdir = tempfile.mkdtemp(prefix="fa-vault-")
        try:
            s, idx = self.run_stage(manifest(self.root, "flag"), env={"FREEAGENT_VAULT_DIR": vdir})
            self.assertTrue(os.path.exists(os.path.join(vdir, "vault.db")))
            self.assertFalse(os.path.exists(os.path.join(self.out, "sanitize", "vault.db")))
            self.assertIn("[PII_EMAIL_1]", self.text_of(idx["note.txt"]))
        finally:
            shutil.rmtree(vdir, ignore_errors=True)

    def test_requires_extract_first(self):
        with self.assertRaises(FileNotFoundError):
            sz.sanitize(manifest(self.root, "flag"), self.out, env={})


class SterilizeModeTests(Case):
    def test_recall_backend_findings_are_tokenized(self):
        fake = FakeBackend([("Marisol", "PERSON"), ("Ghost", "PERSON")])
        s, idx = self.run_stage(manifest(self.root, "sterilize"), backend=fake)
        out = self.text_of(idx["note.txt"])
        self.assertNotIn("Marisol", out)
        self.assertIn("[PII_PERSON_1]", out)
        self.assertEqual(idx["note.txt"]["types"]["PERSON"], 1)
        self.assertEqual(idx["note.txt"]["stats"]["llm_ungrounded"], 1)
        self.assertEqual(s["sterilizer"], "sterilize:fake")
        self.assertEqual(FakeBackend.calls, 2)  # note (twin deduped) + clean

    def test_fail_closed_stops_the_stage(self):
        s, idx = self.run_stage(manifest(self.root, "sterilize"), backend=FakeBackend(fail=True))
        self.assertEqual(s["counts"]["ok"], 0)
        self.assertEqual(s["counts"]["not_run"], 3)
        self.assertIn("model unreachable", s["stopped"])
        self.assertEqual(idx["note.txt"]["status"], "not_run")
        self.assertFalse(os.path.exists(sz.store_path(self.out, idx["note.txt"]["sha256"])))
        self.assertEqual(FakeBackend.calls, 1)  # stopped after the first failure

    def test_backend_that_cannot_start_raises(self):
        self.prep(manifest(self.root, "sterilize"))
        with self.assertRaises(sz.SanitizeError):
            sz.sanitize(manifest(self.root, "sterilize"), self.out, env={"PII_RECALL": "nope"})

    def test_chunking_round_trip(self):
        big = ("para %d with m@example.com\n\n" % i for i in range(2000))
        text = "".join(big)
        put(self.root, "big.txt", text)
        chunks = sz.split_chunks(text, limit=5000)
        self.assertGreater(len(chunks), 5)
        self.assertEqual("".join(chunks), text)
        self.assertTrue(all(len(c) <= 5000 for c in chunks))
        sizes = []
        real = sz.InProcess.sterilize

        def spy(front, chunk, scope):
            if chunk.startswith("para "):  # big.txt's chunks, not the other files
                sizes.append(len(chunk))
            return real(front, chunk, scope)

        with mock.patch.object(sz, "SANITIZE_CHUNK_CHARS", 5000), \
                mock.patch.object(sz.InProcess, "sterilize", spy):
            _, idx = self.run_stage(manifest(self.root, "flag"))
        # the stage itself must have split at the patched limit, not the default
        self.assertLessEqual(max(sizes), 5000)
        self.assertEqual(len(sizes), len(chunks))
        out = self.text_of(idx["big.txt"])
        self.assertNotIn("m@example.com", out)
        self.assertEqual(out.count("[PII_EMAIL_1]"), 2000)  # one token, every chunk

    def test_hard_cut_never_splits_a_placeholder(self):
        _, _, Vault = sz.pii_modules()
        from pii import pipeline
        self.assertEqual(sz._PLACEHOLDER_RE.pattern, pipeline.TOKEN_RE.pattern)
        vault = Vault(os.path.join(self.out, "v.db"))
        vault.token_for("s", "EMAIL", "ana@x.org")    # [PII_EMAIL_1] is live
        # the corpus stage escapes every placeholder in a document, but only
        # one that reaches the sterilizer whole: split in half, neither half
        # is recognised and the literal is stored raw, to rehydrate later as
        # the vault's value
        text = "x" * 15 + "[PII_EMAIL_1]" + "y" * 10     # one line, no newline
        chunks = sz.split_chunks(text, limit=20)
        self.assertEqual("".join(chunks), text)
        self.assertTrue(any("[PII_EMAIL_1]" in c for c in chunks), chunks)
        out = "".join(pipeline.sterilize(c, "s", vault, lambda t: [], escape_held_literals=True)[0]
                      for c in chunks)
        self.assertNotIn("[PII_EMAIL_1]", out)
        self.assertEqual(pipeline.rehydrate(out, "s", vault)[0], text)
        # a placeholder at the very start of an over-long piece stays whole
        self.assertEqual(sz.split_chunks("[PII_PERSON_1]" + "z" * 30, limit=10)[0], "[PII_PERSON_1]")

    def test_hard_cut_clears_a_placeholder_of_any_length(self):
        long_ph = "[PII_" + "OTHER_" * 20 + "123456789]"     # well over 64 characters
        for before in (30, 90, 150):
            with self.subTest(before=before):
                text = "x" * before + long_ph + "y" * 40
                chunks = sz.split_chunks(text, limit=100)
                self.assertEqual("".join(chunks), text)
                self.assertTrue(any(long_ph in c for c in chunks), [len(c) for c in chunks])

    def test_corpus_document_quoting_a_live_placeholder_round_trips(self):
        # one manifest-wide scope: a.txt mints [PII_EMAIL_1]; b.txt quotes that
        # placeholder literally and must come back as written, not as a's email
        for name in ("note.txt", "twin.txt", "clean.txt", "blob.bin"):
            os.remove(os.path.join(self.root, name))
        put(self.root, "a.txt", "mail ana@x.org\n")
        quote = "the export shows [PII_EMAIL_1] where the address was\n"
        put(self.root, "b.txt", quote)
        _, idx = self.run_stage(manifest(self.root, "flag"))
        _, _, Vault = sz.pii_modules()
        from pii import pipeline
        vault = Vault(os.path.join(self.out, "sanitize", "vault.db"))
        self.assertEqual(vault.value_for("t", "[PII_EMAIL_1]"), "ana@x.org")
        stored = self.text_of(idx["b.txt"])
        self.assertNotIn("[PII_EMAIL_1]", stored)
        self.assertEqual(pipeline.rehydrate(stored, "t", vault)[0], quote)

    def test_split_chunks_hard_cuts_a_giant_line(self):
        text = "x" * 12000 + "\n" + "y" * 100
        chunks = sz.split_chunks(text, limit=5000)
        self.assertEqual("".join(chunks), text)
        self.assertTrue(all(len(c) <= 5000 for c in chunks))
        self.assertEqual(sz.split_chunks("", 10), [])
        self.assertEqual(sz.split_chunks("short", 10), ["short"])


class _StubPii(BaseHTTPRequestHandler):
    seen = []
    status = 200
    echo = "honour"    # "honour", "strip" (a service that predates the field) or "false"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(n))
        _StubPii.seen.append((self.path, self.headers.get("Authorization"), req))
        if _StubPii.status != 200:
            self.send_response(_StubPii.status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"text": req["text"].replace("Marisol", "[PII_PERSON_1]"),
                           "findings": [{"token": "[PII_PERSON_1]", "type": "PERSON"}],
                           "stats": dict({"rules": 0, "llm": 1, "recall": "llm"}, **(
                               {} if _StubPii.echo == "strip" else
                               {"escape_held_literals": _StubPii.echo == "honour"
                                and req.get("escape_held_literals") is True}))}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ServiceModeTests(Case):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _StubPii)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.addr = "127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        super().setUp()
        _StubPii.seen, _StubPii.status, _StubPii.echo = [], 200, "honour"

    def test_service_path(self):
        env = {"PII_ADDR": self.addr, "PII_API_KEY": "k1"}
        s, idx = self.run_stage(manifest(self.root, "sterilize", scope="conv9"), env=env)
        self.assertEqual(s["sterilizer"], "service:http://" + self.addr)
        self.assertNotIn("Marisol", self.text_of(idx["note.txt"]))
        path, auth, req = _StubPii.seen[0]
        self.assertEqual((path, auth, req["scope"], req["verify"]), ("/sterilize", "Bearer k1", "conv9", False))
        self.assertIs(req["escape_held_literals"], True)   # documents: escape every literal
        # the echo is a handshake, not a count: it never reaches the index
        self.assertNotIn("escape_held_literals", idx["note.txt"]["stats"])
        with open(os.path.join(self.out, "sanitize.jsonl"), encoding="utf-8") as fh:
            self.assertNotIn("escape_held_literals", fh.read())
        self.assertNotIn("escape_held_literals", json.dumps(s))
        self.assertEqual(idx["note.txt"]["stats"]["recall"], "llm")
        # no local vault in service mode — the service owns it
        self.assertFalse(os.path.exists(os.path.join(self.out, "sanitize", "vault.db")))

    def test_service_502_fails_closed(self):
        _StubPii.status = 502
        env = {"PII_ADDR": self.addr, "PII_API_KEY": "k1"}
        s, idx = self.run_stage(manifest(self.root, "sterilize"), env=env)
        self.assertEqual(s["counts"]["not_run"], 3)
        self.assertIn("502", s["stopped"])

    def test_service_that_does_not_echo_the_literal_rule_stops_the_stage(self):
        # an older service ignores escape_held_literals and answers 200 under
        # the narrower rule; the stage must not store what it cannot trust
        env = {"PII_ADDR": self.addr, "PII_API_KEY": "k1"}
        for echo in ("strip", "false"):
            with self.subTest(echo):
                _StubPii.echo = echo
                shutil.rmtree(self.out, ignore_errors=True)
                os.makedirs(self.out)
                s, idx = self.run_stage(manifest(self.root, "sterilize"), env=env)
                self.assertIn("did not honour escape_held_literals", s["stopped"])
                self.assertEqual(s["counts"]["ok"], 0)
                self.assertEqual(s["counts"]["not_run"], 3)
                self.assertFalse(os.path.exists(sz.store_path(self.out, idx["note.txt"]["sha256"])))

    def test_service_without_key_refused(self):
        self.prep(manifest(self.root, "sterilize"))
        with self.assertRaises(sz.SanitizeError):
            sz.sanitize(manifest(self.root, "sterilize"), self.out, env={"PII_ADDR": self.addr})

    def test_flag_mode_never_uses_the_service(self):
        env = {"PII_ADDR": self.addr, "PII_API_KEY": "k1"}
        s, _ = self.run_stage(manifest(self.root, "flag"), env=env)
        self.assertEqual(_StubPii.seen, [])
        self.assertEqual(s["sterilizer"], "flag:rules-only")


if __name__ == "__main__":
    unittest.main()
