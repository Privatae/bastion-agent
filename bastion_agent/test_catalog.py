"""Unit tests for the catalog stage. Run: python3 -m unittest discover .

The summarizer is a loopback stub (same process, test only) speaking both
chat wire formats and echoing a deterministic summary built from the
prompt, so cache and fail-closed behaviour are checked without a model.
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import catalog as cat
from .extract import extract
from .manifest import validate_document
from .sanitize import sanitize
from .walk import walk


def manifest(root, summarize=None):
    doc = {
        "freeagent": 1, "id": "t", "owner": {"host": "h"},
        "scope": {"roots": [root]},
        "mask": ["read", "search", "index"] + (["summarize"] if summarize else []),
        "stages": ["walk", "extract", "sanitize", "catalog"], "sweep": "manual",
        "sanitize": {"mode": "flag"},
        "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"},
    }
    if summarize:
        doc["summarize"] = {"model": "stub-chat", "per": summarize}
    return validate_document(doc)


def put(root, rel, text):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class _StubChat(BaseHTTPRequestHandler):
    serve = ("ollama", "openai")
    calls = []
    fail = False

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(n))
        prompt = req["messages"][-1]["content"]
        _StubChat.calls.append((self.path, req["model"], prompt))
        if _StubChat.fail or (self.path == "/api/chat" and "ollama" not in self.serve) \
                or (self.path == "/v1/chat/completions" and "openai" not in self.serve) \
                or self.path not in ("/api/chat", "/v1/chat/completions"):
            self.send_response(500 if _StubChat.fail else 404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body_text = prompt.split("\n\n", 1)[-1]
        summary = '<think>hmm</think> "SUMMARY of: %s"' % body_text[:40].replace("\n", " ")
        if self.path == "/api/chat":
            body = {"message": {"role": "assistant", "content": summary}}
        else:
            body = {"choices": [{"message": {"role": "assistant", "content": summary}}]}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class UnitTests(unittest.TestCase):
    def test_title_head_keywords(self):
        text = "# Quarterly Budget Review\n\nSpending on routers and firewalls rose. Routers again.\n"
        self.assertEqual(cat.title_of(text), "Quarterly Budget Review")
        self.assertTrue(cat.head_of(text).startswith("# Quarterly Budget Review Spending"))
        counts = cat.term_counts(text)
        self.assertEqual(counts["routers"], 2)
        self.assertNotIn("and", counts)
        kws = cat.keywords(counts, {"routers": 1}, 1, 3)
        self.assertEqual(kws[0], "routers")
        self.assertEqual(kws, cat.keywords(counts, {"routers": 1}, 1, 3))  # deterministic

    def test_mask_name(self):
        detect = cat._rules_detect()
        # the email rule legitimately spans dots and hyphens, so a name that
        # embeds an address is masked conservatively — whole span, not just
        # the address; the card keeps mime/size so nothing is lost but the name
        self.assertEqual(cat.mask_name("invoice-m@example.com.pdf", detect), "[PII_EMAIL]")
        self.assertEqual(cat.mask_name("invoice m@example.com.pdf", detect), "invoice [PII_EMAIL]")
        self.assertEqual(cat.mask_name("notes.txt", detect), "notes.txt")
        self.assertEqual(cat.mask_name("call 415-555-0173 notes", detect), "call [PII_PHONE] notes")

    def test_clean_summary(self):
        self.assertEqual(cat.clean_summary('<think>x</think>  "A  b" '), "A b")
        self.assertEqual(len(cat.clean_summary("x" * 2000)), cat.SUMMARY_MAX_CHARS)


class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _StubChat)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fa-cat-")
        self.out = tempfile.mkdtemp(prefix="fa-catout-")
        _StubChat.serve, _StubChat.calls, _StubChat.fail = ("ollama", "openai"), [], False
        put(self.root, "finance/budget.md", "# Budget 2026\n\nRouters and firewalls. Contact m@example.com.\n")
        put(self.root, "finance/invoice-m@example.com.txt", "invoice for routers 4111 1111 1111 1111\n")
        put(self.root, "notes/orchard.txt", "apples pears plums harvest\n")
        put(self.root, "blob.bin", "\x00\x01")
        self.env = {"SUMMARIZE_URL": self.url}

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    def run_stage(self, m):
        walk(m, self.out)
        extract(m, self.out, use_external=False)
        sanitize(m, self.out, env={})
        s = cat.catalog(m, self.out, env=self.env)
        with open(os.path.join(self.out, "catalog.jsonl"), encoding="utf-8") as fh:
            files = {json.loads(l)["path"]: json.loads(l) for l in fh}
        with open(os.path.join(self.out, "catalog.dirs.jsonl"), encoding="utf-8") as fh:
            dirs = {json.loads(l)["path"]: json.loads(l) for l in fh}
        return s, files, dirs


class StageTests(Case):
    def test_cards_without_summarizer(self):
        s, files, dirs = self.run_stage(manifest(self.root))
        self.assertIsNone(s["summarizer"])
        self.assertEqual(_StubChat.calls, [])
        b = files["finance/budget.md"]
        self.assertEqual(b["title"], "Budget 2026")
        self.assertIn("[PII_EMAIL_1]", b["head"])
        self.assertNotIn("m@example.com", json.dumps(b))
        self.assertEqual(b["entities"], {"EMAIL": 1})
        self.assertIn("routers", b["keywords"])
        self.assertEqual(b["text"], "ok")
        self.assertEqual(b["mime"], "text/markdown")
        self.assertNotIn("summary", b)
        # filename with an email is masked in the card
        self.assertIn("finance/[PII_EMAIL]", files)  # conservative whole-span mask
        self.assertEqual(files["finance/[PII_EMAIL]"]["mime"], "text/plain")
        self.assertEqual(s["counts"]["names_masked"], 1)
        # placeholders never become keywords
        self.assertNotIn("pii", b["keywords"])
        self.assertNotIn("email", b["keywords"])
        # a file with no text still gets a card
        self.assertEqual(files["blob.bin"]["text"], "unsupported")
        self.assertNotIn("head", files["blob.bin"])
        # directories: root "" aggregates everything
        self.assertEqual(dirs[""]["files"], 4)
        self.assertEqual(dirs["finance"]["files"], 2)
        self.assertEqual(dirs["finance"]["with_text"], 2)
        self.assertEqual(dirs["finance"]["entities"], {"EMAIL": 1, "CREDIT_CARD": 1})
        self.assertIn("routers", dirs["finance"]["keywords"])
        self.assertIn("apples", dirs["notes"]["keywords"])
        self.assertEqual(dirs["finance"]["types"]["text/markdown"], 1)
        self.assertEqual(s["counts"], dict(files=4, with_text=3, dirs=3, summaries=0,
                                           summaries_reused=0, summary_errors=0, names_masked=1))

    def test_parent_directory_names_are_masked_too(self):
        # a directory named with an address must not leak through
        # a file card's path, which is what seal ships
        put(self.root, "marisol.vega@example.com/notes.txt", "plain\n")
        s, files, dirs = self.run_stage(manifest(self.root))
        self.assertIn("[PII_EMAIL]/notes.txt", files)
        self.assertIn("[PII_EMAIL]", dirs)
        blob = json.dumps(files) + json.dumps(dirs)
        self.assertNotIn("marisol.vega", blob)
        self.assertEqual(s["counts"]["names_masked"], 2)  # the invoice file + the directory

    def test_catalog_carries_no_values(self):
        _, files, dirs = self.run_stage(manifest(self.root))
        blob = json.dumps(files) + json.dumps(dirs)
        for leak in ("m@example.com", "4111"):
            self.assertNotIn(leak, blob)

    def test_summaries_file_and_directory_with_cache(self):
        m = manifest(self.root, summarize=["file", "directory"])
        s, files, dirs = self.run_stage(m)
        self.assertTrue(s["summarizer"].startswith("stub-chat@"))
        self.assertTrue(s["summarizer"].endswith("(ollama)"))
        self.assertTrue(files["finance/budget.md"]["summary"].startswith("SUMMARY of:"))
        self.assertNotIn("<think>", files["finance/budget.md"]["summary"])
        self.assertIsNone(files["blob.bin"]["summary"])
        self.assertTrue(dirs["finance"]["summary"].startswith("SUMMARY of:"))
        self.assertEqual(s["counts"]["summaries"], 3 + 3)  # 3 texts + 3 dirs
        # the model only ever saw sanitized text
        for _, _, prompt in _StubChat.calls:
            self.assertNotIn("m@example.com", prompt)
            self.assertNotIn("4111", prompt)
        # second run: all summaries from cache, no calls
        _StubChat.calls = []
        s2, _, _ = self.run_stage(m)
        self.assertEqual((s2["counts"]["summaries"], s2["counts"]["summaries_reused"]), (0, 6))
        self.assertEqual(_StubChat.calls, [])

    def test_openai_autodetect(self):
        _StubChat.serve = ("openai",)
        s, files, _ = self.run_stage(manifest(self.root, summarize=["file"]))
        self.assertTrue(s["summarizer"].endswith("(openai)"))
        self.assertTrue(files["notes/orchard.txt"]["summary"])

    def test_summarizer_failure_stops_but_cards_are_written(self):
        _StubChat.fail = True
        s, files, dirs = self.run_stage(manifest(self.root, summarize=["file", "directory"]))
        self.assertIsNotNone(s["stopped"])
        self.assertEqual(s["counts"]["summary_errors"], 1)  # stopped after the first
        self.assertEqual(len(files), 4)
        self.assertEqual(len(dirs), 3)
        errs = [c for c in list(files.values()) + list(dirs.values()) if c.get("summary_error")]
        self.assertEqual(len(errs), 1)
        self.assertTrue(all(c.get("summary") is None for c in files.values()))

    def test_unreachable_summarizer(self):
        m = manifest(self.root, summarize=["file"])
        walk(m, self.out)
        extract(m, self.out, use_external=False)
        sanitize(m, self.out, env={})
        s = cat.catalog(m, self.out, env={"SUMMARIZE_URL": "http://127.0.0.1:9"})
        self.assertIn("summarizer", s["stopped"])

    def test_requires_earlier_stages(self):
        with self.assertRaises(FileNotFoundError):
            cat.catalog(manifest(self.root), self.out, env=self.env)


if __name__ == "__main__":
    unittest.main()
