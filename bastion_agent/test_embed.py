"""Unit tests for chunk / embed / search. Run: python3 -m unittest discover .

The embedding endpoint is a stub HTTP server on loopback (same process,
test only) speaking both wire formats with a deterministic bag-of-words
vector, so search ranking is meaningful without a model.
"""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import embed as em
from .extract import extract
from .manifest import validate_document
from .sanitize import sanitize
from .walk import walk


def manifest(root, model="stub-model", dim=64, size=8, overlap=2):
    return validate_document({
        "freeagent": 1, "id": "t", "owner": {"host": "h"},
        "scope": {"roots": [root]},
        "mask": ["read", "search", "index"],
        "stages": ["walk", "extract", "sanitize", "chunk", "embed"], "sweep": "manual",
        "sanitize": {"mode": "flag"},
        "embed": {"model": model, "dim": dim, "chunk": {"size_tokens": size, "overlap_tokens": overlap}},
        "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"},
    })


def bow_vector(text, dim):
    v = [0.0] * dim
    for w in re.findall(r"\w+", text.lower()):
        h = int(hashlib.md5(w.encode()).hexdigest(), 16)
        v[h % dim] += 1.0
    return v


class _Stub(BaseHTTPRequestHandler):
    dim = 64
    serve = ("ollama", "openai")
    calls = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(n))
        _Stub.calls.append((self.path, req["model"], len(req["input"])))
        inputs = req["input"] if isinstance(req["input"], list) else [req["input"]]
        if self.path == "/api/embed" and "ollama" in self.serve:
            body = {"embeddings": [bow_vector(t, self.dim) for t in inputs]}
        elif self.path == "/v1/embeddings" and "openai" in self.serve:
            body = {"data": [{"index": i, "embedding": bow_vector(t, self.dim)}
                             for i, t in enumerate(inputs)]}
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class ChunkUnitTests(unittest.TestCase):
    def test_windows_cover_text_and_overlap(self):
        text = " ".join("w%d" % i for i in range(20))
        wins = list(em.chunk_text(text, 8, 2))
        self.assertEqual(wins[0][0], 0)
        self.assertEqual(wins[-1][1], len(text))
        # 20 tokens, step 6: windows at 0, 6, 12 — the third reaches the end
        self.assertEqual([em.count_tokens(w[2]) for w in wins], [8, 8, 8])
        # step = 6: window 2 starts at token 6 = "w6"
        self.assertTrue(wins[1][2].startswith("w6 "))
        # every char is inside at least one window
        covered = set()
        for s, e, _ in wins:
            covered.update(range(s, e))
        self.assertEqual(len(covered), len(text))

    def test_short_and_empty(self):
        self.assertEqual(list(em.chunk_text("", 8, 2)), [])
        self.assertEqual(list(em.chunk_text("   \n ", 8, 2)), [])
        wins = list(em.chunk_text("just three tokens", 8, 2))
        self.assertEqual(len(wins), 1)
        self.assertEqual(wins[0][2], "just three tokens")

    def test_punctuation_is_a_token_and_ids_are_content_addressed(self):
        self.assertEqual(em.count_tokens("Hi, there!"), 4)
        self.assertEqual(em.chunk_id("d", "x"), em.chunk_id("d", "x"))
        self.assertNotEqual(em.chunk_id("d", "x"), em.chunk_id("e", "x"))

    def test_pack_roundtrip(self):
        v = [0.5, -1.25, 3.0]
        self.assertEqual(list(em.unpack(em.pack(v))), v)
        self.assertAlmostEqual(em.cosine([1, 0], [1, 0]), 1.0)
        self.assertAlmostEqual(em.cosine([1, 0], [0, 1]), 0.0)
        self.assertEqual(em.cosine([0, 0], [1, 1]), 0.0)


class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fa-em-")
        self.out = tempfile.mkdtemp(prefix="fa-emout-")
        _Stub.dim, _Stub.serve, _Stub.calls = 64, ("ollama", "openai"), []
        self.put("apples.txt", "apples pears plums. " * 12 + "orchard harvest.")
        self.put("routers.txt", "router switch firewall vlan. " * 12 + "network segment.")
        self.put("twin.txt", "apples pears plums. " * 12 + "orchard harvest.")
        self.env = {"EMBED_URL": self.url, "EMBED_BATCH": "4"}

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    def put(self, name, text):
        with open(os.path.join(self.root, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def prep(self, m):
        walk(m, self.out)
        extract(m, self.out, use_external=False)
        sanitize(m, self.out, env={})

    def chunks(self):
        with open(os.path.join(self.out, "chunks.jsonl"), encoding="utf-8") as fh:
            return [json.loads(l) for l in fh]

    def db(self, sql, *params):
        conn = sqlite3.connect(em.vectors_path(self.out))
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()


class StageTests(Case):
    def test_chunk_stage(self):
        m = manifest(self.root)
        self.prep(m)
        s = em.chunk(m, self.out)
        rows = self.chunks()
        self.assertEqual(s["counts"]["docs"], 2)  # twin shares content with apples
        self.assertEqual(s["counts"]["chunks"], len(rows))
        self.assertGreater(len(rows), 4)
        docs = {r["doc"] for r in rows}
        self.assertEqual(len(docs), 2)
        self.assertEqual(rows, sorted(rows, key=lambda r: (r["doc"], r["idx"])))
        # deterministic
        em.chunk(m, self.out)
        self.assertEqual(rows, self.chunks())

    def test_chunk_requires_sanitize(self):
        with self.assertRaises(FileNotFoundError):
            em.chunk(manifest(self.root), self.out)

    def test_embed_probe_refuses_wrong_dim(self):
        m = manifest(self.root, dim=32)  # stub serves 64
        self.prep(m)
        em.chunk(m, self.out)
        with self.assertRaises(em.EmbedError) as cm:
            em.embed(m, self.out, env=self.env)
        self.assertIn("serves 64-dim", str(cm.exception))
        self.assertFalse(os.path.exists(em.vectors_path(self.out)))  # refused before opening the store

    def test_embed_unreachable_fails_closed(self):
        m = manifest(self.root)
        self.prep(m)
        em.chunk(m, self.out)
        with self.assertRaises(em.EmbedError):
            em.embed(m, self.out, env={"EMBED_URL": "http://127.0.0.1:9"})

    def test_embed_writes_reuses_and_keeps_old_models(self):
        m = manifest(self.root)
        self.prep(m)
        em.chunk(m, self.out)
        s1 = em.embed(m, self.out, env=self.env)
        n = s1["counts"]["unique"]  # repeated paragraphs share a chunk id
        self.assertLess(n, s1["counts"]["chunks"])
        self.assertEqual(s1["counts"]["embedded"], n)
        self.assertEqual(s1["endpoint"], "stub-model@%s(ollama)" % self.url)
        # batches of 4 + one probe call
        embed_calls = [c for c in _Stub.calls if c[0] == "/api/embed"]
        self.assertEqual(sum(c[2] for c in embed_calls), n + 1)
        self.assertTrue(all(c[2] <= 4 for c in embed_calls))
        # second run: nothing re-embedded
        s2 = em.embed(m, self.out, env=self.env)
        self.assertEqual((s2["counts"]["embedded"], s2["counts"]["reused"]), (0, n))
        # a second model ADDS rows; the first model's rows survive
        m2 = manifest(self.root, model="other-model")
        s3 = em.embed(m2, self.out, env=self.env)
        self.assertEqual(s3["counts"]["embedded"], n)
        self.assertEqual(sorted(x["model"] for x in s3["models_in_store"]), ["other-model", "stub-model"])
        self.assertEqual(self.db("SELECT COUNT(*) FROM vectors WHERE model='stub-model'")[0][0], n)

    def test_stale_vectors_are_kept_and_counted(self):
        m = manifest(self.root)
        self.prep(m)
        em.chunk(m, self.out)
        em.embed(m, self.out, env=self.env)
        before = self.db("SELECT COUNT(*) FROM vectors")[0][0]
        self.put("routers.txt", "completely different content now.")
        self.prep(m)
        em.chunk(m, self.out)
        s = em.embed(m, self.out, env=self.env)
        self.assertGreater(s["stale_vectors"], 0)
        self.assertGreaterEqual(self.db("SELECT COUNT(*) FROM vectors")[0][0], before)
        # unchanged doc's chunks were reused, not re-embedded
        self.assertGreater(s["counts"]["reused"], 0)

    def test_openai_autodetect_and_forced_api(self):
        _Stub.serve = ("openai",)
        m = manifest(self.root)
        self.prep(m)
        em.chunk(m, self.out)
        s = em.embed(m, self.out, env=self.env)
        self.assertTrue(s["endpoint"].endswith("(openai)"))
        with self.assertRaises(em.EmbedError):
            em.embed(m, self.out, env=dict(self.env, EMBED_API="ollama"))
        with self.assertRaises(em.EmbedError):
            em.build_endpoint(m, dict(self.env, EMBED_API="magic"))

    def test_search_ranks_the_right_document(self):
        m = manifest(self.root)
        self.prep(m)
        em.chunk(m, self.out)
        em.embed(m, self.out, env=self.env)
        hits = em.search(m, self.out, "firewall vlan router", k=3, env=self.env)
        self.assertEqual(len(hits), 3)
        self.assertIn("router", hits[0]["text"])
        self.assertNotIn("apples", hits[0]["text"])
        hits = em.search(m, self.out, "pears and plums", k=1, env=self.env)
        self.assertIn("apples", hits[0]["text"])
        self.assertTrue(0 < hits[0]["score"] <= 1.0)
        # a model with no vectors yields nothing, not an error
        self.assertEqual(em.search(manifest(self.root, model="nope"), self.out, "x", env=self.env), [])


if __name__ == "__main__":
    unittest.main()
