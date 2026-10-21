"""bastion agent `chunk` + `embed` stages, and the local `search` that proves them.

chunk   sanitized store -> <out>/chunks.jsonl
        Overlapping windows sized in approximate tokens (manifest
        embed.chunk.size_tokens / overlap_tokens). "Token" here is a
        deterministic regex unit (a word or a punctuation mark), not a
        model tokenizer: the stdlib has none, and the same text must chunk
        identically on every machine. Chunk id = sha256(doc sha, window
        text) — content-addressed, so an unchanged document keeps its
        vectors; a changed document has a new sha and is embedded again.

embed   chunks -> <out>/vectors.db (SQLite, stdlib)
        The endpoint is resolved from the environment at run time
        (EMBED_URL, default the local Ollama port), never the manifest;
        the manifest pins the MODEL and DIM. Before the first real call
        the stage embeds a probe and refuses to run if the served
        dimension is not the manifest's — a wrong model never writes a
        vector. Two wire formats, auto-detected: Ollama /api/embed and
        OpenAI-style /v1/embeddings (llama.cpp server, TEI).
        Rows are keyed (chunk_id, model): switching models ADDS rows and
        never deletes the old ones, so going back to an earlier model
        costs nothing and no vector is ever thrown away.

search  embed the query the same way, cosine over every vector of the
        manifest's model, return the top-k sanitized chunks. Pure Python;
        fine to tens of thousands of chunks, which is the point where a
        real index is a follow-up.
"""

import array
import datetime as _dt
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
import urllib.error
import urllib.request

from .manifest import signing_digest
from .sanitize import store_path as sanitized_store_path

CHUNK_VERSION = 1
DEFAULT_EMBED_URL = "http://127.0.0.1:11434"   # local Ollama; a sensor, resolved at run time
EMBED_BATCH = 32
EMBED_TIMEOUT = 300.0
PROBE_TEXT = "freeagent embedding probe"

TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


class EmbedError(Exception):
    """Fail-closed stop: the endpoint is unreachable or serves the wrong model."""


# ── chunking ────────────────────────────────────────────────────────────────

def count_tokens(text):
    return len(TOKEN_RE.findall(text))


def chunk_text(text, size_tokens, overlap_tokens):
    """Yield (start, end, window_text). Windows are cut at token
    boundaries; the step is size - overlap tokens; the last window may be
    shorter. Every character of text is inside at least one window."""
    spans = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
    if not spans:
        return
    step = max(1, size_tokens - overlap_tokens)
    i = 0
    n = len(spans)
    while True:
        j = min(n, i + size_tokens)
        start = 0 if i == 0 else spans[i][0]
        end = len(text) if j == n else spans[j - 1][1]
        yield start, end, text[start:end]
        if j >= n:
            return
        i += step


def chunk_id(doc_sha, window_text):
    h = hashlib.sha256()
    h.update(doc_sha.encode("ascii"))
    h.update(b"\x00")
    h.update(window_text.encode("utf-8"))
    return h.hexdigest()


def _atomic_write_text(path, text):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_sanitized_index(out_dir):
    path = os.path.join(out_dir, "sanitize.jsonl")
    if not os.path.exists(path):
        raise FileNotFoundError("no sanitize index at %s — run the sanitize stage first" % path)
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh]


def chunk(manifest, out_dir, now=None):
    cfg = manifest.embed
    if cfg is None:
        raise EmbedError("manifest has no embed section / stage")
    records = load_sanitized_index(out_dir)
    counts = {"docs": 0, "chunks": 0, "skipped": 0}
    seen_docs = set()
    rows = []
    for rec in records:
        if rec.get("status") != "ok":
            counts["skipped"] += 1
            continue
        sha = rec["sha256"]
        if sha in seen_docs:
            continue  # duplicate content chunks once; paths resolve through sanitize.jsonl
        seen_docs.add(sha)
        counts["docs"] += 1
        with open(sanitized_store_path(out_dir, sha), encoding="utf-8") as fh:
            text = fh.read()
        for idx, (start, end, window) in enumerate(
                chunk_text(text, cfg.chunk_size_tokens, cfg.chunk_overlap_tokens)):
            rows.append({"chunk_id": chunk_id(sha, window), "doc": sha, "idx": idx,
                         "start": start, "end": end, "chars": len(window),
                         "tokens": count_tokens(window), "v": CHUNK_VERSION})
            counts["chunks"] += 1
    rows.sort(key=lambda r: (r["doc"], r["idx"]))
    _atomic_write_text(os.path.join(out_dir, "chunks.jsonl"), "".join(
        json.dumps(r, sort_keys=True) + "\n" for r in rows))
    summary = {
        "freeagent": 1, "stage": "chunk", "chunk_version": CHUNK_VERSION,
        "manifest_id": manifest.id,
        "manifest_digest": "sha256:" + signing_digest(manifest.raw),
        "chunked_at": now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "size_tokens": cfg.chunk_size_tokens, "overlap_tokens": cfg.chunk_overlap_tokens,
        "counts": counts,
    }
    _atomic_write_text(os.path.join(out_dir, "chunk.summary.json"),
                       json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ── the vector store ────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
  chunk_id TEXT PRIMARY KEY,
  doc      TEXT NOT NULL,
  idx      INTEGER NOT NULL,
  start    INTEGER NOT NULL,
  end      INTEGER NOT NULL,
  text     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chunks_doc ON chunks(doc, idx);
CREATE TABLE IF NOT EXISTS vectors (
  chunk_id TEXT NOT NULL,
  model    TEXT NOT NULL,
  dim      INTEGER NOT NULL,
  vec      BLOB NOT NULL,
  created  TEXT NOT NULL,
  PRIMARY KEY (chunk_id, model)
);
CREATE INDEX IF NOT EXISTS vectors_model ON vectors(model);
"""


def vectors_path(out_dir):
    return os.path.join(out_dir, "vectors.db")


def open_store(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    conn = sqlite3.connect(vectors_path(out_dir), timeout=30)
    conn.executescript(_SCHEMA)
    return conn


def pack(vec):
    a = array.array("f", vec)
    return a.tobytes()


def unpack(blob):
    a = array.array("f")
    a.frombytes(blob)
    return a


# ── the endpoint (a sensor) ─────────────────────────────────────────────────

class Endpoint:
    """Local embedding endpoint. `api` is 'ollama' or 'openai'; None
    auto-detects on the probe."""

    def __init__(self, url, model, api=None, timeout=EMBED_TIMEOUT):
        self.url = url.rstrip("/")
        self.model = model
        self.api = api
        self.timeout = timeout

    def _post(self, path, body):
        req = urllib.request.Request(
            self.url + path, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp), None
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:200]
            except Exception:
                pass
            return None, "HTTP %d %s" % (e.code, detail)
        except (OSError, ValueError) as e:
            return None, str(e)

    def _ollama(self, texts):
        data, err = self._post("/api/embed", {"model": self.model, "input": texts})
        if err:
            return None, err
        try:
            return [list(map(float, v)) for v in data["embeddings"]], None
        except (KeyError, TypeError, ValueError) as e:
            return None, "malformed ollama response: %s" % e

    def _openai(self, texts):
        data, err = self._post("/v1/embeddings", {"model": self.model, "input": texts})
        if err:
            return None, err
        try:
            items = sorted(data["data"], key=lambda d: d.get("index", 0))
            return [list(map(float, d["embedding"])) for d in items], None
        except (KeyError, TypeError, ValueError) as e:
            return None, "malformed embeddings response: %s" % e

    def embed(self, texts):
        if self.api == "ollama":
            vecs, err = self._ollama(texts)
        elif self.api == "openai":
            vecs, err = self._openai(texts)
        else:
            vecs, err = self._ollama(texts)
            if vecs is not None:
                self.api = "ollama"
            else:
                vecs, err2 = self._openai(texts)
                if vecs is not None:
                    self.api = "openai"
                else:
                    err = "ollama: %s; openai: %s" % (err, err2)
        if vecs is None:
            raise EmbedError("embedding endpoint %s (model %s): %s" % (self.url, self.model, err))
        if len(vecs) != len(texts):
            raise EmbedError("endpoint returned %d vectors for %d inputs" % (len(vecs), len(texts)))
        return vecs

    def probe(self, want_dim):
        vec = self.embed([PROBE_TEXT])[0]
        if len(vec) != want_dim:
            raise EmbedError("model %s serves %d-dim vectors; manifest pins %d — refusing to write"
                             % (self.model, len(vec), want_dim))
        return len(vec)

    def describe(self):
        return "%s@%s(%s)" % (self.model, self.url, self.api or "auto")


def build_endpoint(manifest, env):
    url = env.get("EMBED_URL", DEFAULT_EMBED_URL).strip() or DEFAULT_EMBED_URL
    api = env.get("EMBED_API", "").strip().lower() or None
    if api not in (None, "ollama", "openai"):
        raise EmbedError("EMBED_API=%r is not ollama|openai" % api)
    return Endpoint(url, manifest.embed.model, api=api,
                    timeout=float(env.get("EMBED_TIMEOUT", EMBED_TIMEOUT)))


# ── embed stage ─────────────────────────────────────────────────────────────

def load_chunks(out_dir):
    path = os.path.join(out_dir, "chunks.jsonl")
    if not os.path.exists(path):
        raise FileNotFoundError("no chunks at %s — run the chunk stage first" % path)
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh]


def embed(manifest, out_dir, env=None, endpoint=None, now=None, batch=None):
    cfg = manifest.embed
    if cfg is None:
        raise EmbedError("manifest has no embed section / stage")
    env = dict(os.environ) if env is None else env
    ep = endpoint or build_endpoint(manifest, env)
    batch = batch or int(env.get("EMBED_BATCH", EMBED_BATCH))
    chunks = load_chunks(out_dir)
    ep.probe(cfg.dim)

    conn = open_store(out_dir)
    counts = {"chunks": len(chunks), "unique": 0, "embedded": 0, "reused": 0, "docs": 0}
    try:
        have = {r[0] for r in conn.execute("SELECT chunk_id FROM vectors WHERE model=?", (cfg.model,))}
        # chunk texts come from the sanitized store, sliced by recorded offsets
        texts = {}
        docs = {}
        for c in chunks:
            docs.setdefault(c["doc"], []).append(c)
        counts["docs"] = len(docs)
        for doc, cs in docs.items():
            with open(sanitized_store_path(out_dir, doc), encoding="utf-8") as fh:
                text = fh.read()
            for c in cs:
                texts[c["chunk_id"]] = text[c["start"]:c["end"]]
        # `chunks` is derived from THIS sweep (rebuilt each run); `vectors`
        # is the durable store and is only ever added to.
        with conn:
            conn.execute("DELETE FROM chunks")
            conn.executemany(
                "INSERT OR REPLACE INTO chunks(chunk_id, doc, idx, start, end, text) VALUES (?,?,?,?,?,?)",
                [(c["chunk_id"], c["doc"], c["idx"], c["start"], c["end"], texts[c["chunk_id"]])
                 for c in chunks])
        # identical windows (a repeated paragraph) share a chunk id: embed once
        unique = {}
        for c in chunks:
            unique.setdefault(c["chunk_id"], c)
        counts["unique"] = len(unique)
        todo = [c for c in unique.values() if c["chunk_id"] not in have]
        counts["reused"] = len(unique) - len(todo)
        stamp = now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for i in range(0, len(todo), batch):
            group = todo[i:i + batch]
            vecs = ep.embed([texts[c["chunk_id"]] for c in group])
            rows = []
            for c, v in zip(group, vecs):
                if len(v) != cfg.dim:
                    raise EmbedError("vector of dim %d for chunk %s; manifest pins %d"
                                     % (len(v), c["chunk_id"][:12], cfg.dim))
                rows.append((c["chunk_id"], cfg.model, cfg.dim, pack(v), stamp))
            with conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO vectors(chunk_id, model, dim, vec, created) VALUES (?,?,?,?,?)",
                    rows)
            counts["embedded"] += len(rows)
        # vectors for chunks that no longer exist in this sweep are kept
        # (never dump); report how many so the host can see the drift
        stale = conn.execute(
            "SELECT COUNT(*) FROM vectors v WHERE v.model=? AND NOT EXISTS "
            "(SELECT 1 FROM chunks c WHERE c.chunk_id=v.chunk_id)", (cfg.model,)).fetchone()[0]
        models = [dict(model=m, dim=d, vectors=n) for m, d, n in conn.execute(
            "SELECT model, dim, COUNT(*) FROM vectors GROUP BY model, dim ORDER BY model")]
    finally:
        conn.close()
    summary = {
        "freeagent": 1, "stage": "embed",
        "manifest_id": manifest.id,
        "manifest_digest": "sha256:" + signing_digest(manifest.raw),
        "embedded_at": now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endpoint": ep.describe(), "model": cfg.model, "dim": cfg.dim,
        "counts": counts, "stale_vectors": stale, "models_in_store": models,
        "store": vectors_path(out_dir),
    }
    _atomic_write_text(os.path.join(out_dir, "embed.summary.json"),
                       json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ── search ──────────────────────────────────────────────────────────────────

def cosine(a, b):
    dot = na = nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / math.sqrt(na * nb)


def search(manifest, out_dir, query, k=5, env=None, endpoint=None):
    cfg = manifest.embed
    if cfg is None:
        raise EmbedError("manifest has no embed section")
    env = dict(os.environ) if env is None else env
    ep = endpoint or build_endpoint(manifest, env)
    qv = ep.embed([query])[0]
    if len(qv) != cfg.dim:
        raise EmbedError("query vector dim %d != manifest dim %d" % (len(qv), cfg.dim))
    conn = open_store(out_dir)
    try:
        scored = []
        for chunk_id_, blob in conn.execute("SELECT chunk_id, vec FROM vectors WHERE model=?", (cfg.model,)):
            scored.append((cosine(qv, unpack(blob)), chunk_id_))
        scored.sort(reverse=True)
        out = []
        for score, cid in scored[:k]:
            row = conn.execute("SELECT doc, idx, start, end, text FROM chunks WHERE chunk_id=?", (cid,)).fetchone()
            if row is None:
                continue
            out.append({"score": round(score, 6), "chunk_id": cid, "doc": row[0], "idx": row[1],
                        "start": row[2], "end": row[3], "text": row[4]})
        return out
    finally:
        conn.close()
