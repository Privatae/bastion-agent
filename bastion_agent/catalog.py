"""bastion agent `catalog` stage — the curated dataset.

The catalog is what a host reasons over and what `seal` ships. One card
per file, one per directory, small and structured, built from:

    walk.jsonl          metadata (path, size, mtime, mime, hash)
    extract.jsonl       whether text came out, and how
    sanitize.jsonl      entity counts (token types minted per file)
    sanitize/<sha>.txt  the SANITIZED text — the only text this stage reads
    chunks.jsonl        chunk count per document (optional)

Outputs:
    <out>/catalog.jsonl        file cards, sorted by (root, path)
    <out>/catalog.dirs.jsonl   directory cards, sorted by (root, path)
    <out>/catalog.summary.json

Every text-derived field (title, head, keywords, summary) comes from the
sanitized store, so the catalog carries PII tokens, never values. File
and directory NAMES are plaintext by nature; they go through the rules
pass and any precision anchor in a name (an email, a card number) is
masked as [PII_TYPE] in the card. Contextual PII in a filename
("Marisol_medical.pdf") is not caught by rules — the honest limit of the
sanitize stage applies here too, and the doc says so.

The optional summarizer (manifest `summarize`) is a local chat model — a
sensor: it fills the `summary` string and nothing else, is reached via
SUMMARIZE_URL (never the manifest), sees only sanitized text, and is
cached per (document, model, version). The first failure stops
summarizing (cards still get written, `summary_error` set, exit 1).
"""

import datetime as _dt
import hashlib
import json
import math
import os
import re
import tempfile
import urllib.error
import urllib.request

from .manifest import signing_digest
from .sanitize import store_path as sanitized_store_path


def _rules_detect():
    """pii.detect.detect — a sibling package here and in the .pyz (see
    sanitize.pii_modules for why the old `tools.pii` branch is gone)."""
    from pii.detect import detect
    return detect

CATALOG_VERSION = 1
HEAD_CHARS = 300
TITLE_CHARS = 120
KEYWORDS_PER_CARD = 8
KEYWORDS_PER_DIR = 12
SUMMARY_INPUT_CHARS = 12000
SUMMARY_MAX_CHARS = 600
DEFAULT_SUMMARIZE_URL = "http://127.0.0.1:11434"
SUMMARIZE_TIMEOUT = 300.0

WORD_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)
TOKEN_MARK_RE = re.compile(r"\[PII_[A-Z_]+_\d+\]")
STOPWORDS = set("""
the and for that with this from are was were will have has had not but you your our their they them
its his her she him who what which when where why how all any can could would should may might must
into onto over under than then there here also just more most much many some such very only own same
other another each both few between about after before during while above below off out too again
further once here per via use used using does did done being been each same so if or as at by on in
of to is it be an a we us me my i no yes do go get got let new old one two three first last next see
set run make made take took like well also back down up still even ever never always often sometimes
""".split())


class CatalogError(Exception):
    pass


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


def _read_jsonl(out_dir, name, required=True):
    path = os.path.join(out_dir, name)
    if not os.path.exists(path):
        if required:
            raise FileNotFoundError("no %s at %s — run the earlier stages first" % (name, path))
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh]


# ── text facts ──────────────────────────────────────────────────────────────

def title_of(text):
    for line in text.splitlines():
        s = line.strip().lstrip("#*-= \t").strip()
        if len(s) >= 3:
            return s[:TITLE_CHARS]
    return ""


def head_of(text):
    s = re.sub(r"\s+", " ", text).strip()
    return s[:HEAD_CHARS]


def term_counts(text):
    counts = {}
    text = TOKEN_MARK_RE.sub(" ", text)  # [PII_*_n] placeholders are not keywords
    for w in WORD_RE.findall(text.lower()):
        if w in STOPWORDS:
            continue
        counts[w] = counts.get(w, 0) + 1
    return counts


def keywords(counts, df, ndocs, k):
    """Top-k terms by TF-IDF; ties broken alphabetically for determinism."""
    scored = []
    for w, tf in counts.items():
        idf = math.log((1 + ndocs) / (1 + df.get(w, 0))) + 1.0
        scored.append((-(tf * idf), w))
    scored.sort()
    return [w for _, w in scored[:k]]


def mask_name(name, detect):
    """Rules pass over a file/dir name: precision anchors -> [PII_TYPE]."""
    findings = detect(name)
    if not findings:
        return name
    out = name
    for f in sorted(findings, key=lambda f: -len(f.value)):
        out = out.replace(f.value, "[PII_%s]" % f.type)
    return out


def mask_path(path, detect):
    """Every component of a relative path through mask_name — a parent
    directory can carry an address as easily as a filename, and the file
    card's path is what seal ships. Returns (masked
    path, number of components changed)."""
    if not path:
        return path, 0
    out, changed = [], 0
    for seg in path.split("/"):
        m = mask_name(seg, detect) if seg else seg
        if m != seg:
            changed += 1
        out.append(m)
    return "/".join(out), changed


# ── the summarizer (a sensor) ───────────────────────────────────────────────

SUMMARY_PROMPT = (
    "Summarize the following document in at most three plain sentences for a catalog card: "
    "what it is, what it covers, and who or what it concerns. Placeholders like [PII_PERSON_1] "
    "stand for redacted personal data — keep them as they are, never guess what they hide. "
    "Reply with the summary only.\n\n"
)
DIR_SUMMARY_PROMPT = (
    "These are catalog entries for the files in one folder. In at most three plain sentences "
    "say what the folder is for and what kinds of material it holds. Placeholders like "
    "[PII_PERSON_1] are redacted personal data — keep them as they are. Reply with the "
    "summary only.\n\n"
)


class Summarizer:
    def __init__(self, url, model, api=None, timeout=SUMMARIZE_TIMEOUT):
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
            return None, "HTTP %d" % e.code
        except (OSError, ValueError) as e:
            return None, str(e)

    def _ollama(self, prompt):
        data, err = self._post("/api/chat", {
            "model": self.model, "stream": False, "options": {"temperature": 0},
            "messages": [{"role": "user", "content": prompt}]})
        if err:
            return None, err
        try:
            return data["message"]["content"], None
        except (KeyError, TypeError) as e:
            return None, "malformed ollama response: %s" % e

    def _openai(self, prompt):
        data, err = self._post("/v1/chat/completions", {
            "model": self.model, "temperature": 0,
            "messages": [{"role": "user", "content": prompt}]})
        if err:
            return None, err
        try:
            return data["choices"][0]["message"]["content"], None
        except (KeyError, IndexError, TypeError) as e:
            return None, "malformed chat response: %s" % e

    def complete(self, prompt):
        if self.api == "ollama":
            text, err = self._ollama(prompt)
        elif self.api == "openai":
            text, err = self._openai(prompt)
        else:
            text, err = self._ollama(prompt)
            if text is not None:
                self.api = "ollama"
            else:
                text, err2 = self._openai(prompt)
                if text is not None:
                    self.api = "openai"
                else:
                    err = "ollama: %s; openai: %s" % (err, err2)
        if text is None:
            raise CatalogError("summarizer %s (model %s): %s" % (self.url, self.model, err))
        return clean_summary(text)

    def describe(self):
        return "%s@%s(%s)" % (self.model, self.url, self.api or "auto")


def clean_summary(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)  # thinking models
    text = re.sub(r"\s+", " ", text).strip().strip('"')
    return text[:SUMMARY_MAX_CHARS]


def build_summarizer(manifest, env):
    if manifest.summarize is None:
        return None
    url = env.get("SUMMARIZE_URL", DEFAULT_SUMMARIZE_URL).strip() or DEFAULT_SUMMARIZE_URL
    api = env.get("SUMMARIZE_API", "").strip().lower() or None
    if api not in (None, "ollama", "openai"):
        raise CatalogError("SUMMARIZE_API=%r is not ollama|openai" % api)
    return Summarizer(url, manifest.summarize.model, api=api,
                      timeout=float(env.get("SUMMARIZE_TIMEOUT", SUMMARIZE_TIMEOUT)))


def _cache_path(out_dir):
    return os.path.join(out_dir, "catalog.cache.json")


def _load_cache(out_dir):
    try:
        with open(_cache_path(out_dir), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


# ── the stage ───────────────────────────────────────────────────────────────

def catalog(manifest, out_dir, env=None, summarizer=None, now=None):
    env = dict(os.environ) if env is None else env
    summ = summarizer if summarizer is not None else build_summarizer(manifest, env)
    per = set(manifest.summarize.per) if manifest.summarize else set()
    walk_rows = _read_jsonl(out_dir, "walk.jsonl")
    extract_rows = {(r["root"], r["path"]): r for r in _read_jsonl(out_dir, "extract.jsonl")}
    sanitize_rows = {(r["root"], r["path"]): r for r in _read_jsonl(out_dir, "sanitize.jsonl")}
    chunk_counts = {}
    for c in _read_jsonl(out_dir, "chunks.jsonl", required=False):
        chunk_counts[c["doc"]] = chunk_counts.get(c["doc"], 0) + 1
    detect = _rules_detect()
    cache = _load_cache(out_dir)
    stamp = now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # pass 1: text facts per distinct sanitized document
    texts = {}
    doc_terms = {}
    for key, s in sanitize_rows.items():
        if s.get("status") != "ok":
            continue
        sha = s["sha256"]
        if sha in texts:
            continue
        with open(sanitized_store_path(out_dir, sha), encoding="utf-8") as fh:
            texts[sha] = fh.read()
        doc_terms[sha] = term_counts(texts[sha])
    df = {}
    for counts in doc_terms.values():
        for w in counts:
            df[w] = df.get(w, 0) + 1
    ndocs = len(doc_terms)

    counts = {"files": 0, "with_text": 0, "dirs": 0, "summaries": 0, "summaries_reused": 0,
              "summary_errors": 0, "names_masked": 0}
    stopped = None
    summary_key = lambda sha, kind: "%s|%s|%s|v%d" % (
        kind, sha, manifest.summarize.model if manifest.summarize else "", CATALOG_VERSION)

    def summarize(kind, sha, prompt_body):
        nonlocal stopped
        if summ is None or stopped is not None:
            return None, None
        k = summary_key(sha, kind)
        if k in cache:
            counts["summaries_reused"] += 1
            return cache[k], None
        try:
            text = summ.complete((SUMMARY_PROMPT if kind == "file" else DIR_SUMMARY_PROMPT)
                                 + prompt_body[:SUMMARY_INPUT_CHARS])
        except CatalogError as e:
            stopped = str(e)
            counts["summary_errors"] += 1
            return None, stopped
        cache[k] = text
        counts["summaries"] += 1
        return text, None

    # pass 2: file cards
    cards = []
    dir_acc = {}
    for w in walk_rows:
        if w.get("kind") != "file":
            continue
        key = (w["root"], w["path"])
        counts["files"] += 1
        shown_path, changed = mask_path(w["path"], detect)
        masked = shown_path.rsplit("/", 1)[-1]
        counts["names_masked"] += changed
        e = extract_rows.get(key, {})
        s = sanitize_rows.get(key, {})
        card = {
            "root": w["root"], "path": shown_path, "name": masked, "kind": "file",
            "size": w.get("size"), "mtime": w.get("mtime"), "mime": w.get("mime"),
            "sha256": w.get("sha256"), "v": CATALOG_VERSION,
            "text": e.get("status") if e else "not_extracted",
            "extractor": e.get("extractor"),
            "sanitized": s.get("status") if s else None,
        }
        sha = s.get("sha256") if s.get("status") == "ok" else None
        if sha and sha in texts:
            text = texts[sha]
            counts["with_text"] += 1
            card.update({
                "title": title_of(text),
                "head": head_of(text),
                "chars": len(text),
                "keywords": keywords(doc_terms[sha], df, ndocs, KEYWORDS_PER_CARD),
                "entities": s.get("types", {}),
                "chunks": chunk_counts.get(sha, 0),
            })
            if "file" in per:
                summary, err = summarize("file", sha, text)
                card["summary"] = summary
                if err:
                    card["summary_error"] = err
        elif "file" in per:
            card["summary"] = None  # nothing to summarize
        cards.append(card)
        # directory aggregation: every ancestor, root included as ""
        parts = w["path"].split("/")[:-1]
        for depth in range(len(parts) + 1):
            dpath = "/".join(parts[:depth])
            acc = dir_acc.setdefault((w["root"], dpath), {
                "files": 0, "bytes": 0, "mimes": {}, "latest": "", "terms": {}, "entities": {},
                "children": [], "with_text": 0})
            acc["files"] += 1
            acc["bytes"] += w.get("size") or 0
            m = w.get("mime") or "?"
            acc["mimes"][m] = acc["mimes"].get(m, 0) + 1
            if (w.get("mtime") or "") > acc["latest"]:
                acc["latest"] = w["mtime"]
            if sha and sha in doc_terms:
                acc["with_text"] += 1
                for t, n in doc_terms[sha].items():
                    acc["terms"][t] = acc["terms"].get(t, 0) + n
                for t, n in (s.get("types") or {}).items():
                    acc["entities"][t] = acc["entities"].get(t, 0) + n
            if depth == len(parts):
                acc["children"].append(card)
    cards.sort(key=lambda c: (c["root"], c["path"]))

    # pass 3: directory cards
    dcards = []
    for (root, dpath), acc in dir_acc.items():
        shown, _ = mask_path(dpath, detect)
        masked = shown.rsplit("/", 1)[-1] if shown else ""
        mimes = sorted(acc["mimes"].items(), key=lambda kv: (-kv[1], kv[0]))[:6]
        card = {
            "root": root, "path": shown, "name": masked, "kind": "dir", "v": CATALOG_VERSION,
            "files": acc["files"], "with_text": acc["with_text"], "bytes": acc["bytes"],
            "latest": acc["latest"], "types": dict(mimes),
            "keywords": keywords(acc["terms"], df, ndocs, KEYWORDS_PER_DIR),
            "entities": acc["entities"],
        }
        if "directory" in per:
            body = "\n".join(
                "- %s: %s" % (c["name"], (c.get("summary") or c.get("head") or "")[:200])
                for c in sorted(acc["children"], key=lambda c: c["path"])[:60])
            sha = hashlib.sha256(
                ("%s|%s|" % (root, dpath)).encode("utf-8") + body.encode("utf-8")).hexdigest()
            summary, err = summarize("dir", sha, body)
            card["summary"] = summary
            if err:
                card["summary_error"] = err
        dcards.append(card)
    dcards.sort(key=lambda c: (c["root"], c["path"]))
    counts["dirs"] = len(dcards)

    _atomic_write_text(os.path.join(out_dir, "catalog.jsonl"), "".join(
        json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n" for c in cards))
    _atomic_write_text(os.path.join(out_dir, "catalog.dirs.jsonl"), "".join(
        json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n" for c in dcards))
    _atomic_write_text(_cache_path(out_dir), json.dumps(cache, ensure_ascii=False, sort_keys=True))
    summary = {
        "freeagent": 1, "stage": "catalog", "catalog_version": CATALOG_VERSION,
        "manifest_id": manifest.id,
        "manifest_digest": "sha256:" + signing_digest(manifest.raw),
        "cataloged_at": stamp,
        "summarizer": summ.describe() if summ else None,
        "summarize_per": sorted(per),
        "counts": counts, "stopped": stopped,
        "bytes_catalog": sum(len(json.dumps(c, ensure_ascii=False)) + 1 for c in cards + dcards),
    }
    _atomic_write_text(os.path.join(out_dir, "catalog.summary.json"),
                       json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return summary
