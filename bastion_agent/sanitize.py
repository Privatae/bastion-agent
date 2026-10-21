"""bastion agent `sanitize` stage — the salt.

Runs the PII sterilizer (pii) over the extract store and writes a
SECOND store:

    <out>/sanitize/<aa>/<sha256>.txt    sanitized text — PII replaced by
                                        stable [PII_TYPE_n] tokens
    <out>/sanitize/vault.db             token <-> value map, 0600, local
    <out>/sanitize.jsonl                one record per extracted file:
                                        status, mode, stats (counts only —
                                        never a value)
    <out>/sanitize.summary.json

From here on, later stages read ONLY the sanitized store. The extract
store keeps the plaintext and stays on this machine; the vault is the
only way back (`/rehydrate` semantics, local).

Two ways to reach the sterilizer, chosen from the environment, never the
manifest (no addresses in manifests — docs/pii-sterilization.md):

  in-process   the default. the pii package runs inside this process: the rules
               pass, the recall backend selected by PII_RECALL
               (llm | gliner — the laptop path), the vault under <out>.
  service      PII_ADDR (+ PII_API_KEY) set: POST /sterilize to the
               running PII service, which owns its own vault. The
               server path; the bastion advertises the capability.

Modes (manifest `sanitize.mode`):
  sterilize    rules + recall pass (+ optional adversarial verify).
  flag         rules pass ONLY — deterministic, model-free, always
               in-process. Redacts the precision anchors (emails, cards,
               keys, IBANs, …); contextual PII (names, schools) is NOT
               caught. The manifest doc says so; this docstring says so.

Fail closed: the first recall failure (model unreachable, package
missing) stops the stage — remaining files are recorded `not_run` and
nothing half-sanitized is written. Long texts are split on paragraph
boundaries per call (SANITIZE_CHUNK_CHARS); tokens are stable per scope,
so a value seen in two chunks gets one token.
"""

import datetime as _dt
import json
import os
import re
import tempfile
import urllib.error
import urllib.request

from .extract import store_path as extract_store_path
from .manifest import signing_digest

# Part of the reuse key: bump it whenever the pipeline would sterilize the
# same text differently, or a stored result from older code is kept as is.
SANITIZE_VERSION = 2
SANITIZE_CHUNK_CHARS = 20000     # per sterilize call; under the service's 2 MiB body cap
SERVICE_TIMEOUT = 600.0

STATUS_OK, STATUS_ERROR, STATUS_SKIPPED, STATUS_NOT_RUN = "ok", "error", "skipped", "not_run"


class SanitizeError(Exception):
    """Fail-closed stop: the recall pass is unavailable."""


def pii_modules():
    """The sterilizer, a SIBLING top-level package here and inside the built
    .pyz alike (build.py writes it as `pii/`). One import path: an ImportError
    here means the sterilizer is genuinely absent, which is a fail-closed stop,
    never a silent skip.

    pii.pipeline.sterilize(text, scope, vault, llm_extract, llm_verify=None)
    returning (text, result), pii.recall.build_backend (which raises
    RecallError rather than degrading) and pii.vault.Vault."""
    from pii import pipeline, recall
    from pii.vault import Vault
    return pipeline, recall, Vault


# Test seam: when set, used instead of recall.build_backend(env).
BUILD_BACKEND = None


# ── sterilizer front-ends ───────────────────────────────────────────────────

class InProcess:
    """pii inside this process. Vault lives under the output dir."""

    name = "in-process"

    def __init__(self, out_dir, mode, env, verify=False):
        pipeline, recall, Vault = pii_modules()
        self._pipeline = pipeline
        self._recall_error = recall.RecallError
        self.mode = mode
        self.verify = verify
        os.umask(0o077)
        # FREEAGENT_VAULT_DIR keeps the vault (plaintext PII values) OUT of the
        # output directory when that directory sits inside a folder that may
        # be cloud-synced (<root>/.agent). The bastion sets it to its own
        # state dir; the default stays beside the output for a hand-run agent.
        vault_dir = (env or {}).get("FREEAGENT_VAULT_DIR", "").strip()
        vault_path = (os.path.join(vault_dir, "vault.db") if vault_dir
                      else os.path.join(out_dir, "sanitize", "vault.db"))
        self.vault = Vault(vault_path)
        try:
            os.chmod(self.vault.path, 0o600)
        except OSError:
            pass
        if mode == "flag":
            self.backend = None
            self.describe = "flag:rules-only"
        else:
            build = BUILD_BACKEND or recall.build_backend
            try:
                self.backend = build(env)
            except recall.RecallError as e:
                raise SanitizeError(str(e))
            self.describe = "sterilize:" + self.backend.describe()

    def sterilize(self, text, scope):
        if self.backend is None:
            extract_fn, verify_fn = (lambda t: []), None
        else:
            extract_fn = self.backend.extract
            verify_fn = self.backend.verify if self.verify else None
        try:
            # documents are raw files, never this pipeline's output: every
            # placeholder-shaped literal in one is escaped
            return self._pipeline.sterilize(text, scope, self.vault, extract_fn, verify_fn,
                                            escape_held_literals=True)
        except self._recall_error as e:
            raise SanitizeError("recall pass failed: %s" % e)


class Service:
    """The running PII service over HTTP. It owns the vault."""

    name = "service"

    def __init__(self, addr, api_key, verify=False, timeout=SERVICE_TIMEOUT):
        if not api_key:
            raise SanitizeError("PII_ADDR set but PII_API_KEY empty — the service is fail-closed")
        self.url = ("http://" + addr if "://" not in addr else addr).rstrip("/")
        self.api_key = api_key
        self.verify = verify
        self.timeout = timeout
        self.describe = "service:" + self.url

    def sterilize(self, text, scope):
        body = json.dumps({"text": text, "scope": scope, "verify": self.verify,
                           "escape_held_literals": True}).encode("utf-8")
        req = urllib.request.Request(
            self.url + "/sterilize", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 502:
                raise SanitizeError("pii service: recall pass unavailable (502)")
            raise RuntimeError("pii service HTTP %d" % e.code)
        except (OSError, ValueError) as e:
            raise SanitizeError("pii service unreachable: %s" % e)
        stats = dict(payload.get("stats", {}))
        # a service that predates the field ignores it and applies the narrower
        # rule silently; without its echo the document cannot be trusted
        if stats.pop("escape_held_literals", None) is not True:
            raise SanitizeError("the pii service did not honour escape_held_literals "
                                "(no echo in its stats); upgrade the service")
        return payload["text"], {"findings": payload.get("findings", []), "stats": stats}


def build_front_end(out_dir, sanitize_cfg, env):
    if sanitize_cfg.mode == "flag":
        return InProcess(out_dir, "flag", env)
    addr = env.get("PII_ADDR", "").strip()
    if addr:
        return Service(addr, env.get("PII_API_KEY", ""), verify=sanitize_cfg.verify)
    return InProcess(out_dir, "sterilize", env, verify=sanitize_cfg.verify)


# ── helpers ─────────────────────────────────────────────────────────────────

# Same shape as pii.pipeline.TOKEN_RE (a test keeps them equal). Kept here so
# splitting needs no pii import; the sterilizer is loaded fail-closed elsewhere.
_PLACEHOLDER_RE = re.compile(r"\[PII_([A-Z_]+)_(\d+)\]")


def _clear_of_placeholder(piece, limit):
    """A hard cut at limit, moved back to before the '[' of a placeholder it
    would split. Each half of a split placeholder would reach the sterilizer
    as unrecognised text and be stored unescaped. A placeholder at the very
    start is kept whole instead, so the chunk may run over the limit by the
    rest of the placeholder.

    A placeholder has no '[' after its first character, so the only one that
    can straddle the cut starts at the last '[' before it: exact at any
    placeholder length, with no search window."""
    start = piece.rfind("[", 0, limit)
    if start >= 0:
        m = _PLACEHOLDER_RE.match(piece, start)
        if m and m.end() > limit:
            return start if start > 0 else m.end()
    return limit


def split_chunks(text, limit=None):
    """Split on paragraph, then line, boundaries; a single oversized line
    is cut hard. Concatenation of the chunks is byte-identical to text.
    The default limit is read when called, so a changed
    SANITIZE_CHUNK_CHARS takes effect."""
    if limit is None:
        limit = SANITIZE_CHUNK_CHARS
    if not text:
        return []
    if len(text) <= limit:
        return [text]
    parts = text.split("\n\n")
    paras = [p + ("\n\n" if i < len(parts) - 1 else "") for i, p in enumerate(parts)]
    out, buf = [], ""
    for piece in paras:
        if len(buf) + len(piece) <= limit:
            buf += piece
            continue
        if buf:
            out.append(buf)
            buf = ""
        while len(piece) > limit:
            cut = piece.rfind("\n", 0, limit)
            cut = _clear_of_placeholder(piece, limit) if cut <= 0 else cut + 1
            out.append(piece[:cut])
            piece = piece[cut:]
        buf = piece
    if buf:
        out.append(buf)
    return [c for c in out if c]


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


def store_path(out_dir, sha):
    return os.path.join(out_dir, "sanitize", sha[:2], sha + ".txt")


def load_extract_index(out_dir):
    path = os.path.join(out_dir, "extract.jsonl")
    if not os.path.exists(path):
        raise FileNotFoundError("no extract index at %s — run the extract stage first" % path)
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh]


def load_index(out_dir):
    idx = {}
    try:
        with open(os.path.join(out_dir, "sanitize.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("sha256"):
                    idx[rec["sha256"]] = rec
    except OSError:
        pass
    return idx


def _cache_key(front, cfg):
    return "%s|%s|%s|%s|v%d" % (front.name, cfg.mode, cfg.scope, cfg.verify, SANITIZE_VERSION)


def _merge_stats(acc, stats):
    for k, v in stats.items():
        if isinstance(v, int):
            acc[k] = acc.get(k, 0) + v
        else:
            acc[k] = v


# ── the stage ───────────────────────────────────────────────────────────────

def sanitize(manifest, out_dir, env=None, now=None, front_end=None):
    cfg = manifest.sanitize
    if cfg is None:
        raise SanitizeError("manifest has no sanitize section / stage")
    env = dict(os.environ) if env is None else env
    front = front_end or build_front_end(out_dir, cfg, env)
    key = _cache_key(front, cfg)
    extracted = load_extract_index(out_dir)
    prev = load_index(out_dir)
    counts = {k: 0 for k in ("files", "ok", "reused", "skipped", "error", "not_run")}
    type_counts = {}
    index = []
    done = {}
    stopped = None

    for rec in extracted:
        counts["files"] += 1
        sha = rec.get("sha256")
        base = {"root": rec["root"], "path": rec["path"], "sha256": sha,
                "mode": cfg.mode, "v": SANITIZE_VERSION}
        if rec.get("status") not in ("ok",):
            counts["skipped"] += 1
            index.append(dict(base, status=STATUS_SKIPPED, error="extract: " + str(rec.get("status"))))
            continue
        if sha in done:
            dup = done[sha]
            index.append(dict(dup, root=rec["root"], path=rec["path"]))
            counts["reused" if dup.get("reused") else dup["status"]] += 1
            continue
        if stopped is not None:
            out = dict(base, status=STATUS_NOT_RUN, error=stopped)
            counts["not_run"] += 1
            index.append(out)
            done[sha] = out
            continue
        spath = store_path(out_dir, sha)
        old = prev.get(sha)
        if old and old.get("status") == STATUS_OK and old.get("key") == key and os.path.exists(spath):
            out = dict(base, status=STATUS_OK, key=key, stats=old.get("stats", {}),
                       types=old.get("types", {}), chars=old.get("chars", 0), reused=True)
            counts["reused"] += 1
            index.append(out)
            done[sha] = out
            continue
        try:
            with open(extract_store_path(out_dir, sha), encoding="utf-8") as fh:
                text = fh.read()
        except OSError as e:
            out = dict(base, status=STATUS_ERROR, error="extract store: %s" % e)
            counts["error"] += 1
            index.append(out)
            done[sha] = out
            continue
        pieces, stats, types = [], {}, {}
        try:
            for chunk in split_chunks(text):
                clean, res = front.sterilize(chunk, cfg.scope)
                pieces.append(clean)
                _merge_stats(stats, res.get("stats", {}))
                for f in res.get("findings", []):
                    t = f.get("type", "?")
                    types[t] = types.get(t, 0) + 1
        except SanitizeError as e:
            stopped = str(e)
            out = dict(base, status=STATUS_NOT_RUN, error=stopped)
            counts["not_run"] += 1
            index.append(out)
            done[sha] = out
            continue
        except (RuntimeError, ValueError, KeyError) as e:
            out = dict(base, status=STATUS_ERROR, error="%s: %s" % (type(e).__name__, e))
            counts["error"] += 1
            index.append(out)
            done[sha] = out
            continue
        clean = "".join(pieces)
        _atomic_write_text(spath, clean)
        out = dict(base, status=STATUS_OK, key=key, stats=stats, types=types, chars=len(clean))
        counts["ok"] += 1
        for t, n in types.items():
            type_counts[t] = type_counts.get(t, 0) + n
        index.append(out)
        done[sha] = out

    index.sort(key=lambda r: (r["root"], r["path"]))
    _atomic_write_text(os.path.join(out_dir, "sanitize.jsonl"), "".join(
        json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in index))
    summary = {
        "freeagent": 1,
        "stage": "sanitize",
        "sanitize_version": SANITIZE_VERSION,
        "manifest_id": manifest.id,
        "manifest_digest": "sha256:" + signing_digest(manifest.raw),
        "sanitized_at": now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": cfg.mode,
        "scope": cfg.scope,
        "verify": cfg.verify,
        "sterilizer": front.describe,
        "counts": counts,
        "types": type_counts,
        "stopped": stopped,
        "entries": len(index),
    }
    _atomic_write_text(os.path.join(out_dir, "sanitize.summary.json"),
                       json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return summary
