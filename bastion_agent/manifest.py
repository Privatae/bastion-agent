"""bastion agent job-manifest loader — the only way tools read a manifest.

Validation collects every problem before raising, so one run reports the whole
file. See docs/manifest.md for the format contract. The loader fixes
the *shape* and the signing payload; cryptographic verification of the
signature belongs to the runtime (run.py, x509gate.py), never here.
"""

import base64
import datetime as _dt
import hashlib
import json
import re
from dataclasses import dataclass

import yaml

SCHEMA_VERSION = 1

# The agent lives WITH its folder: <root>/.agent/ holds the manifest and every
# prepared output (catalog, sanitized index, vectors, run log). The walker
# always excludes it, so an agent never indexes its own output. Secrets (the
# PII vault, the identity key) are NOT kept there — a Documents folder is
# often cloud-synced — see FREEAGENT_VAULT_DIR and the bastion's state dir.
AGENT_DIR = ".agent"

SLUG_RE = re.compile(r"^[a-z0-9-]+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# a root must mean the same place wherever the manifest lands: POSIX absolute,
# home-relative, Windows drive-absolute (C:\ or C:/), or UNC (\\server\share)
ROOT_RE = re.compile(r"^(/|~$|~/|[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)")

TOP_KEYS_REQUIRED = ("freeagent", "id", "owner", "scope", "mask", "stages", "sweep", "sink")
TOP_KEYS_OPTIONAL = ("sanitize", "embed", "summarize", "grants", "signature")

MASK_OPS = ("read", "search", "index", "summarize")
MASK_MANDATORY = "read"

# canonical stage order; a manifest's stages must be a subset in this order
STAGES = ("walk", "extract", "sanitize", "chunk", "embed", "catalog", "seal")
# chunk and catalog read the SANITIZED store, so they need sanitize, not
# merely extract (the runtime failed closed, the schema should
# have refused first)
STAGE_NEEDS_STAGE = {
    "extract": "walk",
    "sanitize": "extract",
    "chunk": "sanitize",
    "embed": "chunk",
    "catalog": "sanitize",
    "seal": "catalog",
}
STAGE_NEEDS_OP = {"embed": "index", "catalog": "index"}

SANITIZE_MODES = ("sterilize", "flag")
SUMMARIZE_PER = ("file", "directory")
SWEEPS = ("15m", "hourly", "daily", "manual")  # same vocabulary as the platform context store
SINK_CATALOG = ("local", "host")
SINK_VECTORS = ("local",)
SINK_PLAINTEXT = "never"  # a constant, not a setting
GRANT_OPS = ("search", "read_range")
GRANT_OP_NEEDS_MASK = {"search": "search", "read_range": "read"}
SIGNATURE_ALGS = ("ecdsa-p256-sha256",)

DEFAULT_MAX_FILE_BYTES = 256 * 1024 * 1024


class ManifestError(Exception):
    """Raised with every validation error joined into one message."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__(
            "manifest validation failed:\n" + "\n".join(f"  - {e}" for e in self.errors)
        )


@dataclass(frozen=True)
class Scope:
    roots: tuple
    exclude: tuple = ()
    follow_symlinks: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES


@dataclass(frozen=True)
class Sanitize:
    mode: str
    scope: str
    verify: bool = False


@dataclass(frozen=True)
class Embed:
    model: str
    dim: int
    chunk_size_tokens: int
    chunk_overlap_tokens: int


@dataclass(frozen=True)
class Summarize:
    model: str
    per: tuple


@dataclass(frozen=True)
class Sink:
    catalog: str
    vectors: str = "local"
    plaintext: str = SINK_PLAINTEXT
    seal_to: tuple = ()


@dataclass(frozen=True)
class Grant:
    host: str
    ops: tuple
    until: _dt.date


@dataclass(frozen=True)
class Signature:
    alg: str
    cert: str
    value: str


@dataclass(frozen=True)
class Manifest:
    id: str
    owner_host: str
    scope: Scope
    mask: tuple
    stages: tuple
    sweep: str
    sink: Sink
    sanitize: Sanitize = None
    embed: Embed = None
    summarize: Summarize = None
    grants: tuple = ()
    signature: Signature = None
    raw: dict = None  # the parsed document, for signing_payload()

    @property
    def signed(self):
        return self.signature is not None

    def has_stage(self, name):
        return name in self.stages


# ── signing payload ─────────────────────────────────────────────────────────

def signing_payload(doc):
    """Bytes the signature covers: the document minus `signature`, as
    canonical JSON (sorted keys, no whitespace, UTF-8). Signer and runtime
    must agree byte-for-byte, so this is the single definition."""
    body = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=_canonical_scalar,
    ).encode("utf-8")


def _canonical_scalar(obj):
    # YAML parses a bare 2026-12-31 as a date; a quoted one stays a string.
    # Both must sign to the same bytes, so dates canonicalise to ISO text.
    if isinstance(obj, _dt.date) and not isinstance(obj, _dt.datetime):
        return obj.isoformat()
    raise TypeError(f"signing payload cannot contain {type(obj).__name__}")


def signing_digest(doc):
    return hashlib.sha256(signing_payload(doc)).hexdigest()


# ── helpers ─────────────────────────────────────────────────────────────────

def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_str(v, lo=1, hi=None):
    return isinstance(v, str) and len(v) >= lo and (hi is None or len(v) <= hi)


def _check_keys(where, raw, required, optional, errors):
    """Unknown/missing key check. Returns True when the key set is clean."""
    if not isinstance(raw, dict):
        errors.append(f"{where}: must be a map")
        return False
    unknown = set(raw) - set(required) - set(optional)
    for key in sorted(unknown, key=str):
        errors.append(f"{where}: unknown key {key!r}")
    missing = [k for k in required if k not in raw]
    if missing:
        errors.append(f"{where}: missing required key(s): {', '.join(missing)}")
    return not unknown and not missing


def _str_list(where, key, val, errors, allowed=None, nonempty=True, hi=None):
    """Validate a list of strings (optionally from a closed vocabulary, no
    duplicates). Returns the tuple, or None when invalid."""
    if not isinstance(val, list) or not all(isinstance(s, str) for s in val):
        errors.append(f"{where}: {key} must be a list of strings")
        return None
    if nonempty and not val:
        errors.append(f"{where}: {key} must not be empty")
        return None
    ok = True
    if allowed is not None:
        bad = [s for s in val if s not in allowed]
        if bad:
            errors.append(f"{where}: {key} has value(s) not in {allowed}: {bad}")
            ok = False
    if hi is not None:
        long = [s for s in val if not _is_str(s, 1, hi)]
        if long:
            errors.append(f"{where}: {key} entries must be 1-{hi} chars: {long}")
            ok = False
    dupes = sorted({s for s in val if val.count(s) > 1})
    if dupes:
        errors.append(f"{where}: {key} has duplicate(s): {dupes}")
        ok = False
    return tuple(val) if ok else None


# ── sections ────────────────────────────────────────────────────────────────

def _validate_scope(raw, errors):
    where = "scope"
    if not _check_keys(where, raw, ("roots",), ("exclude", "follow_symlinks", "max_file_bytes"), errors):
        return None
    ok = True
    roots = _str_list(where, "roots", raw.get("roots"), errors)
    if roots is not None:
        bad = [r for r in roots if not ROOT_RE.match(r)]
        if bad:
            errors.append(
                f"{where}: roots must be absolute (/, C:\\, \\\\server\\share) or start with '~/': {bad}"
            )
            ok = False
    else:
        ok = False
    exclude = _str_list(where, "exclude", raw.get("exclude", []), errors, nonempty=False)
    if exclude is None:
        ok = False
    follow = raw.get("follow_symlinks", False)
    if not isinstance(follow, bool):
        errors.append(f"{where}: follow_symlinks must be a boolean")
        ok = False
    max_bytes = raw.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not _is_int(max_bytes) or max_bytes < 1:
        errors.append(f"{where}: max_file_bytes must be a positive integer")
        ok = False
    if not ok:
        return None
    return Scope(roots=roots, exclude=exclude, follow_symlinks=follow, max_file_bytes=max_bytes)


def _validate_stages(raw, errors):
    stages = _str_list("stages", "stages", raw, errors, allowed=STAGES)
    if stages is None:
        return None
    ok = True
    if stages[0] != "walk":
        errors.append("stages: 'walk' must be present and first")
        ok = False
    order = [STAGES.index(s) for s in stages]
    if order != sorted(order):
        errors.append(f"stages: must follow the canonical order {STAGES}")
        ok = False
    for s in stages:
        need = STAGE_NEEDS_STAGE.get(s)
        if need and need not in stages:
            errors.append(f"stages: {s!r} requires {need!r}")
            ok = False
    return stages if ok else None


def _validate_sanitize(raw, manifest_id, errors):
    where = "sanitize"
    if not _check_keys(where, raw, ("mode",), ("scope", "verify"), errors):
        return None
    ok = True
    mode = raw.get("mode")
    if mode not in SANITIZE_MODES:
        errors.append(f"{where}: mode {mode!r} is not one of {SANITIZE_MODES}")
        ok = False
    scope = raw.get("scope", manifest_id)
    if not _is_str(scope, 1, 63):
        errors.append(f"{where}: scope must be a string of 1-63 chars")
        ok = False
    verify = raw.get("verify", False)
    if not isinstance(verify, bool):
        errors.append(f"{where}: verify must be a boolean")
        ok = False
    elif verify and mode == "flag":
        errors.append(f"{where}: verify is only valid with mode 'sterilize' (flag is rules-only)")
        ok = False
    if not ok:
        return None
    return Sanitize(mode=mode, scope=scope, verify=verify)


def _validate_embed(raw, errors):
    where = "embed"
    if not _check_keys(where, raw, ("model", "dim", "chunk"), (), errors):
        return None
    ok = True
    model = raw.get("model")
    if not _is_str(model, 1, 128):
        errors.append(f"{where}: model must be a string of 1-128 chars")
        ok = False
    dim = raw.get("dim")
    if not _is_int(dim) or not 1 <= dim <= 8192:
        errors.append(f"{where}: dim must be an integer 1-8192")
        ok = False
    chunk = raw.get("chunk")
    size = overlap = None
    if _check_keys(f"{where}.chunk", chunk, ("size_tokens", "overlap_tokens"), (), errors):
        size = chunk.get("size_tokens")
        overlap = chunk.get("overlap_tokens")
        if not _is_int(size) or not 1 <= size <= 8192:
            errors.append(f"{where}.chunk: size_tokens must be an integer 1-8192")
            ok = False
        if not _is_int(overlap) or overlap < 0:
            errors.append(f"{where}.chunk: overlap_tokens must be a non-negative integer")
            ok = False
        elif _is_int(size) and overlap >= size:
            errors.append(f"{where}.chunk: overlap_tokens must be smaller than size_tokens")
            ok = False
    else:
        ok = False
    if not ok:
        return None
    return Embed(model=model, dim=dim, chunk_size_tokens=size, chunk_overlap_tokens=overlap)


def _validate_summarize(raw, errors):
    where = "summarize"
    if not _check_keys(where, raw, ("model", "per"), (), errors):
        return None
    model = raw.get("model")
    ok = True
    if not _is_str(model, 1, 128):
        errors.append(f"{where}: model must be a string of 1-128 chars")
        ok = False
    per = _str_list(where, "per", raw.get("per"), errors, allowed=SUMMARIZE_PER)
    if per is None:
        ok = False
    return Summarize(model=model, per=per) if ok else None


def _validate_sink(raw, errors):
    where = "sink"
    if not _check_keys(where, raw, ("catalog", "vectors", "plaintext"), ("seal_to",), errors):
        return None
    ok = True
    catalog = raw.get("catalog")
    if catalog not in SINK_CATALOG:
        errors.append(f"{where}: catalog {catalog!r} is not one of {SINK_CATALOG}")
        ok = False
    vectors = raw.get("vectors")
    if vectors not in SINK_VECTORS:
        errors.append(f"{where}: vectors {vectors!r} is not one of {SINK_VECTORS} (v1: local only)")
        ok = False
    plaintext = raw.get("plaintext")
    if plaintext != SINK_PLAINTEXT:
        errors.append(
            f"{where}: plaintext must be {SINK_PLAINTEXT!r} — it is an invariant, not a setting"
        )
        ok = False
    seal_to = _str_list(where, "seal_to", raw.get("seal_to", []), errors, nonempty=False, hi=128)
    if seal_to is None:
        ok = False
    if not ok:
        return None
    return Sink(catalog=catalog, vectors=vectors, plaintext=plaintext, seal_to=seal_to)


def _validate_grants(raw, owner_host, mask, errors):
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        errors.append("grants: must be a list")
        return None
    grants = []
    seen = set()
    ok = True
    for idx, g in enumerate(raw):
        where = f"grants[{idx}]"
        if not _check_keys(where, g, ("host", "ops", "until"), (), errors):
            ok = False
            continue
        host = g.get("host")
        if not _is_str(host, 1, 63) or not SLUG_RE.match(host):
            errors.append(f"{where}: host must be a lowercase slug [a-z0-9-]+ of 1-63 chars")
            ok = False
        elif host == owner_host:
            errors.append(f"{where}: host {host!r} is the owner — a grant to yourself is a mistake")
            ok = False
        elif host in seen:
            errors.append(f"{where}: duplicate grant for host {host!r}")
            ok = False
        seen.add(host)
        ops = _str_list(where, "ops", g.get("ops"), errors, allowed=GRANT_OPS)
        if ops is None:
            ok = False
        elif mask is not None:
            for op in ops:
                need = GRANT_OP_NEEDS_MASK[op]
                if need not in mask:
                    errors.append(f"{where}: op {op!r} requires {need!r} in mask")
                    ok = False
        until = g.get("until")
        until_date = None
        if isinstance(until, _dt.date) and not isinstance(until, _dt.datetime):
            until_date = until  # PyYAML parses bare YYYY-MM-DD as a date
        elif isinstance(until, str) and DATE_RE.match(until):
            try:
                until_date = _dt.date.fromisoformat(until)
            except ValueError:
                pass
        if until_date is None:
            errors.append(f"{where}: until {until!r} is not a real YYYY-MM-DD date")
            ok = False
        if ok and until_date is not None and ops is not None:
            grants.append(Grant(host=host, ops=ops, until=until_date))
    return tuple(grants) if ok else None


def _validate_signature(raw, errors):
    where = "signature"
    if not _check_keys(where, raw, ("alg", "cert", "value"), (), errors):
        return None
    ok = True
    alg = raw.get("alg")
    if alg not in SIGNATURE_ALGS:
        errors.append(f"{where}: alg {alg!r} is not one of {SIGNATURE_ALGS}")
        ok = False
    cert = raw.get("cert")
    if not _is_str(cert, 1, 256):
        errors.append(f"{where}: cert must be a path string of 1-256 chars")
        ok = False
    value = raw.get("value")
    if not _is_str(value, 1):
        errors.append(f"{where}: value must be a non-empty base64 string")
        ok = False
    else:
        try:
            base64.b64decode(value, validate=True)
        except Exception:
            errors.append(f"{where}: value is not valid base64")
            ok = False
    return Signature(alg=alg, cert=cert, value=value) if ok else None


# ── entry point ─────────────────────────────────────────────────────────────

def validate_document(doc, require_signed=False):
    """Validate a parsed manifest document. Raises ManifestError listing all
    problems; returns a Manifest otherwise."""
    errors = []
    if not isinstance(doc, dict):
        raise ManifestError(["top level must be a map"])
    _check_keys("top level", doc, TOP_KEYS_REQUIRED, TOP_KEYS_OPTIONAL, errors)

    ver = doc.get("freeagent")
    if "freeagent" in doc and ver != SCHEMA_VERSION:
        errors.append(f"freeagent: schema version {ver!r} is not {SCHEMA_VERSION}")

    manifest_id = doc.get("id")
    if "id" in doc and (not _is_str(manifest_id, 1, 63) or not SLUG_RE.match(manifest_id)):
        errors.append(f"id {manifest_id!r} is not a lowercase slug [a-z0-9-]+ of 1-63 chars")
        manifest_id = None

    owner_host = None
    if "owner" in doc and _check_keys("owner", doc.get("owner"), ("host",), (), errors):
        owner_host = doc["owner"].get("host")
        if not _is_str(owner_host, 1, 63) or not SLUG_RE.match(owner_host):
            errors.append(f"owner.host {owner_host!r} is not a lowercase slug [a-z0-9-]+ of 1-63 chars")
            owner_host = None

    scope = _validate_scope(doc.get("scope"), errors) if "scope" in doc else None

    mask = None
    if "mask" in doc:
        mask = _str_list("mask", "mask", doc.get("mask"), errors, allowed=MASK_OPS)
        if mask is not None and MASK_MANDATORY not in mask:
            errors.append(f"mask: {MASK_MANDATORY!r} is mandatory")
            mask = None

    stages = _validate_stages(doc.get("stages"), errors) if "stages" in doc else None

    sweep = doc.get("sweep")
    if "sweep" in doc and sweep not in SWEEPS:
        errors.append(f"sweep {sweep!r} is not one of {SWEEPS}")
        sweep = None

    sink = _validate_sink(doc.get("sink"), errors) if "sink" in doc else None

    # conditional sections — present iff their stage is
    sanitize = embed = summarize = None
    if stages is not None:
        if "sanitize" in stages and "sanitize" not in doc:
            errors.append("sanitize: section required when 'sanitize' is in stages")
        if "sanitize" not in stages and "sanitize" in doc:
            errors.append("sanitize: section present but 'sanitize' is not in stages")
        if "embed" in stages and "embed" not in doc:
            errors.append("embed: section required when 'embed' is in stages")
        if "embed" not in stages and "embed" in doc:
            errors.append("embed: section present but 'embed' is not in stages")
    if "sanitize" in doc:
        sanitize = _validate_sanitize(doc["sanitize"], manifest_id or "", errors)
    if "embed" in doc:
        embed = _validate_embed(doc["embed"], errors)
    if "summarize" in doc:
        summarize = _validate_summarize(doc["summarize"], errors)

    grants = _validate_grants(doc.get("grants"), owner_host, mask, errors)

    signature = None
    if "signature" in doc:
        signature = _validate_signature(doc["signature"], errors)
    elif require_signed:
        errors.append("signature: required (--require-signed) but absent")

    # cross-section rules — the doctrine
    if stages is not None and mask is not None:
        for s in stages:
            need = STAGE_NEEDS_OP.get(s)
            if need and need not in mask:
                errors.append(f"stages: {s!r} requires {need!r} in mask")
    if "summarize" in doc:
        if mask is not None and "summarize" not in mask:
            errors.append("summarize: section present but 'summarize' is not in mask")
        if stages is not None and "catalog" not in stages:
            errors.append("summarize: requires the 'catalog' stage (summaries live in the catalog)")
    if stages is not None:
        if sink is not None and sink.catalog == "host" and "seal" not in stages:
            errors.append("sink: catalog 'host' requires the 'seal' stage — nothing leaves unsealed")
        if grants and "seal" not in stages:
            errors.append("grants: any grant requires the 'seal' stage — nothing is served unsealed")
        if sink is not None and sink.seal_to and "seal" not in stages:
            errors.append("sink: seal_to given but 'seal' is not in stages")

    if errors:
        raise ManifestError(errors)
    return Manifest(
        id=manifest_id,
        owner_host=owner_host,
        scope=scope,
        mask=mask,
        stages=stages,
        sweep=sweep,
        sink=sink,
        sanitize=sanitize,
        embed=embed,
        summarize=summarize,
        grants=grants,
        signature=signature,
        raw=doc,
    )


def load_manifest(path, require_signed=False):
    """Load and validate a manifest file. Raises ManifestError listing all problems."""
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except FileNotFoundError:
        raise ManifestError([f"manifest file not found: {path}"])
    except yaml.YAMLError as exc:
        raise ManifestError([f"not valid YAML: {exc}"])
    return validate_document(doc, require_signed=require_signed)
