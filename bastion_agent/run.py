"""bastion agent runtime: the `sweep` scheduler and the manifest gate.

This is what turns seven commands into an agent. Each cycle:

  1. re-read the manifest (a re-signed manifest takes effect next sweep)
  2. GATE: verify its signature — ECDSA P-256 over the canonical payload,
     the leaf cert's CN must equal owner.host, and the cert must chain to
     FREEAGENT_CA_ROOT, which is required. Unsigned or unverifiable → the
     sweep does nothing and says so. (--allow-unsigned exists for
     development and is recorded in every run it touches.)
  3. run the stages in manifest order, each with the module already
     proven alone; the first failure stops the run (fail closed — a
     later stage never consumes a half-finished earlier one)
  4. append one line to run.jsonl, rewrite run.state.json, sleep until
     the next due time (manifest `sweep`), or exit for `manual`.

A lock file (atomic create, pid + time inside) keeps two sweeps off one
output directory; a stale lock (dead pid on POSIX, or older than
LOCK_STALE_HOURS anywhere) is reclaimed and logged.

Stdlib only. The gate's certificate and signature checks are in x509gate
(the stdlib has no ECDSA, so it carries its own P-256 verifier); openssl is
needed only by the developer helper that SIGNS a manifest. Python 3.8 floor.
"""

import datetime as _dt
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from . import catalog as _catalog
from . import embed as _embed
from . import extract as _extract
from . import sanitize as _sanitize
from . import seal as _seal
from . import walk as _walk
from . import x509gate as _x509
from .manifest import AGENT_DIR, ManifestError, load_manifest, signing_payload

RUN_VERSION = 1
SWEEP_SECONDS = {"15m": 15 * 60, "hourly": 60 * 60, "daily": 24 * 60 * 60, "manual": None}
LOCK_STALE_HOURS = 12
MIN_RETRY_SECONDS = 60


class RunError(Exception):
    pass


class GateError(RunError):
    """The manifest did not pass the gate; nothing ran."""


# ── the gate ────────────────────────────────────────────────────────────────

def _openssl():
    p = shutil.which("openssl")
    if not p:
        raise GateError("openssl is not on PATH — cannot verify the manifest signature")
    return p


def _run(argv, data=None):
    try:
        proc = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError("%s: %s" % (argv[0], exc))
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", "replace")


def cert_cn(cert_path):
    try:
        return _x509.load_cert_file(cert_path).cn()
    except (OSError, _x509.CertError, ValueError, TypeError, IndexError, OverflowError) as exc:
        raise GateError("cannot read signing cert %s: %s" % (cert_path, exc))


def verify_signature(manifest, env, manifest_dir="."):
    """Raise GateError unless the manifest carries a valid signature.

    Standard library only (x509gate): the gate used to shell out to openssl,
    which Windows does not ship, so on a Windows machine every manifest was
    refused and the agent never ran. The checks
    are the ones openssl made: exactly one CN, equal to the owner; the cert
    chains to FREEAGENT_CA_ROOT and is inside its validity window; the
    ECDSA P-256 / SHA-256 signature verifies over the canonical payload."""
    sig = manifest.signature
    if sig is None:
        raise GateError("manifest is unsigned — the runtime refuses to execute it")
    cert = sig.cert if os.path.isabs(sig.cert) else os.path.join(manifest_dir, sig.cert)
    if not os.path.exists(cert):
        raise GateError("signing cert %s not found" % cert)
    try:
        leaf = _x509.load_cert_file(cert)
        cn = leaf.cn()
    except (OSError, _x509.CertError, ValueError, TypeError, IndexError, OverflowError) as exc:
        # Anything a malformed cert raises is a refusal, never a crash.
        raise GateError("cannot read signing cert %s: %s" % (cert, exc))
    if cn != manifest.owner_host:
        raise GateError("signing cert CN %r is not the manifest owner %r" % (cn, manifest.owner_host))
    ca_root = env.get("FREEAGENT_CA_ROOT", "").strip()
    if not ca_root:
        # without a root the gate would only prove "signed by the key in the
        # cert next to the manifest" — that authenticates nothing
        raise GateError("FREEAGENT_CA_ROOT is not set — the gate cannot verify who signed this manifest")
    try:
        with open(ca_root, "rb") as fh:
            roots = _x509.load_root_file(fh.read())
        _x509.verify_chain(leaf, roots)
    except OSError as exc:
        raise GateError("cannot read FREEAGENT_CA_ROOT %s: %s" % (ca_root, exc))
    except (_x509.CertError, ValueError, TypeError, IndexError, OverflowError) as exc:
        raise GateError("signing cert does not chain to FREEAGENT_CA_ROOT: %s" % exc)
    import base64
    try:
        raw = base64.b64decode(sig.value, validate=True)
    except Exception:
        raise GateError("signature value is not base64")
    if not _x509.ecdsa_p256_sha256_verify(leaf.public_key, signing_payload(manifest.raw), raw):
        raise GateError("manifest signature does not verify (payload changed or wrong key)")
    return {"cn": cn, "cert": cert, "chained": True}


def manifest_payload(path):
    """The exact bytes a manifest's signature covers (the canonical payload).
    A signer that holds the key elsewhere — the Go bastion, which mints the
    managed agent's identity with its own crypto — signs these and hands the
    result back through write_signature."""
    return signing_payload(load_manifest(path).raw)


def write_signature(path, der_signature, cert_path):
    """Write the signature block (a DER ECDSA signature over manifest_payload)
    into the manifest, replacing any earlier one. Checked before it is kept:
    the manifest must still load as signed."""
    import base64
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # simpler and safe: drop an existing top-level signature block, then append
    body = _strip_signature_block(text)
    block = "signature:\n  alg: ecdsa-p256-sha256\n  cert: %s\n  value: %s\n" % (
        cert_path, base64.b64encode(der_signature).decode("ascii"))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body.rstrip("\n") + "\n" + block)
    load_manifest(path, require_signed=True)  # must still validate
    return block


def sign_manifest_file(path, key_path, cert_path):
    """Developer/host helper: sign the canonical payload with a PEM key via
    openssl and write the signature block. The managed install does not use
    this — the bastion signs with its own key and calls write_signature — so
    no machine needs openssl to run the agent."""
    rc, out, err = _run([_openssl(), "dgst", "-sha256", "-sign", key_path],
                        data=manifest_payload(path))
    if rc != 0:
        raise GateError("signing failed: %s" % err.strip())
    return write_signature(path, out, cert_path)


def _strip_signature_block(text):
    out, skipping = [], False
    for line in text.splitlines(keepends=True):
        if line.startswith("signature:"):
            skipping = True
            continue
        if skipping and (line.startswith(" ") or line.startswith("\t")):
            continue
        skipping = False
        out.append(line)
    return "".join(out)


# ── the lock ────────────────────────────────────────────────────────────────

def _pid_alive(pid):
    if os.name == "nt":
        return True  # cannot cheaply tell; the age rule decides
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class Lock:
    def __init__(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        self.path = os.path.join(out_dir, "sweep.lock")
        self.reclaimed = None

    def __enter__(self):
        for attempt in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if attempt == 0 and self._stale():
                    self.reclaimed = self._read()
                    try:
                        os.unlink(self.path)
                    except OSError:
                        pass
                    continue
                raise RunError("another sweep holds %s (%s)" % (self.path, self._read()))
            with os.fdopen(fd, "w") as fh:
                json.dump({"pid": os.getpid(), "since": time.time()}, fh)
            return self
        raise RunError("could not acquire %s" % self.path)

    def _read(self):
        try:
            with open(self.path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _stale(self):
        """A lock is stale when its holder is provably dead. On POSIX that is
        the pid check and nothing else — a live pid keeps its lock however
        long the sweep runs (age alone stole live locks). The
        age rule applies only where the pid cannot be checked (Windows) or the
        file is unreadable, and then by the FILE's mtime, so a truncated lock
        is not instantly stale."""
        info = self._read()
        pid = info.get("pid")
        if os.name != "nt" and isinstance(pid, int):
            return not _pid_alive(pid)
        try:
            age = time.time() - os.stat(self.path).st_mtime
        except OSError:
            return False
        return age > LOCK_STALE_HOURS * 3600

    def __exit__(self, *exc):
        try:
            os.unlink(self.path)
        except OSError:
            pass


# ── one run ─────────────────────────────────────────────────────────────────

STAGES = {
    "walk": lambda m, out, env: _walk.walk(m, out),
    "extract": lambda m, out, env: _extract.extract(m, out, use_external=env.get("FREEAGENT_NO_EXTERNAL") != "1"),
    "sanitize": lambda m, out, env: _sanitize.sanitize(m, out, env=env),
    "chunk": lambda m, out, env: _embed.chunk(m, out),
    "embed": lambda m, out, env: _embed.embed(m, out, env=env),
    "catalog": lambda m, out, env: _catalog.catalog(m, out, env=env),
    "seal": lambda m, out, env: _seal.seal(m, out, env=env),
}
STAGE_ERRORS = (FileNotFoundError, _sanitize.SanitizeError, _embed.EmbedError,
                _catalog.CatalogError, _seal.SealError, OSError)


def _stage_failed(name, summary):
    """A stage that completed but reports it stopped is a failure too."""
    if summary.get("stopped"):
        return summary["stopped"]
    return None


def _brief(name, summary):
    c = summary.get("counts", {})
    keys = {"walk": ("files", "errors"), "extract": ("ok", "reused", "error"),
            "sanitize": ("ok", "reused", "not_run"), "chunk": ("chunks",),
            "embed": ("embedded", "reused"), "catalog": ("files", "dirs", "summaries"),
            "seal": ()}.get(name, ())
    out = {k: c[k] for k in keys if k in c}
    if name == "seal":
        out = {"bytes_sealed": summary.get("bytes_sealed"), "recipients": len(summary.get("recipients", []))}
    return out


def default_out(m):
    """Where an agent keeps itself: <root>/.agent for a single-root manifest
    (files-and-folders style: copy the folder, the agent comes with it);
    build/freeagent/<id> when there are several roots and no obvious home.
    Every command uses this default, so `sweep` and `serve` run without
    --out share one folder.

    The directory keeps the old name deliberately: it is on-disk output a user
    may already have, and renaming it would orphan it."""
    roots = m.scope.roots
    if len(roots) == 1:
        return os.path.join(os.path.abspath(os.path.expanduser(roots[0])), AGENT_DIR)
    return os.path.join("build", "freeagent", m.id)


def run_once(manifest_path, out_dir=None, env=None, allow_unsigned=False, now=None, clock=time.time):
    env = dict(os.environ) if env is None else env
    started = now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = clock()
    record = {"v": RUN_VERSION, "started": started, "manifest": manifest_path, "stages": [],
              "ok": False, "allow_unsigned": bool(allow_unsigned)}
    try:
        m = load_manifest(manifest_path)
    except ManifestError as exc:
        record.update(error="manifest: %s" % "; ".join(exc.errors), finished=_now(now), seconds=round(clock() - t0, 3))
        # a refused manifest is a run that happened; the append-only log must
        # say so. With no id to derive a directory from, the
        # caller's --out or a fixed 'refused' directory holds the record.
        _append_run(out_dir or os.path.join("build", "freeagent", "refused"), record)
        return record, None
    out_dir = out_dir or default_out(m)
    record["out"] = out_dir
    record["manifest_id"] = m.id
    from .manifest import signing_digest
    record["manifest_digest"] = "sha256:" + signing_digest(m.raw)
    try:
        gate = verify_signature(m, env, manifest_dir=os.path.dirname(os.path.abspath(manifest_path)))
        record["gate"] = gate
    except GateError as exc:
        if not allow_unsigned:
            record.update(error="gate: %s" % exc, finished=_now(now), seconds=round(clock() - t0, 3))
            _append_run(out_dir, record)  # a gate refusal is on the record too
            return record, m
        record["gate"] = {"bypassed": str(exc)}
    try:
        with Lock(out_dir) as lock:
            if lock.reclaimed:
                record["lock_reclaimed"] = lock.reclaimed
            for name in m.stages:
                s0 = clock()
                entry = {"stage": name}
                try:
                    summary = STAGES[name](m, out_dir, env)
                    err = _stage_failed(name, summary)
                    entry.update(status="failed" if err else "ok", seconds=round(clock() - s0, 3),
                                 **_brief(name, summary))
                    if err:
                        entry["error"] = err
                except STAGE_ERRORS as exc:
                    entry.update(status="failed", seconds=round(clock() - s0, 3),
                                 error="%s: %s" % (type(exc).__name__, exc))
                record["stages"].append(entry)
                if entry["status"] != "ok":
                    record["error"] = "stage %s: %s" % (name, entry["error"])
                    break
            else:
                record["ok"] = True
    except RunError as exc:
        record["error"] = str(exc)
    record["finished"] = _now(now)
    record["seconds"] = round(clock() - t0, 3)
    _append_run(out_dir, record)
    return record, m


def _now(fixed=None):
    return fixed or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_run(out_dir, record):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "run.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _write_state(out_dir, state):
    path = os.path.join(out_dir, "run.state.json")
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=out_dir)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def load_state(out_dir):
    try:
        with open(os.path.join(out_dir, "run.state.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def next_due(sweep, last_started_ts, ok, failures):
    """Seconds-since-epoch of the next run. Failures retry with backoff
    (1 min, 2, 4 … capped at the cadence); manual never schedules."""
    period = SWEEP_SECONDS.get(sweep)
    if period is None:
        return None
    if ok:
        return last_started_ts + period
    backoff = min(period, MIN_RETRY_SECONDS * (2 ** min(failures - 1, 10)))
    return last_started_ts + backoff


# ── the loop ────────────────────────────────────────────────────────────────

def sweep(manifest_path, out_dir=None, env=None, allow_unsigned=False, once=False,
          sleep=time.sleep, clock=time.time, max_runs=None, log=None):
    """Run on the manifest's cadence until stopped. Returns the last record."""
    env = dict(os.environ) if env is None else env
    log = log or (lambda s: sys.stderr.write(s + "\n"))
    stop = {"flag": False}

    def _stop(signum, frame):
        stop["flag"] = True
        log("sweep: stop requested (signal %d); finishing the current run" % signum)

    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if sig is not None:
            try:
                signal.signal(sig, _stop)
            except (ValueError, OSError):
                pass  # not the main thread (tests) — run without handlers

    runs = 0
    last = None
    while not stop["flag"]:
        t_start = clock()
        record, m = run_once(manifest_path, out_dir, env, allow_unsigned=allow_unsigned, clock=clock)
        runs += 1
        last = record
        out = record.get("out") or out_dir or "."
        state = load_state(out) if os.path.isdir(out) else {}
        failures = 0 if record["ok"] else state.get("consecutive_failures", 0) + 1
        sweep_kind = m.sweep if m is not None else "manual"
        due = next_due(sweep_kind, t_start, record["ok"], failures)
        state = {"last_started": record["started"], "last_finished": record.get("finished"),
                 "last_ok": record["ok"], "last_error": record.get("error"),
                 "consecutive_failures": failures, "sweep": sweep_kind,
                 "next_due": _dt.datetime.fromtimestamp(due, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if due else None,
                 "pid": os.getpid(), "runs_this_process": runs}
        if os.path.isdir(out):
            _write_state(out, state)
        stages = ", ".join("%s:%s" % (s["stage"], s["status"]) for s in record["stages"]) or "-"
        log("sweep: %s %s in %.1fs [%s]%s" % (
            record.get("manifest_id", "?"), "ok" if record["ok"] else "FAILED",
            record.get("seconds", 0), stages,
            "" if record["ok"] else " — " + str(record.get("error"))))
        if once or due is None or (max_runs and runs >= max_runs):
            break
        while not stop["flag"]:
            wait = due - clock()
            if wait <= 0:
                break
            sleep(min(wait, 30))
    return last
