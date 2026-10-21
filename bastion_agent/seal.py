"""bastion agent `seal` stage — encrypt the catalog to the owner (and named
recipients) so it can leave the machine.

What is sealed — and ONLY this — is an allowlisted bundle:

    manifest.json               the manifest as executed (minus signature)
    catalog.jsonl               file cards
    catalog.dirs.jsonl          directory cards
    *.summary.json              every stage's summary — counts, digests,
                                tool names; never a value
    seal.manifest.json          bundle inventory with sha256 per member

Never in the bundle, by construction (the allowlist is the mechanism, a
test is the proof): the extract store (plaintext), the sanitized store,
the vault, vectors.db, chunks. `sink.plaintext: never` is enforced here
one more time by not having a code path that could add those files.

The envelope is age (X25519 + ChaCha20-Poly1305): a small, widely reviewed
format with a single static binary on Mac/Windows/Linux. It is REQUIRED for this stage
— the stdlib cannot produce the envelope, and a catalog that cannot be
sealed does not leave. Recipients:

    owner       FREEAGENT_OWNER_RECIPIENT (an age1… public key), from the
                environment, never the manifest. Always present.
    seal_to     manifest sink.seal_to — each entry an age1… recipient (or
                an ssh-ed25519/ssh-rsa public key line, which age accepts).

Grantees (manifest `grants`) are NOT recipients: they query the container
over the mesh; they never receive the sealed catalog.

Output: <out>/sealed/<id>-<stamp>.tar.age, <out>/sealed/latest.json (a
pointer, not a symlink — Windows), <out>/seal.summary.json. Optional
detached signature with the host's key: SEAL_SIGN_KEY (PEM path) →
<file>.sig via openssl, so a receiving host can check who sealed it once
the runtime's CA verification lands.
"""

import datetime as _dt
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile

from .manifest import signing_digest

SEAL_VERSION = 1
AGE_RECIPIENT_RE = re.compile(r"^(age1[a-z0-9]{58}|ssh-(ed25519|rsa) [A-Za-z0-9+/=]+( .*)?)$")
BUNDLE_ALLOW = ("catalog.jsonl", "catalog.dirs.jsonl")
SUMMARY_GLOB_RE = re.compile(r"^[a-z]+\.summary\.json$")
TOOL_TIMEOUT = 300


class SealError(Exception):
    """Fail closed: nothing leaves."""


def tool_path(name):
    return shutil.which(name)


def run(argv, data=None, timeout=TOOL_TIMEOUT):
    try:
        proc = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SealError("%s: %s" % (argv[0], exc))
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise SealError("%s exited %d: %s" % (argv[0], proc.returncode, err[-1] if err else ""))
    return proc.stdout


def recipients_for(manifest, env):
    owner = env.get("FREEAGENT_OWNER_RECIPIENT", "").strip()
    if not owner:
        raise SealError("FREEAGENT_OWNER_RECIPIENT is not set — the owner's age public key "
                        "is the mandatory recipient; refusing to seal to nobody")
    recips = [owner] + list(manifest.sink.seal_to)
    bad = [r for r in recips if not AGE_RECIPIENT_RE.match(r)]
    if bad:
        raise SealError("not an age recipient (age1… or ssh-ed25519/ssh-rsa public key): %s"
                        % ", ".join(r[:24] + "…" if len(r) > 24 else r for r in bad))
    seen = set()
    out = []
    for r in recips:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for buf in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(buf)
    return h.hexdigest()


def build_bundle(manifest, out_dir, stamp):
    """The plaintext tar, in memory. Returns (bytes, inventory)."""
    members = []
    for name in BUNDLE_ALLOW:
        path = os.path.join(out_dir, name)
        if not os.path.exists(path):
            raise SealError("no %s in %s — run the catalog stage first" % (name, out_dir))
        members.append(name)
    for name in sorted(os.listdir(out_dir)):
        if SUMMARY_GLOB_RE.match(name) and name != "seal.summary.json":
            members.append(name)
    inventory = {"freeagent": 1, "seal_version": SEAL_VERSION, "manifest_id": manifest.id,
                 "manifest_digest": "sha256:" + signing_digest(manifest.raw),
                 "sealed_at": stamp, "members": {}}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add_bytes(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0          # reproducible: the content is what is signed, not the clock
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
            inventory["members"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

        body = {k: v for k, v in manifest.raw.items() if k != "signature"}
        add_bytes("manifest.json", json.dumps(body, sort_keys=True, indent=2, default=str).encode("utf-8"))
        for name in members:
            with open(os.path.join(out_dir, name), "rb") as fh:
                add_bytes(name, fh.read())
        add_bytes("seal.manifest.json", json.dumps(inventory, sort_keys=True, indent=2).encode("utf-8"))
    return buf.getvalue(), inventory


def seal(manifest, out_dir, env=None, now=None):
    if "seal" not in manifest.stages:
        raise SealError("'seal' is not in this manifest's stages")
    env = dict(os.environ) if env is None else env
    age = tool_path("age")
    if not age:
        raise SealError("`age` is not on PATH — the envelope cannot be produced, nothing leaves "
                        "(install age: https://age-encryption.org, one static binary)")
    recips = recipients_for(manifest, env)
    stamp = now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    plain, inventory = build_bundle(manifest, out_dir, stamp)

    sealed_dir = os.path.join(out_dir, "sealed")
    os.makedirs(sealed_dir, exist_ok=True)
    fname = "%s-%s.tar.age" % (manifest.id, stamp)
    target = os.path.join(sealed_dir, fname)
    argv = [age, "--encrypt"]
    for r in recips:
        argv += ["-r", r]
    argv += ["-o", target + ".tmp"]
    run(argv, data=plain)
    os.replace(target + ".tmp", target)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass

    signature = None
    sign_key = env.get("SEAL_SIGN_KEY", "").strip()
    if sign_key:
        openssl = tool_path("openssl")
        if not openssl:
            raise SealError("SEAL_SIGN_KEY set but openssl is not on PATH")
        sig = run([openssl, "dgst", "-sha256", "-sign", sign_key, target])
        with open(target + ".sig", "wb") as fh:
            fh.write(sig)
        signature = os.path.basename(target) + ".sig"

    summary = {
        "freeagent": 1, "stage": "seal", "seal_version": SEAL_VERSION,
        "manifest_id": manifest.id,
        "manifest_digest": inventory["manifest_digest"],
        "sealed_at": stamp,
        "file": os.path.join("sealed", fname),
        "bytes_plain": len(plain),
        "bytes_sealed": os.path.getsize(target),
        "sha256_plain": hashlib.sha256(plain).hexdigest(),
        "sha256_sealed": _sha256_file(target),
        "recipients": recips,          # public keys — safe to record
        "members": sorted(inventory["members"]),
        "signature": signature,
        "catalog_sink": manifest.sink.catalog,
    }
    pointer = {"file": summary["file"], "sha256_sealed": summary["sha256_sealed"],
               "sealed_at": stamp, "manifest_digest": summary["manifest_digest"]}
    _atomic_write(os.path.join(sealed_dir, "latest.json"), json.dumps(pointer, indent=2, sort_keys=True) + "\n")
    _atomic_write(os.path.join(out_dir, "seal.summary.json"), json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def unseal(sealed_path, identity_path, dest_dir):
    """Owner-side: open a sealed bundle with an age identity file into
    dest_dir. Verifies every member against the inventory."""
    age = tool_path("age")
    if not age:
        raise SealError("`age` is not on PATH")
    plain = run([age, "--decrypt", "-i", identity_path, sealed_path])
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r") as tar:
        names = tar.getnames()
        if any(n.startswith("/") or ".." in n.split("/") for n in names):
            raise SealError("bundle contains an unsafe path")
        inv_member = tar.extractfile("seal.manifest.json")
        if inv_member is None:
            raise SealError("bundle has no seal.manifest.json")
        inventory = json.loads(inv_member.read().decode("utf-8"))
        for name in names:
            data = tar.extractfile(name).read()
            if name != "seal.manifest.json":
                want = inventory["members"].get(name, {}).get("sha256")
                if want != hashlib.sha256(data).hexdigest():
                    raise SealError("member %s does not match the inventory" % name)
            with open(os.path.join(dest_dir, name), "wb") as fh:
                fh.write(data)
    return inventory


def _atomic_write(path, text):
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
