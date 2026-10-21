"""Rebuild the published bastion agent from source and check it is what was published.

    python3 -m bastion_agent.verify_release [--base URL]

Run it from a clone of this repository. It needs Python 3.8 or later, git,
network access to the download address, and PyYAML at the version build.py
pins (the build vendors it). It needs no key or account of ours.

It fetches the release manifest (version.json) and the signature beside it,
checks the signature against the release keys the bastion pins, checks out the
source of that version in a separate worktree, rebuilds the .pyz with that
version's own build.py, and compares the sha256 with the manifest's. A match
means the file every bastion downloads is exactly what this source produces,
and the signature says the release key holder published it.

The source is the tag v<version>. The public repository is a snapshot of the
development one, so the commit the manifest names (built_from) exists only
there; the tag marks the same tree in the public history. When the tag is
absent and built_from is present (a clone of the development repository),
built_from is used instead.

The signature check is ed25519 in pure Python, because the standard library
has no ed25519 and this has to run where nothing else is installed. It only
verifies public data, so speed and side channels do not matter here; the code
follows the reference implementation in RFC 8032, section 6.

This module is a tool for checking releases. build.py leaves it out of the
.pyz: a verifier shipped inside the file it verifies would prove nothing.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEFAULT_BASE = "https://privatae.ai/bastion-agent"
KIND = "bastion-agent"

# The public halves of the release signing keys: base64 of the raw 32-byte
# ed25519 key, the primary first and then the spare kept offline. They are the
# keys the bastion compiles in (productionReleaseKeys in client-go/release_sign.go
# in the bastion's repository), because a bastion refuses any agent manifest
# that does not verify against those. When the bastion rotates a key, this list
# changes in the same way, or this check fails where a bastion would pass.
RELEASE_KEYS = (
    "tWOyZm38DwTwbawSnvExQG/CQsVJBKYWc46arCBZj9E=",
    "CKL+J0VSdqrfY4AmxChvylJ1ha4e8GvcrYF2o17Ah+g=",
)

FETCH_TIMEOUT = 30
FETCH_MAX = 1 << 20  # a manifest or a signature is a few kilobytes


class VerifyError(Exception):
    pass


# ---- ed25519 verification (RFC 8032, section 6) -----------------------------

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _add(a, b):
    # Extended homogeneous coordinates (X, Y, Z, T).
    ea = (a[1] - a[0]) * (b[1] - b[0]) % _P
    eb = (a[1] + a[0]) * (b[1] + b[0]) % _P
    ec = 2 * a[3] * b[3] * _D % _P
    ed = 2 * a[2] * b[2] % _P
    e, f, g, h = eb - ea, ed - ec, ed + ec, eb + ea
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, pt):
    acc = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        s >>= 1
    return acc


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _compress(pt):
    zi = _inv(pt[2])
    x, y = pt[0] * zi % _P, pt[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * _inv(5) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def ed25519_verify(public, msg, sig):
    """True when sig is a valid ed25519 signature of msg by the 32-byte key public."""
    if len(public) != 32 or len(sig) != 64:
        return False
    a = _decompress(public)
    r = _decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


def ed25519_public_key(seed):
    """The public key for a 32-byte seed. Used by the tests to check the
    arithmetic against published vectors; verification never needs it."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(_mul(a, _G))


# ---- the release signature --------------------------------------------------

def statement(kind, version, manifest_sha256_hex):
    """The exact text a release signature covers. The bastion builds the same
    text (releaseStatement in client-go/release_sign.go), and so does the
    signing tool the key holder runs."""
    return ("privatae-release-signature-v1\n%s\n%s\n%s\n"
            % (kind, version, manifest_sha256_hex)).encode("utf-8")


def sig_name(body):
    """The signature file's name beside version.json: named by the first 16 hex
    of the manifest's sha256, so a signature can only pair with its manifest."""
    return "version.json.%s.sig" % hashlib.sha256(body).hexdigest()[:16]


def check_signature(body, sig_text, keys=None, kind=KIND):
    """Return the manifest (parsed) when sig_text verifies over body against
    one of keys, and the index of the key that verified. Raise VerifyError
    otherwise; there is no unsigned fallback."""
    try:
        m = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise VerifyError("the manifest is not JSON")
    ver = m.get("version") if isinstance(m, dict) else None
    if not isinstance(ver, str) or not ver or "\n" in ver or "\r" in ver:
        raise VerifyError("the manifest names no usable version")
    try:
        raw = base64.b64decode(sig_text.strip(), validate=True)
    except (ValueError, TypeError):
        raise VerifyError("the signature is not base64")
    if len(raw) != 64:
        raise VerifyError("the signature is malformed")
    msg = statement(kind, ver, hashlib.sha256(body).hexdigest())
    for i, k in enumerate(RELEASE_KEYS if keys is None else keys):
        pub = base64.b64decode(k)
        if ed25519_verify(pub, msg, raw):
            return m, i
    raise VerifyError("the signature does not verify against any pinned release key")


# ---- fetching, checking out, rebuilding -------------------------------------

def fetch(url):
    # A named client: the download address sits behind Cloudflare, whose
    # Browser Integrity Check refuses Python's default user agent (error
    # 1010, a 403), the signature generic scrapers send.
    req = urllib.request.Request(url, headers={"User-Agent": "bastion-agent-verify-release"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        data = resp.read(FETCH_MAX + 1)
    if len(data) > FETCH_MAX:
        raise VerifyError("%s is larger than a release manifest can be" % url)
    return data


def _git(repo, *args, check=True):
    return subprocess.run(("git", "-C", repo) + args, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)


def _commit(repo, ref):
    r = _git(repo, "rev-parse", "-q", "--verify", ref + "^{commit}", check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def pick_source(repo, version, built_from):
    """(label, commit) of the source to rebuild: the tag v<version>, else the
    manifest's built_from, else VerifyError."""
    tag = "v" + version
    # Fetch the tag if the clone lacks it; a failure (offline, no such tag)
    # just leaves the local refs to decide.
    _git(repo, "fetch", "-q", "origin", "refs/tags/%s:refs/tags/%s" % (tag, tag), check=False)
    c = _commit(repo, "refs/tags/" + tag)
    if c:
        return "tag " + tag, c
    if built_from:
        c = _commit(repo, built_from)
        if c:
            return "built_from " + built_from, c
    raise VerifyError("this clone has neither the tag %s nor the commit %s. Check that "
                      "the public repository has the tag (git fetch --tags origin); if it "
                      "does not, the release predates tagging and can only be checked from a "
                      "clone that has its built_from commit" % (tag, built_from or "(none named)"))


def rebuild(repo, commit, version, work):
    """sha256 of the .pyz that commit's own build.py produces."""
    src = os.path.join(work, "src")
    _git(repo, "worktree", "add", "-q", "--detach", src, commit)
    try:
        with open(os.path.join(src, "bastion_agent", "VERSION"), encoding="utf-8") as fh:
            got = fh.read().strip()
        if got != version:
            raise VerifyError("the source says version %s, the manifest %s" % (got, version))
        dist = os.path.join(work, "dist")
        r = subprocess.run((sys.executable, "-m", "bastion_agent.build", "--out", dist),
                           cwd=src, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True)
        if r.returncode != 0:
            raise VerifyError("the build failed: %s" % (r.stderr.strip() or r.stdout.strip()))
        with open(os.path.join(dist, "bastion-agent-%s.pyz" % version), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    finally:
        _git(repo, "worktree", "remove", "--force", src, check=False)


def main(argv=None, repo=REPO, keys=None):
    ap = argparse.ArgumentParser(prog="bastion_agent.verify_release",
                                 description="Rebuild the published agent and compare it with the release manifest.")
    ap.add_argument("--base", default=os.environ.get("MANIFEST_BASE", DEFAULT_BASE),
                    help="where version.json is served (default %s)" % DEFAULT_BASE)
    args = ap.parse_args(argv)
    base = args.base.rstrip("/")
    work = tempfile.mkdtemp(prefix="agent-verify-")
    try:
        body = fetch(base + "/version.json")
        sig = fetch(base + "/" + sig_name(body)).decode("ascii", "replace")
        m, key = check_signature(body, sig, keys)
        ver, built_from = m["version"], m.get("built_from") or ""
        print("published: v%s built from %s" % (ver, built_from or "(not named)"))
        print("signature: ok (release key %d of %d, %s)"
              % (key + 1, len(RELEASE_KEYS if keys is None else keys), "primary" if key == 0 else "spare"))
        files = m.get("files") if isinstance(m.get("files"), dict) else {}
        # Every .pyz the manifest lists: the artifact under its own name, and
        # the same bytes under the legacy name while that is still published.
        pyz = {n: (e or {}).get("sha256") for n, e in sorted(files.items()) if n.endswith(".pyz")}
        if "bastion-agent-%s.pyz" % ver not in pyz:
            raise VerifyError("the manifest lists no bastion-agent-%s.pyz" % ver)
        label, commit = pick_source(repo, ver, built_from)
        print("source:    %s (%s)" % (label, commit[:12]))
        got = rebuild(repo, commit, ver, work)
        bad = 0
        for name, want in pyz.items():
            same = got == want
            bad += not same
            print("rebuild:   %-28s %s" % (name, "matches %s" % got if same
                                             else "DIFFERS (rebuilt %s, published %s)" % (got, want)))
        return 1 if bad else 0
    except VerifyError as exc:
        print("verify: %s" % exc, file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print("verify: git %s failed: %s" % (" ".join(exc.cmd[3:]), (exc.stderr or "").strip()), file=sys.stderr)
        return 1
    except OSError as exc:  # network errors from urllib are OSErrors
        print("verify: %s" % exc, file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
