"""Unit tests for the seal stage. Run: python3 -m unittest discover .

Round trips use a real age identity generated with age-keygen when the
binaries are on PATH (they are on the server and in CI); the envelope
tests are skipped where age is absent, the fail-closed tests are not.
"""

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from . import seal as sl
from .catalog import catalog
from .extract import extract
from .manifest import validate_document
from .sanitize import sanitize
from .walk import walk

HAVE_AGE = bool(shutil.which("age") and shutil.which("age-keygen"))


def manifest(root, seal_to=(), stages=None):
    doc = {
        "freeagent": 1, "id": "t", "owner": {"host": "h"},
        "scope": {"roots": [root]},
        "mask": ["read", "search", "index"],
        "stages": stages or ["walk", "extract", "sanitize", "catalog", "seal"], "sweep": "manual",
        "sanitize": {"mode": "flag"},
        "sink": {"catalog": "host", "vectors": "local", "plaintext": "never", "seal_to": list(seal_to)},
    }
    return validate_document(doc)


def keygen(dirpath):
    ident = os.path.join(dirpath, "key.txt")
    out = subprocess.run(["age-keygen", "-o", ident], capture_output=True, text=True, check=True)
    pub = [l for l in (out.stderr + out.stdout).splitlines() if "age1" in l][-1].split()[-1]
    return ident, pub


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fa-seal-")
        self.out = tempfile.mkdtemp(prefix="fa-sealout-")
        with open(os.path.join(self.root, "note.txt"), "w", encoding="utf-8") as fh:
            fh.write("Marisol's email is m@example.com and card 4111 1111 1111 1111.\n")
        m = manifest(self.root)
        walk(m, self.out)
        extract(m, self.out, use_external=False)
        sanitize(m, self.out, env={})
        catalog(m, self.out, env={})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)


class FailClosedTests(Case):
    def test_no_owner_recipient(self):
        # age is faked present: seal checks for it first, and this test is
        # about the recipient refusal, whether or not age is installed
        with mock.patch.object(sl, "tool_path", lambda n: "/usr/bin/" + n):
            with self.assertRaises(sl.SealError) as cm:
                sl.seal(manifest(self.root), self.out, env={})
        self.assertIn("FREEAGENT_OWNER_RECIPIENT", str(cm.exception))
        self.assertFalse(os.path.exists(os.path.join(self.out, "sealed")))

    def test_bad_recipient_strings(self):
        env = {"FREEAGENT_OWNER_RECIPIENT": "not-a-key"}
        with mock.patch.object(sl, "tool_path", lambda n: "/usr/bin/" + n):
            with self.assertRaises(sl.SealError) as cm:
                sl.seal(manifest(self.root), self.out, env=env)
        self.assertIn("not an age recipient", str(cm.exception))
        env = {"FREEAGENT_OWNER_RECIPIENT": "age1" + "q" * 58}
        with self.assertRaises(sl.SealError) as cm:
            sl.recipients_for(manifest(self.root, seal_to=["partner-key"]), env)
        self.assertIn("partner-key", str(cm.exception))

    def test_no_age_on_path(self):
        env = {"FREEAGENT_OWNER_RECIPIENT": "age1" + "q" * 58}
        with mock.patch.object(sl, "tool_path", lambda n: None):
            with self.assertRaises(sl.SealError) as cm:
                sl.seal(manifest(self.root), self.out, env=env)
        self.assertIn("age", str(cm.exception))

    def test_seal_not_in_stages(self):
        # (a `catalog: host` manifest cannot even omit seal — the schema refuses it)
        m = validate_document({
            "freeagent": 1, "id": "t", "owner": {"host": "h"}, "scope": {"roots": [self.root]},
            "mask": ["read", "index"], "stages": ["walk", "extract", "sanitize", "catalog"],
            "sweep": "manual", "sanitize": {"mode": "flag"},
            "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"}})
        with self.assertRaises(sl.SealError):
            sl.seal(m, self.out, env={"FREEAGENT_OWNER_RECIPIENT": "age1" + "q" * 58})

    def test_bundle_allowlist(self):
        plain, inv = sl.build_bundle(manifest(self.root), self.out, "20260828T000000Z")
        with tarfile.open(fileobj=io.BytesIO(plain)) as tar:
            names = tar.getnames()
        self.assertIn("catalog.jsonl", names)
        self.assertIn("catalog.dirs.jsonl", names)
        self.assertIn("manifest.json", names)
        self.assertIn("seal.manifest.json", names)
        self.assertIn("walk.summary.json", names)
        self.assertIn("sanitize.summary.json", names)
        for forbidden in ("walk.jsonl", "extract.jsonl", "sanitize.jsonl", "vectors.db", "vault.db"):
            self.assertFalse(any(n.endswith(forbidden) for n in names), forbidden)
        self.assertFalse(any(n.startswith(("extract/", "sanitize/")) for n in names))
        # nothing in the bundle is a value
        self.assertNotIn(b"m@example.com", plain)
        self.assertNotIn(b"4111", plain)
        self.assertIn(b"[PII_EMAIL_1]", plain)  # sanitized head is there, as designed
        self.assertEqual(set(inv["members"]), set(names))

    def test_bundle_reproducible(self):
        a, _ = sl.build_bundle(manifest(self.root), self.out, "20260828T000000Z")
        b, _ = sl.build_bundle(manifest(self.root), self.out, "20260828T000000Z")
        self.assertEqual(a, b)


@unittest.skipUnless(HAVE_AGE, "age / age-keygen not on PATH")
class RoundTripTests(Case):
    def test_seal_and_unseal(self):
        ident, pub = keygen(self.out)
        other_ident, other_pub = keygen(tempfile.mkdtemp(prefix="fa-k2-"))
        env = {"FREEAGENT_OWNER_RECIPIENT": pub}
        s = sl.seal(manifest(self.root, seal_to=[other_pub]), self.out, env=env, now="20260828T000000Z")
        sealed = os.path.join(self.out, s["file"])
        self.assertTrue(os.path.exists(sealed))
        self.assertEqual(s["recipients"], [pub, other_pub])
        self.assertGreater(s["bytes_sealed"], 0)
        self.assertIsNone(s["signature"])
        with open(sealed, "rb") as fh:
            blob = fh.read()
        self.assertTrue(blob.startswith(b"age-encryption.org/v1"))
        self.assertNotIn(b"PII_EMAIL", blob)  # sealed: the catalog text is not visible
        with open(os.path.join(self.out, "sealed", "latest.json")) as fh:
            self.assertEqual(json.load(fh)["file"], s["file"])
        # both recipients can open it; a stranger cannot
        for who in (ident, other_ident):
            dest = tempfile.mkdtemp(prefix="fa-un-")
            inv = sl.unseal(sealed, who, dest)
            self.assertEqual(inv["manifest_id"], "t")
            with open(os.path.join(dest, "catalog.jsonl"), encoding="utf-8") as fh:
                self.assertIn("[PII_EMAIL_1]", fh.read())
            shutil.rmtree(dest, ignore_errors=True)
        stranger, _ = keygen(tempfile.mkdtemp(prefix="fa-k3-"))
        with self.assertRaises(sl.SealError):
            sl.unseal(sealed, stranger, tempfile.mkdtemp(prefix="fa-un-"))

    def test_owner_recipient_deduped_and_signature(self):
        ident, pub = keygen(self.out)
        key = os.path.join(self.out, "sign.pem")
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key],
                       check=True, capture_output=True)
        env = {"FREEAGENT_OWNER_RECIPIENT": pub, "SEAL_SIGN_KEY": key}
        s = sl.seal(manifest(self.root, seal_to=[pub]), self.out, env=env)
        self.assertEqual(s["recipients"], [pub])
        sig = os.path.join(self.out, "sealed", s["signature"])
        self.assertTrue(os.path.exists(sig))
        # the signature verifies against the public half
        pubkey = os.path.join(self.out, "sign.pub")
        subprocess.run(["openssl", "ec", "-in", key, "-pubout", "-out", pubkey],
                       check=True, capture_output=True)
        v = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pubkey, "-signature", sig,
                            os.path.join(self.out, s["file"])], capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stderr)

    def test_tampered_member_refused(self):
        ident, pub = keygen(self.out)
        env = {"FREEAGENT_OWNER_RECIPIENT": pub}
        s = sl.seal(manifest(self.root), self.out, env=env)
        # rebuild a bundle with a modified catalog but the old inventory, seal it, and unseal
        plain, _ = sl.build_bundle(manifest(self.root), self.out, "x")
        buf = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(plain)) as src, tarfile.open(fileobj=buf, mode="w") as dst:
            for m in src.getmembers():
                data = src.extractfile(m).read()
                if m.name == "catalog.jsonl":
                    data = data + b"\n{\"forged\": true}\n"
                    m.size = len(data)
                dst.addfile(m, io.BytesIO(data))
        bad = os.path.join(self.out, "bad.tar.age")
        subprocess.run(["age", "-r", pub, "-o", bad], input=buf.getvalue(), check=True)
        with self.assertRaises(sl.SealError) as cm:
            sl.unseal(bad, ident, tempfile.mkdtemp(prefix="fa-un-"))
        self.assertIn("does not match the inventory", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
