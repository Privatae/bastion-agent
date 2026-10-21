"""Tests for the release verifier. Run: python3 -m unittest discover ."""

import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from . import build as bd
from . import verify_release as vr

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def _sign(seed, msg):
    """RFC 8032 signing, for the tests only: the verifier never signs."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = vr._compress(vr._mul(a, vr._G))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % vr._Q
    big_r = vr._compress(vr._mul(r, vr._G))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % vr._Q
    return big_r + ((r + k * a) % vr._Q).to_bytes(32, "little")


class Ed25519Tests(unittest.TestCase):
    # RFC 8032, section 7.1, tests 1 and 2.
    RFC = (
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    )

    def test_rfc8032_vectors(self):
        for seed, pub, msg, sig in self.RFC:
            seed, pub, msg, sig = (bytes.fromhex(x) for x in (seed, pub, msg, sig))
            self.assertEqual(vr.ed25519_public_key(seed), pub)
            self.assertTrue(vr.ed25519_verify(pub, msg, sig))
            self.assertEqual(_sign(seed, msg), sig)

    def test_any_changed_bit_is_refused(self):
        seed, pub, msg, sig = (bytes.fromhex(x) for x in self.RFC[1])
        self.assertFalse(vr.ed25519_verify(pub, msg + b"\x00", sig))
        for i in (0, 31, 32, 63):
            bad = bytearray(sig)
            bad[i] ^= 1
            self.assertFalse(vr.ed25519_verify(pub, msg, bytes(bad)))
        other = vr.ed25519_public_key(b"\x02" * 32)
        self.assertFalse(vr.ed25519_verify(other, msg, sig))

    def test_malformed_input_is_false_not_an_error(self):
        _, pub, msg, sig = (bytes.fromhex(x) for x in self.RFC[0])
        self.assertFalse(vr.ed25519_verify(pub[:31], msg, sig))
        self.assertFalse(vr.ed25519_verify(pub, msg, sig[:63]))
        # S at or above the group order is refused (signature malleability).
        s = int.from_bytes(sig[32:], "little") + vr._Q
        if s < 1 << 256:
            self.assertFalse(vr.ed25519_verify(pub, msg, sig[:32] + s.to_bytes(32, "little")))
        # A y coordinate that is on no point of the curve.
        self.assertFalse(vr.ed25519_verify(b"\x02" + b"\x00" * 31, msg, sig))


class StatementTests(unittest.TestCase):
    def test_statement_bytes(self):
        self.assertEqual(vr.statement("bastion-agent", "0.1.13", "ab" * 32),
                         b"privatae-release-signature-v1\nbastion-agent\n0.1.13\n" + b"ab" * 32 + b"\n")

    def test_the_signing_tool_and_this_check_agree(self):
        # The vector the bastion's release-signing tool and the bastion share:
        # seed of 32 bytes of 1, this manifest, kind "bastion", this signature.
        # If the statement format drifted here, this would fail.
        pub = base64.b64encode(vr.ed25519_public_key(b"\x01" * 32)).decode()
        body = b'{"version":"1.2.3","binaries":{}}'
        sig = "tr5h3oXjBDmwvwQiZSriW4T6Y6oBFQDymfofLEGXMdTJSXfoQAKN+ajhCs89FO9vdCEZH3Y8mYzYXPZ7RzZVDw=="
        m, i = vr.check_signature(body, sig, keys=(pub,), kind="bastion")
        self.assertEqual((m["version"], i), ("1.2.3", 0))
        # Bound to its kind: a bastion manifest's signature is not an agent's.
        with self.assertRaises(vr.VerifyError):
            vr.check_signature(body, sig, keys=(pub,), kind="bastion-agent")

    def test_signature_file_name(self):
        body = b'{"version":"0.1.13"}'
        self.assertEqual(vr.sig_name(body),
                         "version.json.%s.sig" % hashlib.sha256(body).hexdigest()[:16])

    def test_pinned_keys_are_two_valid_points(self):
        self.assertEqual(len(vr.RELEASE_KEYS), 2)
        for k in vr.RELEASE_KEYS:
            raw = base64.b64decode(k, validate=True)
            self.assertEqual(len(raw), 32)
            self.assertIsNotNone(vr._decompress(raw))

    def test_refusals(self):
        seed = b"\x03" * 32
        pub = base64.b64encode(vr.ed25519_public_key(seed)).decode()

        def signed(body):
            msg = vr.statement("bastion-agent", json.loads(body)["version"], hashlib.sha256(body).hexdigest())
            return base64.b64encode(_sign(seed, msg)).decode()

        body = b'{"version":"0.2.0"}'
        self.assertEqual(vr.check_signature(body, signed(body), keys=(pub,))[1], 0)
        # The key that verified is reported by position: the spare is second.
        self.assertEqual(vr.check_signature(body, signed(body), keys=(vr.RELEASE_KEYS[0], pub))[1], 1)
        cases = (
            (b"not json", "AAAA"),
            (b'{"version":""}', signed(body)),
            (b'{"version":"0.2.0\\n"}', signed(body)),
            (body, "not base64!"),
            (body, base64.b64encode(b"short").decode()),
            (body + b" ", signed(body)),           # the manifest changed after signing
            (body, signed(body)),                  # the production keys did not sign it
        )
        for i, (b, s) in enumerate(cases):
            keys = None if i == len(cases) - 1 else (pub,)
            with self.subTest(i=i), self.assertRaises(vr.VerifyError):
                vr.check_signature(b, s, keys=keys)


@unittest.skipUnless(shutil.which("git"), "needs git")
class EndToEndTests(unittest.TestCase):
    """The whole check against a throwaway repository holding this tree."""

    SEED = b"\x04" * 32

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="agent-verify-test-")
        cls.repo = os.path.join(cls.tmp, "repo")
        ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
        shutil.copytree(HERE, os.path.join(cls.repo, "bastion_agent"), ignore=ignore)
        shutil.copytree(os.path.join(REPO, "pii"), os.path.join(cls.repo, "pii"), ignore=ignore)
        shutil.copy(os.path.join(REPO, "LICENSE"), cls.repo)
        git = ("git", "-C", cls.repo, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false")
        run = lambda *a: subprocess.run(git + a, check=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, universal_newlines=True).stdout.strip()
        subprocess.run(("git", "init", "-q", cls.repo), check=True)
        run("add", "-A")
        run("commit", "-q", "-m", "release")
        cls.commit = run("rev-parse", "HEAD")
        cls.run_git = staticmethod(run)
        cls.version = bd.version()
        # The same files as this tree, so the same bytes as building this tree.
        cls.digest = hashlib.sha256(bd.build_bytes()).hexdigest()
        cls.pub = base64.b64encode(vr.ed25519_public_key(cls.SEED)).decode()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def manifest(self, built_from, digest=None):
        name = "bastion-agent-%s.pyz" % self.version
        return json.dumps({"version": self.version, "built_from": built_from,
                           "files": {name: {"sha256": digest or self.digest},
                                     name + ".sha256": {"sha256": "0" * 64}}}).encode()

    def verify(self, body, seed=None):
        msg = vr.statement("bastion-agent", self.version, hashlib.sha256(body).hexdigest())
        sig = base64.b64encode(_sign(seed or self.SEED, msg))
        served = {"/version.json": body, "/" + vr.sig_name(body): sig}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(vr, "fetch", lambda url: served[url[len("https://test"):]]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vr.main(["--base", "https://test"], repo=self.repo, keys=(self.pub,))
        return code, out.getvalue() + err.getvalue()

    def test_tag_first_then_built_from(self):
        code, out = self.verify(self.manifest("0000000"))
        self.assertEqual(code, 1, out)
        self.assertIn("neither the tag v%s" % self.version, out)

        code, out = self.verify(self.manifest(self.commit[:7]))
        self.assertEqual(code, 0, out)
        self.assertIn("source:    built_from", out)
        self.assertIn("matches %s" % self.digest, out)

        self.run_git("tag", "v" + self.version)
        try:
            code, out = self.verify(self.manifest("0000000"))
            self.assertEqual(code, 0, out)
            self.assertIn("source:    tag v%s" % self.version, out)
        finally:
            self.run_git("tag", "-d", "v" + self.version)

    def test_a_different_build_is_reported(self):
        code, out = self.verify(self.manifest(self.commit, digest="1" * 64))
        self.assertEqual(code, 1, out)
        self.assertIn("DIFFERS", out)

    def test_a_foreign_signature_stops_before_any_checkout(self):
        code, out = self.verify(self.manifest(self.commit), seed=b"\x05" * 32)
        self.assertEqual(code, 1, out)
        self.assertIn("does not verify", out)
        self.assertNotIn("source:", out)


if __name__ == "__main__":
    unittest.main()
