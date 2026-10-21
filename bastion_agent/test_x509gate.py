"""The manifest gate needs no openssl (x509gate).

A Windows machine ships no openssl, and the gate used to shell out to it: the
agent refused every manifest there and never ran. These tests mint real
certificates with openssl (a test-machine tool only) and then run the gate with openssl REMOVED from PATH, and cover
the managed install's signing lane — the bastion signs `payload` with its
own key and records it with `sign --value`.
"""

import base64
import datetime as _dt
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from . import run as _run
from . import x509gate as x
from .manifest import load_manifest
from .test_run import write_manifest

HAVE_OPENSSL = bool(shutil.which("openssl"))



def sh(*argv, data=None):
    return subprocess.run(argv, input=data, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE).stdout


def _der_sign(key, data):
    return sh("openssl", "dgst", "-sha256", "-sign", key, data=data)


@unittest.skipUnless(HAVE_OPENSSL, "openssl is needed to MINT the test certificates")
class GateWithoutOpenssl(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        p = lambda n: os.path.join(self.d, n)  # noqa: E731
        self.p = p
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p("host.key"))
        sh("openssl", "req", "-new", "-x509", "-key", p("host.key"), "-out", p("host.crt"),
           "-days", "2", "-subj", "/CN=desk-example")
        os.makedirs(p("root"))
        write_manifest(p("m.yaml"), p("root"), ["walk"], cn="desk-example")
        self.env = {"FREEAGENT_CA_ROOT": p("host.crt")}

    def _no_openssl(self):
        return mock.patch.object(shutil, "which", lambda name, *a, **k: None)

    def _bastion_sign(self):
        """What the managed install does: sign `payload` with its own key and
        record it with `sign --value` — no openssl on the machine."""
        der = _der_sign(self.p("host.key"), _run.manifest_payload(self.p("m.yaml")))
        with self._no_openssl():
            _run.write_signature(self.p("m.yaml"), der, self.p("host.crt"))

    def test_gate_verifies_with_openssl_removed_from_path(self):
        self._bastion_sign()
        with self._no_openssl():
            m = load_manifest(self.p("m.yaml"), require_signed=True)
            got = _run.verify_signature(m, self.env, manifest_dir=self.d)
        self.assertEqual(got["cn"], "desk-example")
        self.assertTrue(got["chained"])

    def test_tampered_manifest_refused_without_openssl(self):
        self._bastion_sign()
        with open(self.p("m.yaml")) as fh:
            text = fh.read()
        with open(self.p("m.yaml"), "w") as fh:
            fh.write(text.replace("sweep: manual", "sweep: hourly", 1))
        with self._no_openssl():
            m = load_manifest(self.p("m.yaml"), require_signed=True)
            with self.assertRaises(_run.GateError) as cm:
                _run.verify_signature(m, self.env, manifest_dir=self.d)
        self.assertIn("does not verify", str(cm.exception))

    def test_cli_sign_value_records_a_bastion_signature(self):
        der = _der_sign(self.p("host.key"), _run.manifest_payload(self.p("m.yaml")))
        env = dict(os.environ, PATH="/nonexistent")   # no openssl for the CLI either
        r = subprocess.run(
            [shutil.which("python3") or "python3", "-m", "bastion_agent", "sign", self.p("m.yaml"),
             "--value", base64.b64encode(der).decode(), "--cert", self.p("host.crt")],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with self._no_openssl():
            m = load_manifest(self.p("m.yaml"), require_signed=True)
            _run.verify_signature(m, self.env, manifest_dir=self.d)

    def test_expired_cert_refused(self):
        self._bastion_sign()
        leaf = x.load_cert_file(self.p("host.crt"))
        later = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30)
        with self.assertRaises(x.CertError):
            x.verify_chain(leaf, [leaf], now=later)

    def test_cert_signed_by_another_ca_refused(self):
        p = self.p
        for n in ("ca", "other"):
            sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p(n + ".key"))
            sh("openssl", "req", "-new", "-x509", "-key", p(n + ".key"), "-out", p(n + ".crt"),
               "-days", "2", "-subj", "/CN=Same Name CA")
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p("leaf.key"))
        sh("openssl", "req", "-new", "-key", p("leaf.key"), "-out", p("leaf.csr"), "-subj", "/CN=desk-example")
        sh("openssl", "x509", "-req", "-in", p("leaf.csr"), "-CA", p("other.crt"), "-CAkey", p("other.key"),
           "-CAcreateserial", "-out", p("leaf.crt"), "-days", "2")
        leaf = x.load_cert_file(p("leaf.crt"))
        ca = x.load_cert_file(p("ca.crt"))
        # Same subject, different key: the name matches, the signature must not.
        with self.assertRaises(x.CertError):
            x.verify_chain(leaf, [ca])
        x.verify_chain(leaf, [x.load_cert_file(p("other.crt"))])

    def test_signature_bit_flips_never_verify(self):
        leaf = x.load_cert_file(self.p("host.crt"))
        for i in range(8):
            msg = os.urandom(40 + i)
            der = _der_sign(self.p("host.key"), msg)
            self.assertTrue(x.ecdsa_p256_sha256_verify(leaf.public_key, msg, der))
            bad = bytearray(der)
            bad[-1 - i] ^= 0x01
            self.assertFalse(x.ecdsa_p256_sha256_verify(leaf.public_key, msg, bytes(bad)))
            self.assertFalse(x.ecdsa_p256_sha256_verify(leaf.public_key, msg + b"x", der))


class DerSafety(unittest.TestCase):
    def test_garbage_is_a_cert_error_not_a_crash(self):
        for junk in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", os.urandom(64)):
            with self.assertRaises(x.CertError):
                x.Cert(junk)
        self.assertFalse(x.ecdsa_p256_sha256_verify(x._G, b"m", b"\x30\x00"))


if __name__ == "__main__":
    unittest.main()
