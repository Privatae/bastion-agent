"""Tests for the query endpoint. Run: python3 -m unittest discover .

A miniature PKI is minted with openssl per test class: a root CA, a
server cert, an owner client cert, a grantee client cert, an expired-
grant client cert, and a client cert from a DIFFERENT CA. The server
binds loopback here ONLY because client and server are the same test
process; production binds the mesh interface (docs/serve.md).
"""

import http.client
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest

from . import embed as em
from . import run as rn
from . import serve as sv
from .catalog import catalog
from .extract import extract
from .manifest import validate_document
from .sanitize import sanitize
from .test_embed import _Stub as EmbedStub  # deterministic bag-of-words embedder
from .walk import walk

HAVE_OPENSSL = bool(shutil.which("openssl"))
import datetime as _dt
TODAY = _dt.date(2026, 8, 28)


def sh(*argv):
    subprocess.run(list(argv), check=True, capture_output=True)


def mint_pki(d):
    """root CA + server + clients; returns dict of paths."""
    p = lambda n: os.path.join(d, n)
    def root(name, cn):
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p(name + ".key"))
        sh("openssl", "req", "-new", "-x509", "-key", p(name + ".key"), "-out", p(name + ".crt"), "-days", "2",
           "-subj", "/CN=" + cn, "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign")

    root("ca", "test-root")
    root("other-ca", "other-root")

    def leaf(name, cn, ca="ca", san=None):
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p(name + ".key"))
        sh("openssl", "req", "-new", "-key", p(name + ".key"), "-out", p(name + ".csr"), "-subj", "/CN=" + cn)
        ext = p(name + ".ext")
        with open(ext, "w") as fh:
            fh.write("subjectAltName=%s\nbasicConstraints=CA:FALSE\n"
                     "extendedKeyUsage=serverAuth,clientAuth\n" % (san or "DNS:" + cn))
        sh("openssl", "x509", "-req", "-in", p(name + ".csr"), "-CA", p(ca + ".crt"), "-CAkey", p(ca + ".key"),
           "-CAcreateserial", "-out", p(name + ".crt"), "-days", "2", "-extfile", ext)
        return p(name + ".crt"), p(name + ".key")

    out = {"ca": p("ca.crt"), "other_ca": p("other-ca.crt")}
    out["server"] = leaf("server", "localhost", san="DNS:localhost,IP:127.0.0.1")
    out["owner"] = leaf("owner", "owner-host")
    out["partner"] = leaf("partner", "partner-host")
    out["expired"] = leaf("expired", "old-host")
    out["stranger"] = leaf("stranger", "owner-host", ca="other-ca")  # right CN, wrong CA
    out["nobody"] = leaf("nobody", "nobody-host")
    return out


@unittest.skipUnless(HAVE_OPENSSL, "openssl not on PATH")
class ServeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp(prefix="fa-serve-")
        cls.pki = mint_pki(cls.work)
        cls.root = os.path.join(cls.work, "corpus")
        os.makedirs(cls.root)
        for name, text in (("apples.txt", "apples pears plums orchard harvest m@example.com\n"),
                           ("routers.txt", "router switch firewall vlan network segment\n")):
            with open(os.path.join(cls.root, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        cls.out = os.path.join(cls.work, "out")
        cls.manifest = os.path.join(cls.work, "m.yaml")
        cls.write_manifest(grants=[{"host": "partner-host", "ops": ["search"], "until": "2026-12-31"},
                                   {"host": "old-host", "ops": ["search", "read_range"], "until": "2026-01-01"}])
        m = cls.load()
        # embedding stub
        from http.server import ThreadingHTTPServer
        EmbedStub.dim = 64
        cls.estub = ThreadingHTTPServer(("127.0.0.1", 0), EmbedStub)
        threading.Thread(target=cls.estub.serve_forever, daemon=True).start()
        cls.env = {"EMBED_URL": "http://127.0.0.1:%d" % cls.estub.server_address[1],
                   "FREEAGENT_TLS_CERT": cls.pki["server"][0], "FREEAGENT_TLS_KEY": cls.pki["server"][1],
                   "FREEAGENT_CA_ROOT": cls.pki["ca"]}
        walk(m, cls.out)
        extract(m, cls.out, use_external=False)
        sanitize(m, cls.out, env={})
        em.chunk(m, cls.out)
        em.embed(m, cls.out, env=cls.env)
        catalog(m, cls.out, env={})
        cls.srv = sv.build_server(cls.manifest, cls.out, env=cls.env, bind="127.0.0.1:0", today=TODAY)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.estub.shutdown()
        shutil.rmtree(cls.work, ignore_errors=True)

    @classmethod
    def write_manifest(cls, grants):
        import yaml
        doc = {"freeagent": 1, "id": "t", "owner": {"host": "owner-host"},
               "scope": {"roots": [cls.root]}, "mask": ["read", "search", "index"],
               "stages": ["walk", "extract", "sanitize", "chunk", "embed", "catalog", "seal"],
               "sanitize": {"mode": "flag"},
               "embed": {"model": "stub-model", "dim": 64, "chunk": {"size_tokens": 8, "overlap_tokens": 2}},
               "sweep": "manual",
               "sink": {"catalog": "host", "vectors": "local", "plaintext": "never"},
               "grants": grants}
        with open(cls.manifest, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False)
        rn.sign_manifest_file(cls.manifest, cls.pki["owner"][1], cls.pki["owner"][0])

    @classmethod
    def load(cls):
        from .manifest import load_manifest
        return load_manifest(cls.manifest)

    # ── client ───────────────────────────────────────────────────────────
    def client(self, who, ca=None):
        ctx = ssl.create_default_context(cafile=ca or self.pki["ca"])
        ctx.check_hostname = False  # test server cert is for localhost/127.0.0.1; keep simple
        if who:
            ctx.load_cert_chain(*self.pki[who])
        return http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=10)

    def call(self, who, method, path, body=None):
        c = self.client(who)
        data = json.dumps(body).encode() if body is not None else None
        c.request(method, path, body=data, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        out = json.loads(r.read().decode("utf-8"))
        c.close()
        return r.status, out

    def audit(self):
        with open(os.path.join(self.out, "serve.audit.jsonl"), encoding="utf-8") as fh:
            return [json.loads(l) for l in fh]

    # ── tests ────────────────────────────────────────────────────────────
    def test_owner_everything(self):
        st, body = self.call("owner", "GET", "/health")
        self.assertEqual((st, body["ok"], body["serving"]), (200, True, True))
        st, body = self.call("owner", "POST", "/search", {"query": "firewall vlan", "k": 2})
        self.assertEqual(st, 200)
        self.assertEqual(len(body["hits"]), 2)
        self.assertIn("router", body["hits"][0]["text"])
        doc = body["hits"][0]["doc"]
        st, body = self.call("owner", "POST", "/read_range", {"doc": doc, "start": 0, "end": 20})
        self.assertEqual(st, 200)
        self.assertEqual(body["text"], "router switch firewa")
        self.assertEqual(body["total"], 44)
        st, body = self.call("owner", "GET", "/catalog")
        self.assertEqual(st, 200)
        self.assertEqual({c["path"] for c in body["cards"]}, {"apples.txt", "routers.txt"})
        # sanitized store only: the apples card head carries a token, not the address
        apples = [c for c in body["cards"] if c["path"] == "apples.txt"][0]
        self.assertIn("[PII_EMAIL_1]", apples["head"])
        st, body = self.call("owner", "GET", "/status")
        self.assertEqual(st, 200)
        # the map: directory cards, root "" aggregates everything
        st, body = self.call("owner", "GET", "/catalog/dirs")
        self.assertEqual((st, body["kind"]), (200, "dirs"))
        root = [c for c in body["cards"] if c["path"] == ""][0]
        self.assertEqual(root["files"], 2)
        self.assertEqual(root["entities"], {"EMAIL": 1})
        self.assertEqual(self.call("partner", "GET", "/catalog/dirs")[0], 403)
        # paging: total/offset/limit/next_offset; prefix filters by path
        st, body = self.call("owner", "GET", "/catalog?limit=1")
        self.assertEqual((st, body["total"], len(body["cards"]), body["next_offset"]), (200, 2, 1, 1))
        st, body = self.call("owner", "GET", "/catalog?limit=1&offset=1")
        self.assertEqual((len(body["cards"]), body["next_offset"]), (1, None))
        st, body = self.call("owner", "GET", "/catalog?prefix=rou")
        self.assertEqual([c["path"] for c in body["cards"]], ["routers.txt"])
        self.assertEqual(self.call("owner", "GET", "/catalog?limit=x")[0], 400)

    def test_grantee_gets_only_its_ops(self):
        st, body = self.call("partner", "POST", "/search", {"query": "apples"})
        self.assertEqual(st, 200)
        self.assertIn("[PII_EMAIL_1]", body["hits"][0]["text"])  # sanitized, always
        doc = body["hits"][0]["doc"]
        st, body = self.call("partner", "POST", "/read_range", {"doc": doc, "start": 0, "end": 5})
        self.assertEqual(st, 403)
        self.assertIn("partner-host", body["error"])
        self.assertEqual(self.call("partner", "GET", "/catalog")[0], 403)
        self.assertEqual(self.call("partner", "GET", "/status")[0], 403)
        self.assertEqual(self.call("partner", "GET", "/health")[0], 200)

    def test_expired_grant_and_unknown_cn(self):
        self.assertEqual(self.call("expired", "POST", "/search", {"query": "x"})[0], 403)
        self.assertEqual(self.call("nobody", "POST", "/search", {"query": "x"})[0], 403)
        self.assertEqual(self.call("nobody", "GET", "/health")[0], 200)  # chained, so alive

    def test_no_cert_or_foreign_ca_never_reaches_a_handler(self):
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            self.call(None, "GET", "/health")
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            self.call("stranger", "GET", "/health")  # CN 'owner-host' but signed by another CA
        # and no audit line was written for either
        self.assertFalse(any(a["cn"] is None for a in self.audit()))

    def test_read_range_is_bounded_and_sanitized_only(self):
        st, body = self.call("owner", "POST", "/search", {"query": "apples", "k": 1})
        doc = body["hits"][0]["doc"]
        st, body = self.call("owner", "POST", "/read_range", {"doc": doc, "start": 0, "end": 10 ** 9})
        self.assertEqual(st, 200)
        self.assertLessEqual(body["end"] - body["start"], sv.READ_RANGE_MAX)
        self.assertNotIn("m@example.com", body["text"])
        # one id per document: the extract and sanitized stores share the
        # content hash, and the route reads ONLY the sanitized directory —
        # so the extract-side plaintext for the same id is never what comes back
        with open(os.path.join(self.out, "extract.jsonl"), encoding="utf-8") as fh:
            ext_sha = [json.loads(l) for l in fh if "apples" in l][0]["sha256"]
        st, body = self.call("owner", "POST", "/read_range", {"doc": ext_sha, "start": 0, "end": 200})
        self.assertEqual(st, 200)
        self.assertIn("[PII_EMAIL_1]", body["text"])
        self.assertNotIn("m@example.com", body["text"])
        with open(os.path.join(self.out, "extract", ext_sha[:2], ext_sha + ".txt"), encoding="utf-8") as fh:
            self.assertIn("m@example.com", fh.read())  # the plaintext exists on disk; it has no route
        st, _ = self.call("owner", "POST", "/read_range", {"doc": "0" * 64, "start": 0, "end": 10})
        self.assertEqual(st, 404)
        self.assertEqual(self.call("owner", "POST", "/read_range", {"doc": "zz", "start": 0, "end": 1})[0], 400)
        self.assertEqual(self.call("owner", "POST", "/search", {"query": ""})[0], 400)
        self.assertEqual(self.call("owner", "POST", "/nope", {})[0], 404)

    def test_silent_tcp_connection_does_not_stall_other_clients(self):
        # with the handshake on the accept loop one idle raw TCP
        # connection blocked every client; now the handshake runs in the
        # connection's own thread with its own timeout
        import socket
        staller = socket.create_connection(("127.0.0.1", self.port))
        try:
            st, body = self.call("owner", "GET", "/health")
            self.assertEqual((st, body["ok"]), (200, True))
        finally:
            staller.close()

    def test_audit_hashes_query_never_logs_it(self):
        self.call("owner", "POST", "/search", {"query": "secret question about marisol"})
        lines = self.audit()
        last = [a for a in lines if a["op"] == "search"][-1]
        self.assertEqual(last["cn"], "owner-host")
        self.assertEqual(len(last["q"]), 16)
        blob = json.dumps(lines)
        self.assertNotIn("marisol", blob)

    def test_revoke_grant_by_resigning(self):
        self.assertEqual(self.call("partner", "POST", "/search", {"query": "apples"})[0], 200)
        self.write_manifest(grants=[])  # drop the grant, re-sign
        self.assertEqual(self.call("partner", "POST", "/search", {"query": "apples"})[0], 403)
        self.assertEqual(self.call("owner", "POST", "/search", {"query": "apples"})[0], 200)
        # tamper without re-signing -> the endpoint refuses everything but health
        with open(self.manifest, encoding="utf-8") as fh:
            text = fh.read()
        with open(self.manifest, "w", encoding="utf-8") as fh:
            fh.write(text.replace("sweep: manual", "sweep: daily"))
        st, body = self.call("owner", "POST", "/search", {"query": "apples"})
        self.assertEqual(st, 503)
        self.assertIn("gate", body["error"])
        self.assertEqual(self.call("owner", "GET", "/health")[1]["serving"], False)
        # restore
        self.write_manifest(grants=[{"host": "partner-host", "ops": ["search"], "until": "2026-12-31"},
                                    {"host": "old-host", "ops": ["search", "read_range"], "until": "2026-01-01"}])
        self.assertEqual(self.call("owner", "POST", "/search", {"query": "apples"})[0], 200)


class UnitTests(unittest.TestCase):
    def test_policy_fails_closed_when_the_manifest_cannot_be_read(self):
        # Review: an unreadable manifest (PermissionError, bad encoding) is
        # not a ManifestError, and it escaped after _mtime advanced — leaving
        # the PREVIOUS manifest in force.
        from unittest import mock
        work = tempfile.mkdtemp(prefix="fa-pol-")
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        man = os.path.join(work, "m.yaml")
        with open(man, "w") as fh:
            fh.write("x: 1\n")
        good = object()
        with mock.patch.object(sv, "load_manifest", return_value=good), \
                mock.patch.object(sv, "verify_signature", return_value={}):
            pol = sv.Policy(man, {})
        self.assertIs(pol.manifest, good)
        os.utime(man, ns=(1, 1))
        with mock.patch.object(sv, "load_manifest", side_effect=PermissionError("denied")):
            pol.reload()
        self.assertIsNone(pol.manifest)
        self.assertIn("manifest unreadable", pol.gate_error)

    # skipped rather than faked: the port file is written by build_server
    # only after it has loaded a real certificate chain and verified a signed
    # manifest, and minting those needs openssl
    @unittest.skipUnless(HAVE_OPENSSL, "openssl not on PATH: needed to mint the test PKI and sign the manifest")
    def test_port_file_written_after_bind(self):
        # a supervisor binds :0 and reads the port back — one atomic file
        work = tempfile.mkdtemp(prefix="fa-pf-")
        try:
            pki = mint_pki(work)
            man = os.path.join(work, "m.yaml")
            import yaml
            with open(man, "w") as fh:
                yaml.safe_dump({"freeagent": 1, "id": "p", "owner": {"host": "owner-host"},
                                "scope": {"roots": [work]}, "mask": ["read"], "stages": ["walk"],
                                "sweep": "manual",
                                "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"}}, fh)
            rn.sign_manifest_file(man, pki["owner"][1], pki["owner"][0])
            env = {"FREEAGENT_TLS_CERT": pki["server"][0], "FREEAGENT_TLS_KEY": pki["server"][1],
                   "FREEAGENT_CA_ROOT": pki["ca"]}
            pf = os.path.join(work, "port")
            srv = sv.build_server(man, os.path.join(work, "out"), env=env, bind="127.0.0.1:0", port_file=pf)
            try:
                with open(pf) as fh:
                    self.assertEqual(int(fh.read().strip()), srv.server_address[1])
            finally:
                srv.server_close()
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_parse_bind(self):
        self.assertEqual(sv.parse_bind("[::]:8470"), ("::", 8470))
        self.assertEqual(sv.parse_bind("10.0.0.5:9"), ("10.0.0.5", 9))
        self.assertEqual(sv.parse_bind("[fd00:1::31]:8470"), ("fd00:1::31", 8470))
        with self.assertRaises(sv.ServeError):
            sv.parse_bind("nope")

    def test_peer_cn(self):
        self.assertEqual(sv.peer_cn({"subject": ((("commonName", "x"),),)}), "x")
        self.assertIsNone(sv.peer_cn({}))
        self.assertIsNone(sv.peer_cn(None))

    def test_ssl_context_requires_all_three(self):
        with self.assertRaises(sv.ServeError):
            sv.build_ssl_context("", "", "")


if __name__ == "__main__":
    unittest.main()
