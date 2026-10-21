"""Tests for the zipapp build and the doctor. Run: python3 -m unittest discover ."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from . import build as bd
from . import doctor as dr

HERE = os.path.dirname(os.path.abspath(__file__))
# Repo root: bastion_agent/ is a top-level package.
REPO = os.path.dirname(HERE)


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="fa-build-")
        cls.path, cls.digest, cls.size = bd.build(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_reproducible(self):
        self.assertEqual(bd.build_bytes(), bd.build_bytes())
        p2, d2, _ = bd.build(os.path.join(self.tmp, "again"))
        self.assertEqual(d2, self.digest)
        with open(self.path + ".sha256") as fh:
            self.assertTrue(fh.read().startswith(self.digest))

    def test_contents(self):
        with open(self.path, "rb") as fh:
            data = fh.read()
        self.assertTrue(data.startswith(b"#!/usr/bin/env python3\n"))
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            times = {zf.getinfo(n).date_time for n in names}
        self.assertIn("__main__.py", names)
        self.assertIn("bastion_agent/__main__.py", names)
        self.assertIn("bastion_agent/serve.py", names)
        self.assertIn("bastion_agent/VERSION", names)
        self.assertIn("pii/pipeline.py", names)
        self.assertIn("yaml/__init__.py", names)
        self.assertIn("yaml/LICENSE-NOTICE.txt", names)
        self.assertFalse(any("test_" in n for n in names))
        self.assertFalse(any(n.endswith((".so", ".pyc", ".pyd")) for n in names))
        self.assertNotIn("bastion_agent/build.py", names)
        self.assertNotIn("bastion_agent/verify_release.py", names)
        self.assertNotIn("pii/Dockerfile", names)
        self.assertEqual(times, {bd.FIXED_TIME})
        self.assertLess(self.size, 1_000_000)  # the ~10MB helper is the bar; this is well under

    def run_pyz(self, *args, env=None, cwd=None):
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run([sys.executable, self.path] + list(args), capture_output=True,
                              text=True, env=e, cwd=cwd or REPO)

    def test_pyz_runs_version_doctor_validate(self):
        r = self.run_pyz("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "bastion-agent " + bd.version())
        r = self.run_pyz("doctor", "--json")
        self.assertIn(r.returncode, (0, 1), r.stderr)
        results = json.loads(r.stdout)
        byname = {x["check"]: x for x in results}
        self.assertTrue(byname["python >= 3.8"]["ok"])
        self.assertTrue(byname["yaml (manifest loader)"]["ok"])
        r = self.run_pyz("validate", os.path.join(REPO, "manifests", "home-documents.yaml"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK", r.stdout)

    def test_pyz_runs_a_full_pipeline_outside_the_repo(self):
        # from a scratch directory, no repo on sys.path: walk -> ... -> catalog via the zipapp
        work = tempfile.mkdtemp(prefix="fa-pyzrun-")
        try:
            corpus = os.path.join(work, "c")
            os.makedirs(corpus)
            with open(os.path.join(corpus, "a.txt"), "w") as fh:
                fh.write("hello m@example.com\n")
            man = os.path.join(work, "m.yaml")
            with open(man, "w") as fh:
                fh.write("freeagent: 1\nid: z\nowner: {host: h}\nscope: {roots: ['%s']}\n"
                         "mask: [read, index]\nstages: [walk, extract, sanitize, catalog]\n"
                         "sanitize: {mode: flag}\nsweep: manual\n"
                         "sink: {catalog: local, vectors: local, plaintext: never}\n" % corpus)
            r = self.run_pyz("sweep", man, "--out", os.path.join(work, "out"), "--once",
                             "--allow-unsigned", cwd=work, env={"PYTHONPATH": ""})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("ok", r.stderr)
            with open(os.path.join(work, "out", "catalog.jsonl")) as fh:
                card = json.loads(fh.readline())
            self.assertIn("[PII_EMAIL_1]", card["head"])
        finally:
            shutil.rmtree(work, ignore_errors=True)


class DefaultOutTests(unittest.TestCase):
    def test_single_root_lives_in_dot_agent(self):
        from .__main__ import default_out
        from .manifest import validate_document
        m = validate_document({"freeagent": 1, "id": "d", "owner": {"host": "h"},
                               "scope": {"roots": ["/srv/docs"]}, "mask": ["read"], "stages": ["walk"],
                               "sweep": "manual", "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"}})
        self.assertEqual(default_out(m), os.path.join(os.path.abspath("/srv/docs"), ".agent"))
        m2 = validate_document(dict(m.raw, scope={"roots": ["/a", "/b"]}))
        self.assertEqual(default_out(m2), os.path.join("build", "freeagent", "d"))


class DoctorTests(unittest.TestCase):
    def test_checks_and_render(self):
        res = dr.checks(env={"EMBED_URL": "http://127.0.0.1:9", "FREEAGENT_CA_ROOT": "/nonexistent"})
        byname = {x["check"]: x for x in res}
        self.assertTrue(byname["python >= 3.8"]["ok"])
        self.assertFalse(byname["embedding endpoint http://127.0.0.1:9"]["ok"])
        self.assertFalse(byname["embedding endpoint http://127.0.0.1:9"]["required"])
        self.assertFalse(byname["FREEAGENT_CA_ROOT"]["ok"])
        self.assertIn("missing file", byname["FREEAGENT_CA_ROOT"]["detail"])
        text = dr.render(res)
        self.assertIn("python >= 3.8", text)
        self.assertTrue(text.endswith("pass") or "required missing" in text)


if __name__ == "__main__":
    unittest.main()
