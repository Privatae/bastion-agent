"""Unit tests for the sweep scheduler and the manifest gate. Run:
python3 -m unittest discover .

The gate tests generate a real EC key + self-signed cert with openssl (on
PATH here and in CI); the loop is driven with a fake clock and sleep so
a 'daily' cadence runs in milliseconds.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from . import run as rn
from .manifest import load_manifest

HAVE_OPENSSL = bool(shutil.which("openssl"))


def write_manifest(path, root, stages, cn="owner-host", sweep="manual", extra=None):
    doc = {
        "freeagent": 1, "id": "t", "owner": {"host": cn},
        "scope": {"roots": [root]}, "mask": ["read", "index"],
        "stages": stages, "sweep": sweep,
        "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"},
    }
    if "sanitize" in stages:
        doc["sanitize"] = {"mode": "flag"}
    if extra:
        doc.update(extra)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)
    return path


def make_identity(dirpath, cn):
    key = os.path.join(dirpath, "host.key")
    cert = os.path.join(dirpath, "host.crt")
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", key, "-out", cert, "-days", "2",
                    "-subj", "/CN=%s" % cn], check=True, capture_output=True)
    return key, cert


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fa-run-")
        self.work = tempfile.mkdtemp(prefix="fa-runwork-")
        self.out = os.path.join(self.work, "out")
        with open(os.path.join(self.root, "a.txt"), "w", encoding="utf-8") as fh:
            fh.write("hello m@example.com\n")
        self.manifest = os.path.join(self.work, "m.yaml")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.work, ignore_errors=True)

    def runs(self):
        with open(os.path.join(self.out, "run.jsonl"), encoding="utf-8") as fh:
            return [json.loads(l) for l in fh]


@unittest.skipUnless(HAVE_OPENSSL, "openssl not on PATH")
class GateTests(Case):
    def test_sign_then_verify(self):
        write_manifest(self.manifest, self.root, ["walk"])
        key, cert = make_identity(self.work, "owner-host")
        rn.sign_manifest_file(self.manifest, key, "host.crt")
        m = load_manifest(self.manifest, require_signed=True)
        gate = rn.verify_signature(m, {"FREEAGENT_CA_ROOT": cert}, manifest_dir=self.work)
        self.assertEqual(gate["cn"], "owner-host")
        self.assertTrue(gate["chained"])
        # no root, no gate: "signed by the key next to the manifest" proves nothing
        with self.assertRaises(rn.GateError) as cm:
            rn.verify_signature(m, {}, manifest_dir=self.work)
        self.assertIn("FREEAGENT_CA_ROOT", str(cm.exception))
        # re-signing replaces the block rather than stacking a second one
        rn.sign_manifest_file(self.manifest, key, "host.crt")
        with open(self.manifest, encoding="utf-8") as fh:
            self.assertEqual(fh.read().count("signature:"), 1)

    def test_tampered_payload_fails(self):
        write_manifest(self.manifest, self.root, ["walk"])
        key, cert = make_identity(self.work, "owner-host")
        rn.sign_manifest_file(self.manifest, key, "host.crt")
        with open(self.manifest, encoding="utf-8") as fh:
            text = fh.read()
        with open(self.manifest, "w", encoding="utf-8") as fh:
            fh.write(text.replace("sweep: manual", "sweep: daily"))
        m = load_manifest(self.manifest, require_signed=True)
        with self.assertRaises(rn.GateError) as cm:
            rn.verify_signature(m, {"FREEAGENT_CA_ROOT": cert}, manifest_dir=self.work)
        self.assertIn("does not verify", str(cm.exception))

    def test_wrong_cn_fails(self):
        write_manifest(self.manifest, self.root, ["walk"], cn="owner-host")
        key, cert = make_identity(self.work, "someone-else")
        rn.sign_manifest_file(self.manifest, key, "host.crt")
        m = load_manifest(self.manifest, require_signed=True)
        with self.assertRaises(rn.GateError) as cm:
            rn.verify_signature(m, {"FREEAGENT_CA_ROOT": cert}, manifest_dir=self.work)
        self.assertIn("not the manifest owner", str(cm.exception))

    def test_multi_cn_cert_refused(self):
        # a cert carrying the owner's CN next to its real one must not pass
        write_manifest(self.manifest, self.root, ["walk"], cn="owner-host")
        key = os.path.join(self.work, "host.key")
        cert = os.path.join(self.work, "host.crt")
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", key, "-out", cert, "-days", "2",
                        "-subj", "/CN=attacker/CN=owner-host"], check=True, capture_output=True)
        rn.sign_manifest_file(self.manifest, key, "host.crt")
        m = load_manifest(self.manifest, require_signed=True)
        with self.assertRaises(rn.GateError) as cm:
            rn.verify_signature(m, {"FREEAGENT_CA_ROOT": cert}, manifest_dir=self.work)
        self.assertIn("exactly one CN", str(cm.exception))

    def test_ca_chain(self):
        write_manifest(self.manifest, self.root, ["walk"])
        key, cert = make_identity(self.work, "owner-host")
        rn.sign_manifest_file(self.manifest, key, "host.crt")
        m = load_manifest(self.manifest, require_signed=True)
        # self-signed: chains to itself, not to a stranger's root
        gate = rn.verify_signature(m, {"FREEAGENT_CA_ROOT": cert}, manifest_dir=self.work)
        self.assertTrue(gate["chained"])
        _, other_root = make_identity(tempfile.mkdtemp(prefix="fa-ca-"), "other-ca")
        with self.assertRaises(rn.GateError) as cm:
            rn.verify_signature(m, {"FREEAGENT_CA_ROOT": other_root}, manifest_dir=self.work)
        self.assertIn("chain", str(cm.exception))

    def test_unsigned_refused_unless_allowed(self):
        write_manifest(self.manifest, self.root, ["walk"])
        rec, _ = rn.run_once(self.manifest, self.out, env={})
        self.assertFalse(rec["ok"])
        self.assertIn("unsigned", rec["error"])
        self.assertEqual(rec["stages"], [])
        # the refusal is on the append-only record
        self.assertEqual(len(self.runs()), 1)
        self.assertIn("gate:", self.runs()[0]["error"])
        rec, _ = rn.run_once(self.manifest, self.out, env={}, allow_unsigned=True)
        self.assertTrue(rec["ok"])
        self.assertTrue(rec["allow_unsigned"])
        self.assertIn("bypassed", rec["gate"])


class RunTests(Case):
    def test_stages_in_order_and_logged(self):
        write_manifest(self.manifest, self.root, ["walk", "extract", "sanitize", "catalog"])
        rec, m = rn.run_once(self.manifest, self.out, env={}, allow_unsigned=True, now="2026-08-28T00:00:00Z")
        self.assertTrue(rec["ok"], rec)
        self.assertEqual([s["stage"] for s in rec["stages"]], ["walk", "extract", "sanitize", "catalog"])
        self.assertTrue(all(s["status"] == "ok" for s in rec["stages"]))
        self.assertEqual(rec["stages"][0]["files"], 1)
        self.assertEqual(rec["stages"][2]["ok"], 1)
        self.assertTrue(os.path.exists(os.path.join(self.out, "catalog.jsonl")))
        self.assertEqual(len(self.runs()), 1)
        self.assertEqual(self.runs()[0]["started"], "2026-08-28T00:00:00Z")

    def test_default_out_is_the_folder_serve_uses(self):
        # without --out, sweep must write where serve reads: <root>/.agent
        write_manifest(self.manifest, self.root, ["walk"])
        rec, m = rn.run_once(self.manifest, None, env={}, allow_unsigned=True)
        self.assertTrue(rec["ok"], rec)
        want = os.path.join(os.path.abspath(self.root), ".agent")
        self.assertEqual(rec["out"], want)
        from .__main__ import default_out  # what serve and every stage command use
        self.assertEqual(default_out(m), want)
        self.assertTrue(os.path.exists(os.path.join(want, "run.jsonl")))

    def test_failure_stops_the_run(self):
        # sterilize with an unstartable recall backend stops at sanitize
        write_manifest(self.manifest, self.root, ["walk", "extract", "sanitize", "catalog"],
                       extra={"sanitize": {"mode": "sterilize"}})
        rec, _ = rn.run_once(self.manifest, self.out, env={"PII_RECALL": "nope"}, allow_unsigned=True)
        self.assertFalse(rec["ok"])
        self.assertEqual([s["stage"] for s in rec["stages"]], ["walk", "extract", "sanitize"])
        self.assertEqual(rec["stages"][-1]["status"], "failed")
        self.assertIn("PII_RECALL", rec["error"])
        self.assertFalse(os.path.exists(os.path.join(self.out, "catalog.jsonl")))

    def test_invalid_manifest_is_a_recorded_error(self):
        with open(self.manifest, "w") as fh:
            fh.write("freeagent: 2\n")
        rec, m = rn.run_once(self.manifest, self.out, env={}, allow_unsigned=True)
        self.assertIsNone(m)
        self.assertIn("manifest:", rec["error"])
        self.assertIn("manifest:", self.runs()[0]["error"])  # refused manifests are logged too

    def test_lock_blocks_and_reclaims(self):
        write_manifest(self.manifest, self.root, ["walk"])
        os.makedirs(self.out, exist_ok=True)
        with rn.Lock(self.out):
            with self.assertRaises(rn.RunError):
                with rn.Lock(self.out):
                    pass
            rec, _ = rn.run_once(self.manifest, self.out, env={}, allow_unsigned=True)
            self.assertIn("another sweep holds", rec["error"])
        # a stale lock (dead pid) is reclaimed
        with open(os.path.join(self.out, "sweep.lock"), "w") as fh:
            json.dump({"pid": 2 ** 22 + 12345, "since": 0}, fh)
        rec, _ = rn.run_once(self.manifest, self.out, env={}, allow_unsigned=True)
        self.assertTrue(rec["ok"])
        self.assertIn("lock_reclaimed", rec)
        self.assertFalse(os.path.exists(os.path.join(self.out, "sweep.lock")))
        # a LIVE holder keeps its lock however old the file is (never stolen)
        with open(os.path.join(self.out, "sweep.lock"), "w") as fh:
            json.dump({"pid": os.getpid(), "since": 0}, fh)
        rec, _ = rn.run_once(self.manifest, self.out, env={}, allow_unsigned=True)
        self.assertIn("another sweep holds", rec["error"])
        os.unlink(os.path.join(self.out, "sweep.lock"))
        # a truncated lock is judged by file age, not instantly stale
        with open(os.path.join(self.out, "sweep.lock"), "w") as fh:
            fh.write("{")
        rec, _ = rn.run_once(self.manifest, self.out, env={}, allow_unsigned=True)
        self.assertIn("another sweep holds", rec["error"])
        os.unlink(os.path.join(self.out, "sweep.lock"))

    def test_next_due(self):
        self.assertEqual(rn.next_due("hourly", 1000, True, 0), 4600)
        self.assertEqual(rn.next_due("15m", 1000, True, 0), 1900)
        self.assertIsNone(rn.next_due("manual", 1000, True, 0))
        self.assertEqual(rn.next_due("daily", 1000, False, 1), 1060)   # 1 min
        self.assertEqual(rn.next_due("daily", 1000, False, 3), 1240)   # 4 min
        self.assertEqual(rn.next_due("15m", 1000, False, 20), 1900)    # capped at cadence


class SweepLoopTests(Case):
    def test_manual_runs_once(self):
        write_manifest(self.manifest, self.root, ["walk"], sweep="manual")
        sleeps = []
        last = rn.sweep(self.manifest, self.out, env={}, allow_unsigned=True,
                        sleep=sleeps.append, clock=lambda: 1000.0, log=lambda s: None)
        self.assertTrue(last["ok"])
        self.assertEqual(sleeps, [])
        state = rn.load_state(self.out)
        self.assertIsNone(state["next_due"])
        self.assertEqual(state["consecutive_failures"], 0)

    def test_cadence_loops_with_fake_clock(self):
        write_manifest(self.manifest, self.root, ["walk"], sweep="15m")
        clock = {"t": 1000.0}
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            clock["t"] += s

        logs = []
        last = rn.sweep(self.manifest, self.out, env={}, allow_unsigned=True, sleep=sleep,
                        clock=lambda: clock["t"], max_runs=3, log=logs.append)
        self.assertTrue(last["ok"])
        self.assertEqual(len(self.runs()), 3)
        self.assertEqual(sum(sleeps), 2 * 15 * 60)       # slept out two full cadences
        self.assertTrue(all(s <= 30 for s in sleeps))    # in short naps, so a stop lands quickly
        state = rn.load_state(self.out)
        self.assertEqual(state["runs_this_process"], 3)
        self.assertEqual(state["next_due"], "1970-01-01T01:01:40Z")  # 1000 + 2*900 + 900
        self.assertEqual(len(logs), 3)
        self.assertIn("ok", logs[0])

    def test_failure_backoff_and_counter(self):
        write_manifest(self.manifest, self.root, ["walk", "extract", "sanitize"], sweep="hourly",
                       extra={"sanitize": {"mode": "sterilize"}})
        clock = {"t": 1000.0}
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            clock["t"] += s

        rn.sweep(self.manifest, self.out, env={"PII_RECALL": "nope"}, allow_unsigned=True,
                 sleep=sleep, clock=lambda: clock["t"], max_runs=3, log=lambda s: None)
        state = rn.load_state(self.out)
        self.assertEqual(state["consecutive_failures"], 3)
        self.assertFalse(state["last_ok"])
        # retries at 60 s then 120 s, not the hourly cadence
        self.assertEqual(sum(sleeps), 60 + 120)


if __name__ == "__main__":
    unittest.main()
