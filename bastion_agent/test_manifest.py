"""Unit tests for the bastion agent manifest loader. Run: python3 -m unittest discover ."""

import copy
import hashlib
import os
import tempfile
import unittest

import yaml

from .manifest import (
    ManifestError,
    load_manifest,
    signing_digest,
    signing_payload,
    validate_document,
)

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(HERE, "..", "manifests", "home-documents.yaml")

MINIMAL = {
    "freeagent": 1,
    "id": "docs",
    "owner": {"host": "owner-host"},
    "scope": {"roots": ["~/Documents"]},
    "mask": ["read"],
    "stages": ["walk"],
    "sweep": "manual",
    "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"},
}

FULL = {
    "freeagent": 1,
    "id": "docs",
    "owner": {"host": "owner-host"},
    "scope": {"roots": ["/srv/a", "~/b"], "exclude": ["**/.git/**"]},
    "mask": ["read", "search", "index", "summarize"],
    "stages": ["walk", "extract", "sanitize", "chunk", "embed", "catalog", "seal"],
    "sanitize": {"mode": "sterilize", "verify": True},
    "embed": {"model": "m", "dim": 1024, "chunk": {"size_tokens": 512, "overlap_tokens": 64}},
    "summarize": {"model": "s", "per": ["file"]},
    "sweep": "daily",
    "sink": {"catalog": "host", "vectors": "local", "plaintext": "never", "seal_to": ["k1"]},
    "grants": [{"host": "other-host", "ops": ["search", "read_range"], "until": "2026-12-31"}],
}


def errors_of(doc, **kw):
    try:
        validate_document(doc, **kw)
    except ManifestError as exc:
        return exc.errors
    return []


def with_(base, **changes):
    doc = copy.deepcopy(base)
    for k, v in changes.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


class ValidTests(unittest.TestCase):
    def test_minimal(self):
        m = validate_document(MINIMAL)
        self.assertEqual(m.stages, ("walk",))
        self.assertEqual(m.scope.max_file_bytes, 256 * 1024 * 1024)
        self.assertIsNone(m.sanitize)
        self.assertIsNone(m.embed)
        self.assertEqual(m.grants, ())
        self.assertFalse(m.signed)

    def test_full(self):
        m = validate_document(FULL)
        self.assertEqual(m.sanitize.scope, "docs")  # defaults to the manifest id
        self.assertTrue(m.sanitize.verify)
        self.assertEqual(m.embed.chunk_overlap_tokens, 64)
        self.assertEqual(m.summarize.per, ("file",))
        self.assertEqual(m.sink.seal_to, ("k1",))
        self.assertEqual(m.grants[0].host, "other-host")
        self.assertEqual(m.grants[0].until.isoformat(), "2026-12-31")

    def test_example_file_loads(self):
        m = load_manifest(EXAMPLE)
        self.assertEqual(m.id, "home-documents")
        self.assertEqual(m.stages[-1], "seal")
        self.assertEqual(len(m.grants), 1)

    def test_yaml_date_grant(self):
        # PyYAML parses a bare 2026-12-31 as a date; both forms are accepted
        doc = yaml.safe_load("until: 2026-12-31")
        g = with_(FULL, grants=[{"host": "h", "ops": ["search"], "until": doc["until"]}])
        self.assertEqual(errors_of(g), [])


class DoctrineTests(unittest.TestCase):
    """The rules that exist because of what the product promises."""

    def test_plaintext_is_an_invariant(self):
        doc = with_(MINIMAL, sink={"catalog": "local", "vectors": "local", "plaintext": "host"})
        self.assertTrue(any("invariant" in e for e in errors_of(doc)))

    def test_vectors_local_only(self):
        doc = with_(MINIMAL, sink={"catalog": "local", "vectors": "host", "plaintext": "never"})
        self.assertTrue(any("vectors" in e for e in errors_of(doc)))

    def test_read_is_mandatory(self):
        self.assertTrue(any("mandatory" in e for e in errors_of(with_(MINIMAL, mask=["search"]))))

    def test_write_does_not_exist(self):
        self.assertTrue(any("mask" in e for e in errors_of(with_(MINIMAL, mask=["read", "write"]))))

    def test_stage_needs_mask_op(self):
        doc = with_(FULL, mask=["read", "search", "summarize"])
        errs = errors_of(doc)
        self.assertTrue(any("'embed' requires 'index'" in e for e in errs))
        self.assertTrue(any("'catalog' requires 'index'" in e for e in errs))

    def test_host_catalog_needs_seal(self):
        doc = with_(FULL, stages=["walk", "extract", "sanitize", "chunk", "embed", "catalog"],
                    grants=None, sink={"catalog": "host", "vectors": "local", "plaintext": "never"})
        self.assertTrue(any("unsealed" in e for e in errors_of(doc)))

    def test_grant_needs_seal(self):
        doc = with_(FULL, stages=["walk", "extract", "sanitize", "chunk", "embed", "catalog"],
                    sink={"catalog": "local", "vectors": "local", "plaintext": "never"})
        self.assertTrue(any("grants: any grant requires the 'seal'" in e for e in errors_of(doc)))

    def test_grant_search_needs_mask_search(self):
        doc = with_(FULL, mask=["read", "index", "summarize"])
        self.assertTrue(any("op 'search' requires 'search' in mask" in e for e in errors_of(doc)))

    def test_grant_to_self_refused(self):
        doc = with_(FULL, grants=[{"host": "owner-host", "ops": ["search"], "until": "2026-12-31"}])
        self.assertTrue(any("owner" in e for e in errors_of(doc)))

    def test_require_signed(self):
        self.assertTrue(any("signature: required" in e
                            for e in errors_of(MINIMAL, require_signed=True)))
        signed = with_(MINIMAL, signature={"alg": "ecdsa-p256-sha256", "cert": "c.crt",
                                           "value": "AAAA"})
        self.assertEqual(errors_of(signed, require_signed=True), [])


class StageTests(unittest.TestCase):
    def test_walk_first(self):
        self.assertTrue(any("first" in e for e in errors_of(with_(MINIMAL, stages=["extract"]))))

    def test_canonical_order(self):
        doc = with_(FULL, stages=["walk", "chunk", "extract", "sanitize", "embed", "catalog", "seal"])
        self.assertTrue(any("canonical order" in e for e in errors_of(doc)))

    def test_prerequisite_stage(self):
        doc = with_(MINIMAL, mask=["read", "index"], stages=["walk", "catalog"])
        self.assertTrue(any("'catalog' requires 'sanitize'" in e for e in errors_of(doc)))
        # chunk and catalog read the sanitized store: extract alone is not enough
        doc = with_(MINIMAL, mask=["read", "index"], stages=["walk", "extract", "catalog"])
        self.assertTrue(any("'catalog' requires 'sanitize'" in e for e in errors_of(doc)))
        doc = with_(FULL, stages=["walk", "extract", "chunk", "embed", "catalog", "seal"], sanitize=None)
        self.assertTrue(any("'chunk' requires 'sanitize'" in e for e in errors_of(doc)))

    def test_unknown_stage(self):
        self.assertTrue(errors_of(with_(MINIMAL, stages=["walk", "upload"])))

    def test_section_iff_stage(self):
        errs = errors_of(with_(MINIMAL, sanitize={"mode": "flag"}))
        self.assertTrue(any("not in stages" in e for e in errs))
        errs = errors_of(with_(MINIMAL, stages=["walk", "extract", "sanitize"]))
        self.assertTrue(any("sanitize: section required" in e for e in errs))
        errs = errors_of(with_(MINIMAL, mask=["read", "index"], sanitize={"mode": "flag"},
                               stages=["walk", "extract", "sanitize", "chunk", "embed"]))
        self.assertTrue(any("embed: section required" in e for e in errs))

    def test_summarize_needs_mask_and_catalog(self):
        doc = with_(MINIMAL, summarize={"model": "s", "per": ["file"]})
        errs = errors_of(doc)
        self.assertTrue(any("'summarize' is not in mask" in e for e in errs))
        self.assertTrue(any("requires the 'catalog' stage" in e for e in errs))


class FieldTests(unittest.TestCase):
    def test_unknown_keys_everywhere(self):
        self.assertTrue(any("unknown key 'extra'" in e for e in errors_of(with_(MINIMAL, extra=1))))
        doc = with_(MINIMAL, scope={"roots": ["/a"], "excludes": []})
        self.assertTrue(any("unknown key 'excludes'" in e for e in errors_of(doc)))

    def test_relative_root_refused(self):
        doc = with_(MINIMAL, scope={"roots": ["Documents"]})
        self.assertTrue(any("absolute" in e for e in errors_of(doc)))
        self.assertTrue(errors_of(with_(MINIMAL, scope={"roots": ["C:relative"]})))

    def test_windows_and_unc_roots_accepted(self):
        for root in (r"C:\Users\me\Documents", "D:/data", r"\\nas\share\docs", "~", "~/x", "/x"):
            self.assertEqual(errors_of(with_(MINIMAL, scope={"roots": [root]})), [], root)

    def test_schema_version(self):
        self.assertTrue(any("schema version" in e for e in errors_of(with_(MINIMAL, freeagent=2))))

    def test_slugs(self):
        self.assertTrue(errors_of(with_(MINIMAL, id="Home Docs")))
        self.assertTrue(errors_of(with_(MINIMAL, owner={"host": "Owner"})))

    def test_sweep_vocabulary(self):
        self.assertTrue(any("sweep" in e for e in errors_of(with_(MINIMAL, sweep="weekly"))))

    def test_embed_overlap_smaller_than_size(self):
        doc = with_(FULL, embed={"model": "m", "dim": 8,
                                 "chunk": {"size_tokens": 64, "overlap_tokens": 64}})
        self.assertTrue(any("smaller than size_tokens" in e for e in errors_of(doc)))

    def test_flag_mode_rejects_verify(self):
        doc = with_(FULL, sanitize={"mode": "flag", "verify": True})
        self.assertTrue(any("only valid with mode 'sterilize'" in e for e in errors_of(doc)))

    def test_bad_grant_date(self):
        doc = with_(FULL, grants=[{"host": "h", "ops": ["search"], "until": "2026-02-30"}])
        self.assertTrue(any("real YYYY-MM-DD" in e for e in errors_of(doc)))

    def test_bad_signature_base64(self):
        doc = with_(MINIMAL, signature={"alg": "ecdsa-p256-sha256", "cert": "c", "value": "*!*"})
        self.assertTrue(any("base64" in e for e in errors_of(doc)))

    def test_all_errors_collected(self):
        doc = with_(MINIMAL, freeagent=9, id="BAD", sweep="never", mask=["search"])
        self.assertGreaterEqual(len(errors_of(doc)), 4)


class SigningTests(unittest.TestCase):
    def test_payload_excludes_signature_and_is_canonical(self):
        signed = with_(FULL, signature={"alg": "ecdsa-p256-sha256", "cert": "c", "value": "AAAA"})
        self.assertEqual(signing_payload(signed), signing_payload(FULL))
        # key order in the source must not change the bytes
        reordered = dict(reversed(list(FULL.items())))
        self.assertEqual(signing_payload(reordered), signing_payload(FULL))
        self.assertNotIn(b" ", signing_payload(FULL))

    def test_digest_matches_payload(self):
        self.assertEqual(signing_digest(FULL),
                         hashlib.sha256(signing_payload(FULL)).hexdigest())

    def test_yaml_date_and_quoted_date_sign_identically(self):
        bare = yaml.safe_load("until: 2026-12-31")["until"]
        a = with_(FULL, grants=[{"host": "h", "ops": ["search"], "until": bare}])
        b = with_(FULL, grants=[{"host": "h", "ops": ["search"], "until": "2026-12-31"}])
        self.assertEqual(signing_payload(a), signing_payload(b))

    def test_any_field_change_changes_digest(self):
        self.assertNotEqual(signing_digest(FULL), signing_digest(with_(FULL, sweep="manual")))


class FileTests(unittest.TestCase):
    def test_missing_file(self):
        with self.assertRaises(ManifestError):
            load_manifest("/nonexistent/manifest.yaml")

    def test_invalid_yaml(self):
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as fh:
            fh.write("freeagent: [1\n")
        try:
            with self.assertRaises(ManifestError) as cm:
                load_manifest(path)
            self.assertIn("not valid YAML", cm.exception.errors[0])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
