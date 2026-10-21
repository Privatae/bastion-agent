"""Unit tests for the walk stage. Run: python3 -m unittest discover .

Builds a real temp tree so the walker is exercised on whatever OS runs the
suite; Windows-only behaviours (junctions, casefold) are covered by the
pieces that can be tested everywhere (the exclude matcher, _is_link fallback)
and by the platform guard in each test.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from .manifest import validate_document
from .walk import Excluder, Walker, _glob_to_regex, load_hash_cache, walk

IS_WINDOWS = os.name == "nt"


def manifest(root, **scope):
    doc = {
        "freeagent": 1, "id": "t", "owner": {"host": "h"},
        "scope": dict({"roots": [root]}, **scope),
        "mask": ["read"], "stages": ["walk"], "sweep": "manual",
        "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"},
    }
    return validate_document(doc)


def touch(path, data=b""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fa-walk-")
        self.out = tempfile.mkdtemp(prefix="fa-out-")
        touch(os.path.join(self.root, "a.txt"), b"hello\n")
        touch(os.path.join(self.root, "docs", "b.pdf"), b"%PDF-1.7 fake")
        touch(os.path.join(self.root, "docs", "c.bin"), b"\x00\x01\x02")
        touch(os.path.join(self.root, "docs", "empty"), b"")
        touch(os.path.join(self.root, "node_modules", "x", "y.js"), b"1")
        touch(os.path.join(self.root, "secret.key"), b"k")
        touch(os.path.join(self.root, "report.docx"), b"PK\x03\x04zip")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    def by_path(self, entries):
        return {e["path"]: e for e in entries}


class WalkTests(TreeCase):
    def test_map_shape_and_sorting(self):
        s = walk(manifest(self.root), self.out, now="2026-08-28T00:00:00Z")
        entries = read_jsonl(os.path.join(self.out, "walk.jsonl"))
        paths = [e["path"] for e in entries]
        self.assertEqual(paths, sorted(paths))
        m = self.by_path(entries)
        self.assertEqual(m["a.txt"]["kind"], "file")
        self.assertEqual(m["a.txt"]["size"], 6)
        self.assertEqual(m["a.txt"]["mime"], "text/plain")
        self.assertEqual(m["a.txt"]["sha256"], hashlib.sha256(b"hello\n").hexdigest())
        self.assertTrue(m["a.txt"]["mtime"].endswith("Z"))
        self.assertEqual(m["docs"]["kind"], "dir")
        self.assertEqual(m["docs/b.pdf"]["mime"], "application/pdf")
        self.assertEqual(m["docs/c.bin"]["mime"], "application/octet-stream")
        self.assertEqual(m["docs/empty"]["mime"], "inode/x-empty")
        self.assertEqual(m["report.docx"]["mime"],
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        self.assertEqual(s["entries"], len(entries))
        self.assertEqual(s["counts"]["files"], 7)
        self.assertEqual(s["counts"]["errors"], 0)
        self.assertEqual(s["walked_at"], "2026-08-28T00:00:00Z")
        self.assertTrue(s["manifest_digest"].startswith("sha256:"))
        self.assertEqual(s["roots"][0]["resolved"], os.path.abspath(self.root))
        # paths are '/'-separated on every OS
        self.assertTrue(all("\\" not in e["path"] for e in entries))

    def test_agent_dir_is_always_excluded(self):
        touch(os.path.join(self.root, ".agent", "catalog.jsonl"), b"{}")
        touch(os.path.join(self.root, "sub", ".agent", "x"), b"x")
        touch(os.path.join(self.root, "other", ".Agent", "y"), b"y")  # case-insensitive volumes
        walk(manifest(self.root), self.out)
        paths = {e["path"] for e in read_jsonl(os.path.join(self.out, "walk.jsonl"))}
        self.assertFalse(any(".agent" in p.lower() for p in paths), paths)

    def test_excludes_prune(self):
        m = manifest(self.root, exclude=["node_modules", "*.key", "docs/c.*"])
        s = walk(m, self.out)
        paths = {e["path"] for e in read_jsonl(os.path.join(self.out, "walk.jsonl"))}
        self.assertNotIn("node_modules", paths)
        self.assertNotIn("node_modules/x/y.js", paths)
        self.assertNotIn("secret.key", paths)
        self.assertNotIn("docs/c.bin", paths)
        self.assertIn("docs/b.pdf", paths)
        self.assertEqual(s["counts"]["excluded"], 3)

    def test_too_large_is_metadata_only(self):
        m = manifest(self.root, max_file_bytes=4)
        walk(m, self.out)
        e = self.by_path(read_jsonl(os.path.join(self.out, "walk.jsonl")))
        self.assertEqual(e["a.txt"]["skip"], "too_large")
        self.assertIsNone(e["a.txt"]["sha256"])
        self.assertEqual(e["a.txt"]["mime"], "text/plain")  # still sniffed
        self.assertEqual(e["docs/c.bin"]["sha256"], hashlib.sha256(b"\x00\x01\x02").hexdigest())

    def test_no_hash(self):
        s = walk(manifest(self.root), self.out, do_hash=False)
        self.assertEqual(s["counts"]["hashed"], 0)
        self.assertFalse(s["hashing"])
        e = self.by_path(read_jsonl(os.path.join(self.out, "walk.jsonl")))
        self.assertIsNone(e["a.txt"]["sha256"])

    def test_hash_cache_reuse_and_invalidation(self):
        walk(manifest(self.root), self.out)
        s2 = walk(manifest(self.root), self.out)
        self.assertEqual(s2["counts"]["hashed"], 0)
        self.assertEqual(s2["counts"]["hash_reused"], 7)
        # a content change with a new mtime is re-hashed
        p = os.path.join(self.root, "a.txt")
        touch(p, b"changed\n")
        os.utime(p, ns=(1, 1_700_000_000_000_000_000))
        s3 = walk(manifest(self.root), self.out)
        self.assertEqual(s3["counts"]["hashed"], 1)
        e = self.by_path(read_jsonl(os.path.join(self.out, "walk.jsonl")))
        self.assertEqual(e["a.txt"]["sha256"], hashlib.sha256(b"changed\n").hexdigest())

    def test_deterministic_output(self):
        walk(manifest(self.root), self.out)
        first = open(os.path.join(self.out, "walk.jsonl"), "rb").read()
        walk(manifest(self.root), self.out)
        self.assertEqual(first, open(os.path.join(self.out, "walk.jsonl"), "rb").read())

    def test_missing_root_is_an_error_not_a_crash(self):
        missing = os.path.join(self.root, "nope")
        m = manifest(missing)
        s = walk(m, self.out)
        self.assertEqual(s["counts"]["errors"], 1)
        self.assertIn("error", s["roots"][0])
        self.assertEqual(s["entries"], 0)

    def test_unreadable_dir_recorded(self):
        real = os.scandir

        def flaky(path):
            if os.path.basename(path) == "docs":
                raise PermissionError(13, "Permission denied")
            return real(path)

        with mock.patch("bastion_agent.walk.os.scandir", flaky):
            s = walk(manifest(self.root), self.out)
        e = self.by_path(read_jsonl(os.path.join(self.out, "walk.jsonl")))
        self.assertEqual(s["counts"]["errors"], 1)
        self.assertIn("Permission denied", e["docs"]["error"])
        self.assertNotIn("docs/b.pdf", e)

    def test_unicode_paths(self):
        touch(os.path.join(self.root, "résumé — 履歴書.txt"), b"x")
        walk(manifest(self.root), self.out)
        e = self.by_path(read_jsonl(os.path.join(self.out, "walk.jsonl")))
        self.assertIn("résumé — 履歴書.txt", e)

    def test_home_root_expands(self):
        with mock.patch.dict(os.environ, {"HOME": self.root, "USERPROFILE": self.root}):
            s = walk(manifest("~"), self.out)
        self.assertEqual(s["roots"][0]["resolved"], os.path.abspath(self.root))
        self.assertGreater(s["entries"], 0)

    @unittest.skipIf(IS_WINDOWS, "symlink creation needs a privilege on Windows")
    def test_symlink_recorded_not_followed(self):
        os.symlink(os.path.join(self.root, "docs"), os.path.join(self.root, "link-to-docs"))
        os.symlink("a.txt", os.path.join(self.root, "link-to-a"))
        s = walk(manifest(self.root), self.out)
        e = self.by_path(read_jsonl(os.path.join(self.out, "walk.jsonl")))
        self.assertEqual(e["link-to-docs"]["kind"], "symlink")
        self.assertEqual(e["link-to-a"]["target"], "a.txt")
        self.assertNotIn("link-to-docs/b.pdf", e)
        self.assertEqual(s["counts"]["symlinks"], 2)

    @unittest.skipIf(IS_WINDOWS, "symlink creation needs a privilege on Windows")
    def test_follow_symlinks_when_granted(self):
        os.symlink(os.path.join(self.root, "docs"), os.path.join(self.root, "link-to-docs"))
        walk(manifest(self.root, follow_symlinks=True), self.out)
        e = self.by_path(read_jsonl(os.path.join(self.out, "walk.jsonl")))
        self.assertEqual(e["link-to-docs"]["kind"], "dir")
        self.assertIn("link-to-docs/b.pdf", e)


class ExcludeTests(unittest.TestCase):
    def test_glob_translation(self):
        import re
        rx = lambda p: re.compile("^" + _glob_to_regex(p) + "$")
        self.assertTrue(rx("**/node_modules/**").match("a/b/node_modules/c/d.js"))
        self.assertTrue(rx("**/node_modules/**").match("node_modules/c"))
        self.assertTrue(rx("*.key").match("id.key"))
        self.assertFalse(rx("*.key").match("a/id.key"))
        self.assertTrue(rx("docs/*.pdf").match("docs/x.pdf"))
        self.assertFalse(rx("docs/*.pdf").match("docs/sub/x.pdf"))
        self.assertTrue(rx("docs/**").match("docs/sub/x.pdf"))
        self.assertTrue(rx("[!a]?.txt").match("bx.txt"))
        self.assertFalse(rx("[!a]?.txt").match("ax.txt"))

    def test_double_star_dir_pattern_prunes_the_dir(self):
        ex = Excluder(["**/.git/**"])
        self.assertTrue(ex.matches(".git"))
        self.assertTrue(ex.matches("a/.git"))
        self.assertTrue(ex.matches("a/.git/HEAD"))
        self.assertFalse(ex.matches("a/.gitignore"))

    def test_segment_patterns_match_at_any_depth(self):
        ex = Excluder(["node_modules", "*.key", ".git"])
        self.assertTrue(ex.matches("node_modules"))
        self.assertTrue(ex.matches("a/b/node_modules"))
        self.assertTrue(ex.matches("deep/id.key"))
        self.assertTrue(ex.matches("proj/.git"))
        self.assertFalse(ex.matches("proj/gitignore"))

    def test_path_patterns_are_anchored(self):
        ex = Excluder(["docs/private/**", "**/*.tmp"])
        self.assertTrue(ex.matches("docs/private/x"))
        self.assertTrue(ex.matches("docs/private"))  # the dir itself is pruned
        self.assertFalse(ex.matches("docs"))
        self.assertFalse(ex.matches("other/docs/private/x"))
        self.assertTrue(ex.matches("a.tmp"))
        self.assertTrue(ex.matches("a/b/c.tmp"))

    def test_backslash_patterns_normalised(self):
        ex = Excluder(["docs\\private\\**"])
        self.assertTrue(ex.matches("docs/private/x"))

    def test_case_sensitivity_matches_os(self):
        ex = Excluder(["*.PDF"])
        self.assertEqual(ex.matches("x.pdf"), IS_WINDOWS)


class CacheTests(unittest.TestCase):
    def test_cache_ignores_garbage_and_non_files(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w") as fh:
            fh.write('{"root":0,"path":"a","kind":"file","size":1,"mtime_ns":2,"sha256":"h"}\n')
            fh.write('{"root":0,"path":"d","kind":"dir"}\n')
            fh.write("not json\n")
        try:
            c = load_hash_cache(path)
        finally:
            os.unlink(path)
        self.assertEqual(c, {(0, "a"): (1, 2, "h")})

    def test_missing_cache_is_empty(self):
        self.assertEqual(load_hash_cache("/nonexistent/walk.jsonl"), {})


# The Python 3.8 syntax floor is enforced for this package by
# test_syntax_floor.py (shared with pii).


if __name__ == "__main__":
    unittest.main()
