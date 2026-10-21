#!/usr/bin/env python3
"""Gate: no person's data in this repository — invented data only.

    python3 scripts/test_no_personal_data.py [--root DIR] [path-prefix ...]

Reads files, runs nothing. --root is the tree to scan (default: the directory
above this file). Optional path prefixes narrow the scan (for working on one
area); the gate always scans the whole tree.

A git repository holds code. Every value in a test, fixture, comment, doc,
config or prompt is invented: fictional names, example.com / .example domains,
entity ids of 9000 and above. A real incident is described by its mechanism,
never by its content: no database row, chat message, transcript line or
person's own words is pasted in, even to reproduce a bug. Source is copied
everywhere (clones, mirrors, the code index, CI logs, images), so data that
lands here is published far past where it came from.

This fails on:

  term       a word or phrase from TERMS: the owner's and members' details that
             were once copied into a repository (bank, employer, account
             digits, places, names, addresses, a device, a customer, a person's
             project, a Host's content, record ids). They are held as keyed
             digests, so this file does not publish what it keeps out, and a
             guess cannot be tested against the table without the key: every
             1-3 token n-gram of a line is normalised (lowercase letters and
             digits, joined by one space), HMAC-SHA256'd with the maintainers'
             key and looked up. The key lives outside the repository
             (NO_PERSONAL_DATA_KEY_FILE, default
             /etc/privatae/keys/no-personal-data.hmac), as do the plain list
             and the script that hashes it. Where the key is absent (a CI job,
             which holds no secrets) this class is skipped and the run says
             so; the other classes always run. A key other than the one TERMS
             was made with fails the run (KEY_CHECK), since it would match
             nothing.
  entity-id  a real entity id that labels a person's Host (RESERVED_ENTITY_IDS)
             in entity-N, entity N, entity_id=N, "entity_id": N, entity id N,
             Host N, Host #N or host-N form; examples and tests use 9000 and up
  provenance a line that says its data is real: "real rows" followed by
             "that" or "from", an all-caps "REAL" row, "verbatim" from a
             transcript or a run, a row "read off" an entity...
  email      a mailbox at a personal mail provider (gmail, yahoo, proton...)
  phone      a North American number outside the 555 fiction range

Every tracked text file is scanned, file names included, and every text member
of each zip-format bundle (an app bundle is one), since a bundle is what
installs. Lockfiles and other binary files are not.

A legitimate hit goes in the allow file beside this script
(test_no_personal_data.allow: path regex, class, text that must appear on the
line, why; tab-separated). An allow entry that matches nothing fails too, so
the list cannot outlive the line it was written for. The allow file quotes the
entity ids it allows, so that one class is not checked in it; the others are.

The same file is copied into each repository unchanged (it began as the Host
source's own gate of the same name). A copy rather than a
shared package: these repositories share no package index, and each CI job
fetches only its own repository with a token that can read nothing else.
What differs per repository is only its allow file.

Exit 0 = clean; exit 1 + FAIL lines otherwise.
"""

from __future__ import annotations

import hmac
import os
import re
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOW_FILE = os.path.join(HERE, "test_no_personal_data.allow")

# ── what is refused ──────────────────────────────────────────────────────────

# HMAC-SHA256(key, n-gram)[:32 hex] of each listed term (no labels: a label
# would say what kind of thing to guess).
TERMS: frozenset[str] = frozenset({
    "000bc5fad3f02d146be0dc6e4f26715d",
    "04e463f569b219d8f11026f0959826cb",
    "06f4cd7cf91b60d004f6412c9dfb7b06",
    "0c13f4c827dd9d1f534a8e789217289e",
    "1060330bf845a73f1ea3ff9afb6c1e6b",
    "116f56fc49ff92182ecf551aa998bc55",
    "12ae7bf559abc1e9b8006c7bdd0a8853",
    "19045b4e8ab55b83d7326a7cd729969d",
    "2415c59bff2a7b3b8a6d5d33c5181c02",
    "29ea8199c8b46d4bcfcfa1de1786e39c",
    "485c89ce20424f63cf61bcf0e99e8628",
    "4b1490e2c82c17e0549459f3db90d345",
    "4f6395fbbb21bed61fd7f09f130741bf",
    "5a1a3e985be55d572508f5ffe14efd31",
    "5c4cbfc9dcea9220b3e704d195227c9e",
    "5fc3674ca953220355c326e90b4f3550",
    "6b8cb443b5065174f6e43fb173366dae",
    "6fe596c2149f0b18f8f7c90d7f2c7624",
    "7f10fd17ee0f18bc8a1a5eb2df807633",
    "817e1b4a08dd711ac7acf8ab1174abd7",
    "8c322d5c2dd63340e29c692e333377cd",
    "99924c62fd06d98054ab779a56c3a32a",
    "a2e3a188d9d11a5cfb2d955df979d68c",
    "aed4a071febc17392ac3a6caf3addce6",
    "b5370efcf25e30a7f1dc99c97b595a69",
    "b5c8646d8b020e1badc0acf1c02a5b3c",
    "bb91be7ac9ffaaf209f03d398678692a",
    "cd007c979d9a8878075178046aa0d4fc",
    "cd0f03e03fd7cdde5a71b5dba23db423",
    "cf489ac86c8ea473b7e9ad7d0cd0621f",
    "d23b9d85227c17501b30ba87b4458139",
    "d7f731ffa3b06c56d17ad46b22a9f26a",
    "dbfb3de5d93b52e8f40698032af5569c",
    "e28851bfa17cafb8ac4b64c5a74819b0",
    "ef07986d74c66d20d72735adb76e419f",
    "f7e7951627d22c5021e56d11c59680db",
    "fe58dd5d2fd55c306be80b45c333adee",
})
_NGRAM_MAX = 3

# Entity ids of real Hosts that belong to people (the operator's own, members',
# the platform's Security entity and the two security-test Hosts).
RESERVED_ENTITY_IDS = (3, 102, 122, 123, 128, 163, 164)
_IDS = "|".join(str(i) for i in RESERVED_ENTITY_IDS)
ENTITY_ID = re.compile(
    r"\b(?:entit(?:y|ies)(?:[-_ ]|_id\s*==?\s*|_id[\"']?\s*:\s*|\s+id\s+|\s+#)"
    r"|Host\s+#?|host-)(?:%s)\b" % _IDS, re.I)

PROVENANCE = re.compile(
    r"\breal rows? (?:that|from|read|copied|taken|off)\b"
    r"|(?-i:\bREAL rows?\b)"
    r"|\bverbatim from (?:the |a |an )?(?:raw )?(?:transcript|capture|entity|host|run|turn|thread|chat|pod)\b"
    r"|\bread off entity\b"
    r"|\bcopied (?:in )?from (?:a|the) (?:live|real) (?:host|row|db|database|pod)\b"
    r"|\breal (?:host )?repl(?:y|ies) (?:from|on|of) (?:entity|host)\b"
    r"|\bthe incident's real\b", re.I)

EMAIL = re.compile(
    r"[A-Za-z0-9._%+-]+@(?:gmail|googlemail|yahoo|hotmail|outlook|live|icloud|me|aol|proton|protonmail|pm|gmx)"
    r"\.(?:com|me|net|org|co\.uk|de)\b", re.I)
PHONE = re.compile(r"(?<![\w.+])(?<!\d[ .-])(?:\+1[ .-]?)?\(?([2-9]\d{2})\)?[ .-]([2-9]\d{2})[ .-](\d{4})(?!\w)(?![ .-]\d)"
                   r"|(?<![\w.+])\+1([2-9]\d{2})([2-9]\d{2})(\d{4})(?!\w)")

CLASSES = ("term", "entity-id", "provenance", "email", "phone")

SKIP_FILES = re.compile(r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$")
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
              ".ttf", ".otf", ".eot", ".pdf", ".gz", ".tgz", ".wasm",
              ".mp3", ".mp4", ".webm", ".ogg", ".wav", ".bin", ".der", ".raw", ".pem", ".crt"}
# A bundle is recognised by its zip signature, not its name: any tracked file
# that opens as a zip and is not one of the binary types above. A .zip is not
# one of them: a zip a repository serves (a browser extension) installs too.
ZIP_MAGIC = b"PK\x03\x04"
_TOKEN = re.compile(r"[A-Za-z0-9]+")


KEY_FILE = os.environ.get("NO_PERSONAL_DATA_KEY_FILE", "/etc/privatae/keys/no-personal-data.hmac")


def load_key(path: str = KEY_FILE) -> bytes | None:
    try:
        with open(path) as f:
            return bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        return None


def digest(gram: str, key: bytes) -> str:
    return hmac.new(key, gram.encode(), "sha256").hexdigest()[:32]


# digest(KEY_CHECK_TEXT, key) for the key TERMS was made with. Any other key (a
# rotated, truncated or empty key file) would match none of TERMS and pass every
# tree, so the run fails on it instead. A MAC of a fixed public text says
# nothing about the key or the terms.
KEY_CHECK_TEXT = "no-personal-data key check"
KEY_CHECK = "7294506d83fc44365cf8647a7e400e89"


def key_matches(key: bytes) -> bool:
    return hmac.compare_digest(digest(KEY_CHECK_TEXT, key), KEY_CHECK)


class TermScanner:
    """Finds TERMS in a line by hashing its 1-3 token n-grams. Digests are
    cached, so a repeated n-gram is hashed once."""

    def __init__(self, terms, key):
        self.terms = terms
        self.key = key
        self._cache = {}

    def _hit(self, gram: str) -> bool:
        if gram not in self._cache:
            self._cache[gram] = digest(gram, self.key) in self.terms
        return self._cache[gram]

    def scan(self, line: str) -> int:
        if self.key is None:
            return 0
        toks = [t.lower() for t in _TOKEN.findall(line)]
        found = 0
        for n in range(1, _NGRAM_MAX + 1):
            for i in range(len(toks) - n + 1):
                if self._hit(" ".join(toks[i:i + n])):
                    found += 1
        return found


# A minified asset or a bundle member can hold one line of megabytes. It is read
# in windows rather than cut short, so a term past the first window is still
# found; the overlap is wider than any n-gram the table holds.
_WINDOW = 20000
_OVERLAP = 512


def windows(line: str):
    if len(line) <= _WINDOW:
        yield line
        return
    step = _WINDOW - _OVERLAP
    for i in range(0, len(line), step):
        yield line[i:i + _WINDOW]
        if i + _WINDOW >= len(line):
            return


def line_hits(line: str, scanner: TermScanner):
    """(window, class, what) for one line. A hit that two overlapping windows
    both hold is reported once."""
    seen = set()
    chunked = len(line) > _WINDOW
    for part in windows(line):
        for cls, what in line_findings(part, scanner):
            if chunked:
                if (cls, what) in seen:
                    continue
                seen.add((cls, what))
            yield part, cls, what


# Classes whose line would carry the personal value itself: their FAIL line
# names the file, the line and the class, never the text, so a CI log does not
# publish what the gate keeps out.
_QUIET = {"term", "email", "phone"}


def line_findings(line: str, scanner: TermScanner):
    out = []
    for _ in range(scanner.scan(line)):
        out.append(("term", "a listed term"))
    for m in ENTITY_ID.finditer(line):
        out.append(("entity-id", m.group(0)))
    for m in PROVENANCE.finditer(line):
        out.append(("provenance", m.group(0)))
    for m in EMAIL.finditer(line):
        out.append(("email", "a personal mail provider"))
    for m in PHONE.finditer(line):
        if (m.group(2) or m.group(5)) != "555":
            out.append(("phone", "a phone number"))
    return out


# ── the allow file ───────────────────────────────────────────────────────────

def load_allow(path: str = ALLOW_FILE):
    """[(path regex, class, text, why)] from the allow file; a missing file is
    an empty list. A malformed line is a failure, not a skipped entry."""
    entries, errors = [], []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return entries, errors
    for n, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) != 4 or not all(p.strip() for p in parts):
            errors.append("%s:%d: an allow entry is 4 tab-separated fields: path regex, class, text, why"
                          % (os.path.basename(path), n))
            continue
        path_re, cls, text, why = parts
        if cls not in CLASSES:
            errors.append("%s:%d: class %r is not one of %s" % (os.path.basename(path), n, cls, ", ".join(CLASSES)))
            continue
        try:
            re.compile(path_re)
        except re.error as e:
            errors.append("%s:%d: path regex does not compile: %s" % (os.path.basename(path), n, e))
            continue
        entries.append((path_re, cls, text, why))
    return entries, errors


def allowed(allow, label: str, cls: str, line: str, used: set) -> bool:
    for i, (path_re, a_cls, text, _why) in enumerate(allow):
        if a_cls == cls and text in line and re.search(path_re, label):
            used.add(i)
            return True
    return False


# ── reading the tree ─────────────────────────────────────────────────────────

def tracked_files(root: str):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=True, timeout=60).stdout
        files = [p for p in out.decode("utf-8", "replace").split("\0") if p]
        if files:
            return files
    except (OSError, subprocess.SubprocessError):
        pass
    files = []
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]
        for n in names:
            files.append(os.path.relpath(os.path.join(d, n), root))
    return files


def is_text(data: bytes) -> bool:
    return b"\0" not in data[:8192]


def texts(root: str, rel: str):
    """(label, text) for one tracked path: the file, or each bundle member.
    A file with a zip signature that does not open as a zip gives (label,
    None): its members cannot be read, so the run fails on it rather than
    passing what it could not see."""
    path = os.path.join(root, rel)
    if not os.path.isfile(path) or SKIP_FILES.search(rel):
        return
    if os.path.splitext(rel)[1].lower() in BINARY_EXT:
        return
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith(ZIP_MAGIC):
        try:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if os.path.splitext(name)[1].lower() in BINARY_EXT or SKIP_FILES.search(name):
                        continue
                    member = z.read(name)
                    if is_text(member):
                        yield "%s!%s" % (rel, name), member.decode("utf-8", "replace")
        except zipfile.BadZipFile:
            yield rel, None
        return
    if is_text(data):
        yield rel, data.decode("utf-8", "replace")


# ── self-test: the detector is not vacuous ───────────────────────────────────

def self_test():
    """Each class fires on a planted line and stays quiet on its look-alikes.
    Planted lines carry a "|" that is removed before they are read, so this
    file does not match its own patterns when it is scanned."""
    def live(s: str) -> str:
        return s.replace("|", "")

    fails = []
    probe_key = os.urandom(32)
    sc = TermScanner(frozenset(digest(g, probe_key) for g in ("zorblaxquent", "quilmar vesk", "tam orvel prax")),
                     probe_key)

    def classes(line):
        return {c for c, _ in line_findings(line, sc)}

    positives = [(c, live(s)) for c, s in [
        ("term", "pays into the Zorblaxquent ledger"), ("term", "QUILMAR-vesk sent it"),
        ("term", "a tam_orvel.prax file"),
        ("entity-id", "entity_id=|3,"), ("entity-id", '"entity_id": |128'), ("entity-id", "Entity |164's app"),
        ("entity-id", "kubectl -n entity-|3 exec"), ("entity-id", "pod entity-|3-0 restarted"), ("entity-id", "measured on Host #|163"),
        ("entity-id", "gitea_user = 'host-|3'"), ("entity-id", "entity id |122 knocked"),
        ("provenance", "the real| rows that fired on the Host"), ("provenance", "the REAL| row 9"),
        ("provenance", "verbatim| from the transcript"), ("provenance", "read| off entity 9001"),
        ("email", "mail ana.b@gm|ail.com today"), ("email", "x@proto|nmail.com"),
        ("phone", "call +1 (2|02) 555-|0100 or +1 30|1 444 1234"), ("phone", "+1|3014441234"),
    ]]
    negatives = [live(s) for s in [
        "zorblax quent", "quilmar", "a vesk quilmar", "orvel prax tam",
        "entity_id=9003", "entity_id=30", "entity 1023", "entity-3x", "host-31", "Host 7",
        "entity-9310-0.svc", "the v0.3.128 tag", "entity_id = <id>",
        "real rows in a throwaway container", "the real row replaces the echo",
        "returns the text verbatim", "ana@example.com", "a•••@gmail.com shows the first letter",
        "+1 415 555 0199", "+1|5555550100", "ids 2026091812345", "port 8800, 4096 MiB",
        "MemoryHigh=15032385536 MemoryMax=17179869184", "2026-10-07 12:00",
        "widths 278 584 556 1015 667 722",
    ]]
    for cls, line in positives:
        if cls not in classes(line):
            fails.append("self-test: %s not found in %r" % (cls, line))
    for line in negatives:
        if classes(line):
            fails.append("self-test: false hit %s in %r" % (classes(line), line))
    # A long line is read to its end: a term far past the first window, and one
    # straddling a window edge, are each found once.
    pad = "x " * 40000
    far = pad + live("the zorblax|quent ledger")
    edge = "y" * (_WINDOW - 10) + live(" zorblax|quent ") + "z" * 30000
    for name, line in (("far past the first window", far), ("on a window edge", edge)):
        got = [c for _p, c, _w in line_hits(line, sc) if c == "term"]
        if got != ["term"]:
            fails.append("self-test: a term %s of a long line is found once, got %s" % (name, got))
    # The real table is wired: every entry is a digest of the right shape.
    if not TERMS or not all(re.fullmatch(r"[0-9a-f]{32}", k) for k in TERMS):
        fails.append("self-test: TERMS is empty or malformed")
    # Without a key the term class is off and nothing else changes.
    keyless = TermScanner(sc.terms, None)
    got = {c for c, _ in line_findings(live("the zorblax|quent ledger, entity_id=|3, x@proto|nmail.com"), keyless)}
    if got != {"entity-id", "email"}:
        fails.append("self-test: without a key only the term class is off, got %s" % sorted(got))
    # A key other than the one TERMS was made with is told apart from it.
    if key_matches(probe_key) or key_matches(b""):
        fails.append("self-test: a key TERMS was not made with passes the key check")
    # An allow entry needs all four fields and a known class.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "a.allow")
        with open(p, "w", encoding="utf-8") as f:
            f.write("# a comment\n^docs/x\\.md$\tentity-id\tentity\tok\n^y$\tnot-a-class\tz\twhy\n^z$\tphone\n")
        entries, errors = load_allow(p)
        if len(entries) != 1 or len(errors) != 2:
            fails.append("self-test: the allow file reader kept %d entries and %d errors, want 1 and 2"
                         % (len(entries), len(errors)))
        # A zip-format bundle is opened by its signature, whatever it is named
        # (an app bundle, or a .zip such as a browser extension a site serves),
        # and its text members are read.
        for name in ("app.bundle", "ext.zip"):
            with zipfile.ZipFile(os.path.join(td, name), "w") as z:
                z.writestr("notes.txt", live("write to x@proto|nmail.com\n"))
            got = [(label, {c for ln in text.splitlines() for c, _ in line_findings(ln, keyless)})
                   for label, text in texts(td, name)]
            if got != [(name + "!notes.txt", {"email"})]:
                fails.append("self-test: a bundle's text member is read, got %s" % got)
        # A file with the zip signature that does not open is reported as
        # unreadable, not passed as an empty text.
        with open(os.path.join(td, "broken.bundle"), "wb") as f:
            f.write(ZIP_MAGIC + b"\x14\x00 not a zip")
        got = list(texts(td, "broken.bundle"))
        if got != [("broken.bundle", None)]:
            fails.append("self-test: a bundle that does not open is reported, got %s" % got)
    return fails


# ── main ─────────────────────────────────────────────────────────────────────

def main(argv) -> int:
    root = os.path.dirname(HERE)
    args = list(argv)
    if "--root" in args:
        i = args.index("--root")
        if i + 1 >= len(args):
            print("usage: test_no_personal_data.py [--root DIR] [path-prefix ...]")
            return 2
        root = os.path.abspath(args[i + 1])
        del args[i:i + 2]
    only = [a.rstrip("/") for a in args if not a.startswith("-")]
    fails = self_test()
    for f in fails:
        print("  FAIL  %s" % f)
    allow, allow_errors = load_allow()
    for e in allow_errors:
        fails.append(e)
        print("  FAIL  %s" % e)
    key = load_key()
    if key is None:
        print("  NOTE  term check skipped: no key at %s (set NO_PERSONAL_DATA_KEY_FILE); "
              "the entity-id, provenance, email and phone checks still run" % KEY_FILE)
    elif not key_matches(key):
        fails.append("the key at %s is not the one TERMS was made with, so it would match "
                     "nothing: point NO_PERSONAL_DATA_KEY_FILE at that key, or remake TERMS and KEY_CHECK" % KEY_FILE)
        print("  FAIL  %s" % fails[-1])
        key = None
    scanner = TermScanner(TERMS, key)
    used = set()
    findings = []
    counts = {}
    n_texts = 0
    # The allow file quotes the entity ids it allows; every other class is
    # still checked in it.
    allow_rel = os.path.relpath(ALLOW_FILE, root).replace(os.sep, "/")
    for rel in sorted(tracked_files(root)):
        if only and not any(rel == p or rel.startswith(p + "/") for p in only):
            continue
        for cls, what in line_findings(rel, scanner):
            if not allowed(allow, rel, cls, rel, used):
                findings.append("%s  [%s: %s]  (file name)" % (rel, cls, what))
                counts[cls] = counts.get(cls, 0) + 1
        for label, text in texts(root, rel):
            n_texts += 1
            if text is None:
                fails.append("%s has a zip signature but does not open as a zip, so its "
                             "members cannot be read" % label)
                print("  FAIL  %s" % fails[-1])
                continue
            for i, line in enumerate(text.splitlines(), 1):
                for part, cls, what in line_hits(line, scanner):
                    if (cls == "entity-id" and label == allow_rel) or allowed(allow, label, cls, part, used):
                        continue
                    shown = "" if cls in _QUIET else part.strip()[:140]
                    findings.append(("%s:%d  [%s: %s]  %s" % (label, i, cls, what, shown)).rstrip())
                    counts[cls] = counts.get(cls, 0) + 1
    for f in findings:
        print("  FAIL  %s" % f)
    if not only:
        for i, entry in enumerate(allow):
            if i not in used:
                fails.append("allow entry matches nothing, remove it: %s" % (entry[:3],))
                print("  FAIL  %s" % fails[-1])
    if findings or fails:
        summary = ", ".join("%s %d" % (k, v) for k, v in sorted(counts.items()))
        print("FAIL  %d finding(s) in %d texts (%s); %d other failure(s)"
              % (len(findings), n_texts, summary, len(fails)))
        return 1
    print("ok    %d texts clean" % n_texts)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
