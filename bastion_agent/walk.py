"""bastion agent `walk` stage — the filesystem + metadata map.

The cheapest thing a host can plan from: every entry under the manifest's
roots with path, kind, size, mtime, a sniffed MIME type and (for files within
`max_file_bytes`) a SHA-256. Nothing is read beyond an 8 KiB sniff and the
hash stream; nothing is written outside the output directory.

Portability is a requirement, not a nicety: this runs on the owner's Mac,
Windows box or Linux server. So: stdlib only, no syntax newer than Python
3.8, paths recorded `/`-separated relative to their root regardless of OS,
`~` expanded per-OS, symlinks AND Windows junctions treated alike (recorded,
never followed unless the manifest says so), and every entry sorted so two
runs over the same tree produce byte-identical maps.

Output (docs/walk.md): `<out>/walk.jsonl` (one JSON object per
entry, sorted by root index then path) and `<out>/walk.summary.json`. Both
are written atomically. A previous walk.jsonl in the same directory is used
as a hash cache: a file whose size and mtime_ns are unchanged keeps its
hash without being re-read.
"""

import datetime as _dt
import hashlib
import json
import os
import platform
import re
import tempfile

from .manifest import AGENT_DIR, signing_digest

HASH_BUF = 1024 * 1024
SNIFF_BYTES = 16
TEXT_PROBE_BYTES = 8192

# (prefix, mime) — a small, deterministic magic table for the formats a
# home corpus is made of. Anything else falls back to the extension, then
# to a text/binary probe. Order matters only where prefixes overlap.
MAGIC = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "application/x-riff"),  # refined below: WEBP / WAV / AVI
    (b"PK\x03\x04", "application/zip"),  # refined below: docx/xlsx/pptx by ext
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (b"\x7fELF", "application/x-executable"),
    (b"MZ", "application/x-dosexec"),
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
    (b"ID3", "audio/mpeg"),
    (b"fLaC", "audio/flac"),
    (b"OggS", "audio/ogg"),
    (b"\x00\x00\x00\x1cftyp", "video/mp4"),
    (b"\x00\x00\x00\x18ftyp", "video/mp4"),
    (b"\x00\x00\x00\x20ftyp", "video/mp4"),
    (b"\x1aE\xdf\xa3", "video/x-matroska"),
    (b"{\\rtf", "application/rtf"),
)
ZIP_BY_EXT = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".epub": "application/epub+zip",
    ".jar": "application/java-archive",
    ".apk": "application/vnd.android.package-archive",
}
OLE_BY_EXT = {
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".msg": "application/vnd.ms-outlook",
}
# extension table kept here rather than the `mimetypes` module: that module
# reads the OS registry / /etc/mime.types, so the same file would get a
# different type on a different machine. Determinism wins.
EXT_MIME = {
    ".txt": "text/plain", ".md": "text/markdown", ".markdown": "text/markdown",
    ".rst": "text/x-rst", ".csv": "text/csv", ".tsv": "text/tab-separated-values",
    ".json": "application/json", ".jsonl": "application/x-ndjson",
    ".yaml": "application/yaml", ".yml": "application/yaml", ".toml": "application/toml",
    ".xml": "application/xml", ".html": "text/html", ".htm": "text/html",
    ".css": "text/css", ".js": "text/javascript", ".mjs": "text/javascript",
    ".ts": "text/x-typescript", ".tsx": "text/x-typescript", ".jsx": "text/javascript",
    ".py": "text/x-python", ".go": "text/x-go", ".rs": "text/x-rust",
    ".java": "text/x-java", ".c": "text/x-c", ".h": "text/x-c", ".cpp": "text/x-c++",
    ".hpp": "text/x-c++", ".cs": "text/x-csharp", ".rb": "text/x-ruby",
    ".php": "text/x-php", ".sh": "text/x-shellscript", ".bash": "text/x-shellscript",
    ".ps1": "text/x-powershell", ".bat": "text/x-msdos-batch", ".sql": "application/sql",
    ".ini": "text/plain", ".cfg": "text/plain", ".conf": "text/plain", ".log": "text/plain",
    ".eml": "message/rfc822", ".ics": "text/calendar", ".vcf": "text/vcard",
    ".svg": "image/svg+xml", ".bmp": "image/bmp", ".tif": "image/tiff", ".tiff": "image/tiff",
    ".heic": "image/heic", ".webp": "image/webp",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".m4a": "audio/mp4", ".aac": "audio/aac",
    ".mp4": "video/mp4", ".mov": "video/quicktime", ".avi": "video/x-msvideo",
    ".mkv": "video/x-matroska", ".webm": "video/webm",
    ".pdf": "application/pdf", ".zip": "application/zip", ".gz": "application/gzip",
    ".tar": "application/x-tar", ".key": "application/x-pem-file", ".pem": "application/x-pem-file",
}
EXT_MIME.update(ZIP_BY_EXT)
EXT_MIME.update(OLE_BY_EXT)

KIND_FILE, KIND_DIR, KIND_SYMLINK, KIND_OTHER = "file", "dir", "symlink", "other"
SKIP_TOO_LARGE = "too_large"

_CASEFOLD = os.name == "nt"


class WalkError(Exception):
    pass


# ── exclude globs ───────────────────────────────────────────────────────────

def _glob_to_regex(pat):
    """`**` spans segments, `*`/`?` stay inside one, `[...]` passes through."""
    i, n, out = 0, len(pat), []
    while i < n:
        c = pat[i]
        if c == "*":
            if pat[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pat[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pat[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


class Excluder:
    """Compiled `scope.exclude`. A pattern with a `/` matches the whole
    root-relative path; one without also matches any single segment (so
    `node_modules` or `*.key` prune at any depth, gitignore-style)."""

    def __init__(self, patterns):
        flags = re.IGNORECASE if _CASEFOLD else 0
        self._path = []
        self._segment = []
        for p in patterns:
            p = p.replace("\\", "/").rstrip("/")
            rx = re.compile("^" + _glob_to_regex(p) + "$", flags)
            self._path.append(rx)
            if "/" not in p:
                self._segment.append(rx)
            elif p.endswith("/**"):
                # `docs/**` and `**/.git/**` prune the directory itself, not
                # just what is under it — otherwise the dir entry leaks into
                # the map while its contents are excluded
                self._path.append(re.compile("^" + _glob_to_regex(p[:-3]) + "$", flags))

    def matches(self, relpath):
        if not relpath:
            return False
        for rx in self._path:
            if rx.match(relpath):
                return True
        if self._segment:
            for seg in relpath.split("/"):
                for rx in self._segment:
                    if rx.match(seg):
                        return True
        return False


# ── helpers ─────────────────────────────────────────────────────────────────

def _utc_iso(ns):
    secs, rem = divmod(ns, 1_000_000_000)
    dt = _dt.datetime.fromtimestamp(secs, _dt.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%06dZ" % (rem // 1000)


def _relposix(root, path):
    rel = os.path.relpath(path, root)
    return "" if rel == os.curdir else rel.replace(os.sep, "/")


def _is_link(entry):
    """Symlink on every OS; on Windows also a junction (3.12+ exposes
    is_junction; older Pythons see junctions as directories, in which case
    the reparse tag on the lstat result is the tell)."""
    try:
        if entry.is_symlink():
            return True
    except OSError:
        return False
    is_junction = getattr(entry, "is_junction", None)
    if is_junction is not None:
        try:
            return bool(is_junction())
        except OSError:
            return False
    if os.name == "nt":
        try:
            st = entry.stat(follow_symlinks=False)
            tag = getattr(st, "st_reparse_tag", 0)
            return tag == 0xA0000003  # IO_REPARSE_TAG_MOUNT_POINT
        except OSError:
            return False
    return False


def _sniff(path, ext):
    """MIME by magic first, extension second, text/binary probe last."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(TEXT_PROBE_BYTES)
    except OSError as exc:
        return None, "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    for prefix, mime in MAGIC:
        if head.startswith(prefix):
            if mime == "application/zip":
                return ZIP_BY_EXT.get(ext, mime), None
            if mime == "application/x-ole-storage":
                return OLE_BY_EXT.get(ext, mime), None
            if mime == "application/x-riff":
                sub = head[8:12]
                return {b"WEBP": "image/webp", b"WAVE": "audio/wav",
                        b"AVI ": "video/x-msvideo"}.get(sub, mime), None
            return mime, None
    if ext in EXT_MIME:
        return EXT_MIME[ext], None
    if not head:
        return "inode/x-empty", None
    if b"\x00" in head:
        return "application/octet-stream", None
    return "text/plain", None


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(HASH_BUF)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def load_hash_cache(jsonl_path):
    """(root, path) -> (size, mtime_ns, sha256) from a previous walk."""
    cache = {}
    try:
        with open(jsonl_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("kind") == KIND_FILE and rec.get("sha256"):
                    cache[(rec["root"], rec["path"])] = (
                        rec.get("size"), rec.get("mtime_ns"), rec["sha256"])
    except OSError:
        pass
    return cache


def _atomic_write(path, write_fn):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            write_fn(fh)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── the walk ────────────────────────────────────────────────────────────────

class Walker:
    def __init__(self, manifest, hash_cache=None, do_hash=True):
        self.m = manifest
        # .agent/ is always excluded: it is the agent's own output, and indexing
        # it would feed the catalog back into itself
        self.excluder = Excluder(list(manifest.scope.exclude) + [AGENT_DIR])
        # …and on every OS regardless of case: a pre-existing ".Agent" on a
        # case-insensitive macOS volume IS the agent dir
        self.excluder._segment.append(re.compile("^" + re.escape(AGENT_DIR) + "$", re.IGNORECASE))
        self.cache = hash_cache or {}
        self.do_hash = do_hash
        self.entries = []
        self.counts = {k: 0 for k in (
            "files", "dirs", "symlinks", "other", "excluded", "errors",
            "too_large", "hashed", "hash_reused")}
        self.bytes = 0

    # records ---------------------------------------------------------------
    def _rec(self, root_idx, rel, kind, **extra):
        rec = {"root": root_idx, "path": rel, "kind": kind}
        rec.update(extra)
        self.entries.append(rec)
        return rec

    def _error(self, root_idx, rel, exc, kind=KIND_OTHER):
        self.counts["errors"] += 1
        msg = "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or exc)
        return self._rec(root_idx, rel, kind, error=msg)

    # per-entry --------------------------------------------------------------
    def _file(self, root_idx, rel, entry_path, st):
        size = st.st_size
        mtime_ns = st.st_mtime_ns
        ext = os.path.splitext(rel)[1].lower()
        mime, err = _sniff(entry_path, ext)
        rec = {"size": size, "mtime": _utc_iso(mtime_ns), "mtime_ns": mtime_ns,
               "mime": mime, "sha256": None}
        if err is not None:
            self.counts["errors"] += 1
            rec["error"] = err
            self._rec(root_idx, rel, KIND_FILE, **rec)
            return
        self.counts["files"] += 1
        self.bytes += size
        if size > self.m.scope.max_file_bytes:
            self.counts["too_large"] += 1
            rec["skip"] = SKIP_TOO_LARGE
        elif self.do_hash:
            cached = self.cache.get((root_idx, rel))
            if cached and cached[0] == size and cached[1] == mtime_ns:
                rec["sha256"] = cached[2]
                self.counts["hash_reused"] += 1
            else:
                try:
                    rec["sha256"] = _sha256(entry_path)
                    self.counts["hashed"] += 1
                except OSError as exc:
                    self.counts["errors"] += 1
                    rec["error"] = "%s: %s" % (type(exc).__name__, exc.strerror or exc)
        self._rec(root_idx, rel, KIND_FILE, **rec)

    def _link(self, root_idx, rel, entry_path):
        self.counts["symlinks"] += 1
        try:
            target = os.readlink(entry_path)
        except OSError as exc:
            target = None
            err = "%s: %s" % (type(exc).__name__, exc.strerror or exc)
            self._rec(root_idx, rel, KIND_SYMLINK, target=None, error=err)
            self.counts["errors"] += 1
            return
        if isinstance(target, bytes):
            target = os.fsdecode(target)
        self._rec(root_idx, rel, KIND_SYMLINK, target=target.replace(os.sep, "/"))

    # recursion --------------------------------------------------------------
    def _walk_dir(self, root_idx, root, dirpath):
        try:
            it = os.scandir(dirpath)
        except OSError as exc:
            self._error(root_idx, _relposix(root, dirpath), exc, KIND_DIR)
            return
        with it:
            try:
                entries = list(it)
            except OSError as exc:
                self._error(root_idx, _relposix(root, dirpath), exc, KIND_DIR)
                return
        for entry in entries:
            rel = _relposix(root, entry.path)
            if self.excluder.matches(rel):
                self.counts["excluded"] += 1
                continue
            follow = self.m.scope.follow_symlinks
            if _is_link(entry) and not follow:
                self._link(root_idx, rel, entry.path)
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=follow)
            except OSError as exc:
                self._error(root_idx, rel, exc)
                continue
            if is_dir:
                self.counts["dirs"] += 1
                try:
                    st = entry.stat(follow_symlinks=follow)
                    self._rec(root_idx, rel, KIND_DIR,
                              mtime=_utc_iso(st.st_mtime_ns), mtime_ns=st.st_mtime_ns)
                except OSError as exc:
                    self._error(root_idx, rel, exc, KIND_DIR)
                    continue
                self._walk_dir(root_idx, root, entry.path)
                continue
            try:
                is_file = entry.is_file(follow_symlinks=follow)
                st = entry.stat(follow_symlinks=follow)
            except OSError as exc:
                self._error(root_idx, rel, exc)
                continue
            if is_file:
                self._file(root_idx, rel, entry.path, st)
            else:
                self.counts["other"] += 1  # socket, fifo, device
                self._rec(root_idx, rel, KIND_OTHER)

    def run(self):
        roots = []
        for idx, raw in enumerate(self.m.scope.roots):
            resolved = os.path.abspath(os.path.expanduser(raw))
            roots.append({"index": idx, "path": raw, "resolved": resolved})
            if not os.path.isdir(resolved):
                self.counts["errors"] += 1
                roots[-1]["error"] = "not a directory or not present on this machine"
                continue
            self._walk_dir(idx, resolved, resolved)
        self.entries.sort(key=lambda r: (r["root"], r["path"]))
        return roots


def walk(manifest, out_dir, do_hash=True, now=None):
    """Run the walk stage for a validated manifest; write walk.jsonl and
    walk.summary.json into out_dir. Returns the summary dict."""
    os.makedirs(out_dir, exist_ok=True)
    jsonl = os.path.join(out_dir, "walk.jsonl")
    summary_path = os.path.join(out_dir, "walk.summary.json")
    cache = load_hash_cache(jsonl) if do_hash else {}
    w = Walker(manifest, hash_cache=cache, do_hash=do_hash)
    roots = w.run()

    def _write_jsonl(fh):
        for rec in w.entries:
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True))
            fh.write("\n")

    _atomic_write(jsonl, _write_jsonl)
    walked_at = now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = {
        "freeagent": 1,
        "stage": "walk",
        "manifest_id": manifest.id,
        "manifest_digest": "sha256:" + signing_digest(manifest.raw),
        "walked_at": walked_at,
        "platform": {"system": platform.system(), "python": platform.python_version()},
        "roots": roots,
        "entries": len(w.entries),
        "bytes": w.bytes,
        "counts": w.counts,
        "hashing": bool(do_hash),
    }
    _atomic_write(summary_path, lambda fh: fh.write(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"))
    return summary
