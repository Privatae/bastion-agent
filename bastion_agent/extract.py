"""bastion agent `extract` stage — text out of the files the walk found.

Input is the walk map (walk.jsonl); output is a content-addressed text
store plus an index:

    <out>/extract/<aa>/<sha256>.txt     the extracted text, one file per
                                        distinct content hash
    <out>/extract.jsonl                 one record per walked file:
                                        status, extractor, chars, error
    <out>/extract.summary.json

Content-addressing is the cache: a file whose hash already has a text
entry is not opened again, on this sweep or the next, and two copies of
the same document are extracted once.

Portability rules are the walker's: stdlib only, Python 3.8 syntax floor,
runs on Mac/Windows/Linux. Office formats are zip + XML and need no
library. Two OUTSIDE tools are used when — and only when — they are on
the machine's PATH: `pdftotext` (poppler) for PDFs and `tesseract` for
images. They are sensors, resolved at run time and named in every record
they produced; nothing pins them and nothing fails for their absence —
the file is recorded `unsupported` with the tool that would handle it,
so the host can see exactly what it cannot read.

The built-in PDF path handles simple PDFs (uncompressed or Flate content
streams with simple fonts). It refuses to emit text that does not look
like text (CID/Identity-encoded fonts come out as byte salad), recording
`unsupported` instead — garbage in the catalog is worse than a gap.
"""

import codecs
import csv
import datetime as _dt
import email
import email.policy
import html
import html.parser
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
import zlib

from . import pdftext as _pdftext
import xml.etree.ElementTree as ET

from .manifest import signing_digest

STATUS_OK, STATUS_UNSUPPORTED, STATUS_ERROR, STATUS_SKIPPED, STATUS_EMPTY = (
    "ok", "unsupported", "error", "skipped", "empty")

# Bump when an extractor's output changes: every cached verdict and text
# carries the version it was produced by and is redone under a new one.
EXTRACT_VERSION = 2   # 2: the built-in PDF reader (pdftext) reads real PDFs

ZIP_MEMBER_CAP = 64 * 1024 * 1024   # decompressed bytes we will read from one member
TOOL_TIMEOUT = 300                   # seconds per external-tool call
PDF_TEXT_MIN_RATIO = 0.9             # printable share below which builtin PDF text is refused

TEXT_MIMES_PREFIX = ("text/",)
TEXT_MIMES = {
    "application/json", "application/x-ndjson", "application/yaml", "application/toml",
    "application/xml", "application/sql", "image/svg+xml", "application/x-pem-file",
}
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
ODT, ODS, ODP = ("application/vnd.oasis.opendocument.text",
                 "application/vnd.oasis.opendocument.spreadsheet",
                 "application/vnd.oasis.opendocument.presentation")
IMAGE_OCR_MIMES = ("image/png", "image/jpeg", "image/tiff", "image/bmp", "image/gif", "image/webp")


# ── text normalisation ──────────────────────────────────────────────────────

def _normalise(text):
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    text = unicodedata.normalize("NFC", text)
    return text.strip("\n") + ("\n" if text.strip() else "")


def decode_bytes(data):
    """Best-effort decode with the encoding recorded. BOMs first, strict
    UTF-8 next, UTF-16 by NUL pattern, then cp1252 with replacement."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace"), "utf-8-sig"
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", "replace"), "utf-16"
    # BOM-less UTF-16 is byte-valid UTF-8 (NUL is a code point), so the
    # NUL-density test has to come before the strict UTF-8 attempt.
    sample = data[:4096]
    if len(sample) >= 4 and sample.count(b"\x00") > len(sample) // 4:
        enc = "utf-16-le" if sample[1:2] == b"\x00" else "utf-16-be"
        return data.decode(enc, "replace"), enc
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    return data.decode("cp1252", "replace"), "cp1252"


# ── html ────────────────────────────────────────────────────────────────────

_BLOCK_TAGS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
               "section", "article", "header", "footer", "table", "ul", "ol",
               "blockquote", "pre", "hr", "td", "th", "dd", "dt", "title"}


class _HtmlText(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "template"):
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "template"):
            self._skip = max(0, self._skip - 1)
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)

    def text(self):
        out = "".join(self.parts)
        out = re.sub(r"[ \t\f\v]+", " ", out)
        out = re.sub(r" *\n *", "\n", out)
        return re.sub(r"\n{3,}", "\n\n", out)


def html_to_text(markup):
    p = _HtmlText()
    p.feed(markup)
    p.close()
    return p.text()


# ── office (zip + xml) ──────────────────────────────────────────────────────
#
# STREAMED, ON A BUDGET. A 200 KB spreadsheet can hold a gigabyte of XML, and
# parsing a member whole (ElementTree.fromstring) built the full tree in
# memory — two of them at once across sheets (measured 2.2 GB peak for a
# 1.3 MB xlsx). Members are fed to a pull parser in chunks; each wanted element
# (a paragraph, a row) is read and then dropped from its parent, so memory is
# one element, not one document. A document's decompressed XML, its text and
# its wall time are capped; reaching a cap stops the read with the text so far
# and says so on the last line. A DTD is refused outright: Office XML never
# carries one, and one is how entity expansion is smuggled in.

OFFICE_DOC_CAP = 256 * 1024 * 1024   # decompressed XML bytes, one document
OFFICE_TEXT_CAP = 16 * 1024 * 1024   # characters of text, one document
OFFICE_SECONDS = 60.0                # wall time, one document
# Parts one paragraph / row may hold while it is being read. A real paragraph
# has tens of runs and an Excel row at most 16,384 cells; a crafted one with
# millions is refused rather than held in memory.
OFFICE_PARTS_PER_ITEM = 200_000
_OFFICE_CHUNK = 64 * 1024
_DTD = re.compile(rb"<!(?:DOCTYPE|ENTITY)", re.I)
_DROPPED = "\x00dropped"
_XML_ENCODING = re.compile(r"""(<\?xml[^>]*?encoding\s*=\s*["'])[^"']*(["'])""")


class _OfficeStop(Exception):
    """A per-document cap was reached; the text so far stands."""


class _OfficeBudget:
    def __init__(self):
        self.bytes = self.chars = 0
        self.deadline = time.monotonic() + OFFICE_SECONDS
        self.cut_items = 0     # paragraphs/rows cut at OFFICE_PARTS_PER_ITEM

    def take_bytes(self, n):
        self.bytes += n
        if self.bytes > OFFICE_DOC_CAP:
            raise _OfficeStop("the document expands past %d MB of XML" % (OFFICE_DOC_CAP >> 20))
        if time.monotonic() > self.deadline:
            raise _OfficeStop("the document took longer than %ds to read" % OFFICE_SECONDS)

    def take_text(self, out, line):
        self.chars += len(line) + 1
        if self.chars > OFFICE_TEXT_CAP:
            raise _OfficeStop("the document holds more than %d MB of text" % (OFFICE_TEXT_CAP >> 20))
        out.append(line)


def _zip_elements(zf, name, budget, wanted, skip_within=()):
    """Yield each `wanted` element of one member as it closes, then drop it.
    A wanted tag inside a `skip_within` ancestor is left in place for that
    ancestor (an ODF table row reads its own cells' paragraphs). Every other
    finished element that no open wanted element needs is dropped as it
    closes too, so siblings never pile up — memory is one item, and removal
    from a parent stays O(1)."""
    info = zf.getinfo(name)
    if info.file_size > ZIP_MEMBER_CAP:
        raise ValueError("zip member %s too large (%d bytes)" % (name, info.file_size))
    keep = set(wanted) | set(skip_within)
    parser = ET.XMLPullParser(("start", "end"))
    stack = []
    state = {"skipping": 0, "keeping": 0, "parts": 0}

    # Finished elements are cleared at once (their subtree is freed) and
    # detached from their parents in one batch per fed chunk. The pull parser
    # reads the whole chunk ahead, so a closing element is NOT its parent's
    # last child when its event is handled, and remove() scans every kept
    # sibling from the start: per element that was quadratic.
    detach = {}

    def drop(el):
        el.clear()
        # Until flush() detaches it, a dropped element is still a child of
        # its parent; renamed so no reader's tag match sees it (a cut row
        # would otherwise end in empty cells).
        el.tag = _DROPPED
        if stack:
            parent = stack[-1]
            detach.setdefault(id(parent), (parent, set()))[1].add(id(el))

    def flush():
        for parent, gone in detach.values():
            parent[:] = [c for c in parent if id(c) not in gone]
        detach.clear()

    def drain():
        for ev, el in parser.read_events():
            if ev == "start":
                stack.append(el)
                if el.tag in skip_within:
                    state["skipping"] += 1
                if el.tag in keep:
                    state["keeping"] += 1
                elif state["keeping"]:
                    state["parts"] += 1
                    if state["parts"] == OFFICE_PARTS_PER_ITEM + 1:
                        budget.cut_items += 1
                continue
            stack.pop()
            if el.tag in skip_within:
                state["skipping"] -= 1
            if el.tag in keep:
                state["keeping"] -= 1
                if not state["keeping"]:
                    state["parts"] = 0
            if el.tag in wanted and not (state["skipping"] and el.tag not in skip_within):
                # How many wanted items are still open around this one: a
                # docx text box is a paragraph inside a paragraph.
                yield el, state["keeping"]
                drop(el)
            elif not state["keeping"] or state["parts"] > OFFICE_PARTS_PER_ITEM:
                # Past the cap, an item's further parts are dropped as they
                # close: that one paragraph or row is cut, the rest of the
                # document still reads.
                drop(el)

    seen, tail, utf16 = 0, b"", None
    with zf.open(name) as fh:
        while True:
            chunk = fh.read(_OFFICE_CHUNK)
            if not chunk:
                break
            if not seen:
                # OOXML allows UTF-8 or UTF-16. UTF-16 is decoded to UTF-8
                # here, BEFORE the DTD check, so a DTD cannot ride past it in
                # a wide encoding; the declaration is rewritten to match.
                # Anything else wide (UTF-32, no BOM) is refused.
                if chunk[:2] in (b"\xff\xfe", b"\xfe\xff"):
                    utf16 = codecs.getincrementaldecoder("utf-16")("strict")
                elif b"\x00" in chunk[:4]:
                    raise ValueError("zip member %s is not UTF-8 or UTF-16 XML" % name)
            if utf16 is not None:
                text = utf16.decode(chunk)
                if not seen:
                    text = _XML_ENCODING.sub(r"\1UTF-8\2", text, count=1)
                raw = chunk
                chunk = text.encode("utf-8")
                seen += len(raw)
            else:
                seen += len(chunk)
            if seen > ZIP_MEMBER_CAP:
                raise ValueError("zip member %s too large" % name)
            if _DTD.search(tail + chunk):
                raise ValueError("zip member %s declares a DTD; refused" % name)
            tail = chunk[-16:]
            budget.take_bytes(len(chunk))
            parser.feed(chunk)
            for item in drain():
                yield item
            flush()
    parser.close()
    for item in drain():
        yield item
    flush()


def _office(read):
    """Run one reader with a fresh budget; a cap reached keeps the text so
    far and names the cap on the last line."""
    budget, out = _OfficeBudget(), []
    try:
        read(budget, out)
    except _OfficeStop as e:
        out.append("[stopped reading here: %s]" % e)
    if budget.cut_items:
        out.append("[%d paragraph(s) or row(s) held more than %d parts; each was cut there]"
                   % (budget.cut_items, OFFICE_PARTS_PER_ITEM))
    return "\n".join(out)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
TEXT_NS = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
TABLE_NS = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"


def _docx_paragraph(p):
    parts = []
    for node in p.iter():
        t = _local(node.tag)
        if t == "t" and node.text:
            parts.append(node.text)
        elif t == "tab":
            parts.append("\t")
        elif t in ("br", "cr"):
            parts.append("\n")
    return "".join(parts)


def extract_docx(data):
    def read(budget, out):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            order = ["word/document.xml"] + sorted(
                n for n in names if re.match(r"word/(header|footer)\d*\.xml$", n))
            for name in order:
                if name not in names:
                    continue
                boxed = []      # text-box paragraphs, read after the paragraph holding them
                for p, depth in _zip_elements(zf, name, budget, {W + "p"}):
                    if depth:
                        boxed.append(_docx_paragraph(p))
                        continue
                    budget.take_text(out, _docx_paragraph(p))
                    for line in boxed:
                        budget.take_text(out, line)
                    boxed = []
                for line in boxed:
                    budget.take_text(out, line)
                out.append("")
    return _office(read)


def extract_xlsx(data):
    def read(budget, out):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            shared = []
            if "xl/sharedStrings.xml" in names:
                for si, _ in _zip_elements(zf, "xl/sharedStrings.xml", budget, {S + "si"}):
                    text = "".join(t.text or "" for t in si.iter(S + "t"))
                    budget.take_text([], text)       # shared strings count against the cap too
                    shared.append(text)
            sheets = sorted(n for n in names if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
            for name in sheets:
                out.append("# " + name.rsplit("/", 1)[-1][:-4])
                for row, _ in _zip_elements(zf, name, budget, {S + "row"}):
                    cells = []
                    for c in row.iter(S + "c"):
                        v = c.find(S + "v")
                        is_node = c.find(S + "is")
                        val = ""
                        if c.get("t") == "s" and v is not None and v.text is not None:
                            try:
                                val = shared[int(v.text)]
                            except (ValueError, IndexError):
                                val = ""
                        elif c.get("t") == "inlineStr" and is_node is not None:
                            val = "".join(t.text or "" for t in is_node.iter(S + "t"))
                        elif v is not None and v.text is not None:
                            val = v.text
                        cells.append(val)
                    if any(cells):
                        budget.take_text(out, "\t".join(cells))
                out.append("")
    return _office(read)


def extract_pptx(data):
    def read(budget, out):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            slides = sorted((n for n in names if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                            key=lambda n: int(re.search(r"(\d+)\.xml$", n).group(1)))
            for name in slides:
                out.append("# " + name.rsplit("/", 1)[-1][:-4])
                for p, _ in _zip_elements(zf, name, budget, {A + "p"}):
                    line = "".join(t.text or "" for t in p.iter(A + "t"))
                    if line:
                        budget.take_text(out, line)
                out.append("")
    return _office(read)


def extract_odf(data):
    row_tag, cell_tag = TABLE_NS + "table-row", TABLE_NS + "table-cell"

    def read(budget, out):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            wanted = {TEXT_NS + "p", TEXT_NS + "h", row_tag}
            for el, _ in _zip_elements(zf, "content.xml", budget, wanted, skip_within={row_tag}):
                if el.tag == row_tag:
                    # A row's cells hold paragraphs; the row is one line.
                    cells = ["".join(c.itertext()) for c in el if c.tag == cell_tag]
                    if any(cells):
                        budget.take_text(out, "\t".join(cells))
                else:
                    budget.take_text(out, "".join(el.itertext()))
    return _office(read)


# ── email, rtf ──────────────────────────────────────────────────────────────

def extract_eml(data):
    msg = email.message_from_bytes(data, policy=email.policy.default)
    head = []
    for h in ("From", "To", "Cc", "Date", "Subject"):
        if msg[h]:
            head.append("%s: %s" % (h, msg[h]))
    body = msg.get_body(preferencelist=("plain", "html"))
    text = ""
    if body is not None:
        content = body.get_content()
        text = html_to_text(content) if body.get_content_type() == "text/html" else content
    return "\n".join(head) + "\n\n" + text


_RTF_SKIP_GROUPS = {"fonttbl", "colortbl", "stylesheet", "info", "pict", "object",
                    "header", "footer", "xmlnstbl", "themedata", "datastore", "generator"}
_RTF_TOKEN = re.compile(r"\\([a-zA-Z]+)(-?\d+)? ?|\\'([0-9a-fA-F]{2})|\\([^a-zA-Z])|([{}])|([^\\{}]+)")


def extract_rtf(data):
    text = data.decode("latin-1", "replace")
    out = []
    stack = []
    skip_depth = None
    uc_skip = 0
    for m in _RTF_TOKEN.finditer(text):
        word, arg, hexch, esc, brace, plain = m.groups()
        if brace == "{":
            stack.append(len(out))
            continue
        if brace == "}":
            if stack:
                stack.pop()
            # the skipped group closes when the stack drops below the depth
            # it was opened at
            if skip_depth is not None and len(stack) < skip_depth:
                skip_depth = None
            continue
        if skip_depth is not None:
            continue
        if word:
            if word in _RTF_SKIP_GROUPS:
                skip_depth = len(stack)
            elif word in ("par", "line", "sect", "page"):
                out.append("\n")
            elif word == "tab":
                out.append("\t")
            elif word == "u" and arg is not None:
                cp = int(arg)
                out.append(chr(cp + 65536 if cp < 0 else cp))
                uc_skip = 1
            continue
        if hexch:
            if uc_skip:
                uc_skip -= 1
                continue
            out.append(bytes([int(hexch, 16)]).decode("cp1252", "replace"))
            continue
        if esc:
            out.append({"~": "\u00a0", "-": "", "_": "-", "\n": "\n", "\r": ""}.get(esc, esc))
            continue
        if plain:
            if uc_skip:
                plain = plain[uc_skip:]
                uc_skip = 0
            out.append(plain.replace("\r", "").replace("\n", ""))
    return "".join(out)


# ── pdf (built-in best effort) ──────────────────────────────────────────────

def extract_pdf_builtin(data):
    """Text from the document's pages with the standard library (pdftext):
    fonts' /ToUnicode maps, compressed streams and object streams, so a
    browser-printed PDF reads the same as an old literal-string one. Returns
    None when the result does not look like text (encrypted files, pages that
    are only pictures). pdftext never raises and reads on a per-document
    budget, so a hostile file costs bounded time and is at worst no text."""
    text = _pdftext.extract_text(data)
    if not text or not text.strip():
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t\f")
    if printable / max(1, len(text)) < PDF_TEXT_MIN_RATIO:
        return None
    return text


# ── external tools (sensors) ────────────────────────────────────────────────

def tool_path(name):
    return shutil.which(name)


def run_tool(argv, timeout=TOOL_TIMEOUT):
    """Run an external tool; returns stdout bytes or raises RuntimeError."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("%s: %s" % (argv[0], exc))
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError("%s exited %d: %s" % (argv[0], proc.returncode, err[-1] if err else ""))
    return proc.stdout


def extract_pdf_tool(path, pdftotext):
    return decode_bytes(run_tool([pdftotext, "-layout", "-enc", "UTF-8", path, "-"]))[0]


def extract_image_tool(path, tesseract):
    return decode_bytes(run_tool([tesseract, path, "stdout"]))[0]


# ── dispatch ────────────────────────────────────────────────────────────────

class Extractor:
    """Maps a walk record to (status, extractor_name, text_or_None, error)."""

    def __init__(self, use_external=True):
        self.pdftotext = tool_path("pdftotext") if use_external else None
        self.tesseract = tool_path("tesseract") if use_external else None

    def tools(self):
        return {"pdftotext": self.pdftotext, "tesseract": self.tesseract}

    def _read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def extract(self, path, mime):
        try:
            return self._extract(path, mime)
        except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError, zlib.error,
                RuntimeError, UnicodeError, KeyError, csv.Error) as exc:
            # csv.Error is NOT a ValueError: one >128 KiB CSV field escaped this
            # tuple and crash-looped the whole sweep
            return STATUS_ERROR, None, None, "%s: %s" % (type(exc).__name__, exc)

    def _extract(self, path, mime):
        if mime is None:
            return STATUS_UNSUPPORTED, None, None, "no mime"
        if mime == "inode/x-empty":
            return STATUS_OK, "empty", "", None  # recorded as `empty` by the stage
        if mime.startswith(TEXT_MIMES_PREFIX) or mime in TEXT_MIMES:
            text, enc = decode_bytes(self._read(path))
            if mime == "text/html":
                return STATUS_OK, "html", html_to_text(text), None
            if mime == "message/rfc822":
                return STATUS_OK, "eml", extract_eml(self._read(path)), None
            if mime in ("text/csv", "text/tab-separated-values"):
                rows = csv.reader(io.StringIO(text), delimiter="\t" if "tab" in mime else ",")
                return STATUS_OK, "csv", "\n".join("\t".join(r) for r in rows), None
            return STATUS_OK, "text:" + enc, text, None
        if mime == "message/rfc822":
            return STATUS_OK, "eml", extract_eml(self._read(path)), None
        if mime == "application/rtf":
            return STATUS_OK, "rtf", extract_rtf(self._read(path)), None
        if mime == DOCX:
            return STATUS_OK, "docx", extract_docx(self._read(path)), None
        if mime == XLSX:
            return STATUS_OK, "xlsx", extract_xlsx(self._read(path)), None
        if mime == PPTX:
            return STATUS_OK, "pptx", extract_pptx(self._read(path)), None
        if mime in (ODT, ODS, ODP):
            return STATUS_OK, "odf", extract_odf(self._read(path)), None
        if mime == "application/pdf":
            if self.pdftotext:
                return STATUS_OK, "pdftotext", extract_pdf_tool(path, self.pdftotext), None
            text = extract_pdf_builtin(self._read(path))
            if text is None:
                return (STATUS_UNSUPPORTED, "pdf-builtin", None,
                        "needs pdftotext (poppler) on this machine")
            return STATUS_OK, "pdf-builtin", text, None
        if mime in IMAGE_OCR_MIMES:
            if self.tesseract:
                return STATUS_OK, "tesseract", extract_image_tool(path, self.tesseract), None
            return STATUS_UNSUPPORTED, None, None, "needs tesseract on this machine"
        return STATUS_UNSUPPORTED, None, None, "no extractor for %s" % mime


# ── the stage ───────────────────────────────────────────────────────────────

def _atomic_write_text(path, text):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def store_path(out_dir, sha):
    return os.path.join(out_dir, "extract", sha[:2], sha + ".txt")


def load_walk(out_dir):
    path = os.path.join(out_dir, "walk.jsonl")
    if not os.path.exists(path):
        raise FileNotFoundError("no walk map at %s — run the walk stage first" % path)
    summary_path = os.path.join(out_dir, "walk.summary.json")
    with open(summary_path, encoding="utf-8") as fh:
        summary = json.load(fh)
    roots = {r["index"]: r["resolved"] for r in summary["roots"]}
    records = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("kind") == "file":
                records.append(rec)
    return roots, records, summary


def load_index(out_dir):
    """Previous extract.jsonl: sha256 -> record, so unchanged content is
    not re-extracted and prior unsupported/error verdicts are re-tried
    only when the machine's tools changed."""
    idx = {}
    path = os.path.join(out_dir, "extract.jsonl")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("sha256"):
                    idx[rec["sha256"]] = rec
    except OSError:
        pass
    return idx


def extract(manifest, out_dir, use_external=True, now=None):
    roots, files, walk_summary = load_walk(out_dir)
    ex = Extractor(use_external=use_external)
    tools = ex.tools()
    prev = load_index(out_dir)
    counts = {k: 0 for k in ("files", "ok", "reused", "unsupported", "error", "skipped", "empty")}
    chars = 0
    index = []
    done_sha = {}

    for rec in files:
        counts["files"] += 1
        sha = rec.get("sha256")
        base = {"root": rec["root"], "path": rec["path"], "sha256": sha, "mime": rec.get("mime"),
                "v": EXTRACT_VERSION}
        if rec.get("skip") or rec.get("error") or not sha:
            counts["skipped"] += 1
            index.append(dict(base, status=STATUS_SKIPPED,
                              error=rec.get("skip") or rec.get("error") or "no hash"))
            continue
        if sha in done_sha:  # duplicate content on this sweep
            dup = done_sha[sha]
            index.append(dict(dup, root=rec["root"], path=rec["path"]))
            counts["reused" if dup.get("reused") else dup["status"]] += 1
            if dup.get("reused") is None and dup["status"] == STATUS_OK:
                chars += dup.get("chars", 0)
            continue
        spath = store_path(out_dir, sha)
        old = prev.get(sha)
        if old and old.get("v") != EXTRACT_VERSION:
            old = None  # produced by an older extractor: redo
        if old and old.get("status") in (STATUS_OK, STATUS_EMPTY) and (
                old["status"] == STATUS_EMPTY or os.path.exists(spath)):
            out = dict(base, status=old["status"], extractor=old.get("extractor"),
                       chars=old.get("chars", 0), reused=True)
            counts["reused"] += 1
            chars += out["chars"]
            index.append(out)
            done_sha[sha] = out
            continue
        if old and old.get("status") == STATUS_UNSUPPORTED and old.get("tools") == tools:
            out = dict(base, status=STATUS_UNSUPPORTED, extractor=old.get("extractor"),
                       error=old.get("error"), tools=tools, reused=True)
            counts["unsupported"] += 1
            index.append(out)
            done_sha[sha] = out
            continue

        full = os.path.join(roots[rec["root"]], *rec["path"].split("/"))
        status, name, text, err = ex.extract(full, rec.get("mime"))
        out = dict(base, status=status, extractor=name)
        if status == STATUS_OK:
            text = _normalise(text or "")
            if not text.strip():
                out["status"] = STATUS_EMPTY
                out["chars"] = 0
            else:
                _atomic_write_text(spath, text)
                out["chars"] = len(text)
                chars += len(text)
        else:
            out["error"] = err
            if status == STATUS_UNSUPPORTED:
                out["tools"] = tools
        counts[out["status"]] += 1
        index.append(out)
        done_sha[sha] = out

    index.sort(key=lambda r: (r["root"], r["path"]))
    idx_path = os.path.join(out_dir, "extract.jsonl")
    _atomic_write_text(idx_path, "".join(
        json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in index))
    summary = {
        "freeagent": 1,
        "stage": "extract",
        "extractor_version": EXTRACT_VERSION,
        "manifest_id": manifest.id,
        "manifest_digest": "sha256:" + signing_digest(manifest.raw),
        "walk_digest": walk_summary.get("manifest_digest"),
        "extracted_at": now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": tools,
        "counts": counts,
        "chars": chars,
        "entries": len(index),
    }
    _atomic_write_text(os.path.join(out_dir, "extract.summary.json"),
                       json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return summary
