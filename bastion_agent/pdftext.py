"""Text out of a PDF with the standard library — the agent's built-in reader.

The regex reader it replaces found only literal `(...) Tj` strings, which is
how old PDFs set text. A browser's "Print to PDF" (and most modern writers)
sets text as glyph codes in hex strings through Type0 / Identity-H fonts,
mapped back to Unicode by each font's /ToUnicode CMap — the regex saw none of
it and returned nothing for a browser-printed page. A machine without
poppler (every Windows install) therefore got no text from most real PDFs.

This reader walks the document the way a viewer does, far enough for text:

  objects     `N G obj … endobj`, indexed in one linear pass (a later
              definition — an incremental update — wins), plus compressed
              object streams (/ObjStm)
  streams     raw or FlateDecode, each decoded once
  pages       the /Pages tree in order, with inherited /Resources
  fonts       /ToUnicode CMaps (bfchar, bfrange, byte widths from the
              codespace ranges); a simple font without one by its encoding
              (WinAnsi, MacRoman); glyph widths (/Widths, /W), so a word
              placed by position alone still gets its space
  content     BT/ET, Tf, TL, Tj, TJ, ', ", T*, Td/TD/Tm, and form XObjects
              (Do) with their own resources; the text state carries across
              a page's content streams

It reads arbitrary files, so it reads on a BUDGET (see Budget): wall time,
decoded bytes, content operators, form invocations and CMap entries are
capped per document, and reaching one stops the read with the text found so
far. Nothing raises out of extract_text; references never loop; encrypted
documents are refused (None).
"""

import bisect
import re
import time
import zlib

MAX_SECONDS = 60.0                    # wall time, one document
MAX_DECODED = 256 * 1024 * 1024       # decoded stream bytes, one document
MAX_INFLATE = 64 * 1024 * 1024        # decoded bytes, one stream
MAX_OPS = 5_000_000                   # content operators, one document
MAX_FORM_CALLS = 2_000                # form XObject invocations, one document
MAX_XOBJECT_DEPTH = 6
MAX_CMAP_ENTRIES = 200_000            # ToUnicode entries, one document
MAX_NESTING = 200                     # dict/array nesting inside one object
MAX_TOKENS = 20_000_000               # tokens lexed, one document
MAX_LEXED = 1024 * 1024 * 1024        # bytes lexed (re-reads included), one document
MAX_ARGS = 64                         # operands kept before an operator

# A gap wider than this share of the font size, on the same line, is a space
# (TJ kerning or an explicit move). With no real glyph widths the pen position
# is a guess, so only a gap past GUESS_GAP_EM is trusted to be a word break.
# A vertical move wider than NEWLINE_EM of the font size (and NEWLINE_Y at
# least) is a new line — a superscript's small rise is not.
GAP_EM = 0.18
GUESS_GAP_EM = 1.0
NEWLINE_EM = 0.5
NEWLINE_Y = 0.5

_HDR = re.compile(rb"(\d{1,10})\s+(\d{1,5})\s+obj\b")
_ENDOBJ = re.compile(rb"\bendobj\b")
_ENDSTREAM = re.compile(rb"endstream")
_STREAM_AFTER = re.compile(rb"[ \t\r\n\x0c\x00]*stream(?:\r\n|\n|\r)")
_NUM = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)")
_WS = b" \t\r\n\x0c\x00"
# Runs the lexer skips or takes whole are matched in C: a 64 MB run of
# spaces, a comment, a name or a string body is one regex call, not a
# Python loop per byte.
_WS_RUN = re.compile(rb"[ \t\r\n\x0c\x00]+")
_COMMENT_RUN = re.compile(rb"%[^\r\n]*")
_REGULAR_RUN = re.compile(rb"[^ \t\r\n\x0c\x00()<>\[\]{}/%]*")
_LITERAL_RUN = re.compile(rb"[^()\\]+")
# Everything that is not a hex digit, deleted in C by bytes.translate: a
# regex substitution made one match object per stripped byte (~90 bytes of
# memory each — 3 GB for a 32 MB spaced hex string).
_NON_HEX = bytes(b for b in range(256) if b not in b"0123456789abcdefABCDEF")
_DELIM = b"()<>[]{}/%"


def _first_at_or_after(positions, x):
    """Index of the first sorted integer position >= x (bisect_left on ints,
    spelled so the 3.8 syntax-floor check has nothing to flag)."""
    return bisect.bisect_right(positions, x - 1)


class _Ref(tuple):
    """An indirect reference (num, gen)."""


class _Spent(Exception):
    """A per-document limit was reached."""


class Budget:
    """What one document may cost. Every limit is per document, so a file
    built to multiply work (a form drawn by a form drawn by a form…, a CMap
    range per line, one huge stream referenced a thousand times) runs out of
    budget instead of out of memory or time."""

    def __init__(self, seconds=MAX_SECONDS):
        self.deadline = time.monotonic() + seconds
        self.decoded = self.ops = self.forms = self.cmap = self.tokens = 0
        self.lexed = self._lexed_at_check = 0
        self.reason = None

    def _stop(self, reason):
        self.reason = reason
        raise _Spent(reason)

    def check_time(self):
        if time.monotonic() > self.deadline:
            self._stop("time")

    def spend_decoded(self, n):
        self.decoded += n
        if self.decoded > MAX_DECODED:
            self._stop("decoded bytes")
        self.check_time()

    def spend_op(self):
        self.ops += 1
        if self.ops > MAX_OPS:
            self._stop("operators")
        if not self.ops & 0x3FFF:
            self.check_time()

    def spend_token(self, nbytes):
        """One token, and the bytes it covered: a single token can be a
        64 MB run of spaces, and a shared stream is re-read per page."""
        self.tokens += 1
        self.lexed += nbytes
        if self.tokens > MAX_TOKENS:
            self._stop("tokens")
        if self.lexed > MAX_LEXED:
            self._stop("bytes lexed")
        if not self.tokens & 0xFFF or self.lexed - self._lexed_at_check > (1 << 20):
            self._lexed_at_check = self.lexed
            self.check_time()

    def spend_form(self):
        self.forms += 1
        if self.forms > MAX_FORM_CALLS:
            self._stop("form invocations")

    def spend_cmap(self, n):
        self.cmap += n
        if self.cmap > MAX_CMAP_ENTRIES:
            self._stop("cmap entries")


def _number(word):
    """A PDF number: plain decimal only — PDF has no exponents, so `1.e999`
    is not a number, and an absurd digit string is 0, never an error."""
    if not _NUM.fullmatch(word):
        return None
    if len(word) > 20:                # no real coordinate or count is this long
        return 0
    try:
        return float(word) if b"." in word else int(word)
    except (ValueError, OverflowError):
        return 0


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# ── tokenizer / object parser ───────────────────────────────────────────────

class _Lexer:
    """Tokens of `data[pos:end]`. With a budget, every token is charged to it:
    one decoded stream may be lexed once per page, form or font that uses it,
    so the cost that has to be bounded is the lexing, not the decode."""

    def __init__(self, data, pos=0, end=None, budget=None):
        self.d = data
        self.i = pos
        self.n = len(data) if end is None else min(end, len(data))
        self.budget = budget

    def _skip(self):
        # Whitespace and comments alternate; each run is one C regex call and
        # the loop holds no state per pass (a single repeated-group regex kept
        # state per comment line: 5.8 GB for 32 MB of "%\\n"). The clock is
        # checked as the loop goes, so one huge run cannot outlast the budget.
        d, n, passes = self.d, self.n, 0
        while self.i < n:
            m = _WS_RUN.match(d, self.i, n) or _COMMENT_RUN.match(d, self.i, n)
            if not m or m.end() == self.i:
                break
            self.i = m.end()
            passes += 1
            if self.budget is not None and not passes & 0xFFF:
                self.budget.check_time()

    def token(self):
        """Next token: ('num', v) ('name', b) ('str', b) ('op', b) ('[',)
        (']',) ('<<',) ('>>',) or None at end."""
        start = self.i
        t = self._token()
        if self.budget is not None:
            self.budget.spend_token(self.i - start)
        return t

    def _token(self):
        self._skip()
        d, n = self.d, self.n
        if self.i >= n:
            return None
        c = d[self.i]
        if c == 0x28:  # (
            return ("str", self._literal())
        if c == 0x3c:  # <
            if d[self.i + 1:self.i + 2] == b"<":
                self.i += 2
                return ("<<",)
            return ("str", self._hex())
        if c == 0x3e and d[self.i + 1:self.i + 2] == b">":
            self.i += 2
            return (">>",)
        if c == 0x5b:
            self.i += 1
            return ("[",)
        if c == 0x5d:
            self.i += 1
            return ("]",)
        if c in b"{}":
            self.i += 1
            return ("op", bytes([c]))
        if c == 0x2f:  # /name
            j = _REGULAR_RUN.match(d, self.i + 1, n).end()
            name = d[self.i + 1:j]
            self.i = j
            return ("name", re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), name))
        j = _REGULAR_RUN.match(d, self.i, n).end()
        if j == self.i:           # a stray delimiter: step over it
            self.i += 1
            return ("op", bytes([c]))
        word = d[self.i:j]
        self.i = j
        v = _number(word)
        return ("op", word) if v is None else ("num", v)

    def _literal(self):
        d, n = self.d, self.n
        self.i += 1
        depth, out, passes = 1, bytearray(), 0
        while self.i < n:
            passes += 1
            if self.budget is not None and not passes & 0xFFFF:
                self.budget.check_time()     # escapes and parens go byte by byte
            m = _LITERAL_RUN.match(d, self.i, n)
            if m:
                out += m.group(0)
                self.i = m.end()
                if self.i >= n:
                    break
            c = d[self.i]
            if c == 0x5c:  # backslash
                self.i += 1
                if self.i >= n:
                    break
                e = d[self.i]
                if e in b"nrtbf":
                    out += {0x6e: b"\n", 0x72: b"\r", 0x74: b"\t", 0x62: b"\b", 0x66: b"\f"}[e]
                    self.i += 1
                elif 0x30 <= e <= 0x37:
                    m = re.match(rb"[0-7]{1,3}", d[self.i:self.i + 3])
                    out.append(int(m.group(0), 8) & 0xFF)
                    self.i += len(m.group(0))
                elif e in b"\r\n":   # line continuation
                    self.i += 1
                    if e == 0x0d and d[self.i:self.i + 1] == b"\n":
                        self.i += 1
                else:
                    out.append(e)
                    self.i += 1
                continue
            if c == 0x28:
                depth += 1
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    self.i += 1
                    break
            out.append(c)
            self.i += 1
        return bytes(out)

    def _hex(self):
        d = self.d
        j = d.find(b">", self.i + 1, self.n)
        if j < 0:
            j = self.n
        hx = d[self.i + 1:j].translate(None, _NON_HEX)
        self.i = j + 1
        if len(hx) % 2:
            hx += b"0"
        return bytes.fromhex(hx.decode("ascii"))

    def obj(self, depth=0):
        """One PDF object at the cursor (dicts, arrays, refs as _Ref).
        Nesting deeper than MAX_NESTING is a ValueError, never a
        RecursionError."""
        if depth > MAX_NESTING:
            raise ValueError("nesting too deep")
        return self._from(self.token(), depth)

    def _from(self, t, depth):
        if t is None:
            return None
        k = t[0]
        if k == "<<":
            dct = {}
            while True:
                kt = self.token()
                if kt is None or kt[0] == ">>":
                    return dct
                if kt[0] != "name":
                    continue
                dct[kt[1]] = self.obj(depth + 1)
        if k == "[":
            arr = []
            while True:
                save = self.i
                it = self.token()
                if it is None or it[0] == "]":
                    return arr
                if it[0] == "op" and it[1] == b"R" and len(arr) >= 2 \
                        and _is_int(arr[-1]) and _is_int(arr[-2]):
                    g, nnum = arr.pop(), arr.pop()
                    arr.append(_Ref((nnum, g)))
                    continue
                self.i = save
                arr.append(self.obj(depth + 1))
        if k == "num":
            # `N G R` → a reference
            save = self.i
            t2 = self.token()
            if t2 and t2[0] == "num" and _is_int(t[1]):
                t3 = self.token()
                if t3 and t3[0] == "op" and t3[1] == b"R":
                    return _Ref((t[1], t2[1]))
            self.i = save
            return t[1]
        if k in ("name", "str"):
            return t[1]
        if k == "op":
            return {b"true": True, b"false": False, b"null": None}.get(t[1], t[1])
        return None


# ── the document ────────────────────────────────────────────────────────────

class _Doc:
    def __init__(self, data, budget):
        self.data = data
        self.budget = budget
        self.objs = {}            # num -> (value, raw stream bytes or None)
        self._at = {}             # num -> file offset of the definition kept
        self._decoded = {}        # num -> decoded stream bytes (or None)
        self.cmaps = {}           # ToUnicode stream num -> (map, code widths)
        self._index(data)
        for num, (val, raw) in list(self.objs.items()):
            if isinstance(val, dict) and val.get(b"Type") == b"ObjStm" and raw is not None:
                self._unpack_objstm(num, val)

    def _index(self, data):
        # One linear pass: object headers, `endobj`s and `endstream`s are
        # each found once and paired by bisection, so a file with a missing
        # `endobj` (or thousands of them) costs the same as a clean one.
        hdrs = list(_HDR.finditer(data))
        ends = [m.start() for m in _ENDOBJ.finditer(data)]
        estreams = [m.start() for m in _ENDSTREAM.finditer(data)]
        skip = 0
        for idx, m in enumerate(hdrs):
            if not idx & 0x3FF:
                self.budget.check_time()
            if m.start() < skip:          # inside the previous stream's bytes
                continue
            k = _first_at_or_after(ends, m.end())
            stop = ends[k] if k < len(ends) else len(data)
            nxt = hdrs[idx + 1].start() if idx + 1 < len(hdrs) else len(data)
            # The object first, bounded by its own endobj (or the next header):
            # only a DICTIONARY followed directly by the `stream` keyword owns
            # stream bytes — the word inside a string or a name does not.
            lx = _Lexer(data, m.end(), min(stop, nxt), budget=self.budget)
            try:
                val = lx.obj()
            except ValueError:            # one bad object is skipped, not fatal
                continue
            raw = None
            sm = _STREAM_AFTER.match(data, lx.i) if isinstance(val, dict) else None
            if sm:
                start = sm.end()
                end = None
                ln = val.get(b"Length")
                if _is_int(ln) and ln >= 0 and \
                        data[start + ln:start + ln + 12].lstrip(_WS).startswith(b"endstream"):
                    end = start + ln
                if end is None:           # indirect or wrong /Length: the keyword
                    j = _first_at_or_after(estreams, start)
                    end = estreams[j] if j < len(estreams) else len(data)
                    if data[end - 2:end] == b"\r\n":
                        end -= 2
                    elif data[end - 1:end] in (b"\n", b"\r"):
                        end -= 1
                raw = data[start:end]
                skip = end
            self._put(int(m.group(1)), val, raw, m.start())

    def _put(self, num, val, raw, at):
        # Incremental updates APPEND a new definition: the later one wins.
        if num in self._at and self._at[num] > at:
            return
        self.objs[num] = (val, raw)
        self._at[num] = at
        self._decoded.pop(num, None)

    def _unpack_objstm(self, snum, dct):
        data = self.stream(_Ref((snum, 0)))
        if data is None:
            return
        n, first = self.get(dct.get(b"N")), self.get(dct.get(b"First"))
        if not (_is_int(n) and _is_int(first)) or n <= 0 or not 0 <= first <= len(data):
            return
        lx = _Lexer(data, budget=self.budget)
        pairs = []
        for _ in range(min(n, len(data))):
            a, b = lx.token(), lx.token()
            if not a or not b or a[0] != "num" or b[0] != "num" \
                    or not _is_int(a[1]) or not _is_int(b[1]):
                break
            pairs.append((a[1], b[1]))
        at = self._at.get(snum, 0)
        for num, off in pairs:
            if not 0 <= off < len(data) - first:
                continue
            try:
                val = _Lexer(data, first + off, budget=self.budget).obj()
            except ValueError:
                continue
            self._put(num, val, None, at)

    def get(self, v):
        """Resolve references (cycle-safe)."""
        seen = set()
        while isinstance(v, _Ref):
            if v[0] in seen:
                return None
            seen.add(v[0])
            v = self.objs.get(v[0], (None, None))[0]
        return v

    def stream(self, v):
        """The decoded bytes of a stream object (by ref), or None. Decoded
        once per document; the cost counts against the budget."""
        if not isinstance(v, _Ref):
            return None
        num = v[0]
        if num in self._decoded:
            return self._decoded[num]
        dct, raw = self.objs.get(num, (None, None))
        out = None
        if raw is not None and isinstance(dct, dict):
            out = self._decode(dct, raw)
            if out is not None:
                self.budget.spend_decoded(len(out))
        self._decoded[num] = out
        return out

    def _decode(self, dct, raw):
        f = self.get(dct.get(b"Filter"))
        filters = f if isinstance(f, list) else ([f] if f else [])
        data = raw
        for flt in filters:
            flt = self.get(flt)
            if flt in (b"FlateDecode", b"Fl"):
                try:
                    data = zlib.decompressobj().decompress(data, MAX_INFLATE)
                except zlib.error:
                    return None
            else:
                return None          # a filter we do not read: skip the stream
        return data

    def pages(self):
        """(page dict, resources) in document order, resources inherited."""
        root = None
        for val, _ in self.objs.values():
            if isinstance(val, dict) and val.get(b"Type") == b"Catalog":
                root = self.get(val.get(b"Pages"))
                break
        out = []
        if isinstance(root, dict):
            self._walk_pages(root, None, out, set(), 0)
        if not out:     # no usable tree: every page object, in file order
            for val, _ in self.objs.values():
                if isinstance(val, dict) and val.get(b"Type") == b"Page":
                    res = self.get(val.get(b"Resources"))
                    out.append((val, res if isinstance(res, dict) else None))
        return out

    def _walk_pages(self, node, res, out, seen, depth):
        if id(node) in seen or depth > 64:
            return
        seen.add(id(node))
        r = self.get(node.get(b"Resources"))
        if isinstance(r, dict):
            res = r
        kids = self.get(node.get(b"Kids"))
        if node.get(b"Type") == b"Page" or not isinstance(kids, list):
            out.append((node, res))
            return
        for k in kids:
            kid = self.get(k)
            if isinstance(kid, dict):
                self._walk_pages(kid, res, out, seen, depth + 1)


# ── fonts ───────────────────────────────────────────────────────────────────

_SIMPLE_CODECS = {b"WinAnsiEncoding": "cp1252", b"MacRomanEncoding": "mac_roman"}


def _widths(text):
    return [int(x) for x in text.split()]


# THE STANDARD FONTS' OWN WIDTHS, for a simple font that names one and ships
# no /Widths (legal before PDF 1.5, and common in old files). Codes 32-126 in
# StandardEncoding, from the metric-compatible URW base-35 AFMs (NimbusSans =
# Helvetica, NimbusRoman = Times); Courier is 600 for every glyph. Real widths
# are what let a gap between words placed by position read as a space without
# inventing one inside a word of wide letters.
_STD_WIDTHS = {
    "Helvetica": _widths("""
        278 278 355 556 556 889 667 222 333 333 389 584 278 333 278 278 556 556 556
        556 556 556 556 556 556 556 278 278 584 584 584 556 1015 667 667 722 722 667
        611 778 722 278 500 667 556 833 722 778 667 778 722 667 611 722 667 944 667
        667 611 278 278 278 469 556 222 556 556 500 556 556 278 556 556 222 222 500
        222 833 556 556 556 556 333 500 278 556 500 722 500 500 500 334 260 334 584"""),
    "Helvetica-Bold": _widths("""
        278 333 474 556 556 889 722 278 333 333 389 584 278 333 278 278 556 556 556
        556 556 556 556 556 556 556 333 333 584 584 584 611 975 722 722 722 722 667
        611 778 722 278 556 722 611 833 722 778 667 778 722 667 611 722 667 944 667
        667 611 333 278 333 584 556 278 556 611 556 611 556 333 611 611 278 278 556
        278 889 611 611 611 611 389 556 333 611 556 778 556 556 500 389 280 389 584"""),
    "Times": _widths("""
        250 333 408 500 500 833 778 333 333 333 500 564 250 333 250 278 500 500 500
        500 500 500 500 500 500 500 278 278 564 564 564 444 921 722 667 667 722 611
        556 722 722 333 389 722 611 889 722 722 556 722 667 556 611 722 722 944 722
        722 611 333 278 333 469 500 333 444 500 444 500 444 333 500 500 278 278 500
        278 778 500 500 500 500 333 389 278 500 500 722 500 500 444 480 200 480 541"""),
    "Times-Bold": _widths("""
        250 333 555 500 500 1000 833 333 333 333 500 570 250 333 250 278 500 500 500
        500 500 500 500 500 500 500 333 333 570 570 570 500 930 722 667 722 722 667
        611 778 778 389 500 778 667 944 722 778 611 778 722 556 667 722 722 1000 722
        722 667 333 278 333 581 500 333 500 556 444 556 444 333 500 556 278 333 556
        278 833 556 500 556 556 444 389 333 556 500 722 500 500 444 394 220 394 520"""),
}


def _standard_widths(base):
    """(first code, widths) for a standard-14 BaseFont name, or None."""
    name = base.split(b"+", 1)[-1].decode("latin-1", "replace").replace(",", "-")
    if name.startswith("Courier"):
        return 32, [600] * 95
    family = ("Helvetica" if name.startswith(("Helvetica", "Arial")) else
              "Times" if name.startswith("Times") else None)
    if family is None:
        return None
    bold = "Bold" in name or "Black" in name
    return 32, _STD_WIDTHS[family + ("-Bold" if bold else "")]


class _Font:
    def __init__(self, doc, fdict):
        self.map = {}          # code bytes -> str
        self.widths = [1]      # byte lengths codes come in
        self.cid = fdict.get(b"Subtype") == b"Type0"
        self.codec = "cp1252"  # a simple font with no map (StandardEncoding ≈ ASCII)
        self.adv = {}          # code -> advance, 1/1000 of the font size
        self.default_adv = 1000 if self.cid else 500
        enc = doc.get(fdict.get(b"Encoding"))
        if isinstance(enc, dict):
            enc = doc.get(enc.get(b"BaseEncoding"))
        if isinstance(enc, bytes) and enc in _SIMPLE_CODECS:
            self.codec = _SIMPLE_CODECS[enc]
        if self.cid:
            self.widths = [2]
            self._cid_widths(doc, fdict)
        else:
            self._simple_widths(doc, fdict)
            if not self.adv:
                # No widths and not a standard font (a spec violation, but
                # seen): guess wide, so the guessed pen never falls short of
                # a real glyph and invents a space inside a word.
                self.default_adv = 1000
        tu = fdict.get(b"ToUnicode")
        if isinstance(tu, _Ref):
            # One CMap is often shared by many fonts: parse it once.
            cached = doc.cmaps.get(tu[0])
            if cached is None:
                cmap = doc.stream(tu)
                if cmap:
                    self._parse(cmap, doc.budget)
                cached = doc.cmaps[tu[0]] = (self.map, self.widths)
            self.map, self.widths = cached

    def _simple_widths(self, doc, fdict):
        first = doc.get(fdict.get(b"FirstChar"))
        ws = doc.get(fdict.get(b"Widths"))
        if not isinstance(ws, list):
            base = doc.get(fdict.get(b"BaseFont"))
            std = _standard_widths(base) if isinstance(base, bytes) else None
            if std:
                first, ws = std
        if _is_int(first) and isinstance(ws, list):
            for i, w in enumerate(ws[:256]):
                w = doc.get(w)
                if _is_num(w):
                    self.adv[first + i] = w

    def _cid_widths(self, doc, fdict):
        ds = doc.get(fdict.get(b"DescendantFonts"))
        d0 = doc.get(ds[0]) if isinstance(ds, list) and ds else None
        if not isinstance(d0, dict):
            return
        dw = doc.get(d0.get(b"DW"))
        if _is_num(dw):
            self.default_adv = dw
        w = doc.get(d0.get(b"W"))
        if not isinstance(w, list):
            return
        # [c [w1 w2 …]] or [c_first c_last w], repeated.
        i = 0
        while i < len(w) and len(self.adv) < 65536:
            c = doc.get(w[i])
            nxt = doc.get(w[i + 1]) if i + 1 < len(w) else None
            if _is_int(c) and isinstance(nxt, list):
                for k, val in enumerate(nxt[:65536]):
                    val = doc.get(val)
                    if _is_num(val):
                        self.adv[c + k] = val
                i += 2
            elif _is_int(c) and _is_int(nxt) and i + 2 < len(w):
                val = doc.get(w[i + 2])
                if _is_num(val) and 0 <= nxt - c < 65536:
                    for code in range(c, nxt + 1):
                        self.adv[code] = val
                i += 3
            else:
                break

    def _parse(self, cmap, budget):
        lx = _Lexer(cmap, budget=budget)
        widths = set()
        while True:
            t = lx.token()
            if t is None:
                break
            if not (t[0] == "op" and t[1] in (b"begincodespacerange", b"beginbfchar", b"beginbfrange")):
                continue
            mode, stack = t[1], []
            while True:
                u = lx.token()
                if u is None or (u[0] == "op" and u[1].startswith(b"end")):
                    break
                if u[0] == "[":
                    arr = []
                    while True:
                        v = lx.token()
                        if v is None or v[0] == "]":
                            break
                        if v[0] == "str":
                            arr.append(v[1])
                    stack.append(arr)
                elif u[0] == "str":
                    stack.append(u[1])
            if mode == b"begincodespacerange":
                for lo in stack[0::2]:
                    if isinstance(lo, bytes) and 0 < len(lo) <= 4:
                        widths.add(len(lo))
            elif mode == b"beginbfchar":
                for src, dst in zip(stack[0::2], stack[1::2]):
                    if isinstance(src, bytes) and isinstance(dst, bytes) and 0 < len(src) <= 4:
                        budget.spend_cmap(1)
                        self.map[src] = _utf16(dst)
                        widths.add(len(src))
            else:
                for i in range(0, len(stack) - 2, 3):
                    lo, hi, dst = stack[i], stack[i + 1], stack[i + 2]
                    if not (isinstance(lo, bytes) and isinstance(hi, bytes)) \
                            or len(lo) != len(hi) or not 0 < len(lo) <= 4:
                        continue
                    a, b = int.from_bytes(lo, "big"), int.from_bytes(hi, "big")
                    if not 0 <= b - a < 65536:
                        continue
                    budget.spend_cmap(b - a + 1)
                    widths.add(len(lo))
                    for k, code in enumerate(range(a, b + 1)):
                        key = code.to_bytes(len(lo), "big")
                        if isinstance(dst, list):
                            if k >= len(dst):
                                break
                            self.map[key] = _utf16(dst[k]) if isinstance(dst[k], bytes) else ""
                        elif isinstance(dst, bytes) and 0 < len(dst) <= 64:
                            base = int.from_bytes(dst, "big") + k
                            if base >= 1 << (8 * len(dst)):   # the range runs past its width
                                break
                            self.map[key] = _utf16(base.to_bytes(len(dst), "big"))
        if widths:
            self.widths = sorted(widths, reverse=True)

    def codes(self, s):
        """[(code, text)] for one shown string, code for the glyph width."""
        if not self.map:
            if self.cid:          # CID codes with no map: widths, no honest text
                return [(int.from_bytes(s[i:i + 2], "big"), "") for i in range(0, len(s) - 1, 2)]
            return [(b, bytes([b]).decode(self.codec, "replace")) for b in s]
        out, i = [], 0
        while i < len(s):
            for w in self.widths:
                key = s[i:i + w]
                if len(key) == w and key in self.map:
                    out.append((int.from_bytes(key, "big"), self.map[key]))
                    i += w
                    break
            else:
                w = self.widths[-1]
                out.append((int.from_bytes(s[i:i + w], "big"), ""))
                i += w
        return out

    def advance(self, code):
        return self.adv.get(code, self.default_adv)


def _utf16(b):
    try:
        return b.decode("utf-16-be")
    except UnicodeDecodeError:
        return ""


# ── content ─────────────────────────────────────────────────────────────────

class _Text:
    """The text state, carried across one page's content streams (a writer
    may set the font in one stream and show text in the next).

    Positions are in text space scaled by the text matrix (a, d); that is
    enough to tell a new line (y moved) from a new run on the same line, and
    a run placed after a visible gap (a word set by position, not by a
    space) from a run that continues the word."""

    def __init__(self):
        self.font = None
        self.size = 0.0
        self.leading = 0.0
        self.a = self.d = 1.0
        self.lx = self.ly = 0.0   # start of the current line (Td/T*/Tm)
        self.x = 0.0              # pen: where the next glyph goes
        self.end_x = None         # where the last shown glyph ended…
        self.end_y = None         # …and on which line
        self.tail = ""            # last character written

    def begin(self):              # BT: the text matrix is the identity again
        self.a = self.d = 1.0
        self.lx = self.ly = self.x = 0.0

    def move(self, tx, ty):       # Td
        self.lx += tx * self.a
        self.ly += ty * self.d
        self.x = self.lx

    def next_line(self):          # T*
        self.move(0, -(self.leading or self.size * 1.2 or 1.0))

    def matrix(self, a, d, e, f):  # Tm
        self.a = a or 1.0
        self.d = d or 1.0
        self.lx = self.x = e
        self.ly = f

    def em(self):
        return abs(self.size * self.a)


class _Reader:
    def __init__(self, doc):
        self.doc = doc
        self.budget = doc.budget
        self.fonts = {}         # id(font dict) -> _Font

    def _font(self, res, name):
        fonts = self.doc.get(res.get(b"Font")) if isinstance(res, dict) else None
        fd = self.doc.get(fonts.get(name)) if isinstance(fonts, dict) else None
        if not isinstance(fd, dict):
            return None
        key = id(fd)
        if key not in self.fonts:
            try:
                self.fonts[key] = _Font(self.doc, fd)
            except _Spent:
                raise
            except Exception:  # noqa: BLE001 — a malformed font reads as no font
                self.fonts[key] = None
        return self.fonts[key]

    @staticmethod
    def _emit(st, out, text):
        if text:
            out.append(text)
            st.tail = text[-1]

    def _show(self, st, s, out):
        font = st.font
        if st.end_y is not None:
            if abs(st.ly - st.end_y) > max(NEWLINE_Y, NEWLINE_EM * st.em()):
                if st.tail != "\n":
                    self._emit(st, out, "\n")
            elif not st.tail.isspace():
                # Same line, placed after a gap. With real widths a small gap
                # is a word break; with guessed widths only a wide one is, so
                # the guess never invents a space inside a word.
                real = font is not None and font.adv
                if st.x - st.end_x > (GAP_EM if real else GUESS_GAP_EM) * st.em():
                    self._emit(st, out, " ")
        if font is None:
            text = s.decode("cp1252", "replace")
            self._emit(st, out, text)
            st.x += len(s) * 0.5 * st.em()
        else:
            adv = 0.0
            for code, text in font.codes(s):
                self._emit(st, out, text)
                adv += font.advance(code)
            st.x += adv / 1000.0 * st.em()
        st.end_x, st.end_y = st.x, st.ly

    def content(self, data, res, out, st, depth=0):
        budget = self.budget
        lx = _Lexer(data, budget=budget)
        args = []
        while True:
            t = lx.token()
            if t is None:
                break
            k = t[0]
            if k == "[":
                arr = []
                while True:
                    u = lx.token()
                    if u is None or u[0] == "]":
                        break
                    if u[0] in ("str", "num"):
                        arr.append(u[1])
                args.append(arr)
                continue
            if k == "<<":        # inline dictionaries (marked content): skip
                depth_d = 1
                while depth_d:
                    u = lx.token()
                    if u is None:
                        break
                    depth_d += {"<<": 1, ">>": -1}.get(u[0], 0)
                continue
            if k != "op":
                args.append(t[1] if len(t) > 1 else None)
                if len(args) > MAX_ARGS:      # operands with no operator: keep the tail
                    del args[:-MAX_ARGS]
                continue
            budget.spend_op()
            op = t[1]
            if op == b"Tf" and len(args) >= 2 and isinstance(args[-2], bytes):
                st.font = self._font(res, args[-2])
                if _is_num(args[-1]):
                    st.size = float(args[-1])
            elif op == b"TL" and args and _is_num(args[-1]):
                st.leading = float(args[-1])
            elif op in (b"Tj", b"'", b'"') and args and isinstance(args[-1], bytes):
                if op != b"Tj":
                    st.next_line()
                self._show(st, args[-1], out)
            elif op == b"TJ" and args and isinstance(args[-1], list):
                for el in args[-1]:
                    if isinstance(el, bytes):
                        self._show(st, el, out)
                    elif _is_num(el):
                        st.x -= el / 1000.0 * st.em()
                        if el < -GAP_EM * 1000 and not st.tail.isspace() and st.tail:
                            self._emit(st, out, " ")
            elif op == b"T*":
                st.next_line()
            elif op in (b"Td", b"TD") and len(args) >= 2 and _is_num(args[-2]) and _is_num(args[-1]):
                if op == b"TD":
                    st.leading = -float(args[-1])
                st.move(float(args[-2]), float(args[-1]))
            elif op == b"Tm" and len(args) >= 6 and all(_is_num(v) for v in args[-6:]):
                a, _b, _c, d, e, f = (float(v) for v in args[-6:])
                st.matrix(a, d, e, f)
            elif op == b"BT":
                st.begin()
            elif op == b"Do" and args and isinstance(args[-1], bytes) and depth < MAX_XOBJECT_DEPTH:
                xos = self.doc.get(res.get(b"XObject")) if isinstance(res, dict) else None
                ref = xos.get(args[-1]) if isinstance(xos, dict) else None
                xo = self.doc.get(ref)
                if isinstance(xo, dict) and xo.get(b"Subtype") == b"Form":
                    budget.spend_form()
                    sub = self.doc.stream(ref)
                    if sub:
                        r = self.doc.get(xo.get(b"Resources"))
                        self.content(sub, r if isinstance(r, dict) else res, out, st, depth + 1)
            elif op == b"BI":            # inline image: skip its data
                end = data.find(b"EI", lx.i)
                lx.i = len(data) if end < 0 else end + 2
            args = []


def extract_text(data, budget=None):
    """The document's text, pages separated by form feeds, or None when it is
    encrypted or holds no text a reader could recover.

    Never raises: the input is whatever file a user had. A spent budget
    returns the pages read so far; any other failure is None."""
    budget = budget or Budget()
    pages_out = []          # finished pages, then the page being read
    try:
        return _extract(data, budget, pages_out)
    except _Spent:
        text = "\f".join(p if isinstance(p, str) else _tidy("".join(p)) for p in pages_out)
        return text if text.strip() else None
    except Exception:  # noqa: BLE001 — a malformed file is "no text", never a crash
        return None


def _read_isolated(rd, stream, res, buf, st):
    """One content stream. A malformed value in it ends THIS stream's read
    with the text found so far; the page's other streams and the document's
    other pages still read. A spent budget still stops everything."""
    try:
        rd.content(stream, res, buf, st)
    except _Spent:
        raise
    except Exception:  # noqa: BLE001
        pass


def _extract(data, budget, pages_out):
    if re.search(rb"/Encrypt(?![A-Za-z])", data):
        return None
    doc = _Doc(data, budget)
    rd = _Reader(doc)
    read_any = False
    for page, res in doc.pages():
        # /Contents is one stream reference, or an array of them (possibly
        # itself behind a reference).
        contents = page.get(b"Contents")
        resolved = doc.get(contents)
        refs = resolved if isinstance(resolved, list) else [contents]
        buf = []
        pages_out.append(buf)
        st = _Text()
        for r in refs:
            s = doc.stream(r)
            if s:
                read_any = True
                _read_isolated(rd, s, res, buf, st)
        pages_out[-1] = _tidy("".join(buf))
    text = "\f".join(pages_out)
    if not read_any:
        # No page tree a reader could follow (a damaged or hand-made file):
        # read every stream that carries text operators, in file order, the
        # way the old regex reader did — fonts unknown. Only then: pages that
        # WERE read and hold no text (a CID font with no map, a scan) must not
        # be re-read without their fonts, which turns glyph codes into junk.
        found = []
        for num in sorted(doc.objs):
            s = doc.stream(_Ref((num, 0)))
            if s and b"BT" in s and (b"Tj" in s or b"TJ" in s):
                buf = []
                _read_isolated(rd, s, None, buf, _Text())
                found.append(_tidy("".join(buf)))
        text = "\n".join(t for t in found if t)
    return text if text.strip() else None


_LIGATURES = {"ﬀ": "ff", "ﬁ": "fi", "ﬂ": "fl", "ﬃ": "ffi",
              "ﬄ": "ffl", "ﬅ": "st", "ﬆ": "st", " ": " "}


def _tidy(t):
    for a, b in _LIGATURES.items():
        t = t.replace(a, b)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r" *\n *", "\n", t)
    return re.sub(r"\n{3,}", "\n\n", t).strip()
