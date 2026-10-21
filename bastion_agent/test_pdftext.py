"""The agent's built-in PDF reader (pdftext) on the shapes real writers make.

The regex reader it replaced returned NOTHING for a browser-printed PDF: text
there is glyph codes in hex strings through Type0 / Identity-H fonts, mapped
back by /ToUnicode CMaps, one Td per glyph run. These tests build such files
with a small writer (no third-party code, no user documents) and read them.
"""

import random
import time
import unittest
import zlib
from unittest import mock

from . import extract as ex
from . import pdftext as pt

CMAP = b"""/CIDInit /ProcSet findresource begin 12 dict begin begincmap
1 begincodespacerange <0000> <FFFF> endcodespacerange
2 beginbfchar
<0003> <0020>
<0010> <00660069>
endbfchar
1 beginbfrange
<0024> <003D> <0041>
endbfrange
endcmap CMapName currentdict /CMap defineresource pop end end
"""


def _enc(text):
    """Glyph codes for our CMap: A-Z -> 0x24.., space -> 3, 'fi' -> 0x10."""
    out = b""
    i = 0
    while i < len(text):
        if text[i:i + 2] == "fi":
            out += b"\x00\x10"
            i += 2
            continue
        c = text[i]
        out += b"\x00\x03" if c == " " else (0x24 + ord(c) - 0x41).to_bytes(2, "big")
        i += 1
    return b"<" + out.hex().upper().encode() + b">"


class Pdf:
    def __init__(self):
        self.objs = []

    def add(self, body, stream=None, compress=True):
        n = len(self.objs) + 1
        if stream is not None:
            data = zlib.compress(stream) if compress else stream
            flt = b"/Filter /FlateDecode " if compress else b""
            body = body.rstrip(b">") + b" " + flt + b"/Length " + str(len(data)).encode() + b" >>"
            self.objs.append(b"%d 0 obj\n" % n + body + b"\nstream\n" + data + b"\nendstream\nendobj\n")
        else:
            self.objs.append(b"%d 0 obj\n" % n + body + b"\nendobj\n")
        return n

    def bytes(self):
        return b"%PDF-1.7\n" + b"".join(self.objs) + b"trailer << /Root 1 0 R >>\n%%EOF\n"


def browser_like(pages, xobject=False):
    """A catalog -> pages tree with RESOURCES ON THE PARENT (inherited), a
    Type0 Identity-H font with a ToUnicode CMap, and per-glyph-run Td moves."""
    pdf = Pdf()
    pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")                   # 1
    pdf.add(b"PLACEHOLDER")                                          # 2 pages
    cmap = pdf.add(b"<< >>", CMAP)                                   # 3
    font = pdf.add(b"<< /Type /Font /Subtype /Type0 /BaseFont /F /Encoding /Identity-H "
                   b"/ToUnicode %d 0 R >>" % cmap)                   # 4
    kids = []
    form = None
    if xobject:
        form = pdf.add(b"<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] >>",
                       b"BT /F1 9 Tf 1 0 0 1 10 10 Tm " + _enc("FOOTER") + b" Tj ET")
    for lines in pages:
        content = b"BT /F1 12 Tf 1 0 0 1 50 700 Tm "
        y = 700
        for line in lines:
            words = line.split(" ")
            # one Td per word run on the SAME line (x moves only)
            for k, w in enumerate(words):
                run = (w + " ") if k < len(words) - 1 else w
                content += b"[" + _enc(run) + b"] TJ 20 0 Td "
            y -= 14
            content += b"1 0 0 1 50 %d Tm " % y
        content += b"ET"
        if form:
            content += b" /X1 Do"
        c = pdf.add(b"<< >>", content)
        kids.append(pdf.add(b"<< /Type /Page /Parent 2 0 R /Contents %d 0 R >>" % c))
    res = b"/Resources << /Font << /F1 %d 0 R >>" % font
    if form:
        res += b" /XObject << /X1 %d 0 R >>" % form
    res += b" >>"
    pdf.objs[1] = (b"2 0 obj\n<< /Type /Pages /Count %d /Kids [%s] %s >>\nendobj\n"
                   % (len(kids), b" ".join(b"%d 0 R" % k for k in kids), res))
    return pdf.bytes()


class PdfTextTests(unittest.TestCase):
    def test_type0_identity_h_with_tounicode(self):
        data = browser_like([["HELLO WORLD", "SECOND LINE"]])
        self.assertEqual(pt.extract_text(data), "HELLO WORLD\nSECOND LINE")

    def test_the_old_reader_found_nothing_here(self):
        # The shape of the regression: no literal (…) strings at all.
        data = browser_like([["HELLO WORLD"]])
        for chunk in data.split(b"stream\n")[1:]:
            raw = chunk.split(b"\nendstream")[0]
            try:
                self.assertNotIn(b"HELLO", zlib.decompress(raw))
            except zlib.error:
                pass

    def test_words_are_not_shredded_by_per_run_moves(self):
        out = pt.extract_text(browser_like([["THE QUICK BROWN FOX"]]))
        self.assertEqual(out, "THE QUICK BROWN FOX")

    def test_ligature_codes_map_back_to_letters(self):
        out = pt.extract_text(browser_like([["CLARIfiES"]]))
        self.assertEqual(out, "CLARIFIES".replace("FI", "fi"))

    def test_pages_in_order_and_inherited_resources(self):
        out = pt.extract_text(browser_like([["PAGE ONE"], ["PAGE TWO"], ["PAGE THREE"]]))
        self.assertEqual(out.split("\f"), ["PAGE ONE", "PAGE TWO", "PAGE THREE"])

    def test_form_xobject_text_is_read(self):
        out = pt.extract_text(browser_like([["BODY"]], xobject=True))
        self.assertIn("BODY", out)
        self.assertIn("FOOTER", out)

    def test_object_streams(self):
        # The page tree and font live inside an /ObjStm (PDF 1.5+ writers).
        cmap_raw = zlib.compress(CMAP)
        content = zlib.compress(b"BT /F1 12 Tf " + _enc("PACKED") + b" Tj ET")
        inner = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            b"<< /Type /Page /Parent 2 0 R /Contents 6 0 R "
            b"/Resources << /Font << /F1 4 0 R >> >> >>",
            b"<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 5 0 R >>",
        ]
        header, body, off = b"", b"", 0
        for i, o in enumerate(inner, start=1):
            header += b"%d %d " % (i, off)
            body += o + b" "
            off += len(o) + 1
        packed = zlib.compress(header + body)
        doc = (b"%PDF-1.7\n"
               + (b"5 0 obj\n<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(cmap_raw))
               + cmap_raw + b"\nendstream\nendobj\n"
               + (b"6 0 obj\n<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(content))
               + content + b"\nendstream\nendobj\n"
               + (b"7 0 obj\n<< /Type /ObjStm /N 4 /First %d /Filter /FlateDecode /Length %d >>\nstream\n"
                  % (len(header), len(packed)))
               + packed + b"\nendstream\nendobj\n%%EOF\n")
        self.assertEqual(pt.extract_text(doc), "PACKED")

    def test_extract_pdf_builtin_uses_it(self):
        self.assertEqual(ex.extract_pdf_builtin(browser_like([["HELLO"]])), "HELLO")

    def test_hostile_input_never_raises(self):
        for junk in (b"", b"%PDF-1.4\n", b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 1 0 R >> endobj",
                     b"%PDF-1.4\n1 0 obj << /Length 99999999 >>\nstream\n\x78\x9c\xff\xff\nendstream\nendobj"):
            ex.extract_pdf_builtin(junk)     # returns None or text; must not raise

    def test_reference_cycles_do_not_hang(self):
        doc = (b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
               b"2 0 obj << /Type /Pages /Kids [2 0 R] >> endobj\n%%EOF")
        self.assertIsNone(pt.extract_text(doc))


HELVETICA = (b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /FirstChar 32 /LastChar 126 "
             b"/Widths [" + b" ".join([b"500"] * 95) + b"] >>")


def simple_doc(streams, font=HELVETICA, objects=(), page_extra=b""):
    """One page, font /F1, content from `streams` (each its own stream in
    /Contents), `objects` appended as-is after the page."""
    pdf = Pdf()
    pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")                   # 1
    pdf.add(b"<< /Type /Pages /Count 1 /Kids [4 0 R] >>")            # 2
    pdf.add(font)                                                     # 3
    first = len(pdf.objs) + 2
    refs = b" ".join(b"%d 0 R" % (first + i) for i in range(len(streams)))
    pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> %s >> "
            b"/Contents [%s] >>" % (page_extra, refs))               # 4
    for s in streams:
        pdf.add(b"<< >>", s)
    for o in objects:
        pdf.objs.append(o)
    return pdf.bytes()


class HostileInput(unittest.TestCase):
    """Review B1/B2: a user's file is arbitrary bytes. Every shape here once
    raised past the extractor or ran without bound."""

    def test_kids_that_is_not_an_array(self):
        doc = (b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
               b"2 0 obj << /Type /Pages /Kids 5 >> endobj\n%%EOF")
        self.assertIsNone(pt.extract_text(doc))

    def test_objstm_offsets_that_are_not_integers(self):
        packed = zlib.compress(b"1 1.e999 2 1e5 << /Type /Catalog >> ")
        doc = (b"%PDF-1.7\n" + b"7 0 obj\n<< /Type /ObjStm /N 2 /First 14 /Filter /FlateDecode "
               b"/Length %d >>\nstream\n" % len(packed) + packed + b"\nendstream\nendobj\n%%EOF")
        self.assertIsNone(pt.extract_text(doc))

    def test_bfrange_destination_past_its_width(self):
        cmap = (b"1 begincodespacerange <0000> <FFFF> endcodespacerange\n"
                b"1 beginbfrange <0000> <FFFF> <FFF0> endbfrange\n")
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 1 /Kids [5 0 R] >>")
        tu = pdf.add(b"<< >>", cmap)
        pdf.add(b"<< /Type /Font /Subtype /Type0 /ToUnicode %d 0 R >>" % tu)
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 6 0 R >>")
        pdf.add(b"<< >>", b"BT /F1 12 Tf <00000001> Tj ET")
        # In-range codes map (U+FFF0, U+FFF1); the run past 0xFFFF stops, never raises.
        self.assertEqual(pt.extract_text(pdf.bytes()), "\ufff0\ufff1")

    def test_deep_nesting_is_skipped_not_a_recursion_error(self):
        doc = (b"%PDF-1.4\n9 0 obj " + b"[" * 100000 + b" endobj\n"
               + simple_doc([b"BT /F1 12 Tf (STILL READ) Tj ET"])[len(b"%PDF-1.7\n"):])
        self.assertEqual(pt.extract_text(doc), "STILL READ")

    def test_form_fan_out_is_bounded(self):
        # X1 draws X2 ten times, X2 draws X3 ten times … six levels: 10^6
        # invocations unbounded. The budget stops it quickly with the text
        # read so far.
        objs, first = [], 6
        for lvl in range(6):
            num = first + lvl
            if lvl < 5:
                body = b"BT /F1 12 Tf (L%d) Tj ET " % lvl + b"/X Do " * 10
                res = b"/Resources << /Font << /F1 3 0 R >> /XObject << /X %d 0 R >> >>" % (num + 1)
            else:
                body, res = b"BT /F1 12 Tf (LEAF) Tj ET", b"/Resources << /Font << /F1 3 0 R >> >>"
            objs.append(b"%d 0 obj\n<< /Type /XObject /Subtype /Form %s /Length %d >>\nstream\n"
                        % (num, res, len(body)) + body + b"\nendstream\nendobj\n")
        doc = simple_doc([b"/X Do"], objects=objs, page_extra=b"/XObject << /X 6 0 R >>")
        t0 = time.monotonic()
        out = pt.extract_text(doc)
        self.assertLess(time.monotonic() - t0, 10)
        self.assertTrue(out.startswith("L0"))

    def test_cmap_entries_are_bounded(self):
        cmap = b"1 begincodespacerange <0000> <FFFF> endcodespacerange\n" + \
            b"1 beginbfrange <0000> <FFFF> <0041> endbfrange\n" * 2000
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 1 /Kids [5 0 R] >>")
        tu = pdf.add(b"<< >>", cmap)
        pdf.add(b"<< /Type /Font /Subtype /Type0 /ToUnicode %d 0 R >>" % tu)
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 6 0 R >>")
        pdf.add(b"<< >>", b"BT /F1 12 Tf <0000> Tj ET")
        b = pt.Budget()
        t0 = time.monotonic()
        pt.extract_text(pdf.bytes(), b)
        self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual(b.reason, "cmap entries")

    def test_a_stream_is_decoded_once(self):
        doc = simple_doc([b"BT /F1 12 Tf (ONCE) Tj ET /X Do /X Do /X Do /X Do"],
                         objects=[b"6 0 obj\n<< /Type /XObject /Subtype /Form /Length 30 >>\nstream\n"
                                  b"BT /F1 12 Tf (FORM) Tj ET    \nendstream\nendobj\n"],
                         page_extra=b"/XObject << /X 6 0 R >>")
        with mock.patch.object(pt._Doc, "_decode", autospec=True, side_effect=pt._Doc._decode) as dec:
            self.assertIn("FORM", pt.extract_text(doc))
        self.assertEqual(sum(1 for c in dec.call_args_list if c.args[2].startswith(b"BT /F1 12 Tf (FORM)")), 1)

    def test_missing_endobj_is_linear(self):
        doc = b"%PDF-1.4\n" + b"1 0 obj << /A 1 >>\n" * 60000 + b"endobj\n"
        t0 = time.monotonic()
        pt.extract_text(doc)
        self.assertLess(time.monotonic() - t0, 5)

    def test_wall_time_budget(self):
        b = pt.Budget(seconds=0)
        out = pt.extract_text(browser_like([["A"]] * 30), b)
        self.assertEqual(b.reason, "time")
        self.assertIsNone(out)

    def test_mutated_real_shapes_never_raise(self):
        rnd = random.Random(1)
        seeds = [browser_like([["HELLO WORLD"], ["PAGE TWO"]], xobject=True),
                 simple_doc([b"BT /F1 12 Tf (plain) Tj ET"])]
        for _ in range(400):
            d = bytearray(rnd.choice(seeds))
            for _ in range(rnd.randint(1, 12)):
                i = rnd.randrange(len(d))
                d[i:i + rnd.randint(1, 4)] = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 4)))
            ex.extract_pdf_builtin(bytes(d))     # None or text; never raises


class Layout(unittest.TestCase):
    """Review non-blocking items: where words and lines break."""

    def test_bt_resets_the_text_matrix(self):
        # Two blocks on the SAME line: Td in the second block is from the
        # origin again, not from where the first block left off.
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf 50 700 Td (LEFT) Tj ET "
                                          b"BT /F1 10 Tf 200 700 Td (RIGHT) Tj ET"]))
        self.assertEqual(out, "LEFT RIGHT")

    def test_words_placed_by_position_get_a_space_from_widths(self):
        # No space glyph: the gap between HELLO (5 x 500/1000 x 10 = 25 wide)
        # and a run moved 40 to the right is the only word boundary.
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf 0 0 Td (HELLO) Tj 40 0 Td (WORLD) Tj ET"]))
        self.assertEqual(out, "HELLO WORLD")

    def test_runs_that_continue_a_word_stay_joined(self):
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf 0 0 Td (HEL) Tj 15 0 Td (LO) Tj ET"]))
        self.assertEqual(out, "HELLO")

    def test_without_widths_no_space_is_invented(self):
        font = b"<< /Type /Font /Subtype /Type1 /BaseFont /SomeFace >>"
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf 0 0 Td (HEL) Tj 15 0 Td (LO) Tj ET"], font=font))
        self.assertEqual(out, "HELLO")

    def test_cid_widths_from_w_array(self):
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 1 /Kids [6 0 R] >>")
        tu = pdf.add(b"<< >>", CMAP)
        desc = pdf.add(b"<< /Type /Font /Subtype /CIDFontType2 /DW 1000 /W [36 [600 600 600 600 600 600]] >>")
        pdf.add(b"<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /DescendantFonts [%d 0 R] "
                b"/ToUnicode %d 0 R >>" % (desc, tu))
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>")
        # "AB" at 600/1000 x 10 = 12 wide; the next run 20 on is a new word.
        pdf.add(b"<< >>", b"BT /F1 10 Tf 0 0 Td " + _enc("AB") + b" Tj 20 0 Td " + _enc("CD") + b" Tj ET")
        self.assertEqual(pt.extract_text(pdf.bytes()), "AB CD")

    def test_winansi_encoding(self):
        font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf (caf\\351 \\223q\\224 \\200) Tj ET"], font=font))
        self.assertEqual(out, "caf\u00e9 \u201cq\u201d \u20ac")

    def test_macroman_encoding(self):
        font = (b"<< /Type /Font /Subtype /Type1 /BaseFont /Times "
                b"/Encoding << /BaseEncoding /MacRomanEncoding >> >>")
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf (caf\\216) Tj ET"], font=font))
        self.assertEqual(out, "caf\u00e9")

    def test_font_carries_across_a_pages_content_streams(self):
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 1 /Kids [5 0 R] >>")
        tu = pdf.add(b"<< >>", CMAP)
        pdf.add(b"<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode %d 0 R >>" % tu)
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
                b"/Contents [6 0 R 7 0 R] >>")
        pdf.add(b"<< >>", b"BT /F1 12 Tf")
        pdf.add(b"<< >>", _enc("SPLIT") + b" Tj ET")
        self.assertEqual(pt.extract_text(pdf.bytes()), "SPLIT")

    def test_incremental_update_later_definition_wins(self):
        doc = simple_doc([b"BT /F1 12 Tf (OLD) Tj ET"])
        body = b"BT /F1 12 Tf (NEW) Tj ET"
        doc += (b"5 0 obj\n<< /Length %d >>\nstream\n" % len(body)) + body + b"\nendstream\nendobj\n%%EOF\n"
        self.assertEqual(pt.extract_text(doc), "NEW")

    def test_stream_holding_endobj_text_is_read_whole(self):
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 1 /Kids [4 0 R] >>")
        pdf.add(HELVETICA)
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R >>")
        pdf.add(b"<< >>", b"BT /F1 12 Tf (a endobj b) Tj 0 -20 Td (AFTER) Tj ET", compress=False)
        self.assertEqual(pt.extract_text(pdf.bytes()), "a endobj b\nAFTER")


class ReviewRound2(unittest.TestCase):
    """Second review: lexing is what repeats, so lexing is what is charged;
    one bad value costs one stream, not the document."""

    def _pages_sharing(self, body, npages):
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        kids = b" ".join(b"%d 0 R" % (5 + i) for i in range(npages))
        pdf.add(b"<< /Type /Pages /Count %d /Kids [%s] >>" % (npages, kids))
        pdf.add(HELVETICA)
        pdf.add(b"<< >>", body)                                        # 4
        for _ in range(npages):
            pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> "
                    b"/Contents 4 0 R >>")
        return pdf.bytes()

    def test_one_stream_lexed_by_many_pages_is_bounded(self):
        doc = self._pages_sharing(b"BT /F1 12 Tf (hello) Tj ET " + b"1 " * 1_000_000, 40)
        b = pt.Budget(seconds=1)
        t0 = time.monotonic()
        out = pt.extract_text(doc, b)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(b.reason, "time")
        self.assertTrue(out.startswith("hello"))

    def test_token_cap(self):
        doc = self._pages_sharing(b"BT /F1 12 Tf (hi) Tj ET " + b"1 " * 50_000, 10)
        with mock.patch.object(pt, "MAX_TOKENS", 120_000):
            b = pt.Budget()
            pt.extract_text(doc, b)
        self.assertEqual(b.reason, "tokens")

    def test_a_shared_tounicode_is_parsed_once(self):
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 1 /Kids [6 0 R] >>")
        tu = pdf.add(b"<< >>", CMAP)                                    # 3
        pdf.add(b"<< /Type /Font /Subtype /Type0 /ToUnicode %d 0 R >>" % tu)   # 4
        pdf.add(b"<< /Type /Font /Subtype /Type0 /ToUnicode %d 0 R >>" % tu)   # 5
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> "
                b"/Contents 7 0 R >>")
        pdf.add(b"<< >>", b"BT /F1 12 Tf " + _enc("AB") + b" Tj /F2 12 Tf " + _enc("CD") + b" Tj ET")
        with mock.patch.object(pt._Font, "_parse", autospec=True, side_effect=pt._Font._parse) as parse:
            self.assertEqual(pt.extract_text(pdf.bytes()), "ABCD")
        self.assertEqual(parse.call_count, 1)

    def test_words_far_apart_without_widths_are_separated(self):
        font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        for ops in (b"BT /F1 10 Tf 50 700 Td (Name) Tj 150 0 Td (Value) Tj ET",
                    b"BT /F1 10 Tf 1 0 0 1 50 700 Tm (Name) Tj 1 0 0 1 200 700 Tm (Value) Tj ET"):
            self.assertEqual(pt.extract_text(simple_doc([ops], font=font)), "Name Value")

    def test_standard_font_without_widths_uses_its_real_widths(self):
        # Helvetica W is 944/1000: (WWWW) ends at 37.76 at size 10. The rest of
        # the word placed exactly there is the same word; a guessed 500 would
        # have read a 17.76-unit gap and split it.
        font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf 0 0 Td (WWWW) Tj 37.76 0 Td (ORD) Tj ET"],
                                         font=font))
        self.assertEqual(out, "WWWWORD")
        self.assertEqual(pt._standard_widths(b"ABCDEF+Arial,Bold")[1][ord("W") - 32], 944)
        self.assertEqual(pt._standard_widths(b"Courier-Oblique"), (32, [600] * 95))
        self.assertIsNone(pt._standard_widths(b"SomeFace"))

    def test_unknown_font_without_widths_guesses_wide(self):
        font = b"<< /Type /Font /Subtype /Type1 /BaseFont /SomeFace >>"
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf 0 0 Td (WWWW) Tj 37.76 0 Td (ORD) Tj ET"],
                                         font=font))
        self.assertEqual(out, "WWWWORD")

    def test_superscript_rise_is_not_a_new_line(self):
        out = pt.extract_text(simple_doc([b"BT /F1 10 Tf 0 0 Td (E=mc) Tj 20 3 Td (2) Tj "
                                          b"5 -3 Td ( is) Tj ET"]))
        self.assertEqual(out, "E=mc2 is")

    def test_the_word_stream_inside_a_string_owns_no_bytes(self):
        # The stray object sits BEFORE every page object.
        doc = simple_doc([b"BT /F1 12 Tf (BODY) Tj ET"])
        head, rest = doc.split(b"1 0 obj", 1)
        doc = head + b"9 0 obj\n<< /Title (a live stream\n) >>\nendobj\n1 0 obj" + rest
        self.assertEqual(pt.extract_text(doc), "BODY")

    def test_indirect_length(self):
        body = b"BT /F1 12 Tf (INDIRECT) Tj ET"
        raw = (b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
               b"2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj\n"
               b"3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj\n"
               b"4 0 obj << /Length 5 0 R >>\nstream\n" + body + b"\nendstream\nendobj\n"
               b"5 0 obj %d endobj\n%%%%EOF" % len(body))
        self.assertEqual(pt.extract_text(raw), "INDIRECT")

    def test_one_bad_value_costs_one_stream_not_the_document(self):
        bad_font = b"<< /Type /Font /Subtype /Type1 /Encoding [/a /b] >>"
        self.assertEqual(pt.extract_text(simple_doc([b"BT /F1 12 Tf (still) Tj ET"], font=bad_font)),
                         "still")
        huge = b"BT /F1 12 Tf (hello world) Tj [(a) 1" + b"0" * 400 + b" (b)] TJ ET"
        self.assertTrue(pt.extract_text(simple_doc([huge])).startswith("hello world"))
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 2 /Kids [4 0 R 5 0 R] >>")
        pdf.add(HELVETICA)
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents 6 0 R >>")
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents 7 0 R >>")
        pdf.add(b"<< >>", b"BT /F1 12 Tf (PAGE ONE) Tj ET")
        pdf.add(b"<< >>", b"BT /F1 12 Tf (PAGE TWO) Tj ET")
        real = pt._Reader.content
        calls = []

        def first_page_breaks(self, data, *a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise TypeError("a malformed value")
            return real(self, data, *a, **k)
        with mock.patch.object(pt._Reader, "content", first_page_breaks):
            self.assertEqual(pt.extract_text(pdf.bytes()).split("\f"), ["", "PAGE TWO"])

    def test_cid_pages_without_a_map_do_not_fall_back_to_junk(self):
        pdf = Pdf()
        pdf.add(b"<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(b"<< /Type /Pages /Count 1 /Kids [4 0 R] >>")
        pdf.add(b"<< /Type /Font /Subtype /Type0 /Encoding /Identity-H >>")
        pdf.add(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R >>")
        pdf.add(b"<< >>", b"BT /F1 12 Tf <00410042> Tj ET")
        self.assertIsNone(pt.extract_text(pdf.bytes()))

    def test_index_checks_the_clock(self):
        data = b"%PDF-1.4\n" + b"".join(b"%d 0 obj [1 2 3] endobj\n" % i for i in range(200_000))
        b = pt.Budget(seconds=0)
        pt.extract_text(data, b)
        self.assertEqual(b.reason, "time")



class ReviewRound4(unittest.TestCase):
    """Memory, not just time: a lexer step must not allocate per byte."""

    def _peak(self, fn):
        import tracemalloc
        tracemalloc.start()
        fn()
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        return peak

    def test_spaced_hex_string_is_stripped_without_per_byte_objects(self):
        data = b"<" + b"0 " * 2_000_000 + b"41>"
        peak = self._peak(lambda: pt._Lexer(data).token())
        self.assertEqual(pt._Lexer(b"<4 1 4 2>").token(), ("str", b"AB"))
        self.assertLess(peak, 3 * len(data), peak)

    def test_comment_lines_are_skipped_without_per_line_state(self):
        data = b"%\n" * 1_000_000 + b"(x)"
        peak = self._peak(lambda: pt._Lexer(data).token())
        self.assertEqual(pt._Lexer(data).token(), ("str", b"x"))
        self.assertLess(peak, len(data), peak)

    def test_a_long_escape_run_checks_the_clock(self):
        b = pt.Budget(seconds=0)
        with self.assertRaises(pt._Spent):
            pt._Lexer(b"(" + b"\\a" * 300_000 + b")", budget=b).token()


if __name__ == "__main__":
    unittest.main()
