"""Unit tests for the extract stage. Run: python3 -m unittest discover .

Every fixture is generated here with the stdlib (zip + XML for office
formats, hand-built PDFs), so the suite needs no binary blobs and runs on
any OS. External tools are mocked; the real-tool path is exercised only
where the machine happens to have them.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
import zlib
from unittest import mock

from . import extract as ex
from .manifest import validate_document
from .walk import walk


def manifest(root, **scope):
    return validate_document({
        "freeagent": 1, "id": "t", "owner": {"host": "h"},
        "scope": dict({"roots": [root]}, **scope),
        "mask": ["read"], "stages": ["walk", "extract"], "sweep": "manual",
        "sink": {"catalog": "local", "vectors": "local", "plaintext": "never"},
    })


def put(root, rel, data):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def zipped(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


DOCX_XML = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:tab/><w:t>World</w:t></w:r></w:p>'
            '<w:p><w:r><w:t>Second paragraph</w:t></w:r></w:p></w:body></w:document>')
XLSX_SST = ('<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<si><t>Name</t></si><si><t>Ada</t></si></sst>')
XLSX_SHEET = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<sheetData><row><c t="s"><v>0</v></c><c><v>42</v></c></row>'
              '<row><c t="s"><v>1</v></c><c t="inlineStr"><is><t>inline</t></is></c></row>'
              '</sheetData></worksheet>')
PPTX_SLIDE = ('<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
              'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
              '<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Slide </a:t></a:r>'
              '<a:r><a:t>title</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>')
ODT_CONTENT = ('<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
               'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
               'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"><office:body><office:text>'
               '<text:h>Heading</text:h><text:p>Body <text:span>span</text:span></text:p>'
               '<table:table><table:table-row><table:table-cell><text:p>c1</text:p></table:table-cell>'
               '<table:table-cell><text:p>c2</text:p></table:table-cell></table:table-row></table:table>'
               '</office:text></office:body></office:document-content>')


def pdf_bytes(content, compress=False):
    stream = zlib.compress(content) if compress else content
    filt = b"/Filter /FlateDecode " if compress else b""
    return (b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n"
            b"2 0 obj << " + filt + b"/Length " + str(len(stream)).encode() + b" >>\nstream\n"
            + stream + b"\nendstream\nendobj\n%%EOF\n")


class ExtractorUnitTests(unittest.TestCase):
    def test_decode_bytes(self):
        self.assertEqual(ex.decode_bytes("héllo".encode("utf-8")), ("héllo", "utf-8"))
        self.assertEqual(ex.decode_bytes(b"\xef\xbb\xbfhi"), ("hi", "utf-8-sig"))
        self.assertEqual(ex.decode_bytes("hi".encode("utf-16"))[0], "hi")
        self.assertEqual(ex.decode_bytes("hi there".encode("utf-16-le")), ("hi there", "utf-16-le"))
        self.assertEqual(ex.decode_bytes(b"caf\xe9"), ("café", "cp1252"))

    def test_html_to_text(self):
        out = ex.html_to_text("<html><head><title>T</title><style>x{}</style></head>"
                              "<body><p>One &amp; two</p><script>bad()</script><div>Three</div></body>")
        self.assertIn("One & two", out)
        self.assertIn("Three", out)
        self.assertNotIn("bad()", out)
        self.assertNotIn("x{}", out)

    def test_docx(self):
        text = ex.extract_docx(zipped({"word/document.xml": DOCX_XML}))
        self.assertEqual(text.strip().splitlines(), ["Hello\tWorld", "Second paragraph"])

    def test_xlsx(self):
        text = ex.extract_xlsx(zipped({"xl/sharedStrings.xml": XLSX_SST,
                                       "xl/worksheets/sheet1.xml": XLSX_SHEET}))
        self.assertIn("Name\t42", text)
        self.assertIn("Ada\tinline", text)

    def test_pptx(self):
        text = ex.extract_pptx(zipped({"ppt/slides/slide2.xml": PPTX_SLIDE,
                                       "ppt/slides/slide1.xml": PPTX_SLIDE.replace("title", "first")}))
        lines = [l for l in text.splitlines() if l]
        self.assertEqual(lines, ["# slide1", "Slide first", "# slide2", "Slide title"])

    def test_odf(self):
        text = ex.extract_odf(zipped({"content.xml": ODT_CONTENT}))
        self.assertEqual(text.splitlines(), ["Heading", "Body span", "c1\tc2"])

    def test_zip_member_cap(self):
        big = zipped({"content.xml": b"x" * (ex.ZIP_MEMBER_CAP + 1)})
        with self.assertRaises(ValueError):
            ex.extract_odf(big)

    def test_office_refuses_a_dtd(self):
        # Office XML never carries a DTD; one is how entity expansion gets in.
        bomb = (b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaaaaaaaa">'
                b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
                b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b'<w:body><w:p><w:r><w:t>&b;</w:t></w:r></w:p></w:body></w:document>')
        with self.assertRaises(ValueError):
            ex.extract_docx(zipped({"word/document.xml": bomb}))

    def test_office_text_cap_stops_with_the_text_so_far(self):
        rows = "".join('<row><c t="inlineStr"><is><t>row %d</t></is></c></row>' % i for i in range(200))
        sheet = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                 "<sheetData>%s</sheetData></worksheet>" % rows).encode()
        with mock.patch.object(ex, "OFFICE_TEXT_CAP", 300):
            text = ex.extract_xlsx(zipped({"xl/worksheets/sheet1.xml": sheet}))
        self.assertIn("row 0", text)
        self.assertNotIn("row 199", text)
        self.assertTrue(text.splitlines()[-1].startswith("[stopped reading here:"))

    def test_office_decompressed_cap_counts_every_member(self):
        para = b"<w:p><w:r><w:t>x</w:t></w:r></w:p>" * 2000
        doc = (b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
               b"<w:body>" + para + b"</w:body></w:document>")
        files = {"word/document.xml": doc}
        files.update({"word/header%d.xml" % i: doc for i in range(1, 6)})
        with mock.patch.object(ex, "OFFICE_DOC_CAP", len(doc) * 3):
            text = ex.extract_docx(zipped(files))
        self.assertIn("[stopped reading here: the document expands past", text)

    def test_office_parse_is_streamed(self):
        # Rows are dropped as they are read: the parsed tree never holds them all.
        import tracemalloc
        rows = "".join('<row><c t="inlineStr"><is><t>%s</t></is></c></row>' % ("v" * 50)
                       for _ in range(60000))
        sheet = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                 "<sheetData>%s</sheetData></worksheet>" % rows).encode()
        data = zipped({"xl/worksheets/sheet1.xml": sheet})
        tracemalloc.start()
        text = ex.extract_xlsx(data)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertEqual(text.count("v" * 50), 60000)
        # the XML is ~4.6 MB; a whole-tree parse peaks at many times that
        self.assertLess(peak, 3 * len(sheet), peak)

    def test_office_drops_unwanted_siblings_linear(self):
        body = b"<w:bookmarkStart/><w:p><w:r><w:t>hi</w:t></w:r></w:p>" * 100000
        doc = (b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
               b"<w:body>" + body + b"</w:body></w:document>")
        import time as _t
        t0 = _t.monotonic()
        text = ex.extract_docx(zipped({"word/document.xml": doc}))
        self.assertLess(_t.monotonic() - t0, 10)
        self.assertEqual(text.count("hi"), 100000)
        self.assertNotIn("[stopped", text)

    def test_office_one_paragraph_with_endless_parts_is_cut_and_reading_goes_on(self):
        runs = b"<w:r><w:t>a</w:t></w:r>" * 10
        doc = (b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
               b"<w:body><w:p>" + runs + b"</w:p><w:p><w:r><w:t>after</w:t></w:r></w:p>"
               b"</w:body></w:document>")
        with mock.patch.object(ex, "OFFICE_PARTS_PER_ITEM", 15):
            text = ex.extract_docx(zipped({"word/document.xml": doc}))
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("a") and len(lines[0]) < 10, lines[0])
        self.assertIn("after", lines)
        self.assertEqual(lines[-1], "[1 paragraph(s) or row(s) held more than 15 parts; each was cut there]")

    def test_office_dropping_past_the_cap_is_linear(self):
        # A closing element is not its parent's last child when the pull
        # parser has read ahead; per-element remove() was quadratic (400k
        # runs: 60 s and the rest of the document lost).
        import time as _t
        runs = b"<w:r><w:t>a</w:t></w:r>" * 60000
        doc = (b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
               b"<w:body><w:p>" + runs + b"</w:p><w:p><w:r><w:t>TAIL</w:t></w:r></w:p>"
               b"</w:body></w:document>")
        with mock.patch.object(ex, "OFFICE_PARTS_PER_ITEM", 20000):
            t0 = _t.monotonic()
            text = ex.extract_docx(zipped({"word/document.xml": doc}))
        self.assertLess(_t.monotonic() - t0, 10)
        self.assertIn("TAIL", text.splitlines())

    def test_office_cut_row_has_no_phantom_cells(self):
        cells = "".join('<c t="inlineStr"><is><t>v</t></is></c>' for _ in range(40))
        sheet = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                 "<sheetData><row>%s</row><row><c t=\"inlineStr\"><is><t>next</t></is></c></row>"
                 "</sheetData></worksheet>" % cells).encode()
        with mock.patch.object(ex, "OFFICE_PARTS_PER_ITEM", 30):
            text = ex.extract_xlsx(zipped({"xl/worksheets/sheet1.xml": sheet}))
        first = text.splitlines()[1]
        self.assertTrue(all(c == "v" for c in first.split("\t")), first)
        self.assertIn("next", text.splitlines())

    def test_office_utf16_is_read_and_its_dtd_still_refused(self):
        ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
        good = ('<?xml version="1.0" encoding="UTF-16"?><w:document %s><w:body>'
                "<w:p><w:r><w:t>wide caf\u00e9</w:t></w:r></w:p></w:body></w:document>" % ns)
        for enc in ("utf-16", "utf-16-be"):
            data = good.encode(enc)
            if enc == "utf-16-be":
                data = b"\xfe\xff" + data
            self.assertEqual(ex.extract_docx(zipped({"word/document.xml": data})).strip(), "wide caf\u00e9")
        bomb = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE d [<!ENTITY a "A">]>'
                "<w:document %s><w:body><w:p><w:r><w:t>&a;</w:t></w:r></w:p></w:body></w:document>" % ns)
        with self.assertRaises(ValueError):
            ex.extract_docx(zipped({"word/document.xml": bomb.encode("utf-16")}))
        with self.assertRaises(ValueError):       # UTF-32: not an Office encoding
            ex.extract_docx(zipped({"word/document.xml": good.replace("UTF-16", "UTF-32").encode("utf-32-le")}))

    def test_docx_text_box_follows_the_paragraph_holding_it(self):
        ns = b'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
        doc = (b"<w:document " + ns + b"><w:body>"
               b"<w:p><w:r><w:t>before</w:t></w:r></w:p>"
               b"<w:p><w:r><w:t>holder</w:t></w:r><w:r><w:txbxContent>"
               b"<w:p><w:r><w:t>boxed</w:t></w:r></w:p></w:txbxContent></w:r></w:p>"
               b"<w:p><w:r><w:t>after</w:t></w:r></w:p></w:body></w:document>")
        text = ex.extract_docx(zipped({"word/document.xml": doc}))
        self.assertEqual([l for l in text.splitlines() if l], ["before", "holder", "boxed", "after"])

    def test_eml_plain_and_html(self):
        plain = b"From: a@b.c\nTo: d@e.f\nSubject: Hi\n\nbody text\n"
        out = ex.extract_eml(plain)
        self.assertIn("Subject: Hi", out)
        self.assertIn("body text", out)
        htm = (b"From: a@b.c\nSubject: H\nContent-Type: text/html\n\n"
               b"<p>rich <b>body</b></p><script>x</script>")
        out = ex.extract_eml(htm)
        self.assertIn("rich body", out)
        self.assertNotIn("<b>", out)

    def test_rtf(self):
        rtf = (rb"{\rtf1\ansi{\fonttbl{\f0 Arial;}}{\colortbl;\red0;}"
               rb"\f0 Hello\par caf\'e9 \u8364? end\tab tabbed}")
        out = ex.extract_rtf(rtf)
        self.assertEqual(out, "Hello\ncafé € end\ttabbed")
        self.assertNotIn("Arial", out)

    def test_pdf_builtin_plain_and_flate(self):
        content = b"BT /F1 12 Tf 72 700 Td (Hello) Tj T* [(Wor) -20 (ld)] TJ ET"
        self.assertIn("Hello", ex.extract_pdf_builtin(pdf_bytes(content)))
        out = ex.extract_pdf_builtin(pdf_bytes(content, compress=True))
        self.assertIn("Hello", out)
        self.assertIn("World", out.replace(" ", "").replace("\n", "") and out)

    def test_pdf_builtin_refuses_garbage_and_encrypted(self):
        garbage = b"BT (\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0e\x0f\x10\x11\x12) Tj ET"
        self.assertIsNone(ex.extract_pdf_builtin(pdf_bytes(garbage)))
        self.assertIsNone(ex.extract_pdf_builtin(pdf_bytes(b"BT (x) Tj ET") + b"/Encrypt 5 0 R"))
        self.assertIsNone(ex.extract_pdf_builtin(pdf_bytes(b"no text ops here")))

    def test_pdf_escapes(self):
        from . import pdftext as pt
        self.assertEqual(pt._Lexer(rb"(a\)b\\c\101\n)").token(), ("str", b"a)b\\cA\n"))


class StageCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fa-ex-")
        self.out = tempfile.mkdtemp(prefix="fa-exout-")
        put(self.root, "a.txt", "plain text\n")
        put(self.root, "copy-of-a.txt", "plain text\n")
        put(self.root, "latin.txt", "caf\xe9".encode("cp1252"))
        put(self.root, "page.html", "<p>hello <b>web</b></p>")
        put(self.root, "data.csv", "a,b\n1,2\n")
        put(self.root, "conf.json", '{"k": 1}')
        put(self.root, "mail.eml", "From: a@b.c\nSubject: S\n\nhi\n")
        put(self.root, "doc.docx", zipped({"word/document.xml": DOCX_XML}))
        put(self.root, "sheet.xlsx", zipped({"xl/sharedStrings.xml": XLSX_SST,
                                             "xl/worksheets/sheet1.xml": XLSX_SHEET}))
        put(self.root, "deck.pptx", zipped({"ppt/slides/slide1.xml": PPTX_SLIDE}))
        put(self.root, "text.odt", zipped({"content.xml": ODT_CONTENT}))
        put(self.root, "doc.pdf", pdf_bytes(b"BT (pdf words) Tj ET", compress=True))
        put(self.root, "scan.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
        put(self.root, "blob.bin", b"\x00\x01\x02\x03")
        put(self.root, "empty.txt", "")
        put(self.root, "noext-empty", "")
        put(self.root, "broken.docx", b"PK\x03\x04not really a zip")
        put(self.root, "big.txt", "x" * 100_000)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)

    def run_stage(self, use_external=False, **scope):
        m = manifest(self.root, **scope)
        walk(m, self.out)
        s = ex.extract(m, self.out, use_external=use_external)
        with open(os.path.join(self.out, "extract.jsonl"), encoding="utf-8") as fh:
            idx = {json.loads(l)["path"]: json.loads(l) for l in fh}
        return s, idx

    def text_of(self, rec):
        with open(ex.store_path(self.out, rec["sha256"]), encoding="utf-8") as fh:
            return fh.read()


class StageTests(StageCase):
    def test_everything_builtin(self):
        s, idx = self.run_stage(max_file_bytes=50_000)
        self.assertEqual(idx["a.txt"]["status"], "ok")
        self.assertEqual(idx["a.txt"]["extractor"], "text:utf-8")
        self.assertEqual(self.text_of(idx["a.txt"]), "plain text\n")
        self.assertEqual(idx["latin.txt"]["extractor"], "text:cp1252")
        self.assertEqual(self.text_of(idx["latin.txt"]), "café\n")
        self.assertEqual(self.text_of(idx["page.html"]).strip(), "hello web")
        self.assertEqual(self.text_of(idx["data.csv"]), "a\tb\n1\t2\n")
        self.assertEqual(idx["conf.json"]["status"], "ok")
        self.assertIn("Subject: S", self.text_of(idx["mail.eml"]))
        self.assertIn("Hello\tWorld", self.text_of(idx["doc.docx"]))
        self.assertIn("Name\t42", self.text_of(idx["sheet.xlsx"]))
        self.assertIn("Slide title", self.text_of(idx["deck.pptx"]))
        self.assertIn("Heading", self.text_of(idx["text.odt"]))
        self.assertEqual(idx["doc.pdf"]["extractor"], "pdf-builtin")
        self.assertIn("pdf words", self.text_of(idx["doc.pdf"]))
        self.assertEqual(idx["scan.png"]["status"], "unsupported")
        self.assertIn("tesseract", idx["scan.png"]["error"])
        self.assertEqual(idx["blob.bin"]["status"], "unsupported")
        self.assertEqual(idx["empty.txt"]["status"], "empty")
        # same (empty) content as empty.txt -> deduped onto its record
        self.assertEqual(idx["noext-empty"]["status"], "empty")
        self.assertEqual(idx["noext-empty"]["sha256"], idx["empty.txt"]["sha256"])
        # the inode/x-empty branch on its own
        self.assertEqual(ex.Extractor(use_external=False).extract("/nonexistent", "inode/x-empty"),
                         ("ok", "empty", "", None))
        self.assertEqual(idx["broken.docx"]["status"], "error")
        self.assertEqual(idx["big.txt"]["status"], "skipped")
        self.assertEqual(idx["big.txt"]["error"], "too_large")
        # duplicate content: one store entry, both paths indexed
        self.assertEqual(idx["copy-of-a.txt"]["sha256"], idx["a.txt"]["sha256"])
        c = s["counts"]
        self.assertEqual(c["files"], len(idx))
        self.assertEqual(c["skipped"], 1)
        self.assertEqual(c["error"], 1)
        self.assertEqual(c["unsupported"], 2)
        self.assertEqual(c["empty"], 2)  # empty.txt + its content-twin noext-empty
        self.assertEqual(s["tools"], {"pdftotext": None, "tesseract": None})

    def test_reuse_across_sweeps(self):
        s1, _ = self.run_stage()
        s2, idx = self.run_stage()
        # everything that produced text (or was empty) last sweep, incl. the duplicate copy
        self.assertEqual(s2["counts"]["reused"], s1["counts"]["ok"] + s1["counts"]["empty"])
        self.assertEqual(s2["counts"]["ok"], 0)
        self.assertTrue(idx["a.txt"]["reused"])
        # unsupported verdicts are reused while the tool set is unchanged
        self.assertTrue(idx["scan.png"].get("reused"))
        # a changed file is re-extracted
        put(self.root, "a.txt", "new text\n")
        s3, idx3 = self.run_stage()
        self.assertEqual(self.text_of(idx3["a.txt"]), "new text\n")
        self.assertFalse(idx3["a.txt"].get("reused"))

    def test_cached_verdicts_invalidate_on_extractor_upgrade(self):
        self.run_stage()
        with mock.patch.object(ex, "EXTRACT_VERSION", ex.EXTRACT_VERSION + 1):
            s, idx = self.run_stage()
        self.assertEqual(s["counts"]["reused"], 0)
        self.assertFalse(idx["a.txt"].get("reused"))
        self.assertFalse(idx["scan.png"].get("reused"))

    def test_unsupported_retried_when_tools_change(self):
        self.run_stage()
        fake_tess = lambda path, tool: "OCR TEXT\n"
        with mock.patch.object(ex, "tool_path", lambda n: "/usr/bin/" + n), \
             mock.patch.object(ex, "extract_image_tool", fake_tess), \
             mock.patch.object(ex, "extract_pdf_tool", lambda p, t: "from poppler\n"):
            s, idx = self.run_stage(use_external=True)
        self.assertEqual(idx["scan.png"]["status"], "ok")
        self.assertEqual(idx["scan.png"]["extractor"], "tesseract")
        self.assertEqual(self.text_of(idx["scan.png"]), "OCR TEXT\n")
        self.assertEqual(s["tools"]["pdftotext"], "/usr/bin/pdftotext")
        # the pdf was already extracted by the builtin path and is reused, not re-run
        self.assertTrue(idx["doc.pdf"].get("reused"))

    def test_tool_failure_is_an_error_entry(self):
        def boom(path, tool):
            raise RuntimeError("tesseract exited 1: no language data")
        with mock.patch.object(ex, "tool_path", lambda n: "/usr/bin/" + n if n == "tesseract" else None), \
             mock.patch.object(ex, "extract_image_tool", boom):
            s, idx = self.run_stage(use_external=True)
        self.assertEqual(idx["scan.png"]["status"], "error")
        self.assertIn("no language data", idx["scan.png"]["error"])
        self.assertEqual(s["counts"]["error"], 2)  # + broken.docx

    def test_oversized_csv_field_is_an_error_entry_not_a_crash(self):
        # csv.Error is not a ValueError; a >128 KiB field used to escape the
        # handler and take the whole sweep down
        put(self.root, "huge.csv", "a,b\n1," + "x" * 200_000 + "\n")
        s, idx = self.run_stage(max_file_bytes=1_000_000)
        self.assertEqual(idx["huge.csv"]["status"], "error")
        self.assertIn("Error", idx["huge.csv"]["error"])
        self.assertEqual(s["counts"]["error"], 2)  # + broken.docx

    def test_requires_walk_first(self):
        with self.assertRaises(FileNotFoundError):
            ex.extract(manifest(self.root), self.out)

    def test_index_sorted_and_normalised(self):
        put(self.root, "crlf.txt", "one\r\ntwo\r\n\x00")
        _, idx = self.run_stage()
        self.assertEqual(self.text_of(idx["crlf.txt"]), "one\ntwo\n")
        paths = list(idx)
        self.assertEqual(paths, sorted(paths))


class RunToolTests(unittest.TestCase):
    def test_run_tool_ok_and_failure(self):
        import sys
        out = ex.run_tool([sys.executable, "-c", "print('hi')"])
        self.assertEqual(out.strip(), b"hi")
        with self.assertRaises(RuntimeError) as cm:
            ex.run_tool([sys.executable, "-c", "import sys; sys.stderr.write('bad\\n'); sys.exit(3)"])
        self.assertIn("exited 3: bad", str(cm.exception))
        with self.assertRaises(RuntimeError):
            ex.run_tool(["/nonexistent/tool"])


if __name__ == "__main__":
    unittest.main()
