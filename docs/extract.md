# bastion agent `extract` stage: text out of the walked files

The extract stage turns every walked file it can read into plain text, with
built-in readers or with local tools when they are installed. It is
`bastion_agent/extract.py` and `bastion_agent/pdftext.py`, standard library
only.

## What it produces

`python3 -m bastion_agent extract <manifest.yaml> [--out DIR] [--no-external] [--require-signed]`
reads `walk.jsonl` and `walk.summary.json` from `DIR` (the walk must have run;
the stage refuses otherwise) and writes:

- **`extract/<aa>/<sha256>.txt`**: the text store, one file per distinct
  content hash, UTF-8, normalised (CRLF and lone CR become LF, NUL removed,
  NFC). Content addressing is the cache: two copies of a document are
  extracted once, and an unchanged file costs nothing on the next sweep.
- **`extract.jsonl`**: one record per walked file, sorted by `(root, path)`:
  `sha256`, `mime`, `status`, `extractor`, `chars`, `error`, `v` (the
  extractor version), `reused` when a prior verdict was kept, and on
  `unsupported` records the `tools` that were present, so the verdict is
  retried when a tool appears.
- **`extract.summary.json`**: counts, total characters, the tools found, the
  extractor version, the manifest digest, and the manifest digest the walk
  recorded, which ties the walk map and the text store to one manifest.

`DIR` defaults as for the walk (`<root>/.agent/` for one root). This text
store is the plaintext of every file in scope. The agent never serves it, but
by default it sits in the folder, so if the folder is synced, the sync provider
gets a copy. A bastion from 0.58.1 on never serves `.agent/` to a host. On an
older bastion, a host whose folder grant has `read` can read the store like
any other file unless the grant excludes `.agent`; see
[runtime.md](runtime.md#where-an-agent-lives-rootagent).

| `status` | Meaning |
|---|---|
| `ok` | Text written to the store. |
| `empty` | The reader ran and found no text (an empty file, a document with only pictures). |
| `unsupported` | No reader for this type on this machine; `error` names what would handle it. |
| `error` | The reader failed (a corrupt zip, bad XML, a tool failure); the stage continues. |
| `skipped` | The walk has no hash for it (too large, a read error, or a `--no-hash` walk). |

A record whose earlier verdict was kept carries `reused: true` and is counted
under `reused` in the summary.

Exit code: `0` clean; `1` the manifest is invalid, `extract` is not in its
stages, or there is no walk map; `2` completed with `error` records.

## Readers

Built in, no libraries:

| Type | How |
|---|---|
| `text/*`, JSON, YAML, TOML, XML, SQL, SVG, PEM, code | Decoded, and the encoding recorded (`text:utf-8`, `text:cp1252`, …): a byte-order mark first, then BOM-less UTF-16 by the share of NUL bytes, then strict UTF-8, then cp1252. |
| `text/html` | `html.parser`: scripts, styles, `noscript` and `template` dropped; block tags become line breaks; entities resolved. |
| CSV / TSV | `csv` module; each row written as tab-separated values. |
| `message/rfc822` | `email` (modern policy): From/To/Cc/Date/Subject lines, then the plain body, or the HTML body through the HTML reader. |
| RTF | A small reader of its own: control words, `\'hh` (cp1252), `\uN` (one fallback character skipped), and the groups that hold no body text (`fonttbl`, `colortbl`, `stylesheet`, `info`, `pict`, `object`, `header`, `footer`, and others) discarded. |
| DOCX | Paragraphs of `word/document.xml` (runs, tabs, breaks, text boxes after the paragraph that holds them), plus headers and footers. |
| XLSX | Shared strings, inline strings and values, one tab-separated line per row, a `# sheetN` line per sheet; empty rows dropped. |
| PPTX | Every paragraph on every slide, slides in numeric order, a `# slideN` line per slide. |
| ODT / ODS / ODP | `content.xml`: paragraphs and headings; table rows tab-separated. |
| PDF | **`pdftotext -layout -enc UTF-8` when poppler is on PATH.** Otherwise the built-in reader (below). |
| Images (PNG, JPEG, TIFF, BMP, GIF, WebP) | **`tesseract` when it is on PATH**; otherwise `unsupported`. |

Anything else (archives, executables, audio, video, unknown binaries) is
`unsupported`, with the MIME type named.

### The built-in PDF reader

Without poppler (on Windows, usually) PDFs are read by `pdftext.py`, which
walks the document far enough for text: the object table (a later definition
wins, so incremental updates are respected) and compressed object streams;
FlateDecode streams (a stream with any other filter is skipped); the page tree
in order with inherited resources; fonts through their `/ToUnicode` maps
(Type0 / Identity-H fonts, as browsers print them), or WinAnsi / MacRoman for
simple fonts without one; glyph widths, so a word placed by position still
gets its space; the text operators, and form XObjects. Pages are separated by
a form feed.

Encrypted files are refused. Output below 90% printable characters is refused
too, so a font without a usable map comes back as `unsupported` (`extractor:
pdf-builtin`, `needs pdftotext (poppler) on this machine`), never as byte salad
in the catalog.

It reads arbitrary files, so it reads on a budget per document: 60 s of wall
time, 256 MiB of decoded streams (64 MiB per stream), 5 million content
operators, 2,000 form invocations at most 6 deep, 200,000 CMap entries,
20 million tokens and 1 GiB lexed. Reaching a limit stops the read with the
pages read so far. Nothing in it raises out to the stage.

## Rules the stage enforces

- **External tools are sensors, not dependencies.** They are looked up on
  PATH at run time, named in every record they produced (`extractor:
  pdftotext`), and their absence is a recorded gap, never a failure.
  `--no-external` (in a sweep, `FREEAGENT_NO_EXTERNAL=1`) uses the built-in
  readers only. A manifest cannot name a tool or an address.
- **Nothing is written outside the output directory**, and every file is
  written atomically.
- **Bounded reads.** One zip member is read to at most 64 MiB decompressed
  (`ZIP_MEMBER_CAP`), so a hostile office file cannot balloon memory. Office
  documents are parsed as a stream, each finished paragraph or row dropped
  once read, and capped per document: 256 MiB of XML, 16 Mi characters of
  text, 60 s, and 200,000 parts in one paragraph or row. Reaching a cap keeps
  the text read so far and ends it with a line naming the cap. XML with a DTD
  or an entity declaration is refused (Office files never carry one, and it is
  how entity expansion gets in), as is XML that is neither UTF-8 nor UTF-16.
  Tool calls time out at 300 s.
- **Errors are entries.** A corrupt document is one `error` record; the stage
  finishes and reports the count.
- **Retry only when something changed.** An `unsupported` verdict is kept
  while the machine's tool set is the same; install `pdftotext` and the next
  sweep tries exactly those files again. `error` records are retried on every
  sweep. Every record carries the extractor version (`v`, `EXTRACT_VERSION`,
  now 2); raising it after a reader changes redoes every cached verdict and
  text on the next sweep.

## Tests

`python3 -m unittest bastion_agent.test_extract bastion_agent.test_pdftext`.
`test_extract` runs every reader against a generated fixture (docx, xlsx,
pptx and odt built with `zipfile`, plain and Flate PDFs, RTF with hex and
Unicode escapes, plain and HTML e-mail, encodings), the Office streaming caps,
DTD refusal and UTF-16 input, the zip member cap, an oversized CSV field, the
whole stage over a mixed tree (statuses, counts, duplicates), reuse across
sweeps and its invalidation when content or the extractor version changes,
tool discovery and failure (mocked), and the walk-first guard. `test_pdftext`
builds browser-shaped PDFs with a small writer (Type0 fonts with ToUnicode
maps, per-run positioning, ligatures, inherited resources, form XObjects,
object streams) and hostile ones (reference cycles, deep nesting, malformed
tables and maps), and checks each budget.

The external-tool paths are tested with mocks; a real scanned PDF or image
through `pdftotext` or `tesseract` is not part of the suite.

## Not in this stage

Sanitizing (the next stage: the text store goes through the PII sterilizer),
chunking, and change detection beyond the content hash. Audio and video are not
extracted.
