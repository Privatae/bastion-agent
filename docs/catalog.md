# bastion agent `catalog` stage: the curated dataset

The catalog is the small, structured thing a host reasons over and the thing
`seal` ships: one card per file and one per directory, built only from the
sanitized text. It is `bastion_agent/catalog.py`, standard library only.

`python3 -m bastion_agent catalog <manifest> [--out DIR] [--require-signed]`
needs the walk, extract and sanitize outputs, and reads `chunks.jsonl` if it
is there. It writes:

- **`catalog.jsonl`**: one card per file the walk found, sorted by
  `(root, path)`.
- **`catalog.dirs.jsonl`**: one card per directory that holds files (every
  ancestor of every file; the root is `""`), sorted the same way.
- **`catalog.summary.json`**: counts, the summarizer that ran (or `null`),
  `stopped`, and `bytes_catalog` (the length of all the cards, in
  characters).

## The file card

| Field | From | Notes |
|---|---|---|
| `root`, `path`, `name`, `kind`, `size`, `mtime`, `mime`, `sha256` | walk | `path` and `name` after the name mask (below). |
| `text` | extract | `ok`, `empty`, `unsupported`, `error`, `skipped` or `not_extracted`. |
| `extractor` | extract | Which reader, e.g. `pdftotext`, `pdf-builtin`, `docx`, `text:utf-8`. |
| `sanitized` | sanitize | `ok`, `skipped`, `error`, `not_run`, or `null` when the sanitize stage has no record for it. |
| `title` | **sanitized text** | The first line of at least three characters, list and heading markers stripped, at most 120 characters. |
| `head` | **sanitized text** | The first 300 characters, whitespace collapsed. |
| `chars` | sanitized text | Length. |
| `keywords` | **sanitized text** | The top 8 by TF-IDF across the catalog: words of three or more letters, stopwords and placeholders removed, ties broken alphabetically (so the result is deterministic). |
| `entities` | sanitize | Token counts per type minted for this file, e.g. `{"EMAIL": 2, "PERSON": 1}`. Counts, never values. |
| `chunks` | chunk | How many windows the document produced (0 without the chunk stage). |
| `summary` | summarizer | Present only when the manifest asks for file summaries; `null` when there was no text. |
| `v` | | The card format version. |

Only files with sanitized text get the text fields. A file without text still
gets a card: the host can see that it exists, its type and size, and why it
has no text.

## The directory card

`files`, `with_text`, `bytes`, `latest` (newest mtime), `types` (the top 6
MIME types), `keywords` (the top 12 over the merged term counts), `entities`
(summed over the files), and `summary` when asked for.

## What never enters the catalog

- **Values.** Every field derived from text comes from the sanitized store. A
  test searches the whole catalog for the fixture's personal data and fails on
  any hit.
- **Placeholders as keywords.** `[PII_*_n]` tokens are removed before terms
  are counted.
- **Anchors in names.** File and directory names are plaintext by nature, so
  every segment of every path (parent directories included) goes through the
  rules pass; an e-mail address, phone number, card or key in a name is masked
  to `[PII_TYPE]`. The masking is conservative: the e-mail rule spans dots and
  hyphens, so `invoice-m@example.com.pdf` becomes `[PII_EMAIL]`; `mime` and
  `size` still say what it was. The summary counts masked segments as
  `names_masked`. **A name like `Marisol_medical.pdf` is not caught**: that is
  contextual personal data, the same limit as the rules-only `flag` mode. The
  mask is the catalog's: the bastion's own listing, for a grant with `read`,
  returns names as they are.
- **Not hidden: content hashes.** Each file card's `sha256`, also the `doc` id in
  search hits and excerpts, is the hash of the original file, so whoever holds
  a copy of a file can confirm it is in the folder.

## The summarizer (a sensor)

A manifest section `summarize: {model, per: [file, directory]}` turns it on
(it needs `summarize` in the mask). The model is reached through
`SUMMARIZE_URL` (default `http://127.0.0.1:11434`, a local Ollama),
`SUMMARIZE_API` (`ollama` or `openai`; unset means try Ollama's `/api/chat`,
then `/v1/chat/completions`) and `SUMMARIZE_TIMEOUT` (300 s): the
environment, never the manifest.

It sees only sanitized text (the first 12,000 characters), is told that
placeholders are redactions to keep as they are, and runs at temperature 0.
Its reply is cleaned (`<think>` blocks and surrounding quotes removed,
whitespace collapsed, at most 600 characters) into the `summary` string, the
only field it can touch. A directory's summary is built from its direct
children's summaries or heads (at most 60, 200 characters each). Summaries are
cached in `catalog.cache.json` by document, model and version, so a re-run
costs nothing for unchanged documents.

The first failure stops summarizing: every card is still written, one card
carries `summary_error`, the summary says `stopped`, and the exit code is 1.

## Tests

`python3 -m unittest bastion_agent.test_catalog` covers title, head and
keywords and their determinism; name masking (e-mail, phone, plain names,
parent directories); summary cleaning; the whole stage with and without a
summarizer (card fields, entities, keywords free of placeholders, a card for
a file with no text, directory totals including the root, masked names
counted); the catalog containing none of the fixture's personal data; file and
directory summaries with the cache reused on the second run and the model
seeing only sanitized text; OpenAI-style detection; a summarizer failure
stopping after one call with every card still written; an unreachable
summarizer; and the guard that the earlier stages ran first.

The stopword list is for prose: on source code, identifiers such as `self`
and `def` count as keywords.

## Not in this stage

Sealing (the next stage: the catalog encrypted to the owner and the
manifest's `seal_to` recipients) and any rendering of the cards on the host.
