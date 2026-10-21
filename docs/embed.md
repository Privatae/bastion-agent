# bastion agent `chunk` and `embed` stages, and `search`

`chunk` splits the sanitized text into overlapping windows, `embed` turns each
window into a vector with a model on this machine, and `search` answers a
query against those vectors. They are `bastion_agent/embed.py`, standard
library only.

## chunk

`python3 -m bastion_agent chunk <manifest> [--out DIR] [--require-signed]`
reads the **sanitized** store (never the extract store) and writes
`chunks.jsonl`: one row per window (`chunk_id`, `doc` (the sanitized text's
sha256), `idx`, `start` and `end` character offsets, `chars`, `tokens`, `v`),
sorted by `(doc, idx)`, plus `chunk.summary.json`.

- Windows are `embed.chunk.size_tokens` long and advance by
  `size - overlap` tokens; the last window may be shorter. With any overlap,
  every character of the text is inside at least one window (with
  `overlap_tokens: 0` the whitespace between two windows may fall outside
  both).
- A "token" is a fixed regular-expression unit (a word or a punctuation mark),
  not a model's tokenizer. The standard library has none, and the same text
  must chunk the same way on every machine; the count is close enough to model
  tokens to size windows by.
- `chunk_id = sha256(document sha256, NUL, window text)`. An unchanged
  document keeps its chunk ids, and so its vectors, from one sweep to the
  next. A changed document has a new sha256, so all of its windows get new ids
  and are embedded again. Identical windows inside one document (a repeated
  paragraph) share an id and are embedded once.
- Duplicate documents (the same sanitized content at several paths) are
  chunked once.

## embed

`python3 -m bastion_agent embed <manifest> [--out DIR] [--require-signed]`
writes `vectors.db` (SQLite) and `embed.summary.json`.

**The endpoint is a sensor.** It comes from the environment, never the
manifest: `EMBED_URL` (default `http://127.0.0.1:11434`, a local Ollama),
`EMBED_API` (`ollama` or `openai`; unset means detect it with the probe),
`EMBED_BATCH` (32), `EMBED_TIMEOUT` (300 s). The manifest pins the **model
name and dimension**. Two wire formats: Ollama's `POST /api/embed` and the
OpenAI-style `POST /v1/embeddings` (llama.cpp server, TEI).

**The probe is the gate.** Before the first real call the stage embeds a fixed
probe string. If the served dimension is not the manifest's, the stage stops
before opening the store, so a wrong or mislabelled model never writes a
vector. An unreachable endpoint stops it the same way.

**Storage** (`vectors.db`):

| Table | Role |
|---|---|
| `chunks(chunk_id PK, doc, idx, start, end, text)` | This sweep's windows, rebuilt on every run. Holds the sanitized window text, so a search can return it. |
| `vectors(chunk_id, model, dim, vec BLOB float32, created)`, PK `(chunk_id, model)` | Kept across runs; rows are only ever added. |

Switching models **adds** rows for the new model; the old model's rows stay.
Vectors whose chunk no longer exists in this sweep also stay, and are counted
as `stale_vectors` in the summary: nothing is thrown away, so going back to an
earlier model or document costs nothing. A re-run embeds only chunk ids that
have no vector for the manifest's model (the rest are `reused`).

## search

`python3 -m bastion_agent search <manifest> "<query>" [-k N] [--out DIR]`
embeds the query through the same endpoint, scores cosine similarity against
every vector of the manifest's model, and prints the top k (default 5)
sanitized windows with their score, document id and index. It is a linear scan
in pure Python, which is fine to tens of thousands of chunks; an index
(HNSW or sqlite-vec) is the next step for a folder that outgrows it. The
query endpoint (`serve`, [serve.md](serve.md)) uses the same search.

## Tests

`python3 -m unittest bastion_agent.test_embed` runs against a loopback stub
that speaks both wire formats with a deterministic bag-of-words embedding:
window coverage, overlap and step; empty and short inputs; content-addressed
ids; the float32 packing and cosine edge cases; the chunk stage (duplicate
documents, sort order, determinism, the sanitize-first guard); the probe
refusing a wrong dimension before the store exists; an unreachable endpoint
failing closed; batching; reuse on a re-run; a second model adding rows while
the first model's rows stay; stale vectors kept and counted after a document
changes; OpenAI-style detection and a forced wrong API refused; and search
ranking the right document, with an empty result for a model that has no
vectors.
