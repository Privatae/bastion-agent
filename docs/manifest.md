# bastion agent job manifest: schema

The manifest is the contract between the agent and whoever directs it: what to
read, what to do with it, and who may query the result. Every part of the
agent validates against it. The loader is `bastion_agent/manifest.py`; the
signature is checked by the runtime ([runtime.md](runtime.md)) with
`bastion_agent/x509gate.py`.

## What a bastion agent is

A bastion agent is a program that runs on the owner's own machine and does the
data work that must stay there: walk a folder, extract text, sterilize personal
data, chunk, embed with a local model, catalog, and seal. A model on the
machine may serve as a sensor (for recall of personal data, embeddings and
summaries), and that is all: the same rule as the PII sterilizer
([pii-sterilization.md](pii-sterilization.md)), a deterministic program owns
the control flow and every change, and a model proposes, never acts.

The owner's host writes a **job manifest**, and it is signed (by the bastion,
in the managed install). The agent executes exactly that manifest and nothing
else. The output is a **catalog** (small, structured cards per file and per
directory) plus local vectors. The agent never sends the files themselves; a
host reasons over them by querying the agent. Sharing is a grant that lets
another host search the sanitized text or read ranges of it, until a set date
([`grants`](#grants)).

## Rules the schema enforces

1. **No plaintext sink.** `sink.plaintext` is the constant `never`. Any
   other value is a validation error, not a setting.
2. **Nothing runs that was not granted.** `mask` is the ceiling; every stage
   must be covered by an op in the mask, or the manifest is refused before it
   runs.
3. **Sharing needs `seal`.** `sink.catalog: host`, `seal_to` recipients, or
   any grant requires the `seal` stage. What `serve` returns, to the owner or
   to a grantee, is never sealed.
4. **No addresses.** The sanitizer and the embedder are found from the
   machine's environment when the agent runs. The manifest never carries a
   host:port.
5. **Signed by a CA-issued identity.** The runtime refuses a manifest whose
   signing certificate does not chain to the root in `FREEAGENT_CA_ROOT`, and
   refuses to judge at all without that root, because "signed by the key in
   the certificate next to the manifest" proves nothing. The signing
   certificate must carry exactly one CN. The loader checks the shape and
   computes the signing payload; the runtime checks the signature and the
   chain in the standard library (ECDSA P-256 / SHA-256), so the agent needs
   neither openssl nor a third-party package on the machine.

## File layout

```yaml
freeagent: 1
id: <slug>
owner:
  host: <slug>                 # the authoring host's cert CN

scope:
  roots: [<abs-or-~path>, ...]
  exclude: [<glob>, ...]        # optional
  follow_symlinks: false        # optional
  max_file_bytes: 268435456     # optional

mask: [read, search, index, summarize]   # subset; 'read' is mandatory

stages: [walk, extract, sanitize, chunk, embed, catalog, seal]  # ordered subset

sanitize:                       # required iff 'sanitize' in stages
  mode: sterilize | flag
  scope: <token scope>          # optional, default = id
  verify: false                 # optional

embed:                          # required iff 'embed' in stages
  model: <name>
  dim: <int>
  chunk:
    size_tokens: <int>
    overlap_tokens: <int>

summarize:                      # optional; needs 'summarize' in mask
  model: <name>
  per: [file, directory]

sweep: 15m | hourly | daily | manual

sink:
  catalog: local | host
  vectors: local
  plaintext: never
  seal_to: [<key-id>, ...]      # optional

grants:                         # optional, default []
  - host: <slug>
    ops: [search, read_range]
    until: <YYYY-MM-DD>

signature:                      # optional in the file; runtime requires it
  alg: ecdsa-p256-sha256
  cert: <path>
  value: <base64>
```

The first key, `freeagent: 1`, keeps the program's first name on purpose: the
bastion writes it into every manifest it generates, and renaming it would make
the agent refuse them.

## Fields

### Top level

| Field | Required | Rules |
|---|---|---|
| `freeagent` | yes | Schema version. Integer `1`. |
| `id` | yes | Lowercase slug `[a-z0-9-]+`, 1–63 characters. Names the catalog and is the default token scope for personal data. |
| `owner.host` | yes | Slug, 1–63 characters. The authoring host's certificate CN; the runtime checks the signing certificate's CN against it. |

Unknown keys anywhere are a validation error, so a misspelled `excludes:`
fails loudly instead of silently indexing everything.

### `scope`

| Field | Required | Rules |
|---|---|---|
| `roots` | yes | Non-empty list of paths. Each must be absolute (POSIX `/srv/a`, a Windows drive `C:\Users\me` or `C:/Users/me`, UNC `\\server\share`) or start with `~/` (or be exactly `~`), which expands to the running user's home on every OS. Relative paths are refused, so a manifest means the same thing wherever it lands. No duplicates. |
| `exclude` | no | List of glob strings, matched against the `/`-separated path relative to each root (`**` spans directories; a pattern with no `/` also matches any single path segment, so `node_modules` prunes it at any depth). Case-insensitive on Windows only. Default `[]`. See [walk.md](walk.md). |
| `follow_symlinks` | no | Boolean, default `false`. |
| `max_file_bytes` | no | Positive integer, default `268435456` (256 MiB). Larger files are catalogued by metadata only, never read. |

### `mask`: the ceiling

A non-empty list from `read`, `search`, `index`, `summarize`, with no
duplicates.

- `read`: **mandatory**; every stage reads.
- `search`: the agent may answer `search` queries over the vectors.
- `index`: the agent may write vectors and catalog entries. Required by
  `embed` and `catalog`.
- `summarize`: a local model may write summaries. Required by the `summarize`
  section.

There is no `write` and no `delete`: an agent never changes the files it
reads. Any other value is an error.

### `stages`: what runs, in order

A non-empty list, a subset of the canonical order, in canonical order:

```
walk → extract → sanitize → chunk → embed → catalog → seal
```

| Stage | Needs | Does |
|---|---|---|
| `walk` | (always first, always present) | The file system and metadata map: path, size, mtime, type, hash. The cheapest thing a host can plan from. |
| `extract` | `walk` | Text out of documents, code and (with a local OCR tool) images. |
| `sanitize` | `extract` | Personal data replaced by tokens in the text every later stage reads; never in the source files. |
| `chunk` | `sanitize` | Splits the sanitized text for embedding. |
| `embed` | `chunk`; mask `index` | Vectors from a local model, stored locally. |
| `catalog` | `sanitize`; mask `index` | Per-file and per-directory cards: what it is, when, entity counts, summary. **This is the curated dataset.** |
| `seal` | `catalog` | Encrypts the catalog to the owner's key and `sink.seal_to`. |

Out-of-order, duplicate or unknown stage names are errors, as is a stage whose
prerequisite stage is absent.

### `sanitize`

Present **if and only if** `sanitize` is in `stages`.

| Field | Required | Rules |
|---|---|---|
| `mode` | yes | `sterilize`: the full pipeline (rules, local-model recall, vault). `flag`: the rules pass only; deterministic, no model, and **not** "no personal data" (see [sanitize.md](sanitize.md)). |
| `scope` | no | Token scope, 1–63 characters. Default: the manifest `id`. The same (scope, type, value) gets the same token; a different scope gets a different token, so two catalogs cannot be linked through placeholders. |
| `verify` | no | Boolean, default `false`. A second, adversarial model pass (`sterilize` only; an error with `flag`). |

Where the sterilizer runs is never in the manifest; the agent reads it from
its environment and fails closed if it is absent.

### `embed`

Present **if and only if** `embed` is in `stages`.

| Field | Required | Rules |
|---|---|---|
| `model` | yes | Model name, 1–128 characters. |
| `dim` | yes | Integer 1–8192. The stage refuses to write if the embedding server (`EMBED_URL`) returns vectors of another dimension. Vectors are stored per model, so a later model change never discards existing vectors. |
| `chunk.size_tokens` | yes | Integer 1–8192. |
| `chunk.overlap_tokens` | yes | Integer, 0 ≤ overlap < size. |

There is no endpoint field: the embedder is the server `EMBED_URL` names in
the agent's environment, by default the Ollama port on the same machine. The
bastion sets it to `127.0.0.1:11434`; an agent run by hand can be pointed
anywhere.

### `summarize`

Optional. Requires `summarize` in `mask` and `catalog` in `stages`.

| Field | Required | Rules |
|---|---|---|
| `model` | yes | Model name, 1–128 characters, at the server `SUMMARIZE_URL` names. |
| `per` | yes | Non-empty subset of `file`, `directory`. |

### `sweep`

One of `15m`, `hourly`, `daily`, `manual`.

### `sink`

| Field | Required | Rules |
|---|---|---|
| `catalog` | yes | `local`: the catalog stays here, and the host queries it through `serve`. `host`: the sealed catalog is meant for the owner's host. The agent writes it to `<out>/sealed/` and neither the agent nor the bastion sends it. When `<out>` is inside the folder (the default, `<root>/.agent/`), a host whose folder grant has `read` can fetch it like any other file. Requires the `seal` stage. |
| `vectors` | yes | `local`, the only value. |
| `plaintext` | yes | `never`, the only value, ever. It is there so the rule is written down in every manifest and can be searched for, not remembered. |
| `seal_to` | no | List of recipient keys, 1–128 characters each, no duplicates. Requires the `seal` stage. The owner's key is always added by the agent and need not be listed. |

### `grants`

An optional list, default `[]`. Each entry lets another host query this
catalog. Requires the `seal` stage.

| Field | Required | Rules |
|---|---|---|
| `host` | yes | Slug, 1–63 characters: the grantee host's certificate CN. Must not equal `owner.host`. Unique across grants. |
| `ops` | yes | Non-empty subset of `search`, `read_range`. `search` requires `search` in the mask; `read_range` requires `read` (always present). |
| `until` | yes | `YYYY-MM-DD` expiry, a real calendar date. |

Revoking is removing the entry and re-signing; `serve` stops serving that host
on its next request. The grantee's client certificate must also chain to
`FREEAGENT_CA_ROOT` ([serve.md](serve.md)).

### `signature`

Optional in the file, so a manifest can be written, validated and reviewed
before it is signed. **The runtime refuses an unsigned manifest.**
`python3 -m bastion_agent validate --require-signed` enforces that here.

| Field | Required | Rules |
|---|---|---|
| `alg` | yes | `ecdsa-p256-sha256`. |
| `cert` | yes | Path to the signing host's PEM certificate, 1–256 characters, read relative to the manifest. |
| `value` | yes | Base64 signature over the signing payload. |

**Signing payload** = the manifest with `signature` removed, serialized as
canonical JSON (sorted keys, no whitespace, UTF-8, dates as ISO strings).
`bastion_agent.signing_payload(doc)` produces it and `signing_digest(doc)` its
SHA-256 hex, so the signer and the runtime agree byte for byte. Any ECDSA P-256
/ SHA-256 signer will do; the managed install signs in the bastion and records
the result with `sign --value`. By hand, with openssl:

```
python3 -m bastion_agent payload manifests/home-documents.yaml > payload.json
openssl dgst -sha256 -sign <host key> payload.json | base64 -w0
python3 -m bastion_agent sign manifests/home-documents.yaml --value <that base64> --cert <cert path>
```

(`sign --key <host key> --cert <cert path>` does the same in one step.)

The gate, in the standard library: exactly one CN, equal to `owner.host`; the
certificate inside its validity window and either identical to a certificate
in `FREEAGENT_CA_ROOT` (the managed install: its certificate is its own root,
and its self-signature must verify) or signed directly by one that is a CA
(basicConstraints, and keyCertSign when the root has a keyUsage extension);
and the signature over this payload. It is a one-level PKI only: longer chains
are not built.

## Loader

`bastion_agent/manifest.py` (Python 3, PyYAML). Library API:

```python
from bastion_agent import load_manifest, signing_payload, signing_digest
m = load_manifest("manifests/home-documents.yaml")   # raises ManifestError listing every problem
m.id, m.owner_host, m.scope.roots, m.mask, m.stages   # typed, frozen
m.sanitize, m.embed, m.summarize                      # None when the section is absent
m.sink.catalog, m.grants, m.signed                    # grants: tuple of Grant
signing_payload(m.raw)                                # bytes the signature covers
```

CLI (from the repository root):

```
python3 -m bastion_agent validate [--require-signed] <manifest.yaml> [...]
python3 -m bastion_agent show <manifest.yaml>          # stages, mask, grants, signed?
python3 -m bastion_agent payload <manifest.yaml>       # canonical signing payload to stdout
```

Validation collects **all** errors before failing, so one pass shows
everything wrong with the file. `python3 -m bastion_agent validate manifests/*.yaml`
validates every example. `python3 -m unittest bastion_agent.test_manifest`
runs the loader's tests, which also load `manifests/home-documents.yaml`, so
the example can never drift from the schema.

## Deliberately absent

- A `write` op. An agent reads; adding a way to change files is a decision of
  its own, not a field.
- An endpoint or address field anywhere, for the reason in rule 4.
