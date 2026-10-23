# bastion agent `sanitize` stage: personal data out of the text

The sanitize stage runs the extracted text through the PII sterilizer
(`pii/`, described in [pii-sterilization.md](pii-sterilization.md)) and keeps
the result in a store of its own. Every later stage reads that store, never the
extracted text. It is `bastion_agent/sanitize.py`.

## What it produces

`python3 -m bastion_agent sanitize <manifest.yaml> [--out DIR] [--require-signed]`
reads the extract index and store and writes:

- **`sanitize/<aa>/<sha256>.txt`**: the sanitized text store. Personal data is
  replaced by stable `[PII_TYPE_n]` tokens. **From this stage on, later
  stages read only this store.** The extract store keeps the plaintext and
  never leaves the machine.
- **`vault.db`**: the token-to-value map (in-process mode only), created 0600
  under umask 077. It is the only way back from a token to a value, and it
  stays on the machine. It is `<out>/sanitize/vault.db`, or
  `$FREEAGENT_VAULT_DIR/vault.db` when that is set: the output folder may be
  synced to a cloud drive, the vault must not be, so the bastion sets
  `FREEAGENT_VAULT_DIR` to its own state directory.
- **`sanitize.jsonl`**: one record per extracted file: `status`, `mode`,
  `stats` (counts from the pipeline, summed over the file's chunks: rule hits,
  recall hits, dropped proposals, residuals and verify hits replaced, and
  `literal_tokens_escaped`, so a literal that appears in two chunks counts
  twice), `types` (token counts per type), `chars`, `reused`,
  `error`. **Never a value.** A test searches the index and the summary for
  the fixture's personal data and fails if any appears.
- **`sanitize.summary.json`**: counts, token totals per type, the sterilizer
  that ran (`flag:rules-only`, `sterilize:llm=…`, `sterilize:gliner=…@0.50`,
  `service:http://…`), and `stopped` when the stage failed closed.

| `status` | Meaning |
|---|---|
| `ok` | Sanitized text written (or kept from an earlier run: then `reused` is true). |
| `skipped` | The extract stage had no text for it (unsupported, error, empty, too large). |
| `error` | A failure that is not the recall pass (the store unreadable, an HTTP error from the service other than 502). The stage continues. |
| `not_run` | The stage stopped (fail closed) at or before this file. |

Exit code: `0` clean; `1` the manifest is invalid, `sanitize` is not in its
stages, there is no extract index, or the stage **stopped**; `2` completed with
`error` records.

## Modes (manifest `sanitize.mode`)

- **`sterilize`**: the full pipeline: the rules pass, the recall pass,
  grounding, replacement by the program, the residual loop, and the optional
  adversarial `verify` pass. Contextual personal data (names, schools,
  employers, medical facts) is found by the recall pass.
- **`flag`**: the rules pass **only**: deterministic, no model, milliseconds.
  It replaces the anchors a pattern can find: e-mail addresses, phone
  numbers, SSNs, cards, IBANs, routing numbers, crypto addresses, IP and MAC
  addresses, API keys, private-key blocks, JWTs. It can also replace an
  ordinary number that looks like a phone or ID number. **It does not find names,
  street addresses, dates of birth**, or anything else that takes reading for
  meaning (an employer, a school, a medical fact). It is the mode the bastion
  writes into every manifest it deploys. A flag-mode catalog is not free of
  personal data, and the manifest doc says so too.

## Where the sterilizer runs

It is chosen from the environment, never the manifest (a manifest carries no
addresses).

| Condition | Where | Vault |
|---|---|---|
| `mode: flag` | In this process, rules only. `PII_ADDR` is ignored. | `vault.db` as above |
| `mode: sterilize`, no `PII_ADDR` | In this process: `pii` inside the agent, the recall pass from `PII_RECALL` (`llm` → the server at `LLM_URL`; `gliner` → an in-process CPU model). The laptop case. | `vault.db` as above |
| `mode: sterilize`, `PII_ADDR` set | A running PII service over HTTP (`POST /sterilize`, `Authorization: Bearer $PII_API_KEY`). | The service's own |

`PII_ADDR` without `PII_API_KEY` is refused: the service fails closed, and so
does its caller.

## Rules the stage enforces

- **Fail closed.** The first recall failure (the model unreachable, the service
  answering 502 or not at all) stops the stage. So does a service that does
  not confirm it escaped every placeholder-shaped string in the document
  (`stats.escape_held_literals` missing or false: a service older than the
  agent); upgrade the service. The file being sanitized and
  every file not yet reached are recorded `not_run`; nothing half-sanitized is
  written; the exit code is 1 and `summary.stopped` says why. A recall backend
  that cannot start (for example `PII_RECALL=gliner` without the `gliner`
  package) stops the stage before the first file, with exit code 1 and no
  index written.
- **Tokens are stable within a scope.** `sanitize.scope` (default: the
  manifest id) is the vault scope: the same e-mail address in two documents of
  one catalog gets one token, so the catalog stays coherent, and a different
  catalog gets different tokens, so two catalogs cannot be joined through
  shared placeholders.
- **Long texts are split, not truncated.** The sterilizer is called per chunk
  of at most 20,000 characters (`SANITIZE_CHUNK_CHARS`), split at paragraph
  and then line boundaries (a single longer line is cut). The chunks join back
  to the input exactly, and because tokens are stable a value that appears in
  two chunks gets one token. A cut never falls inside a placeholder: it moves
  back to before the placeholder, or just after it when the placeholder starts
  the chunk (only possible when the placeholder is longer than the limit), so
  that chunk runs over the limit by the rest of the placeholder.
  Any text in a document that looks like a placeholder is escaped, whether or
  not the vault holds that name, so a document quoting `[PII_EMAIL_1]` comes
  back as written and never as another document's value.
- **What makes a file be done again**: a change in its content, the mode, the
  scope, `verify`, where the sterilizer runs (in process or service), or
  `SANITIZE_VERSION`. **Results are redone when the pipeline changes:**
  `SANITIZE_VERSION` is raised whenever the same text would be sterilized
  differently, so an upgrade that raises it re-sanitizes every file once.
  Changing only the recall backend or its model does not redo files already
  sanitized; raise `SANITIZE_VERSION`, or start from an empty output folder,
  when that matters.
- **Duplicate content is sanitized once**, and every path that has it is
  indexed.

## Tests

`python3 -m unittest bastion_agent.test_sanitize` covers flag mode with the
real pipeline and vault (anchors replaced, a name left alone: the limit is
asserted, not hidden), the index and summary carrying no values, the vault's
0600 mode and `FREEAGENT_VAULT_DIR`, reuse and its invalidation (content,
scope), token stability across files, sterilize mode with a fake recall
backend (grounding drops an invented span; stats reported), the fail-closed
stop after the first recall failure (`not_run`, no store file written, the
backend called once), a backend that cannot start, the chunking round trip
(one token across every chunk) and hard cuts, the service path over a stub
speaking the real wire format (auth header, scope, verify, `stats.recall`), a
service 502 failing closed, a service without a key refused, flag mode never
touching the service, and the extract-first guard.

A `sterilize` run against a real recall model is not part of the suite; the
PII service's `verify-live.sh` does that against a running service.

## Not in this stage

Chunking for embedding (the next stage, which reads the sanitized store),
putting values back (the vault is local, and `/rehydrate` belongs to the PII
service), and encryption of the vault at rest (not done: the controls are the
file's 0600 mode and where it is kept).
