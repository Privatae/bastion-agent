# PII sterilization

The `pii` package finds personal data in text and replaces it with
placeholder tokens, keeping the real values in a local vault. The agent's
`sanitize` stage runs it in process ([sanitize.md](sanitize.md)); it also
runs on its own as a small HTTP service. It is a deterministic program with
a model as one of its sensors: the program owns the control flow and every
change to the text, and the model only proposes.

## Purpose

Text that is going to leave the machine (a catalog, a chunk returned to a
host, context sent to a cloud model) first passes through `/sterilize`:
personal data is replaced with stable placeholder tokens, the real values stay
in a local vault, and `/rehydrate` puts them back, locally, on demand. A cloud
model can then work over the text without the values in it. Patterns alone
cannot do this: "my daughter goes to Lincoln Elementary" contains no pattern,
only meaning.

## Pipeline (`pii/pipeline.py`)

1. **Rules pass** (`detect.py`): deterministic detectors (below) for the
   anchors a pattern can find. They never depend on a model. Overlaps are
   resolved by type priority, then by length (an IP address is not a dotted
   phone number).
2. **Recall pass** (`recall.py`): a model proposes verbatim spans with a type
   from a closed vocabulary: names, addresses, employers, schools, medical
   facts, credentials. Which model is chosen when the service starts (below).
3. **Grounding**: every proposed span must occur exactly in the input, be at
   least two characters, have a known type and not contain a token or a
   token's bare name (`PII_PERSON_1`), or it is dropped and counted. An invented span can never mint a token or touch the
   text.
4. **Replacement**, by the program only: longest value first, every
   occurrence. The model never rewrites the text, so a model that misbehaves
   can cost recall but cannot corrupt the rest of the text. Replacement is by
   exact substring, so a value is also replaced where it appears inside a
   longer word ("Garcia" in "Garcias", "Marisol" in `Marisol_resume.pdf`): a
   missed inflection would be a leak, and an extra match only costs
   readability. No match may overlap a placeholder already in the text.
   Matches that overlap each other, including a value that overlaps itself
   ("aba" in "ababa"), become one placeholder over their union, typed by the
   longer value, so no fragment of either is left in the clear.
   Placeholder-shaped text in the input is first replaced by a placeholder of
   its own, so rehydrating gives back the literal text. Documents the agent
   reads are raw files, so every such literal in them is escaped. Text sent to
   the service may be the service's own earlier output (a stored conversation
   sent back on every save), so there a literal the vault holds for the scope
   is taken to be that token and passes through unchanged, and only a literal
   the vault does not hold (`[PII_FOO_99]`) is escaped. A caller can ask for
   every literal to be escaped with `escape_held_literals: true`. The cost of
   replacement grows with the number of occurrences times the number of
   placeholders in the text.
5. **Residual loop**: the rules pass runs again on the output until it is
   clean, at most three rounds; residuals are replaced, not only reported.
6. **Optional verify** (`verify: true`): a second, adversarial model pass over
   the sterilized text; its grounded findings go through replacement too.

If the recall pass fails, `/sterilize` answers 502: fail closed. Text without
the recall pass never leaves as "sterilized".

## Tokens, scopes, vault

- Tokens look like `[PII_<TYPE>_<n>]`: plain ASCII, they survive a round trip
  through a cloud model, and the model can reason about `[PII_PERSON_1]`
  across a conversation.
- **Stable within a scope**: the same (scope, type, value) always gets the
  same token. **Isolated across scopes**: the same value in another scope gets
  a different token, so two conversations or catalogs cannot be linked through
  shared placeholders. Stability is per value as replaced, not per detection:
  where a model's span overlaps a rule's hit (a phone number inside an address
  the model proposed), the two become one placeholder for the combined text,
  typed by the longer value. That placeholder differs from the one the phone
  number gets on its own elsewhere. If a later run proposes the longer span
  with a different type, the same bytes get a different placeholder. The
  caller chooses the scope (default `default`; the agent uses the manifest's
  `sanitize.scope`).
- The vault is SQLite, created 0600 under umask 077. Rows are never deleted:
  the next number in a scope is the count of its rows plus one, so after a
  delete that number either names a token that still exists (and the insert
  fails) or, if the newest row was deleted, gives its token to a different
  value. A delete feature would first need a separate sequence. In the service, every sterilize and rehydrate also
  writes an audit row; `GET /scope/<id>` lists tokens, types and creation
  times, never values.

## The service (`pii/service.py`)

Standard library only: the process holds the most sensitive data on the
machine, and every dependency is attack surface.

| Route | Auth | Does |
|---|---|---|
| `GET /health` | none | Liveness. |
| `GET /scope/<id>` | key | The token inventory of a scope (no values). |
| `POST /sterilize {text, scope?, verify?, escape_held_literals?}` | key | The pipeline; returns `{text, findings, stats}`, with `stats.recall` naming the recall backend. `escape_held_literals: true` escapes every placeholder-shaped string in `text`, even one the vault holds; the agent sends it for documents. |
| `POST /rehydrate {text, scope?}` | key | Values back in place of known tokens; returns `{text, restored, unknown_tokens}`. |
| `POST /flag {text}` | key | The rules pass alone: `{flagged, counts}`. No model, no vault rows, no audit. |

Request bodies are limited to 2 MiB.

`stats` in a `/sterilize` answer counts what this call did: `rules` (rule
findings), `llm` (grounded model proposals), `llm_ungrounded` (proposals
dropped by grounding), `residual_tokenized` and `verify_tokenized` (values
those passes actually replaced), and `literal_tokens_escaped`
(placeholder-shaped strings in the input that were escaped, each distinct
string counted once per call). Escaped literals appear in neither `findings`
nor the per-type counts. `stats.recall` names the recall backend, and
`stats.escape_held_literals` echoes which literal rule was applied, so a
caller that asked for it can check.

**A clean `/flag` does not mean "no personal data".** It sees only what the
rules find, never contextual data such as a name; anything that is kept or
sent on goes through `/sterilize`.

Configuration, from the environment:

| Variable | Default | Meaning |
|---|---|---|
| `PII_API_KEY` | (none) | Required. Without it the service refuses to start: `/rehydrate` returns real values, so there is no unauthenticated mode. (`PII_ALLOW_NOAUTH=1` exists for the unit tests only.) |
| `PII_BIND` | `0.0.0.0:8091` | The address the service listens on; this is its exposure control. |
| `PII_DB` | `/data/vault.db` | The vault. |
| `PII_RECALL` | `llm` | The recall backend (below). |
| `LLM_URL` | `http://llm:8080` | The model server for `llm`. |
| `PII_LLM_TIMEOUT` | `300` | Seconds per model call. |

Two ways to run it, the same code:

- **Container**: `pii/Dockerfile` (a pinned `python:*-slim` image, no pip
  install; the vault on a mounted `/data`).
- **systemd**: `pii/pii.service`, with install steps in its header. It runs
  with `DynamicUser`, a private 0700 state directory for the vault
  (`/var/lib/privatae-pii/vault.db`), loopback bind (`127.0.0.1:8091`), and
  the key in a 0600 environment file.

The bastion can make a service on the machine reachable to the owner's host:
with `PRIVATAE_PII_ADDR` set to the service's address, it forwards to it
through its tunnel and reports in its heartbeat that the service is there and
whether it answers. The bastion passes requests through without reading them
and never holds the API key; the caller sends it.

## Recall backends (`pii/recall.py`)

The recall pass is a pluggable sensor, chosen by whoever runs the service
with `PII_RECALL` when it starts, never per request, so a request cannot
downgrade it. Whichever sensor proposes, grounding drops any span that is not
exactly in the input and the program makes every replacement, so swapping the
sensor changes recall, never the integrity rules.

| `PII_RECALL` | What | Where it fits |
|---|---|---|
| `llm` (default) | A llama.cpp-compatible server's `/v1/chat/completions` at `LLM_URL`, with the output constrained by a JSON schema (`response_format: json_schema`), temperature 0, thinking turned off per request (`llmclient.py`). | A machine that can reach a model server. Best recall. |
| `gliner` | GLiNER (Apache-2.0), zero-shot named-entity recognition in this process, on CPU. Its labels are plain-English phrases mapped onto the closed type vocabulary (`recall.GLINER_LABELS`); `OTHER` is deliberately not a label. `GLINER_MODEL` (default `urchade/gliner_multi_pii-v1`), `GLINER_THRESHOLD` (0.5), `GLINER_VERIFY_THRESHOLD` (0.3, the more aggressive second pass). | A laptop with no GPU and no model server. |

Fail closed when it starts: `PII_RECALL=gliner` without the `gliner` package,
a model that will not load, or an unknown backend name stops the service before
it serves a request. (The `llm` server is not probed at start; an unreachable
one fails each `/sterilize` with 502.)

Why GLiNER and not Presidio: Presidio (MIT) is the usual framework, but it
brings spaCy and optionally torch into the process that holds the data. GLiNER
is one optional import, loaded only when chosen. What was taken from Presidio
instead is its list of recognizers, as deterministic rules. The cost is real:
the `gliner` package pulls in torch (a CPU build), hundreds of megabytes on
the machine.

## The rules pass (`pii/detect.py`)

Every detector is anchored by a checksum, a prefix or a fixed shape; none
depends on a model.

- **E-mail, phone, SSN, IPv4/IPv6, MAC.**
- **Cards** → `CREDIT_CARD`, checked with Luhn.
- **IBAN** → `BANK_ACCOUNT`: ISO 13616 mod-97 plus a per-country length
  table. It runs before the card detector, so an IBAN's digits cannot be
  claimed as a card number.
- **US ABA routing number** → `BANK_ACCOUNT`: the weighted checksum and a
  `routing`, `ABA`, `RTN` or `transit` cue within 40 characters before it
  (one random 9-digit string in ten passes the checksum alone).
- **Bitcoin legacy and P2SH addresses** → `BANK_ACCOUNT`: base58check
  (double SHA-256). Bech32 (`bc1…`) addresses are not detected.
- **Secrets** → `CREDENTIAL`: AWS access key ids, GitHub classic and
  fine-grained tokens, Slack tokens, Google API keys, Stripe keys, GitLab
  tokens, OpenAI-style `sk-` keys, JWTs, and whole PEM private-key blocks (one
  finding per block, at the highest priority, so the digits inside are never
  claimed piece by piece).

## Portability

The package parses at the Python 3.8 floor shared with the agent
(`test_syntax_floor.py`), with `typing` generics and no newer standard-library
calls, so the systemd form runs on older interpreters as it is.

## Tests

- `python3 -m unittest pii.test_pii`: detectors, vault stability and
  isolation, grounding, longest match first, the HTTP wire format against a
  stub llama.cpp server, auth, and fail-closed configuration. No model is
  needed.
- `PII_API_KEY=<key> pii/verify-live.sh [host:port]` runs eight checks
  against a running service and its real model: rules-class sterilization,
  contextual recall (school, address, doctor, medical), a round trip back to
  the original, token stability, scope isolation, untouched non-personal text,
  auth, and health.

## Limits

- **Sterilization narrows what is missed; it cannot guarantee nothing is.** The
  recall pass is probabilistic. The layers (rules, model, residual loop,
  optional verify) reduce misses but cannot make them impossible. Anything
  that tells a person their data is protected has to say so.
- **The vault is not encrypted at rest.** The controls are the file's 0600 mode,
  its directory, and the bind address.
- **Rows are never deleted** (see above), so there is no erasure yet.
- **Placeholders are plain tokens.** Surrogate values (invented names in place
  of real ones, for fluency) are not done.
- **Through the service, a quoted placeholder that names a live token is read
  as that token.** If text sent to `/sterilize` quotes `[PII_PERSON_1]` and the
  vault holds `[PII_PERSON_1]` for the same scope, rehydrating gives the
  vault's value in its place. The placeholder cannot be told apart from one
  the service minted earlier, and treating it as a token is what lets
  already-sterilized text be sterilized again without change. A quoted
  placeholder the vault does not hold is escaped and comes back as written.
  The agent's document stage is not affected: it asks for every literal to be
  escaped.
- **One model call per `/sterilize`**, two with `verify`; the agent makes one
  per 20,000-character chunk. That suits writes to context and memory; an
  interactive path would want smaller calls or a smaller model.
