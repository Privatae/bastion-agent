# bastion agent runtime: the `sweep` scheduler and the manifest gate

`sweep` is the agent proper: the loop that checks the manifest and runs its
stages on the manifest's cadence, on the owner's machine. It is
`bastion_agent/run.py`, with the signature check in `bastion_agent/x509gate.py`,
standard library only apart from the manifest loader's PyYAML.

`python3 -m bastion_agent sweep <manifest> [--out DIR] [--once] [--allow-unsigned]`

Each cycle:

1. **Read the manifest again.** A re-signed manifest takes effect on the next
   sweep: a revoked grant, a new root, a changed cadence.
2. **The gate.** The manifest must carry a signature that verifies: ECDSA
   P-256 over the canonical payload (`signing_payload`, the same bytes the
   `payload` command prints), from a certificate with exactly one CN, equal to
   `owner.host`, that chains to `FREEAGENT_CA_ROOT`. The root is required:
   without one the gate refuses rather than trust the certificate beside the
   manifest. Anything else (unsigned, the wrong key, edited after signing,
   someone else's certificate, a certificate outside the CA, a certificate with
   two CNs) and **nothing runs**. The refusal is appended to `run.jsonl` like
   any other run; a manifest too broken to have an id is logged under
   `build/freeagent/refused/` unless `--out` is given. `--allow-unsigned` is
   for development only: the CLI help says so in capitals, and it is written
   into every run record it touches.
3. **The stages, in the manifest's order.** The first failure stops the run,
   so a later stage never consumes a half-finished earlier one. A stage that
   completes but reports `stopped` (sanitize or catalog failing closed) counts
   as failed.
4. **Record and wait.** One line is appended to `run.jsonl`, `run.state.json`
   is rewritten, and the loop sleeps until the next run is due, or exits for
   `manual` (and after `--once`).

Signing, on the host's side: `python3 -m bastion_agent sign <manifest> --cert <cert> --key <key>`
signs with openssl and writes (or replaces) the signature block;
`--value <base64>` records a signature made elsewhere instead. The bastion
signs in its own process with the key it minted for the agent and records it
with `--value`. The certificate path is recorded as given and read relative to
the manifest. [manifest.md](manifest.md) has the details.

## Where an agent lives: `<root>/.agent/`

One agent per folder, and the agent lives with its folder. For a manifest with
one root, the commands that run a single stage, `sweep` and `serve` default
their output directory to `<root>/.agent/`: the signed manifest and every prepared output
(walk map, extract index, sanitized store, chunks, vectors, catalog, run log,
sealed bundles). Copy the folder and the agent comes with it; fork it and you
have a new one. The walker always excludes `.agent/`, so an agent never
indexes its own output.

What is in `.agent/`: the **extract store is the plaintext of every file in
scope** (a PDF or DOCX becomes a flat `.txt`), and the sanitized store is that
text with personal data tokenized (only the rules-pass anchors, unless the
manifest uses `sterilize`). That is the same trust boundary as the folder
itself, since the source files are already there, but a sync provider now
receives a second, flattened, indexable copy, and a host whose folder grant
has `read` can read the extract store as it is: the bastion's listing and raw
reads cover `.agent/` like any other folder the grant does not exclude. If that
matters for a folder, exclude `.agent` from sync; add `.agent` to the paths the
grant excludes, and the bastion then leaves it out of a host's listings and
refuses reads of it; or, for an agent run by hand, keep the output elsewhere
(`--out`). The bastion keeps its agent in `<root>/.agent/` too, except on
Windows when the bastion runs as the system service, or when it cannot create
`.agent` in the folder (a read-only folder, for one); it then keeps it in its
own state directory.

The identity key is never in `.agent/`: it is wherever `FREEAGENT_TLS_KEY`
points. The PII vault (plaintext values) is in `.agent/sanitize/vault.db` for
an agent run by hand. A Documents folder is often cloud-synced, so set
`FREEAGENT_VAULT_DIR` to keep the vault out of it; the bastion always sets it
to its own state directory. The certificate is public and may sit anywhere.

**One machine per folder.** The manifest is signed by the machine's own key,
and the gate proves "signed by this key", not "the newest". If a synced folder
is served from two machines, or a sync conflict restores an earlier signed
manifest, the endpoint serves the older terms until the manifest is rewritten.
Run one agent per folder, on one machine.

## Cadence and backoff

| `sweep` | Period | On failure |
|---|---|---|
| `15m` / `hourly` / `daily` | 900 / 3600 / 86400 s from the run's start | Retry after 60 s, 120 s, 240 s … capped at the period; `consecutive_failures` counts up and resets on success. |
| `manual` | | One run, then exit. |

Waits are taken in naps of at most 30 s, so SIGTERM or SIGINT lands quickly; a
stop request lets the current run finish and never interrupts a stage.

## The lock

`<out>/sweep.lock`, created atomically (`O_EXCL`) with the pid and time
inside. A second sweep on the same output directory is refused, with the holder
named. A lock is stale only when its holder is provably gone: on POSIX the pid
decides, and a live pid keeps its lock however long its sweep runs; only where
the pid cannot be checked (Windows) or the file cannot be read does age decide,
by the file's mtime, after 12 hours. A reclaimed lock is noted in the run
record.

## Files

| File | Content |
|---|---|
| `run.jsonl` | Append-only, one record per run: `v`, `started`, `finished`, `seconds`, `manifest`, `out`, `manifest_id`, `manifest_digest`, `gate` (`cn`, `cert`, `chained`, or `bypassed` with the reason), `stages[]` (`stage`, `status`, `seconds`, a few counts, `error`), `ok`, `error` (on failure), `allow_unsigned`, `lock_reclaimed` (when it happened). |
| `run.state.json` | The latest state: `last_started`, `last_finished`, `last_ok`, `last_error`, `consecutive_failures`, `sweep`, `next_due`, `pid`, `runs_this_process`. What a health check reads. |
| `sweep.lock` | Present only while a sweep runs. |

The stages read their settings from the environment, never the manifest:
`FREEAGENT_OWNER_RECIPIENT`, `FREEAGENT_VAULT_DIR`, `FREEAGENT_CA_ROOT`,
`FREEAGENT_NO_EXTERNAL=1` (built-in readers only), `EMBED_URL` / `EMBED_API`,
`PII_ADDR` / `PII_API_KEY` / `PII_RECALL` / `LLM_URL`, `SUMMARIZE_URL`, and
`SEAL_SIGN_KEY`.

## Running it as a service by hand

The bastion runs the agent itself. To run one without a bastion on Linux,
`bastion_agent/bastion-agent.service` is a systemd **user** unit: the sweep
runs under the owner's account with their permissions, reads its environment
from `~/.config/bastion-agent/env` (create it 0600, as the unit's header
shows), writes to `~/.local/share/bastion-agent/out`, and runs with
`UMask=0077`, `NoNewPrivileges` and `PrivateTmp`, restarting 60 s after a
failure. There is no launchd or Scheduled Task file yet; on a Mac or Windows
machine run the same command from either.

## Tests

`python3 -m unittest bastion_agent.test_run bastion_agent.test_x509gate`.
`test_run` covers the gate (sign then verify; re-signing replaces the block; an
edit after signing refused; a CN mismatch refused; a certificate with two CNs
refused; the CA chain accepted against the right root and refused against
another; unsigned refused unless `--allow-unsigned`, and then recorded), runs
(stages in order with counts logged; a failing stage stops the run and later
stages never execute; an invalid manifest recorded as an error; the lock
refusing a second holder and reclaiming a dead one; `next_due` arithmetic
including the backoff cap), and the loop with a fake clock (`manual` runs
once; `15m` runs three times, sleeping exactly two periods in naps of at most
30 s, with `next_due` right; hourly failures retry after 60 s then 120 s with
the counter at 3). `test_x509gate` runs the gate with openssl removed from
PATH, through the CLI with no openssl, and against bit flips, expiry and a
foreign CA with the same name.
