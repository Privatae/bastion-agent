# Changelog

All notable changes to the bastion agent.

The version in `bastion_agent/VERSION` on `main` is the next release, not
necessarily the one machines run. A merged change waits there until it is
published. The published version is whatever
<https://privatae.ai/bastion-agent/version.json> names at the moment, and it
is the only version a bastion installs. When a second release is merged before
the first is published, only the later one is published, and it carries the
changes of both. This file does not record which versions were published.

Changes to the release tooling (`publish.sh`, `build.py`, `verify_release.py`)
and to the documentation are listed under the version whose source first
carried them, although they do not change what the `.pyz` does.

## 0.1.15

- **No change to what the agent does.** The README says how this repository
  is published (one tagged snapshot per release, the same on GitHub) and that
  issues and pull requests are welcome on GitHub, and it links the bastion's
  SECURITY.md on GitHub.

## 0.1.14

- **Rollout order: upgrade any running PII service before publishing this
  agent.** The sanitize stage now asks the service to escape every
  placeholder-shaped string in a document and stops, fail closed, when the
  service does not confirm it (`stats.escape_held_literals`). An older service
  does not, so a `sterilize` manifest pointed at one stops at its first file.
- **Anyone can check a release.** `python3 -m bastion_agent.verify_release`
  fetches the published manifest and its signature, checks the ed25519
  signature against the release keys the bastion pins, checks out the tag
  `v<version>` (or the manifest's `built_from` commit where it exists),
  rebuilds the `.pyz` with that version's `build.py`, and compares its sha256
  with every `.pyz` the manifest lists. It needs Python, git and PyYAML at the
  pinned version, nothing else; the signature check is ed25519 in pure Python,
  tested against RFC 8032's vectors and the vector the bastion's signing tool
  and the bastion share. `build.py` leaves it out of the `.pyz`.
- `SECURITY.md` (how to report a problem in the agent, and what is in scope),
  `CONTRIBUTING.md` (the checks a change must pass and the rules it must keep)
  and this changelog.
- The documents under `docs/` describe the program as it is. Test commands are
  the real ones (`python3 -m unittest …`), and the status lines, dates, live
  measurements from the development machine and lists of work that is now
  done are gone. Descriptions that no longer matched the code are corrected,
  among them: the built-in PDF reader, the Office limits, the default output
  directory of each command, the `/catalog` paging and `--port-file` of
  `serve`, which environment variables the PII service reads, and when a chunk
  keeps its vector.
- Comments and help text follow the same rule: the `--out` help names the real
  default, and no comment names a machine, a model deployment or a file that is
  not in this repository. No change in behaviour.
- `pii/verify-live.sh` takes the service's address as an argument (default
  `127.0.0.1:8091`, where `pii.service` binds) and the key from
  `PII_API_KEY`, instead of reading a file outside this repository.
- `sweep` without `--out` now uses `<root>/.agent`, the same folder as
  `serve`.
- PII: overlapping matches, including a value that overlaps itself, become one
  placeholder; no match may split an existing placeholder; placeholder-looking
  text in a document always survives a round trip (through the service, only
  text the vault does not hold; `escape_held_literals: true` asks for all of
  it), and a chunk is never cut inside a placeholder; a phone number, IPv4 or
  MAC address at the end of a sentence is now detected, and one followed by
  `.txt`-style text is not.
- The `residual_tokenized` and `verify_tokenized` stats count what was actually
  replaced. There is a new stat, `literal_tokens_escaped`, and `/sterilize`
  echoes `stats.escape_held_literals`.
- The sanitize stage re-sanitizes every file once after this upgrade
  (`SANITIZE_VERSION` 2): output written by older code is not reused.
- The legacy address `privatae.ai/freeagent/` is retired, so this release is
  published under the new file name only (`publish.sh` finds the route gone
  on every edge and the public 404 by itself). A bastion older than 0.20.0
  keeps the agent it has.

## 0.1.13

- No change in what the agent does. The README describes it as it is: the
  stages and their order, how the bastion runs the agent, what `serve`
  returns, verifying a release, and reporting a security problem.
- **Release manifests are signed.** 0.1.13 is the first release published
  with a signature; none is served for the 0.1.12 manifest. `publish.sh`
  builds the release, prints the command for the key holder to sign it on
  their own computer (the release key never comes to the publishing machine),
  and publishes only once the signature verifies against the keys the bastion
  pins, both in the release being prepared and in the one machines run now. The signature is published
  beside the manifest as `version.json.<first 16 hex of its sha256>.sig`, and
  old signature files are never removed.
- **The build is reproducible on any machine.** `build.py` vendors PyYAML only
  at the pinned version (`PYYAML_VERSION`) and refuses any other, so two
  machines build the same bytes from the same source.
- `publish.sh` writes the legacy `freeagent-<version>.pyz` file name only while
  some edge still serves the legacy `/freeagent/` address, judged per edge from
  the configuration its web server has loaded; `docs/packaging.md` has the
  steps to retire that address.

## 0.1.12

- No change in behaviour: comments no longer carry ticket numbers or name
  machines, so the source can be published as it is.

## 0.1.11

- **The manifest gate needs no openssl.** Reading the certificate, checking
  its chain to `FREEAGENT_CA_ROOT` and verifying the ECDSA P-256 signature are
  done in the standard library (`x509gate.py`), with strict DER parsing, so the
  agent runs on machines without openssl, Windows included. `sign --value`
  records a signature made elsewhere (the bastion signs with its own key);
  `sign --key` still uses openssl. `doctor` no longer lists openssl as
  required.
- **The built-in PDF reader reads real PDFs** (`pdftext.py`): object streams,
  compressed streams, the page tree, fonts' `/ToUnicode` maps (so
  browser-printed PDFs read), simple font encodings, glyph widths for spacing,
  and form XObjects. Without poppler it used to find text only in old PDFs. It
  reads on a budget per document (time, decoded bytes, operators, tokens,
  CMap entries) and never raises; encrypted files are refused. Cached PDF
  verdicts are redone (`EXTRACT_VERSION` 2).
- **Office files are read on a budget.** DOCX, XLSX, PPTX and OpenDocument
  files are parsed as a stream, each finished paragraph or row dropped once
  read, with caps on XML size, text size, time and parts per paragraph or row;
  reaching a cap keeps the text read so far and says so. A DTD is refused, and
  UTF-16 documents are read.

## 0.1.10

- Licensed under the GNU General Public License, version 3 or later, in place
  of PolyForm Internal Use. The `LICENSE` file is also inside the `.pyz`.

## 0.1.9

- No change to the agent. Test fixtures use generic addresses, and
  `publish.sh` takes its backup directory from the environment and refuses one
  inside the web root.

## 0.1.8

- Licensed under PolyForm Internal Use 1.0.0 in place of PolyForm
  Noncommercial 1.0.0, which had forbidden running the agent for work.
- `publish.sh` names no publishing target of its own: the edges, key and web
  root come from its environment, and it stops when one is missing. Documents
  no longer cite files outside the repository, and test fixtures use invented
  people. No change in behaviour.

## 0.1.7

- **The program is named the bastion agent.** The package is `bastion_agent`,
  the artifact `bastion-agent-<version>.pyz`, the command `bastion-agent`, and
  the address `privatae.ai/bastion-agent/`. The manifest's `freeagent: 1`
  field, the `FREEAGENT_*` environment variables, the `freeagent` stamp in
  output records and the `build/freeagent/` output directory keep the old
  word: bastions write and set them, and output already on disk uses them.
  Every publish lists the artifact under both file names, with the same bytes.
- The agent and the PII sterilizer became a repository of their own, licensed
  under PolyForm Noncommercial 1.0.0.

## 0.1.6

- `serve`'s `/catalog` and `/catalog/dirs` are paged: `prefix`, `offset` and
  `limit`, answered with `total` and `next_offset`.

## 0.1.5

- `serve` answers `/catalog/dirs`: the directory cards, the map a host plans
  from.

## 0.1.4

- `.agent` is excluded in any letter case on every OS (a case-insensitive Mac
  volume has only one `.Agent`).
- The documents say plainly that the extract store in `.agent` is the plaintext
  of every file in scope, and that a folder should be served from one machine.

## 0.1.3

- **An agent lives with its folder.** For a manifest with one root, the output
  directory defaults to `<root>/.agent`, and the walk always excludes `.agent`.
- `FREEAGENT_VAULT_DIR` keeps the PII vault out of the folder, which may be
  synced elsewhere.

## 0.1.2

- `serve --port-file` writes the port it bound, so a supervisor can bind port
  0 and learn it.
- `publish.sh`: the agent is published at `privatae.ai/freeagent/`.

## 0.1.1

- Each TLS handshake in `serve` runs in its connection's own thread with a
  timeout, and an idle connection is closed after 60 s, so a client that says
  nothing cannot hold up the others.
- The manifest gate requires `FREEAGENT_CA_ROOT` and a signing certificate
  with exactly one CN, and a refused manifest is recorded in the run log.
- Every segment of a path is masked in the catalog, not only the file name.
- The sweep lock is never taken from a live process; `chunk` and `catalog`
  require the `sanitize` stage; a malformed CSV is an error record instead of a
  crash.

## 0.1.0

The first version with a number: the whole pipeline in one file.

- The job manifest, its loader and validator.
- The stages: `walk`, `extract`, `sanitize` (the PII sterilizer, in process or
  as a service, with rules, a recall model and a local vault), `chunk`,
  `embed` (a local model, vectors in SQLite) and `search`, `catalog`, and
  `seal` (an age envelope to the owner and named recipients).
- `sweep`, the scheduler with the manifest signature gate and a lock, and a
  systemd user unit.
- `serve`, the mutual-TLS query endpoint, with grants read from the signed
  manifest on each request.
- Packaging: a reproducible single-file zipapp, the `doctor` preflight, and
  installers for sh and PowerShell.
