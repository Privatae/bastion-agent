# bastion agent packaging: one file for three operating systems

## The artifact

`python3 -m bastion_agent.build --out dist` → `dist/bastion-agent-<version>.pyz`
and `.sha256`.

A **zipapp**, the standard library's own single-file format: one file of about
150 KB that runs on any Python 3.8 or later on Mac, Windows or Linux:

```
python3 bastion-agent-<version>.pyz doctor
python3 bastion-agent-<version>.pyz sweep manifest.yaml --once
python3 bastion-agent-<version>.pyz serve manifest.yaml
```

Inside: the `bastion_agent` package (every stage, the scheduler, the
endpoint; no tests, and neither `build.py` nor `verify_release.py`, which are
tools for making and checking a release), the `pii` package (the sterilizer; no
tests, no Dockerfile), a vendored **pure-Python PyYAML** (MIT, its notice
included; the C accelerator is left out so one file runs everywhere), which is
the one import the manifest loader needs beyond the standard library, and the
repository's `LICENSE`, so the license travels with the program. The version
comes from `bastion_agent/VERSION`, read with `pkgutil` so it works from inside
the zip.

`bastion_agent/VERSION` on `main` is the next release, not necessarily the one
bastions run. A merged change waits there until it is published, and the
published version is whatever <https://privatae.ai/bastion-agent/version.json>
names at the moment: a bastion installs that version and no other. Between a
merge and a publish, `main` is ahead of the manifest; when a second release is
merged before the first is published, only the later one is published.

**Reproducible.** Fixed member timestamps, sorted members, no bytecode, and
the vendored PyYAML pinned to one release (`PYYAML_VERSION`; the build refuses
any other): two builds of the same tree are byte-identical on any machine, so
the `.sha256` is a real statement about the file, and anyone can rebuild a
release and compare (`python3 -m bastion_agent.verify_release`, in the README).
`test_build` asserts identical bytes across two builds.

`age` stays what it is, a single external binary, because the standard library
cannot do X25519 or ChaCha20. The manifest gate does **not** need `openssl`: it
reads the certificate and verifies the ECDSA P-256 signature in the standard
library (`x509gate.py`), so the agent runs on a machine without it (Windows
ships none). `openssl` is needed only to sign with `sign --key` and for
`SEAL_SIGN_KEY` seal signatures. `doctor` reports both.

## doctor

`bastion-agent doctor [--json]` is the preflight; it changes nothing:

| Check | Used by | Required? |
|---|---|---|
| Python ≥ 3.8, PyYAML | everything | yes |
| `age` | seal | yes |
| `openssl` | `sign --key`, seal signatures | no: the gate verifies in the standard library |
| `pdftotext`, `tesseract` | extract | no: without them the gaps are recorded |
| `gliner` package | sanitize | no: the laptop recall backend |
| `EMBED_URL` (default `http://127.0.0.1:11434`), and `PII_ADDR` / `SUMMARIZE_URL` when set | embed / sanitize / catalog | no: reachable? Any HTTP answer counts, so a proxy that allows only the embedding path (and answers 403 on `/`) is reachable |
| `FREEAGENT_OWNER_RECIPIENT` set; `FREEAGENT_CA_ROOT`, `FREEAGENT_TLS_CERT`, `FREEAGENT_TLS_KEY` set and the files present | seal / sweep / serve | no, for the preflight: the stages that need them refuse without them |

The exit code is 1 only when a required item is missing; optional gaps are
printed as `opt`.

## Installers (a hand install)

The bastion installs the agent itself from a grant; these are for running it
by hand.

- `install.sh <pyz>`: Linux and macOS, POSIX sh, no root, no downloads. It
  checks for `python3` 3.8 or later, verifies the `.sha256` when it sits next
  to the `.pyz` (`sha256sum` or `shasum`), copies to
  `~/.local/bin/bastion-agent.pyz`, writes a `bastion-agent` wrapper (and
  repoints an existing `freeagent` wrapper, so an earlier hand install keeps
  working), runs `doctor`, and prints the next step. `BASTION_AGENT_BIN_DIR`,
  or else `FREEAGENT_BIN_DIR`, overrides the directory.
- `install.ps1 <pyz>`: Windows PowerShell, no administrator. The same checks
  with `Get-FileHash`; installs to `%LOCALAPPDATA%\bastion-agent`, writes
  `bastion-agent.cmd`, adds the directory to the user's PATH, and runs
  `--version` and `doctor`.

Neither installer fetches anything. Get the `.pyz` and its `.sha256` from the
download address, then run one command (Linux or macOS):

```
V=<version from https://privatae.ai/bastion-agent/version.json>
curl -fsSLO https://privatae.ai/bastion-agent/dl/bastion-agent-$V.pyz && \
curl -fsSLO https://privatae.ai/bastion-agent/dl/bastion-agent-$V.pyz.sha256 && \
curl -fsSL https://privatae.ai/bastion-agent/install.sh | sh -s -- bastion-agent-$V.pyz
```

## The download address

`bastion_agent/publish.sh` publishes to every edge server named in its
environment, each serving from its own disk, at `/bastion-agent/*`, with
backups and dotfiles refused. The legacy `/freeagent/*` path is retired (see
"The legacy name" below):

```
https://privatae.ai/bastion-agent/version.json          version, built_from, python_floor, files (url, sha256, bytes), installers, notes
https://privatae.ai/bastion-agent/version.json.<h>.sig  ed25519 signature; <h> = first 16 hex of version.json's sha256
https://privatae.ai/bastion-agent/dl/bastion-agent-<v>.pyz  the artifact
https://privatae.ai/bastion-agent/dl/bastion-agent-<v>.pyz.sha256
https://privatae.ai/bastion-agent/install.sh            and install.ps1
```

The manifest is signed with the bastion's release key, which stays on the key
holder's own computer. A publish therefore runs twice: the first run builds
and prints the `release-sign sign bastion-agent <version> <sha256>` command to
run there, and the second, with `SIGNATURE=<the line it printed>` and
`BASTION_TREE` pointing at a privatae-bastion checkout, checks the signature
against the keys that checkout pins and the keys the published bastion pins,
and only then publishes. What is signed is a short statement naming the kind
of release, its version and the manifest's sha256. A bastion from 0.42.0 on
fetches `version.json.<h>.sig`, refuses a manifest that does not verify, and
never replaces an installed agent with an older version.

The script builds reproducibly, runs the built `.pyz` once (`--version`),
refuses to publish a version that is not newer than the one already served
(`ALLOW_REPUBLISH=1` overrides it deliberately), uploads to every edge, then
checks each edge's bytes against the manifest it serves. Where it publishes
is not written into the script: the edges, the ssh key, the web root and the
backup directory come from its environment, and it stops if one is missing.

The manifest's `notes` link to the GitHub release of the tag `v<version>`,
which marks the source of that release and carries its files. `publish.sh`
does not make the tag; it is made when that release's source is published to
the public repository, and pushing it starts `.github/workflows/release.yml`,
which rebuilds the `.pyz` from the tag and attaches it, with its `.sha256`, the
signed manifest and its signature, once its sha256 matches the manifest.

### The legacy name

The agent was first published as freeagent, at `privatae.ai/freeagent/`, and
a bastion older than 0.20.0 knows only that address and the
`freeagent-<v>.pyz` file name. Bastions from 0.20.0 read the new address first
and fall back to the legacy one; from 0.42.0 they read only the new one.

The legacy address is retired: no edge has the `/freeagent/*` route, and
`https://privatae.ai/freeagent/version.json` answers 404. A bastion that
cannot fetch the manifest keeps the agent it has installed, so a bastion older
than 0.20.0 keeps the agent it has and gets no newer one. What would strand a
machine is the other case, a legacy manifest that answers but does not list
the legacy file name, and a retired address cannot produce it.

`publish.sh` still checks on every run, on every edge (the route in the Caddy
configuration each edge has loaded) and at the public address. With no route
anywhere and a 404 in public it prints, per edge, "no /freeagent route" and
publishes the new file name only. It publishes both names again, the same
bytes under each, if any edge still has the route, if any edge cannot be
asked (ssh fails or times out, or the configuration Caddy has loaded cannot
be read), or if the public address answers anything but 404 (no answer
included), so that address could not serve a manifest without the name an
old bastion asks for.

The names inside the agent that keep the word freeagent (the `FREEAGENT_*`
environment variables and the manifest's `freeagent: 1` field) are stable
names, not part of this retirement: the bastion sets and writes them, so
renaming one would have to change the bastion and the agent in step, for no
change in behaviour.

## What this is not

A native binary. PyInstaller or Nuitka make one per OS, but each has to be
built on that OS, and none is produced; it would be built from the same
`members()` list. Until then the `.pyz` and a system Python are the artifact.
Python 3.8 or later is on every Linux and current Mac (with the Xcode command
line tools or Homebrew) and one Store install away on Windows, and the floor
test keeps the code there.

## Tests

`python3 -m unittest bastion_agent.test_build` covers byte-identical builds;
the contents (the entry point, both packages, VERSION, the vendored YAML and
its notice; no tests, no `.so` or `.pyc`, no `build.py`, `verify_release.py`
or Dockerfile; every member at the fixed time; under 1 MB); the `.pyz`
answering `--version` and `doctor --json` and validating the example manifest;
**a full sweep from the `.pyz` in a scratch directory with `PYTHONPATH=""`**
(nothing from the repository on the path) producing a catalog with sanitized
heads; the `.agent` default output directory; and the doctor's checks against
unreachable and missing inputs.

Every push to `main` and every pull request into it runs CI
(`.gitea/workflows/ci.yml`, `.github/workflows/ci.yml`): the 3.8 floor,
pyflakes, every test on Python 3.8 and a current Python, a personal-data scan
and a reproducibility check. [CONTRIBUTING.md](../CONTRIBUTING.md) lists the
checks to run before proposing a change, and `publish.sh` builds the release
and runs it before anything is uploaded. The installers are not exercised by
the test suite.
