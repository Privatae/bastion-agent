# bastion agent

[![ci](https://github.com/Privatae/bastion-agent/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Privatae/bastion-agent/actions/workflows/ci.yml)

The small program the bastion runs on your own machine, for one folder.

It is deployed **from a grant**, and you do not install it yourself: the bastion fetches
`privatae.ai/bastion-agent/version.json`, checks its ed25519 release signature
(`version.json.<first 16 hex of its sha256>.sig`) against the keys compiled into the bastion, downloads the `.pyz`
and checks it against the sha256 in that signed manifest,
mints a P-256 identity per store, writes and signs a manifest from the grant you
approved, and supervises `sweep` and `serve`. Your files stay on the machine;
what crosses the tunnel is what the grant's mask allows: catalog cards, and
the sanitized excerpts that `search` and `read_range` return, each reply naming
the sanitize mode that made it (`sanitize_mode`, [serve.md](docs/serve.md)).

The published version is whatever `privatae.ai/bastion-agent/version.json`
names. `bastion_agent/VERSION` on `main` is the next release, which may not be
published yet. Release manifests are published signed from 0.1.13 on, and the
`.pyz` can be rebuilt from this source and compared
([Verify a release](#verify-a-release)).

This repository is free software, licensed under the GNU General Public License version 3 or (at your option) any later version (see `LICENSE`). Copyright Privatae LLC. You may run it, read it, change it and redistribute it under that license. The Host the bastion connects to is separate software and is not covered by this license: a C-Series Host is [Privatae/cseries](https://github.com/Privatae/cseries), under AGPL-3.0-only, and a Host on Privatae's own platform is proprietary software. A member runs their own build on their own machine — nothing here depends on a Privatae-held credential or a Privatae-side build.

## What it does

For one shared folder, on the manifest's cadence, the agent runs the stages its
manifest names, always in this order and starting with `walk`; the first
failure stops the run:

| stage | what it does | doc |
|---|---|---|
| walk | the map of the folder: files, sizes, types, what the grant excludes | [walk.md](docs/walk.md) |
| extract | text out of each file, with built-in extractors or local tools | [extract.md](docs/extract.md) |
| sanitize | replaces the personal data its mode finds with tokens; the originals stay in a vault on this machine. In the mode the bastion deploys it does not find names, street addresses or dates of birth ([below](#how-the-bastion-runs-it)) | [sanitize.md](docs/sanitize.md), [pii-sterilization.md](docs/pii-sterilization.md) |
| chunk, embed | splits the text and embeds it with a model on this machine | [embed.md](docs/embed.md) |
| catalog | the curated dataset built from the stages above | [catalog.md](docs/catalog.md) |
| seal | packs an allowlisted bundle of the catalog and encrypts it with age to the owner and the manifest's named recipients; the one way a dataset leaves the machine | [seal.md](docs/seal.md) |

`serve` answers queries over the index with mutual TLS, returning chunks and
catalog cards from the sanitized text ([serve.md](docs/serve.md)). The gate refuses an
unsigned, edited or foreign manifest, and the bastion never starts the agent
without a valid one. (`--allow-unsigned` exists for development only; the
bastion never passes it.) See [runtime.md](docs/runtime.md) and
[manifest.md](docs/manifest.md).

## How the bastion runs it

The bastion installs and runs the agent itself from a folder grant you
approved; you do not install it by hand. (The `.pyz` can also be installed and
run by hand, to try it outside the bastion: [packaging.md](docs/packaging.md).)
For each shared folder the bastion:

- downloads the `.pyz` only through the signed manifest, and never replaces an
  installed agent with an older version;
- mints the agent its own identity and writes and signs its manifest from the
  grant, so the agent works only on what you granted;
- sets the sanitize stage to `flag` mode: rules only, no model. It replaces
  e-mail addresses, phone numbers, card, bank and social security numbers, IP
  and MAC addresses and keys. **It does not find names, street addresses or
  dates of birth**, so text a Host receives from the agent still contains them.
  `sterilize` mode adds a model on this machine that looks for those, and the
  bastion does not set it ([sanitize.md](docs/sanitize.md#modes-manifest-sanitizemode));
- points the embed stage at the model server on this machine (a local ollama)
  and at nothing else;
- runs `serve` on the loopback address only, with mutual TLS, so the bastion is
  the only client;
- keeps the personal-data vault in the bastion's own state directory rather
  than in the folder, which may be synced elsewhere;
- on a machine where the bastion runs as root, runs the agent as the folder's
  owner, never as root.

The agent updates without asking: while a folder is shared, the bastion checks
the agent's signed manifest every ten minutes and installs any newer version.
The bastion's [SECURITY.md](https://github.com/Privatae/bastion/blob/main/SECURITY.md)
says what that means for what you trust.

## Layout

| path | what it is |
|---|---|
| `bastion_agent/` | the agent: walk, extract, sanitize, embed, catalog, seal, manifest, serve; plus `build.py` and `verify_release.py`, which make and check a release and are not part of the `.pyz` |
| `pii/` | the sterilizer the agent runs **in-process** — its rules, vault and recall backends |
| `docs/` | one document per module, plus `pii-sterilization.md` |
| `test_syntax_floor.py` | the Python 3.8 floor gate for both packages |

`bastion_agent/` and `pii/` are siblings on purpose: `sanitize.py` and `catalog.py`
import `pii`, and `bastion_agent/build.py` bundles it into the `.pyz` as a top-level
package, which is what the built artifact has always looked like inside.

## Build and test

```sh
pip install pyyaml==6.0.3                # the PyYAML build.py vendors; the manifest loader imports it
python3 -m unittest discover .          # every module's tests, plus the 3.8 floor
python3 -m bastion_agent.build --out dist   # produces dist/bastion-agent-<ver>.pyz + .sha256
python3 dist/bastion-agent-<ver>.pyz --version
```

A test that needs `age`, `openssl` or `git` is skipped where that tool is not
installed. Every push runs the same checks in CI (`.gitea/workflows/ci.yml` on
git.privatae.ai, `.github/workflows/ci.yml` on GitHub), with the tools
installed, so there no test is skipped, plus `pyflakes`.

The build is reproducible: the same commit gives the same bytes on any machine
with PyYAML at the pinned version (`PYYAML_VERSION` in `build.py`).

The floor matters: this ships to whatever the owner runs, and a Mac or Windows
box may lag years behind Debian stable. `test_syntax_floor.py` parses both
packages at 3.8 and denies stdlib calls that parse on 3.8 and then fail at
runtime.

## Verify a release

```sh
python3 -m bastion_agent.verify_release
```

Run it from a clone of this repository. It needs Python 3.8 or later, git,
network access, and PyYAML at the version `build.py` pins (the build vendors
it); no key or account of ours. It:

1. fetches `privatae.ai/bastion-agent/version.json` and the signature beside it
   (`version.json.<first 16 hex of its sha256>.sig`), and checks the ed25519
   signature against the release keys the bastion pins, the same check a
   bastion makes before it installs an agent. The public keys are in
   `bastion_agent/verify_release.py`, copied from `client-go/release_sign.go`
   in the bastion's repository;
2. checks out the source of that version in a separate worktree: the tag
   `v<version>`, which must be annotated with the line
   `built from <built_from>`, or else the commit the manifest names as
   `built_from` if the clone has it;
3. rebuilds the `.pyz` with that version's own `build.py`, and compares its
   sha256 with every `.pyz` the manifest lists.

A match means the file every bastion downloads is exactly what this source
produces, and the signature means the release key holder published it. The
exit code is 0 only when both hold.

From 0.1.16 on, each GitHub release carries the `.pyz`, its `.sha256`, the
signed manifest `version.json` and its signature `version.json.<h>.sig`. The
release workflow (`.github/workflows/release.yml`) attaches them when the tag
is pushed, after running this same check against the published manifest and
rebuilding the `.pyz` from the tag; it attaches nothing if a digest differs.
To check downloaded files yourself, `sha256sum -c bastion-agent-<ver>.pyz.sha256`
checks the `.pyz` against its `.sha256`, the manifest lists the sha256 of both,
and `check_signature` in `bastion_agent/verify_release.py` checks the manifest
against the pinned release keys:

```sh
python3 -c 'import sys; from bastion_agent import verify_release as v; print(v.check_signature(open(sys.argv[1], "rb").read(), open(sys.argv[2]).read())[0]["files"])' version.json version.json.*.sig
```

The public repository does not carry the development history, so
`built_from` names a commit that exists only in the development repository.
Each published release from 0.1.14 on carries the tag `v<version>`, which
marks the source the release was built from. Earlier releases have no tag
here, and can be checked from `built_from` only where that commit is
available. A manifest from before signing has no
signature file beside it, and the check refuses it.

## How this repo is published

Development happens in a private repository, and its history is not
published. When a release is published, each change merged since the last one
arrives on GitHub, at
[github.com/Privatae/bastion-agent](https://github.com/Privatae/bastion-agent),
as a commit with the same files, titled as the change was and dated when it
was merged; the copy at git.privatae.ai receives the release as one commit.
In both, the release is tagged `v<version>` on a commit whose tree is the
source the signed manifest says the release was built from.
Every published `.pyz` can be rebuilt from its tag and compared
([Verify a release](#verify-a-release)).

Issues and pull requests are welcome on GitHub. An accepted change is carried
into the development repository and arrives here with the next release.

## Security and contributing

Please do not open a public issue for a security problem: see
[SECURITY.md](SECURITY.md) for how to report one and what is in scope.
[CONTRIBUTING.md](CONTRIBUTING.md) lists the checks a change must pass and the
rules it must keep. [CHANGELOG.md](CHANGELOG.md) says what changed in each
version.

## Where this came from

The two packages were extracted from a larger repository they started in. The
bastion itself is a separate program in its own repository, and stays that way:
two programs, both open, kept separate on purpose.

## The name

The program is the **bastion agent**; this repository is named for it. It
was first called freeagent. The package (`bastion_agent`), the artifact
(`bastion-agent-<v>.pyz`) and the published address
(`privatae.ai/bastion-agent/`) carry the new name. The legacy address
`privatae.ai/freeagent/` is retired and answers 404; a bastion older than
0.20.0, which knows only that address, keeps the agent it has
([docs/packaging.md](docs/packaging.md#the-legacy-name)). The environment
variables (`FREEAGENT_*`), the manifest's `freeagent: 1` field and the
bastion's heartbeat fields keep the old word as stable names: the bastion
sets and writes them, so renaming one would have to change the bastion and
the agent in step, for no change in behaviour.
