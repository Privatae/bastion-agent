# bastion agent

[![ci](https://git.privatae.ai/privatae/bastion-agent/actions/workflows/ci.yml/badge.svg?branch=main)](https://git.privatae.ai/privatae/bastion-agent/actions)

The small program the bastion runs on your own machine, for one folder.

It is deployed **from a grant, never installed by a person**: the bastion fetches
`privatae.ai/bastion-agent/version.json`, checks its ed25519 release signature
(`version.json.<first 16 hex of its sha256>.sig`) against the keys compiled into the bastion, downloads the `.pyz`
and checks it against the sha256 in that signed manifest,
mints a P-256 identity per store, writes and signs a manifest from the grant you
approved, and supervises `sweep` and `serve`. Your files never leave the machine;
what crosses the tunnel is the index and what the grant's mask allows.

The published version is whatever `privatae.ai/bastion-agent/version.json`
names. `bastion_agent/VERSION` on `main` is the next release, which may not be
published yet. Release manifests are published signed from 0.1.13 on, and the
`.pyz` can be rebuilt from this source and compared
([Verify a release](#verify-a-release)).

This repository is free software, licensed under the GNU General Public License version 3 or (at your option) any later version (see `LICENSE`). Copyright Privatae LLC. You may run it, read it, change it and redistribute it under that license. The Privatae platform the bastion connects to is separate, proprietary software and is not covered by this license. A member runs their own build on their own machine — nothing here depends on a Privatae-held credential or a Privatae-side build.

## What it does

For one shared folder, on the manifest's cadence, the agent runs the stages its
manifest names, always in this order and starting with `walk`; the first
failure stops the run:

| stage | what it does | doc |
|---|---|---|
| walk | the map of the folder: files, sizes, types, what the grant excludes | [walk.md](docs/walk.md) |
| extract | text out of each file, with built-in extractors or local tools | [extract.md](docs/extract.md) |
| sanitize | finds personal data and replaces it with tokens; the originals stay in a vault on this machine | [sanitize.md](docs/sanitize.md), [pii-sterilization.md](docs/pii-sterilization.md) |
| chunk, embed | splits the text and embeds it with a model on this machine | [embed.md](docs/embed.md) |
| catalog | the curated dataset built from the stages above | [catalog.md](docs/catalog.md) |
| seal | packs an allowlisted bundle of the catalog and encrypts it with age to the owner and the manifest's named recipients; the one way a dataset leaves the machine | [seal.md](docs/seal.md) |

`serve` answers queries over the index with mutual TLS, returning sanitized
chunks and catalog cards ([serve.md](docs/serve.md)). The gate refuses an
unsigned, edited or foreign manifest, and the bastion never starts the agent
without a valid one. (`--allow-unsigned` exists for development only; the
bastion never passes it.) See [runtime.md](docs/runtime.md) and
[manifest.md](docs/manifest.md).

## How the bastion runs it

The bastion installs and runs the agent itself from a folder grant you
approved; nobody installs it by hand. For each shared folder the bastion:

- downloads the `.pyz` only through the signed manifest, and never replaces an
  installed agent with an older version;
- mints the agent its own identity and writes and signs its manifest from the
  grant, so the agent works only on what you granted;
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
python3 -m unittest discover .          # every module's tests, plus the 3.8 floor
python3 -m bastion_agent.build --out dist   # produces dist/bastion-agent-<ver>.pyz + .sha256
python3 dist/bastion-agent-<ver>.pyz --version
```

Every push runs the same checks in CI (`.gitea/workflows/ci.yml`).

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
   `v<version>`, or else the commit the manifest names as `built_from` if the
   clone has it;
3. rebuilds the `.pyz` with that version's own `build.py`, and compares its
   sha256 with every `.pyz` the manifest lists.

A match means the file every bastion downloads is exactly what this source
produces, and the signature means the release key holder published it. The
exit code is 0 only when both hold.

The public repository is a copy of each release's source, not the development
history, so `built_from` names a commit that exists only in the development
repository. From this release on, each public snapshot carries the tag
`v<version>`, which marks the source the release was built from. A snapshot
published before that has no tag, and can be checked from `built_from` only
where that commit is available. A manifest from before signing has no
signature file beside it, and the check refuses it.

## How this repo is published

Development happens in a private repository. This repository receives the
source of each published release as one snapshot commit, tagged
`v<version>`, whose tree is the source the signed manifest says the release
was built from; that is why its history is short. The same snapshot is on
GitHub at [github.com/Privatae/bastion-agent](https://github.com/Privatae/bastion-agent).
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
