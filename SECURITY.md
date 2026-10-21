# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Email **info@privatae.ai** with:

- the agent's version (`python3 bastion-agent-<version>.pyz --version`) and
  platform,
- what you found and how to reproduce it,
- what an attacker could do with it.

You will get an acknowledgement within three business days. We will keep you
informed as the report is confirmed and fixed, and credit you in the release
notes if you wish.

## What is in scope

This repository: the bastion agent and the `.pyz` it is built into. The agent
reads a person's files, so anything that lets it read, keep or give out more
than its signed manifest and the person's grant allow is in scope. For
example:

- **The walk** reading outside the manifest's roots (through a link, a
  junction, a path trick), or descending into an excluded directory.
- **The extractors** (including the built-in PDF and Office readers) being
  made to exhaust memory or time past their limits, to run a program other
  than the named tools, or to write outside the output directory.
- **The sanitizer** (`pii/`) writing personal data it found into the sanitized
  store, an index or a summary; a recall failure that does not stop the stage;
  a value reachable from a token without the local vault; the vault readable
  by another user.
- **The embedder and the summarizer** sending text that has not been sanitized
  to a model.
- **The catalog and the sealed bundle** carrying a value, the extract store,
  the vault or the vectors; a bundle readable by anyone but the owner and the
  manifest's recipients.
- **`serve`** answering a client whose certificate does not chain to the
  configured root, giving a grantee more than its grant or anything after its
  expiry, returning plaintext instead of sanitized text, or continuing to serve
  after the manifest stops verifying.
- **The manifest gate** accepting an unsigned, edited or foreign manifest, or a
  certificate that does not chain to the configured root.
- **The artifact**: a `.pyz` that is not what this source builds, or a
  weakness in `verify_release.py` that makes a mismatched build or a bad
  signature pass.

## What is out of scope

- **The bastion**, which installs, updates and supervises the agent, signs its
  manifest and holds its keys. It is a separate program with its own policy:
  [privatae-bastion's SECURITY.md](https://git.privatae.ai/privatae/privatae-bastion/src/branch/main/SECURITY.md).
  Report there, or to the same address.
- **The Privatae platform** the bastion connects to. It is separate software
  with its own reporting path; reports about it sent to the address above are
  forwarded.
- **What the design already says it does not do.** The rules-only `flag` mode
  does not find names, and the recall pass is probabilistic
  ([docs/pii-sterilization.md](docs/pii-sterilization.md#limits)); the extract
  store in the output folder is plaintext by design
  ([docs/runtime.md](docs/runtime.md#where-an-agent-lives-rootagent)); the
  vault is not encrypted at rest. A report that shows one of these is worse
  than documented is in scope.
- **Findings that need the owner's account already.** The agent runs as the
  person whose folder it reads; someone who can act as that person can read
  the folder without it.

## Supported versions

Only the current release receives fixes: the version
<https://privatae.ai/bastion-agent/version.json> names. While a folder is
shared, the bastion checks that signed manifest every ten minutes and installs
any newer version, so a fixed release reaches every machine running the agent
without anyone installing it. `bastion_agent/VERSION` on `main` may be ahead
of the published version; see [CHANGELOG.md](CHANGELOG.md).

## Checking what you run

Every release manifest is signed with the bastion's release key (the bastion's
SECURITY.md says how that key is held and what trusting it means), and the
build is reproducible. `python3 -m bastion_agent.verify_release` checks the
signature against the pinned keys, rebuilds the published version from this
source, and compares the bytes; see the README.
