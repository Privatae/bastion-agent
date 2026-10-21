# bastion agent `seal` stage: the catalog leaves, nothing else does

`seal` is the last stage of a run and the one way a dataset leaves the machine:
an allowlisted bundle of the catalog, encrypted with age to the owner and the
manifest's named recipients. It is `bastion_agent/seal.py`.

## What it does

`python3 -m bastion_agent seal <manifest> [--out DIR] [--require-signed]`
builds the bundle and encrypts it to the owner and the manifest's
`sink.seal_to` recipients:

```
<out>/sealed/<id>-<stamp>.tar.age      the envelope (0600)
<out>/sealed/<id>-<stamp>.tar.age.sig  optional detached signature
<out>/sealed/latest.json               pointer to the newest envelope
<out>/seal.summary.json                sizes, digests, recipients, members
```

`python3 -m bastion_agent unseal <file.tar.age> --identity <age key> --dest DIR`
is the owner's side: it decrypts, refuses unsafe paths, and checks every
member's SHA-256 against the inventory the sealer wrote inside the bundle.

## What is in the bundle, and what cannot be

| Member | Content |
|---|---|
| `manifest.json` | The manifest as executed (signature block removed). |
| `catalog.jsonl`, `catalog.dirs.jsonl` | The cards: sanitized text only. |
| `<stage>.summary.json` | The earlier stages' summaries: counts, digests, tool and model names. |
| `seal.manifest.json` | The inventory: sha256 and size per member, the manifest digest, the time of sealing. |

The bundle is built from an **allowlist**: the two catalog files
(`BUNDLE_ALLOW`), the stage summaries (names matching `<stage>.summary.json`),
and the two files the sealer writes itself. There is no code path that adds
the extract store, the sanitized store, the vault, `vectors.db`, or any other
`*.jsonl` index. A test opens the bundle and checks exactly that, and searches
it for the fixture's personal data. The tar is built with fixed member times
and a fixed order, so the same catalog sealed at the same moment is the same
plaintext.

## Recipients

- **Owner**: `FREEAGENT_OWNER_RECIPIENT`, an `age1…` public key, from the
  environment. Mandatory: no owner recipient, no seal. It is never in the
  manifest, because the manifest is written by the host and the owner's key is
  the machine's business.
- **`sink.seal_to`**: each entry is an `age1…` recipient or an `ssh-ed25519`
  or `ssh-rsa` public-key line (age accepts both). Any other string is refused
  before anything is written.
- Duplicates collapse; the owner is always first.
- **Grantees are not recipients.** A `grants` entry lets another host *query*
  this agent; it never receives the sealed catalog. Sharing is access, not a
  copy.

## Why age

age (X25519 and ChaCha20-Poly1305) is a small, widely reviewed format with a
single static binary for Mac, Windows and Linux. The envelope cannot be made
with the standard library (it has no X25519 and no ChaCha20-Poly1305), so,
unlike the extract stage's optional tools, **age is required here**: a catalog
that cannot be sealed does not leave, and the stage says so and exits 1.

## Signature (optional)

`SEAL_SIGN_KEY=<path to a PEM private key>` adds a detached
`openssl dgst -sha256` signature over the envelope, so a receiving host can
check who sealed it. The signature covers that one envelope (age encrypts
differently every time), not the plaintext. The stage only produces the
signature; checking it against a certificate is the receiver's job. A test
proves it verifies against the public half.

## Tests

`python3 -m unittest bastion_agent.test_seal` covers: no owner recipient,
refused with nothing written; malformed recipients refused and named; no `age`
on PATH, refused; `seal` not in the stages, refused; the bundle allowlist
(present members, forbidden members absent, no values, sanitized placeholders
present); reproducible plaintext; a round trip with two real recipients and a
stranger refused; owner and recipient de-duplication and an ECDSA P-256
signature that verifies with openssl; and a tampered member refused on unseal.
The round-trip tests are skipped where `age` or `age-keygen` is not installed.

## Where it sits

walk → extract → sanitize → chunk → embed → catalog → seal, each usable on its
own and each with its own document here. The runtime around them (the `sweep`
scheduler and the manifest gate) is [runtime.md](runtime.md); the query
endpoint is [serve.md](serve.md).
