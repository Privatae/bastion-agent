# Contributing

Thank you for looking at the bastion agent. It runs on machines people own and
reads their files, so the bar is: nothing lands that lets personal data leave
the machine unsanitized, or lets the agent do more than its signed manifest
says.

## Before you open a pull request

From the repository root:

```sh
python3 -m unittest discover .                    # every test, including the 3.8 floor
python3 -m bastion_agent.build --out /tmp/agent   # the .pyz and its .sha256
python3 /tmp/agent/bastion-agent-*.pyz --version
bash -n bastion_agent/publish.sh pii/verify-live.sh && sh -n bastion_agent/install.sh
```

- **All tests pass.** They need PyYAML (the manifest loader uses it), at the
  version `build.py` pins (`PYYAML_VERSION`) for the build tests. The
  round-trip seal tests are skipped where `age` and `age-keygen` are not
  installed, so install them to run the whole suite.
- **The Python 3.8 floor.** `test_syntax_floor.py` parses every module in
  `bastion_agent/` and `pii/` at 3.8 and denies the newer standard-library
  calls that parse on 3.8 and then fail at run time. The agent ships to
  whatever the owner runs; keep it there.
- **The build reproduces.** `test_build` builds twice and requires identical
  bytes. Nothing that depends on the machine or the clock (a timestamp, an
  unsorted directory listing, bytecode, a different PyYAML) may reach the
  `.pyz`. Anyone checks a release by rebuilding it
  (`python3 -m bastion_agent.verify_release`), so a build that drifts breaks
  that check for everyone.
- **Standard library only** in both packages, apart from the vendored PyYAML
  and the optional `gliner` import. A new dependency is new attack surface in
  the process that holds the most sensitive data on the machine.

A change to a stage's output adds a test for it, and a change to what a stage
refuses adds a test that it refuses.

## What a change has to respect

- **Bytes never leave the machine.** The files, their extracted text and the
  vault stay local. What leaves is the sealed catalog, to the recipients the
  manifest names, and what `serve` returns to a certificate the manifest
  allows. There is no plaintext sink: `sink.plaintext` is `never` and has no
  other value.
- **Sanitize before anything is written for later stages.** Chunks, vectors,
  keywords, titles, summaries, the catalog and everything `serve` returns come
  from the sanitized store, never the extract store. A test that searches an
  output for the fixture's personal data should keep passing.
- **Fail closed.** A recall pass that fails stops the stage; a manifest that
  does not verify runs nothing and serves nothing; a model with the wrong
  dimension writes nothing. When in doubt, stop and say why in the run record.
- **No delete, no write.** The agent never changes, moves or deletes the files
  it reads, and rows in the vault and the vectors table are only ever added.
- **Addresses come from the environment, never the manifest.** A manifest names
  models and policy; where the model or the sterilizer runs is the machine's
  business.
- **Stable wire names stay.** Installed bastions write `freeagent: 1` into
  every manifest and set the `FREEAGENT_*` environment variables; renaming one
  breaks them. The `build/freeagent/` default output directory keeps its name
  so output a person already has is not orphaned.
- **The release keys match the bastion's.** `RELEASE_KEYS` in
  `bastion_agent/verify_release.py` is a copy of `productionReleaseKeys` in the
  bastion's `client-go/release_sign.go`. When the bastion's list changes,
  change this one the same way.

## Style

- Comments explain why, in plain words. State the invariant and the failure it
  prevents. No ticket numbers, no dates, no names of people or machines.
- Documentation describes the program as it is, including what it does not
  do. It carries no status lines, dates or plans, which go stale the day they
  land.
- One module per stage, with its own `test_<module>.py` and its own document
  under `docs/`.
- Error text a person reads says what was refused and what they can do about
  it.

## Reporting a problem

Bugs and feature requests: the issue tracker on the repository. Security
problems: see [SECURITY.md](SECURITY.md), and please do not file them
publicly.

## License

By contributing you agree that your contribution is licensed under the GNU
General Public License, version 3 or later, like the rest of the repository.
