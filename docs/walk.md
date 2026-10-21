# bastion agent `walk` stage: the filesystem and metadata map

The walk is the first stage of every run and the cheapest thing a host can
plan from: every entry under the manifest's roots, with its size, time, type
and hash. It is `bastion_agent/walk.py`, standard library only.

## What it produces

`python3 -m bastion_agent walk <manifest.yaml> [--out DIR] [--no-hash] [--require-signed]`
reads the manifest's `scope`, walks every root, and writes two files into
`DIR`. Without `--out`, `DIR` is `<root>/.agent/` for a manifest with one
root, and `build/freeagent/<id>/` (under the current directory) for one with
several. The second keeps the program's first name on purpose: it is output a
person may already have, and renaming it would orphan it. Both files are
written atomically (a temporary file, then a rename), so a reader never sees a
half-written map.

**`walk.jsonl`**: one JSON object per entry, sorted by `(root, path)`, keys
sorted, UTF-8. Identical trees produce byte-identical files.

| Key | Present on | Meaning |
|---|---|---|
| `root` | all | Index into the manifest's `scope.roots`. |
| `path` | all | Path relative to that root, `/`-separated on every OS. |
| `kind` | all | `file`, `dir`, `symlink` (Windows junctions too), `other` (socket, fifo, device). |
| `size` | file | Bytes. |
| `mtime`, `mtime_ns` | file, dir | Modification time as UTC ISO-8601 and as integer nanoseconds (the cache key). |
| `mime` | file | Sniffed type: magic bytes first, then a fixed extension table, then a text/binary probe. `inode/x-empty` for empty files. The `mimetypes` module is not used, because it reads per-machine registries and would make the map depend on the machine. |
| `sha256` | file | Hex digest, or `null` when the file was too large, could not be read, or `--no-hash` was given. |
| `skip` | file | `too_large` when `size > scope.max_file_bytes` (default 256 MiB). The file is still sniffed and listed, never read in full. |
| `target` | symlink | The link text, `/`-separated. |
| `error` | any | `ExceptionName: message`. The entry is recorded and the walk continues. |

**`walk.summary.json`**: `manifest_id`, `manifest_digest` (the signing
digest, which ties the map to the exact manifest that produced it),
`walked_at`, `platform`, `roots` (each with its `resolved` absolute path, and
an `error` when it is absent on this machine), `entries`, `bytes`, `counts`
(`files dirs symlinks other excluded errors too_large hashed hash_reused`) and
`hashing`.

Exit code: `0` clean; `1` the manifest failed validation (or was unsigned
under `--require-signed`); `2` the walk completed with errors recorded
(a missing root, an unreadable directory). The map is written in every case
but the first.

## Rules the walker enforces

- **Excludes prune.** An excluded directory is not descended, so its subtree
  costs nothing. Patterns (`scope.exclude`) are `/`-separated and relative to
  the root. `**` spans directories; `*` and `?` stay within one segment;
  `[..]` and `[!..]` classes work. A pattern with no `/` also matches any
  single path segment, so `node_modules` or `*.key` prune at any depth. A
  pattern ending in `/**` prunes the directory itself as well as its contents.
  Backslashes in patterns are read as `/`. Matching is case-insensitive on
  Windows only, as the file system is.
- **The agent's own folder is always excluded.** `.agent` is pruned at any
  depth and in any letter case on every OS, whatever the manifest says, so an
  agent never indexes its own output (on a case-insensitive Mac volume,
  `.Agent` is the same folder).
- **Links are recorded, never followed**, unless `scope.follow_symlinks` is
  true. This covers symlinks on every OS and junctions on Windows
  (`is_junction()` on Python 3.12 and later, the reparse tag before that).
  Following is opt-in because a link out of the root is the usual way a
  scoped walk ends up reading the whole disk.
- **Large files are metadata only.** Over `max_file_bytes` the walker reads
  8 KiB to sniff the type and stops.
- **Errors are entries, not aborts.** Permission denied on a directory gives a
  `dir` entry with `error`, and the walk moves on; a root that does not exist
  on this machine is reported in the summary and skipped. The host can see
  exactly what it could not see.
- **Hashes are reused.** A previous `walk.jsonl` in the output directory is a
  cache keyed on `(root, path)` → `(size, mtime_ns)`. An unchanged file keeps
  its digest without being read again, so a daily sweep of a large folder
  costs one `stat` per file, not one read. `--no-hash` skips hashing (and the
  cache) for a fast first survey.

## Portability

The stage runs on the owner's machine, whatever it is.

- **Standard library only**: nothing to install on the machine that holds the
  files.
- **Python 3.8 syntax floor**, enforced by `test_syntax_floor.py` at the
  repository root, which parses every module in `bastion_agent/` and `pii/` at
  3.8 and denies the newer standard-library calls that parse on 3.8 and then
  fail at run time.
- **Roots** may be POSIX absolute paths, `~` or `~/...` (expanded with
  `os.path.expanduser`: `HOME` on Unix, `USERPROFILE` on Windows), Windows
  drive paths (`C:\...` or `C:/...`) and UNC paths (`\\server\share`).
- **Paths in the map are always `/`-separated**, so a map made on Windows
  reads the same as one made on a Mac, and exclude patterns mean the same thing
  everywhere.
- **Unicode file names** are written as they are (`ensure_ascii=False`);
  undecodable bytes in link targets go through `os.fsdecode`.
- **Timestamps** are nanosecond integers from `st_mtime_ns`, which exists on
  all three platforms; the ISO form is derived from it.

## What the stage does not do

- It does not read file contents beyond the 8 KiB sniff and the hash stream.
  Extraction is the next stage.
- It does not detect changes by itself. Two maps diff trivially because they
  are sorted, and later stages find their work from the hashes.
- It does not treat mounts specially. A network share under a root is walked
  like any directory; exclude it if that is not wanted.

## Tests

`python3 -m unittest bastion_agent.test_walk` covers the map's shape and sort
order, MIME sniffing (magic, extension, empty, binary), excludes (segment,
anchored, `/**` pruning, backslashes, Windows case folding, `.agent` in any
case), the too-large skip, `--no-hash`, hash reuse and its invalidation when a
file changes, byte-identical re-runs, a missing root, an unreadable directory,
Unicode names, `~` expansion, and symlinks recorded but not followed, or
followed when the manifest allows it. The symlink tests are skipped on Windows,
where creating a symlink needs a privilege.
