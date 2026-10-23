# bastion agent query endpoint: `serve`

`serve` is how a host reads what the agent prepared without the data moving:
a host (the owner's, or a grantee's) sends a query and gets **sanitized**
chunks and catalog cards back (sanitized by the manifest's mode: in `flag`
mode, which the bastion deploys, names, street addresses and dates of birth
remain; [sanitize.md](sanitize.md#modes-manifest-sanitizemode)). Nothing else has a route: not the extract
store, not the vault, not the vectors table. It is `bastion_agent/serve.py`,
mutual TLS with the standard library's `ssl`.

`python3 -m bastion_agent serve <manifest> [--out DIR] [--bind HOST:PORT] [--port-file FILE] [--allow-unsigned]`

## Identity: the client certificate

TLS runs with `ssl.CERT_REQUIRED` against `FREEAGENT_CA_ROOT`, TLS 1.2 at
least. Each connection's handshake runs in that connection's own thread with a
10 s timeout, never on the accept loop, so a peer that connects and says
nothing costs its own thread and nothing else; an idle connection is closed
after 60 s. A client with no certificate, or one from another CA, never
reaches a handler: the handshake fails, one line goes to stderr, and there is
no audit row (it never became a request). For a client that did chain, the
certificate's CN is who they are:

| CN | Gets |
|---|---|
| equal to the manifest's `owner.host` | `search` (if `search` is in the mask), `read_range`, `catalog`, `status`, `health` |
| a host in `manifest.grants`, on or before its `until` date | exactly that entry's `ops` (`search` and/or `read_range`), plus `health` |
| anyone else who chained | `health` only; everything else is 403, audited with the CN |

There is no other credential: no token, no password, no header.

## Routes

| Route | Body | Returns |
|---|---|---|
| `POST /search` | `{query, k?}` (k defaults to 5 and is held to 1–50) | `{hits, k}`: the top k sanitized windows with score, document id, chunk id, index and offsets. The same search as the CLI, through the same `EMBED_URL` model ([embed.md](embed.md)); 502 if the model cannot be reached. |
| `POST /read_range` | `{doc, start?, end}` | Up to 65,536 characters of the **sanitized** text of that document, with `total`. |
| `GET /catalog`, `GET /catalog/dirs` | query `prefix`, `offset`, `limit` (default 500, at most 2,000) | The file cards or the directory cards (owner only), a page at a time: `{cards, kind, total, offset, limit, next_offset, prefix}`, `next_offset` being `null` on the last page. 404 until the first sweep has written a catalog. |
| `GET /status` | | `{state}`: `run.state.json` (owner only). |
| `GET /health` | | `{ok, id, serving}` for any client that chained. |

`doc` is the document's content hash (64 lowercase hex), the same id the
extract and sanitized stores share. The route reads only the `sanitize/`
directory, so the plaintext for that id, which exists on disk, is never what
comes back; a test checks both halves of that sentence.

## The manifest is the policy, live

On each request the endpoint checks whether the manifest file
changed, and if so re-reads it and runs the same gate as the scheduler: the
signature over the canonical payload, the signing certificate's CN equal to
`owner.host`, and the chain to `FREEAGENT_CA_ROOT` (required). So:

- **Revoke a grant**: delete the entry and re-sign. The next request from that
  CN is 403.
- **Edit without re-signing**: the endpoint serves nothing but `/health`
  (which reports `serving: false`), and answers everything else with 503 and
  the gate's reason until the manifest verifies again.
- `--allow-unsigned` is for development only, as for `sweep`.

## Audit

Every request that reached a handler is one line in `<out>/serve.audit.jsonl`:
`ts`, `cn`, `op`, `path`, `status`, `bytes`; for `search` the first 16 hex
characters of the query's sha256 (never the query) and the number of hits; for
`read_range` the start of the document id and the characters served; for the
catalog the page size and the total. A test checks that the query text is not
in the file.

## Bind and certificates

- `--bind` or `FREEAGENT_BIND`: `host:port` or `[v6]:port`, default
  `[::]:8470`. `--bind` wins. An IPv6 address gets an `AF_INET6` socket.
- `--port-file FILE` writes the port actually bound. The bastion runs `serve`
  on `127.0.0.1:0` and reads the port from this file, so the endpoint is not
  reachable from the network; the bastion is its client.
  Run by hand for another machine to reach, bind the interface it reaches
  instead.
- `FREEAGENT_TLS_CERT` and `FREEAGENT_TLS_KEY`: the machine's certificate and
  key. `FREEAGENT_CA_ROOT`: the CA that client certificates must chain to. All
  three are required; the server refuses to start without them.

## Tests

`python3 -m unittest bastion_agent.test_serve` builds a small PKI per test
class (a CA root, a server certificate, owner, grantee, expired-grant and
unknown-CN client certificates, and a client certificate with the owner's CN
from a different CA) and checks: the owner gets every route and sees sanitized
heads in the catalog, paged; the grantee gets `search` and is 403 on
`read_range`, `catalog` and `status`; an expired grant and an unknown CN are
403; no certificate, or a foreign CA, fails the handshake and leaves no audit
row; a connection that never speaks does not stall the server; `read_range` is
capped, returns sanitized text for the shared id while the plaintext sits on
disk with no route, and gives 404 for an unknown id and 400 for malformed ids
and queries; the audit hashes the query; a grant revoked by re-signing is
refused on the next request; an edit without re-signing turns the endpoint
into 503 with `serving: false`, and re-signing restores it; an unreadable
manifest fails closed; and `--port-file` reports the bound port. Plus bind
parsing, CN extraction, and the required TLS inputs.
