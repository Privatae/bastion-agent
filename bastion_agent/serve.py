"""bastion agent query endpoint — the container on the mesh.

The other half of "access moves, data does not". Serves the owner's host
and the manifest's grantees over MUTUAL TLS; nothing here ever reads the
extract store, the vault, or the vectors' raw table for a client — the
only bytes that leave are sanitized chunks and catalog cards.

Identity is the presented client certificate:
  - the TLS layer requires a client cert that chains to FREEAGENT_CA_ROOT
    (ssl.CERT_REQUIRED); no cert or a foreign CA never reaches a handler
  - the cert's CN is the caller. CN == manifest owner.host → owner.
    CN in manifest.grants (and today <= until) → grantee with that entry's
    ops. Anyone else who chained → 403, audited.

Ops (JSON over HTTPS):
  POST /search      {query, k?}           search  (owner, grantee w/ op)
  POST /read_range  {doc, start, end}     read_range (owner, grantee w/ op)
                                          from the SANITIZED store only,
                                          <= READ_RANGE_MAX bytes
  Both answer with `sanitize_mode`, the mode the sanitize stage recorded for
  the text in the reply ("flag" or "sterilize"; the weakest across a
  search's hits; "unknown" when the record does not vouch for that text; a
  search with no hits names the manifest's mode, or "none"), so a caller can
  say what the text has had done to it: in flag mode names, street addresses
  and dates of birth remain.
  GET  /catalog[?prefix=&offset=&limit=]  owner only: the file cards (paged)
  GET  /catalog/dirs[?...]                owner only: the directory cards (paged)
  GET  /status                            owner only: run.state.json
  GET  /health                            any chained cert: {ok, id}

The manifest is re-read and re-gated (signature verified) whenever its
file changes: revoke a grant = drop the entry, re-sign, and the next
request is refused. A manifest that no longer passes the gate makes the
server refuse everything but /health until it does.

Every request is audited to <out>/serve.audit.jsonl: CN, op, status,
bytes, a sha256 of the query (never the query), doc id for read_range.

Bind: --bind or FREEAGENT_BIND (host:port, default [::]:8470). The bastion
binds 127.0.0.1:0 and reads the port from --port-file, so it is the only
client; bind another interface only for another machine to reach. Server
cert and key: FREEAGENT_TLS_CERT / FREEAGENT_TLS_KEY. Stdlib only; the embedding endpoint is the same sensor `search`
already uses.
"""

import datetime as _dt
import hashlib
import json
import os
import ssl
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import embed as _embed
from .manifest import ManifestError, load_manifest
from .run import GateError, verify_signature
from .sanitize import store_path as sanitized_store_path

DEFAULT_BIND = "[::]:8470"
MAX_BODY = 64 * 1024
READ_RANGE_MAX = 64 * 1024
SEARCH_K_MAX = 50
CATALOG_PAGE_DEFAULT = 500
CATALOG_PAGE_MAX = 2000
OWNER_OPS = ("search", "read_range", "catalog", "status")


class ServeError(Exception):
    pass


def sanitize_mode(manifest):
    """The sanitize mode the manifest sets: "flag", "sterilize", or "none" when
    it names no sanitize stage. A reply with no text in it (a search with no
    hits) carries this; a reply with text carries served_mode."""
    s = getattr(manifest, "sanitize", None)
    return getattr(s, "mode", None) or "none"


# Weakest first: a reply that mixes texts names the weakest mode among them.
_MODE_RANK = {"unknown": 0, "flag": 1, "sterilize": 2}
_index_lock = threading.Lock()
_index_cache = {}  # sanitize.jsonl path -> ((ino, mtime_ns, size), {doc: mode})


def _sanitize_index(out_dir):
    """({doc sha: mode} for every document the last sanitize run wrote with
    status ok, the index's mtime_ns), from <out>/sanitize.jsonl; ({}, None)
    when there is none. Re-read only when the file changes."""
    path = os.path.join(out_dir, "sanitize.jsonl")
    try:
        st = os.stat(path)
    except OSError:
        return {}, None
    sig = (st.st_ino, st.st_mtime_ns, st.st_size)
    with _index_lock:
        hit = _index_cache.get(path)
        if hit and hit[0] == sig:
            return hit[1], st.st_mtime_ns
        modes = {}
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(rec, dict) and rec.get("status") == "ok" and rec.get("sha256"):
                        modes[rec["sha256"]] = rec.get("mode")
        except OSError:
            return {}, None
        _index_cache[path] = (sig, modes)
        return modes, st.st_mtime_ns


def served_mode(out_dir, doc, start=None, text=None):
    """The sanitize mode that wrote the text served for doc, as the sanitize
    stage recorded it, or "unknown" when that record does not vouch for the
    text. The manifest's mode says what the NEXT sweep will do; the store can
    still hold an earlier sweep's text (the manifest switched to sterilize and
    the sweep has not run, or stopped; a sweep is rewriting the store now; the
    chunks a search reads were cut before the latest sanitize run).

    Unknown when: no status-ok record for doc, the file is newer than the
    index (a run that has not finished rewrote it), or, for a search hit,
    `text` at `start` is not what the store holds now."""
    modes, index_mtime = _sanitize_index(out_dir)
    mode = modes.get(doc)
    if mode not in ("flag", "sterilize"):
        return "unknown"
    path = sanitized_store_path(out_dir, doc)
    try:
        if os.stat(path).st_mtime_ns > index_mtime:
            return "unknown"
        if text is not None:
            with open(path, encoding="utf-8") as fh:
                stored = fh.read()
            if stored[start:start + len(text)] != text:
                return "unknown"
    except (OSError, TypeError, ValueError):
        return "unknown"
    return mode


def _weakest(modes):
    return min(modes, key=lambda m: _MODE_RANK.get(m, 0))


def parse_bind(bind):
    bind = bind.strip()
    if bind.startswith("["):
        host, _, port = bind[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = bind.rpartition(":")
    if not host or not port.isdigit():
        raise ServeError("FREEAGENT_BIND must be host:port or [v6]:port, got %r" % bind)
    return host, int(port)


def peer_cn(cert):
    for rdn in (cert or {}).get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return None


class Policy:
    """Who may do what, from a gated manifest. Reloads on file change."""

    def __init__(self, manifest_path, env, allow_unsigned=False, today=None):
        self.path = manifest_path
        self.env = env
        self.allow_unsigned = allow_unsigned
        self.today = today
        self._mtime = None
        self.manifest = None
        self.gate_error = None
        self._lock = threading.Lock()
        self.reload()

    def reload(self):
        with self._lock:
            try:
                mtime = os.stat(self.path).st_mtime_ns
            except OSError as e:
                self.manifest, self.gate_error = None, "manifest unreadable: %s" % e
                return
            if mtime == self._mtime and (self.manifest or self.gate_error):
                return
            self._mtime = mtime
            try:
                m = load_manifest(self.path)
            except ManifestError as e:
                self.manifest, self.gate_error = None, "manifest invalid: %s" % "; ".join(e.errors)
                return
            except Exception as e:  # noqa: BLE001
                # FAIL CLOSED here too: a manifest that cannot be read at all
                # (permissions, bad encoding) must not leave the previous one
                # in force once _mtime has advanced.
                self.manifest, self.gate_error = None, "manifest unreadable: %s" % e
                return
            try:
                verify_signature(m, self.env, manifest_dir=os.path.dirname(os.path.abspath(self.path)))
            except GateError as e:
                if not self.allow_unsigned:
                    self.manifest, self.gate_error = None, "gate: %s" % e
                    return
            except Exception as e:  # noqa: BLE001
                # FAIL CLOSED: an unexpected error in the gate must never leave
                # the previous manifest in force (_mtime is already advanced).
                self.manifest, self.gate_error = None, "gate: %s" % e
                return
            self.manifest, self.gate_error = m, None

    def allowed_ops(self, cn):
        """Ops for this CN, or an empty tuple. Owner gets everything the
        mask permits; a grantee gets its entry's ops while unexpired."""
        self.reload()
        m = self.manifest
        if m is None or not cn:
            return ()
        if cn == m.owner_host:
            ops = list(OWNER_OPS)
            if "search" not in m.mask:
                ops.remove("search")
            return tuple(ops)
        today = self.today or _dt.datetime.now(_dt.timezone.utc).date()
        for g in m.grants:
            if g.host == cn:
                if today > g.until:
                    return ()
                return tuple(g.ops)
        return ()


HANDSHAKE_TIMEOUT = 10


class Handler(BaseHTTPRequestHandler):
    server_version = "freeagent"
    protocol_version = "HTTP/1.1"
    # keep-alive is one thread per connection here; an idle client must not
    # pin that thread forever (a bastion review measured exactly that)
    timeout = 60

    def setup(self):
        # The TLS handshake happens HERE, in this connection's own thread —
        # never in the accept loop. Wrapping the listening socket (the first
        # cut) ran every handshake synchronously in accept(), so one idle
        # pre-auth TCP connection stalled every client.
        # The raw socket arrives with a short timeout from get_request, so a
        # peer that connects and says nothing is dropped after
        # HANDSHAKE_TIMEOUT, and only its own thread waited.
        self.request = self.server.ssl_ctx.wrap_socket(
            self.request, server_side=True, do_handshake_on_connect=False)
        self.request.do_handshake()
        self.connection = self.request
        super().setup()
    policy = None      # injected by build_server
    out_dir = None
    env = None
    embed_endpoint = None
    audit_lock = threading.Lock()

    # ── plumbing ────────────────────────────────────────────────────────
    def _cn(self):
        try:
            return peer_cn(self.connection.getpeercert())
        except (AttributeError, ValueError):
            return None

    def _send(self, code, obj, cn=None, op=None, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._audit(cn, op, code, len(body), extra)

    def _audit(self, cn, op, status, nbytes, extra):
        rec = {"ts": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "cn": cn, "op": op, "path": self.path, "status": status, "bytes": nbytes}
        if extra:
            rec.update(extra)
        with self.audit_lock:
            with open(os.path.join(self.out_dir, "serve.audit.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n > MAX_BODY:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b"{}"
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("body must be a JSON object")
        return obj

    def _authorize(self, op):
        cn = self._cn()
        allowed = self.policy.allowed_ops(cn)
        if op in allowed:
            return cn, None
        if self.policy.gate_error:
            return cn, (503, {"error": "manifest not serving: %s" % self.policy.gate_error})
        return cn, (403, {"error": "not permitted for %s: %s" % (cn or "no-cn", op)})

    def log_message(self, fmt, *args):
        pass  # the audit file is the log; no request lines on stderr

    # ── routes ───────────────────────────────────────────────────────────
    def do_GET(self):
        cn = self._cn()
        if self.path == "/health":
            m = self.policy.manifest
            self.policy.reload()
            self._send(200, {"ok": True, "id": m.id if m else None,
                             "serving": self.policy.gate_error is None}, cn, "health")
            return
        route, _, qs = self.path.partition("?")
        if route in ("/catalog", "/catalog/dirs"):
            # /catalog = file cards; /catalog/dirs = directory cards — the MAP
            # (sizes, types, newest change, keywords, entity counts per folder)
            # a host plans a cleanup or an archive from without reading a file.
            # PAGED: ?prefix=<path prefix>&offset=<n>&limit=<n> — a big store's
            # file cards are megabytes and a client's reply cap is finite.
            cn, denied = self._authorize("catalog")
            if denied:
                self._send(denied[0], denied[1], cn, "catalog")
                return
            q = urllib.parse.parse_qs(qs)
            prefix = (q.get("prefix") or [""])[0]
            try:
                offset = max(0, int((q.get("offset") or ["0"])[0]))
                limit = max(1, min(CATALOG_PAGE_MAX, int((q.get("limit") or [str(CATALOG_PAGE_DEFAULT)])[0])))
            except ValueError:
                self._send(400, {"error": "offset/limit must be integers"}, cn, "catalog")
                return
            name = "catalog.dirs.jsonl" if route.endswith("/dirs") else "catalog.jsonl"
            path = os.path.join(self.out_dir, name)
            if not os.path.exists(path):
                self._send(404, {"error": "no catalog yet — the first sweep has not finished"}, cn, "catalog")
                return
            with open(path, encoding="utf-8") as fh:
                cards = [json.loads(l) for l in fh]
            if prefix:
                cards = [c for c in cards if str(c.get("path", "")).startswith(prefix)]
            total = len(cards)
            page = cards[offset:offset + limit]
            nxt = offset + limit if offset + limit < total else None
            self._send(200, {"cards": page, "kind": "dirs" if name.endswith("dirs.jsonl") else "files",
                             "total": total, "offset": offset, "limit": limit, "next_offset": nxt,
                             "prefix": prefix},
                       cn, "catalog", {"kind": name, "n": len(page), "total": total})
            return
        if self.path == "/status":
            cn, denied = self._authorize("status")
            if denied:
                self._send(denied[0], denied[1], cn, "status")
                return
            path = os.path.join(self.out_dir, "run.state.json")
            state = {}
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    state = json.load(fh)
            self._send(200, {"state": state}, cn, "status")
            return
        self._send(404, {"error": "not found"}, cn, None)

    def do_POST(self):
        if self.path == "/search":
            cn, denied = self._authorize("search")
            if denied:
                self._send(denied[0], denied[1], cn, "search")
                return
            try:
                req = self._body()
                query = req["query"]
                k = int(req.get("k", 5))
                if not isinstance(query, str) or not query.strip():
                    raise ValueError("query must be a non-empty string")
                k = max(1, min(SEARCH_K_MAX, k))
            except (ValueError, KeyError, TypeError) as e:
                self._send(400, {"error": "bad request: %s" % e}, cn, "search")
                return
            qhash = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
            try:
                hits = _embed.search(self.policy.manifest, self.out_dir, query, k=k,
                                     env=self.env, endpoint=self.embed_endpoint)
            except (_embed.EmbedError, OSError) as e:
                self._send(502, {"error": "search unavailable: %s" % e}, cn, "search", {"q": qhash})
                return
            if hits:
                mode = _weakest([served_mode(self.out_dir, h.get("doc"), h.get("start"), h.get("text"))
                                 for h in hits])
            else:
                mode = sanitize_mode(self.policy.manifest)
            self._send(200, {"hits": hits, "k": k, "sanitize_mode": mode},
                       cn, "search", {"q": qhash, "hits": len(hits)})
            return
        if self.path == "/read_range":
            cn, denied = self._authorize("read_range")
            if denied:
                self._send(denied[0], denied[1], cn, "read_range")
                return
            try:
                req = self._body()
                doc = req["doc"]
                start = int(req.get("start", 0))
                end = int(req["end"])
                if not isinstance(doc, str) or len(doc) != 64 or not all(c in "0123456789abcdef" for c in doc):
                    raise ValueError("doc must be a sanitized-document sha256")
                if start < 0 or end <= start:
                    raise ValueError("start/end out of order")
                end = min(end, start + READ_RANGE_MAX)
            except (ValueError, KeyError, TypeError) as e:
                self._send(400, {"error": "bad request: %s" % e}, cn, "read_range")
                return
            path = sanitized_store_path(self.out_dir, doc)  # the ONLY store with a route
            if not os.path.exists(path):
                self._send(404, {"error": "no such document"}, cn, "read_range", {"doc": doc[:12]})
                return
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            piece = text[start:end]
            self._send(200, {"doc": doc, "start": start, "end": start + len(piece),
                             "total": len(text), "text": piece,
                             "sanitize_mode": served_mode(self.out_dir, doc)},
                       cn, "read_range", {"doc": doc[:12], "chars": len(piece)})
            return
        self._send(404, {"error": "not found"}, self._cn(), None)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    ssl_ctx = None  # set by build_server; used by Handler.setup per connection

    def get_request(self):
        # Plain TCP accept; the handshake is the handler thread's job (Handler.setup).
        sock, addr = self.socket.accept()
        sock.settimeout(HANDSHAKE_TIMEOUT)
        return sock, addr

    def handle_error(self, request, client_address):
        # a client that fails the TLS handshake (no cert, foreign CA) is the
        # expected case, not a bug: one line, no traceback, no audit row
        # (it never became a request)
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, OSError)):
            sys.stderr.write("freeagent serve: rejected %s: %s\n" % (client_address[0], exc))
            return
        super().handle_error(request, client_address)


def build_ssl_context(cert, key, ca_root):
    for label, p in (("FREEAGENT_TLS_CERT", cert), ("FREEAGENT_TLS_KEY", key), ("FREEAGENT_CA_ROOT", ca_root)):
        if not p:
            raise ServeError("%s is not set — the endpoint is mTLS-only; refusing to serve" % label)
        if not os.path.exists(p):
            raise ServeError("%s=%s does not exist" % (label, p))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_root)
    ctx.load_cert_chain(cert, key)
    return ctx


def build_server(manifest_path, out_dir, env=None, allow_unsigned=False, bind=None,
                 embed_endpoint=None, today=None, port_file=None):
    env = dict(os.environ) if env is None else env
    ctx = build_ssl_context(env.get("FREEAGENT_TLS_CERT", ""), env.get("FREEAGENT_TLS_KEY", ""),
                            env.get("FREEAGENT_CA_ROOT", ""))
    policy = Policy(manifest_path, env, allow_unsigned=allow_unsigned, today=today)
    if policy.manifest is None and not allow_unsigned:
        raise ServeError("refusing to start: %s" % policy.gate_error)
    os.makedirs(out_dir, exist_ok=True)
    handler = type("BoundHandler", (Handler,), {
        "policy": policy, "out_dir": out_dir, "env": env, "embed_endpoint": embed_endpoint})
    host, port = parse_bind(bind or env.get("FREEAGENT_BIND", DEFAULT_BIND))
    srv = _Server((host, port), handler, bind_and_activate=False)
    if ":" in host:
        import socket
        srv.address_family = socket.AF_INET6
        srv.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.server_bind()
    srv.server_activate()
    srv.ssl_ctx = ctx  # per-connection wrap in Handler.setup, not on the listener
    srv.policy = policy
    if port_file:
        # a supervisor (the bastion) binds port 0 and reads the real port here
        tmp = port_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("%d\n" % srv.server_address[1])
        os.replace(tmp, port_file)
    return srv


def serve(manifest_path, out_dir, env=None, allow_unsigned=False, bind=None, log=None, port_file=None):
    log = log or (lambda s: sys.stderr.write(s + "\n"))
    srv = build_server(manifest_path, out_dir, env, allow_unsigned=allow_unsigned, bind=bind,
                       port_file=port_file)
    m = srv.policy.manifest
    log("freeagent serve: %s on %s (owner %s, %d grant(s), mTLS)" % (
        m.id if m else "?", srv.server_address[:2], m.owner_host if m else "?", len(m.grants) if m else 0))
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
