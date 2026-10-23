"""PII sterilization service — HTTP surface over pipeline + vault.

Stdlib-only by design: this process holds the household's most sensitive
data, and zero third-party runtime dependencies is the audit story
(every dependency is attack surface).

Endpoints (JSON in/out):
  GET  /health                     liveness, no auth
  GET  /scope/<scope>              token inventory (types+tokens, no values)
  POST /sterilize {text, scope?, verify?, escape_held_literals?}  -> {text, findings, stats}
  POST /rehydrate {text, scope?}           -> {text, restored, unknown_tokens}
  POST /flag {text}                -> {flagged, counts}  rules-only, no model
       call, no vault writes — the milliseconds pre-inference check. A clean
       /flag does NOT mean no PII (contextual PII needs /sterilize).

Auth is fail-closed: PII_API_KEY must be set in the environment or the
service refuses to start. PII_ALLOW_NOAUTH=1
exists for the unit-test harness only. /rehydrate returns REAL values —
callers are trusted surfaces only; every call lands in the vault's audit
table.

Config (env): PII_BIND (host:port, default 127.0.0.1:8091; another address
only when set), LLM_URL
(default http://llm:8080), PII_DB (default /data/vault.db),
PII_LLM_TIMEOUT seconds (default 300).
"""

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import detect, pipeline, recall
from .vault import Vault

_MAX_BODY = 2 * 1024 * 1024


class Config:
    def __init__(self, env):
        self.bind = env.get("PII_BIND", "127.0.0.1:8091")
        self.llm_url = env.get("LLM_URL", "http://llm:8080")
        self.db = env.get("PII_DB", "/data/vault.db")
        self.api_key = env.get("PII_API_KEY", "")
        self.llm_timeout = float(env.get("PII_LLM_TIMEOUT", "300"))
        if not self.api_key and env.get("PII_ALLOW_NOAUTH") != "1":
            raise SystemExit(
                "refusing to start: PII_API_KEY unset (fail-closed; "
                "PII_ALLOW_NOAUTH=1 is for tests only)"
            )
        # The recall sensor is chosen here, at boot, by the operator — never
        # per request. A backend that cannot start stops the service.
        try:
            self.recall = recall.build_backend(env)
        except recall.RecallError as e:
            raise SystemExit("refusing to start: %s" % e)


class Handler(BaseHTTPRequestHandler):
    server_version = "privatae-pii"
    protocol_version = "HTTP/1.1"

    # injected by build_server
    cfg: Config = None
    vault: Vault = None

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        if not self.cfg.api_key:
            return True  # only reachable via PII_ALLOW_NOAUTH (tests)
        got = self.headers.get("Authorization", "")
        want = f"Bearer {self.cfg.api_key}"
        return hmac.compare_digest(got.encode(), want.encode())

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
            return
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        if self.path.startswith("/scope/"):
            scope = self.path[len("/scope/"):]
            self._send(200, {"scope": scope, "tokens": self.vault.scope_tokens(scope)})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > _MAX_BODY:
                self._send(413, {"error": "body too large"})
                return
            req = json.loads(self.rfile.read(length))
            text = req["text"]
            scope = req.get("scope", "default")
            if not isinstance(text, str) or not isinstance(scope, str) or not scope:
                raise ValueError("text must be a string, scope a non-empty string")
        except (ValueError, KeyError, TypeError) as e:
            self._send(400, {"error": f"bad request: {e}"})
            return

        if self.path == "/sterilize":
            backend = self.cfg.recall
            llm_verify = backend.verify if req.get("verify") else None
            escape_all = req.get("escape_held_literals") is True
            try:
                out, result = pipeline.sterilize(
                    text, scope, self.vault, backend.extract, llm_verify,
                    escape_held_literals=escape_all,
                )
            except recall.RecallError as e:
                # Fail closed: no recall pass means no recall guarantee, so no
                # partially-sterilized text ever leaves this process.
                self._send(502, {"error": str(e)})
                return
            result["stats"]["recall"] = backend.name
            # echo the literal rule applied, so a caller that asked for
            # escape_held_literals can tell it was honoured
            result["stats"]["escape_held_literals"] = escape_all
            self.vault.audit(scope, "sterilize", json.dumps(result["stats"]))
            self._send(200, {"text": out, **result})
            return

        if self.path == "/flag":
            # Rules pass only: deterministic, model-free, no vault rows, no
            # audit (nothing minted, nothing recallable). Precision anchors
            # only — callers must not treat a clean flag as PII-free.
            counts = {}
            for f in detect.detect(text):
                counts[f.type] = counts.get(f.type, 0) + 1
            self._send(200, {"flagged": bool(counts), "counts": counts})
            return

        if self.path == "/rehydrate":
            out, result = pipeline.rehydrate(text, scope, self.vault)
            self.vault.audit(
                scope, "rehydrate",
                json.dumps({"restored": result["restored"],
                            "unknown": len(result["unknown_tokens"])}),
            )
            self._send(200, {"text": out, **result})
            return

        self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        # No request bodies in logs, ever; method+path+status only.
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def build_server(cfg: Config) -> ThreadingHTTPServer:
    os.umask(0o077)
    handler = type("BoundHandler", (Handler,), {"cfg": cfg, "vault": Vault(cfg.db)})
    host, port = cfg.bind.rsplit(":", 1)
    return ThreadingHTTPServer((host, int(port)), handler)


def main():
    cfg = Config(os.environ)
    srv = build_server(cfg)
    sys.stderr.write("pii service on %s, recall %s, db=%s\n"
                     % (cfg.bind, cfg.recall.describe(), cfg.db))
    srv.serve_forever()


if __name__ == "__main__":
    main()
