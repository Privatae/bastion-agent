"""`bastion-agent doctor` — the preflight a member runs before the first sweep.

Reports what this machine has and what it lacks, per stage, and never
changes anything. Required items are what a stage refuses to run
without; optional ones are the sensors that widen coverage (pdftotext,
tesseract, the gliner package) — their absence is a recorded gap in the
stage output, not a failure here.
"""

import json
import os
import platform
import shutil
import sys
import urllib.request

PY_FLOOR = (3, 8)


def _which(name):
    return shutil.which(name)


def _probe_http(url, path, timeout=5):
    """Reachable means the server answered — any HTTP status counts (a
    proxy that only permits the embed path answers 403 on '/'). Only a
    connection failure is 'not reachable'."""
    import urllib.error
    try:
        with urllib.request.urlopen(url.rstrip("/") + path, timeout=timeout) as r:
            return True, "HTTP %d" % r.status
    except urllib.error.HTTPError as e:
        return True, "reachable (HTTP %d on %s)" % (e.code, path)
    except Exception as e:
        return False, str(e)[:120]


def checks(env=None):
    env = dict(os.environ) if env is None else env
    out = []

    def add(name, ok, detail, required=True, stage=None):
        out.append({"check": name, "ok": bool(ok), "detail": detail, "required": required,
                    "stage": stage})

    v = sys.version_info[:3]
    add("python >= %d.%d" % PY_FLOOR, v >= PY_FLOOR, "%s %s (%s)" % (platform.python_implementation(),
        ".".join(map(str, v)), sys.executable))
    add("platform", True, "%s %s %s" % (platform.system(), platform.release(), platform.machine()),
        required=False)
    try:
        import yaml  # noqa: F401
        add("yaml (manifest loader)", True, "PyYAML %s" % getattr(yaml, "__version__", "?"))
    except ImportError:
        add("yaml (manifest loader)", False, "PyYAML not importable")

    for tool, stage, req, why in (
            ("age", "seal", True, "the envelope; https://age-encryption.org"),
            # Not needed to RUN the agent: the gate verifies in the standard
            # library (x509gate) and the bastion signs with its own key.
            ("openssl", "sign/seal", False, "only for `sign --key` and SEAL_SIGN_KEY seal signatures"),
            ("pdftotext", "extract", False, "PDF text (poppler); without it simple PDFs only"),
            ("tesseract", "extract", False, "image OCR; without it images are recorded unsupported")):
        p = _which(tool)
        add(tool, bool(p), p or ("not on PATH — " + why), required=req, stage=stage)

    try:
        import gliner  # noqa: F401
        add("gliner package", True, "importable (PII_RECALL=gliner available)", required=False, stage="sanitize")
    except ImportError:
        add("gliner package", False, "not installed — sanitize sterilize on a laptop needs "
            "PII_RECALL=gliner (pip install gliner) or a reachable LLM_URL / PII_ADDR",
            required=False, stage="sanitize")

    embed_url = env.get("EMBED_URL", "http://127.0.0.1:11434")
    ok, detail = _probe_http(embed_url, "/")
    add("embedding endpoint %s" % embed_url, ok, detail, required=False, stage="embed")
    if env.get("PII_ADDR"):
        url = env["PII_ADDR"] if "://" in env["PII_ADDR"] else "http://" + env["PII_ADDR"]
        ok, detail = _probe_http(url, "/health")
        add("pii service %s" % url, ok, detail, required=False, stage="sanitize")
    if env.get("SUMMARIZE_URL"):
        ok, detail = _probe_http(env["SUMMARIZE_URL"], "/")
        add("summarizer %s" % env["SUMMARIZE_URL"], ok, detail, required=False, stage="catalog")

    for var, stage, why in (
            ("FREEAGENT_OWNER_RECIPIENT", "seal", "owner's age public key"),
            ("FREEAGENT_CA_ROOT", "sweep/serve", "CA root for the manifest gate and client certs"),
            ("FREEAGENT_TLS_CERT", "serve", "this machine's cert"),
            ("FREEAGENT_TLS_KEY", "serve", "this machine's key")):
        val = env.get(var, "")
        if var.endswith(("_ROOT", "_CERT", "_KEY")) and val:
            ok, detail = os.path.exists(val), (val if os.path.exists(val) else val + " (missing file)")
        else:
            ok, detail = bool(val), (("set" if val else "unset — " + why))
        add(var, ok, detail, required=False, stage=stage)
    return out


def render(results):
    lines = []
    for r in results:
        mark = "ok  " if r["ok"] else ("MISS" if r["required"] else "opt ")
        stage = (" [%s]" % r["stage"]) if r["stage"] else ""
        lines.append("%s %-34s %s%s" % (mark, r["check"], r["detail"], stage))
    missing = [r for r in results if r["required"] and not r["ok"]]
    lines.append("")
    lines.append("required missing: %d" % len(missing) if missing else "all required checks pass")
    return "\n".join(lines)


def main(argv=None, env=None):
    argv = sys.argv[1:] if argv is None else argv
    results = checks(env)
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    else:
        print(render(results))
    return 1 if any(r["required"] and not r["ok"] for r in results) else 0
