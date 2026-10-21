"""CLI: python3 -m bastion_agent {validate,show,payload,walk} <manifest.yaml> [...]"""

import argparse
import os
import sys

from . import doctor as _doctor
from .catalog import CatalogError, catalog
from .embed import EmbedError, chunk, embed, search
from .extract import extract
from .manifest import ManifestError, load_manifest, signing_digest, signing_payload
from .run import GateError, RunError, default_out, sign_manifest_file, sweep, write_signature
from .sanitize import SanitizeError, sanitize
from .seal import SealError, seal, unseal
from .serve import ServeError, serve
from .walk import walk


def _show(m, path):
    print(f"{path}: {m.id} (owner {m.owner_host})")
    print(f"  roots:   {', '.join(m.scope.roots)}")
    if m.scope.exclude:
        print(f"  exclude: {', '.join(m.scope.exclude)}")
    print(f"  mask:    {' '.join(m.mask)}")
    print(f"  stages:  {' -> '.join(m.stages)}")
    if m.sanitize:
        print(f"  sanitize: {m.sanitize.mode} (scope {m.sanitize.scope}"
              f"{', verify' if m.sanitize.verify else ''})")
    if m.embed:
        print(f"  embed:   {m.embed.model} {m.embed.dim}d, chunk "
              f"{m.embed.chunk_size_tokens}/{m.embed.chunk_overlap_tokens}")
    if m.summarize:
        print(f"  summarize: {m.summarize.model} per {', '.join(m.summarize.per)}")
    print(f"  sweep:   {m.sweep}")
    print(f"  sink:    catalog={m.sink.catalog} vectors={m.sink.vectors} "
          f"plaintext={m.sink.plaintext}"
          f"{' seal_to=' + ','.join(m.sink.seal_to) if m.sink.seal_to else ''}")
    if m.grants:
        for g in m.grants:
            print(f"  grant:   {g.host} may {', '.join(g.ops)} until {g.until.isoformat()}")
    else:
        print("  grants:  none")
    print(f"  signed:  {'yes (' + m.signature.alg + ')' if m.signed else 'NO — runtime will refuse'}")
    print(f"  digest:  sha256:{signing_digest(m.raw)}")


def _version():
    # pkgutil reads from a zipapp as well as a checkout; a plain open() cannot
    import pkgutil
    try:
        data = pkgutil.get_data(__package__ or "bastion_agent", "VERSION")
        return data.decode("utf-8").strip() if data else "0.0.0"
    except (OSError, ValueError):
        return "0.0.0"


def main():
    parser = argparse.ArgumentParser(prog="bastion-agent")
    parser.add_argument("--version", action="version", version="bastion-agent %s" % _version())
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_doc = sub.add_parser("doctor", help="preflight: python, tools, endpoints, environment")
    p_doc.add_argument("--json", action="store_true")
    p_val = sub.add_parser("validate", help="validate manifest(s), exit 1 on any error")
    p_val.add_argument("--require-signed", action="store_true",
                       help="also fail when the signature block is absent")
    p_val.add_argument("paths", nargs="+")
    p_show = sub.add_parser("show", help="print a manifest's effective plan")
    p_show.add_argument("paths", nargs="+")
    p_pay = sub.add_parser("payload", help="emit the canonical signing payload (bytes) to stdout")
    p_pay.add_argument("path")
    p_walk = sub.add_parser("walk", help="run the walk stage: filesystem + metadata map")
    p_walk.add_argument("path")
    p_walk.add_argument("--out", help="output directory (default <root>/.agent, or build/freeagent/<id> for several roots)")
    p_walk.add_argument("--no-hash", action="store_true",
                        help="metadata only; skip SHA-256 (fast survey)")
    p_walk.add_argument("--require-signed", action="store_true",
                        help="refuse an unsigned manifest, as the runtime will")
    p_ext = sub.add_parser("extract", help="run the extract stage: text out of walked files")
    p_ext.add_argument("path")
    p_ext.add_argument("--out", help="output directory (default <root>/.agent, or build/freeagent/<id> for several roots)")
    p_ext.add_argument("--no-external", action="store_true",
                       help="built-in extractors only; ignore pdftotext/tesseract on PATH")
    p_ext.add_argument("--require-signed", action="store_true")
    p_san = sub.add_parser("sanitize", help="run the sanitize stage: PII out of the extracted text")
    p_san.add_argument("path")
    p_san.add_argument("--out", help="output directory (default <root>/.agent, or build/freeagent/<id> for several roots)")
    p_san.add_argument("--require-signed", action="store_true")
    for name, helptext in (("chunk", "run the chunk stage: sanitized text -> overlapping windows"),
                           ("embed", "run the embed stage: chunks -> local vectors.db")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("path")
        p.add_argument("--out")
        p.add_argument("--require-signed", action="store_true")
    p_srch = sub.add_parser("search", help="query the local vectors (proves the lane end to end)")
    p_srch.add_argument("path")
    p_srch.add_argument("query")
    p_srch.add_argument("--out")
    p_srch.add_argument("-k", type=int, default=5)
    p_cat = sub.add_parser("catalog", help="run the catalog stage: file + directory cards")
    p_cat.add_argument("path")
    p_cat.add_argument("--out")
    p_cat.add_argument("--require-signed", action="store_true")
    p_seal = sub.add_parser("seal", help="run the seal stage: catalog -> age envelope for the owner")
    p_seal.add_argument("path")
    p_seal.add_argument("--out")
    p_seal.add_argument("--require-signed", action="store_true")
    p_unseal = sub.add_parser("unseal", help="owner-side: open a sealed bundle with an age identity")
    p_unseal.add_argument("sealed")
    p_unseal.add_argument("--identity", required=True, help="age identity file (age-keygen output)")
    p_unseal.add_argument("--dest", required=True)
    p_sw = sub.add_parser("sweep", help="the runtime: gate the manifest, run its stages on its cadence")
    p_sw.add_argument("path")
    p_sw.add_argument("--out", help="output directory (default <root>/.agent, or build/freeagent/<id> "
                                    "for several roots; the same folder serve uses)")
    p_sw.add_argument("--once", action="store_true", help="one run, then exit (any cadence)")
    p_sw.add_argument("--allow-unsigned", action="store_true",
                      help="DEVELOPMENT ONLY: run an unsigned or unverifiable manifest; recorded in run.jsonl")
    p_sign = sub.add_parser("sign", help="write the signature block into a manifest (host-side helper)")
    p_sign.add_argument("path")
    p_sign_by = p_sign.add_mutually_exclusive_group(required=True)
    p_sign_by.add_argument("--key", help="PEM private key (signs with openssl)")
    p_sign_by.add_argument("--value", help="a base64 DER signature over `payload`, made "
                                           "elsewhere (the bastion signs with its own key)")
    p_sign.add_argument("--cert", required=True, help="cert path to record in the manifest")
    p_srv = sub.add_parser("serve", help="the query endpoint: search/read_range over mTLS for owner + grantees")
    p_srv.add_argument("path")
    p_srv.add_argument("--out")
    p_srv.add_argument("--bind", help="host:port or [v6]:port (default FREEAGENT_BIND or [::]:8470)")
    p_srv.add_argument("--allow-unsigned", action="store_true",
                       help="DEVELOPMENT ONLY: serve an unsigned/unverifiable manifest")
    p_srv.add_argument("--port-file", help="write the bound port here (for a supervisor binding port 0)")
    args = parser.parse_args()

    if args.cmd == "doctor":
        return _doctor.main(["--json"] if args.json else [])

    if args.cmd == "serve":
        try:
            m = load_manifest(args.path)
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        out = args.out or default_out(m)
        try:
            serve(args.path, out, allow_unsigned=args.allow_unsigned, bind=args.bind,
                  port_file=args.port_file)
        except ServeError as exc:
            print("serve: %s" % exc, file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            pass
        return 0

    if args.cmd == "sign":
        try:
            if args.value:
                import base64
                try:
                    der = base64.b64decode(args.value, validate=True)
                except Exception:
                    print("sign: --value is not base64", file=sys.stderr)
                    return 1
                write_signature(args.path, der, args.cert)
            else:
                sign_manifest_file(args.path, args.key, args.cert)
        except (GateError, ManifestError) as exc:
            print("sign: %s" % exc, file=sys.stderr)
            return 1
        print("%s: signed (cert %s)" % (args.path, args.cert))
        return 0

    if args.cmd == "sweep":
        try:
            last = sweep(args.path, args.out, allow_unsigned=args.allow_unsigned, once=args.once)
        except RunError as exc:
            print("sweep: %s" % exc, file=sys.stderr)
            return 1
        return 0 if (last and last.get("ok")) else 1

    if args.cmd == "unseal":
        try:
            inv = unseal(args.sealed, args.identity, args.dest)
        except SealError as exc:
            print("unseal: %s" % exc, file=sys.stderr)
            return 1
        print("%s: %d members verified -> %s (manifest %s, sealed %s)"
              % (args.sealed, len(inv["members"]), args.dest, inv["manifest_id"], inv["sealed_at"]))
        return 0

    if args.cmd == "seal":
        try:
            m = load_manifest(args.path, require_signed=args.require_signed)
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        out = args.out or default_out(m)
        try:
            s = seal(m, out)
        except SealError as exc:
            print("seal: %s" % exc, file=sys.stderr)
            return 1
        print("%s: sealed %d members (%d bytes -> %d) to %d recipient(s)%s -> %s"
              % (m.id, len(s["members"]), s["bytes_plain"], s["bytes_sealed"],
                 len(s["recipients"]), " + signature" if s["signature"] else "",
                 os.path.join(out, s["file"])))
        return 0

    if args.cmd == "catalog":
        try:
            m = load_manifest(args.path, require_signed=args.require_signed)
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        if "catalog" not in m.stages:
            print("%s: 'catalog' is not in this manifest's stages" % args.path, file=sys.stderr)
            return 1
        out = args.out or default_out(m)
        try:
            s = catalog(m, out)
        except (FileNotFoundError, CatalogError) as exc:
            print("catalog: %s" % exc, file=sys.stderr)
            return 1
        c = s["counts"]
        print("%s: %d file cards (%d with text), %d directory cards, %d names masked; "
              "summaries %d new, %d reused [%s]; catalog %d bytes -> %s"
              % (m.id, c["files"], c["with_text"], c["dirs"], c["names_masked"],
                 c["summaries"], c["summaries_reused"], s["summarizer"] or "none",
                 s["bytes_catalog"], out))
        if s["stopped"]:
            print("catalog: summarizer STOPPED: %s" % s["stopped"], file=sys.stderr)
            return 1
        return 0

    if args.cmd in ("chunk", "embed", "search"):
        try:
            m = load_manifest(args.path, require_signed=getattr(args, "require_signed", False))
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        stage = "embed" if args.cmd == "search" else args.cmd
        if stage not in m.stages:
            print("%s: %r is not in this manifest's stages" % (args.path, stage), file=sys.stderr)
            return 1
        out = args.out or default_out(m)
        try:
            if args.cmd == "chunk":
                s = chunk(m, out)
                c = s["counts"]
                print("%s: %d docs -> %d chunks (%d/%d tokens), %d skipped -> %s"
                      % (m.id, c["docs"], c["chunks"], s["size_tokens"], s["overlap_tokens"],
                         c["skipped"], out))
                return 0
            if args.cmd == "embed":
                s = embed(m, out)
                c = s["counts"]
                print("%s: %d chunks in %d docs -> %d embedded, %d reused [%s, %dd]; "
                      "%d stale vectors kept; store %s"
                      % (m.id, c["chunks"], c["docs"], c["embedded"], c["reused"], s["endpoint"],
                         s["dim"], s["stale_vectors"], s["store"]))
                return 0
            hits = search(m, out, args.query, k=args.k)
            for h in hits:
                snippet = h["text"].replace("\n", " ")[:160]
                print("%.4f  %s#%d  %s" % (h["score"], h["doc"][:12], h["idx"], snippet))
            if not hits:
                print("no vectors for model %s" % m.embed.model, file=sys.stderr)
            return 0
        except (FileNotFoundError, EmbedError) as exc:
            print("%s: %s" % (args.cmd, exc), file=sys.stderr)
            return 1

    if args.cmd == "sanitize":
        try:
            m = load_manifest(args.path, require_signed=args.require_signed)
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        if "sanitize" not in m.stages:
            print("%s: 'sanitize' is not in this manifest's stages" % args.path, file=sys.stderr)
            return 1
        out = args.out or default_out(m)
        try:
            s = sanitize(m, out)
        except (FileNotFoundError, SanitizeError) as exc:
            print("sanitize: %s" % exc, file=sys.stderr)
            return 1
        c = s["counts"]
        types = ", ".join("%s=%d" % kv for kv in sorted(s["types"].items())) or "none"
        print("%s: %d files -> %d sanitized, %d reused, %d skipped, %d errors, %d not run "
              "[%s, scope %s]; tokens: %s -> %s"
              % (m.id, c["files"], c["ok"], c["reused"], c["skipped"], c["error"], c["not_run"],
                 s["sterilizer"], s["scope"], types, out))
        if s["stopped"]:
            print("sanitize STOPPED (fail closed): %s" % s["stopped"], file=sys.stderr)
            return 1
        return 2 if c["error"] else 0

    if args.cmd == "extract":
        try:
            m = load_manifest(args.path, require_signed=args.require_signed)
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        if "extract" not in m.stages:
            print("%s: 'extract' is not in this manifest's stages" % args.path, file=sys.stderr)
            return 1
        out = args.out or default_out(m)
        try:
            s = extract(m, out, use_external=not args.no_external)
        except FileNotFoundError as exc:
            print(exc, file=sys.stderr)
            return 1
        c = s["counts"]
        tools = ", ".join(k for k, v in s["tools"].items() if v) or "none"
        print("%s: %d files -> %d extracted (%d chars), %d reused, %d empty, %d unsupported, "
              "%d skipped, %d errors; tools: %s -> %s"
              % (m.id, c["files"], c["ok"], s["chars"], c["reused"], c["empty"],
                 c["unsupported"], c["skipped"], c["error"], tools, out))
        return 2 if c["error"] else 0

    if args.cmd == "walk":
        try:
            m = load_manifest(args.path, require_signed=args.require_signed)
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        out = args.out or default_out(m)
        s = walk(m, out, do_hash=not args.no_hash)
        c = s["counts"]
        print("%s: walked %d entries, %d files (%d bytes), %d dirs, %d links; "
              "%d hashed, %d reused, %d too large, %d excluded, %d errors -> %s"
              % (m.id, s["entries"], c["files"], s["bytes"], c["dirs"], c["symlinks"],
                 c["hashed"], c["hash_reused"], c["too_large"], c["excluded"],
                 c["errors"], out))
        for r in s["roots"]:
            if r.get("error"):
                print("  root %d %s: %s" % (r["index"], r["path"], r["error"]), file=sys.stderr)
        return 2 if c["errors"] else 0

    if args.cmd == "payload":
        try:
            m = load_manifest(args.path)
        except ManifestError as exc:
            print(exc, file=sys.stderr)
            return 1
        sys.stdout.buffer.write(signing_payload(m.raw))
        return 0

    rc = 0
    for path in args.paths:
        try:
            m = load_manifest(path, require_signed=getattr(args, "require_signed", False))
        except ManifestError as exc:
            print(f"{path}:", file=sys.stderr)
            print(exc, file=sys.stderr)
            rc = 1
            continue
        if args.cmd == "validate":
            print(f"{path}: OK — {m.id}, {len(m.stages)} stages, {len(m.grants)} grants, "
                  f"{'signed' if m.signed else 'unsigned'}")
        else:
            _show(m, path)
    return rc


if __name__ == "__main__":
    sys.exit(main())
