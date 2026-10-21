#!/usr/bin/env bash
# Publish the bastion agent distributable to the public edges. It is served at
# BOTH addresses, because one of them is compiled into every bastion already
# installed:
#
#   new     https://privatae.ai/bastion-agent/version.json
#   legacy  https://privatae.ai/freeagent/version.json
#
# Those are two Caddy paths over ONE directory on each edge (WEBROOT below).
# There is a single copy of every file; the new address is an alias, so the two
# addresses can never drift or fall out of step at release time.
#
# THE LEGACY NAME, and when it ends. A bastion older than 0.20.0 knows only the
# legacy address, builds the artifact's filename itself and asks the manifest
# for `freeagent-<ver>.pyz`. If that address answers with a manifest that lists
# only the new name, the bastion gets "no entry" and loses the agent; if the
# address does not answer at all, the bastion keeps the agent it has. So:
#
#   - while the legacy address is served, every publish writes the SAME BYTES
#     under BOTH filenames and lists both, each with the same sha256;
#   - once it is not served (it answers 404), a publish writes the new name only.
#
# The script reads which of the two is true on every run, on every edge, so it
# cannot publish the one combination that strands a machine. Retiring the legacy address is a
# step on the edges, taken once the published bastion is 0.42.0 or later (the
# first release that never reads it); docs/packaging.md has it.
#
# The bastion's own deploy/publish.sh is the model: build
# reproducibly, write a manifest with a sha256 per file, upload to EVERY edge,
# then verify each edge's bytes against the manifest IT serves. Same key, same
# edges, same webroot walls (Caddy refuses backups and dotfiles under both paths).
#
# Ratchet: refuse to publish a version that is not strictly newer than the one
# already published (a rebuilt older version would regress installers that
# compare versions). Override deliberately with ALLOW_REPUBLISH=1.
set -euo pipefail
# Repo root. This script sits in bastion_agent/, which is a top-level package
# here, hence one `..`.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# WHERE THIS PUBLISHES IS NOT BAKED IN. This repository is read by everyone who
# runs the agent, so it names no host, no key path and no webroot of ours: the
# three below are required, and an unset one stops the script with a message
# rather than publishing somewhere wrong. Whoever cuts a release supplies them.
: "${KEY:?set KEY to the ssh key that reaches the edges}"
# EDGE (one box) satisfies the requirement on its own -- it is the documented
# single-box override below, and checking EDGES first would kill it with an error
# naming a variable the operator was never told to set.
if [ -n "${EDGE:-}" ]; then EDGES="$EDGE"; fi
: "${EDGES:?set EDGES to the space-separated edge hosts to publish to (or EDGE=<one> for a single box)}"
: "${WEBROOT:?set WEBROOT to the directory on each edge that both URLs serve}"
: "${BACKUP_DIR:?set BACKUP_DIR to a directory OUTSIDE the webroot for rotated installers}"
# OUTSIDE is load-bearing: a backup inside the webroot is served at a stable public
# URL, which is how a superseded installer stays reachable forever. Assert it.
case "$BACKUP_DIR" in
  "$WEBROOT"|"$WEBROOT"/*)
    echo "BACKUP_DIR ($BACKUP_DIR) is inside WEBROOT ($WEBROOT) -- rotated installers would be served publicly" >&2
    exit 1;;
esac
# The manifest is signed with the bastion's release key, which never comes to
# this machine: it stays on the key holder's own computer. So a publish runs
# twice. The first run builds, writes the manifest and prints the one
# release-sign command to run there; the second, with SIGNATURE=<the line it
# printed>, rebuilds (the build is reproducible, so the manifest is the same
# bytes), checks the signature against the keys the bastion pins, and
# publishes. BASTION_TREE is a checkout of privatae-bastion at the release the
# fleet is moving to: its deploy/release-verify.sh and pinned keys are what a
# bastion will check this manifest against.
: "${BASTION_TREE:?set BASTION_TREE to a privatae-bastion checkout (its deploy/release-verify.sh checks the signature)}"
[ -x "$BASTION_TREE/deploy/release-verify.sh" ] || { echo "$BASTION_TREE has no deploy/release-verify.sh" >&2; exit 1; }
# The bastions that will read this manifest run the published bastion release,
# and check it with the keys THAT release pins. So the signature is held to
# those keys too, not only to BASTION_TREE's.
FLEET_FROM="$(curl -fsS --max-time 15 https://privatae.ai/bastion/version.json | python3 -c 'import sys,json;print(json.load(sys.stdin).get("built_from",""))' 2>/dev/null || true)"
git -C "$BASTION_TREE" fetch -q origin 2>/dev/null || true
if [ -n "$FLEET_FROM" ] && ! git -C "$BASTION_TREE" cat-file -e "$FLEET_FROM^{commit}" 2>/dev/null; then
  echo "BASTION_TREE does not have the published bastion commit $FLEET_FROM; fetch it first" >&2
  exit 1
fi
BASE_NEW="https://privatae.ai/bastion-agent"
BASE_OLD="https://privatae.ai/freeagent"

VER="$(tr -d '[:space:]' < "$HERE/bastion_agent/VERSION")"
# Is the legacy address still served? It is asked of EVERY edge, not only of
# the one the public name reaches now: each edge serves from its own disk and
# its own Caddy config, and an edge that still has the route would serve a
# manifest without the legacy name the day traffic fails over to it. Each edge
# is asked for the route in the config Caddy has loaded (its local admin API).
# Anything but a clear "no route" (an answer, a timeout, an error) counts as
# served, because writing the legacy name when it is not needed costs one extra
# file, and leaving it out when it is needed costs every old bastion its agent.
# The public address is asked too, and a 404 there is also required.
# Counts the routes whose path matcher would take /freeagent/version.json,
# however the matcher is spelled (/freeagent/*, /freeagent*, a regexp), which
# covers handle, handle_path and redir alike. Anything unreadable is "unknown".
ROUTES_PY='
import fnmatch, json, re, sys
try:
    cfg = json.load(sys.stdin)
except Exception:
    print("unknown"); sys.exit()
if not isinstance(cfg, dict) or "apps" not in cfg:
    print("unknown"); sys.exit()
target = "/freeagent/version.json"
n = 0
def walk(o):
    global n
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "path" and isinstance(v, list) and any(isinstance(p, str) and fnmatch.fnmatchcase(target, p) and p not in ("*", "/*") for p in v):
                n += 1
            elif k == "path_regexp" and isinstance(v, dict) and isinstance(v.get("pattern"), str):
                try:
                    if re.search(v["pattern"], target) and "freeagent" in v["pattern"].lower():
                        n += 1
                except re.error:
                    n += 1
            walk(v)
    elif isinstance(o, list):
        for x in o:
            walk(x)
walk(cfg)
print(n)
'
LEGACY=0
for E in $EDGES; do
  n="$(ssh -n -i "$KEY" "$E" 'curl -fsS --max-time 10 http://localhost:2019/config/' 2>/dev/null \
       | python3 -c "$ROUTES_PY" 2>/dev/null || true)"
  if [ "$n" = 0 ]; then echo "  $E: no /freeagent route"
  else LEGACY=1; echo "  $E: /freeagent route ${n:-unknown} (served)"; fi
done
LEGACY_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$BASE_OLD/version.json" 2>/dev/null || true)"
[ "$LEGACY_CODE" = 404 ] || LEGACY=1
if [ "$LEGACY" = 0 ]; then echo "legacy address retired on every edge (public: 404): publishing the new name only"
else echo "legacy address still served somewhere (public: HTTP ${LEGACY_CODE:-none}): publishing both names"; fi
GITSHA="$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "publishing bastion agent v$VER ($GITSHA)"

# Both addresses serve one directory, so the new one is the record of what is
# published, and it stays served after the legacy one is retired.
CUR="$(curl -fsS --max-time 15 "$BASE_NEW/version.json" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("version",""))' 2>/dev/null || true)"
if [ -n "$CUR" ]; then
  newer="$(python3 -c 'import sys
a=[int(x) for x in sys.argv[1].split(".")]; b=[int(x) for x in sys.argv[2].split(".")]
print("yes" if a>b else "no")' "$VER" "$CUR")"
  if [ "$newer" = yes ]; then echo "ratchet ok: $CUR -> $VER"; else
    echo "RATCHET REFUSED: v$VER is not newer than published v$CUR (ALLOW_REPUBLISH=1 to override)" >&2
    [ "${ALLOW_REPUBLISH:-}" = "1" ] || exit 1
  fi
fi

DIST="$HERE/dist"
(cd "$HERE" && python3 -m bastion_agent.build --out dist >/dev/null)
PYZ="$DIST/bastion-agent-$VER.pyz"
[ -f "$PYZ" ] || { echo "build did not produce $PYZ" >&2; exit 1; }
python3 "$PYZ" --version >/dev/null

UPLOAD=("$PYZ" "$PYZ.sha256")
if [ "$LEGACY" = 1 ]; then
  # The same bytes under the legacy filename, for bastions that ask for it by name.
  LEGACY_PYZ="$DIST/freeagent-$VER.pyz"
  cp -f "$PYZ" "$LEGACY_PYZ"
  sed "s|bastion-agent-$VER.pyz|freeagent-$VER.pyz|" "$PYZ.sha256" > "$LEGACY_PYZ.sha256"
  # Prove they are the same artifact rather than assuming the copy worked.
  a="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$PYZ")"
  b="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$LEGACY_PYZ")"
  [ "$a" = "$b" ] || { echo "the two filenames do not carry the same bytes" >&2; exit 1; }
  echo "artifact: $a (published under both names)"
  UPLOAD+=("$LEGACY_PYZ" "$LEGACY_PYZ.sha256")
fi

python3 - "$VER" "$GITSHA" "$DIST" "$HERE/bastion_agent" "$BASE_NEW" "$BASE_OLD" "$LEGACY" > "$DIST/version.json" <<'PY'
import sys, os, hashlib, json
ver, sha, dist, pkg, base_new, base_old, legacy = sys.argv[1:8]
def h(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
def entry(name, base):
    p = os.path.join(dist, name)
    return name, {"url": "%s/dl/%s" % (base, name), "sha256": h(p), "bytes": os.path.getsize(p)}

files = {}
names = [("bastion-agent-%s.pyz" % ver, base_new),
         ("bastion-agent-%s.pyz.sha256" % ver, base_new)]
# While the legacy address is served, the legacy pair is what a bastion older
# than 0.20.0 asks for by name; leave it out and that bastion loses the agent.
if legacy == "1":
    names += [("freeagent-%s.pyz" % ver, base_old),
              ("freeagent-%s.pyz.sha256" % ver, base_old)]
for name, base in names:
    k, v = entry(name, base)
    files[k] = v

installers = {n: {"url": "%s/%s" % (base_new, n), "sha256": h(os.path.join(pkg, n))}
              for n in ("install.sh", "install.ps1")}
json.dump({"version": ver, "built_from": sha, "python_floor": "3.8",
           "files": files, "installers": installers,
           "notes": "https://git.privatae.ai/privatae/bastion-agent/releases/tag/v%s" % ver},
          sys.stdout, indent=2)
PY

MAN="$DIST/version.json"
MAN_SHA="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$MAN")"
if [ -z "${SIGNATURE:-}" ]; then
  cat <<ASK

Built bastion agent v$VER. Nothing has been published.

On the computer that holds the release key, run:

    release-sign sign bastion-agent $VER $MAN_SHA

then run this again with the line it prints:

    SIGNATURE='<that line>' bastion_agent/publish.sh

ASK
  exit 3
fi
# Named by the manifest's digest, the name a bastion asks for; old ones are
# never removed, so a bastion that read the previous manifest a moment ago
# still finds its signature.
SIG_NAME="version.json.${MAN_SHA:0:16}.sig"
printf '%s\n' "$SIGNATURE" > "$DIST/$SIG_NAME"
SIGNED_BY="$("$BASTION_TREE/deploy/release-verify.sh" bastion-agent "$MAN" "$DIST/$SIG_NAME" ${FLEET_FROM:+"$FLEET_FROM"})" \
  || { echo "SIGNATURE does not verify for bastion agent v$VER (manifest $MAN_SHA); nothing was published." >&2
       echo "If the key holder signed the command the first run printed, compare the 'legacy address' lines of the two runs: a change on the edges between them changes the manifest." >&2
       exit 1; }
echo "manifest signature ok (key $SIGNED_BY)"

for E in $EDGES; do
  echo "--- publishing to $E ---"
  ssh -i "$KEY" "$E" 'rm -rf /tmp/ba && mkdir -p /tmp/ba'
  scp -q -i "$KEY" "${UPLOAD[@]}" "$DIST/version.json" "$DIST/$SIG_NAME" \
    "$HERE/bastion_agent/install.sh" "$HERE/bastion_agent/install.ps1" "$E":/tmp/ba/
  ssh -i "$KEY" "$E" "
    set -e
    install -d -m755 \"$WEBROOT/dl\"
    install -d -m700 \"$BACKUP_DIR\"
    ts=\$(date +%s)
    for f in install.sh install.ps1 version.json; do cp -a \"$WEBROOT/\$f\" \"$BACKUP_DIR/\$f.bak-\$ts\" 2>/dev/null || true; done
    for f in /tmp/ba/bastion-agent-* /tmp/ba/freeagent-*; do [ -e \"\$f\" ] || continue; b=\$(basename \"\$f\"); mv \"\$f\" \"$WEBROOT/dl/\$b\"; chmod 644 \"$WEBROOT/dl/\$b\"; done
    # The signature lands before the manifest it signs.
    for f in /tmp/ba/version.json.*.sig; do b=\$(basename \"\$f\"); mv \"\$f\" \"$WEBROOT/\$b\"; chmod 644 \"$WEBROOT/\$b\"; done
    for f in version.json install.sh install.ps1; do mv /tmp/ba/\$f \"$WEBROOT/\$f\"; chmod 644 \"$WEBROOT/\$f\"; done
    rm -rf /tmp/ba"
done

# Verify each edge against the manifest IT serves, and, while the legacy address
# is served, assert the legacy entries are present: their absence is the failure
# that strands old bastions.
for E in $EDGES; do
  printf '  %s: ' "$E"
  ssh -i "$KEY" "$E" "cd $WEBROOT && LEGACY=$LEGACY python3 - <<VERIFY
import hashlib, json, os, sys
m = json.load(open('version.json'))
bad = []
for name, v in m['files'].items():
    p = os.path.join('dl', name)
    if not os.path.exists(p): bad.append(name + ' MISSING'); continue
    if hashlib.sha256(open(p, 'rb').read()).hexdigest() != v['sha256']: bad.append(name + ' DIGEST-MISMATCH')
for name, v in m['installers'].items():
    if not os.path.exists(name): bad.append(name + ' MISSING'); continue
    if hashlib.sha256(open(name, 'rb').read()).hexdigest() != v['sha256']: bad.append(name + ' DIGEST-MISMATCH')
sig = 'version.json.%s.sig' % hashlib.sha256(open('version.json', 'rb').read()).hexdigest()[:16]
if not os.path.exists(sig): bad.append(sig + ' MISSING')
legacy = [n for n in m['files'] if n.startswith('freeagent-')]
if os.environ.get('LEGACY') == '1' and not legacy: bad.append('NO LEGACY ENTRY - old bastions would lose the agent')
print(('VERIFY FAILED: ' + '; '.join(bad)) if bad else
      'ok - %d files + %d installers match the manifest (v%s)%s' % (len(m['files']), len(m['installers']), m['version'],
      ', legacy entries present' if legacy else ''))
sys.exit(1 if bad else 0)
VERIFY"
done

# From the public internet, at every address still served, the way a bastion asks
# (version.json.<first 8 bytes of the manifest's sha256>.sig), checked against
# the manifest that address serves and the keys the bastion pins.
SIGCHECK="$(mktemp -d)"; trap 'rm -rf "$SIGCHECK"' EXIT
# The legacy address is checked from outside only when it answers there: while
# edges disagree, the public name may reach one that no longer has the route,
# and the per-edge check above has already held every edge's files to the
# manifest.
ADDRS=("$BASE_NEW"); [ "$LEGACY" = 1 ] && [ "$LEGACY_CODE" != 404 ] && ADDRS+=("$BASE_OLD")
for B in "${ADDRS[@]}"; do
  curl -fsS --max-time 30 "$B/version.json" -o "$SIGCHECK/m"
  H="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$SIGCHECK/m")"
  curl -fsS --max-time 30 "$B/version.json.$H.sig" -o "$SIGCHECK/s" \
    || { echo "  VERIFY FAILED: $B/version.json.$H.sig is not served publicly" >&2; exit 1; }
  if "$BASTION_TREE/deploy/release-verify.sh" bastion-agent "$SIGCHECK/m" "$SIGCHECK/s" ${FLEET_FROM:+"$FLEET_FROM"} >/dev/null; then
    echo "  $B/version.json.$H.sig ok"
  else
    echo "  VERIFY FAILED: $B/version.json.$H.sig does not verify against the manifest served there" >&2
    exit 1
  fi
done

echo "published bastion agent v$VER to: $EDGES"
echo "  new:    $BASE_NEW/version.json  ·  $BASE_NEW/dl/bastion-agent-$VER.pyz"
if [ "$LEGACY" = 1 ]; then
  echo "  legacy: $BASE_OLD/version.json  ·  $BASE_OLD/dl/freeagent-$VER.pyz"
fi
