#!/usr/bin/env sh
# bastion agent installer — Linux and macOS. POSIX sh, no root, no downloads.
#   sh install.sh dist/bastion-agent-0.1.7.pyz
# Puts `bastion-agent` on your PATH (~/.local/bin) and runs the preflight.
#
# This is the HAND install. The managed path — the bastion deploying the agent
# from a grant — does not use this script.
set -eu
PYZ="${1:?usage: install.sh <bastion-agent-X.Y.Z.pyz>}"
# FREEAGENT_BIN_DIR keeps its name deliberately: the six FREEAGENT_* variables
# are the contract the bastion sets when it spawns the agent, and renaming them
# here would break every bastion that still sets the old ones. They move in
# their own compatibility window, not this one.
BIN="${BASTION_AGENT_BIN_DIR:-${FREEAGENT_BIN_DIR:-$HOME/.local/bin}}"
PY="$(command -v python3 || true)"
[ -n "$PY" ] || { echo "python3 is required (3.8 or newer); none on PATH" >&2; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
    || { echo "python3 is older than 3.8: $("$PY" --version)" >&2; exit 1; }
if [ -f "${PYZ}.sha256" ]; then
    (cd "$(dirname "$PYZ")" && { command -v sha256sum >/dev/null && sha256sum -c "$(basename "$PYZ").sha256" \
        || shasum -a 256 -c "$(basename "$PYZ").sha256"; }) >/dev/null \
        && echo "checksum ok" || { echo "checksum MISMATCH — refusing to install" >&2; exit 1; }
fi
mkdir -p "$BIN"
cp "$PYZ" "$BIN/bastion-agent.pyz"
printf '#!/usr/bin/env sh\nexec python3 "%s/bastion-agent.pyz" "$@"\n' "$BIN" > "$BIN/bastion-agent"
chmod 755 "$BIN/bastion-agent" "$BIN/bastion-agent.pyz"
# An earlier hand install left a `freeagent` wrapper pointing at a file this
# install replaces. Repoint it rather than leaving it broken on someone's PATH;
# it is the same program under its old name.
if [ -f "$BIN/freeagent" ]; then
    printf '#!/usr/bin/env sh\n# renamed to bastion-agent; this wrapper kept so an old habit still works\nexec python3 "%s/bastion-agent.pyz" "$@"\n' "$BIN" > "$BIN/freeagent"
    chmod 755 "$BIN/freeagent"
    rm -f "$BIN/freeagent.pyz" "$BIN/bastion_agent.pyz"
    echo "note: kept $BIN/freeagent working — it now runs bastion-agent"
fi
echo "installed $BIN/bastion-agent ($("$BIN/bastion-agent" --version))"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "note: add $BIN to PATH";; esac
echo
"$BIN/bastion-agent" doctor || true
echo
echo "next: put your manifest at ~/.config/bastion-agent/manifest.yaml, set FREEAGENT_OWNER_RECIPIENT"
echo "      (age-keygen), then: bastion-agent sweep ~/.config/bastion-agent/manifest.yaml --once"
