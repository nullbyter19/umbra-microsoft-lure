// Package umbra resolves Windows NT system services at runtime and executes
// them through indirect syscalls.
//
// Instead of importing ntdll function pointers (which leaves import-table
// strings an EDR can hook and alert on), umbra walks the process PEB to find
// ntdll, parses its export table in memory, derives each service number from
// the export ordering and jumps to a real `syscall;ret` gadget inside ntdll.
// The kernel therefore always returns to a legitimate ntdll address.
//
// The package is pure Go apart from two tiny assembly helpers (PEB lookup and
// the syscall stub) and has no external dependencies.
package umbra

import "fmt"

// Syscall describes a single resolved NT system service.
type Syscall struct {
	Name string  // canonical Nt* name
	Hash uint64  // Hash(Name)
	RVA  uint32  // export RVA inside ntdll
	Addr uintptr // ntdll base + RVA (address of the real stub)
	SSN  uint16  // system service number, derived from export order
	Gate uintptr // address of a `syscall;ret` gadget inside ntdll
}

// Engine holds the resolved service table and runs indirect syscalls.
type Engine struct {
	table map[uint64]*Syscall
}

// New resolves the in-memory ntdll export table and returns a ready Engine.
func New() (*Engine, error) {
	table, err := resolve()
	if err != nil {
		return nil, err
	}
	return &Engine{table: table}, nil
}

// HashString returns the lookup key for a system service name. Prefer the
// precomputed constants in hash.go (e.g. HashAllocVM) over building a hash from
// a string literal, so the API name never lands in the compiled binary.
func (e *Engine) HashString(s string) uint64 { return Hash(s) }

// GetSyscall returns the resolved service for fnHash, or an error.
func (e *Engine) GetSyscall(fnHash uint64) (*Syscall, error) {
	if s := e.table[fnHash]; s != nil {
		return s, nil
	}
	return nil, fmt.Errorf("umbra: no syscall for hash 0x%x", fnHash)
}

// Count reports how many services were resolved.
func (e *Engine) Count() int { return len(e.table) }

// Syscall performs an indirect syscall. args are passed verbatim as the service
// arguments (uintptr width). The NTSTATUS is returned together with an error
// for the failure case.
func (e *Engine) Syscall(fnHash uint64, args ...uintptr) (uint32, error) {
	s := e.table[fnHash]
	if s == nil {
		return StatusUmbraNotFound, fmt.Errorf("umbra: no syscall for hash 0x%x", fnHash)
	}
	st := invoke(s.SSN, s.Gate, args...)
	if !NT_SUCCESS(st) {
		return st, fmt.Errorf("umbra: %s failed with status 0x%x", s.Name, st)
	}
	return st, nil
}
