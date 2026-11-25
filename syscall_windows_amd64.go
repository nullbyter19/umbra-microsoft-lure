//go:build windows && amd64

package umbra

// invoke runs a single indirect syscall.
//
// The service number is placed in RAX and control jumps to gate, a `syscall;ret`
// instruction pair inside ntdll. Executing the transition from ntdll means the
// return address the kernel sees is legitimate ntdll code, defeating simple
// "return address outside a module" checks. The first service argument is moved
// into R10 to mirror what a real ntdll stub does before `syscall`.
//
// Defined in syscall_windows_amd64.s.
func invoke(ssn uint16, gate uintptr, args ...uintptr) uint32
