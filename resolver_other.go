//go:build !(windows && amd64)

package umbra

import "errors"

// resolve is a stub so the package builds on non-target platforms. Indirect
// syscalls require the Windows amd64 ABI and the PEB walk.
func resolve() (map[uint64]*Syscall, error) {
	return nil, errors.New("umbra: indirect syscalls are only supported on windows/amd64")
}
