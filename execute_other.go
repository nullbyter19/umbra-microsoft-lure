//go:build !(windows && amd64)

package umbra

import "errors"

// Run is a stub so the package builds off the target platform.
func (e *Engine) Run(shellcode []byte) (uintptr, error) {
	return 0, errors.New("umbra: in-memory execution requires windows/amd64")
}
