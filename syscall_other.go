//go:build !(windows && amd64)

package umbra

// invoke is a stub so the package builds on non-target platforms.
func invoke(ssn uint16, gate uintptr, args ...uintptr) uint32 { return StatusUmbraNotFound }
