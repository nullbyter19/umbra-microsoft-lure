package umbra

import "testing"

func TestHashCaseInsensitive(t *testing.T) {
	if Hash("NtAllocateVirtualMemory") != Hash("ntallocatevirtualmemory") {
		t.Fatal("Hash must fold ASCII upper case to lower case")
	}
}

func TestHashDistinct(t *testing.T) {
	seen := map[uint64]string{}
	for _, n := range []string{
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtWaitForSingleObject",
		"NtFreeVirtualMemory",
	} {
		h := Hash(n)
		if h == 0 {
			t.Fatalf("Hash(%q) must not be zero", n)
		}
		if prev, dup := seen[h]; dup {
			t.Fatalf("collision between %q and %q", prev, n)
		}
		seen[h] = n
	}
}

// TestPrecomputedConstants guards the numeric hashes in hash.go against drift:
// if Hash ever changes, this fails so the constants cannot silently go stale.
func TestPrecomputedConstants(t *testing.T) {
	cases := []struct {
		h    uint64
		name string
	}{
		{HashAllocVM, "NtAllocateVirtualMemory"},
		{HashWriteVM, "NtWriteVirtualMemory"},
		{HashProtectVM, "NtProtectVirtualMemory"},
		{HashCreateThread, "NtCreateThreadEx"},
		{HashWaitForObject, "NtWaitForSingleObject"},
		{HashFreeVM, "NtFreeVirtualMemory"},
		{HashNtdll, "ntdll.dll"},
	}
	for _, c := range cases {
		if got := Hash(c.name); got != c.h {
			t.Fatalf("constant for %q drifted: 0x%016x != Hash() 0x%016x", c.name, c.h, got)
		}
	}
}
