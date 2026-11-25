//go:build windows && amd64

package umbra

import (
	"fmt"
	"sort"
	"unsafe"
)

// pebLdr returns PEB_LDR_DATA* (TEB -> PEB -> Ldr).
// Implemented in resolver_windows_amd64.s.
func pebLdr() uintptr

// PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY offsets (x64).
const (
	offInMemoryOrder = 0x20 // PEB_LDR_DATA.InMemoryOrderModuleList
	offDllBase       = 0x20 // node (entry+0x10) -> DllBase (entry+0x30)
	offBaseDllName   = 0x48 // node -> BaseDllName.Length (entry+0x58)
	offBaseDllBuf    = 0x50 // node -> BaseDllName.Buffer (entry+0x60)
)

// PE / export-directory offsets.
const (
	offELfanew  = 0x3C // IMAGE_DOS_HEADER.e_lfanew
	offOptional = 0x18 // PE sig (4) + IMAGE_FILE_HEADER (20)
	offDataDir  = 0x70 // IMAGE_OPTIONAL_HEADER64.DataDirectory[0]

	expNumberOfNames = 0x18 // IMAGE_EXPORT_DIRECTORY fields
	expAddrFuncs     = 0x1C
	expAddrNames     = 0x20
	expAddrOrds      = 0x24

	gateScanLen = 48 // bytes of a stub expected to contain the trampoline
)

// ptrAt turns a raw address into an unsafe.Pointer. unsafe.Add lets the compiler
// and vet accept the conversion while keeping the pointer arithmetic explicit.
//
//go:nocheckptr
func ptrAt(p uintptr) unsafe.Pointer { return unsafe.Add(unsafe.Pointer(nil), p) }

//go:nocheckptr
func rd16(p uintptr) uint16 { return *(*uint16)(ptrAt(p)) }

//go:nocheckptr
func rd32(p uintptr) uint32 { return *(*uint32)(ptrAt(p)) }

//go:nocheckptr
func rdptr(p uintptr) uintptr { return *(*uintptr)(ptrAt(p)) }

// cstr reads a NUL-terminated ASCII string from an absolute address.
//
//go:nocheckptr
func cstr(p uintptr) string {
	var b []byte
	for i := 0; i < 512; i++ {
		c := *(*byte)(ptrAt(p))
		if c == 0 {
			break
		}
		b = append(b, c)
		p++
	}
	return string(b)
}

// cstrW reads nBytes of a UTF-16 string and returns it folded to lower-case
// ASCII. Non-ASCII code units are replaced with '?' so the result is only ever
// used for comparisons against plain module names.
//
//go:nocheckptr
func cstrW(p uintptr, nBytes int) string {
	if nBytes < 2 || nBytes > 520 {
		return ""
	}
	units := unsafe.Slice((*uint16)(ptrAt(p)), nBytes/2)
	b := make([]byte, 0, len(units))
	for _, u := range units {
		if u == 0 {
			break
		}
		c := byte(u)
		if u > 0x7f {
			c = '?'
		} else if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}

// ntdllBase walks InMemoryOrderModuleList and returns the DllBase of the module
// whose base name hashes to HashNtdll, or 0 when it cannot be found. Matching by
// hash avoids embedding the module name as a string literal and avoids
// depending on the exact module ordering, which differs across Windows versions
// and process configurations.
func ntdllBase() uintptr {
	ldr := pebLdr()
	if ldr == 0 {
		return 0
	}
	head := ldr + offInMemoryOrder
	for node := rdptr(head); node != 0 && node != head; node = rdptr(node) {
		nameLen := int(rd16(node + offBaseDllName))
		if nameLen == 0 {
			continue
		}
		buf := rdptr(node + offBaseDllBuf)
		if buf == 0 {
			continue
		}
		if Hash(cstrW(buf, nameLen)) == HashNtdll {
			return rdptr(node + offDllBase)
		}
	}
	return 0
}

// findGate scans a stub for the `syscall;ret` (0F 05 C3) byte sequence and
// returns its address, or 0 when the stub is hooked/padded without one.
//
//go:nocheckptr
func findGate(addr uintptr) uintptr {
	b := unsafe.Slice((*byte)(ptrAt(addr)), gateScanLen)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == 0x0F && b[i+1] == 0x05 && b[i+2] == 0xC3 {
			return addr + uintptr(i)
		}
	}
	return 0
}

// resolve locates ntdll, parses its export table and builds the service table.
func resolve() (map[uint64]*Syscall, error) {
	base := ntdllBase()
	if base == 0 {
		return nil, fmt.Errorf("umbra: could not locate loader module")
	}

	nt := base + uintptr(rd32(base+offELfanew))
	opt := nt + offOptional
	expRVA := rd32(opt + offDataDir)
	if expRVA == 0 {
		return nil, fmt.Errorf("umbra: export directory missing")
	}
	exp := base + uintptr(expRVA)

	nNames := rd32(exp + expNumberOfNames)
	funcs := base + uintptr(rd32(exp+expAddrFuncs))
	names := base + uintptr(rd32(exp+expAddrNames))
	ords := base + uintptr(rd32(exp+expAddrOrds))
	if nNames == 0 || funcs == 0 || names == 0 || ords == 0 {
		return nil, fmt.Errorf("umbra: malformed export table")
	}

	stubs := make([]*Syscall, 0, nNames/4) // Zw* is a minority of exports
	for i := uint32(0); i < nNames; i++ {
		nameRVA := rd32(names + uintptr(i)*4)
		name := cstr(base + uintptr(nameRVA))
		if len(name) < 3 || name[0] != 'Z' || name[1] != 'w' {
			continue
		}
		// ZwFoo is the same service as NtFoo; hash the Nt* spelling.
		nn := "Nt" + name[2:]
		ord := rd16(ords + uintptr(i)*2)
		rva := rd32(funcs + uintptr(uint32(ord))*4)
		if rva == 0 {
			continue
		}
		stubs = append(stubs, &Syscall{
			Name: nn,
			Hash: Hash(nn),
			RVA:  rva,
			Addr: base + uintptr(rva),
		})
	}
	if len(stubs) == 0 {
		return nil, fmt.Errorf("umbra: no NT services resolved")
	}

	// On every supported Windows build the SSN equals the index of the stub
	// once the exports are ordered by RVA.
	sort.Slice(stubs, func(i, j int) bool { return stubs[i].RVA < stubs[j].RVA })

	// Collect gate addresses from un-hooked stubs to donate to hooked ones.
	var fallback uintptr
	for _, s := range stubs {
		if g := findGate(s.Addr); g != 0 {
			s.Gate = g
			if fallback == 0 {
				fallback = g
			}
		}
	}
	if fallback == 0 {
		return nil, fmt.Errorf("umbra: no syscall;ret trampoline found")
	}

	table := make(map[uint64]*Syscall, len(stubs))
	for i, s := range stubs {
		s.SSN = uint16(i)
		if s.Gate == 0 {
			s.Gate = fallback
		}
		table[s.Hash] = s
	}
	return table, nil
}
