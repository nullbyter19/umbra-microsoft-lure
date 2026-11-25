#include "textflag.h"

// func pebLdr() uintptr
//
// Returns PEB_LDR_DATA*, reached via TEB -> PEB -> Ldr. The caller walks
// InMemoryOrderModuleList from there and identifies modules by name, so no
// module ordering or string is hard-coded in assembly.
TEXT ·pebLdr(SB), NOSPLIT, $0-8
	MOVQ 0x30(GS), AX   // TEB
	MOVQ 0x60(AX), AX   // PEB
	MOVQ 0x18(AX), AX   // PEB->Ldr (PEB_LDR_DATA*)
	MOVQ AX, ret+0(FP)
	RET
