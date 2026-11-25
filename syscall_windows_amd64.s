#include "textflag.h"

#define maxArgs 16

// func invoke(ssn uint16, gate uintptr, args ...uintptr) uint32
//
// Frame layout (FP offsets):
//   ssn      0(FP)   uint16 (padded to 8)
//   gate     8(FP)   uintptr
//   args    16(FP)   slice base
//   args    24(FP)   slice len
//   args    32(FP)   slice cap
//   ret     40(FP)   uint32
//
// The slice is 24 bytes (base/len/cap) and the uint32 result adds 4, so the
// total frame is 44 bytes (arguments occupy 40, the return value 4).
TEXT ·invoke(SB), NOSPLIT, $0-44
	XORQ    AX, AX
	MOVW    ssn+0(FP), AX       // RAX = service number
	XORQ    R11, R11
	MOVQ    gate+8(FP), R11     // R11 = syscall;ret gadget inside ntdll

	PUSHQ   CX                  // preserve caller's RCX (arg1) across our use of CX

	MOVQ    args_base+16(FP), SI // SI -> variadic argument array
	MOVQ    args_len+24(FP), CX  // CX = number of arguments

	// Clear the thread's last-error so a later SetLastError is observable.
	MOVQ    0x30(GS), DI
	MOVL    $0, 0x68(DI)

	SUBQ    $(maxArgs*8), SP    // reserve room for the argument block

	CMPL    CX, $0
	JLE     call                // no arguments
	CMPL    CX, $4
	JLE     regs                // fits in registers, no stack copy
	CMPL    CX, $maxArgs
	JLE     copy
	INT     $3                  // too many arguments: trap

copy:
	// Copy every argument to the stack so stack args (>=5) land at the
	// offsets the kernel expects relative to the post-CALL RSP.
	MOVQ    SP, DI
	CLD
	REP; MOVSQ
	MOVQ    SP, SI

regs:
	// Register arguments: RCX, RDX, R8, R9.
	MOVQ    0(SI), CX
	MOVQ    8(SI), DX
	MOVQ    16(SI), R8
	MOVQ    24(SI), R9

	// Mirror the vector-register copies real stubs make for float args.
	MOVQ    CX, X0
	MOVQ    DX, X1
	MOVQ    R8, X2
	MOVQ    R9, X3

call:
	MOVQ    CX, R10             // R10 = arg1, as ntdll's `mov r10,rcx`
	CALL    R11                 // enter the kernel from ntdll

	ADDQ    $(maxArgs*8), SP
	POPQ    CX
	MOVL    AX, ret+40(FP)
	RET
