package umbra

// NTSTATUS values used by umbra. ntdll returns a 32-bit NTSTATUS from every
// system service; the top bit signals failure, everything else is a success
// with an informational code.

// StatusUmbraNotFound is the synthetic status returned when the caller asks for
// a syscall that is not present in the resolved ntdll export table. It mirrors
// STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139) so that it is unambiguously a
// failure and cannot be confused with a real service result.
const StatusUmbraNotFound uint32 = 0xC0000139

// NT_SUCCESS reports whether status represents a successful completion, using
// the canonical NT convention (non-negative signed value).
func NT_SUCCESS(status uint32) bool {
	return int32(status) >= 0
}
