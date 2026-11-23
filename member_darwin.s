#include "textflag.h"

// The trampoline to libSystem's sandbox_check, which member_darwin.go calls.
// The package builds without cgo, so the symbol is imported dynamically and
// reached through this address, as golang.org/x/sys/unix reaches its libc
// calls.
TEXT libc_sandbox_check_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_check(SB)

GLOBL	·libc_sandbox_check_trampoline_addr(SB), RODATA, $8
DATA	·libc_sandbox_check_trampoline_addr(SB)/8, $libc_sandbox_check_trampoline<>(SB)
