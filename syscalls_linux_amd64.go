package sandbox

import "golang.org/x/sys/unix"

// auditArch is the architecture the filter allows, as seccomp reports it.
// A system call through the 32-bit ABI reports another and is refused.
const auditArch = unix.AUDIT_ARCH_X86_64

// x32Bit marks a system call made through the x32 ABI, whose numbers the
// filter's list does not describe, so it is refused.
const x32Bit = 0x40000000

// archSyscalls are the system calls KernelStrict allows on amd64 beyond
// commonSyscalls: the older calls arm64 never had, and arch_prctl and
// modify_ldt, which Docker allows on x86.
var archSyscalls = []uint32{
	unix.SYS_ACCESS, unix.SYS_ALARM, unix.SYS_ARCH_PRCTL, unix.SYS_CHMOD,
	unix.SYS_CHOWN, unix.SYS_CREAT, unix.SYS_DUP2, unix.SYS_EPOLL_CREATE,
	unix.SYS_EPOLL_CTL_OLD, unix.SYS_EPOLL_WAIT, unix.SYS_EPOLL_WAIT_OLD,
	unix.SYS_EVENTFD, unix.SYS_FORK, unix.SYS_FUTIMESAT,
	unix.SYS_GET_THREAD_AREA, unix.SYS_GETDENTS, unix.SYS_GETPGRP,
	unix.SYS_INOTIFY_INIT, unix.SYS_LCHOWN, unix.SYS_LINK, unix.SYS_LSTAT,
	unix.SYS_MKDIR, unix.SYS_MKNOD, unix.SYS_MODIFY_LDT, unix.SYS_OPEN,
	unix.SYS_PAUSE, unix.SYS_PIPE, unix.SYS_POLL, unix.SYS_READLINK,
	unix.SYS_RENAME, unix.SYS_RMDIR, unix.SYS_SELECT, unix.SYS_SET_THREAD_AREA,
	unix.SYS_SIGNALFD, unix.SYS_STAT, unix.SYS_SYMLINK, unix.SYS_TIME,
	unix.SYS_UNLINK, unix.SYS_URETPROBE, unix.SYS_UTIME, unix.SYS_UTIMES,
	unix.SYS_VFORK,
}
