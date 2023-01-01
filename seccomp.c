#define _GNU_SOURCE

#include "seccomp.h"

#include "freestanding.h"
#include "axon.h"
#include "telemetry.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <sys/prctl.h>

const char *const empty_string = "";

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

#define OFF_SYSCALL (offsetof(struct seccomp_data, nr))

#if defined(__x86_64__)
#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif
// Mask off the x32 syscall bit
#define LD_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, OFF_SYSCALL), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~__X32_SYSCALL_BIT)
#else
#define LD_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, OFF_SYSCALL)
#endif

#define TRAP_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)

// apply_seccomp applies the standard seccomp filter that traps on exec and any enabled_telemetry
int apply_seccomp(void)
{
	// No new privs
	int result = fs_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (result != 0) {
		return result;
	}

	struct sock_filter filter[256] = {
		// Check the architecture to make sure the calling program is x86_64
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, CURRENT_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
		// Load the syscall ID
		LD_SYSCALL,
		// Early exit for common syscalls that are frequently used
// #if (__NR_write == 1) && (__NR_read == 0)
// 		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, __NR_write, 0, 4),
// #else
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 5, 0),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 4, 0),
// #endif
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_futex, 3, 0),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_epoll_pwait, 2, 0),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_recvfrom, 1, 0),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_sendto, 0, 1),
// 		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		// Only allow execs to the helper via execveat(SELF_FD, "", ..., ..., AT_EMPTY_PATH)
#ifdef __LP64__
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 10),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + sizeof(uint64_t)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)empty_string & 0xffffffffull, 0, 6),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + sizeof(uint64_t) + sizeof(uint32_t)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)empty_string >> 32, 0, 4),
#else
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 8),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + sizeof(uint64_t)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)empty_string, 0, 4),
#endif
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SELF_FD, 0, 2),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + sizeof(uint64_t) * 4), // TODO, get the appropriate arg offset for flags
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AT_EMPTY_PATH, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
#if defined(__x86_64__)
		// TODO: Handle 32-bit __NR_x32_execveat in the trap handler
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 545, 1, 0), // x32's __NR_execveat
#endif
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
		// Disallow closing, duping to, or setting flags on SELF_FD
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_close, 1, 0),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fcntl, 0, 2),
// 		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args)),
// #ifdef __NR_dup2
// 		BPF_JUMP(BPF_JMP+BPF_JA, 3, 0, 0),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup2, 1, 0),
// #else
// 		BPF_JUMP(BPF_JMP+BPF_JA, 2, 0, 0),
// #endif
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup3, 0, 4),
// 		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + 8),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SELF_FD, 1, 0),
// 		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, TELEMETRY_FD, 0, 1),
// 		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO+EBADF),
		// Allow if address matches our syscall function
#ifdef __LP64__
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)&fs_syscall_ret & 0xffffffffull, 0, 3),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + sizeof(uint32_t)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)&fs_syscall_ret >> 32, 0, 1),
#else
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)&fs_syscall_ret, 0, 1),
#endif
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		// Trap all but specific syscalls
		LD_SYSCALL,
#ifdef STACK_PROTECTOR
		// Stack protector requires to be able to send __NR_arch_prctl before
		// the trap handler is installed
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_arch_prctl, 9, 0),
#endif
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_futex, 8, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_pread64, 0, 2),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SELF_FD, 5, 6),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone, 0, 2),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args)),
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, CLONE_VM, 2, 3),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rt_sigreturn, 1, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
		0,
	};
	// write_int(2, ((uintptr_t)&fs_syscall_ret));
	unsigned short i = 0;
	while (filter[i].code) {
		++i;
	}
	// if (enabled_telemetry & (TELEMETRY_TYPE_OPEN_READ_ONLY | TELEMETRY_TYPE_OPEN_FOR_MODIFY)) {
		// filter[i++] = TRAP_SYSCALL(stat);
		// filter[i++] = TRAP_SYSCALL(fstat);
		// filter[i++] = TRAP_SYSCALL(lstat);
		// filter[i++] = TRAP_SYSCALL(access);
		// filter[i++] = TRAP_SYSCALL(kill);
		// filter[i++] = TRAP_SYSCALL(chdir);
		// filter[i++] = TRAP_SYSCALL(fchdir);
		// filter[i++] = TRAP_SYSCALL(rename);
		// filter[i++] = TRAP_SYSCALL(mkdir);
		// filter[i++] = TRAP_SYSCALL(rmdir);
		// filter[i++] = TRAP_SYSCALL(creat);
		// filter[i++] = TRAP_SYSCALL(link);
		// filter[i++] = TRAP_SYSCALL(unlink);
		// filter[i++] = TRAP_SYSCALL(symlink);
		// filter[i++] = TRAP_SYSCALL(readlink);
		// filter[i++] = TRAP_SYSCALL(mknod);
		// filter[i++] = TRAP_SYSCALL(mount);
		// filter[i++] = TRAP_SYSCALL(umount2);
		// filter[i++] = TRAP_SYSCALL(getxattr);
		// filter[i++] = TRAP_SYSCALL(lgetxattr);
		// filter[i++] = TRAP_SYSCALL(fgetxattr);
		// filter[i++] = TRAP_SYSCALL(listxattr);
		// filter[i++] = TRAP_SYSCALL(llistxattr);
		// filter[i++] = TRAP_SYSCALL(flistxattr);
		// filter[i++] = TRAP_SYSCALL(mkdirat);
		// filter[i++] = TRAP_SYSCALL(mknodat);
		// filter[i++] = TRAP_SYSCALL(newfstatat);
		// filter[i++] = TRAP_SYSCALL(unlinkat);
		// filter[i++] = TRAP_SYSCALL(renameat);
		// filter[i++] = TRAP_SYSCALL(linkat);
		// filter[i++] = TRAP_SYSCALL(renameat);
		// filter[i++] = TRAP_SYSCALL(symlinkat);
		// filter[i++] = TRAP_SYSCALL(readlinkat);
		// filter[i++] = TRAP_SYSCALL(open_by_handle_at);
		// filter[i++] = TRAP_SYSCALL(renameat2);
		// filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	// }
	if (enabled_telemetry & TELEMETRY_TYPE_DELETE) {
#ifdef __NR_unlink
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_unlink, 2, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rmdir, 1, 0);
#endif
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_unlinkat, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_RENAME) {
#ifdef __NR_rename
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rename, 2, 0);
#endif
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_renameat, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_renameat2, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_HARDLINK) {
#ifdef __NR_link
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_link, 1, 0);
#endif
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_linkat, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_SYMLINK) {
#ifdef __NR_link
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_symlink, 1, 0);
#endif
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_symlinkat, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & (TELEMETRY_TYPE_ATTRIBUTE_CHANGE | TELEMETRY_TYPE_CHMOD)) {
		// TODO: Support extended attributes
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setxattr, 14, 0);
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_lsetxattr, 13, 0);
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fsetxattr, 12, 0);
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_removexattr, 11, 0);
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_lremovexattr, 10, 0);
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fremovexattr, 9, 0);
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_utimes, 8, 0);
		// filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_futimesat, 7, 1);
#if defined(__NR_chmod) && defined(__NR_chown) && defined(__NR_lchown)
		// should be true on x86_64 only
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_chmod, 6, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_chown, 5, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_lchown, 4, 0);
#endif
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fchmod, 3, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fchmodat, 2, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fchown, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fchownat, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_UPDATE_WORKING_DIR) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_chdir, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fchdir, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_PTRACE) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ptrace, 2, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_process_vm_readv, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_process_vm_writev, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & (TELEMETRY_TYPE_CONNECT | TELEMETRY_TYPE_CONNECT_CLOUD)) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_connect, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_BPF) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_bpf, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_BRK) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_brk, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_IOCTL) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ioctl, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_LISTEN) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_listen, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_BIND) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_bind, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_DUP) {
#ifdef __NR_dup2
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup2, 3, 0);
#endif
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup, 2, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup3, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fcntl, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_RLIMIT) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setrlimit, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_prlimit64, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_USER_FAULT) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_userfaultfd, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_SETUID) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setuid, 3, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setreuid, 2, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setresuid, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setfsuid, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_SETGID) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setgid, 3, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setregid, 2, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setresgid, 1, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setfsgid, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_SENDTO) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_sendto, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_MEMORY_PROTECTION) {
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mprotect, 0, 5);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args));
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_ALU+BPF_AND+BPF_K, PROT_EXEC, 0, 0);
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PROT_EXEC, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW);
	}
	if (enabled_telemetry & TELEMETRY_TYPE_ACCEPT) {
#ifdef __NR_accept4
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_accept4, 1, 0);
#endif
		filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_accept, 0, 1);
		filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	}
#ifdef __NR_fork
	filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fork, 7, 0);
	filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_vfork, 6, 0);
#endif
	filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_munmap, 5, 0);
	filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit, 4, 0);
	filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit_group, 3, 0);
	filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone, 0, 3);
	filter[i++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args));
	filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, CLONE_VM, 1, 0);
	filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP);
	filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW);
	// Set a seccomp filter
	struct sock_fprog prog = {
		.len = i,
		.filter = (struct sock_filter *)filter,
	};
	result = fs_seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
	if (result == -ENOSYS) {
		result = fs_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&prog, 0, 0);
	}
	return result;
}
