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

// apply_seccomp applies the standard seccomp filter that traps on all syscalls except those that can't be processed
int apply_seccomp(void)
{
	// No new privs
	int result = fs_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (result != 0) {
		return result;
	}

	struct sock_filter filter[] = {
		// Check the architecture to make sure the calling program is x86_64
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, CURRENT_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
		// Load the syscall ID
		LD_SYSCALL,
		// Early exit for common syscalls that are frequently used
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_nanosleep, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
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
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 2, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
		// Allow mmap of -1 or 1023 to proceed directly, else trap
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + 4 * sizeof(uint64_t)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, -1, 1, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1023, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
	};
	// Set a seccomp filter
	struct sock_fprog prog = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = (struct sock_filter *)filter,
	};
	result = fs_seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
	if (result == -ENOSYS) {
		result = fs_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&prog, 0, 0);
	}
	return result;
}
