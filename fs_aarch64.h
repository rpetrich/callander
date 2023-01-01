#define FS_DEFINE_SYSCALL __asm__( \
".text\n" \
".global fs_syscall\n" \
".hidden fs_syscall\n" \
".type fs_syscall,@function\n" \
"fs_syscall:\n" \
"	svc 0\n" \
".global fs_syscall_ret\n" \
".hidden fs_syscall_ret\n" \
".type fs_syscall_ret,@function\n" \
"fs_syscall_ret:\n" \
"	ret\n" \
);

#include <stdnoreturn.h>

__attribute__((always_inline))
static inline intptr_t fs_syscall0(intptr_t id)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0");
	asm __volatile__ (
		"bl fs_syscall"
		: "=r"(r0)
		: "r"(r8)
		: "memory", "cc", "x30"
	);
	return r0;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall1(intptr_t id, intptr_t arg1)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0") = arg1;
	asm __volatile__ (
		"bl fs_syscall"
		: "=r"(r0)
		: "r"(r8), "r"(r0)
		: "memory", "cc", "x30"
	);
	return r0;
}

__attribute__((always_inline))
noreturn static inline void fs_syscall_noreturn1(intptr_t id, intptr_t arg1)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0") = arg1;
	asm __volatile__ (
		"b fs_syscall"
		:
		: "r"(r8), "r"(r0)
		: "memory"
	);
	__builtin_unreachable();
}

__attribute__((always_inline))
static inline intptr_t fs_syscall2(intptr_t id, intptr_t arg1, intptr_t arg2)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	asm __volatile__ (
		"bl fs_syscall"
		: "=r"(r0)
		: "r"(r8), "r"(r0), "r"(r1)
		: "memory", "cc", "x30"
	);
	return r0;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall3(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	asm __volatile__ (
		"bl fs_syscall"
		: "=r"(r0)
		: "r"(r8), "r"(r0), "r"(r1), "r"(r2)
		: "memory", "cc", "x30"
	);
	return r0;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall4(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	register intptr_t r3 __asm__("x3") = arg4;
	asm __volatile__ (
		"bl fs_syscall"
		: "=r"(r0)
		: "r"(r8), "r"(r0), "r"(r1), "r"(r2), "r"(r3)
		: "memory", "cc", "x30"
	);
	return r0;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall5(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	register intptr_t r3 __asm__("x3") = arg4;
	register intptr_t r4 __asm__("x4") = arg5;
	asm __volatile__ (
		"bl fs_syscall"
		: "=r"(r0)
		: "r"(r8), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4)
		: "memory", "cc", "x30"
	);
	return r0;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall6(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6)
{
	register intptr_t r8 __asm__("x8") = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	register intptr_t r3 __asm__("x3") = arg4;
	register intptr_t r4 __asm__("x4") = arg5;
	register intptr_t r5 __asm__("x5") = arg6;
	asm __volatile__ (
		"bl fs_syscall"
		: "=r"(r0)
		: "r"(r8), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
		: "memory", "cc", "x30"
	);
	return r0;
}

struct fs_stat {
	dev_t st_dev;
	ino_t st_ino;
	mode_t st_mode;
	nlink_t st_nlink;
	uid_t st_uid;
	gid_t st_gid;
	dev_t st_rdev;
	unsigned long __pad;
	off_t st_size;
	blksize_t st_blksize;
	int __pad2;
	blkcnt_t st_blocks;
	long st_atime_sec;
	long st_atime_nsec;
	long st_mtime_sec;
	long st_mtime_nsec;
	long st_ctime_sec;
	long st_ctime_nsec;
	unsigned __unused[2];
};
