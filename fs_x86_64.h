#ifdef __APPLE__
#define FS_SYSCALL_POSTPROCESS "\njae 1f\nneg %%rax\n1:"
#else
#define FS_SYSCALL_POSTPROCESS ""
#endif
#ifdef FS_INLINE_SYSCALL
#define FS_CALL_SYSCALL "syscall" FS_SYSCALL_POSTPROCESS
#define FS_JUMP_SYSCALL "syscall" FS_SYSCALL_POSTPROCESS
#define FS_DEFINE_SYSCALL
#else
#define FS_CALL_SYSCALL "call fs_syscall"
#define FS_JUMP_SYSCALL "jmp fs_syscall"
#define FS_DEFINE_SYSCALL __asm__( \
".text\n" \
".global fs_syscall\n" \
".hidden fs_syscall\n" \
".type fs_syscall,@function\n" \
"fs_syscall:\n" \
"	syscall\n" \
".global fs_syscall_ret\n" \
".hidden fs_syscall_ret\n" \
".type fs_syscall_ret,@function\n" \
"fs_syscall_ret:" FS_SYSCALL_POSTPROCESS "\n" \
"	ret\n" \
);
#endif

#include <stdnoreturn.h>

__attribute__((always_inline))
static inline intptr_t fs_syscall0(intptr_t id)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	intptr_t result;
	asm __volatile__ (
		FS_CALL_SYSCALL
		: "=a"(result)
		: "a"(id)
		: "memory", "cc", "rcx", "r11"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall1(intptr_t id, intptr_t arg1)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	intptr_t result;
	asm __volatile__ (
		FS_CALL_SYSCALL
		: "=a"(result)
		: "a"(id), "D"(arg1)
		: "memory", "cc", "rcx", "r11"
	);
	return result;
}

__attribute__((always_inline))
noreturn static inline void fs_syscall_noreturn1(intptr_t id, intptr_t arg1)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	asm __volatile__ (
		FS_JUMP_SYSCALL
		:
		: "a"(id), "D"(arg1)
		: "memory"
	);
	__builtin_unreachable();
}

__attribute__((always_inline))
static inline intptr_t fs_syscall2(intptr_t id, intptr_t arg1, intptr_t arg2)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	intptr_t result;
	asm __volatile__ (
		FS_CALL_SYSCALL
		: "=a"(result)
		: "a"(id), "D"(arg1), "S"(arg2)
		: "memory", "cc", "rcx", "r11"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall3(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	intptr_t result;
	asm __volatile__ (
		FS_CALL_SYSCALL
		: "=a"(result)
		: "a"(id), "D"(arg1), "S"(arg2), "d"(arg3)
		: "memory", "cc", "rcx", "r11"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall4(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	intptr_t result;
	register intptr_t r10 asm("r10") = arg4;
	asm __volatile__ (
		FS_CALL_SYSCALL
		: "=a"(result)
		: "a"(id), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
		: "memory", "cc", "rcx", "r11"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall5(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	intptr_t result;
	register intptr_t r10 asm("r10") = arg4;
	register intptr_t r8 asm("r8") = arg5;
	asm __volatile__ (
		FS_CALL_SYSCALL
		: "=a"(result)
		: "a"(id), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8)
		: "memory", "cc", "rcx", "r11"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall6(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6)
{
#ifdef __APPLE__
	id |= 2 << 24;
#endif
	intptr_t result;
	register intptr_t r10 asm("r10") = arg4;
	register intptr_t r8 asm("r8") = arg5;
	register intptr_t r9 asm("r9") = arg6;
	asm __volatile__ (
		FS_CALL_SYSCALL
		: "=a"(result)
		: "a"(id), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
		: "memory", "cc", "rcx", "r11"
	);
	return result;
}

struct fs_stat {
	dev_t st_dev;
	ino_t st_ino;
	nlink_t st_nlink;

	mode_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	unsigned int    __pad0;
	dev_t st_rdev;
	off_t st_size;
	blksize_t st_blksize;
	blkcnt_t st_blocks;

	long st_atime_sec;
	long st_atime_nsec;
	long st_mtime_sec;
	long st_mtime_nsec;
	long st_ctime_sec;
	long st_ctime_nsec;
	long __unused_trailer[3];
};
