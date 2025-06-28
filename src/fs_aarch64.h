#ifdef __APPLE__
#define FS_SYSCALL_POSTPROCESS "b.cc 1f\nneg x0, x0\n1:"
#else
#define FS_SYSCALL_POSTPROCESS ""
#endif
#ifdef FS_INLINE_SYSCALL
#define FS_CALL_SYSCALL "svc 0\n" FS_SYSCALL_POSTPROCESS
#define FS_JUMP_SYSCALL "svc 0\n" FS_SYSCALL_POSTPROCESS
#define FS_DEFINE_SYSCALL
#else
#define FS_CALL_SYSCALL "bl " FS_NAME_ASM(fs_syscall)
#define FS_JUMP_SYSCALL "b " FS_NAME_ASM(fs_syscall)
#define FS_DEFINE_SYSCALL                                                                          \
	__asm__(                                                                                       \
		".text\n"                                                                                  \
		".cfi_startproc\n" FS_HIDDEN_FUNCTION_ASM(fs_syscall)                                      \
			"\n"                                                                                   \
			"	svc 0\n" FS_HIDDEN_FUNCTION_ASM(fs_syscall_ret) "\n" FS_SYSCALL_POSTPROCESS        \
																"\n"                               \
																"	ret\n" FS_SIZE_ASM(fs_syscall) \
																	"\n"                           \
																	".cfi_endproc\n");
#endif

#include <stdnoreturn.h>

#ifdef __linux__
#define FS_SYSCALL_REG "x8"
#elif defined(__APPLE__)
#define FS_SYSCALL_REG "x16"
#else
#error "unsupported target"
#endif

__attribute__((always_inline)) static inline intptr_t fs_syscall0(intptr_t id)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0");
	asm __volatile__(FS_CALL_SYSCALL : "=r"(r0) : "r"(rsys) : "memory", "cc", "x1", "x30");
	return r0;
}

__attribute__((always_inline)) static inline intptr_t fs_syscall1(intptr_t id, intptr_t arg1)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0") = arg1;
	asm __volatile__(FS_CALL_SYSCALL : "=r"(r0) : "r"(rsys), "r"(r0) : "memory", "cc", "x1", "x30");
	return r0;
}

__attribute__((always_inline)) noreturn static inline void fs_syscall_noreturn1(intptr_t id, intptr_t arg1)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0") = arg1;
	asm __volatile__(FS_JUMP_SYSCALL : : "r"(rsys), "r"(r0) : "memory");
	__builtin_unreachable();
}

__attribute__((always_inline)) static inline intptr_t fs_syscall2(intptr_t id, intptr_t arg1, intptr_t arg2)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	asm __volatile__(FS_CALL_SYSCALL : "=r"(r0), "=r"(r1) : "r"(rsys), "r"(r0), "r"(r1) : "memory", "cc", "x30");
	return r0;
}

__attribute__((always_inline)) static inline intptr_t fs_syscall3(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	asm __volatile__(FS_CALL_SYSCALL : "=r"(r0), "=r"(r1) : "r"(rsys), "r"(r0), "r"(r1), "r"(r2) : "memory", "cc", "x30");
	return r0;
}

__attribute__((always_inline)) static inline intptr_t fs_syscall4(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	register intptr_t r3 __asm__("x3") = arg4;
	asm __volatile__(FS_CALL_SYSCALL : "=r"(r0), "=r"(r1) : "r"(rsys), "r"(r0), "r"(r1), "r"(r2), "r"(r3) : "memory", "cc", "x30");
	return r0;
}

__attribute__((always_inline)) static inline intptr_t fs_syscall5(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	register intptr_t r3 __asm__("x3") = arg4;
	register intptr_t r4 __asm__("x4") = arg5;
	asm __volatile__(FS_CALL_SYSCALL : "=r"(r0), "=r"(r1) : "r"(rsys), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4) : "memory", "cc", "x30");
	return r0;
}

__attribute__((always_inline)) static inline intptr_t fs_syscall6(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = id;
	register intptr_t r0 __asm__("x0") = arg1;
	register intptr_t r1 __asm__("x1") = arg2;
	register intptr_t r2 __asm__("x2") = arg3;
	register intptr_t r3 __asm__("x3") = arg4;
	register intptr_t r4 __asm__("x4") = arg5;
	register intptr_t r5 __asm__("x5") = arg6;
	asm __volatile__(FS_CALL_SYSCALL : "=r"(r0), "=r"(r1) : "r"(rsys), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5) : "memory", "cc", "x30");
	return r0;
}

#ifdef __linux__
__attribute__((always_inline)) static inline intptr_t fs_clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, void *regs, void *fn)
{
	register intptr_t rsys __asm__(FS_SYSCALL_REG) = __NR_clone;
	register intptr_t r0 __asm__("x0") = flags;
	register intptr_t r1 __asm__("x1") = (intptr_t)child_stack;
	register intptr_t r2 __asm__("x2") = (intptr_t)ptid;
	register intptr_t r3 __asm__("x3") = (intptr_t)regs;
	register intptr_t r4 __asm__("x4") = (intptr_t)ctid;
	register intptr_t r5 __asm__("x5") = (intptr_t)fn;
	asm __volatile__(
		"svc 0;"
		"cbnz x0, 1f;"
		"mov fp, #0;"
		"mov x0, x3;"
		"br x5;"
		"1:"
		: "=r"(r0)
		: "r"(rsys), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
		: "memory", "cc", "x30");
	return r0;
}
#endif

#ifdef __APPLE__
struct fs_stat
{
	int32_t st_dev;
	uint16_t st_mode;
	uint16_t st_nlink;
	int64_t st_ino;
	uint32_t st_uid;
	uint32_t st_gid;
	int32_t st_rdev;
	struct timespec st_atimespec;
	struct timespec st_mtimespec;
	struct timespec st_ctimespec;
	struct timespec st_birthtimespec;
	int64_t st_size;
	int64_t st_blocks;
	int32_t st_blksize;
	uint32_t st_flags;
	uint32_t st_gen;
	int32_t st_lspare;
	int64_t st_qspare[2];
};
#else
struct fs_stat
{
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
	unsigned __unused_padding[2];
};
#endif
