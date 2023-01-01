#define FS_DEFINE_SYSCALL __asm__( \
".text\n" \
".global fs_syscall\n" \
".hidden fs_syscall\n" \
".type fs_syscall,@function\n" \
"fs_syscall:\n" \
"	int $0x80\n" \
".global fs_syscall_ret\n" \
".hidden fs_syscall_ret\n" \
".type fs_syscall_ret,@function\n" \
"fs_syscall_ret:\n" \
"	ret\n" \
);

__attribute__((always_inline))
static inline intptr_t fs_syscall0(intptr_t id)
{
	intptr_t result;
	asm __volatile__ (
		"call fs_syscall"
		: "=a"(result)
		: "a"(id)
		: "memory", "cc"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall1(intptr_t id, intptr_t arg1)
{
	intptr_t result;
	asm __volatile__ (
		"call fs_syscall"
		: "=a"(result)
		: "a"(id), "b"(arg1)
		: "memory", "cc"
	);
	return result;
}

__attribute__((always_inline))
static inline void fs_syscall_noreturn1(intptr_t id, intptr_t arg1)
{
	asm __volatile__ (
		"jmp fs_syscall"
		:
		: "a"(id), "b"(arg1)
		: "memory"
	);
	__builtin_unreachable();
}

__attribute__((always_inline))
static inline intptr_t fs_syscall2(intptr_t id, intptr_t arg1, intptr_t arg2)
{
	intptr_t result;
	asm __volatile__ (
		"call fs_syscall"
		: "=a"(result)
		: "a"(id), "b"(arg1), "c"(arg2)
		: "memory", "cc"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall3(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3)
{
	intptr_t result;
	asm __volatile__ (
		"call fs_syscall"
		: "=a"(result)
		: "a"(id), "b"(arg1), "c"(arg2), "d"(arg3)
		: "memory", "cc"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall4(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4)
{
	intptr_t result;
	asm __volatile__ (
		"call fs_syscall"
		: "=a"(result)
		: "a"(id), "b"(arg1), "c"(arg2), "d"(arg3), "S"(arg4)
		: "memory", "cc"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall5(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5)
{
	intptr_t result;
	asm __volatile__ (
		"call fs_syscall"
		: "=a"(result)
		: "a"(id), "b"(arg1), "c"(arg2), "d"(arg3), "S"(arg4), "D"(arg5)
		: "memory", "cc"
	);
	return result;
}

__attribute__((always_inline))
static inline intptr_t fs_syscall6(intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6)
{
	struct {
		intptr_t arg1;
		intptr_t arg2;
		intptr_t arg3;
		intptr_t arg4;
		intptr_t arg5;
		intptr_t arg6;
	} args = { arg1, arg2, arg3, arg4, arg5, arg6 };
	intptr_t result;
	asm __volatile__ (
		"call fs_syscall"
		: "=a"(result)
		: "a"(id), "b"(&args)
		: "memory", "cc"
	);
	return result;
}

struct fs_stat {
	dev_t st_dev;
	int __st_dev_padding;
	long __st_ino_truncated;
	mode_t st_mode;
	nlink_t st_nlink;
	uid_t st_uid;
	gid_t st_gid;
	dev_t st_rdev;
	int __st_rdev_padding;
	off_t st_size;
	blksize_t st_blksize;
	blkcnt_t st_blocks;
	long st_atime_sec;
	long st_atime_nsec;
	long st_mtime_sec;
	long st_mtime_nsec;
	long st_ctime_sec;
	long st_ctime_nsec;
	ino_t st_ino;
	char __padding[16];
};
