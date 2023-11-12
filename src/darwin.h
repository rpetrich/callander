#ifndef DARWIN_H
#define DARWIN_H

#include "freestanding.h"

#include <stdint.h>

intptr_t translate_darwin_result(intptr_t result);

#define DARWIN_SYSCALL_BASE (2 << 24)

#define DARWIN_SYS_read       (DARWIN_SYSCALL_BASE | 3)
#define DARWIN_SYS_write      (DARWIN_SYSCALL_BASE | 4)
#define DARWIN_SYS_close      (DARWIN_SYSCALL_BASE | 6)
#define DARWIN_SYS_getpid     (DARWIN_SYSCALL_BASE | 20)
#define DARWIN_SYS_recvfrom   (DARWIN_SYSCALL_BASE | 29)
#define DARWIN_SYS_fcntl      (DARWIN_SYSCALL_BASE | 92)
#define DARWIN_SYS_fsync      (DARWIN_SYSCALL_BASE | 95)
#define DARWIN_SYS_socket     (DARWIN_SYSCALL_BASE | 97)
#define DARWIN_SYS_flock      (DARWIN_SYSCALL_BASE | 131)
#define DARWIN_SYS_sendto     (DARWIN_SYSCALL_BASE | 133)
#define DARWIN_SYS_pread      (DARWIN_SYSCALL_BASE | 153)
#define DARWIN_SYS_pwrite     (DARWIN_SYSCALL_BASE | 154)
#define DARWIN_SYS_fdatasync  (DARWIN_SYSCALL_BASE | 187)
#define DARWIN_SYS_fstat      (DARWIN_SYSCALL_BASE | 189)
#define DARWIN_SYS_lseek      (DARWIN_SYSCALL_BASE | 199)
#define DARWIN_SYS_truncate   (DARWIN_SYSCALL_BASE | 200)
#define DARWIN_SYS_ftruncate  (DARWIN_SYSCALL_BASE | 201)
#define DARWIN_SYS_poll       (DARWIN_SYSCALL_BASE | 230)
#define DARWIN_SYS_getdirentries64 (DARWIN_SYSCALL_BASE | 344)
#define DARWIN_SYS_openat     (DARWIN_SYSCALL_BASE | 463)
#define DARWIN_SYS_faccessat  (DARWIN_SYSCALL_BASE | 466)
#define DARWIN_SYS_fstatat64  (DARWIN_SYSCALL_BASE | 470)
#define DARWIN_SYS_readlinkat (DARWIN_SYSCALL_BASE | 473)

#define DARWIN_AT_FDCWD -2

#define DARWIN_F_GETPATH 50

struct darwin_timespec {
	int64_t tv_sec;
	long tv_nsec;
};

struct darwin_stat {
	int32_t st_dev;
	uint16_t st_mode;
	uint16_t st_nlink;
	int64_t st_ino;
	uint32_t st_uid;
	uint32_t st_gid;
	int32_t st_rdev;
	struct darwin_timespec st_atimespec;
	struct darwin_timespec st_mtimespec;
	struct darwin_timespec st_ctimespec;
	struct darwin_timespec st_birthtimespec;
	int64_t st_size;
	int64_t st_blocks;
	int32_t st_blksize;
	uint32_t st_flags;
	uint32_t st_gen;
	int32_t st_lspare;
	int64_t st_qspare[2];
};

struct darwin_dirent {
	int64_t d_ino;
	uint64_t d_seekoff;
	uint16_t d_reclen;
	uint16_t d_namlen;
	uint8_t d_type;
	char d_name[1024];
};

int translate_at_fd_to_darwin(int fd);
int translate_at_flags_to_darwin(int flags);
int translate_open_flags_to_darwin(int flags);
int translate_seek_whence_to_darwin(int whence);

struct fs_stat translate_darwin_stat(struct darwin_stat stat);

#endif
