#ifndef FREESTANDING_H
#define FREESTANDING_H

#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <errno.h>
#ifdef __linux__
#include <linux/futex.h>
#include <linux/membarrier.h>
#endif
#include <unistd.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdnoreturn.h>
#ifdef __linux__
#include <syscall.h>
#elif defined(__APPLE__)
#define __APPLE_API_PRIVATE
#include <sys/syscall.h>
#else
#error "unsupported target"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <signal.h>
#include <time.h>

extern void fs_syscall(void);
extern void fs_syscall_ret(void);

#define FS_SYSCALL_(_0, _1, _2, _3, _4, _5, _6, N, ...) N
#define FS_SYSCALL(id, ...) FS_SYSCALL_(id, ##__VA_ARGS__, fs_syscall6, fs_syscall5, fs_syscall4, fs_syscall3, fs_syscall2, fs_syscall1, fs_syscall0)(id, ##__VA_ARGS__)
#define FS_SYSCALL_NORETURN(id, ...) do { FS_SYSCALL_(id, ##__VA_ARGS__, fs_syscall_noreturn6, fs_syscall_noreturn5, fs_syscall_noreturn4, fs_syscall_noreturn3, fs_syscall_noreturn2, fs_syscall_noreturn1, fs_syscall_noreturn0)(id, ##__VA_ARGS__); __builtin_unreachable(); } while (0);

#if defined(__x86_64__)
#include "fs_x86_64.h"
#else
#if defined(__i386__)
#include "fs_i386.h"
#else
#if defined(__aarch64__)
#include "fs_aarch64.h"
#else
#error "Unsupported architecture"
#endif
#endif
#endif

static inline unsigned short fs_htons(unsigned short value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return (unsigned short)(value << 8 | value >> 8);
#else
	return value;
#endif
}

static inline unsigned int fs_htonl(unsigned int value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return value >> 24 | ((value >> 8) & 0xff00) | ((value << 8) & 0xff0000) | value << 24;
#else
	return value;
#endif
}

noreturn static inline void fs_exit(int status)
{
#ifdef SYS_exit_group
	FS_SYSCALL_NORETURN(SYS_exit_group, status);
#else
	FS_SYSCALL_NORETURN(SYS_exit, status);
#endif
}

noreturn static inline void fs_exitthread(int status)
{
	FS_SYSCALL_NORETURN(SYS_exit, status);
}

__attribute__((warn_unused_result))
static inline pid_t fs_fork(void)
{
#ifdef SYS_fork
	return (pid_t)FS_SYSCALL(SYS_fork);
#else
	return (pid_t)FS_SYSCALL(SYS_clone, SIGCHLD, 0, 0, 0);
#endif
}

__attribute__((warn_unused_result))
static inline ssize_t fs_getcwd(char *buf, size_t size)
{
#ifdef SYS_getcwd
	return FS_SYSCALL(SYS_getcwd, (intptr_t)buf, (intptr_t)size);
#else
	intptr_t result = FS_SYSCALL(SYS_readlink, (intptr_t)".", (intptr_t)buf, (intptr_t)size);
	if (result >= (intptr_t)size) {
		result = -ERANGE;
	} else if (result >= 0) {
		buf[result] = '\0';
	}
	return result;
#endif
}

__attribute__((warn_unused_result))
static inline intptr_t fs_chdir(const char *path)
{
#ifdef SYS___pthread_chdir
	return FS_SYSCALL(SYS___pthread_chdir, (intptr_t)path);
#else
	return FS_SYSCALL(SYS_chdir, (intptr_t)path);
#endif
}

__attribute__((warn_unused_result))
static inline intptr_t fs_fchdir(int fd)
{
#ifdef SYS___pthread_fchdir
	return FS_SYSCALL(SYS___pthread_fchdir, fd);
#else
	return FS_SYSCALL(SYS_fchdir, fd);
#endif
}

static inline intptr_t fs_write(int fd, const char *buffer, size_t length)
{
	return FS_SYSCALL(SYS_write, fd, (intptr_t)buffer, (intptr_t)length);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_write_all(int fd, const char *buffer, size_t length)
{
	size_t remaining = length;
	while (remaining != 0) {
		intptr_t result = fs_write(fd, buffer, remaining);
		if (result <= 0) {
			if (result == -EINTR) {
				continue;
			}
			return result;
		}
		buffer += result;
		remaining -= (size_t)result;
	}
	return (intptr_t)(length - remaining);
}

static inline intptr_t fs_send(int fd, const char *buffer, size_t length, int flags)
{
	return FS_SYSCALL(SYS_sendto, fd, (intptr_t)buffer, (intptr_t)length, flags, 0, 0);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_writev(int fd, const struct iovec *iov, int iovcnt)
{
	if (iovcnt == 1) {
		return fs_write(fd, iov->iov_base, iov->iov_len);
	}
	return FS_SYSCALL(SYS_writev, fd, (intptr_t)iov, (intptr_t)iovcnt, 0);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_writev_all(int fd, struct iovec *iov, int iovcnt)
{
	intptr_t written_count = 0;
	for (;;) {
		intptr_t result = fs_writev(fd, iov, iovcnt);
		if (result <= 0) {
			if (result == -EINTR) {
				continue;
			}
			return result;
		}
		written_count += result;
		while ((size_t)result >= iov->iov_len) {
			result -= (intptr_t)iov->iov_len;
			++iov;
			if ((--iovcnt) == 0) {
				return written_count;
			}
		}
		iov->iov_base += result;
		iov->iov_len -= (size_t)result;
	}
}

static inline intptr_t fs_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	return FS_SYSCALL(SYS_sendmsg, fd, (intptr_t)msg, flags);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_read(int fd, char *buffer, size_t length)
{
	return FS_SYSCALL(SYS_read, fd, (intptr_t)buffer, (intptr_t)length);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_read_all(int fd, char *buffer, size_t length)
{
	size_t remaining = length;
	while (remaining != 0) {
		intptr_t result = fs_read(fd, buffer, remaining);
		if (result <= 0) {
			if (result == -EINTR) {
				continue;
			}
			return result;
		}
		buffer += result;
		remaining -= (size_t)result;
	}
	return (intptr_t)(length - remaining);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_readv(int fd, const struct iovec *iov, int iovcnt)
{
	return FS_SYSCALL(SYS_readv, fd, (intptr_t)iov, (intptr_t)iovcnt);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_readv_all(int fd, struct iovec *iov, int iovcnt)
{
	intptr_t read_count = 0;
	for (;;) {
		intptr_t result = fs_readv(fd, iov, iovcnt);
		if (result <= 0) {
			if (result == -EINTR) {
				continue;
			}
			return result;
		}
		read_count += result;
		while ((size_t)result >= iov->iov_len) {
			result -= (intptr_t)iov->iov_len;
			++iov;
			if ((--iovcnt) == 0) {
				return read_count;
			}
		}
		iov->iov_base += result;
		iov->iov_len -= (size_t)result;
	}
}

__attribute__((warn_unused_result))
static inline intptr_t fs_recvmsg(int fd, struct msghdr *msg, int flags)
{
	return FS_SYSCALL(SYS_recvmsg, fd, (intptr_t)msg, flags);
}

__attribute__((warn_unused_result))
static inline intptr_t fs_pwrite(int fd, const char *buffer, size_t length, uint64_t offset)
{
#ifdef SYS_pwrite64
#ifdef __LP64__
	return FS_SYSCALL(SYS_pwrite64, fd, (intptr_t)buffer, (intptr_t)length, (intptr_t)offset);
#else
	return FS_SYSCALL(SYS_pwrite64, fd, (intptr_t)buffer, (intptr_t)length, (intptr_t)offset, (intptr_t)(offset >> 32));
#endif
#else
	return FS_SYSCALL(SYS_pwrite, fd, (intptr_t)buffer, (intptr_t)length, (intptr_t)offset);
#endif
}

__attribute__((warn_unused_result))
static inline intptr_t fs_pread(int fd, char *buffer, size_t length, uint64_t offset)
{
#ifdef SYS_pread64
#ifdef __LP64__
	return FS_SYSCALL(SYS_pread64, fd, (intptr_t)buffer, (intptr_t)length, (intptr_t)offset);
#else
	return FS_SYSCALL(SYS_pread64, fd, (intptr_t)buffer, (intptr_t)length, (intptr_t)offset, (intptr_t)(offset >> 32));
#endif
#else
	return FS_SYSCALL(SYS_pread, fd, (intptr_t)buffer, (intptr_t)length, (intptr_t)offset);
#endif
}

__attribute__((warn_unused_result))
static inline intptr_t fs_pread_all(int fd, char *buffer, size_t length, uint64_t offset)
{
	size_t remaining = length;
	while (remaining != 0) {
		intptr_t result = fs_pread(fd, buffer, remaining, offset);
		if (result <= 0) {
			if (result == -EINTR) {
				continue;
			}
			if (result == 0) {
				return (intptr_t)(length - remaining);
			}
			return result;
		}
		offset += (size_t)result;
		buffer += result;
		remaining -= (size_t)result;
	}
	return (intptr_t)length;
}

__attribute__((warn_unused_result))
static inline intptr_t fs_lseek(int fd, off_t offset, int origin)
{
	return FS_SYSCALL(SYS_lseek, fd, (intptr_t)offset, (intptr_t)origin);
}

__attribute__((warn_unused_result))
static inline int fs_pipe(int pipefd[2])
{
#ifdef SYS_pipe
	return (int)FS_SYSCALL(SYS_pipe, (intptr_t)pipefd);
#else
	return (int)FS_SYSCALL(SYS_pipe2, (intptr_t)pipefd, 0);
#endif
}

__attribute__((warn_unused_result))
static inline int fs_socket(int domain, int type, int protocol)
{
	return (int)FS_SYSCALL(SYS_socket, domain, type, protocol);
}

__attribute__((warn_unused_result))
static inline int fs_socketpair(int domain, int type, int protocol, int sv[2])
{
	return (int)FS_SYSCALL(SYS_socketpair, domain, type, protocol, (intptr_t)sv);
}

__attribute__((warn_unused_result))
static inline int fs_setsockopt(int socket, int level, int option, const void *value, size_t value_len)
{
	return (int)FS_SYSCALL(SYS_setsockopt, socket, level, option, (intptr_t)value, (intptr_t)value_len);
}

__attribute__((warn_unused_result))
static inline int fs_getsockopt(int socket, int level, int option, void *value, size_t *value_len)
{
	return (int)FS_SYSCALL(SYS_getsockopt, socket, level, option, (intptr_t)value, (intptr_t)value_len);
}

__attribute__((warn_unused_result))
static inline int fs_connect(int socket, const void *address, size_t address_len)
{
	return (int)FS_SYSCALL(SYS_connect, socket, (intptr_t)address, (intptr_t)address_len);
}

__attribute__((warn_unused_result))
static inline int fs_bind(int socket, const void *address, size_t address_len)
{
	return (int)FS_SYSCALL(SYS_bind, socket, (intptr_t)address, (intptr_t)address_len);
}

__attribute__((warn_unused_result))
static inline int fs_listen(int socket, int backlog)
{
	return (int)FS_SYSCALL(SYS_listen, socket, (intptr_t)backlog);
}

__attribute__((warn_unused_result))
static inline int fs_accept(int socket, void *address, size_t *address_len)
{
	return (int)FS_SYSCALL(SYS_accept, socket, (intptr_t)address, (intptr_t)address_len);
}

__attribute__((warn_unused_result))
static inline int fs_open(const char *path, int flags, mode_t mode)
{
#ifdef SYS_open
	return (int)FS_SYSCALL(SYS_open, (intptr_t)path, flags, mode);
#else
	return (int)FS_SYSCALL(SYS_openat, AT_FDCWD, (intptr_t)path, flags, mode);
#endif
}

__attribute__((warn_unused_result))
static inline int fs_openat(int fd, const char *path, int flags, mode_t mode)
{
	return (int)FS_SYSCALL(SYS_openat, fd, (intptr_t)path, flags, mode);
}

__attribute__((warn_unused_result))
static inline int fs_mkdir(const char *path, mode_t mode)
{
#ifdef SYS_mkdir
	return (int)FS_SYSCALL(SYS_mkdir, (intptr_t)path, mode);
#else
	return (int)FS_SYSCALL(SYS_mkdirat, AT_FDCWD, (intptr_t)path, mode);
#endif
}

__attribute__((warn_unused_result))
static inline int fs_mkdirat(int dirfd, const char *path, mode_t mode)
{
	return (int)FS_SYSCALL(SYS_mkdirat, dirfd, (intptr_t)path, mode);
}

__attribute__((warn_unused_result))
static inline int fs_readlink(const char *path, char *buf, size_t bufsiz)
{
#ifdef SYS_readlink
	return (int)FS_SYSCALL(SYS_readlink, (intptr_t)path, (intptr_t)buf, (intptr_t)bufsiz);
#else
	return (int)FS_SYSCALL(SYS_readlinkat, AT_FDCWD, (intptr_t)path, (intptr_t)buf, (intptr_t)bufsiz);
#endif
}

__attribute__((warn_unused_result))
static inline int fs_readlinkat(int fd, const char *path, char *buf, size_t bufsiz)
{
	return (int)FS_SYSCALL(SYS_readlinkat, fd, (intptr_t)path, (intptr_t)buf, (intptr_t)bufsiz);
}

__attribute__((warn_unused_result))
static inline int fs_unlink(const char *path)
{
#ifdef SYS_unlink
	return (int)FS_SYSCALL(SYS_unlink, (intptr_t)path);
#else
	return (int)FS_SYSCALL(SYS_unlinkat, AT_FDCWD, (intptr_t)path, 0);
#endif
}

__attribute__((warn_unused_result))
static inline int fs_unlinkat(int fd, const char *path, int flags)
{
	return (int)FS_SYSCALL(SYS_unlinkat, fd, (intptr_t)path, flags);
}

__attribute__((warn_unused_result))
static inline int fs_renameat(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path)
{
	return (int)FS_SYSCALL(SYS_renameat, old_dirfd, (intptr_t)old_path, new_dirfd, (intptr_t)new_path);
}

#ifdef SYS_renameat2
__attribute__((warn_unused_result))
static inline int fs_renameat2(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags)
{
	return (int)FS_SYSCALL(SYS_renameat2, old_dirfd, (intptr_t)old_path, new_dirfd, (intptr_t)new_path, flags);
}
#endif

__attribute__((warn_unused_result))
static inline int fs_linkat(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags)
{
	return (int)FS_SYSCALL(SYS_linkat, old_dirfd, (intptr_t)old_path, new_dirfd, (intptr_t)new_path, flags);
}

__attribute__((warn_unused_result))
static inline int fs_symlinkat(const char *old_path, int new_dirfd, const char *new_path)
{
	return (int)FS_SYSCALL(SYS_symlinkat, (intptr_t)old_path, new_dirfd, (intptr_t)new_path);
}

__attribute__((warn_unused_result))
static inline int fs_fchmod(int fd, mode_t mode)
{
	return (int)FS_SYSCALL(SYS_fchmod, fd, mode);
}

__attribute__((warn_unused_result))
static inline int fs_fchown(int fd, uid_t uid, gid_t gid)
{
	return (int)FS_SYSCALL(SYS_fchown, fd, uid, gid);
}

__attribute__((warn_unused_result))
static inline int fs_fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flags)
{
	return (int)FS_SYSCALL(SYS_fchownat, fd, (intptr_t)path, uid, gid, flags);
}

__attribute__((warn_unused_result))
static inline int fs_ftruncate(int fd, size_t size)
{
	return (int)FS_SYSCALL(SYS_ftruncate, fd, (intptr_t)size);
}

__attribute__((warn_unused_result))
static inline int fs_fstat(int fd, struct fs_stat *buf)
{
#ifdef SYS_fstat64
	return (int)FS_SYSCALL(SYS_fstat64, fd, (intptr_t)buf);
#else
	return (int)FS_SYSCALL(SYS_fstat, fd, (intptr_t)buf);
#endif
}

__attribute__((warn_unused_result))
static inline int fs_stat(const char *path, struct fs_stat *buf)
{
#ifdef SYS_stat64
	return (int)FS_SYSCALL(SYS_stat64, (intptr_t)path, (intptr_t)buf);
#else
#ifdef SYS_stat
	return (int)FS_SYSCALL(SYS_stat, (intptr_t)path, (intptr_t)buf);
#else
	return (int)FS_SYSCALL(SYS_newfstatat, AT_FDCWD, (intptr_t)path, (intptr_t)buf, 0);
#endif
#endif
}

struct fs_statfs {
	unsigned long f_type;
	unsigned long f_bsize;
	fsblkcnt_t f_blocks;
	fsblkcnt_t f_bfree;
	fsblkcnt_t f_bavail;
	fsfilcnt_t f_files;
	fsblkcnt_t f_ffree;
	struct { int __val[2]; } f_fsid;
	unsigned long f_namelen;
	unsigned long f_frsize;
	unsigned long f_flags;
	unsigned long f_spare[4];
};

__attribute__((warn_unused_result))
static inline int fs_fstatfs(int fd, struct fs_statfs *buf)
{
	return (int)FS_SYSCALL(SYS_fstatfs, fd, (intptr_t)buf);
}

struct fs_dirent {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#ifdef SYS_getdents64
static inline int fs_getdents(int fd, struct fs_dirent *dirp, size_t size)
{
	return (int)FS_SYSCALL(SYS_getdents64, fd, (intptr_t)dirp, (intptr_t)size);
}
#endif

__attribute__((warn_unused_result))
static inline int fs_access(const char *pathname, int mode)
{
#ifdef SYS_access
	return (int)FS_SYSCALL(SYS_access, (intptr_t)pathname, mode);
#else
	return (int)FS_SYSCALL(SYS_faccessat, AT_FDCWD, (intptr_t)pathname, mode);
#endif
}

__attribute__((warn_unused_result))
static inline int fs_faccessat(int dirfd, const char *pathname, int mode, int flags)
{
	return (int)FS_SYSCALL(SYS_faccessat, dirfd, (intptr_t)pathname, mode, flags);
}

__attribute__((warn_unused_result))
static inline int fs_dup(int oldfd)
{
	return (int)FS_SYSCALL(SYS_dup, oldfd);
}

__attribute__((warn_unused_result))
static inline int fs_dup2(int oldfd, int newfd)
{
#ifdef SYS_dup2
	return (int)FS_SYSCALL(SYS_dup2, oldfd, newfd);
#else
	return (int)FS_SYSCALL(SYS_dup3, oldfd, newfd, 0);
#endif
}

#ifdef SYS_dup3
__attribute__((warn_unused_result))
static inline int fs_dup3(int oldfd, int newfd, int flags)
{
	return (int)FS_SYSCALL(SYS_dup3, oldfd, newfd, flags);
}
#endif

__attribute__((warn_unused_result))
static inline int fs_fcntl(int fd, int cmd, uintptr_t arg)
{
	return (int)FS_SYSCALL(SYS_fcntl, fd, cmd, (intptr_t)arg);
}

static inline int fs_close(int fd)
{
	return (int)FS_SYSCALL(SYS_close, fd);
}

__attribute__((warn_unused_result))
static inline void *fs_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	return (void *)FS_SYSCALL(SYS_mmap, (intptr_t)addr, (intptr_t)length, prot, flags, fd, offset);
}

__attribute__((warn_unused_result))
static inline bool fs_is_map_failed(void *address) {
	return (unsigned long)address > -4096UL;
}

static inline int fs_munmap(void *addr, size_t length)
{
	return (int)FS_SYSCALL(SYS_munmap, (intptr_t)addr, (intptr_t)length);
}

#ifdef SYS_mremap
__attribute__((warn_unused_result))
static inline void *fs_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address)
{
	return (void *)FS_SYSCALL(SYS_mremap, (intptr_t)old_address, (intptr_t)old_size, (intptr_t)new_size, flags, (intptr_t)new_address);
}
#endif

__attribute__((warn_unused_result))
static inline int fs_mprotect(void *addr, size_t len, int prot)
{
	return (int)FS_SYSCALL(SYS_mprotect, (intptr_t)addr, (intptr_t)len, prot);
}

__attribute__((warn_unused_result))
static inline int fs_mincore(const void *addr, size_t length, unsigned char *vec)
{
	return (int)FS_SYSCALL(SYS_mincore, (intptr_t)addr, (intptr_t)length, (intptr_t)vec);
}

#ifdef SYS_prctl
__attribute__((warn_unused_result))
static inline int fs_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	return (int)FS_SYSCALL(SYS_prctl, option, (intptr_t)arg2, (intptr_t)arg3, (intptr_t)arg4, (intptr_t)arg5);
}
#endif

#ifdef SYS_seccomp
__attribute__((warn_unused_result))
static inline int fs_seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return (int)FS_SYSCALL(SYS_seccomp, operation, flags, (intptr_t)args);
}
#endif

#ifdef __linux__
struct fs_sigset_t {
	unsigned long buf[_NSIG / (8 * sizeof(long))];
};

static inline void fs_sigaddset(struct fs_sigset_t *set, int signo)
{
	set->buf[signo >> 6] |= (1UL << ((signo & 0x1f) - 1));
}

static inline void fs_sigdelset(struct fs_sigset_t *set, int signo)
{
	set->buf[signo >> 6] &= ~(1UL << ((signo & 0x1f) - 1));
}

static inline bool fs_sigismember(struct fs_sigset_t *set, int signo)
{
	return set->buf[signo >> 6] & (1UL << ((signo & 0x1f) - 1)) ? true : false;
}
#else
struct fs_sigset_t {
	unsigned int buf;
};

static inline void fs_sigaddset(struct fs_sigset_t *set, int signo)
{
	set->buf |= (1UL << (signo - 1));
}

static inline void fs_sigdelset(struct fs_sigset_t *set, int signo)
{
	set->buf &= ~(1UL << (signo - 1));
}

static inline bool fs_sigismember(struct fs_sigset_t *set, int signo)
{
	return set->buf & (1UL << (signo - 1)) ? true : false;
}
#endif

struct fs_sigaction {
	void (*handler)(int);
	unsigned long flags;
	void (*restorer)(void);
	struct fs_sigset_t mask;
};

#ifdef SYS_sigaction
__attribute__((warn_unused_result))
static inline int fs_sigaction(int signum, const struct fs_sigaction *act, struct fs_sigaction *oldact, size_t sigsetsize)
{
	return (int)FS_SYSCALL(SYS_sigaction, signum, (intptr_t)act, (intptr_t)oldact, sigsetsize);
}
#endif

#ifdef SYS_rt_sigaction
__attribute__((warn_unused_result))
static inline int fs_rt_sigaction(int signum, const struct fs_sigaction *act, struct fs_sigaction *oldact, size_t sigsetsize)
{
	return (int)FS_SYSCALL(SYS_rt_sigaction, signum, (intptr_t)act, (intptr_t)oldact, (intptr_t)sigsetsize);
}
#endif

#ifdef SYS_sigprocmask
__attribute__((warn_unused_result))
static inline int fs_sigprocmask(int how, const struct fs_sigset_t *set, struct fs_sigset_t *oldset, size_t sigsetsize)
{
	return (int)FS_SYSCALL(SYS_sigprocmask, how, (intptr_t)set, (intptr_t)oldset, (intptr_t)sigsetsize);
}
#endif

#ifdef SYS_rt_sigprocmask
__attribute__((warn_unused_result))
static inline int fs_rt_sigprocmask(int how, const struct fs_sigset_t *set, struct fs_sigset_t *oldset, size_t sigsetsize)
{
	return (int)FS_SYSCALL(SYS_rt_sigprocmask, how, (intptr_t)set, (intptr_t)oldset, (intptr_t)sigsetsize);
}
#endif

#ifdef SYS_sigreturn
static inline void fs_sigreturn(void)
{
	FS_SYSCALL_NORETURN(SYS_sigreturn, 0);
	__builtin_unreachable();
}
#endif

#ifdef SYS_rt_sigreturn
static inline void fs_rt_sigreturn(void)
{
	FS_SYSCALL_NORETURN(SYS_rt_sigreturn, 0);
	__builtin_unreachable();
}
#endif

__attribute__((warn_unused_result))
static inline int fs_sigaltstack(const stack_t *ss, stack_t *old_ss)
{
	return (int)FS_SYSCALL(SYS_sigaltstack, (intptr_t)ss, (intptr_t)old_ss);
}

__attribute__((warn_unused_result))
static inline pid_t fs_getpid(void)
{
	return (pid_t)FS_SYSCALL(SYS_getpid);
}

__attribute__((warn_unused_result))
static inline pid_t fs_getpgid(pid_t pid)
{
	return (pid_t)FS_SYSCALL(SYS_getpgid, pid);
}

#ifdef __linux__
__attribute__((warn_unused_result))
static inline pid_t fs_gettid(void)
{
	// darwin's gettid is completely different from linux's
	return (pid_t)FS_SYSCALL(SYS_gettid);
}
#endif

__attribute__((warn_unused_result))
static inline uid_t fs_getuid(void)
{
	return (uid_t)FS_SYSCALL(SYS_getuid);
}

__attribute__((warn_unused_result))
static inline gid_t fs_getgid(void)
{
	return (gid_t)FS_SYSCALL(SYS_getgid);
}

#ifdef SYS_tkill
__attribute__((warn_unused_result))
static inline int fs_tkill(int tid, int sig)
{
	return (int)FS_SYSCALL(SYS_tkill, tid, sig);
}
#endif

__attribute__((warn_unused_result))
static inline int fs_kill(int pid, int sig)
{
	return (int)FS_SYSCALL(__NR_kill, pid, sig);
}

__attribute__((warn_unused_result))
static inline int fs_execve(const char *pathname, char *const argv[], char *const envp[])
{
	return (int)FS_SYSCALL(SYS_execve, (intptr_t)pathname, (intptr_t)argv, (intptr_t)envp);
}

#ifdef SYS_execveat
__attribute__((warn_unused_result))
static inline int fs_execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
{
	return (int)FS_SYSCALL(SYS_execveat, dirfd, (intptr_t)pathname, (intptr_t)argv, (intptr_t)envp, flags);
}
#endif

#ifdef SYS_futex
static inline int fs_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout)
{
	return (int)FS_SYSCALL(SYS_futex, (intptr_t)uaddr, futex_op, val, (intptr_t)timeout);
}
#endif

#ifdef SYS_membarrier
static inline int fs_membarrier(int cmd, int flags)
{
	return (int)FS_SYSCALL(SYS_membarrier, cmd, flags);
}
#endif

#ifdef SYS_sched_yield
static inline int fs_sched_yield(void)
{
	return (int)FS_SYSCALL(SYS_sched_yield);
}
#endif

#ifdef SYS_clock_gettime
static inline int fs_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	return (int)FS_SYSCALL(SYS_clock_gettime, (intptr_t)clk_id, (intptr_t)tp);
}
#endif

#ifdef SYS_nanosleep
static inline int fs_nanosleep(const struct timespec *req, struct timespec *rem)
{
	return (int)FS_SYSCALL(SYS_nanosleep, (intptr_t)req, (intptr_t)rem);
}
#endif

#ifdef SYS_memfd_create
static inline int fs_memfd_create(const char *name, unsigned int flags)
{
	return (int)FS_SYSCALL(SYS_memfd_create, (intptr_t)name, flags);
}
#endif

static inline long fs_ptrace(int request, pid_t pid, void *addr, void *data)
{
	return (long)FS_SYSCALL(__NR_ptrace, request, pid, (intptr_t)addr, (intptr_t)data);
}

static inline ssize_t fs_process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
	return (ssize_t)FS_SYSCALL(__NR_process_vm_readv, pid, (intptr_t)local_iov, (intptr_t)liovcnt, (intptr_t)remote_iov, (intptr_t)riovcnt, (intptr_t)flags);
}

static inline ssize_t fs_process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
	return (ssize_t)FS_SYSCALL(__NR_process_vm_writev, pid, (intptr_t)local_iov, (intptr_t)liovcnt, (intptr_t)remote_iov, (intptr_t)riovcnt, (intptr_t)flags);
}

static inline ssize_t fs_process_vm_read(pid_t pid, void *buf, size_t size, uintptr_t remote)
{
	struct iovec local_iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct iovec remote_iov = {
		.iov_base = (void *)remote,
		.iov_len = size,
	};
	return fs_process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

static inline ssize_t fs_process_vm_write(pid_t pid, const void *buf, size_t size, uintptr_t remote)
{
	struct iovec local_iov = {
		.iov_base = (void *)buf,
		.iov_len = size,
	};
	struct iovec remote_iov = {
		.iov_base = (void *)remote,
		.iov_len = size,
	};
	return fs_process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
}

struct fs_fd_set {
	long int bits[FD_SETSIZE/sizeof(long int)];
};

static inline bool fs_fd_isset(int fd, const struct fs_fd_set *fds)
{
	if ((fd < 0) || (fd >= FD_SETSIZE)) {
		return false;
	}
	return (fds->bits[(unsigned int)fd / (8 * sizeof(long int))] & (1 << ((unsigned int)fd % (8 * sizeof(long int))))) != 0;
}

static inline void fs_fd_clr(int fd, struct fs_fd_set *fds)
{
	if ((fd < 0) || (fd >= FD_SETSIZE)) {
		return;
	}
	fds->bits[(unsigned int)fd / (8 * sizeof(long int))] &= ~(1 << ((unsigned int)fd % (8 * sizeof(long int))));
}

// fs_memset fills a buffer with a specified character value
__attribute__((nonnull(1)))
static inline void *fs_memset(void *buffer, int value, size_t num)
{
	char *buf = buffer;
	for (int i = 0; i < (int)num; i++) {
		buf[i] = (char)value;
	}
	return buffer;
}

// fs_strcmp returns the length of a string as represented by its null terminator
__attribute__((warn_unused_result))
__attribute__((nonnull(1)))
static inline size_t fs_strlen(const char *string)
{
	const char *current = string;
	while (*current) {
		++current;
	}
	return (size_t)(current - string);
}

// fs_strcmp compares two strings
__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
static inline int fs_strcmp(const char *l, const char *r)
{
	while (*l && (*l == *r)) {
		++l;
		++r;
	}
	return *(const unsigned char *)l - *(const unsigned char *)r;
}

// fs_strchr returns the first position in the string where character is found,
// scanning until the null terminator
__attribute__((warn_unused_result))
__attribute__((nonnull(1)))
static inline const char *fs_strchr(const char * str, int character)
{
	while ((*str != '\0') && (*str != (char)character)) {
		++str;
	}
	return str;
}

// fs_strrchr returns the last position in the string where character is found,
// scanning until the null terminator
__attribute__((warn_unused_result))
__attribute__((nonnull(1)))
static inline const char *fs_strrchr(const char * str, int character)
{
	const char *last = NULL;
	while (*str != '\0') {
		if (*str == (char)character) {
			last = str;
		}
		++str;
	}
	return last;
}

// fs_strstr returns the first occurrence of the needle in the haystack
__attribute__((warn_unused_result))
__attribute__((nonnull(1)))
static inline const char *fs_strstr(const char *haystack, const char *needle)
{
	for (; ; haystack++) {
		for (int i = 0; ; i++) {
			if (needle[i] == '\0') {
				return haystack;
			}
			if (haystack[i] == '\0') {
				return NULL;
			}
			if (needle[i] != haystack[i]) {
				break;
			}
		}
	}
}

// fs_memchr returns the position in the buffer where character is found,
// scanning up to n characters
__attribute__((warn_unused_result))
__attribute__((nonnull(1)))
static inline const char *fs_memchr(const char *str, int character, size_t n)
{
	for (int i = 0; i < (int)n; i++) {
		if (str[i] == character) {
			return &str[i];
		}
	}
	return NULL;
}

// fs_memcmp compares two memory regions
__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
static inline int fs_memcmp(const char *l, const char *r, size_t n)
{
	for (;;) {
		if (n-- == 0) {
			return 0;
		}
		if (*l++ != *r++) {
			return *(const unsigned char *)l - *(const unsigned char *)r;
		}
	}
}

__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
static inline const char *fs_strpbrk(const char *str, const char *characters)
{
	for (;;) {
		char c = *str;
		for (const char *chrs = characters;; ++chrs) {
			if (*chrs == c) {
				return str;
			}
			if (*chrs == '\0') {
				break;
			}
		}
		++str;
	}
}

// fs_strncmp compares one string to another, up to a certain number of
// characters; equivalent to strncmp
__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
static inline int fs_strncmp(const char *l, const char *r, size_t num)
{
	while (num && *l && (*l == *r)) {
		++l;
		++r;
		--num;
	}
	return num ? *(const unsigned char *)l - *(const unsigned char *)r : 0;
}

// fs_memcpy copies one buffer onto another without regard for if they overlap; equivalent to memcpy
__attribute__((nonnull(1, 2), always_inline))
static inline void *fs_memcpy(void *restrict destination, const void *restrict source, size_t num)
{
#if defined(__x86_64__)
	void *dest = destination;
	asm volatile ("rep movsb"
	            : "=D" (destination),
	              "=S" (source),
	              "=c" (num)
	            : "D" (destination),
	              "S" (source),
	              "c" (num)
	            : "memory");
	return dest;
#else
	uint8_t *dst = destination;
	const uint8_t *src = source;
	for (size_t i = 0; i < num; i++) {
		dst[i] = src[i];
	}
	return destination;
#endif
}

// fs_memmove moves one buffer onto another; equivalent to memmove
__attribute__((nonnull(1, 2)))
static inline void *fs_memmove(void *destination, const void *source, size_t num)
{
	uint8_t *dst = destination;
	const uint8_t *src = source;
	if (destination == source || num == 0) {
		return destination;
	}
	if (destination > source && (source - destination < (intptr_t)num)) {
		// copy in reverse to avoid overwriting destination
		for (ssize_t i = (ssize_t)(num - 1); i >= 0; i--) {
			dst[i] = src[i];
		}
		return destination;
	}
	if (source > destination && (destination - source) < (intptr_t)num) {
		// copy forwards to avoid overwriting destination
		for (size_t i = 0; i < num; i++) {
			dst[i] = src[i];
		}
		return destination;
	}
	return fs_memcpy(destination, source, num);
}

__attribute__((nonnull(1, 2)))
static inline char *fs_strcpy(char * restrict buf, const char * restrict str)
{
	while ((*buf = *str++)) {
		buf++;
	}
	return buf;
}

// fs_reverse reverses the characters in a buffer
__attribute__((nonnull(1)))
static inline void fs_reverse(char buffer[], size_t length)
{
	for (size_t i = 0, j = length - 1; i < j; i++, j--) {
		char c = buffer[i];
		buffer[i] = buffer[j];
		buffer[j] = c;
	}
}

// fs_utoa formats an unsigned integer as decimal into buffer, which must hold
// enough space for the largest formatted number to be written
__attribute__((nonnull(2)))
static inline size_t fs_utoa(uintptr_t value, char buffer[])
{
	size_t i = 0;
	do {
		buffer[i++] = (char)((value % 10) + '0');
	} while (value /= 10);
	buffer[i] = '\0';
	fs_reverse(buffer, i);
	return i;
}

// fs_itoa formats an integer as decimal into buffer, which must hold enough
// space for the largest formatted number to be written
__attribute__((nonnull(2)))
static inline size_t fs_itoa(intptr_t value, char buffer[])
{
	if (value < 0) {
		*buffer = '-';
		unsigned long long v;
		if (value == INTPTR_MIN) {
			if (sizeof(intptr_t) == 8) {
				v = 9223372036854775808ull;
			} else {
				v = 2147483648ull;
			}
		} else {
			v = (unsigned long long)-value;
		}
		return fs_utoa(v, &buffer[1]) + 1;
	}
	return fs_utoa((unsigned long long)value, buffer);
}

// fs_utoah_noprefix formats an integer as hexadecimal into buffer, which must
// hold enough space for the largest formatted number to be written
__attribute__((nonnull(2)))
static inline size_t fs_utoah_noprefix(uintptr_t value, char buffer[])
{
	size_t i = 0;
	do {
		buffer[i++] = "0123456789abcdef"[(unsigned char)value & 0xf];
		value = value >> 4;
	} while(value);
	buffer[i] = '\0';
	fs_reverse(buffer, i);
	return i;
}

// fs_utoah formats an integer as hexadecimal into buffer, which must hold
// enough space for the largest formatted number to be written
__attribute__((nonnull(2)))
static inline size_t fs_utoah(uintptr_t value, char buffer[])
{
	buffer[0] = '0';
	buffer[1] = 'x';
	size_t i = 2;
	do {
		buffer[i++] = "0123456789abcdef"[(unsigned char)value & 0xf];
		value = value >> 4;
	} while(value);
	buffer[i] = '\0';
	fs_reverse(&buffer[2], i - 2);
	return i;
}

// fs_hexval returns the hexadecimal value of a character if it's hexadecimal
// or -1 if it's not a valid hex character
__attribute__((warn_unused_result))
static inline int fs_hexval(char value)
{
	if (value >= '0' && value <= '9') {
		return value - '0';
	}
	if (value >= 'a' && value <= 'f') {
		return value - 'a' + 10;
	}
	if (value >= 'A' && value <= 'F') {
		return value - 'A' + 10;
	}
	return -1;
}

// fs_scanu scans for a hexadecimal integer and returns the address of the first
// unconsumed character
__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
static inline const char *fs_scanu(const char *buffer, uintptr_t *result)
{
	if (buffer[0] == '0' && buffer[1] == 'x') {
		buffer += 2;
	} else if (fs_hexval(*buffer) == -1) {
		return NULL;
	}
	uintptr_t value = 0;
	for (;;) {
		int val = fs_hexval(*buffer);
		if (val == -1) {
			break;
		}
		value = value << 4 | (uintptr_t)val;
		buffer++;
	}
	*result = value;
	return buffer;
}

// fs_scans scans for a signed decimal integer and returns the address of the
// first unconsumed character
__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
static inline const char *fs_scans(const char *buffer, intptr_t *result)
{
	bool negative = buffer[0] == '-';
	if (negative) {
		buffer++;
	}
	if (*buffer < '0' || *buffer > '9') {
		return NULL;
	}
	intptr_t value = *buffer - '0';
	buffer++;
	while (*buffer >= '0' && *buffer <= '9') {
		value = value * 10 + (*buffer - '0');
		buffer++;
	}
	if (negative) {
		value = -value;
	}
	*result = value;
	return buffer;
}

__attribute__((warn_unused_result))
__attribute__((nonnull(2)))
static inline int fs_readlink_fd(int fd, char *out_path, size_t size)
{
	if (fd < 0) {
		return -EINVAL;
	}
	char dev_path[64];
	fs_memcpy(dev_path, "/proc/self/fd/", sizeof("/proc/self/fd/") - 1);
	fs_utoa((uintptr_t)fd, &dev_path[sizeof("/proc/self/fd/") - 1]);
	return fs_readlink(dev_path, out_path, size);
}

#ifdef SYS_futex

struct fs_mutex {
	// needs manual padding to avoid false sharing
	atomic_int state;
};

__attribute__((warn_unused_result))
__attribute__((nonnull(1)))
static inline int fs_cmpxchg(atomic_int *state, int expected, int desired)
{
	atomic_compare_exchange_strong(state, &expected, desired);
	return expected;
}

#ifdef FS_INLINE_MUTEX_SLOW_PATH
__attribute__((always_inline))
#endif
static inline void fs_mutex_lock_slow_path(struct fs_mutex *mutex, int state)
{
	do {
		if (state == 2 || fs_cmpxchg(&mutex->state, 1, 2) != 0) {
			fs_futex((int *)&mutex->state, FUTEX_WAIT_PRIVATE, 2, NULL);
		}
		state = fs_cmpxchg(&mutex->state, 0, 2);
	} while(state);
}

// fs_mutex_lock acquires the mutex
__attribute__((always_inline))
__attribute__((nonnull(1)))
static inline void fs_mutex_lock(struct fs_mutex *mutex)
{
	int state = fs_cmpxchg(&mutex->state, 0, 1);
	if (__builtin_expect(state, 0)) {
		fs_mutex_lock_slow_path(mutex, state);
	}
}

#ifdef FS_INLINE_MUTEX_SLOW_PATH
__attribute__((always_inline))
#endif
static inline void fs_mutex_unlock_slow_path(struct fs_mutex *mutex)
{
	atomic_store_explicit(&mutex->state, 0, memory_order_relaxed);
	fs_futex((int *)&mutex->state, FUTEX_WAKE_PRIVATE, 1, NULL);
}

// fs_mutex_lock releases the mutex
__attribute__((always_inline))
__attribute__((nonnull(1)))
static inline void fs_mutex_unlock(struct fs_mutex *mutex)
{
	int state = atomic_fetch_sub(&mutex->state, 1);
	if (__builtin_expect(state != 1, 0)) {
		fs_mutex_unlock_slow_path(mutex);
	}
}
#endif

static inline const char *fs_strerror(int err)
{
	if (err >= 0) {
		return "SUCCESS";
	}
	const char *template =
	"EPERM\0\0\0\0\0\0\0\0\0\0\0"
	"ENOENT\0\0\0\0\0\0\0\0\0\0"
	"ESRCH\0\0\0\0\0\0\0\0\0\0\0"
	"EINTR\0\0\0\0\0\0\0\0\0\0\0"
	"EIO\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"ENXIO\0\0\0\0\0\0\0\0\0\0\0"
	"E2BIG\0\0\0\0\0\0\0\0\0\0\0"
	"ENOEXEC\0\0\0\0\0\0\0\0\0"
	"EBADF\0\0\0\0\0\0\0\0\0\0\0"
	"ECHILD\0\0\0\0\0\0\0\0\0\0"
	"EAGAIN\0\0\0\0\0\0\0\0\0\0"
	"ENOMEM\0\0\0\0\0\0\0\0\0\0"
	"EACCES\0\0\0\0\0\0\0\0\0\0"
	"EFAULT\0\0\0\0\0\0\0\0\0\0"
	"ENOTBLK\0\0\0\0\0\0\0\0\0"
	"EBUSY\0\0\0\0\0\0\0\0\0\0\0"
	"EEXIST\0\0\0\0\0\0\0\0\0\0"
	"EXDEV\0\0\0\0\0\0\0\0\0\0\0"
	"ENODEV\0\0\0\0\0\0\0\0\0\0"
	"ENOTDIR\0\0\0\0\0\0\0\0\0"
	"EISDIR\0\0\0\0\0\0\0\0\0\0"
	"EINVAL\0\0\0\0\0\0\0\0\0\0"
	"ENFILE\0\0\0\0\0\0\0\0\0\0"
	"EMFILE\0\0\0\0\0\0\0\0\0\0"
	"ENOTTY\0\0\0\0\0\0\0\0\0\0"
	"ETXTBSY\0\0\0\0\0\0\0\0\0"
	"EFBIG\0\0\0\0\0\0\0\0\0\0\0"
	"ENOSPC\0\0\0\0\0\0\0\0\0\0"
	"ESPIPE\0\0\0\0\0\0\0\0\0\0"
	"EROFS\0\0\0\0\0\0\0\0\0\0\0"
	"EMLINK\0\0\0\0\0\0\0\0\0\0"
	"EPIPE\0\0\0\0\0\0\0\0\0\0\0"
	"EDOM\0\0\0\0\0\0\0\0\0\0\0\0"
	"ERANGE\0\0\0\0\0\0\0\0\0\0"
	"EDEADLK\0\0\0\0\0\0\0\0\0"
	"ENAMETOOLONG\0\0\0\0"
	"ENOLCK\0\0\0\0\0\0\0\0\0\0"
	"ENOSYS\0\0\0\0\0\0\0\0\0\0"
	"ENOTEMPTY\0\0\0\0\0\0\0"
	"ELOOP\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"ENOMSG\0\0\0\0\0\0\0\0\0\0"
	"EIDRM\0\0\0\0\0\0\0\0\0\0\0"
	"ECHRNG\0\0\0\0\0\0\0\0\0\0"
	"EL2NSYNC\0\0\0\0\0\0\0\0"
	"EL3HLT\0\0\0\0\0\0\0\0\0\0"
	"EL3RST\0\0\0\0\0\0\0\0\0\0"
	"ELNRNG\0\0\0\0\0\0\0\0\0\0"
	"EUNATCH\0\0\0\0\0\0\0\0\0"
	"ENOCSI\0\0\0\0\0\0\0\0\0\0"
	"EL2HLT\0\0\0\0\0\0\0\0\0\0"
	"EBADE\0\0\0\0\0\0\0\0\0\0\0"
	"EBADR\0\0\0\0\0\0\0\0\0\0\0"
	"EXFULL\0\0\0\0\0\0\0\0\0\0"
	"ENOANO\0\0\0\0\0\0\0\0\0\0"
	"EBADRQC\0\0\0\0\0\0\0\0\0"
	"EBADSLT\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"EBFONT\0\0\0\0\0\0\0\0\0\0"
	"ENOSTR\0\0\0\0\0\0\0\0\0\0"
	"ENODATA\0\0\0\0\0\0\0\0\0"
	"ETIME\0\0\0\0\0\0\0\0\0\0\0"
	"ENOSR\0\0\0\0\0\0\0\0\0\0\0"
	"ENONET\0\0\0\0\0\0\0\0\0\0"
	"ENOPKG\0\0\0\0\0\0\0\0\0\0"
	"EREMOTE\0\0\0\0\0\0\0\0\0"
	"ENOLINK\0\0\0\0\0\0\0\0\0"
	"EADV\0\0\0\0\0\0\0\0\0\0\0\0"
	"ESRMNT\0\0\0\0\0\0\0\0\0\0"
	"ECOMM\0\0\0\0\0\0\0\0\0\0\0"
	"EPROTO\0\0\0\0\0\0\0\0\0\0"
	"EMULTIHOP\0\0\0\0\0\0\0"
	"EDOTDOT\0\0\0\0\0\0\0\0\0"
	"EBADMSG\0\0\0\0\0\0\0\0\0"
	"EOVERFLOW\0\0\0\0\0\0\0"
	"ENOTUNIQ\0\0\0\0\0\0\0\0"
	"EBADFD\0\0\0\0\0\0\0\0\0\0"
	"EREMCHG\0\0\0\0\0\0\0\0\0"
	"ELIBACC\0\0\0\0\0\0\0\0\0"
	"ELIBBAD\0\0\0\0\0\0\0\0\0"
	"ELIBSCN\0\0\0\0\0\0\0\0\0"
	"ELIBMAX\0\0\0\0\0\0\0\0\0"
	"ELIBEXEC\0\0\0\0\0\0\0\0"
	"EILSEQ\0\0\0\0\0\0\0\0\0\0"
	"ERESTART\0\0\0\0\0\0\0\0"
	"ESTRPIPE\0\0\0\0\0\0\0\0"
	"EUSERS\0\0\0\0\0\0\0\0\0\0"
	"ENOTSOCK\0\0\0\0\0\0\0\0"
	"EDESTADDRREQ\0\0\0\0"
	"EMSGSIZE\0\0\0\0\0\0\0\0"
	"EPROTOTYPE\0\0\0\0\0\0"
	"ENOPROTOOPT\0\0\0\0\0"
	"EPROTONOSUPPORT\0"
	"ESOCKTNOSUPPORT\0"
	"EOPNOTSUPP\0\0\0\0\0\0"
	"EPFNOSUPPORT\0\0\0\0"
	"EAFNOSUPPORT\0\0\0\0"
	"EADDRINUSE\0\0\0\0\0\0"
	"EADDRNOTAVAIL\0\0\0"
	"ENETDOWN\0\0\0\0\0\0\0\0"
	"ENETUNREACH\0\0\0\0\0"
	"ENETRESET\0\0\0\0\0\0\0"
	"ECONNABORTED\0\0\0\0"
	"ECONNRESET\0\0\0\0\0\0"
	"ENOBUFS\0\0\0\0\0\0\0\0\0"
	"EISCONN\0\0\0\0\0\0\0\0\0"
	"ENOTCONN\0\0\0\0\0\0\0\0"
	"ESHUTDOWN\0\0\0\0\0\0\0"
	"ETOOMANYREFS\0\0\0\0"
	"ETIMEDOUT\0\0\0\0\0\0\0"
	"ECONNREFUSED\0\0\0\0"
	"EHOSTDOWN\0\0\0\0\0\0\0"
	"EHOSTUNREACH\0\0\0\0"
	"EALREADY\0\0\0\0\0\0\0\0"
	"EINPROGRESS\0\0\0\0\0"
	"ESTALE\0\0\0\0\0\0\0\0\0\0"
	"EUCLEAN\0\0\0\0\0\0\0\0\0"
	"ENOTNAM\0\0\0\0\0\0\0\0\0"
	"ENAVAIL\0\0\0\0\0\0\0\0\0"
	"EISNAM\0\0\0\0\0\0\0\0\0\0"
	"EREMOTEIO\0\0\0\0\0\0\0"
	"EDQUOT\0\0\0\0\0\0\0\0\0\0"
	"ENOMEDIUM\0\0\0\0\0\0\0"
	"EMEDIUMTYPE\0\0\0\0\0"
	"ECANCELED\0\0\0\0\0\0\0"
	"ENOKEY\0\0\0\0\0\0\0\0\0\0"
	"EKEYEXPIRED\0\0\0\0\0"
	"EKEYREVOKED\0\0\0\0\0"
	"EKEYREJECTED\0\0\0\0"
	"EOWNERDEAD\0\0\0\0\0\0"
	"ENOTRECOVERABLE\0"
	"ERFKILL\0\0\0\0\0\0\0\0\0"
	"EHWPOISON";
	return &template[((-1)-err)*16];
}

#endif
