#ifndef REMOTE_H
#define REMOTE_H

#include "axon.h"
#include "freestanding.h"
#include "linux.h"
#include "proxy.h"

#include <fcntl.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

struct thread_storage;

void remote_spawn_worker(void);

intptr_t remote_mkdirat(int dirfd, const char *path, mode_t mode);
intptr_t remote_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev);
intptr_t remote_openat(int dirfd, const char *path, int flags, mode_t mode);
intptr_t remote_unlinkat(int dirfd, const char *path, int flags);

intptr_t remote_renameat2(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags);
intptr_t remote_linkat(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags);
intptr_t remote_symlinkat(const char *old_path, int new_dirfd, const char *new_path);

intptr_t remote_truncate(const char *path, off_t length);
intptr_t remote_fchmodat(int dirfd, const char *path, mode_t mode, int flags);
intptr_t remote_fchmod(int fd, mode_t mode);
intptr_t remote_fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags);
intptr_t remote_fchown(int fd, uid_t owner, gid_t group);
intptr_t remote_utimensat(int dirfd, const char *path, const struct timespec times[2], int flags);

intptr_t remote_read(int fd, char *buf, size_t bufsz);
intptr_t remote_write(int fd, const char *buf, size_t bufsz);
intptr_t remote_recvfrom(int fd, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
intptr_t remote_sendto(int fd, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
intptr_t remote_lseek(int fd, off_t offset, int whence);
intptr_t remote_fadvise64(int fd, size_t offset, size_t len, int advice);
intptr_t remote_readahead(int fd, off_t offset, size_t count);
intptr_t remote_pread(int fd, void *buf, size_t count, off_t offset);
intptr_t remote_pwrite(int fd, const void *buf, size_t count, off_t offset);
intptr_t remote_flock(int fd, int how);
intptr_t remote_fsync(int fd);
intptr_t remote_fdatasync(int fd);
intptr_t remote_syncfs(int fd);
intptr_t remote_sync_file_range(int fd, off_t offset, off_t nbytes, unsigned int flags);
intptr_t remote_ftruncate(int fd, off_t length);
intptr_t remote_fallocate(int fd, int mode, off_t offset, off_t len);
intptr_t remote_recvmsg(struct thread_storage *thread, int fd, struct msghdr *msg, int flags);
intptr_t remote_sendmsg(struct thread_storage *thread, int fd, const struct msghdr *msg, int flags);
void remote_close(int fd);

intptr_t remote_fcntl_basic(int fd, int cmd, intptr_t argument);
intptr_t remote_fcntl_lock(int fd, int cmd, struct flock *lock);
intptr_t remote_fcntl_int(int fd, int cmd, int *value);

intptr_t remote_fstat(int fd, struct fs_stat *buf);
intptr_t remote_newfstatat(int fd, const char *path, struct fs_stat *stat, int flags);
intptr_t remote_statx(int fd, const char *path, int flags, unsigned int mask, struct linux_statx *restrict statxbuf);
intptr_t remote_statfs(const char *path, struct fs_statfs *out_buf);
intptr_t remote_fstatfs(int fd, struct fs_statfs *out_buf);
intptr_t remote_faccessat(int fd, const char *path, int mode, int flag);
intptr_t remote_readlinkat(int dirfd, const char *path, char *buf, size_t bufsz);
intptr_t remote_readlink_fd(int fd, char *buf, size_t size);
intptr_t remote_getdents(int fd, char *buf, size_t size);
intptr_t remote_getdents64(int fd, char *buf, size_t size);

intptr_t remote_getxattr(const char *path, const char *name, void *out_value, size_t size);
intptr_t remote_lgetxattr(const char *path, const char *name, void *out_value, size_t size);
intptr_t remote_fgetxattr(int fd, const char *name, void *out_value, size_t size);

intptr_t remote_setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
intptr_t remote_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags);
intptr_t remote_fsetxattr(int fd, const char *name, const void *out, size_t size, int flags);

intptr_t remote_removexattr(const char *path, const char *name);
intptr_t remote_lremovexattr(const char *path, const char *name);
intptr_t remote_fremovexattr(int fd, const char *name);

intptr_t remote_listxattr(const char *path, void *out_value, size_t size);
intptr_t remote_llistxattr(const char *path, void *out_value, size_t size);
intptr_t remote_flistxattr(int fd, void *out_value, size_t size);

intptr_t remote_socket(int domain, int type, int protocol);
intptr_t remote_connect(int sockfd, const struct sockaddr *addr, size_t size);
intptr_t remote_bind(int sockfd, const struct sockaddr *addr, size_t size);
intptr_t remote_listen(int sockfd, int backlog);
intptr_t remote_accept4(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags);
intptr_t remote_getsockopt(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen);
intptr_t remote_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
intptr_t remote_getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
intptr_t remote_getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
intptr_t remote_shutdown(int sockfd, int how);

intptr_t remote_sendfile(int out_fd, int in_fd, off_t *offset, size_t size);
intptr_t remote_splice(int in_fd, off_t *off_in, int out_fd, off_t *off_out, size_t size, unsigned int flags);
intptr_t remote_tee(int fd_in, int fd_out, size_t len, unsigned int flags);
intptr_t remote_copy_file_range(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len, unsigned int flags);

intptr_t remote_poll(struct pollfd *fds, nfds_t nfds, int timeout);
intptr_t remote_ppoll(struct pollfd *fds, nfds_t nfds, struct timespec *timeout);

intptr_t invalid_remote_operation(void);

static inline void trim_size(size_t *size)
{
	if (UNLIKELY(*size >= PROXY_BUFFER_SIZE)) {
		*size = PROXY_BUFFER_SIZE;
	}
}

#endif
