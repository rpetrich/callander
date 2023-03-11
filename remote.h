#ifndef REMOTE_H
#define REMOTE_H

#include "freestanding.h"

#include <fcntl.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

struct thread_storage;

intptr_t remote_openat(int dirfd, const char *path, int flags, mode_t mode);
intptr_t remote_truncate(const char *path, off_t length);

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
intptr_t remote_ftruncate(int fd, off_t length);
intptr_t remote_recvmsg(struct thread_storage *thread, int fd, struct msghdr *msg, int flags);
intptr_t remote_sendmsg(struct thread_storage *thread, int fd, const struct msghdr *msg, int flags);
void remote_close(int fd);

intptr_t remote_fcntl_basic(int fd, int cmd, intptr_t argument);
intptr_t remote_fcntl_lock(int fd, int cmd, struct flock *lock);
intptr_t remote_fcntl_int(int fd, int cmd, int *value);

intptr_t remote_fstat(int fd, struct fs_stat *buf);
intptr_t remote_newfstatat(int fd, const char *path, struct fs_stat *stat, int flags);
intptr_t remote_faccessat(int fd, const char *path, int mode, int flag);
intptr_t remote_readlinkat(int dirfd, const char *path, char *buf, size_t bufsz);
intptr_t remote_readlink_fd(int fd, char *buf, size_t size);
intptr_t remote_getdents64(int fd, char *buf, size_t size);

intptr_t remote_socket(int domain, int type, int protocol);
intptr_t remote_getsockopt(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen);
intptr_t remote_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

intptr_t remote_poll(struct pollfd *fds, nfds_t nfds, int timeout);
intptr_t remote_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout);

intptr_t invalid_remote_operation(void);

#endif
