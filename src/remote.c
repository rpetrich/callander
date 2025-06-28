#define _GNU_SOURCE
#include "remote.h"

#include "axon.h"
#include "darwin.h"
#include "freestanding.h"
#include "proxy.h"
#include "windows.h"

#include <dirent.h>
#include <sched.h>
#include <string.h>

intptr_t remote_mkdirat(int dirfd, const char *path, mode_t mode)
{
	return PROXY_LINUX_CALL(LINUX_SYS_mkdirat, proxy_value(dirfd), proxy_string(path), proxy_value(mode));
}

intptr_t remote_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev)
{
	return PROXY_LINUX_CALL(LINUX_SYS_mknodat, proxy_value(dirfd), proxy_string(path), proxy_value(mode), proxy_value(dev));
}

intptr_t remote_openat(int dirfd, const char *path, int flags, mode_t mode)
{
	return PROXY_LINUX_CALL(LINUX_SYS_openat, proxy_value(dirfd), proxy_string(path), proxy_value(flags), proxy_value(mode));
}

intptr_t remote_unlinkat(int dirfd, const char *path, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_unlinkat, proxy_value(dirfd), proxy_string(path), proxy_value(flags));
}

intptr_t remote_renameat2(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_renameat2, proxy_value(old_dirfd), proxy_string(old_path), proxy_value(new_dirfd), proxy_string(new_path), proxy_value(flags));
}

intptr_t remote_linkat(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_linkat, proxy_value(old_dirfd), proxy_string(old_path), proxy_value(new_dirfd), proxy_string(new_path), proxy_value(flags));
}

intptr_t remote_symlinkat(const char *old_path, int new_dirfd, const char *new_path)
{
	return PROXY_LINUX_CALL(LINUX_SYS_symlinkat, proxy_string(old_path), proxy_value(new_dirfd), proxy_string(new_path));
}

intptr_t remote_truncate(const char *path, off_t length)
{
	return PROXY_LINUX_CALL(LINUX_SYS_truncate, proxy_string(path), proxy_value(length));
}

intptr_t remote_fchmodat(int dirfd, const char *path, mode_t mode, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fchmodat, proxy_value(dirfd), proxy_string(path), proxy_value(mode), proxy_value(flags));
}

intptr_t remote_fchmod(int fd, mode_t mode)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fchmod, proxy_value(fd), proxy_value(mode));
}

intptr_t remote_fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fchownat, proxy_value(dirfd), proxy_string(path), proxy_value(owner), proxy_value(group), proxy_value(flags));
}

intptr_t remote_fchown(int fd, uid_t owner, gid_t group)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fchown, proxy_value(fd), proxy_value(owner), proxy_value(group));
}

intptr_t remote_utimensat(int dirfd, const char *path, const struct timespec times[2], int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_utimensat, proxy_value(dirfd), proxy_string(path), proxy_in(times, sizeof(struct timespec) * 2), proxy_value(flags));
}

intptr_t remote_read(int fd, char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	return PROXY_LINUX_CALL(LINUX_SYS_read, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz));
}

intptr_t remote_write(int fd, const char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	return PROXY_LINUX_CALL(LINUX_SYS_write, proxy_value(fd), proxy_in(buf, bufsz), proxy_value(bufsz));
}

intptr_t remote_recvfrom(int fd, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	trim_size(&bufsz);
	return PROXY_LINUX_CALL(LINUX_SYS_recvfrom, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz), proxy_value(flags), src_addr ? proxy_out(src_addr, *addrlen) : proxy_value(0), proxy_inout(addrlen, sizeof(*addrlen)));
}

intptr_t remote_sendto(int fd, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
	trim_size(&bufsz);
	return PROXY_LINUX_CALL(LINUX_SYS_sendto, proxy_value(fd), proxy_in(buf, bufsz), proxy_value(bufsz), proxy_value(flags), proxy_in(dest_addr, dest_len), proxy_value(dest_len));
}

intptr_t remote_lseek(int fd, off_t offset, int whence)
{
	return PROXY_LINUX_CALL(LINUX_SYS_lseek, proxy_value(fd), proxy_value(offset), proxy_value(whence));
}

intptr_t remote_fadvise64(int fd, size_t offset, size_t len, int advice)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fadvise64, proxy_value(fd), proxy_value(offset), proxy_value(len), proxy_value(advice));
}

intptr_t remote_readahead(int fd, off_t offset, size_t count)
{
	return PROXY_LINUX_CALL(LINUX_SYS_readahead, proxy_value(fd), proxy_value(offset), proxy_value(count));
}

intptr_t remote_pread(int fd, void *buf, size_t count, off_t offset)
{
	trim_size(&count);
	return PROXY_LINUX_CALL(LINUX_SYS_pread64, proxy_value(fd), proxy_out(buf, count), proxy_value(count), proxy_value(offset));
}

intptr_t remote_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	trim_size(&count);
	return PROXY_LINUX_CALL(LINUX_SYS_pwrite64, proxy_value(fd), proxy_in(buf, count), proxy_value(count), proxy_value(offset));
}

intptr_t remote_flock(int fd, int how)
{
	return PROXY_LINUX_CALL(LINUX_SYS_flock, proxy_value(fd), proxy_value(how));
}

intptr_t remote_fsync(int fd)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fsync, proxy_value(fd));
}

intptr_t remote_fdatasync(int fd)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fdatasync, proxy_value(fd));
}

intptr_t remote_syncfs(int fd)
{
	return PROXY_LINUX_CALL(LINUX_SYS_syncfs, proxy_value(fd));
}

intptr_t remote_sync_file_range(int fd, off_t offset, off_t nbytes, unsigned int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_sync_file_range, proxy_value(fd), proxy_value(offset), proxy_value(nbytes), proxy_value(flags));
}

intptr_t remote_ftruncate(int fd, off_t length)
{
	return PROXY_LINUX_CALL(LINUX_SYS_ftruncate, proxy_value(fd), proxy_value(length));
}

intptr_t remote_fallocate(int fd, int mode, off_t offset, off_t len)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fallocate, proxy_value(fd), proxy_value(mode), proxy_value(offset), proxy_value(len));
}

intptr_t remote_recvmsg(struct thread_storage *thread, int fd, struct msghdr *msghdr, int flags)
{
	if (msghdr->msg_name != NULL || msghdr->msg_namelen != 0 || msghdr->msg_control != NULL || msghdr->msg_controllen != 0) {
		// TODO: support names and control data
		return invalid_remote_operation();
	}
	int iovcnt = msghdr->msg_iovlen;
	// allocate a local iovec
	struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
	struct attempt_cleanup_state state;
	attempt_push_free(thread, &state, iov_remote);
	// calculate the total size
	size_t total_size = sizeof(struct iovec) * iovcnt;
	for (int i = 0; i < iovcnt; i++) {
		size_t len = msghdr->msg_iov[i].iov_len;
		iov_remote[i].iov_len = len;
		total_size += len;
	}
	// allocate a remote buffer
	attempt_proxy_alloc_state remote_buf;
	attempt_proxy_alloc(total_size, thread, &remote_buf);
	// set up the vectors
	intptr_t buf_cur = remote_buf.addr;
	for (int i = 0; i < iovcnt; i++) {
		size_t len = iov_remote[i].iov_len;
		iov_remote[i].iov_base = (void *)buf_cur;
		buf_cur += len;
	}
	// poke the iovec
	intptr_t result = proxy_poke(buf_cur, sizeof(struct iovec) * iovcnt, iov_remote);
	if (result < 0) {
		attempt_pop_free(&state);
		attempt_proxy_free(&remote_buf);
		return result;
	}
	// perform the recvmsg remotely
	struct msghdr copy = *msghdr;
	copy.msg_iov = (struct iovec *)buf_cur;
	result = PROXY_LINUX_CALL(LINUX_SYS_recvmsg, proxy_value(fd), proxy_in(&copy, sizeof(struct msghdr)), proxy_value(flags));
	if (result >= 0) {
		// peek the bytes we received
		buf_cur = remote_buf.addr;
		for (int i = 0; i < iovcnt; i++) {
			size_t len = iov_remote[i].iov_len;
			intptr_t peek_result = proxy_peek(buf_cur, len, msghdr->msg_iov[i].iov_base);
			if (peek_result < 0) {
				attempt_pop_free(&state);
				attempt_proxy_free(&remote_buf);
				return peek_result;
			}
			buf_cur += len;
		}
	}
	attempt_pop_free(&state);
	attempt_proxy_free(&remote_buf);
	return result;
}

intptr_t remote_sendmsg(struct thread_storage *thread, int fd, const struct msghdr *msghdr, int flags)
{
	if (msghdr->msg_name != NULL || msghdr->msg_namelen != 0 || msghdr->msg_control != NULL || msghdr->msg_controllen != 0) {
		// TODO: support names and control data
		return invalid_remote_operation();
	}
	int iovcnt = msghdr->msg_iovlen;
	// allocate a local iovec
	struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
	struct attempt_cleanup_state state;
	attempt_push_free(thread, &state, iov_remote);
	// calculate the total size
	size_t total_size = sizeof(struct iovec) * iovcnt;
	for (int i = 0; i < iovcnt; i++) {
		size_t len = msghdr->msg_iov[i].iov_len;
		iov_remote[i].iov_len = len;
		total_size += len;
	}
	// allocate a remote buffer
	attempt_proxy_alloc_state remote_buf;
	attempt_proxy_alloc(total_size, thread, &remote_buf);
	// poke the bytes to send
	intptr_t buf_cur = remote_buf.addr;
	for (int i = 0; i < iovcnt; i++) {
		size_t len = iov_remote[i].iov_len;
		intptr_t result = proxy_poke(buf_cur, len, msghdr->msg_iov[i].iov_base);
		if (result < 0) {
			attempt_pop_free(&state);
			attempt_proxy_free(&remote_buf);
			return result;
		}
		iov_remote[i].iov_base = (void *)buf_cur;
		buf_cur += len;
	}
	// poke the iovec
	intptr_t result = proxy_poke(buf_cur, sizeof(struct iovec) * iovcnt, iov_remote);
	attempt_pop_free(&state);
	if (result < 0) {
		attempt_proxy_free(&remote_buf);
		return result;
	}
	// perform the sendmsg remotely
	struct msghdr copy = *msghdr;
	copy.msg_iov = (struct iovec *)buf_cur;
	result = PROXY_LINUX_CALL(LINUX_SYS_sendmsg, proxy_value(fd), proxy_in(&copy, sizeof(struct msghdr)), proxy_value(flags));
	attempt_proxy_free(&remote_buf);
	return result;
}

void remote_close(int fd)
{
	PROXY_LINUX_CALL(LINUX_SYS_close | PROXY_NO_RESPONSE, proxy_value(fd));
}

intptr_t remote_fcntl_basic(int fd, int cmd, intptr_t argument)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(cmd), proxy_value(argument));
}

intptr_t remote_fcntl_lock(int fd, int cmd, struct flock *lock)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(cmd), proxy_inout(lock, sizeof(struct flock)));
}

intptr_t remote_fcntl_int(int fd, int cmd, int *value)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(cmd), proxy_inout(value, sizeof(int)));
}

intptr_t remote_fstat(int fd, struct fs_stat *buf)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fstat, proxy_value(fd), proxy_out(buf, sizeof(*buf)));
}

intptr_t remote_newfstatat(int fd, const char *path, struct fs_stat *stat, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_newfstatat, proxy_value(fd), proxy_string(path), proxy_out(stat, sizeof(struct fs_stat)), proxy_value(flags));
}

intptr_t remote_statx(int fd, const char *path, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
	return PROXY_LINUX_CALL(LINUX_SYS_statx, proxy_value(fd), proxy_string(path), proxy_value(flags), proxy_value(mask), proxy_inout(statxbuf, sizeof(struct statx)));
}

intptr_t remote_statfs(const char *path, struct fs_statfs *out_buf)
{
	return PROXY_LINUX_CALL(LINUX_SYS_statfs, proxy_string(path), proxy_out(out_buf, sizeof(struct fs_statfs)));
}

intptr_t remote_fstatfs(int fd, struct fs_statfs *out_buf)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fstatfs, proxy_value(fd), proxy_out(out_buf, sizeof(struct fs_statfs)));
}

intptr_t remote_faccessat(int fd, const char *path, int mode, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_faccessat, proxy_value(fd), proxy_string(path), proxy_value(mode), proxy_value(flags));
}

intptr_t remote_readlinkat(int dirfd, const char *path, char *buf, size_t bufsz)
{
	return PROXY_LINUX_CALL(LINUX_SYS_readlinkat, proxy_value(dirfd), proxy_string(path), proxy_out(buf, bufsz), proxy_value(bufsz));
}

#define DEV_FD "/proc/self/fd/"

intptr_t remote_readlink_fd(int fd, char *buf, size_t size)
{
	// readlink the fd remotely
	char dev_path[64];
	memcpy(dev_path, DEV_FD, sizeof(DEV_FD) - 1);
	fs_utoa(fd, &dev_path[sizeof(DEV_FD) - 1]);
	return remote_readlinkat(AT_FDCWD, dev_path, buf, size);
}

intptr_t remote_getdents(int fd, char *buf, size_t size)
{
	trim_size(&size);
#ifndef __NR_getdents
	return -ENOSYS;
#else
	return PROXY_LINUX_CALL(LINUX_SYS_getdents, proxy_value(fd), proxy_out(buf, size), proxy_value(size));
#endif
}

intptr_t remote_getdents64(int fd, char *buf, size_t size)
{
	trim_size(&size);
	return PROXY_LINUX_CALL(LINUX_SYS_getdents64, proxy_value(fd), proxy_out(buf, size), proxy_value(size));
}

intptr_t remote_getxattr(const char *path, const char *name, void *out_value, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_getxattr, proxy_string(path), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
}

intptr_t remote_lgetxattr(const char *path, const char *name, void *out_value, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_lgetxattr, proxy_string(path), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
}

intptr_t remote_fgetxattr(int fd, const char *name, void *out_value, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fgetxattr, proxy_value(fd), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
}

intptr_t remote_setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_setxattr, proxy_string(path), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
}

intptr_t remote_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_lsetxattr, proxy_string(path), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
}

intptr_t remote_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fsetxattr, proxy_value(fd), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
}

intptr_t remote_removexattr(const char *path, const char *name)
{
	return PROXY_LINUX_CALL(LINUX_SYS_removexattr, proxy_string(path), proxy_string(name));
}

intptr_t remote_lremovexattr(const char *path, const char *name)
{
	return PROXY_LINUX_CALL(LINUX_SYS_lremovexattr, proxy_string(path), proxy_string(name));
}

intptr_t remote_fremovexattr(int fd, const char *name)
{
	return PROXY_LINUX_CALL(LINUX_SYS_fremovexattr, proxy_value(fd), proxy_string(name));
}

intptr_t remote_listxattr(const char *path, void *out_value, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_listxattr, proxy_string(path), proxy_out(out_value, size), proxy_value(size));
}

intptr_t remote_llistxattr(const char *path, void *out_value, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_llistxattr, proxy_string(path), proxy_out(out_value, size), proxy_value(size));
}

intptr_t remote_flistxattr(int fd, void *out_value, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_flistxattr, proxy_value(fd), proxy_out(out_value, size), proxy_value(size));
}

intptr_t remote_socket(int domain, int type, int protocol)
{
	return PROXY_LINUX_CALL(LINUX_SYS_socket | PROXY_NO_WORKER, proxy_value(domain), proxy_value(type), proxy_value(protocol));
}

intptr_t remote_connect(int sockfd, const struct sockaddr *addr, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_connect, proxy_value(sockfd), proxy_in(addr, size), proxy_value(size));
}

intptr_t remote_bind(int sockfd, const struct sockaddr *addr, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_bind, proxy_value(sockfd), proxy_in(addr, size), proxy_value(size));
}

intptr_t remote_listen(int sockfd, int backlog)
{
	return PROXY_LINUX_CALL(LINUX_SYS_listen, proxy_value(sockfd), proxy_value(backlog));
}

intptr_t remote_accept4(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_accept4, proxy_value(sockfd), addrlen ? proxy_out(addr, *addrlen) : proxy_value(0), proxy_inout(addrlen, sizeof(*addrlen)), proxy_value(flags));
}

intptr_t remote_getsockopt(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen)
{
	return PROXY_LINUX_CALL(LINUX_SYS_getsockopt | PROXY_NO_WORKER, proxy_value(sockfd), proxy_value(level), proxy_value(optname), proxy_out(optval, *optlen), proxy_inout(optlen, sizeof(*optlen)));
}

intptr_t remote_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	return PROXY_LINUX_CALL(LINUX_SYS_setsockopt | PROXY_NO_WORKER, proxy_value(sockfd), proxy_value(level), proxy_value(optname), proxy_in(optval, optlen), proxy_value(optlen));
}

intptr_t remote_getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return PROXY_LINUX_CALL(LINUX_SYS_getsockname | PROXY_NO_WORKER, proxy_value(sockfd), proxy_out(addr, *addrlen), proxy_inout(addrlen, sizeof(socklen_t)));
}

intptr_t remote_getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return PROXY_LINUX_CALL(LINUX_SYS_getpeername | PROXY_NO_WORKER, proxy_value(sockfd), proxy_out(addr, *addrlen), proxy_inout(addrlen, sizeof(socklen_t)));
}

intptr_t remote_shutdown(int sockfd, int how)
{
	return PROXY_LINUX_CALL(LINUX_SYS_shutdown, proxy_value(sockfd), proxy_value(how));
}

intptr_t remote_sendfile(int out_fd, int in_fd, off_t *offset, size_t size)
{
	return PROXY_LINUX_CALL(LINUX_SYS_sendfile, proxy_value(out_fd), proxy_value(in_fd), proxy_inout(offset, sizeof(off_t)), proxy_value(size));
}

intptr_t remote_splice(int in_fd, off_t *off_in, int out_fd, off_t *off_out, size_t size, unsigned int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_splice, proxy_value(in_fd), proxy_inout(off_in, sizeof(off_t)), proxy_value(out_fd), proxy_inout(off_out, sizeof(off_t)), proxy_value(size), proxy_value(flags));
}

intptr_t remote_tee(int fd_in, int fd_out, size_t len, unsigned int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_tee, proxy_value(fd_in), proxy_value(fd_out), proxy_value(len), proxy_value(flags));
}

intptr_t remote_copy_file_range(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len, unsigned int flags)
{
	return PROXY_LINUX_CALL(LINUX_SYS_copy_file_range, proxy_value(fd_in), proxy_inout(off_in, sizeof(off_t)), proxy_value(fd_out), proxy_inout(off_out, sizeof(off_t)), proxy_value(len), proxy_value(flags));
}

intptr_t remote_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
#ifdef LINUX_SYS_poll
	return PROXY_LINUX_CALL(LINUX_SYS_poll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_value(timeout));
#else
	if (timeout < 0) {
		return PROXY_LINUX_CALL(LINUX_SYS_ppoll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_value(0), proxy_value(0), proxy_value(0));
	} else {
		struct timespec timeout_spec;
		timeout_spec.tv_sec = timeout / 1000;
		timeout_spec.tv_nsec = (timeout % 1000) * 1000000;
		return PROXY_LINUX_CALL(LINUX_SYS_ppoll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_in(&timeout_spec, sizeof(struct timespec)), proxy_value(0), proxy_value(0));
	}
#endif
}

intptr_t remote_ppoll(struct pollfd *fds, nfds_t nfds, struct timespec *timeout)
{
	return PROXY_LINUX_CALL(LINUX_SYS_ppoll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), timeout != NULL ? proxy_inout(timeout, sizeof(struct timespec)) : proxy_value(0), proxy_value(0), proxy_value(0));
}

__attribute__((noinline)) intptr_t invalid_remote_operation(void)
{
	return -EINVAL;
}
