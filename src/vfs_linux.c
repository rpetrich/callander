#define _GNU_SOURCE
#include "vfs.h"
#include "proxy.h"

extern const struct vfs_path_ops linux_path_ops;

static intptr_t linux_path_mkdirat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode)
{
	return PROXY_CALL(LINUX_SYS_mkdirat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(mode));
}

static intptr_t linux_path_mknodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, dev_t dev)
{
	return PROXY_CALL(LINUX_SYS_mknodat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(mode), proxy_value(dev));
}

static intptr_t linux_path_openat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, mode_t mode, struct vfs_resolved_file *out_file)
{
	intptr_t result = PROXY_CALL(LINUX_SYS_openat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(flags), proxy_value(mode));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &linux_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t linux_path_unlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags)
{
	return PROXY_CALL(LINUX_SYS_unlinkat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(flags));
}

static intptr_t linux_path_renameat2(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return PROXY_CALL(LINUX_SYS_renameat2, proxy_value(old_resolved.info.handle), proxy_string(old_resolved.info.path), proxy_value(new_resolved.info.handle), proxy_string(new_resolved.info.path), proxy_value(flags));
}

static intptr_t linux_path_linkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return PROXY_CALL(LINUX_SYS_linkat, proxy_value(old_resolved.info.handle), proxy_string(old_resolved.info.path), proxy_value(new_resolved.info.handle), proxy_string(new_resolved.info.path), proxy_value(flags));
}

static intptr_t linux_path_symlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path new_resolved, const char *old_path)
{
	return PROXY_CALL(LINUX_SYS_symlinkat, proxy_string(old_path), proxy_value(new_resolved.info.handle), proxy_string(new_resolved.info.path));
}

static intptr_t linux_path_truncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	if (resolved.info.handle != AT_FDCWD) {
		return vfs_truncate_via_open_and_ftruncate(thread, resolved, length);
	}
	return FS_SYSCALL(LINUX_SYS_truncate, (intptr_t)resolved.info.path, length);
}

static intptr_t linux_path_fchmodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, int flags)
{
	return PROXY_CALL(LINUX_SYS_fchmodat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(mode), proxy_value(flags));
}

static intptr_t linux_path_fchownat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, uid_t owner, gid_t group, int flags)
{
	return PROXY_CALL(LINUX_SYS_fchownat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(owner), proxy_value(group), proxy_value(flags));
}

static intptr_t linux_path_utimensat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const struct timespec times[2], int flags)
{
	return PROXY_CALL(LINUX_SYS_utimensat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_in(times, sizeof(struct timespec) * 2), proxy_value(flags));
}

static intptr_t linux_path_newfstatat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_stat *out_stat, int flags)
{
	return PROXY_CALL(LINUX_SYS_newfstatat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_out(out_stat, sizeof(struct fs_stat)), proxy_value(flags));
}

static intptr_t linux_path_statx(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
	return PROXY_CALL(LINUX_SYS_statx, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(flags), proxy_value(mask), proxy_inout(statxbuf, sizeof(struct statx)));
}

static intptr_t linux_path_statfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_statfs *out_buf)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(LINUX_SYS_statfs, (intptr_t)resolved.info.path, (intptr_t)out_buf);
}

static intptr_t linux_path_faccessat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int mode, int flags)
{
	return PROXY_CALL(LINUX_SYS_faccessat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_value(mode), proxy_value(flags));
}

static intptr_t linux_path_readlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, char *buf, size_t bufsz)
{
	return PROXY_CALL(LINUX_SYS_readlinkat, proxy_value(resolved.info.handle), proxy_string(resolved.info.path), proxy_out(buf, bufsz), proxy_value(bufsz));
}

static intptr_t linux_path_getxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, void *out_value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return PROXY_CALL((flags & AT_SYMLINK_NOFOLLOW) ? LINUX_SYS_lgetxattr : LINUX_SYS_getxattr, proxy_string(path), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
}

static intptr_t linux_path_setxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, const void *value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return PROXY_CALL((flags & AT_SYMLINK_NOFOLLOW) ? LINUX_SYS_lsetxattr : LINUX_SYS_setxattr, proxy_string(path), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
}

static intptr_t linux_path_removexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return PROXY_CALL((flags & AT_SYMLINK_NOFOLLOW) ? LINUX_SYS_lremovexattr : LINUX_SYS_removexattr, proxy_string(path), proxy_string(name));
}

static intptr_t linux_path_listxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, void *out_value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return PROXY_CALL((flags & AT_SYMLINK_NOFOLLOW) ? LINUX_SYS_llistxattr : LINUX_SYS_listxattr, proxy_string(path), proxy_out(out_value, size), proxy_value(size));
}

static intptr_t linux_file_socket(__attribute__((unused)) struct thread_storage *, int domain, int type, int protocol, struct vfs_resolved_file *out_file)
{
	intptr_t result = PROXY_CALL(LINUX_SYS_socket | PROXY_NO_WORKER, proxy_value(domain), proxy_value(type), proxy_value(protocol));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file) {
			.ops = &linux_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t linux_file_close(struct vfs_resolved_file file)
{
	PROXY_CALL(LINUX_SYS_close | PROXY_NO_RESPONSE, proxy_value(file.handle));
	return 0;
}

static intptr_t linux_file_read(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	return PROXY_CALL(LINUX_SYS_read, proxy_value(file.handle), proxy_out(buf, bufsz), proxy_value(bufsz));	
}

static intptr_t linux_file_write(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	return PROXY_CALL(LINUX_SYS_write, proxy_value(file.handle), proxy_in(buf, bufsz), proxy_value(bufsz));	
}

static intptr_t linux_file_recvfrom(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	trim_size(&bufsz);
	return PROXY_CALL(LINUX_SYS_recvfrom, proxy_value(file.handle), proxy_out(buf, bufsz), proxy_value(bufsz), proxy_value(flags), src_addr ? proxy_out(src_addr, *addrlen) : proxy_value(0), proxy_inout(addrlen, sizeof(*addrlen)));
}

static intptr_t linux_file_sendto(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
	trim_size(&bufsz);
	return PROXY_CALL(LINUX_SYS_sendto, proxy_value(file.handle), proxy_in(buf, bufsz), proxy_value(bufsz), proxy_value(flags), proxy_in(dest_addr, dest_len), proxy_value(dest_len));
}

static intptr_t linux_file_lseek(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, int whence)
{
	return PROXY_CALL(LINUX_SYS_lseek, proxy_value(file.handle), proxy_value(offset), proxy_value(whence));
}

static intptr_t linux_file_fadvise64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, size_t offset, size_t len, int advice)
{
	return PROXY_CALL(LINUX_SYS_fadvise64, proxy_value(file.handle), proxy_value(offset), proxy_value(len), proxy_value(advice));
}

static intptr_t linux_file_readahead(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, size_t count)
{
	return PROXY_CALL(LINUX_SYS_readahead, proxy_value(file.handle), proxy_value(offset), proxy_value(count));
}

static intptr_t linux_file_pread(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *buf, size_t count, off_t offset)
{
	trim_size(&count);
	return PROXY_CALL(LINUX_SYS_pread64, proxy_value(file.handle), proxy_out(buf, count), proxy_value(count), proxy_value(offset));
}

static intptr_t linux_file_pwrite(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const void *buf, size_t count, off_t offset)
{
	trim_size(&count);
	return PROXY_CALL(LINUX_SYS_pwrite64, proxy_value(file.handle), proxy_in(buf, count), proxy_value(count), proxy_value(offset));
}

static intptr_t linux_file_flock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return PROXY_CALL(LINUX_SYS_flock, proxy_value(file.handle), proxy_value(how));
}

static intptr_t linux_file_fsync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return PROXY_CALL(LINUX_SYS_fsync, proxy_value(file.handle));
}

static intptr_t linux_file_fdatasync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return PROXY_CALL(LINUX_SYS_fdatasync, proxy_value(file.handle));
}

static intptr_t linux_file_syncfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return PROXY_CALL(LINUX_SYS_syncfs, proxy_value(file.handle));
}

static intptr_t linux_file_sync_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, off_t nbytes, unsigned int flags)
{
	return PROXY_CALL(LINUX_SYS_sync_file_range, proxy_value(file.handle), proxy_value(offset), proxy_value(nbytes), proxy_value(flags));
}

static intptr_t linux_file_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t length)
{
	return PROXY_CALL(LINUX_SYS_ftruncate, proxy_value(file.handle), proxy_value(length));
}

static intptr_t linux_file_fallocate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int mode, off_t offset, off_t len)
{
	return PROXY_CALL(LINUX_SYS_fallocate, proxy_value(file.handle), proxy_value(mode), proxy_value(offset), proxy_value(len));
}

static intptr_t linux_file_recvmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct msghdr *msghdr, int flags)
{
	if (msghdr->msg_name != NULL || msghdr->msg_namelen != 0 || msghdr->msg_control != NULL || msghdr->msg_controllen != 0) {
		// TODO: support names and control data
		return -EINVAL;
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
	attempt_proxy_alloc_state linux_buf;
	attempt_proxy_alloc(total_size, thread, &linux_buf);
	// set up the vectors
	intptr_t buf_cur = linux_buf.addr;
	for (int i = 0; i < iovcnt; i++) {
		size_t len = iov_remote[i].iov_len;
		iov_remote[i].iov_base = (void *)buf_cur;
		buf_cur += len;
	}
	// poke the iovec
	intptr_t result = proxy_poke(buf_cur, sizeof(struct iovec) * iovcnt, iov_remote);
	if (result < 0) {
		attempt_pop_free(&state);
		attempt_proxy_free(&linux_buf);
		return result;
	}
	// perform the recvmsg remotely
	struct msghdr copy = *msghdr;
	copy.msg_iov = (struct iovec *)buf_cur;
	result = PROXY_CALL(LINUX_SYS_recvmsg, proxy_value(file.handle), proxy_in(&copy, sizeof(struct msghdr)), proxy_value(flags));
	if (result >= 0) {
		// peek the bytes we received
		buf_cur = linux_buf.addr;
		for (int i = 0; i < iovcnt; i++) {
			size_t len = iov_remote[i].iov_len;
			intptr_t peek_result = proxy_peek(buf_cur, len, msghdr->msg_iov[i].iov_base);
			if (peek_result < 0) {
				attempt_pop_free(&state);
				attempt_proxy_free(&linux_buf);
				return peek_result;
			}
			buf_cur += len;
		}
	}
	attempt_pop_free(&state);
	attempt_proxy_free(&linux_buf);
	return result;
}

static intptr_t linux_file_sendmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct msghdr *msghdr, int flags)
{
	if (msghdr->msg_name != NULL || msghdr->msg_namelen != 0 || msghdr->msg_control != NULL || msghdr->msg_controllen != 0) {
		// TODO: support names and control data
		return -EINVAL;
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
	attempt_proxy_alloc_state linux_buf;
	attempt_proxy_alloc(total_size, thread, &linux_buf);
	// poke the bytes to send
	intptr_t buf_cur = linux_buf.addr;
	for (int i = 0; i < iovcnt; i++) {
		size_t len = iov_remote[i].iov_len;
		intptr_t result = proxy_poke(buf_cur, len, msghdr->msg_iov[i].iov_base);
		if (result < 0) {
			attempt_pop_free(&state);
			attempt_proxy_free(&linux_buf);
			return result;
		}
		iov_remote[i].iov_base = (void *)buf_cur;
		buf_cur += len;
	}
	// poke the iovec
	intptr_t result = proxy_poke(buf_cur, sizeof(struct iovec) * iovcnt, iov_remote);
	attempt_pop_free(&state);
	if (result < 0) {
		attempt_proxy_free(&linux_buf);
		return result;
	}
	// perform the sendmsg remotely
	struct msghdr copy = *msghdr;
	copy.msg_iov = (struct iovec *)buf_cur;
	result = PROXY_CALL(LINUX_SYS_sendmsg, proxy_value(file.handle), proxy_in(&copy, sizeof(struct msghdr)), proxy_value(flags));
	attempt_proxy_free(&linux_buf);
	return result;
}

static intptr_t linux_file_fcntl_basic(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, intptr_t argument)
{
	return PROXY_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_value(argument));
}

static intptr_t linux_file_fcntl_lock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, struct flock *lock)
{
	return PROXY_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_inout(lock, sizeof(struct flock)));
}

static intptr_t linux_file_fcntl_int(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, int *value)
{
	return PROXY_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_inout(value, sizeof(int)));
}

static intptr_t linux_file_fchmod(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, mode_t mode)
{
	return PROXY_CALL(LINUX_SYS_fchmod, proxy_value(file.handle), proxy_value(mode));
}

static intptr_t linux_file_fchown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, uid_t owner, gid_t group)
{
	return PROXY_CALL(LINUX_SYS_fchown, proxy_value(file.handle), proxy_value(owner), proxy_value(group));
}

static intptr_t linux_file_fstat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_stat *out_stat)
{
	return PROXY_CALL(LINUX_SYS_fstat, proxy_value(file.handle), proxy_out(out_stat, sizeof(struct fs_stat)));
}

static intptr_t linux_file_fstatfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_statfs *out_buf)
{
	return PROXY_CALL(LINUX_SYS_fstatfs, proxy_value(file.handle), proxy_out(out_buf, sizeof(struct fs_statfs)));
}

#define DEV_FD "/proc/self/fd/"
static intptr_t linux_file_readlink_fd(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	// readlink the fd remotely
	char dev_path[64];
	memcpy(dev_path, DEV_FD, sizeof(DEV_FD) - 1);
	fs_utoa(file.handle, &dev_path[sizeof(DEV_FD) - 1]);
	trim_size(&size);
	return vfs_call(readlinkat, ((struct vfs_resolved_path){ .ops = &linux_path_ops, .info = { .handle = AT_FDCWD, .path = dev_path } }), buf, size);
}

static intptr_t linux_file_getdents(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
#ifndef __NR_getdents
	return -ENOSYS;
#else
	trim_size(&size);
	return PROXY_CALL(LINUX_SYS_getdents, proxy_value(file.handle), proxy_out(buf, size), proxy_value(size));
#endif
}

static intptr_t linux_file_getdents64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	trim_size(&size);
	return PROXY_CALL(LINUX_SYS_getdents64, proxy_value(file.handle), proxy_out(buf, size), proxy_value(size));
}

static intptr_t linux_file_fgetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, void *out_value, size_t size)
{
	return PROXY_CALL(LINUX_SYS_fgetxattr, proxy_value(file.handle), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
}

static intptr_t linux_file_fsetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, const void *value, size_t size, int flags)
{
	return PROXY_CALL(LINUX_SYS_fgetxattr, proxy_value(file.handle), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
}

static intptr_t linux_file_fremovexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name)
{
	return PROXY_CALL(LINUX_SYS_fremovexattr, proxy_value(file.handle), proxy_string(name));
}

static intptr_t linux_file_flistxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *out_value, size_t size)
{
	return PROXY_CALL(LINUX_SYS_flistxattr, proxy_value(file.handle), proxy_out(out_value, size), proxy_value(size));
}

static intptr_t linux_file_connect(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return PROXY_CALL(LINUX_SYS_connect, proxy_value(file.handle), proxy_in(addr, size), proxy_value(size));
}

static intptr_t linux_file_bind(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return PROXY_CALL(LINUX_SYS_bind, proxy_value(file.handle), proxy_in(addr, size), proxy_value(size));
}

static intptr_t linux_file_listen(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int backlog)
{
	return PROXY_CALL(LINUX_SYS_listen, proxy_value(file.handle), proxy_value(backlog));
}

static intptr_t linux_file_accept4(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags, struct vfs_resolved_file *out_file)
{
	intptr_t result = PROXY_CALL(LINUX_SYS_accept4, proxy_value(file.handle), addrlen ? proxy_out(addr, *addrlen) : proxy_value(0), proxy_inout(addrlen, sizeof(*addrlen)), proxy_value(flags));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &linux_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t linux_file_getsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, void *restrict optval, socklen_t *restrict optlen)
{
	return PROXY_CALL(LINUX_SYS_getsockopt | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(level), proxy_value(optname), proxy_out(optval, *optlen), proxy_inout(optlen, sizeof(*optlen)));
}

static intptr_t linux_file_setsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, const void *optval, socklen_t optlen)
{
	return PROXY_CALL(LINUX_SYS_setsockopt | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(level), proxy_value(optname), proxy_in(optval, optlen), proxy_value(optlen));
}

static intptr_t linux_file_getsockname(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return PROXY_CALL(LINUX_SYS_getsockname | PROXY_NO_WORKER, proxy_value(file.handle), proxy_out(addr, *addrlen), proxy_inout(addrlen, sizeof(socklen_t)));
}

static intptr_t linux_file_getpeername(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return PROXY_CALL(LINUX_SYS_getpeername | PROXY_NO_WORKER, proxy_value(file.handle), proxy_out(addr, *addrlen), proxy_inout(addrlen, sizeof(socklen_t)));
}

static intptr_t linux_file_shutdown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return PROXY_CALL(LINUX_SYS_shutdown, proxy_value(file.handle), proxy_value(how));
}

static intptr_t linux_file_sendfile(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_out, struct vfs_resolved_file file_in, off_t *offset, size_t size)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return PROXY_CALL(LINUX_SYS_sendfile, proxy_value(file_out.handle), proxy_value(file_in.handle), proxy_inout(offset, sizeof(off_t)), proxy_value(size));
}

static intptr_t linux_file_splice(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off_t *off_in, struct vfs_resolved_file file_out, off_t *off_out, size_t size, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return PROXY_CALL(LINUX_SYS_splice, proxy_value(file_in.handle), proxy_inout(off_in, sizeof(off_t)), proxy_value(file_out.handle), proxy_inout(off_out, sizeof(off_t)), proxy_value(size), proxy_value(flags));
}

static intptr_t linux_file_tee(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, struct vfs_resolved_file file_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return PROXY_CALL(LINUX_SYS_tee, proxy_value(file_in.handle), proxy_value(file_out.handle), proxy_value(len), proxy_value(flags));
}

static intptr_t linux_file_copy_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, uint64_t *off_in, struct vfs_resolved_file file_out, uint64_t *off_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return PROXY_CALL(LINUX_SYS_copy_file_range, proxy_value(file_in.handle), proxy_inout(off_in, sizeof(off_t)), proxy_value(file_out.handle), proxy_inout(off_out, sizeof(off_t)), proxy_value(len), proxy_value(flags));
}

static intptr_t linux_file_ioctl(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case TIOCGSID:
		case TIOCGPGRP: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_out((void *)arg, sizeof(pid_t)));
		}
		case TIOCSPGRP: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_in((void *)arg, sizeof(pid_t)));
		}
		case TIOCGLCKTRMIOS:
		case TCGETS: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_out((void *)arg, sizeof(struct linux_termios)));
		}
		case TIOCSLCKTRMIOS:
		case TCSETS:
		case TCSETSW:
		case TCSETSF: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_in((void *)arg, sizeof(struct linux_termios)));
		}
		// case TCGETA: {
		// 	return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_out((void *)arg, sizeof(struct termio)));
		// }
		// case TCSETA:
		// case TCSETAW:
		// case TCSETAF: {
		// 	return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_in((void *)arg, sizeof(struct termio)));
		// }
		case TIOCGWINSZ: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_out((void *)arg, sizeof(struct winsize)));
		}
		case TIOCSBRK:
		case TCSBRK:
		case TCXONC:
		case TCFLSH:
		case TIOCSCTTY: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_value(arg));
		}
		case TIOCCBRK:
		case TIOCCONS:
		case TIOCNOTTY:
		case TIOCEXCL:
		case TIOCNXCL: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd));
		}
		case FIONREAD:
		case TIOCOUTQ:
		case TIOCGETD:
		case TIOCMGET:
		case TIOCGSOFTCAR: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_out((void *)arg, sizeof(int)));
		}
		case TIOCSETD:
		case TIOCPKT:
		case TIOCMSET:
		case TIOCMBIS:
		case TIOCSSOFTCAR: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_in((void *)arg, sizeof(int)));
		}
		case TIOCSTI: {
			return PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_in((void *)arg, sizeof(char)));
		}
	}
	return -EINVAL;
}

static intptr_t linux_file_ioctl_open_file(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg, struct vfs_resolved_file *out_file)
{
	intptr_t result = PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_value(arg));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &linux_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t linux_file_ppoll(__attribute__((unused)) struct thread_storage *thread, struct vfs_poll_resolved_file *files, nfds_t nfiles, struct timespec *timeout, __attribute__((unused)) const sigset_t *sigmask)
{
	struct attempt_cleanup_state state;
	struct pollfd *linux_fds = malloc(sizeof(struct pollfd) * nfiles);
	attempt_push_free(thread, &state, linux_fds);
	for (nfds_t i = 0; i < nfiles; i++) {
		linux_fds[i].fd = files[i].file.handle;
		linux_fds[i].events = files[i].events;
		linux_fds[i].revents = files[i].revents;
	}
	intptr_t result = PROXY_CALL(LINUX_SYS_ppoll, proxy_inout(linux_fds, sizeof(struct pollfd) * nfiles), proxy_value(nfiles), timeout != NULL ? proxy_inout(timeout, sizeof(struct timespec)) : proxy_value(0), proxy_value(0), proxy_value(0));
	if (result > 0) {
		for (nfds_t i = 0; i < nfiles; i++) {
			files[i].revents = linux_fds[i].revents;
		}
	}
	attempt_pop_free(&state);
	return result;
}

const struct vfs_path_ops linux_path_ops = {
	.dirfd_ops = {
		.socket = linux_file_socket,
		.close = linux_file_close,
		.read = linux_file_read,
		.write = linux_file_write,
		.recvfrom = linux_file_recvfrom,
		.sendto = linux_file_sendto,
		.lseek = linux_file_lseek,
		.fadvise64 = linux_file_fadvise64,
		.readahead = linux_file_readahead,
		.pread = linux_file_pread,
		.pwrite = linux_file_pwrite,
		.flock = linux_file_flock,
		.fsync = linux_file_fsync,
		.fdatasync = linux_file_fdatasync,
		.syncfs = linux_file_syncfs,
		.sync_file_range = linux_file_sync_file_range,
		.ftruncate = linux_file_ftruncate,
		.fallocate = linux_file_fallocate,
		.recvmsg = linux_file_recvmsg,
		.sendmsg = linux_file_sendmsg,
		.fcntl_basic = linux_file_fcntl_basic,
		.fcntl_lock = linux_file_fcntl_lock,
		.fcntl_int = linux_file_fcntl_int,
		.fchmod = linux_file_fchmod,
		.fchown = linux_file_fchown,
		.fstat = linux_file_fstat,
		.fstatfs = linux_file_fstatfs,
		.readlink_fd = linux_file_readlink_fd,
		.getdents = linux_file_getdents,
		.getdents64 = linux_file_getdents64,
		.fgetxattr = linux_file_fgetxattr,
		.fsetxattr = linux_file_fsetxattr,
		.fremovexattr = linux_file_fremovexattr,
		.flistxattr = linux_file_flistxattr,
		.connect = linux_file_connect,
		.bind = linux_file_bind,
		.listen = linux_file_listen,
		.accept4 = linux_file_accept4,
		.getsockopt = linux_file_getsockopt,
		.setsockopt = linux_file_setsockopt,
		.getsockname = linux_file_getsockname,
		.getpeername = linux_file_getpeername,
		.shutdown = linux_file_shutdown,
		.sendfile = linux_file_sendfile,
		.splice = linux_file_splice,
		.tee = linux_file_tee,
		.copy_file_range = linux_file_copy_file_range,
		.ioctl = linux_file_ioctl,
		.ioctl_open_file = linux_file_ioctl_open_file,
		.ppoll = linux_file_ppoll,
		.mmap = vfs_mmap_via_pread,
	},
	.mkdirat = linux_path_mkdirat,
	.mknodat = linux_path_mknodat,
	.openat = linux_path_openat,
	.unlinkat = linux_path_unlinkat,
	.renameat2 = linux_path_renameat2,
	.linkat = linux_path_linkat,
	.symlinkat = linux_path_symlinkat,
	.truncate = linux_path_truncate,
	.fchmodat = linux_path_fchmodat,
	.fchownat = linux_path_fchownat,
	.utimensat = linux_path_utimensat,
	.newfstatat = linux_path_newfstatat,
	.statx = linux_path_statx,
	.statfs = linux_path_statfs,
	.faccessat = linux_path_faccessat,
	.readlinkat = linux_path_readlinkat,
	.getxattr = linux_path_getxattr,
	.setxattr = linux_path_setxattr,
	.removexattr = linux_path_removexattr,
	.listxattr = linux_path_listxattr,
};
