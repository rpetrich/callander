#define _GNU_SOURCE
#include "vfs.h"
#include "proxy.h"
#include "remote.h"

extern const struct vfs_path_ops remote_path_ops;

static intptr_t remote_path_mkdirat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode)
{
	return remote_mkdirat(resolved.info.handle, resolved.info.path, mode);
}

static intptr_t remote_path_mknodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, dev_t dev)
{
	return remote_mknodat(resolved.info.handle, resolved.info.path, mode, dev);
}

static intptr_t remote_path_openat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, mode_t mode, struct vfs_resolved_file *out_file)
{
	int result = remote_openat(resolved.info.handle, resolved.info.path, flags, mode);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &remote_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t remote_path_unlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags)
{
	return remote_unlinkat(resolved.info.handle, resolved.info.path, flags);
}

static intptr_t remote_path_renameat2(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return remote_renameat2(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t remote_path_linkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return remote_linkat(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t remote_path_symlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path new_resolved, const char *old_path)
{
	return remote_symlinkat(old_path, new_resolved.info.handle, new_resolved.info.path);
}

static intptr_t remote_path_truncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	if (resolved.info.handle != AT_FDCWD) {
		return vfs_truncate_via_open_and_ftruncate(thread, resolved, length);
	}
	return FS_SYSCALL(LINUX_SYS_truncate, (intptr_t)resolved.info.path, length);
}

static intptr_t remote_path_fchmodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, int flags)
{
	return remote_fchmodat(resolved.info.handle, resolved.info.path, mode, flags);
}

static intptr_t remote_path_fchownat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, uid_t owner, gid_t group, int flags)
{
	return remote_fchownat(resolved.info.handle, resolved.info.path, owner, group, flags);
}

static intptr_t remote_path_utimensat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const struct timespec times[2], int flags)
{
	return remote_utimensat(resolved.info.handle, resolved.info.path, times, flags);
}

static intptr_t remote_path_newfstatat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_stat *out_stat, int flags)
{
    return remote_newfstatat(resolved.info.handle, resolved.info.path, out_stat, flags);
}

static intptr_t remote_path_statx(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
	return remote_statx(resolved.info.handle, resolved.info.path, flags, mask, statxbuf);
}

static intptr_t remote_path_statfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_statfs *out_buf)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(LINUX_SYS_statfs, (intptr_t)resolved.info.path, (intptr_t)out_buf);
}

static intptr_t remote_path_faccessat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int mode, int flag)
{
	return remote_faccessat(resolved.info.handle, resolved.info.path, mode, flag);
}

static intptr_t remote_path_readlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, char *buf, size_t bufsz)
{
	return remote_readlinkat(resolved.info.handle, resolved.info.path, buf, bufsz);
}

static intptr_t remote_path_getxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, void *out_value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	if (flags & AT_SYMLINK_NOFOLLOW) {
		return remote_lgetxattr(path, name, out_value, size);
	}
	return remote_getxattr(path, name, out_value, size);
}

static intptr_t remote_path_setxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, const void *value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	if (flags & AT_SYMLINK_NOFOLLOW) {
		return remote_lsetxattr(path, name, value, size, flags & ~AT_SYMLINK_NOFOLLOW);
	}
	return remote_setxattr(path, name, value, size, flags);
}

static intptr_t remote_path_removexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	if (flags & AT_SYMLINK_NOFOLLOW) {
		return remote_lremovexattr(path, name);
	}
	return remote_removexattr(path, name);
}

static intptr_t remote_path_listxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, void *out_value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	if (flags & AT_SYMLINK_NOFOLLOW) {
		return remote_llistxattr(path, out_value, size);
	}
	return remote_listxattr(path, out_value, size);
}

static intptr_t remote_file_socket(__attribute__((unused)) struct thread_storage *, int domain, int type, int protocol, struct vfs_resolved_file *out_file)
{
	intptr_t result = remote_socket(domain, type, protocol);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file) {
			.ops = &remote_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t remote_file_close(struct vfs_resolved_file file)
{
	remote_close(file.handle);
	return 0;
}

static intptr_t remote_file_read(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz)
{
	return remote_read(file.handle, buf, bufsz);
}

static intptr_t remote_file_write(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz)
{
	return remote_write(file.handle, buf, bufsz);
}

static intptr_t remote_file_recvfrom(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	return remote_recvfrom(file.handle, buf, bufsz, flags, src_addr, addrlen);
}

static intptr_t remote_file_sendto(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
    return remote_sendto(file.handle, buf, bufsz, flags, dest_addr, dest_len);
}

static intptr_t remote_file_lseek(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, int whence)
{
	return remote_lseek(file.handle, offset, whence);
}

static intptr_t remote_file_fadvise64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, size_t offset, size_t len, int advice)
{
	return remote_fadvise64( file.handle, offset, len, advice);
}

static intptr_t remote_file_readahead(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, size_t count)
{
	return remote_readahead(file.handle, offset, count);
}

static intptr_t remote_file_pread(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *buf, size_t count, off_t offset)
{
	return remote_pread(file.handle, buf, count, offset);
}

static intptr_t remote_file_pwrite(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const void *buf, size_t count, off_t offset)
{
	return remote_pwrite(file.handle, buf, count, offset);
}

static intptr_t remote_file_flock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return remote_flock(file.handle, how);
}

static intptr_t remote_file_fsync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return remote_fsync(file.handle);
}

static intptr_t remote_file_fdatasync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return remote_fdatasync(file.handle);
}

static intptr_t remote_file_syncfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return remote_syncfs(file.handle);
}

static intptr_t remote_file_sync_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, off_t nbytes, unsigned int flags)
{
	return remote_sync_file_range(file.handle, offset, nbytes, flags);
}

static intptr_t remote_file_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t length)
{
	return remote_ftruncate(file.handle, length);
}

static intptr_t remote_file_fallocate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int mode, off_t offset, off_t len)
{
	return remote_fallocate(file.handle, mode, offset, len);
}

static intptr_t remote_file_recvmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct msghdr *msg, int flags)
{
	return remote_recvmsg(thread, file.handle, msg, flags);
}

static intptr_t remote_file_sendmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct msghdr *msg, int flags)
{
	return remote_sendmsg(thread, file.handle, msg, flags);
}

static intptr_t remote_file_fcntl_basic(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, intptr_t argument)
{
	return remote_fcntl_basic(file.handle, cmd, argument);
}

static intptr_t remote_file_fcntl_lock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, struct flock *lock)
{
	return remote_fcntl_lock(file.handle, cmd, lock);
}

static intptr_t remote_file_fcntl_int(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, int *value)
{
	return remote_fcntl_int(file.handle, cmd, value);
}

static intptr_t remote_file_fchmod(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, mode_t mode)
{
	return remote_fchmod(file.handle, mode);
}

static intptr_t remote_file_fchown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, uid_t owner, gid_t group)
{
	return remote_fchown(file.handle, owner, group);
}

static intptr_t remote_file_fstat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_stat *out_stat)
{
    return remote_fstat(file.handle, out_stat);
}

static intptr_t remote_file_fstatfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_statfs *out_buf)
{
	return remote_fstatfs(file.handle, out_buf);
}

static intptr_t remote_file_readlink_fd(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return remote_readlink_fd(file.handle, buf, size);
}

static intptr_t remote_file_getdents(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return remote_getdents(file.handle, buf, size);
}

static intptr_t remote_file_getdents64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return remote_getdents64(file.handle, buf, size);
}

static intptr_t remote_file_fgetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, void *out_value, size_t size)
{
	return remote_fgetxattr(file.handle, name, out_value, size);
}

static intptr_t remote_file_fsetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, const void *value, size_t size, int flags)
{
	return remote_fsetxattr(file.handle, name, value, size, flags);
}

static intptr_t remote_file_fremovexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name)
{
	return remote_fremovexattr(file.handle, name);
}

static intptr_t remote_file_flistxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *out_value, size_t size)
{
	return remote_flistxattr(file.handle, out_value, size);
}

static intptr_t remote_file_connect(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return remote_connect(file.handle, addr, size);
}

static intptr_t remote_file_bind(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return remote_bind(file.handle, addr, size);
}

static intptr_t remote_file_listen(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int backlog)
{
	return remote_listen(file.handle, backlog);
}

static intptr_t remote_file_accept4(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags, struct vfs_resolved_file *out_file)
{
	int result = remote_accept4(file.handle, addr, addrlen, flags);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &remote_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t remote_file_getsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, void *restrict optval, socklen_t *restrict optlen)
{
	return remote_getsockopt(file.handle, level, optname, optval, optlen);
}

static intptr_t remote_file_setsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, const void *optval, socklen_t optlen)
{
	return remote_setsockopt(file.handle, level, optname, optval, optlen);
}

static intptr_t remote_file_getsockname(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return remote_getsockname(file.handle, addr, addrlen);
}

static intptr_t remote_file_getpeername(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return remote_getpeername(file.handle, addr, addrlen);
}

static intptr_t remote_file_shutdown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return remote_shutdown(file.handle, how);
}

static intptr_t remote_file_sendfile(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_out, struct vfs_resolved_file file_in, off_t *offset, size_t size)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_sendfile(file_out.handle, file_in.handle, offset, size);
}

static intptr_t remote_file_splice(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off_t *off_in, struct vfs_resolved_file file_out, off_t *off_out, size_t size, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_splice(file_in.handle, off_in, file_out.handle, off_out, size, flags);
}

static intptr_t remote_file_tee(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, struct vfs_resolved_file file_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_tee(file_in.handle, file_out.handle, len, flags);
}

static intptr_t remote_file_copy_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, uint64_t *off_in, struct vfs_resolved_file file_out, uint64_t *off_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_copy_file_range(file_in.handle, (off64_t *)off_in, file_out.handle, (off64_t *)off_out, len, flags);
}

static intptr_t remote_file_ioctl(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg)
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

static intptr_t remote_file_ioctl_open_file(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg, struct vfs_resolved_file *out_file)
{
	intptr_t result = PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_value(arg));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &remote_path_ops.dirfd_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t remote_file_ppoll(__attribute__((unused)) struct thread_storage *thread, struct vfs_poll_resolved_file *files, nfds_t nfiles, struct timespec *timeout, __attribute__((unused)) const sigset_t *sigmask)
{
	struct attempt_cleanup_state state;
	struct pollfd *real_fds = malloc(sizeof(struct pollfd) * nfiles);
	attempt_push_free(thread, &state, real_fds);
	for (nfds_t i = 0; i < nfiles; i++) {
		real_fds[i].fd = files[i].file.handle;
		real_fds[i].events = files[i].events;
		real_fds[i].revents = files[i].revents;
	}
	intptr_t result = remote_ppoll(real_fds, nfiles, timeout);
	if (result > 0) {
		for (nfds_t i = 0; i < nfiles; i++) {
			files[i].revents = real_fds[i].revents;
		}
	}
	attempt_pop_free(&state);
	return result;
}

const struct vfs_path_ops remote_path_ops = {
	.dirfd_ops = {
		.socket = remote_file_socket,
		.close = remote_file_close,
		.read = remote_file_read,
		.write = remote_file_write,
		.recvfrom = remote_file_recvfrom,
		.sendto = remote_file_sendto,
		.lseek = remote_file_lseek,
		.fadvise64 = remote_file_fadvise64,
		.readahead = remote_file_readahead,
		.pread = remote_file_pread,
		.pwrite = remote_file_pwrite,
		.flock = remote_file_flock,
		.fsync = remote_file_fsync,
		.fdatasync = remote_file_fdatasync,
		.syncfs = remote_file_syncfs,
		.sync_file_range = remote_file_sync_file_range,
		.ftruncate = remote_file_ftruncate,
		.fallocate = remote_file_fallocate,
		.recvmsg = remote_file_recvmsg,
		.sendmsg = remote_file_sendmsg,
		.fcntl_basic = remote_file_fcntl_basic,
		.fcntl_lock = remote_file_fcntl_lock,
		.fcntl_int = remote_file_fcntl_int,
		.fchmod = remote_file_fchmod,
		.fchown = remote_file_fchown,
		.fstat = remote_file_fstat,
		.fstatfs = remote_file_fstatfs,
		.readlink_fd = remote_file_readlink_fd,
		.getdents = remote_file_getdents,
		.getdents64 = remote_file_getdents64,
		.fgetxattr = remote_file_fgetxattr,
		.fsetxattr = remote_file_fsetxattr,
		.fremovexattr = remote_file_fremovexattr,
		.flistxattr = remote_file_flistxattr,
		.connect = remote_file_connect,
		.bind = remote_file_bind,
		.listen = remote_file_listen,
		.accept4 = remote_file_accept4,
		.getsockopt = remote_file_getsockopt,
		.setsockopt = remote_file_setsockopt,
		.getsockname = remote_file_getsockname,
		.getpeername = remote_file_getpeername,
		.shutdown = remote_file_shutdown,
		.sendfile = remote_file_sendfile,
		.splice = remote_file_splice,
		.tee = remote_file_tee,
		.copy_file_range = remote_file_copy_file_range,
		.ioctl = remote_file_ioctl,
		.ioctl_open_file = remote_file_ioctl_open_file,
		.ppoll = remote_file_ppoll,
		.mmap = vfs_mmap_via_pread,
	},
	.mkdirat = remote_path_mkdirat,
	.mknodat = remote_path_mknodat,
	.openat = remote_path_openat,
	.unlinkat = remote_path_unlinkat,
	.renameat2 = remote_path_renameat2,
	.linkat = remote_path_linkat,
	.symlinkat = remote_path_symlinkat,
	.truncate = remote_path_truncate,
	.fchmodat = remote_path_fchmodat,
	.fchownat = remote_path_fchownat,
	.utimensat = remote_path_utimensat,
	.newfstatat = remote_path_newfstatat,
	.statx = remote_path_statx,
	.statfs = remote_path_statfs,
	.faccessat = remote_path_faccessat,
	.readlinkat = remote_path_readlinkat,
	.getxattr = remote_path_getxattr,
	.setxattr = remote_path_setxattr,
	.removexattr = remote_path_removexattr,
	.listxattr = remote_path_listxattr,
};
