#define _GNU_SOURCE
#include "freestanding.h"
#include "linux.h"
#include "vfs.h"

static intptr_t local_path_mkdirat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode)
{
	return fs_mkdirat(resolved.info.handle, resolved.info.path, mode);
}

static intptr_t local_path_mknodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, dev_t dev)
{
	return FS_SYSCALL(LINUX_SYS_mknodat, resolved.info.handle, (intptr_t)resolved.info.path, mode, dev);
}

static intptr_t local_path_openat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, mode_t mode, struct vfs_resolved_file *out_file)
{
	int result = fs_openat(resolved.info.handle, resolved.info.path, flags, mode);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &local_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t local_path_unlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags)
{
	return fs_unlinkat(resolved.info.handle, resolved.info.path, flags);
}

static intptr_t local_path_renameat2(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return fs_renameat2(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t local_path_linkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return fs_linkat(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t local_path_symlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path new_resolved, const char *old_path)
{
	return fs_symlinkat(old_path, new_resolved.info.handle, new_resolved.info.path);
}

static intptr_t local_path_truncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	if (resolved.info.handle != AT_FDCWD) {
		return vfs_truncate_via_open_and_ftruncate(thread, resolved, length);
	}
	return FS_SYSCALL(LINUX_SYS_truncate, (intptr_t)resolved.info.path, length);
}

static intptr_t local_path_fchmodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, int flags)
{
	return fs_fchmodat(resolved.info.handle, resolved.info.path, mode, flags);
}

static intptr_t local_path_fchownat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, uid_t owner, gid_t group, int flags)
{
	return fs_fchownat(resolved.info.handle, resolved.info.path, owner, group, flags);
}

static intptr_t local_path_utimensat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const struct timespec times[2], int flags)
{
	return FS_SYSCALL(LINUX_SYS_utimensat, resolved.info.handle, (intptr_t)resolved.info.path, (intptr_t)times, flags);
}

static intptr_t local_path_newfstatat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_stat *out_stat, int flags)
{
    return FS_SYSCALL(LINUX_SYS_newfstatat, resolved.info.handle, (intptr_t)resolved.info.path, (intptr_t)out_stat, flags);
}

static intptr_t local_path_statx(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
	return FS_SYSCALL(LINUX_SYS_statx, resolved.info.handle, (intptr_t)resolved.info.path, flags, mask, (intptr_t)statxbuf);
}

static intptr_t local_path_statfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_statfs *out_buf)
{
	if (resolved.info.handle != AT_FDCWD) {
		return -ENOTSUP;
	}
	return FS_SYSCALL(LINUX_SYS_statfs, (intptr_t)resolved.info.path, (intptr_t)out_buf);
}

static intptr_t local_path_faccessat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int mode, int flag)
{
	return fs_faccessat(resolved.info.handle, resolved.info.path, mode, flag);
}

static intptr_t local_path_readlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, char *buf, size_t bufsz)
{
	return fs_readlinkat(resolved.info.handle, resolved.info.path, buf, bufsz);
}

static intptr_t local_path_getxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, void *out_value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(flags & AT_SYMLINK_NOFOLLOW ? LINUX_SYS_lgetxattr : LINUX_SYS_getxattr, (intptr_t)path, (intptr_t)name, (intptr_t)out_value, size);
}

static intptr_t local_path_setxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, const void *value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(flags & AT_SYMLINK_NOFOLLOW ? LINUX_SYS_lsetxattr : LINUX_SYS_setxattr, (intptr_t)path, (intptr_t)name, (intptr_t)value, size, flags & ~LINUX_AT_SYMLINK_NOFOLLOW);
}

static intptr_t local_path_removexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(flags & AT_SYMLINK_NOFOLLOW ? LINUX_SYS_lremovexattr : LINUX_SYS_removexattr, (intptr_t)path, (intptr_t)name);
}

static intptr_t local_path_listxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, void *out_value, size_t size, int flags)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(flags & AT_SYMLINK_NOFOLLOW ? LINUX_SYS_llistxattr : LINUX_SYS_listxattr, (intptr_t)path, (intptr_t)out_value, size);
}

struct vfs_path_ops local_path_ops = {
	.dirfd_ops = &local_file_ops,
	.mkdirat = local_path_mkdirat,
	.mknodat = local_path_mknodat,
	.openat = local_path_openat,
	.unlinkat = local_path_unlinkat,
	.renameat2 = local_path_renameat2,
	.linkat = local_path_linkat,
	.symlinkat = local_path_symlinkat,
	.truncate = local_path_truncate,
	.fchmodat = local_path_fchmodat,
	.fchownat = local_path_fchownat,
	.utimensat = local_path_utimensat,
	.newfstatat = local_path_newfstatat,
	.statx = local_path_statx,
	.statfs = local_path_statfs,
	.faccessat = local_path_faccessat,
	.readlinkat = local_path_readlinkat,
	.getxattr = local_path_getxattr,
	.setxattr = local_path_setxattr,
	.removexattr = local_path_removexattr,
	.listxattr = local_path_listxattr,
};


static intptr_t local_file_close(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return fs_close(file.handle);
}

static intptr_t local_file_read(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz)
{
	return fs_read(file.handle, buf, bufsz);
}

static intptr_t local_file_write(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz)
{
	return fs_write(file.handle, buf, bufsz);
}

static intptr_t local_file_recvfrom(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    return FS_SYSCALL(LINUX_SYS_recvfrom, file.handle, (intptr_t)buf, bufsz, flags, (intptr_t)src_addr, (intptr_t)addrlen);
}

static intptr_t local_file_sendto(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
    return FS_SYSCALL(LINUX_SYS_sendto, file.handle, (intptr_t)buf, bufsz, flags, (intptr_t)dest_addr, dest_len);
}

static intptr_t local_file_lseek(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, int whence)
{
	return fs_lseek(file.handle, offset, whence);
}

static intptr_t local_file_fadvise64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, size_t offset, size_t len, int advice)
{
	return FS_SYSCALL(LINUX_SYS_fadvise64, file.handle, offset, len, advice);
}

static intptr_t local_file_readahead(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, size_t count)
{
	return FS_SYSCALL(LINUX_SYS_readahead, file.handle, offset, count);
}

static intptr_t local_file_pread(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *buf, size_t count, off_t offset)
{
	return fs_pread(file.handle, buf, count, offset);
}

static intptr_t local_file_pwrite(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const void *buf, size_t count, off_t offset)
{
	return fs_pwrite(file.handle, buf, count, offset);
}

static intptr_t local_file_flock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return FS_SYSCALL(LINUX_SYS_flock, file.handle, how);
}

static intptr_t local_file_fsync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return FS_SYSCALL(LINUX_SYS_fsync, file.handle);
}

static intptr_t local_file_fdatasync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return FS_SYSCALL(LINUX_SYS_fdatasync, file.handle);
}

static intptr_t local_file_syncfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return FS_SYSCALL(LINUX_SYS_syncfs, file.handle);
}

static intptr_t local_file_sync_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, off_t nbytes, unsigned int flags)
{
	return FS_SYSCALL(LINUX_SYS_sync_file_range, file.handle, offset, nbytes, flags);
}

static intptr_t local_file_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t length)
{
	return fs_ftruncate(file.handle, length);
}

static intptr_t local_file_fallocate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int mode, off_t offset, off_t len)
{
	return FS_SYSCALL(file.handle, mode, offset, len);
}

static intptr_t local_file_recvmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct msghdr *msg, int flags)
{
	return fs_recvmsg(file.handle, msg, flags);
}

static intptr_t local_file_sendmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct msghdr *msg, int flags)
{
	return fs_sendmsg(file.handle, msg, flags);
}

static intptr_t local_file_fcntl_basic(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, intptr_t argument)
{
	return fs_fcntl(file.handle, cmd, argument);
}

static intptr_t local_file_fcntl_lock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, struct flock *lock)
{
	return fs_fcntl(file.handle, cmd, (intptr_t)lock);
}

static intptr_t local_file_fcntl_int(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, int *value)
{
	return fs_fcntl(file.handle, cmd, (intptr_t)value);
}

static intptr_t local_file_fchmod(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, mode_t mode)
{
	return fs_fchmod(file.handle, mode);
}

static intptr_t local_file_fchown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, uid_t owner, gid_t group)
{
	return fs_fchown(file.handle, owner, group);
}

static intptr_t local_file_fstat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_stat *out_stat)
{
    return fs_fstat(file.handle, out_stat);
}

static intptr_t local_file_fstatfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_statfs *out_buf)
{
	return fs_fstatfs(file.handle, out_buf);
}

static intptr_t local_file_readlink_fd(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return fs_readlink_fd(file.handle, buf, size);
}

static intptr_t local_file_getdents(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return FS_SYSCALL(LINUX_SYS_getdents, file.handle, (intptr_t)buf, size);
}

static intptr_t local_file_getdents64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return fs_getdents(file.handle, (struct fs_dirent *)buf, size);
}

static intptr_t local_file_fgetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, void *out_value, size_t size)
{
	return FS_SYSCALL(LINUX_SYS_fgetxattr, file.handle, (intptr_t)name, (intptr_t)out_value, (intptr_t)size);
}

static intptr_t local_file_fsetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, const void *value, size_t size, int flags)
{
	return FS_SYSCALL(LINUX_SYS_fsetxattr, file.handle, (intptr_t)name, (intptr_t)value, (intptr_t)size, flags);
}

static intptr_t local_file_fremovexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name)
{
	return FS_SYSCALL(LINUX_SYS_fremovexattr, file.handle, (intptr_t)name);
}

static intptr_t local_file_flistxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *out_value, size_t size)
{
	return FS_SYSCALL(LINUX_SYS_flistxattr, file.handle, (intptr_t)out_value, (intptr_t)size);
}

static intptr_t local_file_connect(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return fs_connect(file.handle, addr, size);
}

static intptr_t local_file_bind(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return fs_bind(file.handle, addr, size);
}

static intptr_t local_file_listen(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int backlog)
{
	return fs_listen(file.handle, backlog);
}

static intptr_t local_file_accept4(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags, struct vfs_resolved_file *out_file)
{
	int result = FS_SYSCALL(LINUX_SYS_accept4, file.handle, (intptr_t)addr, (intptr_t)addrlen, flags);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &local_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t local_file_getsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, void *restrict optval, socklen_t *restrict optlen)
{
	return fs_getsockopt(file.handle, level, optname, optval, (size_t *)optlen);
}

static intptr_t local_file_setsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, const void *optval, socklen_t optlen)
{
	return fs_setsockopt(file.handle, level, optname, optval, optlen);
}

static intptr_t local_file_getsockname(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return FS_SYSCALL(LINUX_SYS_getsockname, file.handle, (intptr_t)addr, (intptr_t)addrlen);
}

static intptr_t local_file_getpeername(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return FS_SYSCALL(LINUX_SYS_getpeername, file.handle, (intptr_t)addr, (intptr_t)addrlen);
}

static intptr_t local_file_shutdown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return FS_SYSCALL(LINUX_SYS_shutdown, file.handle, how);
}

static intptr_t local_file_sendfile(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_out, struct vfs_resolved_file file_in, off_t *offset, size_t size)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return FS_SYSCALL(LINUX_SYS_sendfile, file_out.handle, file_in.handle, (intptr_t)offset, size);
}

static intptr_t local_file_splice(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off_t *off_in, struct vfs_resolved_file file_out, off_t *off_out, size_t size, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return FS_SYSCALL(LINUX_SYS_splice, file_in.handle, (intptr_t)off_in, file_out.handle, (intptr_t)off_out, size, flags);
}

static intptr_t local_file_tee(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, struct vfs_resolved_file file_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return FS_SYSCALL(LINUX_SYS_tee, file_in.handle, file_out.handle, len, flags);
}

static intptr_t local_file_copy_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off64_t *off_in, struct vfs_resolved_file file_out, off64_t *off_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return FS_SYSCALL(LINUX_SYS_copy_file_range, file_in.handle, (intptr_t)off_in, file_out.handle, (intptr_t)off_out, len, flags);
}

struct vfs_file_ops local_file_ops = {
	.close = local_file_close,
	.read = local_file_read,
	.write = local_file_write,
	.recvfrom = local_file_recvfrom,
	.sendto = local_file_sendto,
	.lseek = local_file_lseek,
	.fadvise64 = local_file_fadvise64,
	.readahead = local_file_readahead,
	.pread = local_file_pread,
	.pwrite = local_file_pwrite,
	.flock = local_file_flock,
	.fsync = local_file_fsync,
	.fdatasync = local_file_fdatasync,
	.syncfs = local_file_syncfs,
	.sync_file_range = local_file_sync_file_range,
	.ftruncate = local_file_ftruncate,
	.fallocate = local_file_fallocate,
	.recvmsg = local_file_recvmsg,
	.sendmsg = local_file_sendmsg,
	.fcntl_basic = local_file_fcntl_basic,
	.fcntl_lock = local_file_fcntl_lock,
	.fcntl_int = local_file_fcntl_int,
	.fchmod = local_file_fchmod,
	.fchown = local_file_fchown,
	.fstat = local_file_fstat,
	.fstatfs = local_file_fstatfs,
	.readlink_fd = local_file_readlink_fd,
	.getdents = local_file_getdents,
	.getdents64 = local_file_getdents64,
	.fgetxattr = local_file_fgetxattr,
	.fsetxattr = local_file_fsetxattr,
	.fremovexattr = local_file_fremovexattr,
	.flistxattr = local_file_flistxattr,
	.connect = local_file_connect,
	.bind = local_file_bind,
	.listen = local_file_listen,
	.accept4 = local_file_accept4,
	.getsockopt = local_file_getsockopt,
	.setsockopt = local_file_setsockopt,
	.getsockname = local_file_getsockname,
	.getpeername = local_file_getpeername,
	.shutdown = local_file_shutdown,
	.sendfile = local_file_sendfile,
	.splice = local_file_splice,
	.tee = local_file_tee,
	.copy_file_range = local_file_copy_file_range,
};
