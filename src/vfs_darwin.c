#define _GNU_SOURCE
#include "darwin.h"
#include "vfs.h"
#include "proxy.h"
#include "remote.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

extern const struct vfs_file_ops darwin_file_ops;
extern const struct vfs_path_ops darwin_path_ops;

static intptr_t darwin_path_mkdirat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode)
{
	return remote_mkdirat(resolved.info.handle, resolved.info.path, mode);
}

static intptr_t darwin_path_mknodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, dev_t dev)
{
	return remote_mknodat(resolved.info.handle, resolved.info.path, mode, dev);
}

static intptr_t darwin_path_openat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, mode_t mode, struct vfs_resolved_file *out_file)
{
	intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_openat, proxy_value(translate_at_fd_to_darwin(resolved.info.handle)), proxy_string(resolved.info.path), proxy_value(translate_open_flags_to_darwin(flags)), proxy_value(mode)));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &darwin_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t darwin_path_unlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags)
{
	return remote_unlinkat(resolved.info.handle, resolved.info.path, flags);
}

static intptr_t darwin_path_renameat2(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return remote_renameat2(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t darwin_path_linkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return remote_linkat(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t darwin_path_symlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path new_resolved, const char *old_path)
{
	return remote_symlinkat(old_path, new_resolved.info.handle, new_resolved.info.path);
}

static intptr_t darwin_path_truncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	if (resolved.info.handle != AT_FDCWD) {
		return vfs_truncate_via_open_and_ftruncate(thread, resolved, length);
	}
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_truncate, proxy_string(resolved.info.path), proxy_value(length)));
}

static intptr_t darwin_path_fchmodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, int flags)
{
	return remote_fchmodat(resolved.info.handle, resolved.info.path, mode, flags);
}

static intptr_t darwin_path_fchownat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, uid_t owner, gid_t group, int flags)
{
	return remote_fchownat(resolved.info.handle, resolved.info.path, owner, group, flags);
}

static intptr_t darwin_path_utimensat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const struct timespec times[2], int flags)
{
	return remote_utimensat(resolved.info.handle, resolved.info.path, times, flags);
}

static intptr_t darwin_path_newfstatat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_stat *out_stat, int flags)
{
    if ((flags & AT_EMPTY_PATH) && (resolved.info.path == NULL || *resolved.info.path == '\0')) {
        if (resolved.info.handle == AT_FDCWD) {
            resolved.info.path = ".";
        } else {
			return vfs_call(fstat, vfs_get_dir_file(resolved), out_stat);
        }
    }
    struct darwin_stat dstat;
    intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstatat64, proxy_value(translate_at_fd_to_darwin(resolved.info.handle)), proxy_string(resolved.info.path), proxy_out(&dstat, sizeof(struct darwin_stat)), proxy_value(translate_at_flags_to_darwin(flags))));
    if (result >= 0) {
        *out_stat = translate_darwin_stat(dstat);
    }
    return result;
}

static intptr_t darwin_path_statx(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
    struct darwin_stat dstat;
    intptr_t result;
    if ((flags & AT_EMPTY_PATH) && (resolved.info.path == NULL || *resolved.info.path == '\0')) {
        if (resolved.info.handle == AT_FDCWD) {
            result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstatat64, proxy_value(translate_at_fd_to_darwin(resolved.info.handle)), proxy_string("."), proxy_out(&dstat, sizeof(struct darwin_stat)), proxy_value(translate_at_flags_to_darwin(flags))));
        } else {
            result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstat64, proxy_value(resolved.info.handle), proxy_out(&dstat, sizeof(struct darwin_stat))));
        }
    } else {
        result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstatat64, proxy_value(translate_at_fd_to_darwin(resolved.info.handle)), proxy_string(resolved.info.path), proxy_out(&dstat, sizeof(struct darwin_stat)), proxy_value(translate_at_flags_to_darwin(flags))));
    }
    if (result >= 0) {
        translate_darwin_statx(statxbuf, dstat, mask);
    }
    return result;
}

static intptr_t darwin_path_statfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_statfs *out_buf)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(LINUX_SYS_statfs, (intptr_t)resolved.info.path, (intptr_t)out_buf);
}

static intptr_t darwin_path_faccessat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int mode, int flags)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_faccessat, proxy_value(translate_at_fd_to_darwin(resolved.info.handle)), proxy_string(resolved.info.path), proxy_value(mode), proxy_value(translate_at_flags_to_darwin(flags))));
}

static intptr_t darwin_path_readlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, char *buf, size_t bufsz)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_readlinkat, proxy_value(translate_at_fd_to_darwin(resolved.info.handle)), proxy_string(resolved.info.path), proxy_out(buf, bufsz), proxy_value(bufsz)));
}

static intptr_t darwin_path_getxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, void *out_value, size_t size, int flags)
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

static intptr_t darwin_path_setxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, const void *value, size_t size, int flags)
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

static intptr_t darwin_path_removexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, int flags)
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

static intptr_t darwin_path_listxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, void *out_value, size_t size, int flags)
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

const struct vfs_path_ops darwin_path_ops = {
	.dirfd_ops = &darwin_file_ops,
	.mkdirat = darwin_path_mkdirat,
	.mknodat = darwin_path_mknodat,
	.openat = darwin_path_openat,
	.unlinkat = darwin_path_unlinkat,
	.renameat2 = darwin_path_renameat2,
	.linkat = darwin_path_linkat,
	.symlinkat = darwin_path_symlinkat,
	.truncate = darwin_path_truncate,
	.fchmodat = darwin_path_fchmodat,
	.fchownat = darwin_path_fchownat,
	.utimensat = darwin_path_utimensat,
	.newfstatat = darwin_path_newfstatat,
	.statx = darwin_path_statx,
	.statfs = darwin_path_statfs,
	.faccessat = darwin_path_faccessat,
	.readlinkat = darwin_path_readlinkat,
	.getxattr = darwin_path_getxattr,
	.setxattr = darwin_path_setxattr,
	.removexattr = darwin_path_removexattr,
	.listxattr = darwin_path_listxattr,
};


static intptr_t darwin_file_socket(__attribute__((unused)) struct thread_storage *, int domain, int type, int protocol, struct vfs_resolved_file *out_file)
{
    intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_socket, proxy_value(domain), proxy_value(type), proxy_value(protocol)));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file) {
			.ops = &darwin_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t darwin_file_close(struct vfs_resolved_file file)
{
    PROXY_CALL(DARWIN_SYS_close | PROXY_NO_RESPONSE, proxy_value(file.handle));
	return 0;
}

static intptr_t darwin_file_read(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_read, proxy_value(file.handle), proxy_out(buf, bufsz), proxy_value(bufsz)));
}

static intptr_t darwin_file_write(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_write, proxy_value(file.handle), proxy_in(buf, bufsz), proxy_value(bufsz)));
}

static intptr_t darwin_file_recvfrom(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    // TODO: translate addresses
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_recvfrom, proxy_value(file.handle), proxy_out(buf, bufsz), proxy_value(bufsz), proxy_value(flags), proxy_out(src_addr, *addrlen), proxy_inout(addrlen, sizeof(*addrlen))));
}

static intptr_t darwin_file_sendto(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
    // TODO: translate addresses
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_sendto, proxy_value(file.handle), proxy_in(buf, bufsz), proxy_value(bufsz), proxy_value(flags), proxy_in(dest_addr, dest_len), proxy_value(dest_len)));
}

static intptr_t darwin_file_lseek(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, int whence)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_lseek, proxy_value(file.handle), proxy_value(offset), proxy_value(translate_seek_whence_to_darwin(whence))));
}

static intptr_t darwin_file_fadvise64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, size_t offset, size_t len, int advice)
{
	// ignore fadvise
	(void)file;
	(void)offset;
	(void)len;
	(void)advice;
	return 0;
}

static intptr_t darwin_file_readahead(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, size_t count)
{
	// ignore readahead
	(void)file;
	(void)offset;
	(void)count;
	return 0;
}

static intptr_t darwin_file_pread(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *buf, size_t count, off_t offset)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_pread, proxy_value(file.handle), proxy_out(buf, count), proxy_value(count), proxy_value(offset)));
}

static intptr_t darwin_file_pwrite(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const void *buf, size_t count, off_t offset)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_pwrite, proxy_value(file.handle), proxy_in(buf, count), proxy_value(count), proxy_value(offset)));
}

static intptr_t darwin_file_flock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_flock, proxy_value(file.handle), proxy_value(how)));
}

static intptr_t darwin_file_fsync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_fsync, proxy_value(file.handle)));
}

static intptr_t darwin_file_fdatasync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_fdatasync, proxy_value(file.handle)));
}

static intptr_t darwin_file_syncfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return remote_syncfs(file.handle);
}

static intptr_t darwin_file_sync_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, off_t nbytes, unsigned int flags)
{
	return remote_sync_file_range(file.handle, offset, nbytes, flags);
}

static intptr_t darwin_file_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t length)
{
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_ftruncate, proxy_value(file.handle), proxy_value(length)));
}

static intptr_t darwin_file_fallocate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int mode, off_t offset, off_t len)
{
	return remote_fallocate(file.handle, mode, offset, len);
}

static intptr_t darwin_file_recvmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct msghdr *msg, int flags)
{
	return remote_recvmsg(thread, file.handle, msg, flags);
}

static intptr_t darwin_file_sendmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct msghdr *msg, int flags)
{
	return remote_sendmsg(thread, file.handle, msg, flags);
}

static intptr_t darwin_file_fcntl_basic(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, intptr_t argument)
{
    int darwin_cmd;
    switch (cmd) {
        case F_SETFL:
            darwin_cmd = 4;
            break;
        case F_GETFL:
            darwin_cmd = 3;
            break;
        case F_SETLEASE:
            return -EINVAL;
        case F_GETLEASE:
            return -EINVAL;
        case F_SETPIPE_SZ:
            return -EINVAL;
        case F_GETPIPE_SZ:
            return -EINVAL;
        case F_ADD_SEALS:
            return -EINVAL;
        case F_GET_SEALS:
            return -EINVAL;
        default:
            unknown_target();
            break;
    }
    return translate_darwin_result(PROXY_CALL(DARWIN_SYS_fcntl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(darwin_cmd), proxy_value(argument)));
}

static intptr_t darwin_file_fcntl_lock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, struct flock *lock)
{
    return -EINVAL;
}

static intptr_t darwin_file_fcntl_int(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, int *value)
{
    return -EINVAL;
}

static intptr_t darwin_file_fchmod(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, mode_t mode)
{
	return remote_fchmod(file.handle, mode);
}

static intptr_t darwin_file_fchown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, uid_t owner, gid_t group)
{
	return remote_fchown(file.handle, owner, group);
}

static intptr_t darwin_file_fstat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_stat *out_stat)
{
    struct darwin_stat dstat;
    intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstat64, proxy_value(file.handle), proxy_out(&dstat, sizeof(struct darwin_stat))));
    if (result >= 0) {
        *out_stat = translate_darwin_stat(dstat);
    }
    return result;
}

static intptr_t darwin_file_fstatfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_statfs *out_buf)
{
	return remote_fstatfs(file.handle, out_buf);
}

static intptr_t darwin_file_readlink_fd(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
    if (size < 1024) {
        DIE("expected at least 1024 byte buffer", (int)size);
    }
    intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fcntl, proxy_value(file.handle), proxy_value(DARWIN_F_GETPATH), proxy_out(buf, size)));
    if (result >= 0) {
        return fs_strlen(buf);
    }
    return result;
}

static intptr_t darwin_file_getdents(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return remote_getdents(file.handle, buf, size);
}

static intptr_t darwin_file_getdents64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
    char temp[1024];
    uint64_t pos = 0;
    intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_getdirentries64, proxy_value(file.handle), proxy_out(temp, sizeof(temp)), proxy_value(sizeof(temp)), proxy_out(&pos, sizeof(uint64_t))));
    if (result <= 0) {
        return result;
    }
    struct darwin_dirent *dent = (struct darwin_dirent *)&temp[0];
    struct fs_dirent *dirp = (void *)buf;
    size_t consumed = 0;
    do {
        size_t name_len = dent->d_namlen;
        size_t rec_len = sizeof(struct fs_dirent) + name_len + 2;
        size_t aligned_len = (rec_len + 7) & ~7;
        if (consumed + aligned_len > size) {
            result = remote_lseek(file.handle, dent->d_seekoff, SEEK_SET);
            if (result < 0) {
                return 0;
            }
            break;
        }
        dirp->d_ino = dent->d_ino;
        dirp->d_off = consumed + aligned_len;
        dirp->d_reclen = aligned_len;
        dirp->d_type = dent->d_type;
        memcpy(dirp->d_name, dent->d_name, name_len);
        dirp->d_name[name_len] = '\0';
        // move to next record
        consumed += aligned_len;
        result -= dent->d_reclen;
        dirp = (struct fs_dirent *)((intptr_t)dirp + aligned_len);
        dent = (struct darwin_dirent *)((intptr_t)dent + dent->d_reclen);
    } while(result > 0);
    return consumed;
}

static intptr_t darwin_file_fgetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, void *out_value, size_t size)
{
	return remote_fgetxattr(file.handle, name, out_value, size);
}

static intptr_t darwin_file_fsetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, const void *value, size_t size, int flags)
{
	return remote_fsetxattr(file.handle, name, value, size, flags);
}

static intptr_t darwin_file_fremovexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name)
{
	return remote_fremovexattr(file.handle, name);
}

static intptr_t darwin_file_flistxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *out_value, size_t size)
{
	return remote_flistxattr(file.handle, out_value, size);
}

static intptr_t darwin_file_connect(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return remote_connect(file.handle, addr, size);
}

static intptr_t darwin_file_bind(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return remote_bind(file.handle, addr, size);
}

static intptr_t darwin_file_listen(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int backlog)
{
	return remote_listen(file.handle, backlog);
}

static intptr_t darwin_file_accept4(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags, struct vfs_resolved_file *out_file)
{
	int result = remote_accept4(file.handle, addr, addrlen, flags);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &darwin_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t darwin_file_getsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, void *restrict optval, socklen_t *restrict optlen)
{
    return -ENOPROTOOPT;
}

static intptr_t darwin_file_setsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, const void *optval, socklen_t optlen)
{
    return -ENOPROTOOPT;
}

static intptr_t darwin_file_getsockname(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return remote_getsockname(file.handle, addr, addrlen);
}

static intptr_t darwin_file_getpeername(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return remote_getpeername(file.handle, addr, addrlen);
}

static intptr_t darwin_file_shutdown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return remote_shutdown(file.handle, how);
}

static intptr_t darwin_file_sendfile(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_out, struct vfs_resolved_file file_in, off_t *offset, size_t size)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_sendfile(file_out.handle, file_in.handle, offset, size);
}

static intptr_t darwin_file_splice(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off_t *off_in, struct vfs_resolved_file file_out, off_t *off_out, size_t size, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_splice(file_in.handle, off_in, file_out.handle, off_out, size, flags);
}

static intptr_t darwin_file_tee(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, struct vfs_resolved_file file_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_tee(file_in.handle, file_out.handle, len, flags);
}

static intptr_t darwin_file_copy_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off64_t *off_in, struct vfs_resolved_file file_out, off64_t *off_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_copy_file_range(file_in.handle, off_in, file_out.handle, off_out, len, flags);
}

static intptr_t darwin_file_ioctl(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg)
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

static intptr_t darwin_file_ioctl_open_file(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg, struct vfs_resolved_file *out_file)
{
	intptr_t result = PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_value(arg));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &darwin_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

const struct vfs_file_ops darwin_file_ops = {
	.socket = darwin_file_socket,
	.close = darwin_file_close,
	.read = darwin_file_read,
	.write = darwin_file_write,
	.recvfrom = darwin_file_recvfrom,
	.sendto = darwin_file_sendto,
	.lseek = darwin_file_lseek,
	.fadvise64 = darwin_file_fadvise64,
	.readahead = darwin_file_readahead,
	.pread = darwin_file_pread,
	.pwrite = darwin_file_pwrite,
	.flock = darwin_file_flock,
	.fsync = darwin_file_fsync,
	.fdatasync = darwin_file_fdatasync,
	.syncfs = darwin_file_syncfs,
	.sync_file_range = darwin_file_sync_file_range,
	.ftruncate = darwin_file_ftruncate,
	.fallocate = darwin_file_fallocate,
	.recvmsg = darwin_file_recvmsg,
	.sendmsg = darwin_file_sendmsg,
	.fcntl_basic = darwin_file_fcntl_basic,
	.fcntl_lock = darwin_file_fcntl_lock,
	.fcntl_int = darwin_file_fcntl_int,
	.fchmod = darwin_file_fchmod,
	.fchown = darwin_file_fchown,
	.fstat = darwin_file_fstat,
	.fstatfs = darwin_file_fstatfs,
	.readlink_fd = darwin_file_readlink_fd,
	.getdents = darwin_file_getdents,
	.getdents64 = darwin_file_getdents64,
	.fgetxattr = darwin_file_fgetxattr,
	.fsetxattr = darwin_file_fsetxattr,
	.fremovexattr = darwin_file_fremovexattr,
	.flistxattr = darwin_file_flistxattr,
	.connect = darwin_file_connect,
	.bind = darwin_file_bind,
	.listen = darwin_file_listen,
	.accept4 = darwin_file_accept4,
	.getsockopt = darwin_file_getsockopt,
	.setsockopt = darwin_file_setsockopt,
	.getsockname = darwin_file_getsockname,
	.getpeername = darwin_file_getpeername,
	.shutdown = darwin_file_shutdown,
	.sendfile = darwin_file_sendfile,
	.splice = darwin_file_splice,
	.tee = darwin_file_tee,
	.copy_file_range = darwin_file_copy_file_range,
	.ioctl = darwin_file_ioctl,
	.ioctl_open_file = darwin_file_ioctl_open_file,
};
