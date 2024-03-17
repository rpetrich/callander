#define _GNU_SOURCE
#include "vfs.h"
#include "proxy.h"
#include "remote.h"
#include "windows.h"

#include <dirent.h>

extern const struct vfs_file_ops windows_file_ops;
extern const struct vfs_path_ops windows_path_ops;

static intptr_t windows_path_mkdirat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode)
{
	return remote_mkdirat(resolved.info.handle, resolved.info.path, mode);
}

static intptr_t windows_path_mknodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, dev_t dev)
{
	return remote_mknodat(resolved.info.handle, resolved.info.path, mode, dev);
}

static intptr_t windows_path_openat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, __attribute__((unused)) mode_t mode, struct vfs_resolved_file *out_file)
{
	char buf[PATH_MAX];
	const char *path;
	intptr_t result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	WINDOWS_DWORD desired_access = translate_open_flags_to_windows_desired_access(flags);
	uint16_t wbuf[PATH_MAX];
	WINDOWS_CREATEFILE2_EXTENDED_PARAMETERS params;
	params.dwSize = sizeof(params);
	params.dwFileAttributes = WINDOWS_FILE_ATTRIBUTE_NORMAL;
	params.dwFileFlags = WINDOWS_FILE_FLAG_BACKUP_SEMANTICS;
	params.dwSecurityQosFlags = 0;
	params.lpSecurityAttributes = NULL;
	params.hTemplateFile = 0;
	result = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, CreateFile2, proxy_wide_string(translate_windows_wide_path(path, wbuf)), proxy_value(desired_access), proxy_value(WINDOWS_FILE_SHARE_DELETE | WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE), proxy_value(WINDOWS_OPEN_ALWAYS), proxy_in(&params, sizeof(params))));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &windows_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t windows_path_unlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags)
{
	return remote_unlinkat(resolved.info.handle, resolved.info.path, flags);
}

static intptr_t windows_path_renameat2(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return remote_renameat2(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t windows_path_linkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path old_resolved, struct vfs_resolved_path new_resolved, int flags)
{
	return remote_linkat(old_resolved.info.handle, old_resolved.info.path, new_resolved.info.handle, new_resolved.info.path, flags);
}

static intptr_t windows_path_symlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path new_resolved, const char *old_path)
{
	return remote_symlinkat(old_path, new_resolved.info.handle, new_resolved.info.path);
}

static intptr_t windows_path_truncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	if (resolved.info.handle != AT_FDCWD) {
		return vfs_truncate_via_open_and_ftruncate(thread, resolved, length);
	}
	return FS_SYSCALL(LINUX_SYS_truncate, (intptr_t)resolved.info.path, length);
}

static intptr_t windows_path_fchmodat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, mode_t mode, int flags)
{
	return remote_fchmodat(resolved.info.handle, resolved.info.path, mode, flags);
}

static intptr_t windows_path_fchownat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, uid_t owner, gid_t group, int flags)
{
	return remote_fchownat(resolved.info.handle, resolved.info.path, owner, group, flags);
}

static intptr_t windows_path_utimensat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const struct timespec times[2], int flags)
{
	return remote_utimensat(resolved.info.handle, resolved.info.path, times, flags);
}

static intptr_t windows_path_newfstatat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_stat *out_stat, int flags)
{
	if ((flags & AT_EMPTY_PATH) && (resolved.info.path == NULL || *resolved.info.path == '\0')) {
		if (resolved.info.handle == AT_FDCWD) {
			resolved.info.path = ".";
		} else {
			return vfs_call(fstat, vfs_get_dir_file(resolved), out_stat);
		}
	}
	return -EINVAL;
}

static intptr_t windows_path_statx(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
	WINDOWS_BY_HANDLE_FILE_INFORMATION info;
	intptr_t handle;
	intptr_t result;
	if ((flags & AT_EMPTY_PATH) && (resolved.info.path == NULL || *resolved.info.path == '\0')) {
		if (resolved.info.handle == AT_FDCWD) {
			WINDOWS_CREATEFILE2_EXTENDED_PARAMETERS params;
			params.dwSize = sizeof(params);
			params.dwFileAttributes = WINDOWS_FILE_ATTRIBUTE_NORMAL;
			params.dwFileFlags = WINDOWS_FILE_FLAG_BACKUP_SEMANTICS;
			params.dwSecurityQosFlags = 0;
			params.lpSecurityAttributes = NULL;
			params.hTemplateFile = 0;
			uint16_t buf[2];
			buf[0] = '.';
			buf[1] = '\0';
			handle = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, CreateFile2, proxy_wide_string(buf), proxy_value(0), proxy_value(WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE | WINDOWS_FILE_SHARE_DELETE), proxy_value(WINDOWS_OPEN_EXISTING), proxy_in(&params, sizeof(params))));
			if (handle < 0) {
				return handle;
			}
		} else {
			result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, GetFileInformationByHandle, proxy_value(resolved.info.handle), proxy_out(&info, sizeof(info))));
			if (result >= 0) {
				translate_windows_by_handle_file_information_to_statx(statxbuf, info, mask);
			}
			return result;
		}
	} else {
		if (resolved.info.handle != AT_FDCWD) {
			return -EINVAL;
		}
		uint16_t buf[PATH_MAX];
		WINDOWS_CREATEFILE2_EXTENDED_PARAMETERS params;
		params.dwSize = sizeof(params);
		params.dwFileAttributes = WINDOWS_FILE_ATTRIBUTE_NORMAL;
		params.dwFileFlags = WINDOWS_FILE_FLAG_BACKUP_SEMANTICS;
		params.dwSecurityQosFlags = 0;
		params.lpSecurityAttributes = NULL;
		params.hTemplateFile = 0;
		handle = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, CreateFile2, proxy_wide_string(translate_windows_wide_path(resolved.info.path, buf)), proxy_value(WINDOWS_FILE_READ_ATTRIBUTES), proxy_value(WINDOWS_FILE_SHARE_DELETE | WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE), proxy_value(WINDOWS_OPEN_EXISTING), proxy_in(&params, sizeof(params))));
		if (handle < 0) {
			return handle;
		}
	}
	result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, GetFileInformationByHandle, proxy_value(handle), proxy_out(&info, sizeof(info))));
	PROXY_WIN32_BOOL_CALL(kernel32.dll, CloseHandle, proxy_value(handle));
	if (result < 0) {
		return result;
	}
	translate_windows_by_handle_file_information_to_statx(statxbuf, info, mask);
	return 0;
}

static intptr_t windows_path_statfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_statfs *out_buf)
{
	char buf[PATH_MAX];
	const char *path;
	int result = vfs_assemble_simple_path(thread, resolved, buf, &path);
	if (result != 0) {
		return result;
	}
	return FS_SYSCALL(LINUX_SYS_statfs, (intptr_t)resolved.info.path, (intptr_t)out_buf);
}

static intptr_t windows_path_faccessat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, int mode, int flag)
{
	return remote_faccessat(resolved.info.handle, resolved.info.path, mode, flag);
}

static intptr_t windows_path_readlinkat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, char *buf, size_t bufsz)
{
	return remote_readlinkat(resolved.info.handle, resolved.info.path, buf, bufsz);
}

static intptr_t windows_path_getxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, void *out_value, size_t size, int flags)
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

static intptr_t windows_path_setxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, const void *value, size_t size, int flags)
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

static intptr_t windows_path_removexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, const char *name, int flags)
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

static intptr_t windows_path_listxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, void *out_value, size_t size, int flags)
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

const struct vfs_path_ops windows_path_ops = {
	.dirfd_ops = &windows_file_ops,
	.mkdirat = windows_path_mkdirat,
	.mknodat = windows_path_mknodat,
	.openat = windows_path_openat,
	.unlinkat = windows_path_unlinkat,
	.renameat2 = windows_path_renameat2,
	.linkat = windows_path_linkat,
	.symlinkat = windows_path_symlinkat,
	.truncate = windows_path_truncate,
	.fchmodat = windows_path_fchmodat,
	.fchownat = windows_path_fchownat,
	.utimensat = windows_path_utimensat,
	.newfstatat = windows_path_newfstatat,
	.statx = windows_path_statx,
	.statfs = windows_path_statfs,
	.faccessat = windows_path_faccessat,
	.readlinkat = windows_path_readlinkat,
	.getxattr = windows_path_getxattr,
	.setxattr = windows_path_setxattr,
	.removexattr = windows_path_removexattr,
	.listxattr = windows_path_listxattr,
};


static intptr_t windows_file_socket(__attribute__((unused)) struct thread_storage *, int domain, int type, int protocol, struct vfs_resolved_file *out_file)
{
	intptr_t result = remote_socket(domain, type, protocol);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file) {
			.ops = &windows_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t windows_file_close(struct vfs_resolved_file file)
{
	struct windows_state *state = &get_fd_states()[file.handle].windows;
	if (state->dir_handle != NULL) {
		PROXY_WIN32_BOOL_CALL(kernel32.dll, FindClose, proxy_value((intptr_t)state->dir_handle));
		state->dir_handle = NULL;
	}
	PROXY_WIN32_BOOL_CALL(kernel32.dll, CloseHandle, proxy_value(file.handle));
	return 0;
}

static intptr_t windows_file_read(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	WINDOWS_DWORD numberOfBytesRead;
	intptr_t result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, ReadFile, proxy_value(file.handle), proxy_out(buf, bufsz), proxy_value(bufsz), proxy_out(&numberOfBytesRead, sizeof(numberOfBytesRead))));
	return result == 0 ? numberOfBytesRead : result;
}

static intptr_t windows_file_write(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	WINDOWS_DWORD numberOfBytesWritten;
	intptr_t result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, WriteFile, proxy_value(file.handle), proxy_in(buf, bufsz), proxy_value(bufsz), proxy_out(&numberOfBytesWritten, sizeof(numberOfBytesWritten))));
	return result == 0 ? numberOfBytesWritten : result;
}

static intptr_t windows_file_recvfrom(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	return remote_recvfrom(file.handle, buf, bufsz, flags, src_addr, addrlen);
}

static intptr_t windows_file_sendto(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
    return remote_sendto(file.handle, buf, bufsz, flags, dest_addr, dest_len);
}

static intptr_t windows_file_lseek(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, int whence)
{
	return remote_lseek(file.handle, offset, whence);
}

static intptr_t windows_file_fadvise64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, size_t offset, size_t len, int advice)
{
	// ignore fadvise
	(void)file;
	(void)offset;
	(void)len;
	(void)advice;
	return 0;
}

static intptr_t windows_file_readahead(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, size_t count)
{
	// ignore readahead
	(void)file;
	(void)offset;
	(void)count;
	return 0;
}

static intptr_t windows_file_pread(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *buf, size_t count, off_t offset)
{
	return remote_pread(file.handle, buf, count, offset);
}

static intptr_t windows_file_pwrite(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const void *buf, size_t count, off_t offset)
{
	return remote_pwrite(file.handle, buf, count, offset);
}

static intptr_t windows_file_flock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return remote_flock(file.handle, how);
}

static intptr_t windows_file_fsync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return remote_fsync(file.handle);
}

static intptr_t windows_file_fdatasync(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return remote_fdatasync(file.handle);
}

static intptr_t windows_file_syncfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file)
{
	return remote_syncfs(file.handle);
}

static intptr_t windows_file_sync_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t offset, off_t nbytes, unsigned int flags)
{
	return remote_sync_file_range(file.handle, offset, nbytes, flags);
}

static intptr_t windows_file_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, off_t length)
{
	return remote_ftruncate(file.handle, length);
}

static intptr_t windows_file_fallocate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int mode, off_t offset, off_t len)
{
	return remote_fallocate(file.handle, mode, offset, len);
}

static intptr_t windows_file_recvmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct msghdr *msg, int flags)
{
	return remote_recvmsg(thread, file.handle, msg, flags);
}

static intptr_t windows_file_sendmsg(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct msghdr *msg, int flags)
{
	return remote_sendmsg(thread, file.handle, msg, flags);
}

static intptr_t windows_file_fcntl_basic(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, intptr_t argument)
{
	return remote_fcntl_basic(file.handle, cmd, argument);
}

static intptr_t windows_file_fcntl_lock(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, struct flock *lock)
{
	return remote_fcntl_lock(file.handle, cmd, lock);
}

static intptr_t windows_file_fcntl_int(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int cmd, int *value)
{
	return remote_fcntl_int(file.handle, cmd, value);
}

static intptr_t windows_file_fchmod(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, mode_t mode)
{
	return remote_fchmod(file.handle, mode);
}

static intptr_t windows_file_fchown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, uid_t owner, gid_t group)
{
	return remote_fchown(file.handle, owner, group);
}

static intptr_t windows_file_fstat(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_stat *out_stat)
{
	WINDOWS_BY_HANDLE_FILE_INFORMATION info;
	intptr_t result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, GetFileInformationByHandle, proxy_value(file.handle), proxy_out(&info, sizeof(info))));
	if (result >= 0) {
		*out_stat = translate_windows_by_handle_file_information(info);
	}
	return result;
}

static intptr_t windows_file_fstatfs(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_statfs *out_buf)
{
	return remote_fstatfs(file.handle, out_buf);
}

static intptr_t windows_file_readlink_fd(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return remote_readlink_fd(file.handle, buf, size);
}

static intptr_t windows_file_getdents(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	return remote_getdents(file.handle, buf, size);
}

static intptr_t windows_file_getdents64(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t size)
{
	// TODO: check size
	(void)size;
	struct windows_state *state = &get_fd_states()[file.handle].windows;
	WINDOWS_WIN32_FIND_DATAW find_data;
	intptr_t result;
	if (state->dir_handle == NULL) {
		uint16_t path_buf[PATH_MAX];
		result = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, GetFinalPathNameByHandleW, proxy_value(file.handle), proxy_out(path_buf, sizeof(path_buf)), proxy_value(PATH_MAX), proxy_value(0)));
		if (result < 0) {
			return result;
		}
		if (path_buf[result] != '\\') {
			path_buf[result++] = '\\';
		}
		path_buf[result++] = '*';
		path_buf[result++] = '\0';
		result = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, FindFirstFileW, proxy_in(path_buf, result * sizeof(uint16_t)), proxy_out(&find_data, sizeof(find_data))));
		if (result > 0) {
			state->dir_handle = (WINDOWS_HANDLE)result;
		}
	} else {
		result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, FindNextFileW, proxy_value((intptr_t)state->dir_handle), proxy_out(&find_data, sizeof(find_data))));
	}
	if (result < 0) {
		// convert -ENOENT to 0, representing end of directory listing
		return result == -ENOENT ? 0 : result;
	}
	// translate the single directory entry
	struct fs_dirent *dirp = (void *)buf;
	dirp->d_ino = 1;
	dirp->d_type = (find_data.dwFileAttributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY) ? DT_DIR : DT_REG;
	size_t i = 0;
	for (; i < WINDOWS_MAX_PATH; i++) {
		dirp->d_name[i] = find_data.cFileName[i];
		if (dirp->d_name[i] == '\0') {
			break;
		}
	}
	size_t rec_len = sizeof(struct fs_dirent) + i + 2;
	size_t aligned_len = (rec_len + 7) & ~7;
	dirp->d_reclen = aligned_len;
	dirp->d_off = aligned_len;
	return aligned_len;
}

static intptr_t windows_file_fgetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, void *out_value, size_t size)
{
	return remote_fgetxattr(file.handle, name, out_value, size);
}

static intptr_t windows_file_fsetxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name, const void *value, size_t size, int flags)
{
	return remote_fsetxattr(file.handle, name, value, size, flags);
}

static intptr_t windows_file_fremovexattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const char *name)
{
	return remote_fremovexattr(file.handle, name);
}

static intptr_t windows_file_flistxattr(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, void *out_value, size_t size)
{
	return remote_flistxattr(file.handle, out_value, size);
}

static intptr_t windows_file_connect(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return remote_connect(file.handle, addr, size);
}

static intptr_t windows_file_bind(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, const struct sockaddr *addr, size_t size)
{
	return remote_bind(file.handle, addr, size);
}

static intptr_t windows_file_listen(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int backlog)
{
	return remote_listen(file.handle, backlog);
}

static intptr_t windows_file_accept4(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags, struct vfs_resolved_file *out_file)
{
	int result = remote_accept4(file.handle, addr, addrlen, flags);
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &windows_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

static intptr_t windows_file_getsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, void *restrict optval, socklen_t *restrict optlen)
{
	return remote_getsockopt(file.handle, level, optname, optval, optlen);
}

static intptr_t windows_file_setsockopt(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int level, int optname, const void *optval, socklen_t optlen)
{
	return remote_setsockopt(file.handle, level, optname, optval, optlen);
}

static intptr_t windows_file_getsockname(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return remote_getsockname(file.handle, addr, addrlen);
}

static intptr_t windows_file_getpeername(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return remote_getpeername(file.handle, addr, addrlen);
}

static intptr_t windows_file_shutdown(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, int how)
{
	return remote_shutdown(file.handle, how);
}

static intptr_t windows_file_sendfile(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_out, struct vfs_resolved_file file_in, off_t *offset, size_t size)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_sendfile(file_out.handle, file_in.handle, offset, size);
}

static intptr_t windows_file_splice(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off_t *off_in, struct vfs_resolved_file file_out, off_t *off_out, size_t size, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_splice(file_in.handle, off_in, file_out.handle, off_out, size, flags);
}

static intptr_t windows_file_tee(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, struct vfs_resolved_file file_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_tee(file_in.handle, file_out.handle, len, flags);
}

static intptr_t windows_file_copy_file_range(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file_in, off64_t *off_in, struct vfs_resolved_file file_out, off64_t *off_out, size_t len, unsigned int flags)
{
	if (file_in.ops != file_out.ops) {
		return -EINVAL;
	}
	return remote_copy_file_range(file_in.handle, off_in, file_out.handle, off_out, len, flags);
}

static intptr_t windows_file_ioctl(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg)
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

static intptr_t windows_file_ioctl_open_file(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, unsigned int cmd, unsigned long arg, struct vfs_resolved_file *out_file)
{
	intptr_t result = PROXY_CALL(LINUX_SYS_ioctl | PROXY_NO_WORKER, proxy_value(file.handle), proxy_value(cmd), proxy_value(arg));
	if (result >= 0) {
		*out_file = (struct vfs_resolved_file){
			.ops = &windows_file_ops,
			.handle = result,
		};
		return 0;
	}
	return result;
}

const struct vfs_file_ops windows_file_ops = {
	.socket = windows_file_socket,
	.close = windows_file_close,
	.read = windows_file_read,
	.write = windows_file_write,
	.recvfrom = windows_file_recvfrom,
	.sendto = windows_file_sendto,
	.lseek = windows_file_lseek,
	.fadvise64 = windows_file_fadvise64,
	.readahead = windows_file_readahead,
	.pread = windows_file_pread,
	.pwrite = windows_file_pwrite,
	.flock = windows_file_flock,
	.fsync = windows_file_fsync,
	.fdatasync = windows_file_fdatasync,
	.syncfs = windows_file_syncfs,
	.sync_file_range = windows_file_sync_file_range,
	.ftruncate = windows_file_ftruncate,
	.fallocate = windows_file_fallocate,
	.recvmsg = windows_file_recvmsg,
	.sendmsg = windows_file_sendmsg,
	.fcntl_basic = windows_file_fcntl_basic,
	.fcntl_lock = windows_file_fcntl_lock,
	.fcntl_int = windows_file_fcntl_int,
	.fchmod = windows_file_fchmod,
	.fchown = windows_file_fchown,
	.fstat = windows_file_fstat,
	.fstatfs = windows_file_fstatfs,
	.readlink_fd = windows_file_readlink_fd,
	.getdents = windows_file_getdents,
	.getdents64 = windows_file_getdents64,
	.fgetxattr = windows_file_fgetxattr,
	.fsetxattr = windows_file_fsetxattr,
	.fremovexattr = windows_file_fremovexattr,
	.flistxattr = windows_file_flistxattr,
	.connect = windows_file_connect,
	.bind = windows_file_bind,
	.listen = windows_file_listen,
	.accept4 = windows_file_accept4,
	.getsockopt = windows_file_getsockopt,
	.setsockopt = windows_file_setsockopt,
	.getsockname = windows_file_getsockname,
	.getpeername = windows_file_getpeername,
	.shutdown = windows_file_shutdown,
	.sendfile = windows_file_sendfile,
	.splice = windows_file_splice,
	.tee = windows_file_tee,
	.copy_file_range = windows_file_copy_file_range,
	.ioctl = windows_file_ioctl,
	.ioctl_open_file = windows_file_ioctl_open_file,
};
