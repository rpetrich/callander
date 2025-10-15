#define _GNU_SOURCE
#include "vfs.h"
#include "attempt.h"
#include "remote_library.h"

intptr_t vfs_truncate_via_open_and_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	struct vfs_resolved_file temp_file;
	intptr_t result = vfs_call(openat, resolved, O_WRONLY | O_CLOEXEC, 0, &temp_file);
	if (result >= 0) {
		struct attempt_cleanup_state state;
		vfs_attempt_push_close(thread, &state, &temp_file);
		result = vfs_call(ftruncate, temp_file, length);
		vfs_attempt_pop_close(&state);
	}
	return result;
}

intptr_t vfs_mmap_via_pread(struct thread_storage *thread, struct vfs_resolved_file file, void *addr, size_t len, int prot, int flags, size_t off)
{
	void *result = fs_mmap(addr, len, PROT_READ | PROT_WRITE, (flags & ~MAP_FILE) | MAP_ANONYMOUS, -1, 0);
	if (!fs_is_map_failed(result)) {
		size_t successful_reads = 0;
		do {
			intptr_t read_result = vfs_call(pread, file, result + successful_reads, len - successful_reads, off + successful_reads);
			if (read_result <= 0) {
				if (read_result == 0) {
					// can't read past end of file, but can map. ignore short reads
					break;
				}
				fs_munmap(result, len);
				return read_result;
			}
			successful_reads += read_result;
		} while (successful_reads < len);
		if (prot != (PROT_READ | PROT_WRITE)) {
			int prot_result = fs_mprotect(result, len, prot);
			if (prot_result < 0) {
				fs_munmap(result, len);
				return prot_result;
			}
		}
		if (prot == (PROT_READ | PROT_EXEC) && (flags & MAP_DENYWRITE)) {
			discovered_remote_library_mapping(file, (uintptr_t)addr - off);
		}
	}
	return (intptr_t)result;
}

intptr_t vfs_assemble_simple_path(struct thread_storage *thread, struct vfs_resolved_path resolved, char buf[PATH_MAX], const char **out_path)
{
	if (resolved.info.path == NULL || *resolved.info.path == '\0' || (resolved.info.path[0] == '.' && resolved.info.path[1] == '\0')) {
		intptr_t count = vfs_call(readlink_fd, vfs_get_dir_file(resolved), buf, PATH_MAX);
		if (count < 0) {
			return count;
		}
		if (count >= PATH_MAX) {
			return -ENAMETOOLONG;
		}
		buf[count] = '\0';
		*out_path = buf;
		return 0;
	}
	if (resolved.info.path[0] == '/') {
		*out_path = resolved.info.path;
		return 0;
	}
	intptr_t count = vfs_call(readlink_fd, vfs_get_dir_file(resolved), buf, PATH_MAX);
	if (count < 0) {
		return count;
	}
	if (count >= PATH_MAX - 2) {
		return -ENAMETOOLONG;
	}
	if (count && buf[count - 1] != '/') {
		buf[count] = '/';
		count++;
	}
	size_t len = fs_strlen(resolved.info.path);
	if (count + len + 1 > PATH_MAX) {
		return -ENAMETOOLONG;
	}
	fs_memcpy(&buf[count], resolved.info.path, len + 1);
	*out_path = buf;
	return 0;
}

void vfs_close_cleanup_body(void *data, struct thread_storage *)
{
	const struct vfs_resolved_file *file = data;
	file->ops->close(*file, &get_fd_global_state()->files[file->handle].state);
}

void vfs_attempt_push_close(struct thread_storage *thread, struct attempt_cleanup_state *state, const struct vfs_resolved_file *file)
{
	state->body = &vfs_close_cleanup_body;
	state->data = (void *)file;
	attempt_push_cleanup(thread, state);
}

void vfs_attempt_pop_close(struct attempt_cleanup_state *state)
{
	attempt_pop_and_skip_cleanup(state);
	const struct vfs_resolved_file *file = state->data;
	file->ops->close(*file, &get_fd_global_state()->files[file->handle].state);
}

__attribute__((noinline)) intptr_t vfs_unsupported_op(void)
{
	return -EINVAL;
}

__attribute__((noinline)) intptr_t vfs_invalid_mixed_op(void)
{
	return -EINVAL;
}

intptr_t fstat_from_statx(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_file file, struct fs_stat *out_stat)
{
	struct linux_statx statxbuf = {0};
	struct vfs_path_ops *ops = (struct vfs_path_ops *)file.ops;
	intptr_t result = ops->statx(thread, (struct vfs_resolved_path){ .ops = ops, .info = { .handle = file.handle, .path = NULL } }, AT_EMPTY_PATH, STATX_BASIC_STATS, &statxbuf);
	if (result < 0) {
		return result;
	}
	*out_stat = (struct fs_stat) {
		.st_dev = statxbuf.stx_dev_major,
		.st_ino = (statxbuf.stx_mask & STATX_INO) ? statxbuf.stx_ino : 0,
		.st_mode = (statxbuf.stx_mask & (STATX_MODE | STATX_TYPE)) ? statxbuf.stx_mode : 0,
		.st_nlink = (statxbuf.stx_mask & STATX_NLINK) ? statxbuf.stx_nlink : 0,
		.st_uid = (statxbuf.stx_mask & STATX_UID) ? statxbuf.stx_uid : 0,
		.st_gid = (statxbuf.stx_mask & STATX_GID) ? statxbuf.stx_gid : 0,
		.st_rdev = 0,
		.st_size = (statxbuf.stx_mask & STATX_SIZE) ? statxbuf.stx_size : 0,
		.st_blksize = statxbuf.stx_blksize,
		.st_blocks = (statxbuf.stx_mask & STATX_BLOCKS) ? statxbuf.stx_blocks : 0,
		.st_atime_sec = (statxbuf.stx_mask & STATX_ATIME) ? statxbuf.stx_atime.tv_sec : 0,
		.st_atime_nsec = (statxbuf.stx_mask & STATX_ATIME) ? statxbuf.stx_atime.tv_nsec : 0,
		.st_mtime_sec = (statxbuf.stx_mask & STATX_MTIME) ? statxbuf.stx_mtime.tv_sec : 0,
		.st_mtime_nsec = (statxbuf.stx_mask & STATX_MTIME) ? statxbuf.stx_mtime.tv_nsec : 0,
		.st_ctime_sec = (statxbuf.stx_mask & STATX_CTIME) ? statxbuf.stx_ctime.tv_sec : 0,
		.st_ctime_nsec = (statxbuf.stx_mask & STATX_CTIME) ? statxbuf.stx_ctime.tv_nsec : 0,
	};
	return 0;
}

intptr_t newfstatat_from_statx(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, struct fs_stat *out_stat, int flags)
{
	struct linux_statx statxbuf = {0};
	intptr_t result = resolved.ops->statx(thread, resolved, flags, STATX_BASIC_STATS, &statxbuf);
	if (result < 0) {
		return result;
	}
	*out_stat = (struct fs_stat) {
		.st_dev = statxbuf.stx_dev_major,
		.st_ino = (statxbuf.stx_mask & STATX_INO) ? statxbuf.stx_ino : 0,
		.st_mode = (statxbuf.stx_mask & (STATX_MODE | STATX_TYPE)) ? statxbuf.stx_mode : 0,
		.st_nlink = (statxbuf.stx_mask & STATX_NLINK) ? statxbuf.stx_nlink : 0,
		.st_uid = (statxbuf.stx_mask & STATX_UID) ? statxbuf.stx_uid : 0,
		.st_gid = (statxbuf.stx_mask & STATX_GID) ? statxbuf.stx_gid : 0,
		.st_rdev = 0,
		.st_size = (statxbuf.stx_mask & STATX_SIZE) ? statxbuf.stx_size : 0,
		.st_blksize = statxbuf.stx_blksize,
		.st_blocks = (statxbuf.stx_mask & STATX_BLOCKS) ? statxbuf.stx_blocks : 0,
		.st_atime_sec = (statxbuf.stx_mask & STATX_ATIME) ? statxbuf.stx_atime.tv_sec : 0,
		.st_atime_nsec = (statxbuf.stx_mask & STATX_ATIME) ? statxbuf.stx_atime.tv_nsec : 0,
		.st_mtime_sec = (statxbuf.stx_mask & STATX_MTIME) ? statxbuf.stx_mtime.tv_sec : 0,
		.st_mtime_nsec = (statxbuf.stx_mask & STATX_MTIME) ? statxbuf.stx_mtime.tv_nsec : 0,
		.st_ctime_sec = (statxbuf.stx_mask & STATX_CTIME) ? statxbuf.stx_ctime.tv_sec : 0,
		.st_ctime_nsec = (statxbuf.stx_mask & STATX_CTIME) ? statxbuf.stx_ctime.tv_nsec : 0,
	};
	return 0;
}

__attribute__((warn_unused_result)) bool lookup_potential_mount_path(const char *mountpoint, size_t mountpoint_len, int fd, const char *path, path_info *out_path)
{
	if (path != NULL) {
		if (path[0] == '/') {
			if (fs_strncmp(path, mountpoint, mountpoint_len) == 0) {
				if (path[mountpoint_len] == '/') {
					*out_path = (path_info){
						.handle = AT_FDCWD,
						.path = &path[mountpoint_len],
					};
					return true;
				}
				if (path[mountpoint_len] == '\0') {
					*out_path = (path_info){
						.handle = AT_FDCWD,
						.path = "/",
					};
					return true;
				}
			}
			out_path->handle = AT_FDCWD;
			out_path->path = path;
			return false;
		}
		out_path->path = path;
		if (fd == AT_FDCWD) {
			if (lookup_real_fd(CWD_FD, &out_path->handle)) {
				return true;
			}
			out_path->handle = AT_FDCWD;
			return false;
		}
		return lookup_real_fd(fd, &out_path->handle);
	}
	out_path->path = NULL;
	return lookup_real_fd(fd, &out_path->handle);
}
