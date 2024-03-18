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
		if (prot == (PROT_READ|PROT_EXEC) && (flags & MAP_DENYWRITE)) {
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

void vfs_close_cleanup_body(void *data)
{
	const struct vfs_resolved_file *file = data;
	file->ops->close(*file);
}

void vfs_attempt_push_close(struct thread_storage *thread, struct attempt_cleanup_state *state, const struct vfs_resolved_file *file)
{
	state->body = (attempt_cleanup_body)(void *)&vfs_close_cleanup_body;
	state->data = (void *)file;
	attempt_push_cleanup(thread, state);
}

void vfs_attempt_pop_close(struct attempt_cleanup_state *state)
{
	attempt_pop_and_skip_cleanup(state);
	const struct vfs_resolved_file *file = state->data;
	file->ops->close(*file);
}
