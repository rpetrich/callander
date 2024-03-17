#define _GNU_SOURCE
#include "vfs.h"
#include "attempt.h"

intptr_t vfs_truncate_via_open_and_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	struct vfs_resolved_file temp_file;
	intptr_t result = vfs_call(openat, resolved, O_WRONLY | O_CLOEXEC, 0, &temp_file);
	if (result >= 0) {
		struct attempt_cleanup_state state;
		vfs_attempt_push_close(thread, &state, &temp_file);
		result = vfs_call(ftruncate, temp_file, length);
		vfs_attempt_pop_close(thread, &state);
	}
	return result;
}

static inline struct vfs_resolved_file vfs_get_dir_file(struct vfs_resolved_path resolved) {
	return (struct vfs_resolved_file){
		.handle = resolved.info.handle,
		.ops = resolved.ops->dirfd_ops,
	};
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

void vfs_close_cleanup_body(void *data, struct thread_storage *thread)
{
	const struct vfs_resolved_file *file = data;
	vfs_call(close, *file);
}

void vfs_attempt_push_close(struct thread_storage *thread, struct attempt_cleanup_state *state, const struct vfs_resolved_file *file)
{
	state->body = (attempt_cleanup_body)(void *)&vfs_close_cleanup_body;
	state->data = (void *)file;
	attempt_push_cleanup(thread, state);
}

void vfs_attempt_pop_close(struct thread_storage *thread, struct attempt_cleanup_state *state)
{
	attempt_pop_and_skip_cleanup(state);
	const struct vfs_resolved_file *file = state->data;
	vfs_call(close, *file);
}
