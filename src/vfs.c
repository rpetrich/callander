#define _GNU_SOURCE
#include "vfs.h"

intptr_t vfs_truncate_via_open_and_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length)
{
	struct vfs_resolved_file temp_file;
	intptr_t result = resolved.ops->openat(thread, resolved, O_WRONLY | O_CLOEXEC, 0, &temp_file);
	if (result >= 0) {
		result = temp_file.ops->ftruncate(thread, temp_file, length);
		temp_file.ops->close(thread, temp_file);
	}
	return result;
}
