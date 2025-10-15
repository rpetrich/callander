#ifndef VFS_ZIP
#define VFS_ZIP

// #include "libzip/lib/zip.h"

#include <stddef.h>
#include <limits.h>

struct vfs_zip_state {
	size_t size;
	struct zip *za;
	size_t *entry_offsets;
	void *address;
	size_t mountpoint_len;
	char mountpoint[PATH_MAX];
};

void vfs_zip_install(void *addr);
void vfs_zip_configure(void);

extern const struct vfs_path_ops zip_path_ops;

#endif
