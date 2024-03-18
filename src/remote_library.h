#ifndef REMOTE_LIBRARY_H
#define REMOTE_LIBRARY_H

#include <stdint.h>

#include "vfs.h"

void discovered_remote_library_mapping(struct vfs_resolved_file file, uintptr_t local_address);

#endif
