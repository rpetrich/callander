#include "remote_library.h"

#include "axon.h"

void discovered_remote_library_mapping(struct vfs_resolved_file file, uintptr_t local_address)
{
	(void)file;
	(void)local_address;
	DIE("detected load of remote library");
}
