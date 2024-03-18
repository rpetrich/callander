#include "remote_library.h"

#include "axon.h"
#include "proxy.h"

void discovered_remote_library_mapping(struct vfs_resolved_file file, uintptr_t local_address)
{
	PROXY_CALL(0x666, proxy_value(file.handle), proxy_value(local_address));
}
