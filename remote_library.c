#include "remote_library.h"

#include "axon.h"

void discovered_remote_library_mapping(int remote_fd, uintptr_t local_address)
{
	(void)remote_fd;
	(void)local_address;
	DIE("detected load of remote library");
}
