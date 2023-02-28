#include "remote_library.h"

#include "axon.h"
#include "proxy.h"

void discovered_remote_library_mapping(int remote_fd, uintptr_t local_address)
{
	PROXY_CALL(0x666, proxy_value(remote_fd), proxy_value(local_address));
}
