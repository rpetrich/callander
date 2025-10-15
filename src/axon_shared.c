#include "axon_shared.h"

#include "axon.h"
#include "freestanding.h"

void map_shared(void *address, size_t size)
{
	address = fs_mmap(address, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED | MAP_FIXED, SHARED_PAGE_FD, 0);
	if (fs_is_map_failed(address)) {
		if ((intptr_t)address == -EBADF) {
			DIE("not connected to a target");
		}
		DIE("mapping shared page failed: ", as_errno((intptr_t)address));
	}
}

void create_shared(size_t size)
{
	int memfd = fs_memfd_create("axon_shared", 0);
	if (memfd < 0) {
		DIE("unable to create memfd: ", as_errno(memfd));
	}

	intptr_t result = fs_ftruncate(memfd, (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
	if (result == -1) {
		DIE("unable to ftruncate: ", as_errno(result));
	}

	result = fs_dup2(memfd, SHARED_PAGE_FD);
	if (result < 0) {
		DIE("error duping: ", as_errno(result));
	}

	fs_close(memfd);
}
