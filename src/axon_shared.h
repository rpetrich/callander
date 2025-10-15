#ifndef AXON_SHARED
#define AXON_SHARED

#include <stddef.h>

#define SHARED_PAGE_FD 0x3fb

void map_shared(void *address, size_t size);
void create_shared(size_t size);

#endif
