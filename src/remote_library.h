#ifndef REMOTE_LIBRARY_H
#define REMOTE_LIBRARY_H

#include <stdint.h>

void discovered_remote_library_mapping(int remote_fd, uintptr_t local_address);

#endif
