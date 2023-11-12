#ifndef PROXY_TARGET_H
#define PROXY_TARGET_H

#include <sys/types.h>
#include <unistd.h>

#include "target.h"

#define TEXEC_HEAP_SIZE (5 * 1024 * 1024)

struct proxy_target_state {
	uint32_t stream_id;
	target_state *target_state;
	uintptr_t heap;
	int fd_counts[4096];
};

__attribute__((visibility("default")))
extern struct proxy_target_state proxy_state;

#endif
