#ifndef PROXY_TARGET_H
#define PROXY_TARGET_H

#include <sys/types.h>
#include <unistd.h>

#include "target.h"

struct proxy_target_state {
	uint32_t stream_id;
	target_state *target_state;
	int fd_counts[4096];
};

__attribute__((visibility("default")))
extern struct proxy_target_state proxy_state;

#endif
