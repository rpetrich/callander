#ifndef PROXY_TARGET_H
#define PROXY_TARGET_H

#include <sys/types.h>
#include <unistd.h>

struct proxy_target_state {
	pid_t self_pid;
	int fd_counts[4096];
};

__attribute__((visibility("default")))
extern struct proxy_target_state proxy_state;

#endif
