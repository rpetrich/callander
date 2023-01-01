#ifndef EXEC_H
#define EXEC_H

#include <linux/limits.h>
#include <stdbool.h>
#include <sys/types.h>

#include "freestanding.h"

// startup_euid is the euid that the process had at startup
extern uid_t startup_euid;

// startup_egid is the egid that the process had at startup
extern gid_t startup_egid;

// axon_stat is a cached copy of stat for the main axon
extern struct fs_stat axon_stat;

__attribute__((always_inline))
static inline bool is_axon(const struct fs_stat *stat) {
	return stat->st_dev == axon_stat.st_dev && stat->st_ino == axon_stat.st_ino;
}

// get_self_pid returns the current process' PID
pid_t get_self_pid(void);

// get_self_pid invalidates the current process' cached PID
void invalidate_self_pid(void);

// exec_fd executes an open file via the axon bootstrap, handling native-arch ELF and #! programs only
__attribute__((warn_unused_result))
int exec_fd(int fd, const char *named_path, const char *const *argv, const char *const *envp, const char *comm, int depth);

#endif
