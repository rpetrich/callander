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

__attribute__((warn_unused_result))
bool is_axon(const struct fs_stat *stat);

// get_self_pid returns the current process' PID
pid_t get_self_pid(void);

// get_self_pid invalidates the current process' cached PID
void invalidate_self_pid(void);

void set_tid_address(const void *new_address);

// exec_fd executes an open file via the axon bootstrap, handling native-arch ELF and #! programs only
__attribute__((warn_unused_result))
int exec_fd(int fd, const char *named_path, const char *const *argv, const char *const *envp, const char *comm, int depth);

struct thread_storage;

// wrapped_execveat executes a program via the axon bootstrap, handling native-arch ELF and #! programs only
__attribute__((warn_unused_result))
int wrapped_execveat(struct thread_storage *thread, int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags);

// count_args counts the number of arguments in an argv array
static inline size_t count_args(char * const *argv) {
	size_t argc = 0;
	if (argv) {
		while (argv[argc]) {
			argc++;
		}
	}
	return argc;
}

#endif
