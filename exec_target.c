#define _GNU_SOURCE

#include "axon.h"
#include "exec.h"

#include "proxy_target.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

uid_t startup_euid;
gid_t startup_egid;

#ifdef ENABLE_TELEMETRY
uint32_t enabled_telemetry;
#endif

pid_t get_self_pid(void)
{
	return proxy_state.self_pid;
}

// void invalidate_self_pid(void)
// {
// }

__attribute__((warn_unused_result))
bool is_axon(const struct fs_stat *stat)
{
	(void)stat;
	return false;
}

int wrapped_execveat(struct thread_storage *thread, int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags)
{
	(void)thread;
	(void)dfd;
	(void)filename;
	(void)argv;
	(void)envp;
	(void)flags;
	return -ENOSYS;
}

