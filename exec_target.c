#define _GNU_SOURCE

#include "axon.h"
#include "exec.h"

#include "proxy.h"
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

void set_tid_address(const void *tid_address)
{
	if (fs_gettid() == get_self_pid()) {
		PROXY_CALL(__NR_set_tid_address | PROXY_NO_RESPONSE, proxy_value((intptr_t)tid_address));
	}
}

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

