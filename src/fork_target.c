#define _GNU_SOURCE

#include "fork.h"

#include <errno.h>

pid_t wrapped_fork(struct thread_storage *thread)
{
	(void)thread;
	return -ENOSYS;
}

pid_t wrapped_vfork(struct thread_storage *thread)
{
	(void)thread;
	return -ENOSYS;
}

pid_t wrapped_clone(struct thread_storage *thread, unsigned long flags, void *stack, int *parent_tid, int *child_tid, unsigned long tls)
{
	(void)thread;
	(void)flags;
	(void)stack;
	(void)parent_tid;
	(void)child_tid;
	(void)tls;
	return -ENOSYS;
}
