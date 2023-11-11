#ifndef FORK_H
#define FORK_H

#include <sys/types.h>
#include <unistd.h>

struct thread_storage;

pid_t wrapped_fork(struct thread_storage *thread);
pid_t wrapped_vfork(struct thread_storage *thread);
pid_t wrapped_clone(struct thread_storage *thread, unsigned long flags, void *stack, int *parent_tid, int *child_tid, unsigned long tls);

#endif
