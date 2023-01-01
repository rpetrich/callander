#ifndef HANDLER_H
#define HANDLER_H

#include "freestanding.h"

struct signal_state {
	struct fs_sigset_t blocked_required;
	struct fs_sigset_t pending_required;
};

struct thread_storage;

// handle_syscall handles a trapped syscall, potentially emulating or blocking as necessary
__attribute__((warn_unused_result))
intptr_t handle_syscall(struct thread_storage *thread, intptr_t syscall, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6, ucontext_t *context);

#endif
