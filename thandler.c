#include "freestanding.h"

#include "thandler.h"

#include "axon.h"
#include "handler.h"
#include "proxy_target.h"
#include "tls.h"

FS_DEFINE_SYSCALL

__attribute__((naked)) __attribute__((used)) __attribute__((visibility("default")))
noreturn void start_thread(const struct start_thread_args *args)
{
	proxy_state.self_pid = fs_gettid();
	JUMP(args->pc, args->sp, args->arg1, args->arg2, args->arg3);
	__builtin_unreachable();
}

__attribute__((used)) __attribute__((visibility("default")))
void receive_syscall(intptr_t data[7])
{
	struct thread_storage *thread = get_thread_storage();
	data[0] = handle_syscall(thread, data[0], data[1], data[2], data[3], data[4], data[5], data[6], NULL);
}
