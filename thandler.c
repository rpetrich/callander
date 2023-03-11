#include "freestanding.h"

#include "thandler.h"

#include "axon.h"
#include "handler.h"
#include "proxy.h"
#include "proxy_target.h"
#include "tls.h"

FS_DEFINE_SYSCALL

static pid_t self_pid;

pid_t get_self_pid(void)
{
	return self_pid;
}

void set_tid_address(const void *tid_address)
{
	if (fs_gettid() == get_self_pid()) {
		PROXY_CALL(__NR_set_tid_address | PROXY_NO_RESPONSE, proxy_value((intptr_t)tid_address));
	}
}

__attribute__((naked)) __attribute__((used)) __attribute__((visibility("default")))
noreturn void receive_start(const struct receive_start_args *args)
{
	self_pid = fs_gettid();
	JUMP(args->pc, args->sp, args->arg1, args->arg2, args->arg3);
	__builtin_unreachable();
}

__attribute__((used)) __attribute__((visibility("default")))
void receive_clone(intptr_t data[7])
{
	(void)data;
	PROXY_CALL(__NR_clone | PROXY_NO_RESPONSE);
}

__attribute__((used)) __attribute__((visibility("default")))
void receive_syscall(intptr_t data[7])
{
	struct thread_storage *thread = get_thread_storage();
	data[0] = handle_syscall(thread, data[0], data[1], data[2], data[3], data[4], data[5], data[6], NULL);
}
