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

__attribute__((used)) __attribute__((visibility("default"))) NAKED_FUNCTION
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
#ifdef __aarch64__
	data[0] = handle_syscall(thread, data[6], data[0], data[1], data[2], data[3], data[4], data[5], NULL);
#else
	data[0] = handle_syscall(thread, data[0], data[1], data[2], data[3], data[4], data[5], data[6], NULL);
#endif
}

#ifdef PROXY_SUPPORT_ALL_PLATFORMS
enum target_platform proxy_get_target_platform(void) {
#ifdef __linux__
	return TARGET_PLATFORM_LINUX;
#else
#error "thandler only supports linux"
#endif
}
#endif
