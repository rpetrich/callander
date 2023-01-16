#define FS_INLINE_SYSCALL
#include "freestanding.h"
#include "axon.h"
#include "thread_func.h"

__attribute__((naked)) __attribute__((used)) __attribute__((visibility("default")))
noreturn void thread_func(const struct thread_func_args *args)
{
	JUMP(args->pc, args->sp, args->arg1, args->arg2, args->arg3);
	__builtin_unreachable();
}

__attribute__((used)) __attribute__((visibility("default")))
void thread_receive_syscall(intptr_t data[7])
{
	intptr_t syscall = data[0];
	if (syscall == SYS_exit_group) {
		syscall = SYS_exit;
	}
	if (syscall == SYS_openat) {
		FS_SYSCALL_NORETURN(SYS_exit, 0);
	}
	data[0] = FS_SYSCALL(syscall, data[1], data[2], data[3], data[4], data[5], data[6]);
}
