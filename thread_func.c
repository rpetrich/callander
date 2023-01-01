#define FS_INLINE_SYSCALL
#include "freestanding.h"
#include "axon.h"
#include "thread_func.h"

__attribute__((section(THREAD_FUNC_SECTION))) __attribute__((used))
static void thread_func(const struct thread_func_args *args)
{
	JUMP(args->pc, args->sp, args->arg1, args->arg2, args->arg3);
	__builtin_unreachable();
}
