#ifndef THREAD_FUNC_H
#define THREAD_FUNC_H

#define THREAD_FUNC_SECTION ".thread_func"

struct thread_func_args {
	void (*pc)(intptr_t arg1, intptr_t arg2, intptr_t arg3);
	intptr_t sp;
	intptr_t arg1;
	intptr_t arg2;
	intptr_t arg3;
};

noreturn void thread_func(const struct thread_func_args *args);

void thread_receive_syscall(intptr_t data[7]);

#endif
