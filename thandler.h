#ifndef THREAD_FUNC_H
#define THREAD_FUNC_H

struct start_thread_args {
	void (*pc)(intptr_t arg1, intptr_t arg2, intptr_t arg3);
	intptr_t sp;
	intptr_t arg1;
	intptr_t arg2;
	intptr_t arg3;
};

 __attribute__((visibility("default")))
noreturn void start_thread(const struct start_thread_args *args);

 __attribute__((visibility("default")))
void receive_syscall(intptr_t data[7]);

#endif
