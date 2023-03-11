#ifndef THREAD_FUNC_H
#define THREAD_FUNC_H

struct receive_start_args {
	void (*pc)(intptr_t arg1, intptr_t arg2, intptr_t arg3);
	intptr_t sp;
	intptr_t arg1;
	intptr_t arg2;
	intptr_t arg3;
};

 __attribute__((visibility("default")))
noreturn void receive_start(const struct receive_start_args *args);

__attribute__((used)) __attribute__((visibility("default")))
void receive_clone(intptr_t data[7]);

 __attribute__((visibility("default")))
void receive_syscall(intptr_t data[7]);

#endif
