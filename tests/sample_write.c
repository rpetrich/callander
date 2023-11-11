#define FS_INLINE_SYSCALL
#include "../freestanding.h"

#include "../axon.h"
AXON_BOOTSTRAP_ASM

#include <stdnoreturn.h>

typedef struct {
	int argc;
	const char *argv[];
} aux_t;

__attribute__((used))
noreturn void release(aux_t *aux, size_t *dynv)
{
	fs_write(2, "Hello World!\n", sizeof("Hello World!\n") - 1);
	// struct timespec delay;
	// delay.tv_sec = 1;
	// delay.tv_nsec = 0;
	// fs_nanosleep(&delay, NULL);
	// fs_write(2, "Hello World!\n", sizeof("Hello World!\n") - 1);
	fs_exitthread(0);
	__builtin_unreachable();
}
