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
	char buf[20];

	for (int i = 0; i < aux->argc; i++) {
		if (i != 0) {
			fs_write(2, " ", 1);
		}
		fs_write(2, aux->argv[i], fs_strlen(aux->argv[i]));
	}
	fs_write(2, "\n", 1);

	int fd = fs_openat(AT_FDCWD, aux->argv[0], O_RDONLY, 0);
	if (fd < 0) {
		fs_write(2, "Failed to open file: ", sizeof("Failed to open file: ") - 1);
		char buf[21];
		fs_itoa(-fd, buf);
		fs_write(2, buf, fs_strlen(buf));
	} else {
		fs_write(2, "fd=", sizeof("fd=") - 1);
		char buf[21];
		fs_itoa(fd, buf);
		fs_write(2, buf, fs_strlen(buf));
	}
	fs_write(2, "\n", 1);

	char *const args[] = {"echo", "sample.c", NULL};
	int result = fs_execve("/bin/echo", args, NULL);
	if (result != 0) {
		fs_write(2, "Failed to exec /bin/echo: ", sizeof("Failed to exec /bin/echo: ") - 1);
		char buf[21];
		fs_itoa(-result, buf);
		fs_write(2, buf, fs_strlen(buf));
		fs_write(2, "\n", 1);
	}

	fs_exit(0);
	__builtin_unreachable();
}
