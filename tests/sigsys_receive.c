#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "../freestanding.h"

FS_DEFINE_SYSCALL;

int main(int argc, const char *argv[]) {
	// write(2, "Sample\n", sizeof("Sample\n")-1);
	// open a file
	intptr_t result = FS_SYSCALL(-1);
	fprintf(stderr, "invalid syscall returned %lld\n", result);
	kill(getpid(), SIGSYS);
	return 0;
}
