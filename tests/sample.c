#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, const char *argv[]) {
	// write(2, "Sample\n", sizeof("Sample\n")-1);
	// open a file
	int fd = open(argv[0], O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "error %d: %s\n", errno, strerror(errno));
	} else {
		fprintf(stderr, "fd=%d\n", fd);
	}

	int result = execl("/bin/echo", "echo", "sample.c", NULL);
	if (result != 0) {
		fprintf(stderr, "error %d: %s\n", errno, strerror(errno));
	}
	return 0;
}
