#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, const char *argv[]) {
	int fd = open(argv[0] + 4096 * 1024, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "error %d: %s\n", errno, strerror(errno));
	} else {
		fprintf(stderr, "fd=%d\n", fd);
	}
	return 0;
}
