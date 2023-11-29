#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "freestanding.h"

#include "axon.h"

FS_DEFINE_SYSCALL

#define SYSCALL_DEF(name, argc, flags) 1+
#define SYSCALL_DEF_EMPTY() 1+
enum {
	SYSCALL_DEFINED_COUNT = 
#include "syscall_defs.h"
	0,
};
#undef SYSCALL_DEF
#undef SYSCALL_DEF_EMPTY

#define SYSCALL_DEF(name, argc, flags) #name,
#define SYSCALL_DEF_EMPTY() NULL,
const char *syscall_list[] = {
#include "syscall_defs.h"
};
#undef SYSCALL_DEF
#undef SYSCALL_DEF_EMPTY


int main(int argc, const char *argv[]) {
	char buf[4096 * 10 + 1];
	int read_cursor = 0;
	int scan_cursor = 0;
	struct iovec vec[2];
	vec[1].iov_base = "\n";
	vec[1].iov_len = 1;
	for (;;) {
		int result = fs_read(0, &buf[read_cursor], (sizeof(buf) - 1) - read_cursor);
		if (result <= 0) {
			if (result == -EINTR) {
				continue;
			}
			if (result == 0) {
				break;
			}
			DIE("error reading", fs_strerror(result));
		}
		read_cursor += result;
		buf[read_cursor] = '\0';
		while (scan_cursor < read_cursor) {
			intptr_t number;
			const char *result = fs_scans(&buf[scan_cursor], &number);
			if (result == &buf[read_cursor]) {
				break;
			}
			if (result == &buf[scan_cursor] || result == NULL) {
				if (buf[scan_cursor] != ' ') {
					ERROR_FLUSH();
					return 1;
				}
				scan_cursor++;
			} else {
				if ((uintptr_t)number < SYSCALL_DEFINED_COUNT && syscall_list[number] != NULL) {
					vec[0].iov_base = (void *)syscall_list[number];
					vec[0].iov_len = fs_strlen(syscall_list[number]);
				} else {
					vec[0].iov_base = &buf[scan_cursor];
					vec[0].iov_len = result - &buf[scan_cursor];
				}
				ERROR_WRITEV(vec, 2);
				scan_cursor = result - &buf[0];
			}
		}
		fs_memmove(buf, &buf[scan_cursor], read_cursor - scan_cursor);
		read_cursor -= scan_cursor;
		scan_cursor = 0;
	}
	ERROR_FLUSH();

	return 0;
}
