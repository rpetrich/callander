#ifndef __MINGW32__
#define _GNU_SOURCE
#define FS_INLINE_SYSCALL
#define FS_INLINE_MUTEX_SLOW_PATH
#include "freestanding.h"

#ifdef __APPLE__
#include "darwin.h"
#endif

#include "axon.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#endif

#include "target.h"
#include "proxy.h"

#pragma GCC diagnostic ignored "-Wunused-result"

#if 0

#define WRITE_LITERAL(fd, lit) fs_write(fd, lit, sizeof(lit)-1)

static inline void print_with_int(const char *message, size_t message_len, int value) {
	fs_write(2, message, message_len);
	char buf[21];
	int len = fs_itoa(value, buf);
	buf[len] = '\n';
	fs_write(2, buf, len + 1);
}

#define PRINT_WITH_INT(message, value) print_with_int(message ": ", sizeof(message)+1, value)

noreturn static void exit_from_errno(const char *message, size_t message_len, int result) {
	print_with_int(message, message_len, -result);
	fs_exit(1);
	__builtin_unreachable();
}

#define EXIT_FROM_ERRNO(message, err) exit_from_errno(message ": ", sizeof(message)+1, err)
#else
#define EXIT_FROM_ERRNO(message, err) do { fs_exit(1); } while(0)
#endif

typedef struct {
	int argc;
	const char *argv[];
} aux_t;

noreturn static void process_data(void);

static target_state state;

#ifdef __linux__
__attribute__((used)) __attribute__((aligned(4)))
noreturn void release(__attribute__((unused)) uint32_t expected_addr, __attribute__((unused)) uint32_t expected_port)
#else
int main(void)
#endif
{
	intptr_t result;
#if 0
	int fd = 0;
	for (;;) {
		struct sockaddr_in sa;
		socklen_t len = sizeof(sa);
		result = FS_SYSCALL(SYS_getpeername, fd, (intptr_t)&sa, (intptr_t)&len);
		if (result == 0 && sa.sin_family == AF_INET && sa.sin_addr.s_addr == expected_addr && sa.sin_port == expected_port) {
			break;
		}
		fd++;
	}
	(void)fs_fcntl(fd, F_SETFL, O_RDWR);
	result = fs_fork();
	if (result != 0) {
		fs_exit(0);
	}
#else
#ifdef __MINGW32__
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
	int fd = fs_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		EXIT_FROM_ERRNO("Failed to open socket", fd);
	}

	struct sockaddr_in addr = { 0 };
	// addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = fs_htonl((127 << 24) | 1);
	addr.sin_port = fs_htons(8484);

	result = fs_connect(fd, &addr, sizeof(addr));
	if (result < 0) {
		EXIT_FROM_ERRNO("Failed to connect socket", result);
	}

	int flags = 1;
	result = fs_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
	if (result < 0) {
		EXIT_FROM_ERRNO("Failed to disable nagle on socket", result);
	}
#endif
	state.read_mutex = (struct fs_mutex){ 0 };
	state.write_mutex = (struct fs_mutex){ 0 };

	hello_message hello = { 0 };
	hello.target_platform = TARGET_PLATFORM_CURRENT;
	hello.process_data = process_data;
	state.sockfd = fd;
	hello.state = &state;
#ifdef __MINGW32__
	hello.windows.LoadLibraryA = (intptr_t)&LoadLibraryA;
	hello.windows.GetModuleHandleA = (intptr_t)&GetModuleHandleA;
	hello.windows.GetProcAddress = (intptr_t)&GetProcAddress;
#endif
	result = fs_send(fd, (const char *)&hello, sizeof(hello), 0);
	if (result < 0) {
		EXIT_FROM_ERRNO("Failed to write startup message", result);
	}

	process_data();
#ifndef __linux__
	return 0;
#endif
}

noreturn static void process_data(void)
{
	char buf[512 * 1024];
	int sockfd_local = state.sockfd;
	for (;;) {
		// read header
		union {
			char buf[sizeof(request_message)];
			request_message message;
		} request;
		uint32_t bytes_read = 0;
		fs_mutex_lock(&state.read_mutex);
		do {
			int result = fs_recv(sockfd_local, &request.buf[bytes_read], sizeof(request.buf) - bytes_read, 0);
			if (result <= 0) {
				if (fs_is_eintr(result)) {
					continue;
				}
				if (result == 0) {
					fs_exit(0);
				}
				EXIT_FROM_ERRNO("Failed to read from socket", result);
			}
			bytes_read += result;
		} while(bytes_read != sizeof(request));
		// interpret request
		response_message response;
		struct iovec vec[7];
		vec[0].iov_base = &response;
		vec[0].iov_len = sizeof(response);
		size_t io_count = 1;
		switch (request.message.template.nr) {
			case TARGET_NR_PEEK:
				// peek at local memory, writing the current data to the socket
				fs_mutex_unlock(&state.read_mutex);
				vec[io_count].iov_base = (void *)request.message.values[0];
				vec[io_count].iov_len = request.message.values[1];
				io_count++;
				response.result = 0;
				break;
			case TARGET_NR_POKE: {
				// poke at local memory, reading the new data from the socket
				bytes_read = 0;
				char *addr = (char *)request.message.values[0];
				size_t trailer_bytes = request.message.values[1];
				while (trailer_bytes != bytes_read) {
					int result = fs_recv(sockfd_local, addr + bytes_read, trailer_bytes - bytes_read, 0);
					if (result <= 0) {
						if (fs_is_eintr(result)) {
							continue;
						}
						if (result == 0) {
							fs_exit(0);
						}
						EXIT_FROM_ERRNO("Failed to read from socket", result);
					}
					bytes_read += result;
				}
				fs_mutex_unlock(&state.read_mutex);
				break;
			}
			default: {
				size_t trailer_bytes = 0;
				intptr_t index = 0;
				uint64_t values[PROXY_ARGUMENT_COUNT];
				for (int i = 0; i < PROXY_ARGUMENT_COUNT; i++) {
					if (request.message.template.is_in & (1 << i)) {
						trailer_bytes += request.message.values[i];
						if (request.message.template.is_out & (1 << i)) {
							vec[io_count].iov_base = &buf[index];
							vec[io_count].iov_len = request.message.values[i];
							io_count++;
						}
						values[i] = (intptr_t)&buf[index];
						index += request.message.values[i];
					} else if (request.message.template.is_out & (1 << i)) {
					} else {
						values[i] = request.message.values[i];
					}
				}
				for (int i = 0; i < PROXY_ARGUMENT_COUNT; i++) {
					if (request.message.template.is_in & (1 << i)) {
						if (request.message.template.is_out & (1 << i)) {
						}
					} else if (request.message.template.is_out & (1 << i)) {
						vec[io_count].iov_base = &buf[index];
						vec[io_count].iov_len = request.message.values[i];
						io_count++;
						values[i] = (intptr_t)&buf[index];
						index += request.message.values[i];
					}
				}
				// read trailer
				bytes_read = 0;
				while (trailer_bytes != bytes_read) {
					int result = fs_recv(sockfd_local, &buf[bytes_read], sizeof(buf) - bytes_read, 0);
					if (result <= 0) {
						if (fs_is_eintr(result)) {
							continue;
						}
						if (result == 0) {
							fs_exit(0);
						}
						EXIT_FROM_ERRNO("Failed to read from socket", result);
					}
					bytes_read += result;
				}
				fs_mutex_unlock(&state.read_mutex);
				// perform syscall
				int syscall = request.message.template.nr & ~TARGET_NO_RESPONSE;
				if (syscall == TARGET_NR_CALL) {
					intptr_t (*target)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t) = (void *)values[0];
					response.result = target(values[1], values[2], values[3], values[4], values[5]);
#ifdef __MINGW32__
				} else if (syscall == TARGET_NR_WIN32_CALL) {
					intptr_t (*target)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t) = (void *)values[0];
					intptr_t result = target(values[1], values[2], values[3], values[4], values[5]);
					response.result = result < 0 ? -(intptr_t)GetLastError() : result;
				} else if (syscall == TARGET_NR_WIN32_BOOL_CALL) {
					BOOL (*target)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t) = (void *)values[0];
					intptr_t result = target(values[1], values[2], values[3], values[4], values[5]);
					response.result = result == 0 ? -(intptr_t)GetLastError() : 0;
#endif
#ifdef __NR_clone
				} else if (syscall == __NR_clone) {
					response.result = fs_clone(values[0], (void *)values[1], (void *)values[2], (void *)values[3], (void *)values[4], (void *)values[5]);
#endif
				} else {
#ifdef __APPLE__
					syscall |= DARWIN_SYSCALL_BASE;
#endif
#ifndef __MINGW32__
					response.result = FS_SYSCALL(syscall, values[0], values[1], values[2], values[3], values[4], values[5]);
#else
					response.result = -1;
#endif
				}
				break;
			}
		}
		if ((request.message.template.nr & TARGET_NO_RESPONSE) == 0) {
			// write result
			response.id = request.message.id;
			size_t io_start = 0;
			fs_mutex_lock(&state.write_mutex);
			for (;;) {
#ifdef SYS_writev
				intptr_t result = fs_writev(sockfd_local, &vec[io_start], io_count-io_start);
#else
				intptr_t result = fs_send(sockfd_local, vec[io_start].iov_base, vec[io_start].iov_len, 0);
#endif
				if (result <= 0) {
					if (fs_is_eintr(result)) {
						continue;
					}
					if (result == 0) {
						fs_exit(0);
					}
					EXIT_FROM_ERRNO("Failed to write to socket", result);
				}
				while ((uintptr_t)result >= vec[io_start].iov_len) {
					result -= vec[io_start].iov_len;
					if (++io_start == io_count) {
						goto unlock;
					}
				}
				vec[io_start].iov_base += result;
				vec[io_start].iov_len -= result;
			}
	unlock:
			fs_mutex_unlock(&state.write_mutex);
		}
	}
	__builtin_unreachable();
}
