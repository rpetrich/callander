#include "resolver.h"

#include "axon.h"

#include "loader.h"

#include <stdlib.h>

AXON_BOOTSTRAP_ASM

static intptr_t my_openat(int fd, const char *path, int flags, mode_t mode)
{
	return fs_openat(fd, path, flags, mode);
}

static void my_close(int fd)
{
	(void)fs_close(fd);
}

static intptr_t my_socket(int domain, int type, int protocol)
{
	return fs_socket(domain, type, protocol);
}

static intptr_t my_recvfrom(int fd, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	return FS_SYSCALL(__NR_recvfrom, fd, (intptr_t)buf, bufsz, flags, (intptr_t)src_addr, (intptr_t)addrlen);
}

static intptr_t my_sendto(int fd, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
	return FS_SYSCALL(__NR_sendto, fd, (intptr_t)buf, bufsz, flags, (intptr_t)dest_addr, (intptr_t)dest_len);
}

#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
__attribute__((noinline, visibility("hidden")))
int main(int argc, char* argv[], char* envp[])
{
	struct resolver_config_cache cache = { 0 };
	for (int i = 1; argv[i] != NULL; i++) {
		struct addrinfo *results = NULL;
		int local_errno = 0;
		int result = getaddrinfo_custom(argv[i], "http", NULL, (struct resolver_funcs){
			.malloc = malloc,
			.free = free,
			.openat = my_openat,
			.read = fs_read,
			.close = my_close,
			.socket = my_socket,
			.recvfrom = my_recvfrom,
			.sendto = my_sendto,
			.config_cache = &cache,
			.errno_location = &local_errno,
		}, &results);
		switch (result) {
			case 0: {
				while (results != NULL) {
					struct addrinfo *next = results->ai_next;
					switch (results->ai_addr->sa_family) {
						case AF_INET: {
							struct sockaddr_in *addr = (struct sockaddr_in *)results->ai_addr;
							char buffer[16];
							uint8_t addr_bytes[4];
							memcpy(&addr_bytes, &addr->sin_addr.s_addr, 4);
							int offset = 0;
							offset += fs_utoa(addr_bytes[0], &buffer[offset]);
							buffer[offset++] = '.';
							offset += fs_utoa(addr_bytes[1], &buffer[offset]);
							buffer[offset++] = '.';
							offset += fs_utoa(addr_bytes[2], &buffer[offset]);
							buffer[offset++] = '.';
							offset += fs_utoa(addr_bytes[3], &buffer[offset]);
							ERROR("result", &buffer[0]);
							break;
						}
						case AF_INET6: {
							struct sockaddr_in6 *addr = (struct sockaddr_in6 *)results->ai_addr;
							char buffer[INET6_ADDRSTRLEN];
							int offset = 0;
							for (int j = 0; j < 8; j++) {
								if (j != 0) {
									buffer[offset++] = ':';
								}
								offset += fs_utoah_noprefix(((uintptr_t)addr->sin6_addr.s6_addr[j*2] << 8) | addr->sin6_addr.s6_addr[j*2+1], &buffer[offset]);
							}
							ERROR("result", &buffer[0]);
							break;
						}
						default:
							ERROR("result with unknown address type", (uintptr_t)results->ai_addr->sa_family);
							break;
					}
					free(results->ai_addr);
					free(results);
					results = next;
				}
				break;
			}
			case EAI_NONAME:
				ERROR("no results");
				break;
			case EAI_SYSTEM:
				ERROR("system failure during lookup", fs_strerror(local_errno));
				break;
			default:
				ERROR("unknown error", (uintptr_t)result);
				break;
		}
	}
	return 0;
}
#pragma GCC pop_options
