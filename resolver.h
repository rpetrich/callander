#ifndef RESOLVER_H
#define RESOLVER_H

#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>

struct resolver_config_cache {
	uint32_t address;
};

struct resolver_funcs {
	void *(*malloc)(size_t);
	void (*free)(void *);
	intptr_t (*openat)(int dirfd, const char *path, int flags, mode_t mode);
	intptr_t (*read)(int fd, char *buf, size_t bufsz);
	void (*close)(int fd);
	intptr_t (*socket)(int domain, int type, int protocol);
	intptr_t (*recvfrom)(int fd, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
	intptr_t (*sendto)(int fd, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
	struct resolver_config_cache *config_cache;
	int *errno_location;
};

// getaddrinfo_custom loads addresses over a custom tunneled network
int getaddrinfo_custom(const char *node, const char *service, __attribute__((unused)) const struct addrinfo *hints, struct resolver_funcs funcs, struct addrinfo **res);

static inline uint16_t hton_16(uint16_t value)
{
	return value << 8 | value >> 8;
}

#endif
