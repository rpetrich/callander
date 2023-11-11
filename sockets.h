#ifndef SOCKETS_H
#define SOCKETS_H

#include "freestanding.h"
#include "axon.h"
#include "paths.h"

#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/un.h>

union copied_sockaddr {
	struct sockaddr addr;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	struct sockaddr_un un;
};

static inline bool decode_target_addr(union copied_sockaddr *u, size_t *size)
{
	if (u->addr.sa_family == AF_INET6 && *size >= sizeof(struct sockaddr_in6)) {
		if (u->in6.sin6_scope_id == ~(uint32_t)0) {
			// IPv6 rerouted by scope
			u->in6.sin6_scope_id = 0;
			return true;
		}
		if (u->in6.sin6_addr.s6_addr[0] == 0xff && u->in6.sin6_addr.s6_addr[1] == 0xff) {
			// IPv4 address embedded in IPv6
			struct sockaddr_in in;
			in.sin_family = AF_INET;
			in.sin_addr.s_addr = *(const unsigned long *)&u->in6.sin6_addr.s6_addr[12];
			in.sin_port = u->in6.sin6_port;
			u->in = in;
			*size = sizeof(struct sockaddr_in);
			return true;
		}
	}
	path_info real;
	// TODO: support rewriting of local paths
	if (u->addr.sa_family == AF_UNIX) {
		if (lookup_real_path(AT_FDCWD, u->un.sun_path, &real)) {
			if (real.fd == AT_FDCWD) {
				size_t len = fs_strlen(real.path);
				if (len < 108) {
					fs_memcpy(&u->un.sun_path[0], real.path, len + 1);
				}
				return true;
			}
		}
	}
	return false;
}

bool decode_remote_addr(union copied_sockaddr *u, size_t *size);

#endif
