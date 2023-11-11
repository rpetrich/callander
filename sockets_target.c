#include "sockets.h"

bool decode_remote_addr(union copied_sockaddr *u, size_t *size)
{
	return !decode_target_addr(u, size);
}
