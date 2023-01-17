#define _GNU_SOURCE
#include "proxy_target.h"
#include "proxy.h"

#include "axon.h"

__attribute__((visibility("default")))
struct proxy_target_state proxy_state;

intptr_t proxy_send(int syscall, proxy_arg args[6])
{
	(void)syscall;
	(void)args;
	return 0;
}

intptr_t proxy_wait(intptr_t send_id, proxy_arg args[6])
{
	(void)send_id;
	(void)args;
	return -ENOSYS;
}

intptr_t proxy_call(int syscall, proxy_arg args[6])
{
	intptr_t send_id = proxy_send(syscall, args);
	if (syscall & TARGET_NO_RESPONSE) {
		return 0;
	}
	return proxy_wait(send_id, args);
}

void proxy_peek(intptr_t addr, size_t size, void *out_buffer)
{
	(void)addr;
	(void)size;
	(void)out_buffer;
	DIE("proxy_peek is not supported");
}

void proxy_poke(intptr_t addr, size_t size, const void *buffer)
{
	(void)addr;
	(void)size;
	(void)buffer;
	DIE("proxy_poke is not supported");
}

intptr_t proxy_alloc(size_t size)
{
	if (size == 0) {
		return 0;
	}
	DIE("proxy_alloc is not supported");
	return 0;
}

void proxy_free(intptr_t addr, size_t size)
{
	if (addr == 0) {
		return;
	}
	(void)size;
}


int *get_fd_counts(void)
{
	return &proxy_state.fd_counts[0];
}
