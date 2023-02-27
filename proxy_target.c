#define _GNU_SOURCE
#include "proxy_target.h"
#include "proxy.h"

#include "axon.h"

__attribute__((visibility("default")))
struct proxy_target_state proxy_state;

struct remote_result_future {
	struct fs_mutex mutex;
	intptr_t result;
	proxy_arg *args;
};

__attribute__((visibility("default")))
void receive_response(struct remote_result_future *response, intptr_t result, void *buffer)
{
	// copy in/out arguments
	for (int i = 0; i < PROXY_ARGUMENT_COUNT; i++) {
		intptr_t value = response->args[i].value;
		intptr_t size = response->args[i].size;
		if ((size & PROXY_ARGUMENT_MASK) == PROXY_ARGUMENT_MASK && value) {
			fs_memcpy((void *)value, buffer, size & ~PROXY_ARGUMENT_MASK);
			buffer += size & ~PROXY_ARGUMENT_MASK;
		}
	}
	// copy out arguments
	for (int i = 0; i < PROXY_ARGUMENT_COUNT; i++) {
		intptr_t value = response->args[i].value;
		intptr_t size = response->args[i].size;
		if ((size & PROXY_ARGUMENT_MASK) == PROXY_ARGUMENT_OUTPUT && value) {
			fs_memcpy((void *)value, buffer, size & ~PROXY_ARGUMENT_MASK);
			buffer += size & ~PROXY_ARGUMENT_MASK;
		}
	}
	// assign response
	response->result = result;
	// wake up waiting thread
	fs_mutex_unlock(&response->mutex);
}

intptr_t proxy_call(int syscall, proxy_arg args[PROXY_ARGUMENT_COUNT])
{
	// prepare a response future
	struct remote_result_future response = { 0 };
	fs_mutex_lock(&response.mutex);
	response.args = args;
	// prepare a client request
	client_request message;
	if (syscall & TARGET_NO_RESPONSE) {
		message.header.result = 0;
	} else {
		message.header.result = (intptr_t)&response;
	}
	message.header.id = proxy_state.stream_id;
	struct iovec iov[PROXY_ARGUMENT_COUNT+1];
	iov[0].iov_base = &message;
	iov[0].iov_len = sizeof(message);
	// fill the request details
	int arg_vec_count = proxy_fill_request_message(&message.request, &iov[1], syscall, args);
	size_t trailer_bytes = 0;
	for (int i = 0; i < arg_vec_count; i++) {
		trailer_bytes += iov[1+i].iov_len;
	}
	message.request.id = 0;
	// send the request
	fs_mutex_lock(&proxy_state.target_state->write_mutex);
	int result = fs_writev_all(proxy_state.target_state->sockfd, iov, 1 + arg_vec_count);
	if (result <= 0) {
		if (result == -EFAULT) {
			fs_mutex_unlock(&proxy_state.target_state->write_mutex);
			return result;
		}
		DIE("failed to proxy send", fs_strerror(result));
	}
	fs_mutex_unlock(&proxy_state.target_state->write_mutex);
	// exit if no response is expected
	if (syscall & TARGET_NO_RESPONSE) {
		return 0;
	}
	// wait for response
	fs_mutex_lock(&response.mutex);
	return response.result;
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
