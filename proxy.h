#ifndef PROXY_H
#define PROXY_H

#include "target.h"

#include "attempt.h"
#include "freestanding.h"

#include <stdnoreturn.h>
#include <sys/uio.h>

// PROXY_FD is the connection to the victim target
#define PROXY_FD 0x3fc
#define SHARED_PAGE_FD 0x3fb

#define PROXY_ARGUMENT_INPUT ((intptr_t)1 << (sizeof(intptr_t)*8-1))
#define PROXY_ARGUMENT_OUTPUT ((intptr_t)1 << (sizeof(intptr_t)*8-2))
#define PROXY_ARGUMENT_MASK (PROXY_ARGUMENT_INPUT | PROXY_ARGUMENT_OUTPUT)

#define PROXY_NO_RESPONSE TARGET_NO_RESPONSE

#define PROXY_NO_WORKER (1 << 31)

typedef struct {
	intptr_t value;
	intptr_t size;
} proxy_arg;

__attribute__((always_inline))
static inline proxy_arg proxy_value(intptr_t value) {
	return (proxy_arg){
		.value = value,
		.size = 0,
	};
}

__attribute__((always_inline))
static inline proxy_arg proxy_in(const void *address, size_t size) {
	return (proxy_arg){
		.value = (intptr_t)address,
		.size = (size & ~PROXY_ARGUMENT_MASK) | PROXY_ARGUMENT_INPUT,
	};
}

__attribute__((always_inline))
static inline proxy_arg proxy_string(const char *address) {
	if (address == NULL) {
		return (proxy_arg){
			.value = 0,
			.size = 0,
		};
	}
	return (proxy_arg){
		.value = (intptr_t)address,
		.size = (fs_strlen(address) + 1) | PROXY_ARGUMENT_INPUT,
	};
}

__attribute__((always_inline))
static inline proxy_arg proxy_out(void *address, size_t size) {
	return (proxy_arg){
		.value = (intptr_t)address,
		.size = (size & ~PROXY_ARGUMENT_MASK) | PROXY_ARGUMENT_OUTPUT,
	};
}

__attribute__((always_inline))
static inline proxy_arg proxy_inout(void *address, size_t size) {
	return (proxy_arg){
		.value = (intptr_t)address,
		.size = size | (PROXY_ARGUMENT_INPUT | PROXY_ARGUMENT_OUTPUT),
	};
}

intptr_t proxy_call(int syscall, proxy_arg args[6]);
intptr_t proxy_send(int syscall, proxy_arg args[6]);
intptr_t proxy_wait(intptr_t send_id, proxy_arg args[6]);

#ifdef PROXY_SUPPORT_DARWIN
enum target_platform proxy_get_target_platform(void);
#else
__attribute__((always_inline))
static inline enum target_platform proxy_get_target_platform(void) {
	return TARGET_PLATFORM_LINUX;
}
#endif

#define PROXY_ARGS_(_1, _2, _3, _4, _5, N, ...) N
#define PROXY_ARGS(...) (proxy_arg[6]){ \
	PROXY_ARGS_(0, 0, 0, 0, 0, ##__VA_ARGS__, proxy_value(0)), \
	PROXY_ARGS_(0, 0, 0, 0, ##__VA_ARGS__, proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(0, 0, 0, ##__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(0, 0, ##__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(0, ##__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0)) \
}
#define PROXY_CALL(syscall, ...) proxy_call(syscall, PROXY_ARGS(__VA_ARGS__))
#define PROXY_SEND(syscall, ...) proxy_send(syscall, PROXY_ARGS(__VA_ARGS__))
#define PROXY_WAIT(send_id, ...) proxy_wait(send_id, PROXY_ARGS(__VA_ARGS__))

void proxy_peek(intptr_t addr, size_t size, void *out_buffer);
size_t proxy_peek_string(intptr_t addr, size_t buffer_size, void *out_buffer);
void proxy_poke(intptr_t addr, size_t size, const void *buffer);

intptr_t proxy_alloc(size_t size);
void proxy_free(intptr_t mem, size_t size);

void install_proxy(int fd);

int *get_fd_counts(void);

struct resolver_config_cache;
struct resolver_config_cache *get_resolver_config_cache(void);

typedef struct {
	struct attempt_cleanup_state cleanup_state;
	intptr_t addr;
	size_t size;
} attempt_proxy_alloc_state;

static inline void attempt_proxy_cleanup(void *data) {
	const attempt_proxy_alloc_state *state = data;
	proxy_free(state->addr, state->size);
}

static inline void attempt_proxy_alloc(size_t size, struct thread_storage *thread, attempt_proxy_alloc_state *out_state) {
	out_state->cleanup_state.body = attempt_proxy_cleanup;
	out_state->cleanup_state.data = out_state;
	out_state->size = size;
	out_state->addr = proxy_alloc(size);
	attempt_push_cleanup(thread, &out_state->cleanup_state);
}

// attempt_pop_proxy_free frees the remote pointer and cancels the automatic cleanup
static inline void attempt_proxy_free(attempt_proxy_alloc_state *state) {
	attempt_pop_and_skip_cleanup(&state->cleanup_state);
	proxy_free(state->addr, state->size);
}

noreturn void unknown_target(void);

#endif
