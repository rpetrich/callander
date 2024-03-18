#ifndef PROXY_H
#define PROXY_H

#include "freestanding.h"
#include "target.h"

#include <stdnoreturn.h>

#ifdef __MINGW32__
struct iovec {
	size_t iov_len;
	void *iov_base;
};
#else
#include "attempt.h"

#include <sys/uio.h>
#endif

#define PROXY_SUPPORT_ALL_PLATFORMS

// PROXY_FD is the connection to the victim target
#define PROXY_FD 0x3fc
#define SHARED_PAGE_FD 0x3fb

#define PROXY_BUFFER_SIZE (256 * 1024)
static inline void trim_size(size_t *size)
{
	if (*size >= PROXY_BUFFER_SIZE) {
		*size = PROXY_BUFFER_SIZE;
	}
}

#define PROXY_ARGUMENT_INPUT ((intptr_t)1 << (sizeof(intptr_t)*8-1))
#define PROXY_ARGUMENT_OUTPUT ((intptr_t)1 << (sizeof(intptr_t)*8-2))
#define PROXY_ARGUMENT_MASK (PROXY_ARGUMENT_INPUT | PROXY_ARGUMENT_OUTPUT)

#define PROXY_NO_RESPONSE TARGET_NO_RESPONSE

#define PROXY_NO_WORKER (1 << 31)
#define PROXY_WORKER_STACK_SIZE (2 * 1024 * 1024)

#define PROXY_ARGUMENT_COUNT 6

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
static inline proxy_arg proxy_wide_string(const uint16_t *address)
{
	if (address == NULL) {
		return (proxy_arg){
			.value = 0,
			.size = 0,
		};
	}
	const uint16_t *current = address;
	while (*current) {
		++current;
	}
	return (proxy_arg){
		.value = (intptr_t)address,
		.size = (sizeof(uint16_t) * (size_t)(current - address + 1)) | PROXY_ARGUMENT_INPUT,
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

__attribute__((always_inline))
static inline int proxy_fill_request_message(request_message *request, struct iovec iov[PROXY_ARGUMENT_COUNT], int syscall, proxy_arg args[PROXY_ARGUMENT_COUNT])
{
	request->template.nr = syscall;
	request->template.is_in = 0;
	request->template.is_out = 0;
	int vec_index = 0;
	for (int i = 0; i < PROXY_ARGUMENT_COUNT; i++) {
		intptr_t value = args[i].value;
		intptr_t size = args[i].size;
		if (value && size) {
			intptr_t masked_size = size & ~PROXY_ARGUMENT_MASK;
			request->values[i] = masked_size;
			if (size & PROXY_ARGUMENT_INPUT) {
				request->template.is_in |= 1 << i;
				iov[vec_index].iov_base = (void *)value;
				iov[vec_index].iov_len = masked_size;
				vec_index++;
			}
			if (size & PROXY_ARGUMENT_OUTPUT) {
				request->template.is_out |= 1 << i;
			}
		} else {
			request->values[i] = value;
		}
	}
	return vec_index;
}

intptr_t proxy_call(int syscall, proxy_arg args[PROXY_ARGUMENT_COUNT]);

#ifdef PROXY_SUPPORT_ALL_PLATFORMS
enum target_platform proxy_get_target_platform(void);
#else
__attribute__((always_inline))
static inline enum target_platform proxy_get_target_platform(void) {
	return TARGET_PLATFORM_LINUX;
}
#endif

hello_message *proxy_get_hello_message(void);

#define PROXY_ARGS_(_1, _2, _3, _4, _5, N, ...) N
#define PROXY_ARGS(...) (proxy_arg[PROXY_ARGUMENT_COUNT]){ \
	PROXY_ARGS_(0, 0, 0, 0, 0, ##__VA_ARGS__, proxy_value(0)), \
	PROXY_ARGS_(0, 0, 0, 0, ##__VA_ARGS__, proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(0, 0, 0, ##__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(0, 0, ##__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(0, ##__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0)), \
	PROXY_ARGS_(__VA_ARGS__, proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(0)) \
}
#define PROXY_CALL(syscall, ...) proxy_call(syscall, PROXY_ARGS(__VA_ARGS__))
#if 1
#define _PROXY_STR(x) _PROXY_STR2(x)
#define _PROXY_STR2(x) #x
#define PROXY_LINUX_CALL(...) ({ \
	if (proxy_get_target_platform() != TARGET_PLATFORM_LINUX) { \
		DIE("attempt to call linux-only syscall directly at " __FILE__ ":"_PROXY_STR(__LINE__), __func__); \
	} \
	PROXY_CALL(__VA_ARGS__); \
})
#else
#define PROXY_LINUX_CALL(...) ((proxy_get_target_platform() != TARGET_PLATFORM_LINUX) ? (intptr_t)-ENOSYS : PROXY_CALL(__VA_ARGS__))
#endif


__attribute__((warn_unused_result))
intptr_t proxy_peek(intptr_t addr, size_t size, void *out_buffer);
__attribute__((warn_unused_result))
ssize_t proxy_peek_string(intptr_t addr, size_t buffer_size, void *out_buffer);
__attribute__((warn_unused_result))
intptr_t proxy_poke(intptr_t addr, size_t size, const void *buffer);

intptr_t proxy_alloc(size_t size);
void proxy_free(intptr_t mem, size_t size);

uint32_t proxy_generate_stream_id(void);
intptr_t proxy_read_stream_message_start(uint32_t stream_id, request_message *message, const bool *cancellation);
int proxy_read_stream_message_body(uint32_t stream_id, void *buffer, size_t size);
void proxy_read_stream_message_finish(uint32_t stream_id);

void install_proxy(int fd);
void proxy_spawn_worker(void);

struct fd_state {
	int count;
	struct windows_state {
		void *dir_handle;
	} windows;
};

struct fd_state *get_fd_states(void);

struct resolver_config_cache;
struct resolver_config_cache *get_resolver_config_cache(void);

#ifndef __MINGW32__

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

#endif

noreturn void unknown_target(void);

#endif
