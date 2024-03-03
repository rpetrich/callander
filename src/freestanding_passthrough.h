#ifndef FREESTANDING_PASSTHROUGH_H
#define FREESTANDING_PASSTHROUGH_H

#ifdef __MINGW32__
#include <stdlib.h>
#include <winsock2.h>
#include <synchapi.h>

struct fs_mutex {
	// needs manual padding to avoid false sharing
	atomic_int state;
};

__attribute__((warn_unused_result))
__attribute__((nonnull(1)))
static inline int fs_cmpxchg(atomic_int *state, int expected, int desired)
{
	atomic_compare_exchange_strong(state, &expected, desired);
	return expected;
}

#ifdef FS_INLINE_MUTEX_SLOW_PATH
__attribute__((always_inline))
#endif
static inline void fs_mutex_lock_slow_path(struct fs_mutex *mutex, int state)
{
	do {
		if (state == 2 || fs_cmpxchg(&mutex->state, 1, 2) != 0) {
			uint32_t expected = 2;
			WaitOnAddress(&mutex->state, &expected, sizeof(expected), INFINITE);
		}
		state = fs_cmpxchg(&mutex->state, 0, 2);
	} while(state);
}

// fs_mutex_lock acquires the mutex
__attribute__((always_inline))
__attribute__((nonnull(1)))
static inline void fs_mutex_lock(struct fs_mutex *mutex)
{
	int state = fs_cmpxchg(&mutex->state, 0, 1);
	if (__builtin_expect(state, 0)) {
		fs_mutex_lock_slow_path(mutex, state);
	}
}

#ifdef FS_INLINE_MUTEX_SLOW_PATH
__attribute__((always_inline))
#endif
static inline void fs_mutex_unlock_slow_path(struct fs_mutex *mutex)
{
	atomic_store_explicit(&mutex->state, 0, memory_order_relaxed);
	WakeByAddressSingle(&mutex->state);
}

// fs_mutex_lock releases the mutex
__attribute__((always_inline))
__attribute__((nonnull(1)))
static inline void fs_mutex_unlock(struct fs_mutex *mutex)
{
	int state = atomic_fetch_sub(&mutex->state, 1);
	if (__builtin_expect(state != 1, 0)) {
		fs_mutex_unlock_slow_path(mutex);
	}
}

__attribute__((always_inline))
static inline intptr_t fs_adapt_socket_result(intptr_t result)
{
	return result == INVALID_SOCKET ? -WSAGetLastError() : result;
}
#else
static inline intptr_t fs_adapt_socket_result(intptr_t result)
{
	return result == -1 ? -errno : result;
}
#endif

noreturn static inline void fs_exit(int status)
{
	exit(status);
	__builtin_unreachable();
}

__attribute__((warn_unused_result))
static inline int fs_socket(int domain, int type, int protocol)
{
	return fs_adapt_socket_result(socket(domain, type, protocol));
}

__attribute__((warn_unused_result))
static inline int fs_setsockopt(int socket, int level, int option, const void *value, size_t value_len)
{
	return fs_adapt_socket_result(setsockopt(socket, level, option, value, value_len));
}

__attribute__((warn_unused_result))
static inline int fs_connect(int socket, const void *address, size_t address_len)
{
	return fs_adapt_socket_result(connect(socket, address, address_len));
}

static inline intptr_t fs_send(int socket, const char *buffer, size_t length, int flags)
{
	return fs_adapt_socket_result(send(socket, buffer, length, flags));
}

__attribute__((warn_unused_result))
static inline intptr_t fs_recv(int socket, char *buffer, size_t length, int flags)
{
	return fs_adapt_socket_result(recv(socket, buffer, length, flags));
}

#endif
