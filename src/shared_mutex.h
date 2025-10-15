#ifndef SHARED_MUTEX_H
#define SHARED_MUTEX_H

#include <limits.h>
#include <stdatomic.h>

#include "freestanding.h"
#include "axon.h"

struct shared_mutex
{
	atomic_int state;
};

#ifdef FS_INLINE_MUTEX_SLOW_PATH
__attribute__((always_inline))
#endif
__attribute__((nonnull(1))) static inline void
shared_mutex_lock_slow_path(struct shared_mutex *mutex, int state)
{
	do {
		if (state == 2 || fs_cmpxchg(&mutex->state, 1, 2) != 0) {
			fs_futex((int *)&mutex->state, FUTEX_WAIT, 2, NULL);
		}
		state = fs_cmpxchg(&mutex->state, 0, 2);
	} while (state);
}

__attribute__((always_inline)) __attribute__((nonnull(1))) static inline void shared_mutex_lock(struct shared_mutex *mutex)
{
	int state = fs_cmpxchg(&mutex->state, 0, 1);
	if (__builtin_expect(state, 0)) {
		shared_mutex_lock_slow_path(mutex, state);
	}
}

#ifdef FS_INLINE_MUTEX_SLOW_PATH
__attribute__((always_inline))
#endif
__attribute__((nonnull(1))) static inline void
shared_mutex_unlock_slow_path(struct shared_mutex *mutex)
{
	atomic_store_explicit(&mutex->state, 0, memory_order_relaxed);
	fs_futex((int *)&mutex->state, FUTEX_WAKE, 1, NULL);
}

__attribute__((always_inline)) __attribute__((nonnull(1))) static inline void shared_mutex_unlock(struct shared_mutex *mutex)
{
	int state = atomic_fetch_sub(&mutex->state, 1);
	if (__builtin_expect(state != 1, 0)) {
		shared_mutex_unlock_slow_path(mutex);
	}
}

__attribute__((always_inline)) static inline uint32_t shared_mutex_bitset_for_id(uint32_t id)
{
	return 1 << (id & 0x1f);
}

#ifdef FS_INLINE_MUTEX_SLOW_PATH
__attribute__((always_inline))
#endif
static inline bool
shared_mutex_lock_id_slow_path(struct shared_mutex *mutex, uint32_t id, int state, bool interruptable)
{
	do {
		intptr_t result;
		if (state == 2) {
			result = FS_SYSCALL(__NR_futex, (intptr_t)&mutex->state, FUTEX_WAIT_BITSET, 2, 0, 0, shared_mutex_bitset_for_id(id));
		} else if (state == 1) {
			if (fs_cmpxchg(&mutex->state, 1, 2) != 0) {
				result = FS_SYSCALL(__NR_futex, (intptr_t)&mutex->state, FUTEX_WAIT_BITSET, 2, 0, 0, shared_mutex_bitset_for_id(id));
			} else {
				result = 0;
			}
		} else if (state > 2) {
			if (state == (int)((id & ~(1 << 31)) + 3)) {
				atomic_store_explicit(&mutex->state, 2, memory_order_relaxed);
				return true;
			}
			result = FS_SYSCALL(__NR_futex, (intptr_t)&mutex->state, FUTEX_WAIT_BITSET, state, 0, 0, shared_mutex_bitset_for_id(id));
		} else {
			result = 0;
		}
		if (result < 0) {
			switch (result) {
				case -EINTR:
				case -EAGAIN:
					if (interruptable) {
						return false;
					}
					break;
				default:
					DIE("futex wait bitset failed: ", as_errno(result));
			}
		}
		state = fs_cmpxchg(&mutex->state, 0, 2);
	} while (state);
	return true;
}

__attribute__((always_inline)) __attribute__((nonnull(1))) static inline bool shared_mutex_lock_id(struct shared_mutex *mutex, uint32_t id, bool interruptable)
{
	int state = fs_cmpxchg(&mutex->state, 0, 1);
	if (__builtin_expect(state, 0)) {
		return shared_mutex_lock_id_slow_path(mutex, id, state, interruptable);
	} else {
		return true;
	}
}

__attribute__((nonnull(1))) static inline bool shared_mutex_unlock_handoff(struct shared_mutex *mutex, uint32_t id)
{
	int state = atomic_exchange(&mutex->state, (id & ~(1 << 31)) + 3);
	if (state == 1) {
		return false;
	}
	return FS_SYSCALL(__NR_futex, (intptr_t)&mutex->state, FUTEX_WAKE_BITSET, INT_MAX, 0, 0, shared_mutex_bitset_for_id(id)) > 0;
}

#endif
