#ifndef ATTEMPT_H
#define ATTEMPT_H

#include "freestanding.h"

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

struct attempt;
struct thread_storage;

// attempt_handle_fault handles an address fault
__attribute__((warn_unused_result))
bool attempt_handle_fault(struct thread_storage *thread, ucontext_t *context);

// attempt_cancel makes a non-local return out of the current attempt, running any cleanup functions
void attempt_cancel(struct thread_storage *thread);

// attempt_exit runs all of the cleanups in the current attempt with the expectation that the thread
// will exit
void attempt_exit(struct thread_storage *thread);

typedef void (*attempt_body)(struct thread_storage *thread, void *data);

// attempt calls the body function and early exits if it faults, running any cleanup functions
void attempt(struct thread_storage *thread, attempt_body body, void *data);

typedef void (*attempt_cleanup_body)(void *data);
struct attempt_cleanup_state {
	attempt_cleanup_body body;
	void *data;
	struct attempt_cleanup_state *next;
	struct attempt *attempt;
};

// attempt_push_cleanup pushes a cleanup function that is called during faults
void attempt_push_cleanup(struct thread_storage *thread, struct attempt_cleanup_state *state);

// attempt_pop_cleanup pops a previously pushed cleanup function
void attempt_pop_cleanup(struct attempt_cleanup_state *state);

// attempt_pop_and_skip_cleanup pops a previously pushed cleanup function, but does not call it
void attempt_pop_and_skip_cleanup(struct attempt_cleanup_state *state);

// attempt_mutex_lock locks a mutex, automatically cleaning up if the attempt fails
static inline void attempt_lock_and_push_mutex(struct thread_storage *thread, struct attempt_cleanup_state *state, struct fs_mutex *mutex)
{
	fs_mutex_lock(mutex);
	state->body = (attempt_cleanup_body)&fs_mutex_unlock;
	state->data = mutex;
	attempt_push_cleanup(thread, state);
}

// attempt_unlock_and_pop_mutex unlocks the mutex and cancels the automatic cleanup
static inline void attempt_unlock_and_pop_mutex(struct attempt_cleanup_state *state, struct fs_mutex *mutex)
{
	attempt_pop_and_skip_cleanup(state);
	fs_mutex_unlock(mutex);
}

// attempt_push_free sets up a pointer to be freed if the attempt fails
static inline void attempt_push_free(struct thread_storage *thread, struct attempt_cleanup_state *state, void *ptr) {
	state->body = (attempt_cleanup_body)&free;
	state->data = ptr;
	attempt_push_cleanup(thread, state);
}

// attempt_pop_free frees the pointer and cancels the automatic cleanup
static inline void attempt_pop_free(struct attempt_cleanup_state *state) {
	attempt_pop_and_skip_cleanup(state);
	free(state->data);
}

// attempt_push_close sets up a fd to be closed if the attempt fails
static inline void attempt_push_close(struct thread_storage *thread, struct attempt_cleanup_state *state, int fd) {
	state->body = (attempt_cleanup_body)(void *)&fs_close;
	state->data = (void *)(intptr_t)fd;
	attempt_push_cleanup(thread, state);
}

// attempt_pop_free closes the fd and cancels the automatic cleanup
static inline void attempt_pop_close(struct attempt_cleanup_state *state) {
	attempt_pop_and_skip_cleanup(state);
	fs_close((intptr_t)state->data);
}

#endif
