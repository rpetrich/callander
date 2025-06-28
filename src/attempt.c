#define _GNU_SOURCE
#include "attempt.h"

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdnoreturn.h>

#include "axon.h"
#include "tls.h"

// cleanup data contains a cleanup function and the data argument to call it with
struct cleanup_data
{
	attempt_cleanup_body callback;
	void *data;
};

// attempt contains the state necessary to make a non-local return and cleanup
// any partially-used resources
struct attempt
{
	uintptr_t return_address;
	uintptr_t stack_pointer;
	struct attempt *previous;
	struct attempt_cleanup_state *cleanup;
	struct thread_storage *thread;
};

__attribute__((warn_unused_result)) static struct attempt *attempt_exit_current(struct thread_storage *thread)
{
	struct attempt *attempt = thread->attempt;
	if (attempt) {
		thread->attempt = attempt->previous;
		struct attempt_cleanup_state *cleanup = attempt->cleanup;
		while (cleanup != NULL) {
			cleanup->body(cleanup->data);
			cleanup = cleanup->next;
		}
	}
	return attempt;
}

#ifndef __APPLE__

bool attempt_handle_fault(struct thread_storage *thread, ucontext_t *context)
{
	struct attempt *attempt = attempt_exit_current(thread);
	if (attempt) {
		context->uc_mcontext.REG_PC = attempt->return_address;
		context->uc_mcontext.REG_SP = attempt->stack_pointer;
		return true;
	}
	return false;
}

#endif

noreturn void attempt_cancel(struct thread_storage *thread)
{
	struct attempt *attempt = attempt_exit_current(thread);
	JUMP(attempt->return_address, attempt->stack_pointer, 0, 0, 0);
}

// attempt_exit runs all of the cleanups in the current attempt and destroys tls
__attribute__((noinline)) void attempt_exit(struct thread_storage *thread)
{
	struct attempt *attempt = thread->attempt;
	thread->attempt = NULL;
	while (attempt) {
		struct attempt_cleanup_state *cleanup = attempt->cleanup;
		attempt = attempt->previous;
		while (cleanup != NULL) {
			cleanup->body(cleanup->data);
			cleanup = cleanup->next;
		}
	}
}

// attempt_internal is called from the attempt assembly stub. it sets up the
// thread state and calls the body
__attribute__((used, noinline)) static void attempt_internal(attempt_body body, void *data, uintptr_t sp)
{
	struct attempt *attempt = data;
	attempt->return_address = (uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0));
	void *user_data = (void *)attempt->stack_pointer;
	attempt->stack_pointer = sp;
	body(attempt->thread, user_data);
	attempt->thread->attempt = attempt->previous;
	if (UNLIKELY(attempt->cleanup != NULL)) {
		DIE("expected all cleanup functions to be unregistered");
	}
}

#ifndef __clang__
#pragma GCC push_options
#pragma GCC optimize("-fomit-frame-pointer")
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdangling-pointer"
#endif
__attribute__((used)) void attempt(struct thread_storage *thread, attempt_body body, void *data)
{
	struct attempt attempt = {
		.cleanup = NULL,
		.previous = thread->attempt,
		.thread = thread,
		.stack_pointer = (uintptr_t)data,
	};
	thread->attempt = &attempt;
	CALL_SPILLED_WITH_ARGS_AND_SP(attempt_internal, body, &attempt);
}
#ifndef __clang__
#pragma GCC diagnostic pop
#pragma GCC pop_options
#endif

void attempt_push_cleanup(struct thread_storage *thread, struct attempt_cleanup_state *state)
{
	struct attempt *attempt = thread->attempt;
	state->attempt = attempt;
	if (attempt) {
		state->next = attempt->cleanup;
		attempt->cleanup = state;
	}
}

void attempt_pop_and_skip_cleanup(struct attempt_cleanup_state *state)
{
	struct attempt *attempt = state->attempt;
	if (attempt) {
		if (UNLIKELY(attempt->cleanup != state)) {
			DIE("expected to pop the same cleanup function");
		}
		attempt->cleanup = state->next;
	}
}

void attempt_pop_cleanup(struct attempt_cleanup_state *state)
{
	attempt_pop_and_skip_cleanup(state);
	state->body(state->data);
}
