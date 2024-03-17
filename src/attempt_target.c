#define _GNU_SOURCE
#include "attempt.h"

#include <stdatomic.h>
#include <stdnoreturn.h>
#include <signal.h>
#include <errno.h>

#include "axon.h"
#include "tls.h"

struct attempt {
	struct attempt_cleanup_state *cleanup;
};

// attempt_exit runs all of the cleanups in the current attempt and destroys tls
__attribute__((noinline))
void attempt_exit(struct thread_storage *thread)
{
	struct attempt *attempt = thread->attempt;
	if (attempt != NULL) {
		thread->attempt = NULL;
		struct attempt_cleanup_state *cleanup = attempt->cleanup;
		while (cleanup != NULL) {
			cleanup->body(cleanup->data);
			cleanup = cleanup->next;
		}
	}
}

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

void attempt_pop_cleanup(struct thread_storage *thread, struct attempt_cleanup_state *state)
{
	attempt_pop_and_skip_cleanup(state);
	state->body(state->data, thread);
}
