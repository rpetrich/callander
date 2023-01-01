#ifndef TLS_H
#define TLS_H

#include <stdatomic.h>

struct thread_storage;

#include "attempt.h"
#include "handler.h"
#include "stack.h"
#include "coverage.h"

struct thread_storage {
	struct stack_data stack;
	struct attempt *attempt;
	struct signal_state signals;
	struct coverage_data coverage;
};

// get_thread_storage gets the thread local storage for the current thread
struct thread_storage *get_thread_storage(void);

// clean_thread_storage clears the thread local storage for the current thread
// caller is expected to store 0 to the returned intptr_t and immediately exit
// the thread since its stack may be yanked from under it
atomic_intptr_t *clear_thread_storage(void);

// became_multithreaded informs tls that it is now multithreaded
void became_multithreaded(void);

#endif
