#ifndef STACK_H
#define STACK_H

#include <signal.h>
#include <stdbool.h>

struct stack_data
{
#ifdef WATCH_ALTSTACKS
	stack_t altstack;
#endif
	void *allocated_stack;
	bool running;
};

#include "attempt.h"

// call_with_sufficient_stack calls the function on a stack with sufficient
// stack space
extern void call_with_sufficient_stack(struct thread_storage *thread, attempt_body callback, void *data);

// attempt_call_with_sufficient_stack calls the function on a stack with
// sufficient stack space and exits cleanly if the function excepts
extern void attempt_with_sufficient_stack(struct thread_storage *thread, attempt_body callback, void *data);

typedef void (*alt_callback)(void *data1, void *data2);

// call_on_alternate_stack calls the function on an alternate stack with
// sufficient stack space
extern void call_on_alternate_stack(struct thread_storage *thread, alt_callback callback, void *data1, void *data2);

// stack_data_clear is called when a stack is to be cleared
extern void stack_data_clear(struct stack_data *stack);

// use_alternate_stacks configures alternate stacks to always be used
extern void use_alternate_stacks(void);

#endif
