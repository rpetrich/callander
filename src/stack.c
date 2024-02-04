#define _GNU_SOURCE

#include "stack.h"

#include "attempt.h"
#include "freestanding.h"
#include "axon.h"
#include "mapped.h"
#include "tls.h"

#include <signal.h>

#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
#endif

#ifdef USE_PROGRAM_STACK
static atomic_int stack_size_failure_count;
#endif

#define ALT_STACK_SIZE (PAGE_SIZE * 128)
#define STACK_PROBE_SIZE (ALT_STACK_SIZE * 3 / 4)
#define ALT_STACK_RESERVE (PAGE_SIZE * 16)

#define MAX_STACK_FAILURE_COUNT 16

static inline bool stack_has_sufficient_space(__attribute__((unused)) struct thread_storage *thread)
{
	volatile char result;
#ifdef STACK_DESCENDS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
	return region_is_mapped(thread, ((char *)&result) - STACK_PROBE_SIZE, STACK_PROBE_SIZE);
#pragma GCC diagnostic pop
#else
	return region_is_mapped(thread, ((char *)&result), STACK_PROBE_SIZE);
#endif
}

void call_with_sufficient_stack_body(struct thread_storage *thread, attempt_body callback, void *data)
{
	callback(thread, data);
}

#ifdef WATCH_ALTSTACKS
static inline bool altstack_is_usable(struct stack_data *data)
{
	if (data->altstack.ss_flags & SS_DISABLE) {
		// SA_DISABLE only represents the temporary state if currently on the
		// alternate stack and autodisarming is enabled
		if ((data->altstack.ss_flags & (SS_ONSTACK | SS_AUTODISARM)) != (SS_ONSTACK | SS_AUTODISARM)) {
			return false;
		}
	}
	return data->altstack.ss_size >= (STACK_PROBE_SIZE + ALT_STACK_RESERVE) && data->altstack.ss_sp != NULL;
}
#endif

static inline void *get_allocated_stack(struct stack_data *stack_data)
{
	void *stack = stack_data->allocated_stack;
	if (UNLIKELY(stack == NULL)) {
		// map a new stack and guard
#ifdef MAP_STACK
		stack = fs_mmap(NULL, ALT_STACK_SIZE + PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
#else
		stack = fs_mmap(NULL, ALT_STACK_SIZE + PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#endif
		if (fs_is_map_failed(stack)) {
			DIE("failed to allocate stack", fs_strerror((intptr_t)stack));
		}
		// apply the guard page
#ifdef STACK_DESCENDS
		int result = fs_mprotect(stack, PAGE_SIZE, PROT_NONE);
		stack = (char *)stack + ALT_STACK_SIZE + PAGE_SIZE;
#else
		int result = fs_mprotect((char *)stack + ALT_STACK_SIZE, PROT_NONE);
#endif
		if (result != 0) {
			DIE("failed to protect stack guard", fs_strerror(result));
		}
#if defined(__x86_64__)
		// align the stack
		stack -= 8;
#endif
		stack_data->allocated_stack = stack;
	}
	return stack;
}

__attribute__((used))
void call_on_alternate_stack_body(void *data1, void *data2, alt_callback callback)
{
	callback(data1, data2);
}

#ifndef __clang__
#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
#endif
void call_on_alternate_stack(struct thread_storage *thread, alt_callback callback, void *data1, void *data2)
{
	if (thread->stack.allocated_stack && thread->stack.running) {
		callback(data1, data2);
	}
	void *stack = get_allocated_stack(&thread->stack);
	CALL_ON_ALTERNATE_STACK_WITH_ARG(call_on_alternate_stack_body, data1, data2, callback, stack);
}

void call_with_sufficient_stack(struct thread_storage *thread, attempt_body callback, void *data)
{
	struct stack_data *stack_data = &thread->stack;
	if (stack_data->running) {
		return callback(thread, data);
	}
#ifdef WATCH_ALTSTACKS
	if (altstack_is_usable(stack_data)) {
		// reuse the signal stack, but reserve ALT_STACK_RESERVE for signal handlers in case we fault
		// while handling the signal
#ifdef STACK_DESCENDS
		uintptr_t top_of_stack = (uintptr_t)stack_data->altstack.ss_sp + stack_data->altstack.ss_size - ALT_STACK_RESERVE;
#else
		uintptr_t top_of_stack = (uintptr_t)stack_data->altstack.ss_sp + ALT_STACK_RESERVE;
#endif
		CALL_ON_ALTERNATE_STACK_WITH_ARG(call_with_sufficient_stack_body, thread, callback, data, top_of_stack);
		return;
	}
#endif
#ifdef USE_PROGRAM_STACK
	// try to reuse the current stack by probing, but stop attempting if
	// probing repeatedly fails
	if (atomic_load_explicit(&stack_size_failure_count, memory_order_relaxed) < MAX_STACK_FAILURE_COUNT) {
		if (stack_has_sufficient_space(thread)) {
			callback(thread, data);
			return;
		}
		atomic_fetch_add_explicit(&stack_size_failure_count, 1, memory_order_relaxed);
	}
#endif
	// allocate an alternate stack to call the function on
	void *stack = get_allocated_stack(stack_data);
	stack_data->running = true;
	CALL_ON_ALTERNATE_STACK_WITH_ARG(call_with_sufficient_stack_body, thread, callback, data, stack);
	stack_data->running = false;
}

void attempt_with_sufficient_stack(struct thread_storage *thread, attempt_body callback, void *data)
{
	struct stack_data *stack_data = &thread->stack;
	if (stack_data->running) {
		return attempt(thread, callback, data);
	}
#ifdef WATCH_ALTSTACKS
	if (altstack_is_usable(stack_data)) {
		// reuse the signal stack, but reserve ALTSTACK_RESERVE for signal handlers in case we fault
		// while handling the signal
#ifdef STACK_DESCENDS
		uintptr_t top_of_stack = (uintptr_t)stack_data->altstack.ss_sp + stack_data->altstack.ss_size - ALT_STACK_RESERVE;
#else
		uintptr_t top_of_stack = (uintptr_t)stack_data->altstack.ss_sp + ALT_STACK_RESERVE;
#endif
		stack_data->running = true;
		CALL_ON_ALTERNATE_STACK_WITH_ARG(attempt, thread, callback, data, top_of_stack);
		stack_data->running = false;
		return;
	}
#endif
#ifdef USE_PROGRAM_STACK
	// try to reuse the current stack by probing, but stop attempting if
	// probing repeatedly fails
	if (atomic_load_explicit(&stack_size_failure_count, memory_order_relaxed) < MAX_STACK_FAILURE_COUNT) {
		if (stack_has_sufficient_space(thread)) {
			attempt(thread, callback, data);
			return;
		}
		atomic_fetch_add_explicit(&stack_size_failure_count, 1, memory_order_relaxed);
	}
#endif
	// allocate an alternate stack to call the function on
	void *stack = get_allocated_stack(stack_data);
	stack_data->running = true;
	CALL_ON_ALTERNATE_STACK_WITH_ARG(attempt, thread, callback, data, stack);
	stack_data->running = false;
}
#ifndef __clang__
#pragma GCC pop_options
#endif

void stack_data_clear(struct stack_data *stack)
{
	// don't free the stack, this could lead to attempting to free the stack
	// on the stack itself and instead a new thread that uses this slot should
	// inherit the dead stack
	stack->running = false;
#ifdef WATCH_ALTSTACKS
	stack->altstack = (stack_t) { 0 };
#endif
}

void use_alternate_stacks(void)
{
#ifdef USE_PROGRAM_STACK
	atomic_store_explicit(&stack_size_failure_count, MAX_STACK_FAILURE_COUNT, memory_order_relaxed);
#endif
}
