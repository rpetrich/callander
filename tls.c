#define _GNU_SOURCE
#include "tls.h"

#include <stdatomic.h>
#include <signal.h>
#include <errno.h>

#include "defaultlibs.h"
#include "axon.h"

#define THREAD_DATA_COUNT 64 // must be power of two

// thread_data stores the bookkeeping for the TLS linked list as well as the
// actual data itself
__attribute__((aligned(64))) struct thread_data {
	size_t zero1;
	atomic_intptr_t id;
	size_t zero2;
	struct thread_data *next;
	size_t zero3;
	struct thread_storage storage;
	size_t zero4;
};
static struct thread_data threads[THREAD_DATA_COUNT];

#if defined(__x86_64__)
static bool is_multithreaded;
#endif

// read_thread_id returns an identifier unique to the current thread
__attribute__((warn_unused_result))
static inline intptr_t read_thread_id(void)
{
#if defined(__x86_64__)
	if (!is_multithreaded) {
		return 0;
	}
#endif
	return (intptr_t)read_thread_register();
}

// preferred_thread_slot calculates a preferred slot index that will be be first
// attempted before probing to another slot
__attribute__((warn_unused_result))
static inline struct thread_data *preferred_thread_slot(intptr_t thread_id)
{
	if ((uintptr_t)thread_id > (uintptr_t)0x1000) {
		thread_id = (((thread_id >> 4) ^ (thread_id >> 8)));
	}
	return &threads[thread_id & (THREAD_DATA_COUNT - 1)];
}

struct thread_storage *get_thread_storage(void)
{
	intptr_t thread_id = read_thread_id();
	struct thread_data *thread = preferred_thread_slot(thread_id);
	struct thread_data *empty = NULL;
	intptr_t assigned_thread_id = atomic_load_explicit(&thread->id, memory_order_acquire);
	while (assigned_thread_id != thread_id) {
		if ((thread->zero1 | thread->zero2 | thread->zero3 | thread->zero4) != 0) {
			DIE("expected zero padding was not zero");
		}
		if (UNLIKELY(assigned_thread_id == 0)) {
			if (empty == NULL) {
				empty = thread;
			}
		}
		struct thread_data *next = atomic_load_explicit(&thread->next, memory_order_acquire);
		if (UNLIKELY(next == NULL)) {
			// try to use an existing empty slot
			if (empty) {
				assigned_thread_id = 0;
				if (atomic_compare_exchange_strong(&empty->id, &assigned_thread_id, thread_id)) {
					thread = empty;
					break;
				}
			}
			// failed to use an empty slot, allocate a new one
			struct thread_data *new_thread = fs_mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FILE, SELF_FD, 0);
			new_thread->id = thread_id;
			new_thread->zero1 = 0;
			new_thread->zero2 = 0;
			new_thread->zero3 = 0;
			new_thread->zero4 = 0;
			new_thread->next = NULL;
			new_thread->storage = (struct thread_storage) { 0 };
			// add to the end of the list
			while (!atomic_compare_exchange_strong_explicit(&thread->next, &next, new_thread, memory_order_seq_cst, memory_order_seq_cst)) {
				thread = next;
				next = NULL;
			}
			thread = new_thread;
			break;
		}
		// try the next slot
		thread = next;
		assigned_thread_id = atomic_load_explicit(&thread->id, memory_order_acquire);
	}
	// return the storage in the slot
	return &thread->storage;
}

atomic_intptr_t *clear_thread_storage(void)
{
	intptr_t thread_id = read_thread_id();
	struct thread_data *thread = preferred_thread_slot(thread_id);
	do {
		if (atomic_load_explicit(&thread->id, memory_order_acquire) == thread_id) {
			thread->storage.attempt = NULL;
			thread->storage.signals = (struct signal_state) { 0 };
#ifdef COVERAGE
			thread->storage.coverage = (struct coverage_data) { 0 };
#endif
			stack_data_clear(&thread->storage.stack);
			return &thread->id;
		}
	} while((thread = atomic_load_explicit(&thread->next, memory_order_acquire)));
	static atomic_intptr_t dummy;
	return &dummy;
}

#if defined(__x86_64__)
void became_multithreaded(void)
{
	is_multithreaded = true;
}
#endif
