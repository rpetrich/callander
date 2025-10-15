#ifndef PATCH_H
#define PATCH_H

#include "axon.h"
#include "freestanding.h"
#include "ins.h"
#include "mapped.h"

#include <stdbool.h>

#if 0
#define PATCH_LOG ERROR
#else
#define PATCH_LOG(...) \
	do {               \
	} while (0)
#endif

enum patch_status
{
	PATCH_STATUS_FAILED = 0,
	PATCH_STATUS_INSTALLED_TRAMPOLINE = 1,
	PATCH_STATUS_INSTALLED_ILLEGAL = 2,
};

struct patch_body_args
{
	ins_ptr pc;
	intptr_t sp;
	intptr_t bp;
	struct patch_state_shard *shard;
	enum patch_status patched;
	int self_fd;
};

struct thread_storage;

struct instruction_range
{
	ins_ptr start;
	ins_ptr end;
};

// patch_syscall attempts to patch the syscall instruction at pc. it must
// go through great lengths to sanity check to avoid disrupting the program
void patch_syscall(struct thread_storage *thread, ins_ptr pc, intptr_t sp, intptr_t bp, int self_fd);

// patch_breakpoint sets a breakpoint at the address specified that calls
// the associated handler when the address is hit
__attribute__((warn_unused_result)) enum patch_status patch_breakpoint(struct thread_storage *thread, ins_ptr address, ins_ptr entry, void (*handler)(uintptr_t *), int self_fd);

// patch_function patches a function to instead call a handler instead when the
// function would have run. The original behaviour of the function is not called
// and instead a function pointer that will invoke the original behaviour is
// passed to the handler
__attribute__((warn_unused_result)) enum patch_status patch_function(struct thread_storage *thread, ins_ptr function, intptr_t (*handler)(uintptr_t *arguments, intptr_t original), int self_fd);

// find_unused_address finds an unmapped page by searching for an unmapped page
uintptr_t find_unused_address(struct thread_storage *thread, uintptr_t address);

void patch_init(bool enable_syscall_patching);

void patch_memory_map_changed(void *start, size_t length);
__attribute__((warn_unused_result)) int patch_cached_mapping_for_address(const void *address, struct mapping *out_mapping);

#ifdef SYS_membarrier
#ifdef __x86_64__
extern bool membarrier_is_supported;
#endif
#endif

#define TRAMPOLINE_REGION_SIZE PAGE_SIZE

// trampoline_region_has_space checks if the trampoline region has space for at least one more trampoline
static inline bool trampoline_region_has_space(uint8_t *next_trampoline, size_t trampoline_size)
{
	return (((uintptr_t)next_trampoline + trampoline_size) & -TRAMPOLINE_REGION_SIZE) == (((uintptr_t)next_trampoline - 1) & -TRAMPOLINE_REGION_SIZE);
}

struct patch_template
{
	void *start;
	void *entry;
	void *data;
	void *end;
};

#if defined(__x86_64__)
#include "patch_x86_64.h"
#else
#if defined(__aarch64__)
#include "patch_aarch64.h"
#endif
#endif

#ifdef PATCH_EXPOSE_INTERNALS

#define PATCH_TEMPLATE(name)         \
	({                               \
		void name##_start();         \
		void name##_entry();         \
		void name##_data();          \
		void name##_end();           \
		(struct patch_template){     \
			.start = &name##_start,  \
			.entry = &name##_entry,  \
			.data = &name##_data,    \
			.end = &name##_end,      \
		};                           \
	})

void patch_write_pc_relative_jump(ins_ptr buf, intptr_t relative_jump);

#endif

#endif
