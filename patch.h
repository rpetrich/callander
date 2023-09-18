#ifndef PATCH_H
#define PATCH_H

#include "axon.h"

#include <stdbool.h>

#if 0
#define PATCH_LOG ERROR
#else
#define PATCH_LOG(...) do { } while(0)
#endif

enum patch_status {
	PATCH_STATUS_FAILED = 0,
	PATCH_STATUS_INSTALLED_TRAMPOLINE = 1,
	PATCH_STATUS_INSTALLED_ILLEGAL = 2,
};

struct patch_body_args {
	intptr_t pc;
	intptr_t sp;
	intptr_t bp;
	struct patch_state_shard *shard;
	enum patch_status patched;
	int self_fd;
};

struct thread_storage;

// patch_syscall attempts to patch the syscall instruction at pc. it must
// go through great lengths to sanity check to avoid disrupting the program
void patch_syscall(struct thread_storage *thread, intptr_t pc, intptr_t sp, intptr_t bp, int self_fd);

// patch_breakpoint sets a breakpoint at the address specified that calls
// the associated handler when the address is hit
__attribute__((warn_unused_result))
enum patch_status patch_breakpoint(struct thread_storage *thread, intptr_t address, intptr_t entry, void (*handler)(uintptr_t *), int self_fd);

// patch_function patches a function to instead call a handler instead when the
// function would have run. The original behaviour of the function is not called
// and instead a function pointer that will invoke the original behaviour is
// passed to the handler
__attribute__((warn_unused_result))
enum patch_status patch_function(struct thread_storage *thread, intptr_t function, intptr_t (*handler)(uintptr_t *arguments, intptr_t original), int self_fd);

// find_unused_address finds an unmapped page by searching for an unmapped page
uintptr_t find_unused_address(struct thread_storage *thread, uintptr_t address);

void patch_init(bool enable_syscall_patching);

extern bool membarrier_is_supported;

#define TRAMPOLINE_REGION_SIZE PAGE_SIZE

// trampoline_region_has_space checks if the trampoline region has space for at least one more trampoline
static inline bool trampoline_region_has_space(uint8_t *next_trampoline, size_t trampoline_size)
{
	return (((uintptr_t)next_trampoline + trampoline_size) & -TRAMPOLINE_REGION_SIZE) == (((uintptr_t)next_trampoline - 1) & -TRAMPOLINE_REGION_SIZE);
}

#if defined(__x86_64__)
#include "patch_x86_64.h"
#else
#if defined(__aarch64__)
#include "patch_aarch64.h"
#endif
#endif

#endif
