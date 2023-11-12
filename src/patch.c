#define _GNU_SOURCE

#include "patch.h"

#include "attempt.h"
#include "freestanding.h"
#include "mapped.h"

#include <stdbool.h>
#include <string.h>
#include <errno.h>

uintptr_t find_unused_address(struct thread_storage *thread, uintptr_t address)
{
	address &= -PAGE_SIZE;
	uintptr_t attempt_down = address;
	uintptr_t attempt_up = address;
	// Try lower addresses
	for (;;) {
		attempt_down -= 0x800000;
		attempt_up += 0x800000;
		if (attempt_down >= address && attempt_up <= address) {
			break;
		}
		if (attempt_down < address && attempt_down != 0 && !region_is_mapped(thread, (void *)attempt_down, TRAMPOLINE_REGION_SIZE)) {
			return attempt_down;
		}
		if (attempt_up > address && !region_is_mapped(thread, (void *)attempt_up, TRAMPOLINE_REGION_SIZE)) {
			return attempt_up;
		}
	}
	return 0;
}

#ifdef PATCH_SUPPORTED

bool membarrier_is_supported;

bool patch_syscalls;

struct patch_state_shard {
	// carefully laid out to take exactly one cache line
	struct fs_mutex lock;
	uint8_t next_invalid;
	intptr_t invalid_addresses[7];
};
static struct patch_state_shard patch_state_shards[16];

// pc_is_known_invalid checks if a pc is known to be unpatchable
static bool pc_is_known_invalid(intptr_t pc, const struct patch_state_shard *state_shard)
{
	for (int i = 0; i < 7; i++) {
		if (state_shard->invalid_addresses[i] == pc) {
			return true;
		}
	}
	return false;
}

// make_pc_known_invalid sets a pc as known unpatchable
// because the unpatchable cache allows few entries it's possible that old entries will be evicted
static void make_pc_known_invalid(intptr_t pc, struct patch_state_shard *state_shard)
{
	uint8_t next_invalid = state_shard->next_invalid;
	state_shard->invalid_addresses[next_invalid] = pc;
	next_invalid = next_invalid == 6 ? 0 : next_invalid + 1;
	state_shard->next_invalid = next_invalid;
}

// patch_syscall attempts to patch a syscall instruction and returns the new
// program counter that the syscall should return to
void patch_syscall(struct thread_storage *thread, intptr_t pc, intptr_t sp, intptr_t bp, int self_fd)
{
	if (!patch_syscalls) {
		// ERROR("ignoring syscall patch at", (uintptr_t)pc);
		return;
	}
	// ERROR("patching syscall at", (uintptr_t)pc);
	struct patch_body_args args = {
		.pc = pc,
		.sp = sp,
		.bp = bp,
		.shard = &patch_state_shards[((uintptr_t)pc ^ ((uintptr_t)pc >> 3)) & 0xf],
		.patched = false,
		.self_fd = self_fd,
	};
	if (!pc_is_known_invalid(args.pc, args.shard)) {
		fs_mutex_lock(&args.shard->lock);
		if (!pc_is_known_invalid(args.pc, args.shard)) {
			attempt(thread, (attempt_body)((void *)&patch_body), &args);
			if (args.patched == PATCH_STATUS_FAILED) {
				make_pc_known_invalid(args.pc, args.shard);
			}
		}
		fs_mutex_unlock(&args.shard->lock);
	}
}

void patch_init(bool enable_syscall_patching)
{
	patch_syscalls = enable_syscall_patching;
	if (fs_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0) == 0) {
		membarrier_is_supported = true;
	}
}

#else

// patch_syscall does nothing when patching isn't supported
void patch_syscall(__attribute__((unused)) struct thread_storage *thread, __attribute__((unused)) intptr_t pc, __attribute__((unused)) intptr_t sp)
{
}

// patch_breakpoint does nothing when patching isn't supported
enum patch_status patch_breakpoint(__attribute__((unused)) struct thread_storage *thread, __attribute__((unused)) intptr_t address, __attribute__((unused)) intptr_t entry, __attribute__((unused)) void (*handler)(uintptr_t *))
{
	return PATCH_STATUS_FAILED;
}

void patch_init(__attribute((unused)) bool enable_syscall_patching)
{
}

#endif
