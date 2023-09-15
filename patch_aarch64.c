#if defined(__aarch64__)

#include "patch_aarch64.h"

#include "attempt.h"
#include "freestanding.h"
#include "axon.h"
#include "handler.h"
#include "mapped.h"
#include "stack.h"

#include <string.h>
#include <errno.h>

__asm__(
".text\n"
".global trampoline_call_handler_start\n"
".hidden trampoline_call_handler_start\n"
".type trampoline_call_handler_start,@function\n"
"trampoline_call_handler_start:\n"
"	stp x9, x10, [sp, #-0x90]!\n"
"	stp x11, x12, [sp, #-0x10]!\n"
"	stp x13, x14, [sp, #-0x10]!\n"
"	stp x15, lr, [sp, #-0x10]!\n"
"	mrs x9, nzcv\n"
"	stp x7, x9, [sp, #-0x10]!\n"
"	stp x8, x6, [sp, #-0x10]!\n"
"	stp x4, x5, [sp, #-0x10]!\n"
"	stp x2, x3, [sp, #-0x10]!\n"
"	stp x0, x1, [sp, #-0x10]!\n"
"	ldr x7, trampoline_call_handler_end\n"
"	mov x0, sp\n"
"	blr x7\n"
"	ldp x0, x1, [sp], #0x10\n"
"	ldp x2, x3, [sp], #0x10\n"
"	ldp x4, x5, [sp], #0x10\n"
"	ldp x8, x6, [sp], #0x10\n"
"	ldp x7, x9, [sp], #0x10\n"
"	msr nzcv, x9\n"
"	ldp x15, lr, [sp], #0x10\n"
"	ldp x13, x14, [sp], #0x10\n"
"	ldp x11, x12, [sp], #0x10\n"
"	ldp x9, x10, [sp], #0x90\n"
"	brk #0\n"
"	brk #0\n"
".global trampoline_call_handler_end\n"
".hidden trampoline_call_handler_end\n"
".type trampoline_call_handler_end,@function\n"
"trampoline_call_handler_end:\n"
);

void trampoline_call_handler_start();
void trampoline_call_handler_end();

#define INS_SVC_0 0xd4000001
#define INS_B_PC_REL 0x14000000

#define LARGEST_TRAMPOLINE (&trampoline_call_handler_end - &trampoline_call_handler_start + sizeof(uintptr_t))

static struct fs_mutex region_lock;
static uint32_t *current_region;

static void trampoline_body(struct thread_storage *thread, intptr_t data[7])
{
	intptr_t arg0 = data[0];
	data[0] = -EFAULT;
	data[0] = handle_syscall(thread, data[6], arg0, data[1], data[2], data[3], data[4], data[5], NULL);
}

// receive_trampoline is called by trampolines to handle the intercepted syscall
static void receive_trampoline(intptr_t data[7]) {
	struct thread_storage *thread = get_thread_storage();
	attempt_with_sufficient_stack(thread, (attempt_body)&trampoline_body, data);
	if (data[0] == -ENOSYS) {
		data[0] = FS_SYSCALL(data[6], data[0], data[1], data[2], data[3], data[4], data[5]);
	}
}

// is_valid_pc_relative_offset verifies that an offset will fit in a 26-bit offset
static bool is_valid_pc_relative_offset(intptr_t offset)
{
	return ((offset << (64 - 26)) >> (64 - 26)) == offset;
}

// destination_of_pc_relative_addr returns the destination address of a pc-relative offset
__attribute__((unused))
static inline intptr_t destination_of_pc_relative_addr(const uint32_t *addr)
{
	uint32_t mask = (1u << 26) - 1;
	int32_t relative = (*addr ^ mask) - mask;
	return (intptr_t)(addr + 1 + relative);
}

// is_syscall_instruction checks if the instruction at address is a syscall
static inline bool is_syscall_instruction(const uint32_t *addr)
{
	return *addr == INS_SVC_0;
}

__attribute__((warn_unused_result))
static bool patch_common(struct thread_storage *thread, uintptr_t instruction, void *handler, bool skip, int self_fd);

// patch_body attempts to patch a syscall instruction already having taken the shard's lock
void patch_body(struct thread_storage *thread, struct patch_body_args *args)
{
	PATCH_LOG("pc", (uintptr_t)args->pc);
	PATCH_LOG("sp", (uintptr_t)args->sp);
	// Check if syscall has been rewritten
	const uint32_t *instruction = (uint32_t *)args->pc - 1;
	if (!is_syscall_instruction(instruction)) {
		PATCH_LOG("not a syscall", (uintptr_t)*instruction);
		return;
	}
	args->patched = patch_common(thread, (uintptr_t)instruction, &receive_trampoline, true, args->self_fd);
}

#define CACHE_LINE_SIZE 64

static void clear_icache(uintptr_t start, uintptr_t end)
{
	start &= -CACHE_LINE_SIZE;
	end = (end + (CACHE_LINE_SIZE - 1)) & -CACHE_LINE_SIZE;
	for (; start < end; start += CACHE_LINE_SIZE) {
		__asm__ __volatile__("ic ivau, %0; dc cvau, %0" : : "r"(start) : "memory");
	}
	__asm__ __volatile__("dsb ish" : : : "memory");
}

static bool patch_common(struct thread_storage *thread, uintptr_t instruction, void *handler, bool skip, uint self_fd)
{
	// Find the original mapping
	struct mapping target_mapping;
	int mapping_error = lookup_mapping_for_address(patch_target.start, &target_mapping);
	if (mapping_error <= 0) {
		if (mapping_error < 0) {
			DIE("could not read memory mappings", fs_strerror(mapping_error));
		}
		DIE("could not find memory mapping");
	}
	if ((target_mapping.flags & (MAP_SHARED | MAP_PRIVATE)) == MAP_SHARED) {
		// Found that the mapping was shared, don't patch
		PATCH_LOG("found shared mapping", (uintptr_t)target_mapping.flags);
		return false;
	}
	// Find an unused page to detour to
	uintptr_t start_page = instruction & -PAGE_SIZE;
	uintptr_t stub_address;
	struct attempt_cleanup_state lock_cleanup;
	attempt_lock_and_push_mutex(thread, &lock_cleanup, &region_lock);
	if (current_region && trampoline_region_has_space((uint8_t *)current_region, LARGEST_TRAMPOLINE) && is_valid_pc_relative_offset((intptr_t)current_region - (instruction + sizeof(uint32_t)))) {
		// Have at least LARGEST_TRAMPOLINE bytes left in the trampoline page and the trampoline's address is compatible with a PC-relative jump
		stub_address = (uintptr_t)current_region;
	} else {
		void *new_mapping = fs_mmap((void *)start_page, TRAMPOLINE_REGION_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, self_fd, PAGE_SIZE);
		if (UNLIKELY(fs_is_map_failed(new_mapping))) {
			attempt_unlock_and_pop_mutex(&lock_cleanup, &region_lock);
			PATCH_LOG("Failed to patch: mmap failed", -(intptr_t)new_mapping);
			return false;
		}
		if (is_valid_pc_relative_offset((uintptr_t)new_mapping - (instruction + sizeof(uint32_t)))) {
			// Address kernel gave us is compatible with a pc-relative jump, use it
			stub_address = (uintptr_t)new_mapping;
		} else {
			// search for a compatible address by searching the address space for a gap
			stub_address = find_unused_address(thread, start_page);
			PATCH_LOG("new stub_address", stub_address);
			if (!is_valid_pc_relative_offset((intptr_t)stub_address - (instruction + sizeof(uint32_t)))) {
				attempt_unlock_and_pop_mutex(&lock_cleanup, &region_lock);
				PATCH_LOG("Failed to patch: invalid pc-relative offset");
				fs_munmap((void *)new_mapping, TRAMPOLINE_REGION_SIZE);
				return false;

			}
			new_mapping = fs_mremap(new_mapping, TRAMPOLINE_REGION_SIZE, TRAMPOLINE_REGION_SIZE, MREMAP_FIXED|MREMAP_MAYMOVE, (void *)stub_address);
			if (UNLIKELY(fs_is_map_failed(new_mapping))) {
				attempt_unlock_and_pop_mutex(&lock_cleanup, &region_lock);
				PATCH_LOG("Failed to patch: mremap failed", -(intptr_t)new_mapping);
				fs_munmap(new_mapping, TRAMPOLINE_REGION_SIZE);
				return false;
			}
		}
	}
	// Construct the trampoline
	uint32_t *trampoline = (uint32_t *)stub_address;
	// Copy the code to call into rcx with pointer to registers as first arg
	size_t template_size = (uintptr_t)&trampoline_call_handler_end - (uintptr_t)&trampoline_call_handler_start;
	memcpy(trampoline, (const void *)&trampoline_call_handler_start, template_size);
	trampoline += template_size / sizeof(*trampoline) - 2;
	if (!skip) {
		// Insert original instruction
		*trampoline++ = *(uint32_t *)instruction;
	}
	uintptr_t ret_offset = ((instruction + sizeof(uint32_t) - (uintptr_t)trampoline) / sizeof(uint32_t)) & ((1u << 26) - 1);
	*trampoline++ = INS_B_PC_REL | ret_offset;
	if (skip) {
		// Offset to skip over nop
		trampoline++;
	}
	// TODO: Patch the jump back to the original function
	// Patch the receiver address onto the tail
	*(uintptr_t *)trampoline = (uintptr_t)handler;
	trampoline += 2;
	clear_icache(stub_address, (uintptr_t)trampoline);
	// Make the target function writable
	if (fs_mprotect((void *)start_page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		attempt_unlock_and_pop_mutex(&lock_cleanup, &region_lock);
		PATCH_LOG("Failed to patch: mprotect failed");
		return false;
	}
	current_region = trampoline;
	// Patch the syscall instruction to jump to the trampoline
	if (membarrier_is_supported) {
		fs_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0);
	}
	uintptr_t offset = ((stub_address - instruction) / sizeof(uint32_t)) & ((1u << 26) - 1);
	atomic_store((_Atomic uint32_t *)instruction, INS_B_PC_REL | offset);
	clear_icache(instruction, instruction + 4);
	if (mapping_error == 0) {
		int result = fs_mprotect((void *)start_page, PAGE_SIZE, target_mapping.flags & (PROT_READ | PROT_WRITE | PROT_EXEC));
		if (result < 0) {
			PATCH_LOG("Failed to update protection", -result);
		}
	}
	attempt_unlock_and_pop_mutex(&lock_cleanup, &region_lock);
	return true;
	// WRITE_LITERAL(TELEMETRY_FD, " to ");
	// write_int(TELEMETRY_FD, stub_address);
	// WRITE_LITERAL(TELEMETRY_FD, "\n");
}

bool patch_breakpoint(struct thread_storage *thread, intptr_t address, __attribute__((unused)) intptr_t entry, void (*handler)(uintptr_t *), int self_fd)
{
	PATCH_LOG("patching breakpoint", (uintptr_t)address);
	return patch_common(thread, address, handler, false, self_fd);
}

#endif
