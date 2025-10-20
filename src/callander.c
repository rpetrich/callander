#define _GNU_SOURCE
#include "freestanding.h"

#include "axon.h"

#include <errno.h>
#include <limits.h>
#ifdef __linux__
#include <linux/audit.h>
#include <linux/binfmts.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/ptrace.h>
#include <sys/resource.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif

#include "callander.h"
#include "callander_internal.h"
#include "callander_print.h"

#ifdef __linux__
#include "bpf_debug.h"
#endif
#include "linux.h"
#include "loader.h"
#include "qsort.h"
#include "search.h"

#define CALL_TRACE_WITH_RANGE

#ifdef LOGGING
bool should_log;
#endif

#define ABORT_AT_NON_EXECUTABLE_ADDRESS 0

static const struct ins_memory_reference invalid_mem_ref = {
#if defined(__x86_64__)
	.rm = REGISTER_R12,
	.base = 0,
	.index = 0,
	.scale = 0,
	.addr = 0,
#endif
};

__attribute__((nonnull(1))) static bool memory_ref_references_register(const struct ins_memory_reference *rm, int register_index)
{
#if defined(__x86_64__)
	switch (rm->rm) {
		case REGISTER_R12:
			// invalid
			return false;
		case REGISTER_MEM:
			// absolute memory address
			return false;
		case REGISTER_STACK_0:
			if (rm->index == REGISTER_SP) {
				// base register contains memory address
				return rm->base == register_index;
			} else {
				// base register contains memory address, index contains offset
				return rm->base == register_index || rm->index == register_index;
			}
		case REGISTER_STACK_4:
			// relative to cs
			return false;
		default:
			return rm->rm == register_index;
	}
#else
	(void)rm;
	(void)register_index;
	return false;
#endif
}

__attribute__((nonnull(1))) static bool memory_ref_could_reference_stack_slot(const struct ins_memory_reference *rm)
{
#if defined(__x86_64__)
	switch (rm->rm) {
		case REGISTER_R12:
			// invalid
			return true;
		case REGISTER_MEM:
			// absolute memory address
			return true;
		case REGISTER_STACK_0:
			return rm->base == REGISTER_SP;
		case REGISTER_STACK_4:
			// relative to cs
			return true;
		default:
			return false;
	}
#else
	(void)rm;
	return true;
#endif
}

static inline uintptr_t most_significant_bit(uintptr_t val)
{
	val |= val >> 1;
	val |= val >> 2;
	val |= val >> 4;
	val |= val >> 8;
	val |= val >> 16;
	val |= val >> 32;
	return val & ((~val >> 1) ^ 0x8000000000000000);
}

const int sysv_argument_abi_register_indexes[] = {
#if defined(__x86_64__)
	REGISTER_RDI,
	REGISTER_RSI,
	REGISTER_RDX,
	REGISTER_RCX,
	REGISTER_R8,
	REGISTER_R9,
#elif defined(__aarch64__)
	REGISTER_X0,
	REGISTER_X1,
	REGISTER_X2,
	REGISTER_X3,
	REGISTER_X4,
	REGISTER_X5,
	REGISTER_X6,
	REGISTER_X7,
#else
#error "Unknown architecture"
#endif
};

static const int golang_internal_argument_abi_register_indexes[] = {
#if defined(__x86_64__)
	REGISTER_RAX,
	REGISTER_RBX,
	REGISTER_RCX,
	REGISTER_RDI,
	REGISTER_RSI,
	REGISTER_R8,
	REGISTER_R9,
	REGISTER_R10,
	REGISTER_R11,
#elif defined(__aarch64__)
	REGISTER_X0,
	REGISTER_X1,
	REGISTER_X2,
	REGISTER_X3,
	REGISTER_X4,
	REGISTER_X5,
	REGISTER_X6,
	REGISTER_X7,
#else
#error "Unknown architecture"
#endif
};

static const int golang_abi0_argument_abi_register_indexes[] = {
	REGISTER_STACK_0,
	REGISTER_STACK_8,
	REGISTER_STACK_16,
	REGISTER_STACK_24,
	REGISTER_STACK_32,
	REGISTER_STACK_40,
};

const int syscall_argument_abi_register_indexes[] = {
	REGISTER_SYSCALL_ARG0,
	REGISTER_SYSCALL_ARG1,
	REGISTER_SYSCALL_ARG2,
	REGISTER_SYSCALL_ARG3,
	REGISTER_SYSCALL_ARG4,
	REGISTER_SYSCALL_ARG5,
};

static register_mask syscall_argument_abi_used_registers_for_argc[] = {
	(1 << REGISTER_SYSCALL_NR),
	(1 << REGISTER_SYSCALL_NR) | (1 << REGISTER_SYSCALL_ARG0),
	(1 << REGISTER_SYSCALL_NR) | (1 << REGISTER_SYSCALL_ARG0) | (1 << REGISTER_SYSCALL_ARG1),
	(1 << REGISTER_SYSCALL_NR) | (1 << REGISTER_SYSCALL_ARG0) | (1 << REGISTER_SYSCALL_ARG1) | (1 << REGISTER_SYSCALL_ARG2),
	(1 << REGISTER_SYSCALL_NR) | (1 << REGISTER_SYSCALL_ARG0) | (1 << REGISTER_SYSCALL_ARG1) | (1 << REGISTER_SYSCALL_ARG2) | (1 << REGISTER_SYSCALL_ARG3),
	(1 << REGISTER_SYSCALL_NR) | (1 << REGISTER_SYSCALL_ARG0) | (1 << REGISTER_SYSCALL_ARG1) | (1 << REGISTER_SYSCALL_ARG2) | (1 << REGISTER_SYSCALL_ARG3) | (1 << REGISTER_SYSCALL_ARG4),
	(1 << REGISTER_SYSCALL_NR) | (1 << REGISTER_SYSCALL_ARG0) | (1 << REGISTER_SYSCALL_ARG1) | (1 << REGISTER_SYSCALL_ARG2) | (1 << REGISTER_SYSCALL_ARG3) | (1 << REGISTER_SYSCALL_ARG4) | (1 << REGISTER_SYSCALL_ARG5),
};

const struct registers empty_registers = {
	.registers = {{.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
#if BASE_REGISTER_COUNT >= 32
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
#endif
                  {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
#define PER_STACK_REGISTER_IMPL(offset) {.value = (uintptr_t)0, .max = ~(uintptr_t)0},
                  GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
    },
	.sources = {0},
	.matches = {0},
	.modified = 0,
	.requires_known_target = 0,
#if STORE_LAST_MODIFIED
	.last_modify_ins = {0},
#endif
	.mem_ref = invalid_mem_ref,
	.compare_state = {0},
	.stack_address_taken = NULL,
};

static inline bool registers_are_subset_of_registers(const struct register_state potential_subset[REGISTER_COUNT], const struct register_state potential_superset[REGISTER_COUNT], register_mask valid_registers)
{
	for_each_bit (valid_registers, bit, i) {
		if (!register_is_subset_of_register(&potential_subset[i], &potential_superset[i])) {
			return false;
		}
	}
	return true;
}

__attribute__((nonnull(1, 3))) static void register_changed(struct registers *regs, int register_index, __attribute__((unused)) ins_ptr ins)
{
	regs->modified |= mask_for_register(register_index);
	regs->requires_known_target &= ~mask_for_register(register_index);
#if STORE_LAST_MODIFIED
	regs->last_modify_ins[register_index] = ins;
#endif
	if (UNLIKELY(regs->compare_state.validity != COMPARISON_IS_INVALID)) {
		int compare_register = regs->compare_state.target_register;
		if (UNLIKELY(compare_register == register_index)) {
			if (compare_register != REGISTER_MEM || memory_ref_equal(&regs->mem_ref, &regs->compare_state.mem_ref)) {
				LOG("clearing comparison since ", name_for_register(register_index), " changed");
				regs->compare_state.validity = COMPARISON_IS_INVALID;
			}
		} else if (memory_ref_references_register(&regs->compare_state.mem_ref, register_index)) {
			LOG("clearing comparison since ", name_for_register(register_index), " register changed");
			regs->compare_state.validity = COMPARISON_IS_INVALID;
		}
	}
	if (LIKELY(register_index != REGISTER_MEM)) {
		if (UNLIKELY(memory_ref_references_register(&regs->mem_ref, register_index))) {
			if (SHOULD_LOG) {
				if (register_is_partially_known(&regs->registers[REGISTER_MEM])) {
					ERROR_NOPREFIX("clearing mem since register changed", name_for_register(register_index));
				}
			}
			clear_register(&regs->registers[REGISTER_MEM]);
			regs->modified |= mask_for_register(REGISTER_MEM);
			regs->requires_known_target &= ~mask_for_register(REGISTER_MEM);
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[REGISTER_MEM] = ins;
#endif
		}
	}
}

__attribute__((nonnull(1, 2, 4))) void clear_match(const struct loader_context *loader, struct registers *regs, int register_index, __attribute__((unused)) ins_ptr ins)
{
	register_mask mask = regs->matches[register_index];
	if (UNLIKELY(register_index == REGISTER_SP || (register_index == REGISTER_MEM && regs->stack_address_taken && memory_ref_could_reference_stack_slot(&regs->mem_ref)))) {
		for (int i = REGISTER_STACK_0; i < REGISTER_COUNT; i++) {
			if (SHOULD_LOG) {
				if (register_is_partially_known(&regs->registers[i])) {
					if (register_index == REGISTER_SP) {
						ERROR_NOPREFIX("clearing stack slot since stack pointer changed", name_for_register(i));
					} else {
						ERROR_NOPREFIX("clearing stack slot since memory was written", name_for_register(i));
						ERROR_NOPREFIX("memory ref is", temp_str(copy_memory_ref_description(loader, regs->mem_ref)));
#if RECORD_WHERE_STACK_ADDRESS_TAKEN
						ERROR_NOPREFIX("stack address was taken previously at", temp_str(copy_address_description(loader, regs->stack_address_taken)));
#else
						ERROR_NOPREFIX("stack address was taken previously");
#endif
					}
				}
			}
			clear_register(&regs->registers[i]);
			mask |= regs->matches[i];
			regs->matches[i] = 0;
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[i] = ins;
#endif
		}
	}
	if (UNLIKELY(mask != 0)) {
		LOG("clearing matches for ", name_for_register(register_index));
		regs->matches[register_index] = 0;
		register_mask mask_off = ~mask_for_register(register_index);
		for_each_bit (mask &ALL_REGISTERS, bit, i) {
			if (SHOULD_LOG) {
				if (regs->matches[i] & ~mask_off) {
					ERROR_NOPREFIX("clearing match", name_for_register(i));
				}
			}
			regs->matches[i] &= mask_off;
		}
	}
	register_changed(regs, register_index, ins);
}

__attribute__((nonnull(1, 2, 4))) void clear_match_keep_stack(__attribute__((unused)) const struct loader_context *loader, struct registers *regs, int register_index, __attribute__((unused)) ins_ptr ins)
{
	register_mask mask = regs->matches[register_index];
	if (UNLIKELY(mask != 0)) {
		LOG("clearing matches for ", name_for_register(register_index));
		regs->matches[register_index] = 0;
		register_mask mask_off = ~mask_for_register(register_index);
		for_each_bit (mask, bit, i) {
			if (SHOULD_LOG) {
				if (regs->matches[i] & ~mask_off) {
					ERROR_NOPREFIX("clearing match", name_for_register(i));
				}
			}
			regs->matches[i] &= mask_off;
		}
	}
	register_changed(regs, register_index, ins);
}

// add_match_and_sources maintains the mapping table describing which registers have identical values
__attribute__((nonnull(1, 2, 6))) void add_match_and_sources(const struct loader_context *loader, struct registers *regs, int dest_reg, int source_reg, register_mask sources, __attribute__((unused)) ins_ptr ins)
{
#ifdef LOGGING
	if (UNLIKELY(dest_reg < 0 || dest_reg >= REGISTER_COUNT)) {
		DIE("invalid destination register ", (intptr_t)dest_reg);
	}
#endif
	clear_match(loader, regs, dest_reg, ins);
	if (LIKELY(source_reg != REGISTER_INVALID)) {
		register_mask mask = regs->matches[source_reg];
		regs->matches[source_reg] = mask | mask_for_register(dest_reg);
		regs->matches[dest_reg] = mask | mask_for_register(source_reg);
		LOG("matching ", name_for_register(source_reg), " to ", name_for_register(dest_reg));
		for_each_bit (mask &ALL_REGISTERS, bit, i) {
			LOG("existing match is for ", name_for_register(i));
			regs->matches[i] |= mask_for_register(dest_reg);
		}
	}
	regs->sources[dest_reg] = sources;
}

bool binary_has_flags(const struct loaded_binary *binary, binary_flags flags)
{
	return (binary != NULL) && ((binary->special_binary_flags & flags) == flags);
}

__attribute__((nonnull(1, 2, 4))) void clear_call_dirtied_registers(const struct loader_context *loader, struct registers *regs, struct loaded_binary *binary, ins_ptr ins, register_mask modified)
{
	register_mask preserved = CALL_PRESERVED_REGISTERS | mask_for_register(REGISTER_SP);
#ifdef __x86_64__
	if (binary_has_flags(binary, BINARY_IS_GOLANG)) {
		preserved &= ~(mask_for_register(REGISTER_RBX) | mask_for_register(REGISTER_RSI));
	}
#else
	(void)binary;
#endif
	modified &= ~preserved;
	for_each_bit (modified, bit, i) {
		if (SHOULD_LOG && register_is_partially_known(&regs->registers[i])) {
			LOG("clearing call dirtied register, ", name_for_register(i));
		}
		clear_register(&regs->registers[i]);
		regs->sources[i] = 0;
		clear_match(loader, regs, i, ins);
	}
	regs->modified |= modified;
	regs->requires_known_target &= ~modified;
	clear_match(loader, regs, REGISTER_MEM, ins);
	regs->compare_state.validity = COMPARISON_IS_INVALID;
	regs->mem_ref = invalid_mem_ref;
}

__attribute__((nonnull(1))) void push_stack(const struct loader_context *loader, struct registers *regs, int push_count, ins_ptr ins)
{
	LOG("push stack ", push_count, " times");
	if (push_count == 0) {
		return;
	}
	regs->modified |= STACK_REGISTERS;
	if (push_count > REGISTER_COUNT - REGISTER_STACK_0) {
		regs->requires_known_target = regs->requires_known_target & ~STACK_REGISTERS;
		push_count = REGISTER_COUNT - REGISTER_STACK_0;
	} else {
		regs->requires_known_target = (regs->requires_known_target & ~STACK_REGISTERS) | (((regs->requires_known_target & STACK_REGISTERS) << push_count) & ALL_REGISTERS);
		for (int i = REGISTER_COUNT - 1; i >= REGISTER_STACK_0 + push_count; i--) {
			regs->registers[i] = regs->registers[i - push_count];
			regs->sources[i] = regs->sources[i - push_count];
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[i] = regs->last_modify_ins[i - push_count];
#endif
			regs->matches[i] = regs->sources[i - push_count];
		}
	}
	for (int i = 0; i < push_count; i++) {
		clear_register(&regs->registers[REGISTER_STACK_0 + i]);
		regs->sources[REGISTER_STACK_0 + i] = 0;
#if STORE_LAST_MODIFIED
		regs->last_modify_ins[REGISTER_STACK_0 + i] = NULL;
#endif
		regs->matches[REGISTER_STACK_0 + i] = 0;
	}
	// shift the matching bits around
	for (int i = 0; i < REGISTER_COUNT; i++) {
		regs->matches[i] = (regs->matches[i] & ~STACK_REGISTERS) | (((regs->matches[i] & STACK_REGISTERS) << push_count) & ALL_REGISTERS);
	}
	clear_match_keep_stack(loader, regs, REGISTER_SP, ins);
}

__attribute__((nonnull(1))) void pop_stack(const struct loader_context *loader, struct registers *regs, int pop_count, ins_ptr ins)
{
	LOG("popping stack ", pop_count, " times");
	if (pop_count == 0) {
		return;
	}
	regs->modified |= STACK_REGISTERS;
	regs->requires_known_target = (regs->requires_known_target & ~STACK_REGISTERS) | (pop_count > REGISTER_COUNT ? 0 : (regs->requires_known_target >> pop_count) & ALL_REGISTERS);
	for (int i = REGISTER_STACK_0; i < REGISTER_COUNT; i++) {
		if (i + pop_count >= REGISTER_COUNT) {
			clear_register(&regs->registers[i]);
			regs->sources[i] = 0;
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[i] = NULL;
#endif
			regs->matches[i] = 0;
		} else {
			regs->registers[i] = regs->registers[i + pop_count];
			regs->sources[i] = regs->sources[i + pop_count];
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[i] = regs->last_modify_ins[i + pop_count];
#endif
			regs->matches[i] = regs->matches[i + pop_count];
		}
	}
	// shift the matching bits around
	for (int i = 0; i < REGISTER_COUNT; i++) {
		regs->matches[i] = (regs->matches[i] & ~STACK_REGISTERS) | (pop_count > REGISTER_COUNT ? 0 : ((regs->matches[i] >> pop_count) & ALL_REGISTERS));
	}
	clear_match_keep_stack(loader, regs, REGISTER_SP, ins);
}

__attribute__((nonnull(1, 2, 3))) static inline struct registers copy_call_argument_registers(const struct loader_context *loader, const struct registers *regs, __attribute__((unused)) ins_ptr ins)
{
	struct registers result = *regs;
#if defined(__x86_64__)
	clear_register(&result.registers[REGISTER_RBX]);
	result.sources[REGISTER_RBX] = 0;
	clear_register(&result.registers[REGISTER_SP]);
	result.sources[REGISTER_SP] = 0;
	clear_register(&result.registers[REGISTER_RBP]);
	result.sources[REGISTER_RBP] = 0;
	clear_register(&result.registers[REGISTER_R12]);
	result.sources[REGISTER_R12] = 0;
	clear_register(&result.registers[REGISTER_R13]);
	result.sources[REGISTER_R13] = 0;
	clear_register(&result.registers[REGISTER_R14]);
	result.sources[REGISTER_R14] = 0;
	clear_register(&result.registers[REGISTER_R15]);
	result.sources[REGISTER_R15] = 0;
	clear_register(&result.registers[REGISTER_MEM]);
	result.sources[REGISTER_MEM] = 0;
	clear_match(loader, &result, REGISTER_RBX, ins);
	// TODO: clear RSP matches without clearing the stack
	// clear_match(loader, &result, REGISTER_SP, ins);
	clear_match(loader, &result, REGISTER_RBP, ins);
	clear_match(loader, &result, REGISTER_R12, ins);
	clear_match(loader, &result, REGISTER_R13, ins);
	clear_match(loader, &result, REGISTER_R14, ins);
	clear_match(loader, &result, REGISTER_R15, ins);
#elif defined(__aarch64__)
	// TODO: copy call registers
	for (int i = REGISTER_X9; i < REGISTER_SP; i++) {
		clear_register(&result.registers[i]);
		result.sources[i] = 0;
	}
	clear_register(&result.registers[REGISTER_SP]);
	result.sources[REGISTER_SP] = 0;
	clear_register(&result.registers[REGISTER_MEM]);
	result.sources[REGISTER_MEM] = 0;
	for (int i = REGISTER_X9; i < REGISTER_SP; i++) {
		clear_match(loader, &result, i, ins);
	}
	// TODO: clear RSP matches without clearing the stack
	// clear_match(loader, &result, REGISTER_SP, ins);
#else
#error "Unknown architecture"
#endif
	// Clear match state for REGISTER_MEM without invalidating stack
	register_mask mask = result.matches[REGISTER_MEM];
	if (UNLIKELY(mask != 0)) {
		LOG("clearing matches for ", name_for_register(REGISTER_MEM));
		result.matches[REGISTER_MEM] = 0;
		mask = ~mask_for_register(REGISTER_MEM);
#pragma GCC unroll 64
		for (int i = 0; i < REGISTER_COUNT; i++) {
			if (SHOULD_LOG) {
				if (result.matches[i] & ~mask) {
					ERROR_NOPREFIX("clearing ", name_for_register(i), " match");
				}
			}
			result.matches[i] &= mask;
		}
	}
	result.modified |= mask_for_register(REGISTER_MEM);
	result.requires_known_target &= ~mask_for_register(REGISTER_MEM);
#if STORE_LAST_MODIFIED
	result.last_modify_ins[REGISTER_MEM] = ins;
#endif
	result.mem_ref = invalid_mem_ref;
	result.stack_address_taken = NULL;
	result.compare_state.validity = COMPARISON_IS_INVALID;
	return result;
}

__attribute__((nonnull(1, 2))) void dump_registers(const struct loader_context *loader, const struct registers *state, register_mask registers)
{
	if (SHOULD_LOG && (registers != 0)) {
		ERROR_NOPREFIX("regs", temp_str(copy_registers_description(loader, state, registers)));
#if STORE_LAST_MODIFIED
		for (int i = 0; i < REGISTER_COUNT; i++) {
			if (registers & mask_for_register(i)) {
				if (state->last_modify_ins[i] != NULL) {
					ERROR_NOPREFIX("reg", name_for_register(i));
					ERROR_NOPREFIX("last modified at", temp_str(copy_address_description(loader, state->last_modify_ins[i])));
				}
			}
		}
#endif
	}
}

__attribute__((nonnull(1, 2))) void dump_nonempty_registers(const struct loader_context *loader, const struct registers *state, register_mask registers)
{
	if (SHOULD_LOG) {
		for_each_bit (registers, bit, i) {
			if (!register_is_partially_known(&state->registers[i])) {
				registers &= ~bit;
			}
		}
		dump_registers(loader, state, registers);
	}
}

__attribute__((nonnull(1, 2))) bool memory_ref_equal(const struct ins_memory_reference *l, const struct ins_memory_reference *r)
{
#if defined(__x86_64__)
	return l->rm == r->rm && l->base == r->base && l->index == r->index && l->scale == r->scale && l->addr == r->addr;
#else
	// for now, all memory references match
	(void)l;
	(void)r;
	return true;
#endif
}

__attribute__((nonnull(1))) char *copy_memory_ref_description(const struct loader_context *loader, struct ins_memory_reference rm)
{
#if defined(__x86_64__)
	char *result;
	char *buf;
	if (rm.rm == REGISTER_MEM) {
		char *temp = copy_address_description(loader, (const void *)rm.addr);
		size_t len = fs_strlen(temp);
		result = malloc(len + 3);
		buf = result;
		*buf++ = '[';
		fs_memcpy(buf, temp, len);
		free(temp);
		buf += len;
	} else {
		result = malloc(50);
		buf = result;
		*buf++ = '[';
		switch (rm.rm) {
			case REGISTER_STACK_0:
				buf = fs_strcpy(buf, name_for_register(rm.base));
				if (rm.index != REGISTER_SP) {
					*buf++ = '+';
					buf = fs_strcpy(buf, name_for_register(rm.index));
					if (rm.scale != 0) {
						*buf++ = '*';
						buf += fs_utoa(1 << rm.scale, buf);
					}
				}
				break;
			case REGISTER_STACK_4:
				buf = fs_strcpy(buf, "cs");
				break;
			default:
				buf = fs_strcpy(buf, name_for_register(rm.rm));
				break;
		}
		if (rm.addr != 0) {
			if ((intptr_t)rm.addr < 0) {
				*buf++ = '-';
				buf += fs_utoah(-(intptr_t)rm.addr, buf);
			} else {
				*buf++ = '+';
				buf += fs_utoah(rm.addr, buf);
			}
		}
	}
	*buf++ = ']';
	*buf = '\0';
	return result;
#else
	(void)loader;
	(void)rm;
	return strdup("[]");
#endif
}

char *effects_description(function_effects effects)
{
	static char buffer[PAGE_SIZE];
	char *buf = buffer;
	if (effects & EFFECT_RETURNS) {
		buf = fs_strcpy(buf, ", returns");
	}
	if (effects & EFFECT_EXITS) {
		buf = fs_strcpy(buf, ", exits");
	}
	if (effects & EFFECT_STICKY_EXITS) {
		buf = fs_strcpy(buf, ", sticky-exits");
	}
	if (effects & EFFECT_PROCESSED) {
		buf = fs_strcpy(buf, ", processed");
	}
	if (effects & EFFECT_PROCESSING) {
		buf = fs_strcpy(buf, ", processing");
	}
	if (effects & EFFECT_AFTER_STARTUP) {
		buf = fs_strcpy(buf, ", after-startup");
	}
	if (effects & EFFECT_ENTRY_POINT) {
		buf = fs_strcpy(buf, ", as-entrypoint");
	}
	if (effects & EFFECT_MODIFIES_STACK) {
		buf = fs_strcpy(buf, ", modifies-stack");
	}
	return buf == buffer ? "(none)" : &buffer[2];
}

__attribute__((nonnull(1, 2, 4))) void queue_instruction(struct queued_instructions *queue, ins_ptr ins, function_effects effects, const struct registers *registers, ins_ptr caller, const char *description)
{
	uint32_t i = queue->count;
	uint32_t count = i + 1;
	if (count > queue->capacity) {
		queue->capacity = count * 2;
		queue->queue = realloc(queue->queue, queue->capacity * sizeof(struct queued_instruction));
	}
	queue->queue[i] = (struct queued_instruction){
		.ins = ins,
		.effects = effects,
		.registers = *registers,
		.caller = caller,
		.description = description,
	};
	queue->count = count;
}

__attribute__((nonnull(1, 2))) static bool dequeue_instruction(struct queued_instructions *queue, struct queued_instruction *out_instruction)
{
	uint32_t count = queue->count;
	if (count == 0) {
		return false;
	}
	count--;
	queue->count = count;
	*out_instruction = queue->queue[count];
	if (UNLIKELY(count == 0)) {
		free(queue->queue);
		queue->queue = NULL;
		queue->capacity = 0;
	}
	return true;
}

struct lookup_base_address
{
	ins_ptr ins;
	uintptr_t base;
};

__attribute__((nonnull(1, 2))) void add_lookup_table_base_address(struct lookup_base_addresses *addresses, ins_ptr ins, uintptr_t base)
{
	size_t count = addresses->count;
	struct lookup_base_address *result = realloc(addresses->addresses, sizeof(*result) * (count + 1));
	result[count] = (struct lookup_base_address){
		.ins = ins,
		.base = base,
	};
	addresses->addresses = result;
	addresses->count = count + 1;
}

__attribute__((nonnull(1, 2))) uintptr_t find_lookup_table_base_address(const struct lookup_base_addresses *addresses, ins_ptr ins)
{
	const struct lookup_base_address *addr = addresses->addresses;
	size_t count = addresses->count;
	for (size_t i = 0; i < count; i++) {
		if (addr[i].ins == ins) {
			return addr[i].base;
		}
	}
	return 0;
}

__attribute__((nonnull(1))) static size_t sizeof_searched_instruction_data_entry(struct searched_instruction_data_entry *entry)
{
	return sizeof(struct searched_instruction_data_entry) + entry->used_count * sizeof(struct register_state);
}

void init_searched_instructions(struct searched_instructions *search)
{
	search->table = calloc(8, sizeof(*search->table));
	search->mask = 7;
	search->remaining_slots = 7;
	search->generation = 0;
	search->queue = (struct queued_instructions){0};
	search->lookup_base_addresses = (struct lookup_base_addresses){0};
	search->fopen_modes = NULL;
	search->fopen_mode_count = 0;
}

static void cleanup_address_list(struct address_list *list)
{
	free(list->addresses);
	*list = (struct address_list){0};
}

void cleanup_searched_instructions(struct searched_instructions *search)
{
	uint32_t mask = search->mask;
	struct searched_instruction_entry *table = search->table;
	uint32_t count = 0;
	uint32_t last_index = mask;
	for (uint32_t i = 0; i <= last_index; i++) {
		struct searched_instruction_data *data = table[i].data;
		if (data != NULL) {
			count++;
			free(data);
		}
	}
	LOG("processed ", (intptr_t)count, " blocks");
	free(search->fopen_modes);
	search->fopen_mode_count = 0;
	free(table);
	free(search->queue.queue);
	search->table = NULL;
	search->queue.queue = NULL;
	free(search->lookup_base_addresses.addresses);
	cleanup_address_list(&search->loaded_addresses);
	cleanup_address_list(&search->tls_addresses);
	free(search->callbacks);
}

__attribute__((always_inline)) static inline uint32_t hash_instruction_address(ins_ptr addr)
{
	// I don't know why this hash function is so effective at distributing keys, but it is
	uint32_t truncated = (uintptr_t)addr;
	return ((truncated >> 16) ^ truncated) * 0x119de1f3;
}

__attribute__((noinline)) __attribute__((nonnull(1))) static void grow_already_searched_instructions(struct searched_instructions *search)
{
	struct searched_instruction_entry *old_table = search->table;
	uint32_t old_size = search->mask + 1;
	uint32_t new_size = old_size * 2;
	uint32_t mask = new_size - 1;
	struct searched_instruction_entry *new_table = calloc(new_size, sizeof(*new_table));
	uint32_t remaining_slots = (new_size * 3) / 4;
	for (uint32_t i = 0; i < old_size; i++) {
		struct searched_instruction_entry *value = &old_table[i];
		if (value->address != NULL) {
			uint32_t index = hash_instruction_address(value->address);
			for (;; index++) {
				index &= mask;
				struct searched_instruction_entry *entry = &new_table[index];
				if (entry->address == NULL) {
					*entry = *value;
					break;
				}
			}
			remaining_slots--;
		}
	}
	free(old_table);
	search->table = new_table;
	search->mask = mask;
	search->remaining_slots = remaining_slots;
	search->generation++;
}

struct loader_stub
{
	uintptr_t dummy;
	struct loader_stub *next;
};

__attribute__((always_inline)) __attribute__((nonnull(1, 2, 3, 4))) static inline void push_reachable_region(__attribute__((unused)) const struct loader_context *loader, struct reachable_instructions *reachable, ins_ptr entry, ins_ptr exit)
{
	LOG("reachable from ", temp_str(copy_address_description(loader, entry)), " to ", temp_str(copy_address_description(loader, exit)));
	size_t old_count = reachable->count;
	size_t new_count = old_count + 1;
	if (new_count > reachable->buffer_size) {
		reachable->buffer_size = (new_count * 2);
		reachable->regions = realloc(reachable->regions, reachable->buffer_size * sizeof(*reachable->regions));
	}
	reachable->regions[old_count] = (struct reachable_region){
		.entry = entry,
		.exit = exit,
	};
	reachable->count = new_count;
}

__attribute__((always_inline)) __attribute__((nonnull(2))) static inline void expand_registers(struct register_state full[REGISTER_COUNT], const struct searched_instruction_data_entry *entry)
{
	register_mask used_registers = entry->used_registers;
	int j = 0;
#pragma GCC unroll 128
	for (int i = 0; i < REGISTER_COUNT; i++) {
		if (used_registers & mask_for_register(i)) {
#ifdef LOGGING
			if (UNLIKELY(j == entry->used_count)) {
				DIE("invalid register mask: ", used_registers);
			}
#endif
			full[i] = entry->registers[j++];
		} else {
			clear_register(&full[i]);
		}
	}
}

__attribute__((always_inline)) __attribute__((nonnull(1))) static inline bool collapse_registers(struct searched_instruction_data_entry *entry, const struct register_state full[REGISTER_COUNT])
{
	int old_count = entry->used_count;
	int new_count = 0;
	register_mask used_registers = 0;
	for (int i = 0; i < REGISTER_COUNT; i++) {
		if (register_is_partially_known(&full[i])) {
			if (new_count == old_count) {
				LOG("too many registers to collapse: ", new_count);
				return false;
			}
			new_count++;
			used_registers |= mask_for_register(i);
		}
	}
	entry->used_registers = used_registers;
	int j = 0;
	for_each_bit (used_registers, bit, i) {
		entry->registers[j++] = full[i];
	}
	return true;
}

__attribute__((always_inline)) __attribute__((nonnull(2))) static inline bool registers_are_subset_of_entry_registers(const struct register_state potential_subset[REGISTER_COUNT], const struct searched_instruction_data_entry *entry,
                                                                                                                      register_mask valid_registers)
{
	register_mask used_registers = entry->used_registers;
	valid_registers &= used_registers;
	if (UNLIKELY(valid_registers != 0)) {
		int j = 0;
		for_each_bit (used_registers, bit, i) {
			if (valid_registers & bit) {
				if (!register_is_subset_of_register(&potential_subset[i], &entry->registers[j])) {
					return false;
				}
			}
			j++;
		}
	}
	return true;
}

__attribute__((always_inline)) __attribute__((nonnull(1))) static inline bool entry_registers_are_subset_of_registers(const struct searched_instruction_data_entry *entry, const struct register_state potential_superset[REGISTER_COUNT],
                                                                                                                      register_mask valid_registers)
{
	register_mask used_registers = entry->used_registers;
	if (valid_registers != 0) {
		int j = 0;
		for_each_bit (used_registers | valid_registers, bit, i) {
			if (valid_registers & bit) {
				if ((used_registers & bit) && !register_is_subset_of_register(&entry->registers[j], &potential_superset[i])) {
					return false;
				}
			}
			if (used_registers & bit) {
				j++;
			}
		}
	}
	return true;
}

__attribute__((always_inline)) static inline struct searched_instruction_data_entry *entry_for_offset(struct searched_instruction_data *data, size_t offset)
{
	return (struct searched_instruction_data_entry *)((uintptr_t)&data->entries[0] + offset);
}

__attribute__((nonnull(1, 2))) static void add_new_entry_with_registers(struct searched_instruction_entry *table_entry, const struct registers *registers)
{
	register_mask used_registers = 0;
	int used_count = 0;
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		if (register_is_partially_known(&registers->registers[i])) {
			used_registers |= mask_for_register(i);
			used_count++;
		}
	}
	size_t new_entry_size = sizeof(struct searched_instruction_data_entry) + used_count * sizeof(struct register_state);
	size_t end_offset = table_entry->data->end_offset;
	size_t new_end_offset = end_offset + new_entry_size;
	struct searched_instruction_data *data = (table_entry->data = realloc(table_entry->data, sizeof(*table_entry->data) + new_end_offset));
	struct searched_instruction_data_entry *entry = entry_for_offset(data, end_offset);
	entry->effects = table_entry->data->sticky_effects;
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		entry->widen_count[i] = 0;
	}
	entry->used_count = used_count;
	entry->generation = 0;
	entry->used_registers = used_registers;
	entry->modified = registers->modified;
	entry->requires_known_target = registers->requires_known_target;
	int j = 0;
	for_each_bit (used_registers, bit, i) {
		entry->registers[j++] = registers->registers[i];
	}
	data->end_offset = new_end_offset;
}

void populate_reachable_regions(struct program_state *analysis)
{
	struct searched_instruction_entry *table = analysis->search.table;
	uint32_t count = analysis->search.mask + 1;
	for (uint32_t i = 0; i < count; i++) {
		struct searched_instruction_entry *entry = &table[i];
		if (entry->address != NULL) {
			struct searched_instruction_data *data = entry->data;
			size_t end_offset = data->end_offset;
			for (size_t offset = 0; offset < end_offset;) {
				struct searched_instruction_data_entry *data_entry = entry_for_offset(data, offset);
				if (data_entry->effects & EFFECT_AFTER_STARTUP) {
					push_reachable_region(&analysis->loader, &analysis->reachable, entry->address, data->next_ins);
					break;
				}
				offset += sizeof_searched_instruction_data_entry(data_entry);
			}
		}
	}
}

bool combine_register_states(struct register_state *out_state, const struct register_state *combine_state, __attribute__((unused)) int register_index)
{
	if (combine_state->max == out_state->value - 1 && combine_state->value < out_state->value) {
		out_state->value = combine_state->value;
		LOG("widening ", name_for_register(register_index), " down");
		return true;
	}
	if (combine_state->value == out_state->max + 1 && combine_state->max > out_state->max) {
		out_state->max = combine_state->max;
		LOG("widening ", name_for_register(register_index), " up");
		return true;
	}
	if ((combine_state->value >= out_state->value && combine_state->value <= out_state->max) || (out_state->value >= combine_state->value && out_state->value <= combine_state->max)) {
		*out_state = union_of_register_states(*out_state, *combine_state);
		LOG("combining overlapping ", name_for_register(register_index));
		return true;
	}
	return false;
}

bool in_plt_section(const struct loaded_binary *binary, ins_ptr ins)
{
	const ElfW(Shdr) * section;
	protection_for_address_in_binary(binary, (uintptr_t)ins, &section);
	if (section == NULL) {
		return false;
	}
	const char *section_name = &binary->sections.strings[section->sh_name];
	return fs_strcmp(section_name, ".plt") == 0;
}

__attribute__((nonnull(1, 2, 3, 5, 6, 7))) __attribute__((noinline)) static size_t entry_offset_for_registers(struct searched_instruction_entry *table_entry, const struct registers *registers, struct program_state *analysis,
                                                                                                              function_effects required_effects, __attribute__((unused)) ins_ptr addr, struct registers *out_registers,
                                                                                                              bool *out_wrote_registers)
{
	struct searched_instruction_data *data = table_entry->data;
	const struct loader_context *loader = &analysis->loader;
	register_mask relevant_registers = data->relevant_registers;
	size_t end_offset = data->end_offset;
	size_t count = 0;
	*out_wrote_registers = false;
	size_t total_processing_count = 0;
	for (size_t offset = 0; offset < end_offset;) {
		struct searched_instruction_data_entry *entry = entry_for_offset(data, offset);
		bool is_processing = (entry->effects & EFFECT_PROCESSING) == EFFECT_PROCESSING;
		total_processing_count += is_processing;
		if ((entry->effects & required_effects) != required_effects) {
			goto continue_search_initial;
		}
		if (registers_are_subset_of_entry_registers(registers->registers, entry, relevant_registers)) {
			// new register values are a subset of an existing entry, reuse it
			if (SHOULD_LOG) {
				ERROR_NOPREFIX("subset of existing at offset, reusing effects", (intptr_t)offset);
				dump_registers(loader, registers, relevant_registers);
				expand_registers(out_registers->registers, entry);
				dump_registers(loader, out_registers, relevant_registers);
			} else {
				expand_registers(out_registers->registers, entry);
			}
#pragma GCC unroll 64
			for (int i = 0; i < REGISTER_COUNT; i++) {
				out_registers->sources[i] = registers->sources[i];
#if STORE_LAST_MODIFIED
				out_registers->last_modify_ins[i] = registers->last_modify_ins[i];
#endif
			}
#pragma GCC unroll 64
			for (int i = 0; i < REGISTER_COUNT; i++) {
				out_registers->matches[i] = registers->matches[i];
			}
			out_registers->modified = registers->modified;
			out_registers->requires_known_target = registers->requires_known_target;
			out_registers->mem_ref = registers->mem_ref;
			out_registers->stack_address_taken = registers->stack_address_taken;
			out_registers->compare_state = registers->compare_state;
			*out_wrote_registers = true;
			return offset;
		}
		if (entry_registers_are_subset_of_registers(entry, registers->registers, relevant_registers)) {
			// new register values are a superset of an existing entry, widen and reuse it
			for_each_bit (relevant_registers &ALL_REGISTERS, bit, i) {
				if (entry->widen_count[i] >= 15) {
					// widened too many times
					goto continue_search_initial;
				}
				if (!register_is_exactly_known(&registers->registers[i])) {
					entry->widen_count[i]++;
				}
			}
			if (!collapse_registers(entry, registers->registers)) {
				goto continue_search_initial;
			}
			entry->effects = data->sticky_effects;
			LOG("superset of existing at ", (intptr_t)offset, ", reprocessing effects");
			if (is_processing) {
				entry->generation++;
				LOG("processing, so bumping the generation counter");
			}
			return offset;
		}
	continue_search_initial:
		offset += sizeof_searched_instruction_data_entry(entry);
		count++;
	}
	// this is super janky. find and collapse loops
	register_mask widenable_registers = relevant_registers & ~data->preserved_registers;
	register_mask profitable_registers = 0;
	if (widenable_registers != 0 || total_processing_count > 60) {
		LOG("loop heuristics with widenable");
		dump_registers(loader, registers, widenable_registers);
		LOG("additionally relevant");
		dump_registers(loader, registers, relevant_registers & ~widenable_registers);
		out_registers->compare_state.validity = COMPARISON_IS_INVALID;
		size_t processing_count = 0;
		register_mask definitely_widenable_registers = relevant_registers & ~data->preserved_and_kept_registers;
		for (size_t offset = 0; offset < end_offset;) {
			struct searched_instruction_data_entry *entry = entry_for_offset(data, offset);
			if ((entry->effects & required_effects) != required_effects) {
				goto continue_search;
			}
			bool is_processing = entry->effects & EFFECT_PROCESSING;
			processing_count += is_processing;
			expand_registers(out_registers->registers, entry);
#pragma GCC unroll 64
			for (int i = 0; i < REGISTER_COUNT; i++) {
				out_registers->sources[i] = registers->sources[i];
#if STORE_LAST_MODIFIED
				out_registers->last_modify_ins[i] = registers->last_modify_ins[i];
#endif
			}
#pragma GCC unroll 128
			for (int i = 0; i < REGISTER_COUNT; i++) {
				out_registers->matches[i] = registers->matches[i];
			}
			out_registers->modified = registers->modified;
			out_registers->requires_known_target = registers->requires_known_target;
			out_registers->mem_ref = registers->mem_ref;
			out_registers->stack_address_taken = registers->stack_address_taken;
			out_registers->compare_state = registers->compare_state;
			register_mask widened = 0;
			for_each_bit (relevant_registers, bit, r) {
				LOG("", name_for_register(r), " is relevant");
				if (register_is_subset_of_register(&registers->registers[r], &out_registers->registers[r])) {
					continue;
				}
				if (((widenable_registers & bit) == 0) && (processing_count < (definitely_widenable_registers & bit ? 30 : 50))) {
					LOG("not widenable, searching for next ", name_for_register(r));
					goto continue_search;
				}
				if (out_registers->registers[r].value != registers->registers[r].value || out_registers->registers[r].max != registers->registers[r].max) {
					if ((profitable_registers & bit) == 0) {
						LOG("found ", name_for_register(r), " to be profitable");
					} else {
						LOG("", name_for_register(r), " was already profitable");
					}
					dump_registers(loader, out_registers, bit);
					profitable_registers |= bit;
				}
				if (entry->widen_count[r] < 4) {
					if (combine_register_states(&out_registers->registers[r], &registers->registers[r], r)) {
						LOG("combined ", name_for_register(r), ": ", temp_str(copy_register_state_description(loader, out_registers->registers[r])));
					} else if (UNLIKELY(processing_count > 45) && register_is_exactly_known(&registers->registers[r])) {
						struct loaded_binary *binary;
						if (count < 256 && address_is_call_aligned(registers->registers[r].value) && protection_for_address(loader, (ins_ptr)registers->registers[r].value, &binary, NULL) & PROT_EXEC) {
							LOG("couldn't widen ", name_for_register(r), " because executable address in register: ", temp_str(copy_register_state_description(&analysis->loader, out_registers->registers[r])));
							goto continue_search;
						}
						LOG("too many ", name_for_register(r), " actively unwidened exact: ", temp_str(copy_register_state_description(loader, out_registers->registers[r])));
						clear_register(&out_registers->registers[r]);
						out_registers->sources[r] = 0;
						register_mask match_mask = out_registers->matches[r];
						if (match_mask != 0) {
							if ((widenable_registers & match_mask) == match_mask) {
								LOG("widening a register in tandem with ", name_for_register(r), ", preserving match");
							} else {
								clear_match(&analysis->loader, out_registers, r, addr);
							}
						}
					} else if (UNLIKELY(processing_count > 50)) {
						LOG("too many ", name_for_register(r), " actively unwidened inexact: ", temp_str(copy_register_state_description(loader, out_registers->registers[r])));
						clear_register(&out_registers->registers[r]);
						out_registers->sources[r] = 0;
						register_mask match_mask = out_registers->matches[r];
						if (match_mask != 0) {
							if ((widenable_registers & match_mask) == match_mask) {
								LOG("widening ", name_for_register(r), " in tandem with another, preserving match");
							} else {
								clear_match(&analysis->loader, out_registers, r, addr);
							}
						}
					} else {
						LOG("couldn't widen ", name_for_register(r), ": ", temp_str(copy_register_state_description(loader, out_registers->registers[r])));
						goto continue_search;
					}
				} else {
					LOG("widened ", name_for_register(r), " too many times: ", temp_str(copy_register_state_description(loader, out_registers->registers[r])));
					clear_register(&out_registers->registers[r]);
					out_registers->sources[r] = 0;
					register_mask match_mask = out_registers->matches[r];
					if (match_mask != 0) {
						if ((widenable_registers & match_mask) == match_mask) {
							LOG("widening ", name_for_register(r), " in tandem with another, preserving match");
						} else {
							clear_match(&analysis->loader, out_registers, r, addr);
						}
					}
				}
				widened |= bit;
			}
			for (int i = 0; i < REGISTER_COUNT; i++) {
				if (widened & mask_for_register(i)) {
					entry->widen_count[i]++;
				} else if (data->preserved_registers & mask_for_register(i)) {
					out_registers->registers[i] = registers->registers[i];
				} else {
					out_registers->registers[i] = union_of_register_states(registers->registers[i], out_registers->registers[i]);
				}
			}
			if (!collapse_registers(entry, out_registers->registers)) {
				LOG("failed to collapse, continuing loop heuristics");
				goto continue_search;
			}
			entry->effects = data->sticky_effects;
			LOG("loop heuristic chose existing at offset: ", (intptr_t)offset, " for ", temp_str(copy_address_description(loader, addr)), ", reprocessing effects");
			dump_registers(loader, out_registers, widened);
			register_mask unwidened = relevant_registers & ~widened;
			if (unwidened) {
				LOG("registers left as-is");
				dump_registers(loader, out_registers, unwidened);
			}
			if (is_processing) {
				entry->generation++;
				LOG("processing, so bumping the generation counter");
			}
			*out_wrote_registers = true;
			return offset;
		continue_search:
			offset += sizeof_searched_instruction_data_entry(entry);
		}
	}
	if (count > 50) {
		if (count >= 512) {
			LOG("too many entries (", (intptr_t)count, ") with no profitable, using relevant registers");
			profitable_registers = relevant_registers;
		} else if (count >= 256) {
			LOG("too many entries (", (intptr_t)count, ") with no profitable, using widenable registers");
			profitable_registers = widenable_registers;
		} else if (profitable_registers == 0) {
			LOG("numerous entries (", (intptr_t)count, "), but no profitable registers");
		} else {
			LOG("too many entries (", (intptr_t)count, "), widening profitable registers to relevant ones at");
			profitable_registers |= widenable_registers;
		}
		dump_registers(loader, registers, profitable_registers);
		if (profitable_registers != 0) {
			*out_registers = *registers;
			if (SHOULD_LOG) {
				for (int i = 0; i < REGISTER_COUNT; i++) {
					if (profitable_registers & mask_for_register(i)) {
						LOG("widening ", name_for_register(i));
					} else if (relevant_registers & mask_for_register(i)) {
						LOG("skipping widening ", name_for_register(i));
					}
				}
			}
			for_each_bit (profitable_registers, bit, i) {
				struct loaded_binary *binary;
				if (count < 256 && register_is_exactly_known(&registers->registers[i]) && address_is_call_aligned(registers->registers[i].value) &&
				    protection_for_address(loader, (ins_ptr)registers->registers[i].value, &binary, NULL) & PROT_EXEC)
				{
					LOG("skipping widening executable address in ", name_for_register(i));
					continue;
				}
				if (registers->registers[i].max < 0xff) {
					out_registers->registers[i].max = 0xff;
				} else if (registers->registers[i].max < 0xffff) {
					out_registers->registers[i].max = 0xffff;
				} else if (registers->registers[i].max < 0xffffffff) {
					out_registers->registers[i].max = 0xffffffff;
				} else {
					out_registers->registers[i].max = ~(uintptr_t)0;
				}
				out_registers->registers[i].value = 0;
				out_registers->sources[i] = 0;
			}
			*out_wrote_registers = true;
		} else {
			if (SHOULD_LOG) {
				for_each_bit (relevant_registers, bit, i) {
					ERROR_NOPREFIX("skipping widening register", name_for_register(i));
				}
			}
		}
	}
	size_t result = data->end_offset;
	add_new_entry_with_registers(table_entry, *out_wrote_registers ? out_registers : registers);
	LOG("new entry at offset: ", (intptr_t)result, " index: ", (intptr_t)count);
	return result;
}

__attribute__((nonnull(1, 2, 3))) static inline struct searched_instruction_entry *find_searched_instruction_table_entry(struct searched_instructions *search, ins_ptr addr, struct effect_token *token)
{
	token->entry_offset = 0;
	token->entry_generation = 0;
	uint32_t original_index = hash_instruction_address(addr);
retry:;
	struct searched_instruction_entry *table = search->table;
	uint32_t mask = search->mask;
	uint32_t index = original_index & mask;
	token->generation = search->generation;
	for (;; index = (index + 1) & mask) {
		struct searched_instruction_entry *entry = &table[index];
		const void *value = entry->address;
		if (LIKELY(value == addr)) {
			token->index = index;
			return entry;
		}
		if (value == NULL) {
			if (UNLIKELY(search->remaining_slots == 1)) {
				grow_already_searched_instructions(search);
				goto retry;
			}
			search->remaining_slots--;
			entry->address = addr;
			token->index = index;
			struct searched_instruction_data *result = malloc(sizeof(struct searched_instruction_data));
			*result = (struct searched_instruction_data){0};
			entry->data = result;
			return entry;
		}
	}
}

__attribute__((always_inline)) __attribute__((nonnull(1, 2, 3, 5))) static inline function_effects *get_or_populate_effects(struct program_state *analysis, ins_ptr addr, struct registers *registers, function_effects required_effects,
                                                                                                                            struct effect_token *token)
{
	struct searched_instructions *search = &analysis->search;
	struct searched_instruction_entry *table_entry = find_searched_instruction_table_entry(search, addr, token);
	bool wrote_registers;
	int entry_offset = entry_offset_for_registers(table_entry, registers, analysis, required_effects, addr, registers, &wrote_registers);
	token->entry_offset = entry_offset;
	struct searched_instruction_data_entry *entry = entry_for_offset(table_entry->data, entry_offset);
	token->entry_generation = entry->generation;
	return &entry->effects;
}

struct searched_instruction_entry *table_entry_for_token(struct searched_instructions *search, ins_ptr addr, struct effect_token *token)
{
	// optimistically assume the generation hasn't changed
	struct searched_instruction_entry *table = search->table;
	uint32_t index = token->index;
	uint32_t token_generation = token->generation;
	uint32_t table_generation = search->generation;
	// assuming the table has not grown
	if (UNLIKELY(token_generation != table_generation)) {
		uint32_t mask = search->mask;
		index = hash_instruction_address(addr);
		token->generation = table_generation;
		for (;; index++) {
			index &= mask;
			struct searched_instruction_entry *entry = &table[index];
			if (entry->address == addr) {
				token->index = index;
				return entry;
			}
		}
	}
	return &table[index];
}

__attribute__((always_inline)) static inline struct searched_instruction_data *set_effects(struct searched_instructions *search, ins_ptr addr, struct effect_token *token, function_effects new_effects, register_mask modified)
{
	struct searched_instruction_entry *table_entry = table_entry_for_token(search, addr, token);
	uint32_t entry_offset = token->entry_offset;
	struct searched_instruction_data_entry *entry = entry_for_offset(table_entry->data, entry_offset);
	if (token->entry_generation == entry->generation) {
		entry->effects = new_effects;
		entry->modified |= modified;
	} else {
		LOG("skipping setting effects because the generation changed");
	}
	return table_entry->data;
}

struct previous_register_masks
{
	register_mask relevant_registers;
	register_mask preserved_registers;
	register_mask preserved_and_kept_registers;
	struct searched_instruction_data *data;
};

static inline struct previous_register_masks add_relevant_registers(struct searched_instructions *search, const struct loader_context *loader, ins_ptr addr, const struct registers *registers, function_effects required_effects,
                                                                    register_mask relevant_registers, register_mask preserved_registers, register_mask preserved_and_kept_registers, struct effect_token *token)
{
	// optimistically assume the generation hasn't changed
	struct searched_instruction_entry *table = search->table;
	uint32_t index = token->index;
	uint32_t token_generation = token->generation;
	uint32_t table_generation = search->generation;
	if (UNLIKELY(token_generation != table_generation)) {
		uint32_t mask = search->mask;
		index = hash_instruction_address(addr);
		token->generation = table_generation;
		for (;; index++) {
			index &= mask;
			ins_ptr value = table[index].address;
			if (value == addr) {
				token->index = index;
				break;
			}
		}
	}
	struct searched_instruction_data *data = table[index].data;
	int entry_offset = token->entry_offset;
	struct searched_instruction_data_entry *entry = entry_for_offset(data, entry_offset);
	struct previous_register_masks result = (struct previous_register_masks){
		.relevant_registers = data->relevant_registers,
		.preserved_registers = data->preserved_registers,
		.preserved_and_kept_registers = data->preserved_and_kept_registers,
		.data = data,
	};
	data->relevant_registers = result.relevant_registers | relevant_registers;
	data->preserved_registers |= preserved_registers;
	data->preserved_and_kept_registers = result.preserved_and_kept_registers | preserved_and_kept_registers;
	struct registers copy;
	if (SHOULD_LOG) {
		ERROR_NOPREFIX("existing values (index)", (intptr_t)entry_offset);
		expand_registers(copy.registers, entry);
		dump_registers(loader, &copy, data->relevant_registers);
	}
	function_effects effects;
	if (registers_are_subset_of_entry_registers(registers->registers, entry, data->relevant_registers)) {
		effects = entry->effects;
	} else {
		effects = EFFECT_NONE;
	}
	if ((effects & required_effects) != required_effects) {
		expand_registers(copy.registers, entry);
		for (int i = 0; i < REGISTER_COUNT; i++) {
			copy.sources[i] = registers->sources[i];
			copy.matches[i] = registers->matches[i];
#if STORE_LAST_MODIFIED
			copy.last_modify_ins[i] = registers->last_modify_ins[i];
#endif
		}
		copy.modified = registers->modified;
		copy.requires_known_target = registers->requires_known_target;
		copy.mem_ref = registers->mem_ref;
		copy.compare_state = registers->compare_state;
		copy.stack_address_taken = registers->stack_address_taken;
		queue_instruction(&search->queue, addr, required_effects, &copy, addr, "varying ancestors");
	}
	return result;
}

__attribute__((nonnull(1, 2))) static uint16_t index_for_callback_and_data(struct searched_instructions *search, instruction_reached_callback callback, void *callback_data)
{
	int count = search->callback_count;
	for (int i = 1; i < count; i++) {
		if (callback == search->callbacks[i].callback && callback_data == search->callbacks[i].data) {
			return i;
		}
	}
	if (count == 0) {
		// index of 0 is used to represent no callback
		count++;
	}
	search->callbacks = realloc(search->callbacks, (count + 1) * sizeof(struct searched_instruction_callback));
	search->callbacks[count] = (struct searched_instruction_callback){
		.callback = callback,
		.data = callback_data,
	};
	search->callback_count = count + 1;
	return count;
}

__attribute__((nonnull(1, 2))) static char *copy_block_entry_description(const struct loader_context *loader, ins_ptr target, const struct registers *registers)
{
	register_mask mask = 0;
	for (int r = 0; r < REGISTER_COUNT; r++) {
		if (register_is_partially_known(&registers->registers[r])) {
			mask |= mask_for_register(r);
		}
	}
	char *name = copy_address_description(loader, target);
	if (mask == 0) {
		return name;
	}
	size_t name_len = fs_strlen(name);
	char *description = copy_registers_description(loader, registers, mask);
	size_t description_len = fs_strlen(description);
	char *buf = malloc(name_len + description_len + 1);
	fs_memcpy(buf, name, name_len);
	free(name);
	fs_memcpy(&buf[name_len], description, description_len);
	free(description);
	buf[name_len + description_len] = '\0';
	return buf;
}

void log_basic_blocks(const struct program_state *analysis, function_effects required_effects)
{
	struct registers state = {0};
	struct searched_instruction_entry *table = analysis->search.table;
	uint32_t count = analysis->search.mask + 1;
	for (uint32_t i = 0; i < count; i++) {
		struct searched_instruction_entry *entry = &table[i];
		if (entry->address != NULL) {
			struct searched_instruction_data *data = entry->data;
			size_t end_offset = data->end_offset;
			for (size_t offset = 0; offset < end_offset;) {
				struct searched_instruction_data_entry *data_entry = entry_for_offset(data, offset);
				if ((data_entry->effects & required_effects) == required_effects) {
					expand_registers(state.registers, data_entry);
					ERROR_NOPREFIX("block", temp_str(copy_block_entry_description(&analysis->loader, entry->address, &state)));
				}
				offset += sizeof_searched_instruction_data_entry(data_entry);
			}
		}
	}
}

__attribute__((nonnull(1, 2, 7))) static void find_and_add_callback(struct program_state *analysis, ins_ptr addr, register_mask relevant_registers, register_mask preserved_registers, register_mask preserved_and_kept_registers,
                                                                    function_effects additional_effects, instruction_reached_callback callback, void *callback_data)
{
	struct effect_token token;
	struct searched_instruction_data *data = find_searched_instruction_table_entry(&analysis->search, addr, &token)->data;
	data->sticky_effects |= additional_effects & ~EFFECT_PROCESSING;
	data->relevant_registers |= relevant_registers;
	data->preserved_registers |= preserved_registers;
	data->preserved_and_kept_registers |= preserved_and_kept_registers;
	data->callback_index = index_for_callback_and_data(&analysis->search, callback, callback_data);
	uint32_t end_offset = data->end_offset;
	if (end_offset != 0) {
		struct analysis_frame self = {
			.address = addr,
			.description = "add callback",
			.next = NULL,
			.entry = addr,
			.token = {0},
			.current_state = empty_registers,
		};
		self.entry_state = &self.current_state;
		char *copy = malloc(end_offset);
		fs_memcpy(copy, data->entries, end_offset);
		for (uint32_t offset = 0; offset < end_offset;) {
			token.entry_offset = offset;
			struct searched_instruction_data_entry *entry = (struct searched_instruction_data_entry *)&copy[offset];
			token.entry_generation = entry->generation;
			expand_registers(self.current_state.registers, entry);
			LOG("invoking callback on existing entry: ", temp_str(copy_block_entry_description(&analysis->loader, addr, &self.current_state)));
			callback(analysis, addr, &self.current_state, entry->effects, &self, &token, callback_data);
			offset += sizeof_searched_instruction_data_entry(entry);
		}
		free(copy);
	}
}

struct loaded_binary *find_loaded_binary(const struct loader_context *context, const char *path)
{
	unsigned long hash = elf_hash((const unsigned char *)path);
	for (struct loaded_binary *binary = context->binaries; binary != NULL; binary = binary->next) {
		if (hash == binary->path_hash && fs_strcmp(path, binary->path) == 0) {
			return binary;
		}
	}
	return NULL;
}

__attribute__((nonnull(1))) const struct recorded_syscall *find_recorded_syscall(const struct recorded_syscalls *syscalls, uintptr_t nr)
{
	for (int i = 0; i < syscalls->count; i++) {
		if (syscalls->list[i].nr == nr) {
			return &syscalls->list[i];
		}
	}
	return NULL;
}

__attribute__((nonnull(1, 2))) static int load_debuglink(const struct loader_context *loader, struct loaded_binary *binary, bool force_loading);

__attribute__((nonnull(1, 2, 3))) void *resolve_binary_loaded_symbol(const struct loader_context *loader, struct loaded_binary *binary, const char *name, const char *version_name, int symbol_types, const ElfW(Sym) * *out_symbol)
{
	if ((symbol_types & NORMAL_SYMBOL) && binary->has_symbols) {
		const struct symbol_info *symbols = &binary->symbols;
		void *result = find_symbol(&binary->info, symbols, name, version_name, out_symbol);
		if (result != NULL) {
			return result;
		}
	}
	if ((symbol_types & LINKER_SYMBOL) && binary->has_linker_symbols) {
		const struct symbol_info *symbols = &binary->linker_symbols;
		void *result = find_symbol(&binary->info, symbols, name, version_name, out_symbol);
		if (result != NULL) {
			return result;
		}
	}
	if (symbol_types & DEBUG_SYMBOL) {
		if (!binary->has_debuglink_symbols) {
			if ((symbol_types & DEBUG_SYMBOL_FORCING_LOAD) == DEBUG_SYMBOL_FORCING_LOAD) {
				// cast away const, since logically this function can be thought of as not really
				// modifying loader
				if (load_debuglink((struct loader_context *)loader, binary, true) != 0) {
					return NULL;
				}
			} else {
				return NULL;
			}
		}
		const struct symbol_info *symbols = &binary->debuglink_symbols;
		void *result = find_symbol(&binary->info, symbols, name, version_name, out_symbol);
		if (result != NULL) {
			return result;
		}
	}
	return NULL;
}

void *resolve_loaded_symbol(const struct loader_context *context, const char *name, const char *version_name, int symbol_types, struct loaded_binary **out_binary, const ElfW(Sym) * *out_symbol)
{
	for (struct loaded_binary *binary = context->last; binary != NULL; binary = binary->previous) {
		void *result = resolve_binary_loaded_symbol(context, binary, name, version_name, symbol_types, out_symbol);
		if (result != NULL) {
			if (out_binary != NULL) {
				*out_binary = binary;
			}
			return result;
		}
	}
	return NULL;
}

__attribute__((nonnull(1, 2, 3))) static inline ins_ptr update_known_function(struct program_state *analysis, struct loaded_binary *binary, const char *name, int symbol_locations, function_effects effects)
{
	ins_ptr addr = resolve_binary_loaded_symbol(&analysis->loader, binary, name, NULL, symbol_locations, NULL);
	if (addr == NULL) {
		return addr;
	}
	LOG("found known function ", name, " at ", temp_str(copy_address_description(&analysis->loader, addr)));
	struct effect_token token;
	if (effects == EFFECT_STICKY_EXITS) {
		struct searched_instruction_entry *table_entry = find_searched_instruction_table_entry(&analysis->search, addr, &token);
		table_entry->data->sticky_effects |= EFFECT_STICKY_EXITS;
		for (uint32_t offset = 0; offset < table_entry->data->end_offset;) {
			struct searched_instruction_data_entry *entry = entry_for_offset(table_entry->data, offset);
			entry->effects = EFFECT_EXITS | EFFECT_STICKY_EXITS | (entry->effects & ~EFFECT_RETURNS);
			offset += sizeof_searched_instruction_data_entry(entry);
		}
	} else {
		struct registers empty = empty_registers;
		*get_or_populate_effects(analysis, addr, &empty, effects, &token) = effects;
	}
	return addr;
}

static void handle_forkAndExecInChild1(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects,
                                       __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered forkAndExecInChild1 call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	if ((analysis->syscalls.config[SYS_execve] & SYSCALL_CONFIG_BLOCK) == 0) {
		ERROR("program calls execve. unable to analyze through execs. if you know your use of this program doesn't result in new programs being executed specify --block-syscall execve");
		ERROR_FLUSH();
		fs_exit(1);
	}
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_EXITS | EFFECT_ENTER_CALLS, 0);
	add_blocked_symbol(&analysis->known_symbols, "syscall.forkAndExecInChild1", 0, true)->value = ins;
}

struct musl_setxid_wrapper
{
	const char *name;
	int nr;
	int argc;
};

static void handle_musl_setxid(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects,
                               __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, void *data)
{
	LOG("encountered musl __setxid call: ", temp_str(copy_address_description(&analysis->loader, ins)));
	if (analysis->loader.setxid_sighandler_syscall != NULL) {
		struct analysis_frame self = {
			.address = analysis->loader.setxid_sighandler_syscall,
			.description = "syscall",
			.next = caller,
			.entry = caller->address,
			.entry_state = &caller->current_state,
			.token = {0},
			.current_state = empty_registers,
		};
		const struct musl_setxid_wrapper *wrapper = data;
		uintptr_t nr;
		if (wrapper == NULL) {
			int arg0index = sysv_argument_abi_register_indexes[0];
			if (!register_is_exactly_known(&state->registers[arg0index])) {
				DIE("musl __setxid with unknown nr argument: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
			}
			nr = caller->current_state.registers[arg0index].value;
			for (int i = 0; i < 3; i++) {
				self.current_state.registers[syscall_argument_abi_register_indexes[i]] = caller->current_state.registers[sysv_argument_abi_register_indexes[i + 1]];
			}
		} else {
			nr = wrapper->nr;
			if (wrapper->argc < 0) {
				// setegid/seteuid
				set_register(&self.current_state.registers[syscall_argument_abi_register_indexes[0]], -1);
				self.current_state.registers[syscall_argument_abi_register_indexes[1]] = caller->current_state.registers[sysv_argument_abi_register_indexes[0]];
				set_register(&self.current_state.registers[syscall_argument_abi_register_indexes[2]], -1);
			} else {
				// all other setxid wrappers
				for (int i = 0; i < wrapper->argc; i++) {
					self.current_state.registers[syscall_argument_abi_register_indexes[i]] = caller->current_state.registers[sysv_argument_abi_register_indexes[i]];
				}
			}
		}
		set_register(&self.current_state.registers[REGISTER_SYSCALL_NR], nr);
		record_syscall(analysis, wrapper->nr, self, effects);
	}
}

__attribute__((nonnull(1, 2, 3))) void analyze_function_symbols(struct program_state *analysis, const struct loaded_binary *binary, const struct symbol_info *symbols, struct analysis_frame *caller)
{
	for (size_t i = 0; i < symbols->symbol_count; i++) {
		const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbols->symbols + i * symbols->symbol_stride);
		if (ELF64_ST_BIND(symbol->st_info) == STB_GLOBAL && ELF64_ST_TYPE(symbol->st_info) == STT_FUNC) {
			ins_ptr ins = (ins_ptr)apply_base_address(&binary->info, symbol->st_value);
			if (protection_for_address_in_binary(binary, (uintptr_t)ins, NULL) & PROT_EXEC) {
				const char *name = symbol_name(symbols, symbol);
				LOG("symbol ", name, " contains executable code that might be dlsym'ed");
				struct analysis_frame new_caller = {
					.address = ins,
					.description = name,
					.next = caller,
					.current_state = empty_registers,
					.entry = binary->info.base,
					.entry_state = &empty_registers,
					.token = {0},
				};
				analyze_function(analysis, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &new_caller.current_state, ins, &new_caller);
			} else {
				LOG("symbol ", symbol_name(symbols, symbol), " is not executable");
			}
		} else {
			if (ELF64_ST_BIND(symbol->st_info) != STB_GLOBAL) {
				LOG("symbol ", symbol_name(symbols, symbol), " is not global");
			} else {
				LOG("symbol ", symbol_name(symbols, symbol), " is not a function");
			}
		}
	}
}

static const char *apply_loader_sysroot(const struct loader_context *loader, const char *path, char buf[PATH_MAX])
{
	return apply_sysroot(loader->sysroot, path, buf);
}

static int loader_find_executable_in_sysrooted_paths(const struct loader_context *loader, const char *name, const char *paths, bool require_executable, char buf[PATH_MAX], const char **out_path)
{
	if (loader->sysroot == NULL) {
		return find_executable_in_paths(name, paths, require_executable, loader->uid, loader->gid, buf, out_path);
	}
	if (*name == '/') {
		return find_executable_in_paths(apply_loader_sysroot(loader, name, buf), NULL, require_executable, loader->uid, loader->gid, buf, out_path);
	}
	size_t sysroot_len = fs_strlen(loader->sysroot);
	size_t length = sysroot_len;
	size_t i = 0;
	for (;;) {
		if (paths[i] == '\0') {
			break;
		}
		if (paths[i] == ':') {
			length += sysroot_len;
		}
		i++;
	}
	length += i;
	char *new_paths = malloc(length + 1);
	fs_memcpy(new_paths, loader->sysroot, sysroot_len);
	size_t p = sysroot_len;
	for (i = 0;;) {
		char c = paths[i];
		new_paths[p] = c;
		if (c == '\0') {
			break;
		}
		i++;
		p++;
		if (c == ':') {
			fs_memcpy(&new_paths[p], loader->sysroot, sysroot_len);
			p += sysroot_len;
		}
	}
	int result = find_executable_in_paths(name, new_paths, require_executable, loader->uid, loader->gid, buf, out_path);
	free(new_paths);
	return result;
}

static struct loaded_binary *register_dlopen_file(struct program_state *analysis, const char *path, const struct analysis_frame *caller, enum dlopen_options options)
{
	struct loaded_binary *binary = find_loaded_binary(&analysis->loader, path);
	if (binary == NULL) {
		char buf[PATH_MAX];
		const char *full_path;
		int needed_fd = loader_find_executable_in_sysrooted_paths(&analysis->loader, path, "/lib/" ARCH_NAME "-linux-gnu:/lib:/usr/lib", false, buf, &full_path);
		if (needed_fd < 0) {
			LOG("failed to find dlopen'ed pathm \"", path, "\", assuming it will fail at runtime");
			return NULL;
		}
		struct loaded_binary *new_binary;
		int result = load_binary_into_analysis(analysis, path, full_path, needed_fd, NULL, &new_binary);
		fs_close(needed_fd);
		if (result < 0) {
			LOG("failed to load dlopen'ed path, \"", path, "\", assuming it will fail at runtime");
			return NULL;
		}
		new_binary->special_binary_flags |= BINARY_IS_LOADED_VIA_DLOPEN;
		result = load_all_needed_and_relocate(analysis);
		if (result < 0) {
			LOG("failed to load all needed for dlopen");
			return NULL;
		}
		for (struct loaded_binary *other = analysis->loader.binaries; other != NULL; other = other->next) {
			if (other->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_LIBC)) {
				result = finish_loading_binary(analysis, other, EFFECT_NONE, (options & DLOPEN_OPTION_ANALYZE_CODE) == 0);
				if (result != 0) {
					ERROR("failed to load interpreter or libc: ", other->path);
					return NULL;
				}
			}
		}
		result = finish_loading_binary(analysis, new_binary, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, (options & DLOPEN_OPTION_ANALYZE_CODE) == 0);
		if (result != 0) {
			LOG("failed to finish loading dlopen'ed path, \"", path, "\", assuming it will fail at runtime");
			return NULL;
		}
		binary = new_binary;
	} else if (binary->special_binary_flags & BINARY_HAS_FUNCTION_SYMBOLS_ANALYZED) {
		return binary;
	}
	if (options & DLOPEN_OPTION_ANALYZE_SYMBOLS) {
		binary->special_binary_flags |= BINARY_HAS_FUNCTION_SYMBOLS_ANALYZED;
		struct analysis_frame dlopen_caller = {.address = binary->info.base, .description = "dlopen", .next = caller, .current_state = empty_registers, .entry = binary->info.base, .entry_state = &empty_registers, .token = {0}};
		if (binary->has_symbols) {
			LOG("analyzing symbols for ", path);
			analyze_function_symbols(analysis, binary, &binary->symbols, &dlopen_caller);
		} else {
			LOG("skipping analyzing symbols for ", path);
		}
		if (binary->has_linker_symbols) {
			LOG("analyzing linker symbols for ", path);
			analyze_function_symbols(analysis, binary, &binary->linker_symbols, &dlopen_caller);
		} else {
			LOG("skipping linker analyzing symbols for ", path);
		}
	} else {
		LOG("skipping symbol analysis for ", path);
	}
	return binary;
}

struct loaded_binary *register_dlopen_file_owning_path(struct program_state *analysis, char *path, const struct analysis_frame *caller, enum dlopen_options options)
{
	struct loaded_binary *binary = register_dlopen_file(analysis, path, caller, options);
	if (!binary) {
		free(path);
	} else if (binary->path == path) {
		binary->owns_path = true;
	} else {
		free(path);
	}
	return binary;
}

static void handle_gconv_find_shlib(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                    struct effect_token *token, __attribute__((unused)) void *data);

__attribute__((nonnull(1, 2))) static ins_ptr find_function_entry(struct loader_context *loader, ins_ptr ins)
{
	struct loaded_binary *binary = binary_for_address(loader, ins);
	if (binary != NULL) {
		if (binary->has_frame_info) {
			struct frame_details result;
			if (find_containing_frame_info(&binary->frame_info, ins, &result)) {
				return result.address;
			}
		}
	}
	return NULL;
}

static void load_openssl_modules(struct program_state *analysis, const struct analysis_frame *caller)
{
	register_dlopen(analysis, "/lib/" ARCH_NAME "-linux-gnu/ossl-modules", caller, DLOPEN_OPTION_ANALYZE | DLOPEN_OPTION_RECURSE_INTO_FOLDERS | DLOPEN_OPTION_IGNORE_ENOENT);
	register_dlopen(analysis, "/lib/engines-3", caller, DLOPEN_OPTION_ANALYZE | DLOPEN_OPTION_RECURSE_INTO_FOLDERS | DLOPEN_OPTION_IGNORE_ENOENT);
	register_dlopen(analysis, "/lib64/engines-3", caller, DLOPEN_OPTION_ANALYZE | DLOPEN_OPTION_RECURSE_INTO_FOLDERS | DLOPEN_OPTION_IGNORE_ENOENT);
	register_dlopen(analysis, "/usr/lib64/openssl/engines", caller, DLOPEN_OPTION_ANALYZE | DLOPEN_OPTION_RECURSE_INTO_FOLDERS | DLOPEN_OPTION_IGNORE_ENOENT);
}

static void load_nss_libraries(struct program_state *analysis, const struct analysis_frame *caller);

static void handle_dlopen(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, const struct analysis_frame *caller, struct effect_token *token,
                          __attribute__((unused)) void *data)
{
	if (effects == EFFECT_NONE) {
		LOG("encountered dlopen call with no effects: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
		return;
	}
	LOG("encountered dlopen call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)), " with effects: ", (uintptr_t)effects);
	struct register_state *first_arg = &state->registers[sysv_argument_abi_register_indexes[0]];
	if (!register_is_exactly_known(first_arg)) {
		const struct loaded_binary *binary = binary_for_address(&analysis->loader, caller->address);
		if (binary_has_flags(binary, BINARY_IS_LIBP11KIT)) {
			register_dlopen(analysis, "/lib/" ARCH_NAME "-linux-gnu/pkcs11", caller, DLOPEN_OPTION_ANALYZE | DLOPEN_OPTION_RECURSE_INTO_FOLDERS | DLOPEN_OPTION_IGNORE_ENOENT);
			return;
		}
		if (binary_has_flags(binary, BINARY_IS_LIBKRB5)) {
			register_dlopen(analysis, "/lib/" ARCH_NAME "-linux-gnu/krb5/plugins", caller, DLOPEN_OPTION_ANALYZE | DLOPEN_OPTION_RECURSE_INTO_FOLDERS | DLOPEN_OPTION_IGNORE_ENOENT);
			return;
		}
		if (binary_has_flags(binary, BINARY_IS_LIBSASL2)) {
			register_dlopen(analysis, "/usr/lib/" ARCH_NAME "-linux-gnu/sasl2", caller, DLOPEN_OPTION_ANALYZE | DLOPEN_OPTION_RECURSE_INTO_FOLDERS | DLOPEN_OPTION_IGNORE_ENOENT);
			return;
		}
		if (binary_has_flags(binary, BINARY_IS_LIBCRYPTO)) {
			load_openssl_modules(analysis, caller);
			return;
		}
		ins_ptr nss_module_load = analysis->loader.nss_module_load;
		if (binary_has_flags(binary, BINARY_IS_LIBC) && nss_module_load != NULL) {
			for (const struct analysis_frame *c = caller; c != NULL; c = c->next) {
				if (c->entry == nss_module_load) {
					LOG("encountered dlopen from nss_module_load");
					load_nss_libraries(analysis, caller);
					return;
				}
			}
		}
		// check if we're searching for gconv and if so attach handle_gconv_find_shlib as callback
		if (analysis->loader.searching_gconv_dlopen || analysis->loader.searching_libcrypto_dlopen) {
			struct analysis_frame self = {
				.address = ins,
				.description = NULL,
				.next = caller,
				.entry = ins,
				.entry_state = state,
				.token = *token,
			};
			vary_effects_by_registers(&analysis->search,
			                          &analysis->loader,
			                          &self,
			                          mask_for_register(sysv_argument_abi_register_indexes[0]),
			                          mask_for_register(sysv_argument_abi_register_indexes[0]),
			                          mask_for_register(sysv_argument_abi_register_indexes[0]),
			                          EFFECT_PROCESSED);
			find_and_add_callback(analysis, find_function_entry(&analysis->loader, caller->entry) ?: caller->entry, 0, 0, 0, EFFECT_NONE, handle_gconv_find_shlib, NULL);
			if (analysis->loader.searching_gconv_dlopen) {
				analysis->loader.gconv_dlopen = ins;
			}
			if (analysis->loader.searching_libcrypto_dlopen) {
				analysis->loader.libcrypto_dlopen = ins;
				load_openssl_modules(analysis, caller);
			}
			analysis->loader.searching_gconv_dlopen = analysis->loader.searching_libcrypto_dlopen = false;
			return;
		}
		if (analysis->loader.ignore_dlopen) {
			LOG("dlopen with indeterminate value: ", temp_str(copy_register_state_description(&analysis->loader, *first_arg)));
			LOG("call stack: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
			return;
		}
		ERROR("dlopen with indeterminate value: ", temp_str(copy_register_state_description(&analysis->loader, *first_arg)));
		DIE("call stack: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	}
	const char *needed_path = (const char *)first_arg->value;
	if (needed_path == NULL) {
		LOG("dlopen with NULL");
		return;
	}
	struct loaded_binary *binary;
	int prot = protection_for_address(&analysis->loader, needed_path, &binary, NULL);
	if ((prot & PROT_READ) == 0) {
		ERROR("dlopen with constant, but unreadable value: ", temp_str(copy_address_description(&analysis->loader, needed_path)));
		DIE("call stack: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	}
	LOG("dlopen with constant path: ", needed_path);
	struct analysis_frame self = {
		.description = NULL,
		.next = caller,
		.entry = ins,
		.entry_state = state,
		.token = *token,
	};
	vary_effects_by_registers(&analysis->search,
	                          &analysis->loader,
	                          &self,
	                          mask_for_register(sysv_argument_abi_register_indexes[0]),
	                          mask_for_register(sysv_argument_abi_register_indexes[0]),
	                          mask_for_register(sysv_argument_abi_register_indexes[0]),
	                          EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS);
	register_dlopen_file(analysis, needed_path, caller, DLOPEN_OPTION_ANALYZE);
}

static void handle_gconv_find_shlib(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                    struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered gconv_find_shlib call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	struct analysis_frame self = {
		.description = NULL,
		.next = caller,
		.entry = ins,
		.entry_state = state,
		.token = *token,
	};
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_RETURNS | EFFECT_ENTER_CALLS, 0);
	*token = self.token;
	if (analysis->loader.loaded_gconv_libraries) {
		return;
	}
	analysis->loader.loaded_gconv_libraries = true;
	char gconv_buf[PATH_MAX];
	const char *gconv_path = apply_loader_sysroot(&analysis->loader, "/usr/lib/" ARCH_NAME "-linux-gnu/gconv", gconv_buf);
	int dirfd = fs_open(gconv_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	if (dirfd < 0) {
		if (dirfd == -ENOENT) {
			gconv_path = apply_loader_sysroot(&analysis->loader, "/lib64/gconv", gconv_buf);
			dirfd = fs_open(gconv_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
		}
		if (dirfd == -ENOENT) {
			gconv_path = apply_loader_sysroot(&analysis->loader, "/usr/lib64/gconv", gconv_buf);
			dirfd = fs_open(gconv_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
		}
		if (dirfd < 0) {
			if (dirfd == -ENOENT) {
				return;
			}
			DIE("failed to open gconv library path: ", as_errno(dirfd));
		}
	}
	size_t gconv_path_len = fs_strlen(gconv_path);
	for (;;) {
		char buf[8192];
		int count = fs_getdents(dirfd, (struct fs_dirent *)&buf[0], sizeof(buf));
		if (count <= 0) {
			if (count < 0) {
				DIE("failed to read gconv library entries: ", as_errno(count));
			}
			break;
		}
		for (int offset = 0; offset < count;) {
			const struct fs_dirent *ent = (const struct fs_dirent *)&buf[offset];
			const char *name = ent->d_name;
			const char *needle = ".so";
			if (name[0] != 'l' || name[1] != 'i' || name[2] != 'b') {
				for (const char *haystack = name;;) {
					if (*haystack == *needle) {
						if (*needle == '\0') {
							size_t suffix_len = haystack - name;
							char *path = malloc(gconv_path_len + 2 + suffix_len);
							char *path_buf = path;
							fs_memcpy(path_buf, gconv_path, gconv_path_len);
							path_buf += gconv_path_len;
							*path_buf++ = '/';
							fs_memcpy(path_buf, name, suffix_len + 1);
							LOG("found gconv library: ", path);
							register_dlopen_file_owning_path(analysis, path, caller, 0);
						}
						needle++;
					} else {
						needle = ".so";
					}
					if (*haystack == '\0') {
						break;
					}
					haystack++;
				}
			}
			offset += ent->d_reclen;
		}
	}
	fs_close(dirfd);
}

__attribute__((nonnull(1, 2, 3))) static void discovered_nss_provider(struct program_state *analysis, const struct analysis_frame *caller, const char *provider)
{
	size_t len = fs_strlen(provider);
	char *library_name = malloc(len + sizeof("libnss_.so.2"));
	char *buf = library_name;
	*buf++ = 'l';
	*buf++ = 'i';
	*buf++ = 'b';
	*buf++ = 'n';
	*buf++ = 's';
	*buf++ = 's';
	*buf++ = '_';
	fs_memcpy(buf, provider, len);
	buf += len;
	*buf++ = '.';
	*buf++ = 's';
	*buf++ = 'o';
	*buf++ = '.';
	*buf++ = '2';
	*buf++ = '\0';
	register_dlopen_file_owning_path(analysis, library_name, caller, DLOPEN_OPTION_ANALYZE);
}

__attribute__((nonnull(1, 2))) static void load_nss_libraries(struct program_state *analysis, const struct analysis_frame *caller)
{
	if (analysis->loader.loaded_nss_libraries) {
		return;
	}
	analysis->loader.loaded_nss_libraries = true;
	char path_buf[PATH_MAX];
	int nsswitch_fd = fs_open(apply_loader_sysroot(&analysis->loader, "/etc/nsswitch.conf", path_buf), O_RDONLY | O_CLOEXEC, 0);
	if (nsswitch_fd < 0) {
		DIE("nsswitch used, but unable to open nsswitch configuration: ", as_errno(nsswitch_fd));
	}
	struct fs_stat stat;
	int result = fs_fstat(nsswitch_fd, &stat);
	if (result < 0) {
		DIE("nsswitch used, but unable to stat nsswitch configuration: ", as_errno(result));
	}
	char *buf = malloc(stat.st_size + 1);
	result = fs_read(nsswitch_fd, buf, stat.st_size);
	fs_close(nsswitch_fd);
	if (result != stat.st_size) {
		if (result < 0) {
			DIE("nsswitch used, but unable to read nsswitch configuration: ", as_errno(result));
		}
		DIE("nsswitch used, but wrong number of bytes read for nsswitch configuration: ", result);
	}
	buf[stat.st_size] = '\0';
	bool found_hash = false;
	bool found_colon = false;
	int token_start = 0;
	for (int i = 0; i <= stat.st_size; i++) {
		switch (buf[i]) {
			case '\n':
			case '\0':
				// newline
				if (token_start != 0) {
					buf[i] = '\0';
					discovered_nss_provider(analysis, caller, &buf[token_start]);
					token_start = 0;
				}
				found_hash = false;
				found_colon = false;
				break;
			case '\t':
			case ' ':
				// space
				if (token_start != 0) {
					buf[i] = '\0';
					discovered_nss_provider(analysis, caller, &buf[token_start]);
					token_start = 0;
				}
				break;
			case '#':
				// hash
				if (token_start != 0) {
					buf[i] = '\0';
					discovered_nss_provider(analysis, caller, &buf[token_start]);
					token_start = 0;
				}
				found_hash = true;
				found_colon = false;
				break;
			case ':':
				// colon
				if (!found_hash) {
					found_colon = true;
				}
				break;
			default:
				if (found_colon && token_start == 0) {
					token_start = i;
				}
				break;
		}
	}
	free(buf);
}

static void handle_nss_usage(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects,
                             __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered nss call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	load_nss_libraries(analysis, caller);
}

static const char *find_any_symbol_name_by_address(const struct loader_context *loader, struct loaded_binary *binary, const void *addr, int symbol_types)
{
	if (binary != NULL) {
		const struct symbol_info *symbols;
		const ElfW(Sym) * symbol;
		if (find_any_symbol_by_address(loader, binary, addr, symbol_types, &symbols, &symbol) != NULL) {
			return symbol_name(symbols, symbol);
		}
	}
	return NULL;
}

static bool has_same_binary_caller_symbol_named(const struct loader_context *loader, const struct analysis_frame *caller, const char *name)
{
	const struct loaded_binary *required_binary = binary_for_address(loader, caller->entry);
	if (required_binary == NULL) {
		return false;
	}
	const ElfW(Sym) *symbol;
	void *result = find_symbol(&required_binary->info, &required_binary->symbols, name, NULL, &symbol);
	if (result == NULL) {
		return false;
	}
	size_t size = symbol->st_size;
	for (const struct loaded_binary *binary = required_binary;;) {
		if ((void *)caller->entry >= result && (void *)caller->entry < result + size) {
			// normal symbols with proper size information
			return true;
		}
		if (size == 0 && caller->entry == result) {
			// symbols without a size, but with a starting address
			return true;
		}
		caller = caller->next;
		if (caller == NULL) {
			return false;
		}
		binary = binary_for_address(loader, caller->entry);
		if (binary != required_binary) {
			return false;
		}
	}
}

static void handle_mprotect(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                            __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// block creating executable stacks
	LOG("encountered mprotect call: ", temp_str(copy_function_call_description(&analysis->loader, ins, state)));
	int third_arg = sysv_argument_abi_register_indexes[2];
	if (!register_is_exactly_known(&state->registers[third_arg]) || state->registers[third_arg].value == (PROT_READ | PROT_WRITE | PROT_EXEC)) {
		if (caller != NULL) {
			struct loaded_binary *binary = binary_for_address(&analysis->loader, caller->entry);
			const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, caller->entry, NORMAL_SYMBOL);
			if (name != NULL && (fs_strcmp(name, "pthread_create") == 0 || fs_strcmp(name, "__nptl_change_stack_perm") == 0)) {
				LOG("from within pthread_create, forcing PROT_READ|PROT_WRITE: ", temp_str(copy_address_description(&analysis->loader, caller->entry)));
				set_register(&state->registers[third_arg], PROT_READ | PROT_WRITE);
			} else if (has_same_binary_caller_symbol_named(&analysis->loader, caller, "malloc") && state->registers[third_arg].value == (PROT_READ | PROT_WRITE)) {
				LOG("from within malloc, forcing PROT_READ|PROT_WRITE: ", temp_str(copy_address_description(&analysis->loader, caller->entry)));
				set_register(&state->registers[third_arg], PROT_READ | PROT_WRITE);
			}
		}
	}
}

static void handle_mmap(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                        __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// block creating executable stacks
	LOG("encountered mmap call: ", temp_str(copy_function_call_description(&analysis->loader, ins, state)));
	int third_arg = sysv_argument_abi_register_indexes[2];
	int fourth_arg = sysv_argument_abi_register_indexes[3];
	struct loaded_binary *binary = binary_for_address(&analysis->loader, caller->entry);
	if (!register_is_exactly_known(&state->registers[third_arg]) || state->registers[third_arg].value == (PROT_READ | PROT_WRITE | PROT_EXEC)) {
		if (register_is_exactly_known(&state->registers[fourth_arg])) {
			if ((state->registers[fourth_arg].value & LINUX_MAP_STACK) == LINUX_MAP_STACK) {
				if (caller != NULL) {
					const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, caller->entry, NORMAL_SYMBOL);
					if (name != NULL && fs_strcmp(name, "pthread_create") == 0) {
						LOG("from within pthread_create, forcing PROT_READ|PROT_WRITE: ", temp_str(copy_address_description(&analysis->loader, caller->entry)));
						set_register(&state->registers[third_arg], PROT_READ | PROT_WRITE);
						clear_match(&analysis->loader, state, third_arg, ins);
					} else {
						if (binary_has_flags(binary, BINARY_IS_LIBC)) {
							if (has_same_binary_caller_symbol_named(&analysis->loader, caller, "posix_spawnp") || has_same_binary_caller_symbol_named(&analysis->loader, caller, "posix_spawn")) {
								LOG("from within posix_spawn, forcing PROT_READ|PROT_WRITE: ", temp_str(copy_address_description(&analysis->loader, caller->entry)));
								set_register(&state->registers[third_arg], PROT_READ | PROT_WRITE);
								clear_match(&analysis->loader, state, third_arg, ins);
							}
						}
					}
				}
			}
		}
		if (state->registers[third_arg].value == (PROT_READ | PROT_WRITE)) {
			if (binary_has_flags(binary, BINARY_IS_LIBC) && has_same_binary_caller_symbol_named(&analysis->loader, caller, "malloc")) {
				LOG("from within malloc, forcing PROT_READ|PROT_WRITE: ", temp_str(copy_address_description(&analysis->loader, caller->entry)));
				set_register(&state->registers[third_arg], PROT_READ | PROT_WRITE);
				clear_match(&analysis->loader, state, third_arg, ins);
			}
		}
	}
	if (state->registers[fourth_arg].value == (MAP_PRIVATE | MAP_ANONYMOUS) && (uint32_t)state->registers[fourth_arg].max == ~(uint32_t)0) {
		if (binary_has_flags(binary, BINARY_IS_LIBC) && has_same_binary_caller_symbol_named(&analysis->loader, caller, "malloc")) {
			LOG("from within malloc, forcing MAP_PRIVATE|MAP_ANONYMOUS: ", temp_str(copy_address_description(&analysis->loader, caller->entry)));
			if (analysis->glibc_tunables == NULL) {
				set_register(&state->registers[fourth_arg], MAP_PRIVATE | MAP_ANONYMOUS);
				clear_match(&analysis->loader, state, third_arg, ins);
			} else {
				LOG("skipping forcing MAP_PRIVATE|MAP_ANONYMOUS due to the presence of GLIBC_TUNABLES: ", analysis->glibc_tunables);
			}
		}
	}
}

static void handle_change_stack_perm(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                            __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	set_effects(&analysis->search, ins, token, (effects & ~EFFECT_PROCESSING) | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, 0);
}

static void handle_IO_file_fopen(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                 __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// record fopen mode arguments
	size_t i = analysis->search.fopen_mode_count;
	size_t count = i + 1;
	analysis->search.fopen_modes = realloc(analysis->search.fopen_modes, sizeof(*analysis->search.fopen_modes) * count);
	analysis->search.fopen_mode_count = count;
	int mode_arg = sysv_argument_abi_register_indexes[2];
	analysis->search.fopen_modes[i] = state->registers[mode_arg];
}

static void handle_IO_file_open(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// parse previously recorded fopen mode
	size_t count = analysis->search.fopen_mode_count;
	if (count == 0) {
		return;
	}
	if (!register_is_exactly_known(&analysis->search.fopen_modes[count - 1])) {
		return;
	}
	const char *mode_str = (const char *)analysis->search.fopen_modes[count - 1].value;
	struct loaded_binary *binary;
	int prot = protection_for_address(&analysis->loader, mode_str, &binary, NULL);
	if ((prot & (PROT_READ | PROT_WRITE)) != PROT_READ) {
		return;
	}
	int mode;
	int flags = 0;
	switch (mode_str[0]) {
		case 'r':
			mode = LINUX_O_RDONLY;
			break;
		case 'w':
			mode = LINUX_O_WRONLY;
			break;
		case 'a':
			mode = LINUX_O_WRONLY;
			flags = LINUX_O_CREAT | LINUX_O_APPEND;
			break;
		default:
			return;
	}
	for (int i = 1; i < 7; ++i) {
		switch (mode_str[i]) {
			case '\0':
				break;
			case '+':
				mode = LINUX_O_RDWR;
				continue;
			case 'x':
				flags |= LINUX_O_EXCL;
				continue;
			case 'b':
				continue;
			case 'm':
				continue;
			case 'c':
				continue;
			case 'e':
				flags |= LINUX_O_CLOEXEC;
				continue;
			default:
				continue;
		}
		break;
	}
	int mode_arg = sysv_argument_abi_register_indexes[2];
	set_register(&state->registers[mode_arg], mode | flags);
}

static void handle_fopen(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                         __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// record fopen mode arguments
	size_t i = analysis->search.fopen_mode_count;
	size_t count = i + 1;
	analysis->search.fopen_modes = realloc(analysis->search.fopen_modes, sizeof(*analysis->search.fopen_modes) * count);
	analysis->search.fopen_mode_count = count;
	int mode_arg = sysv_argument_abi_register_indexes[1];
	analysis->search.fopen_modes[i] = state->registers[mode_arg];
}

static int musl_fmodeflags(const char *mode)
{
	int flags;
	if (*fs_strchr(mode, '+'))
		flags = LINUX_O_RDWR;
	else if (*mode == 'r')
		flags = LINUX_O_RDONLY;
	else
		flags = LINUX_O_WRONLY;
	if (*fs_strchr(mode, 'x'))
		flags |= LINUX_O_EXCL;
	if (*fs_strchr(mode, 'e'))
		flags |= LINUX_O_CLOEXEC;
	if (*mode != 'r')
		flags |= LINUX_O_CREAT;
	if (*mode == 'w')
		flags |= LINUX_O_TRUNC;
	if (*mode == 'a')
		flags |= LINUX_O_APPEND;
	return flags;
}

static void handle_libseccomp_syscall(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects required_effects,
                                      __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, void *syscall_function)
{
	LOG("encountered libseccomp syscall function call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	// if first syscall argument is unbounded, assume it's LINUX_SYS_seccomp
	struct analysis_frame self = {.address = ins, .description = "libseccomp syscall", .next = caller, .current_state = *state, .entry = ins, .entry_state = state, .token = {0}};
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		self.current_state.sources[i] = mask_for_register(i);
	}
	int first_arg = sysv_argument_abi_register_indexes[0];
	if (!register_is_partially_known_32bit(&self.current_state.registers[first_arg])) {
		set_register(&self.current_state.registers[first_arg], LINUX_SYS_seccomp);
		clear_match(&analysis->loader, &self.current_state, first_arg, ins);
		self.current_state.sources[first_arg] = 0;
	}
	function_effects effects = analyze_function(analysis, required_effects, &self.current_state, syscall_function, &self);
	set_effects(&analysis->search, ins, token, (effects & ~EFFECT_PROCESSING) | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, 0);
}

static void handle_libcap_syscall(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects required_effects,
                                  __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, void *syscall_function)
{
	LOG("encountered libcap syscall function call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	// if first syscall argument is unbounded, assume it's LINUX_SYS_seccomp
	struct registers new_state = *state;
	function_effects effects = 0;
	if (register_is_partially_known_32bit(&new_state.registers[sysv_argument_abi_register_indexes[0]])) {
		effects = analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
	} else {
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], LINUX_SYS_capset);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], LINUX_SYS_prctl);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], LINUX_SYS_setuid);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], LINUX_SYS_setgid);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], LINUX_SYS_setgroups);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], LINUX_SYS_chroot);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
	}
	set_effects(&analysis->search, ins, token, (effects & ~EFFECT_PROCESSING) | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, 0);
}

static void handle_ruby_syscall(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                struct effect_token *token, __attribute__((unused)) void *syscall_function)
{
	LOG("encountered ruby syscall function call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	if (!register_is_partially_known_32bit(&state->registers[sysv_argument_abi_register_indexes[0]])) {
		add_blocked_symbol(&analysis->known_symbols, "rb_f_syscall", 0, false)->value = caller->address;
		set_effects(&analysis->search, ins, token, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS, 0);
	}
}

static void handle_golang_unix_sched_affinity(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects,
                                              __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered unix.schedAffinity call: ", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	// skip affinity
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS, 0);
	LOG("skipping unix.schedAffinity");
}

static void handle_openssl_dso_load(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                    struct effect_token *token, __attribute__((unused)) void *data)
{
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS, 0);
	load_openssl_modules(analysis, caller);
}

__attribute__((nonnull(1, 2, 3, 4))) static void intercept_jump_slot(struct program_state *analysis, struct loaded_binary *binary, const char *slot_name, instruction_reached_callback callback)
{
	if (binary->has_sections) {
		const ElfW(Dyn) *dynamic = binary->info.dynamic;
		size_t relaent = sizeof(ElfW(Rela));
		size_t dynamic_size = binary->info.dynamic_size;
		for (size_t i = 0; i < dynamic_size; i++) {
			switch (dynamic[i].d_tag) {
				case DT_RELAENT:
					relaent = dynamic[i].d_un.d_val;
					break;
			}
		}
		for (size_t i = 0; i < binary->info.section_entry_count; i++) {
			const ElfW(Shdr) *section = (const ElfW(Shdr) *)((char *)binary->sections.sections + i * binary->info.section_entry_size);
			if (section->sh_type != SHT_RELA) {
				continue;
			}
			uintptr_t rela_base = (uintptr_t)apply_base_address(&binary->info, section->sh_addr);
			size_t pltrelsz = section->sh_size;
			Elf32_Word required_type = INS_R_JUMP_SLOT;
			Elf32_Word alternate_type = INS_R_GLOB_DAT;
			for (uintptr_t rel_off = 0; rel_off < pltrelsz; rel_off += relaent) {
				const ElfW(Rela) *rel = (const ElfW(Rela) *)(rela_base + rel_off);
				uintptr_t info = rel->r_info;
				if ((ELF64_R_TYPE(info) == required_type) || (ELF64_R_TYPE(info) == alternate_type)) {
					Elf64_Word symbol_index = ELF64_R_SYM(info);
					const ElfW(Sym) *symbol = (const ElfW(Sym) *)(binary->symbols.symbols + symbol_index * binary->symbols.symbol_stride);
					const char *textual_name = symbol_name(&binary->symbols, symbol);
					if (fs_strcmp(textual_name, slot_name) == 0) {
						uintptr_t offset = rel->r_offset;
						uintptr_t *target = (uintptr_t *)apply_base_address(&binary->info, offset);
						uintptr_t old_value = *target;
						struct loader_stub *stub = malloc(sizeof(struct loader_stub));
						stub->dummy = 0;
						stub->next = analysis->loader.stubs;
						analysis->loader.stubs = stub;
						*target = (uintptr_t)stub;
						find_and_add_callback(analysis, (ins_ptr)stub, 0, 0, 0, EFFECT_NONE, callback, (void *)old_value);
						return;
					}
				}
			}
		}
	}
}

static char *blocked_function_trace_callback(const struct loader_context *loader, const struct analysis_frame *frame, __attribute__((unused)) void *callback_data)
{
	return copy_known_registers_description(loader, &frame->current_state);
}

static void blocked_function_called(__attribute__((unused)) struct program_state *analysis, __attribute__((unused)) ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects,
                                    __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	struct blocked_symbol *blocked_symbol = &analysis->known_symbols.blocked_symbols[(intptr_t)data];
	if (blocked_symbol->reject_entirely) {
		ERROR("blocked function ", blocked_symbol->name, " called");
		DIE("call stack: ", temp_str(copy_call_trace_description_with_additional(&analysis->loader, caller, blocked_function_trace_callback, NULL)));
	} else {
		LOG("blocked function ", blocked_symbol->name, " called");
		LOG("call stack: ", temp_str(copy_call_trace_description_with_additional(&analysis->loader, caller, blocked_function_trace_callback, NULL)));
	}
}

__attribute__((nonnull(1, 2, 3))) static void force_protection_for_symbol(const struct loader_context *loader, struct loaded_binary *binary, const char *symbol_name, int symbol_types, int prot)
{
	const ElfW(Sym) * symbol;
	void *address = resolve_binary_loaded_symbol(loader, binary, symbol_name, NULL, symbol_types, &symbol);
	if (address != NULL) {
		for (int i = 0; i < OVERRIDE_ACCESS_SLOT_COUNT; i++) {
			if (binary->override_access_ranges[i].address == 0) {
				binary->override_access_ranges[i].address = address;
				binary->override_access_ranges[i].size = symbol->st_size;
				binary->override_access_permissions[i] = prot;
				LOG("forcing protection at ", temp_str(copy_address_description(loader, address)));
				return;
			}
		}
		DIE("too many override access symbols in ", binary->path);
	} else {
		LOG("could not find ", symbol_name, " in ", binary->path);
	}
}

static void ignored_load_callback(struct program_state *analysis, ins_ptr address, __attribute__((unused)) const struct analysis_frame *frame, void *callback_data)
{
	struct loaded_binary *binary = binary_for_address(&analysis->loader, address);
	if (binary != NULL) {
		LOG("skipping function pointers at ", temp_str(copy_address_description(&analysis->loader, address)), " size: ", (intptr_t)callback_data, " referenced from: ", temp_str(copy_address_description(&analysis->loader, frame->address)));
		size_t old_count = binary->skipped_symbol_count;
		size_t new_count = old_count + 1;
		binary->skipped_symbols = realloc(binary->skipped_symbols, sizeof(*binary->skipped_symbols) * new_count);
		binary->skipped_symbols[old_count] = (struct address_and_size){
			.address = address,
			.size = (size_t)callback_data,
		};
		binary->skipped_symbol_count = new_count;
	}
}

__attribute__((nonnull(1, 2, 3, 4))) static inline function_effects analyze_function_for_ignored_load(struct program_state *analysis, struct registers *entry_state, ins_ptr ins,
                                                                                                      const struct analysis_frame *caller, size_t ignored_load_size)
{
	address_loaded_callback old_callback = analysis->address_loaded;
	analysis->address_loaded = ignored_load_callback;
	void *old_data = analysis->address_loaded_data;
	analysis->address_loaded_data = (void *)ignored_load_size;
	function_effects result = analyze_function(analysis, EFFECT_PROCESSED /* not EFFECT_ENTER_CALLS! */, entry_state, ins, caller);
	analysis->address_loaded = old_callback;
	analysis->address_loaded_data = old_data;
	return result;
}

static void handle_internal_syscall_cancel(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                    __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data);

__attribute__((nonnull(1, 2))) static void update_known_symbols(struct program_state *analysis, struct loaded_binary *new_binary)
{
	struct known_symbols *known_symbols = &analysis->known_symbols;
	// block functions
	uint32_t count = known_symbols->blocked_symbol_count;
	struct blocked_symbol *blocked_symbols = known_symbols->blocked_symbols;
	for (uint32_t i = 0; i < count; i++) {
		if (blocked_symbols[i].value == NULL) {
			const char *name = blocked_symbols[i].name;
			ins_ptr value = resolve_binary_loaded_symbol(&analysis->loader, new_binary, name, NULL, blocked_symbols[i].symbol_types, NULL);
			if (value == NULL) {
				continue;
			}
			blocked_symbols[i].value = value;
			find_and_add_callback(analysis, value, 0, 0, 0, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_EXITS | EFFECT_ENTER_CALLS, blocked_function_called, (void *)(intptr_t)i);
		}
	}
	update_known_function(analysis, new_binary, "Perl_die_unwind", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_STICKY_EXITS);
	update_known_function(analysis, new_binary, "usage_unknown_option", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_STICKY_EXITS);
	update_known_function(analysis, new_binary, "__cxa_throw", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_STICKY_EXITS);
	ins_ptr dlopen_mode = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__libc_dlopen_mode", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
	if (dlopen_mode) {
		register_mask arg0 = mask_for_register(sysv_argument_abi_register_indexes[0]);
		find_and_add_callback(analysis, dlopen_mode, arg0, arg0, arg0, EFFECT_NONE, handle_dlopen, NULL);
	}
	ins_ptr dlopen = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "dlopen", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
	if (dlopen != NULL && dlopen != dlopen_mode) {
		register_mask arg0 = mask_for_register(sysv_argument_abi_register_indexes[0]);
		find_and_add_callback(analysis, dlopen, arg0, arg0, arg0, EFFECT_NONE, handle_dlopen, NULL);
	}
	if (new_binary->special_binary_flags & (BINARY_IS_LIBC | BINARY_IS_INTERPRETER)) {
		force_protection_for_symbol(&analysis->loader, new_binary, "_rtld_global_ro", NORMAL_SYMBOL | LINKER_SYMBOL, 0);
		// libc exit functions
		update_known_function(analysis, new_binary, "_dl_signal_error", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "__fortify_fail", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "__stack_chk_fail", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "__libc_fatal", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "__assert_fail", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "__libc_longjmp", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "longjmp", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "abort", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "exit", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		update_known_function(analysis, new_binary, "pthread_exit", NORMAL_SYMBOL, EFFECT_STICKY_EXITS);
		// block executable stacks
		ins_ptr __nptl_change_stack_perm = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__nptl_change_stack_perm", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (__nptl_change_stack_perm) {
			find_and_add_callback(analysis, __nptl_change_stack_perm, 0, 0, 0, EFFECT_NONE, handle_change_stack_perm, NULL);
		}
	}
	if (new_binary->special_binary_flags & BINARY_IS_LIBC) {
		// special-case __internal_syscall_cancel by searching clock_nanosleep
		ins_ptr clock_nanosleep = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "clock_nanosleep", NULL, NORMAL_SYMBOL, NULL);
		if (clock_nanosleep != NULL) {
			struct registers registers = empty_registers;
			struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "clock_nanosleep", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
			analysis->loader.searching_for_internal_syscall_cancel = true;
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, clock_nanosleep, &new_caller);
			analysis->loader.searching_for_internal_syscall_cancel = false;
			if (analysis->loader.internal_syscall_cancel == NULL || analysis->loader.internal_syscall_cancel_syscall[0] == NULL) {
				analysis->loader.internal_syscall_cancel = NULL;
				analysis->loader.internal_syscall_cancel_syscall[0] = NULL;
			} else {
				find_and_add_callback(analysis, analysis->loader.internal_syscall_cancel, 0, 0, 0, EFFECT_NONE, handle_internal_syscall_cancel, NULL);
			}
		}
		// detect gconv and load libraries upfront via LD_PRELOAD
		ins_ptr gconv_open = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__gconv_open", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (gconv_open) {
			// search for __gconv_find_shlib so that handle_gconv_find_shlib can be attached to it
			struct registers registers = empty_registers;
			struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "__gconv_open", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
			analysis->loader.searching_gconv_dlopen = true;
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, gconv_open, &new_caller);
			if (analysis->loader.gconv_dlopen != NULL) {
				struct registers state = empty_registers;
				struct effect_token token;
				analysis->loader.searching_gconv_dlopen = true;
				*get_or_populate_effects(analysis, analysis->loader.gconv_dlopen, &state, EFFECT_NONE, &token) = EFFECT_NONE;
			}
			analysis->loader.searching_gconv_dlopen = false;
		}
		// update_known_function(analysis, new_binary, &known_symbols->gconv_find_shlib, "__gconv_find_shlib", NULL, NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL, EFFECT_RETURNS | EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT
		// | EFFECT_ENTER_CALLS);
		ins_ptr module_load = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "module_load", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (module_load) {
			analysis->loader.nss_module_load = module_load;
		} else {
			// load nss libraries if an nss function is used
			ins_ptr nss_lookup_function = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__nss_lookup_function", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
			if (nss_lookup_function) {
				find_and_add_callback(analysis, nss_lookup_function, 0, 0, 0, EFFECT_NONE, handle_nss_usage, NULL);
			}
			ins_ptr nss_lookup = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__nss_lookup", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
			if (nss_lookup) {
				find_and_add_callback(analysis, nss_lookup, 0, 0, 0, EFFECT_NONE, handle_nss_usage, NULL);
			}
			ins_ptr nss_next2 = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__nss_next2", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
			if (nss_next2) {
				find_and_add_callback(analysis, nss_next2, 0, 0, 0, EFFECT_NONE, handle_nss_usage, NULL);
			}
		}
		// block executable stacks
		ins_ptr __mprotect = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__mprotect", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (__mprotect) {
			find_and_add_callback(analysis, __mprotect, 0, 0, 0, EFFECT_NONE, handle_mprotect, NULL);
		}
		ins_ptr mmap = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "mmap", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (mmap) {
			find_and_add_callback(analysis, mmap, 0, 0, 0, EFFECT_NONE, handle_mmap, NULL);
		}
		// special-case fopen's mode argument
		ins_ptr _IO_file_fopen = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "_IO_file_fopen", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		ins_ptr _IO_file_open = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "_IO_file_open", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (_IO_file_fopen && _IO_file_open) {
			find_and_add_callback(analysis, _IO_file_fopen, 0, 0, 0, EFFECT_NONE, handle_IO_file_fopen, NULL);
			find_and_add_callback(analysis, _IO_file_open, 0, 0, 0, EFFECT_NONE, handle_IO_file_open, NULL);
		}
	}
	if (new_binary->special_binary_flags & (BINARY_IS_LIBC | BINARY_IS_INTERPRETER)) {
		if (analysis->ld_profile != NULL) {
			ins_ptr dl_start_profile = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "_dl_start_profile", NULL, INTERNAL_COMMON_SYMBOL, NULL);
			// search for __gconv_find_shlib so that handle_gconv_find_shlib can be attached to it
			if (dl_start_profile != NULL) {
				struct registers registers = empty_registers;
				struct analysis_frame new_caller = {
					.address = new_binary->info.base, .description = "_dl_start_profile", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
				analyze_function(analysis, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, dl_start_profile, &new_caller);
			}
		}
		ins_ptr error = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "error", NULL, NORMAL_SYMBOL, NULL);
		if (error) {
			LOG("found error: ", temp_str(copy_address_description(&analysis->loader, error)));
			struct effect_token token;
			struct registers empty = empty_registers;
			empty.registers[sysv_argument_abi_register_indexes[0]].value = 1;
			*get_or_populate_effects(analysis, error, &empty, EFFECT_NONE, &token) |= EFFECT_EXITS | EFFECT_STICKY_EXITS | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS;
			add_relevant_registers(&analysis->search,
			                       &analysis->loader,
			                       error,
			                       &empty,
			                       0,
			                       mask_for_register(sysv_argument_abi_register_indexes[0]),
			                       mask_for_register(sysv_argument_abi_register_indexes[0]),
			                       mask_for_register(sysv_argument_abi_register_indexes[0]),
			                       &token);
		}
		ins_ptr error_at_line = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "error_at_line", NULL, NORMAL_SYMBOL, NULL);
		if (error_at_line) {
			LOG("found error_at_line: ", temp_str(copy_address_description(&analysis->loader, error_at_line)));
			struct effect_token token;
			struct registers empty = empty_registers;
			empty.registers[sysv_argument_abi_register_indexes[0]].value = 1;
			*get_or_populate_effects(analysis, error, &empty, EFFECT_NONE, &token) |= EFFECT_EXITS | EFFECT_STICKY_EXITS | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS;
			add_relevant_registers(&analysis->search,
			                       &analysis->loader,
			                       error_at_line,
			                       &empty,
			                       0,
			                       mask_for_register(sysv_argument_abi_register_indexes[0]),
			                       mask_for_register(sysv_argument_abi_register_indexes[0]),
			                       mask_for_register(sysv_argument_abi_register_indexes[0]),
			                       &token);
		}
		ins_ptr makecontext = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "makecontext", NULL, NORMAL_SYMBOL, NULL);
		if (makecontext) {
			struct effect_token token;
			struct registers empty = empty_registers;
			*get_or_populate_effects(analysis, makecontext, &empty, EFFECT_NONE, &token) |= EFFECT_EXITS | EFFECT_STICKY_EXITS | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS;
		}
		// block functions that introduce executable code at runtime
		ins_ptr dl_map_object_from_fd = update_known_function(analysis, new_binary, "_dl_map_object_from_fd", INTERNAL_COMMON_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
		if (dl_map_object_from_fd != NULL) {
			struct blocked_symbol *blocked = add_blocked_symbol(&analysis->known_symbols, "_dl_map_object_from_fd", 0, true);
			blocked->value = dl_map_object_from_fd;
			blocked->is_dlopen = true;
		}
		update_known_function(analysis, new_binary, "_dl_relocate_object", INTERNAL_COMMON_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
		update_known_function(analysis, new_binary, "_dl_make_stack_executable", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
	}
	if (new_binary->special_binary_flags & BINARY_IS_INTERPRETER) {
		// find the syscall invocation inside musl's do_setxid call
		ins_ptr do_setxid = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "do_setxid", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (do_setxid == NULL) {
			ins_ptr setuid = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "setuid", NULL, INTERNAL_COMMON_SYMBOL, NULL);
			if (setuid != NULL) {
				struct registers registers = empty_registers;
				struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "setuid", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
				analysis->loader.searching_do_setxid = true;
				analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, setuid, &new_caller);
				analysis->loader.searching_do_setxid = false;
				do_setxid = analysis->loader.do_setxid;
			}
		}
		if (do_setxid != NULL) {
			struct registers registers = empty_registers;
			struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "do_setxid", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
			analysis->loader.searching_setxid_sighandler = true;
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, do_setxid, &new_caller);
			analysis->loader.searching_setxid_sighandler = false;
		}
		// translate calls to musl's setxid wrapper functions into syscalls from inside do_setxid
		ins_ptr setxid = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__setxid", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (setxid != NULL) {
			find_and_add_callback(analysis,
			                      setxid,
			                      mask_for_register(sysv_argument_abi_register_indexes[0]),
			                      mask_for_register(sysv_argument_abi_register_indexes[0]),
			                      mask_for_register(sysv_argument_abi_register_indexes[0]),
			                      EFFECT_NONE,
			                      handle_musl_setxid,
			                      NULL);
		} else {
			static const struct musl_setxid_wrapper wrappers[] = {
				{"setegid", LINUX_SYS_setresgid, -1},
				{"seteuid", LINUX_SYS_setresuid, -1},
				{"setgid", LINUX_SYS_setgid, 1},
				{"setregid", LINUX_SYS_setregid, 2},
				{"setresgid", LINUX_SYS_setresgid, 3},
				{"setresuid", LINUX_SYS_setresuid, 3},
				{"setreuid", LINUX_SYS_setreuid, 2},
				{"setuid", LINUX_SYS_setuid, 1},
			};
			for (size_t i = 0; i < sizeof(wrappers) / sizeof(wrappers[0]); i++) {
				ins_ptr wrapper = resolve_binary_loaded_symbol(&analysis->loader, new_binary, wrappers[i].name, NULL, INTERNAL_COMMON_SYMBOL, NULL);
				if (wrapper != NULL) {
					register_mask mask = 0;
					if (wrappers[i].argc < 0) {
						mask = mask_for_register(sysv_argument_abi_register_indexes[0]);
					} else {
						for (int j = 0; j < wrappers[j].argc; j++) {
							mask |= mask_for_register(sysv_argument_abi_register_indexes[j]);
						}
					}
					find_and_add_callback(analysis, wrapper, mask, 0, 0, EFFECT_NONE, handle_musl_setxid, (void *)&wrappers[i]);
				}
			}
		}
	}
	if (new_binary->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_LIBC | BINARY_IS_PTHREAD)) {
		update_known_function(analysis, new_binary, "cancel_handler", INTERNAL_COMMON_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
		update_known_function(analysis, new_binary, "sigcancel_handler", INTERNAL_COMMON_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
	}
	if (new_binary->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_MAIN)) {
		ins_ptr fopen = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "fopen", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (fopen) {
			find_and_add_callback(analysis, fopen, 0, 0, 0, EFFECT_NONE, handle_fopen, NULL);
		}
	}
	// setxid signal handler callbacks
	if (new_binary->special_binary_flags & (BINARY_IS_PTHREAD | BINARY_IS_LIBC)) {
		analysis->loader.searching_setxid_sighandler = true;
		struct registers registers = empty_registers;
		struct analysis_frame new_caller = {
			.address = new_binary->info.base, .description = "sighandler_setxid", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
		ins_ptr nptl_setxid_sighandler = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__GI___nptl_setxid_sighandler", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (nptl_setxid_sighandler != NULL) {
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, nptl_setxid_sighandler, &new_caller);
		}
		ins_ptr sighandler_setxid = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "sighandler_setxid", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (sighandler_setxid != NULL) {
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, sighandler_setxid, &new_caller);
		}
		analysis->loader.searching_setxid_sighandler = false;
		ins_ptr nptl_setxid = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__nptl_setxid", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (nptl_setxid) {
			new_caller.description = "__nptl_setxid";
			analysis->loader.searching_setxid = true;
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, nptl_setxid, &new_caller);
			analysis->loader.searching_setxid = false;
		}
		ins_ptr pause = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "pause", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (pause != NULL) {
			new_caller.description = "pause";
			analysis->loader.searching_enable_async_cancel = true;
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, pause, &new_caller);
			analysis->loader.searching_enable_async_cancel = false;
		}
		// assume new libraries won't be loaded after startup
		update_known_function(analysis, new_binary, "__make_stacks_executable", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
	}
	if (binary_has_flags(new_binary, BINARY_IS_MAIN | BINARY_IS_GOLANG)) {
		update_known_function(analysis, new_binary, "runtime.runPerThreadSyscall", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTER_CALLS);
		void *forkAndExecInChild1 = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "syscall.forkAndExecInChild1", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (forkAndExecInChild1 != NULL) {
			find_and_add_callback(analysis, forkAndExecInChild1, 0, 0, 0, EFFECT_NONE, handle_forkAndExecInChild1, NULL);
		}
		force_protection_for_symbol(&analysis->loader, new_binary, "internal/syscall/unix.FcntlSyscall", NORMAL_SYMBOL | LINKER_SYMBOL, PROT_READ);
		force_protection_for_symbol(&analysis->loader, new_binary, "syscall.fcntl64Syscall", NORMAL_SYMBOL | LINKER_SYMBOL, PROT_READ);
		force_protection_for_symbol(&analysis->loader, new_binary, "github.com/docker/docker/vendor/golang.org/x/sys/unix.fcntl64Syscall", NORMAL_SYMBOL | LINKER_SYMBOL, PROT_READ);
		void *unixSchedAffinity = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "github.com/docker/docker/vendor/golang.org/x/sys/unix.schedAffinity", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (unixSchedAffinity) {
			register_mask stack_4 = mask_for_register(REGISTER_STACK_4);
			find_and_add_callback(analysis, unixSchedAffinity, stack_4, stack_4, stack_4, EFFECT_NONE, handle_golang_unix_sched_affinity, NULL);
		}
	}
	if (new_binary->special_binary_flags & BINARY_IS_LIBCRYPTO) {
		void *dso_load = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "DSO_load", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (dso_load) {
			find_and_add_callback(analysis, dso_load, 0, 0, 0, EFFECT_NONE, handle_openssl_dso_load, NULL);
		}
		void *DSO_METHOD_openssl = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "DSO_METHOD_openssl", NULL, NORMAL_SYMBOL, NULL);
		if (DSO_METHOD_openssl != NULL) {
			struct analysis_frame new_caller = {
				.address = new_binary->info.base, .description = "DSO_METHOD_openssl", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
			analyze_function_for_ignored_load(analysis, &new_caller.current_state, DSO_METHOD_openssl, &new_caller, 12 * sizeof(uintptr_t));
		}
	}
	if ((new_binary->special_binary_flags & BINARY_IS_SECCOMP) && new_binary->has_symbols) {
		intercept_jump_slot(analysis, new_binary, "syscall", &handle_libseccomp_syscall);
	}
	if ((new_binary->special_binary_flags & BINARY_IS_LIBCAP) && new_binary->has_symbols) {
		intercept_jump_slot(analysis, new_binary, "syscall", &handle_libcap_syscall);
	}
	if ((new_binary->special_binary_flags & BINARY_IS_RUBY) && new_binary->has_symbols) {
		intercept_jump_slot(analysis, new_binary, "syscall", &handle_ruby_syscall);
	}
}

struct blocked_symbol *add_blocked_symbol(struct known_symbols *known_symbols, const char *name, int symbol_types, bool required)
{
	uint32_t i = known_symbols->blocked_symbol_count;
	uint32_t count = i + 1;
	struct blocked_symbol *symbols = realloc(known_symbols->blocked_symbols, count * sizeof(struct blocked_symbol));
	symbols[i].value = NULL;
	symbols[i].name = name;
	symbols[i].symbol_types = symbol_types;
	symbols[i].is_dlopen = false;
	symbols[i].is_required = required;
	known_symbols->blocked_symbols = symbols;
	known_symbols->blocked_symbol_count = count;
	return &symbols[i];
}

__attribute__((nonnull(1, 2))) char *copy_call_trace_description_with_additional(const struct loader_context *context, const struct analysis_frame *head, additional_print_callback callback, void *callback_data)
{
	size_t count = 0;
	for (const struct analysis_frame *node = head; node != NULL; node = node->next) {
		count++;
	}
	if (count == 0) {
		char *empty = malloc(1);
		*empty = '\0';
		return empty;
	}
	struct
	{
		size_t length;
		char *description;
	} *list = malloc(count * sizeof(*list));
	const struct analysis_frame *node = head;
	size_t total_size = 0;
	for (size_t i = 0; i < count; i++) {
#ifdef CALL_TRACE_WITH_RANGE
		char *description = copy_address_description(context, node->entry);
#else
		char *description = copy_address_description(context, node->address);
#endif
		size_t length = fs_strlen(description);
#ifdef CALL_TRACE_WITH_RANGE
		if (node->entry != node->address) {
			char *additional_description = copy_address_description(context, node->address);
			size_t additional_length = fs_strlen(additional_description);
			ssize_t new_length = length + 1 + additional_length;
			description = realloc(description, new_length + 1);
			description[length] = '-';
			fs_memcpy(&description[length + 1], additional_description, additional_length + 1);
			length = new_length;
		}
#endif
		if (node->description) {
			size_t additional_length = fs_strlen(node->description);
			size_t new_length = length + 2 + additional_length + 1;
			description = realloc(description, new_length + 1);
			description[length] = ' ';
			description[length + 1] = '(';
			fs_memcpy(&description[length + 2], node->description, additional_length + 1);
			description[new_length - 1] = ')';
			description[new_length] = '\0';
			length = new_length;
		}
		if (callback != NULL) {
			char *additional = callback(context, node, callback_data);
			if (additional != NULL) {
				size_t additional_length = fs_strlen(additional);
				size_t new_length = length + additional_length;
				description = realloc(description, new_length + 1);
				fs_memcpy(&description[length], additional, additional_length + 1);
				free(additional);
				length = new_length;
			}
		}
		list[i].description = description;
		list[i].length = length;
		total_size += length + 1;
		node = node->next;
	}
	char *result = malloc(total_size);
	char *dest = result;
	for (size_t i = 0; i < count; i++) {
		size_t length = list[i].length;
		fs_memcpy(dest, list[i].description, length);
		free(list[i].description);
		dest += length;
		*dest++ = '\n';
	}
	dest--;
	*dest = '\0';
	free(list);
	return result;
}

__attribute__((nonnull(1, 2))) char *copy_call_trace_description(const struct loader_context *context, const struct analysis_frame *head)
{
	return copy_call_trace_description_with_additional(context, head, NULL, NULL);
}

__attribute__((nonnull(1))) char *copy_syscall_description(const struct loader_context *context, uintptr_t nr, const struct registers *registers, bool include_symbol)
{
	return copy_call_description(context, name_for_syscall(nr), registers, syscall_argument_abi_register_indexes, info_for_syscall(nr), include_symbol);
}

__attribute__((nonnull(1, 2))) char *copy_function_call_description(const struct loader_context *context, ins_ptr target, const struct registers *registers)
{
	char *name = copy_address_description(context, target);
	struct loaded_binary *binary = binary_for_address(context, target);
	int argc;
	const int *register_indexes;
	if (binary_has_flags(binary, BINARY_IS_GOLANG)) {
		size_t name_len = fs_strlen(name);
		if (name_len > 6 && fs_strcmp(&name[name_len - 6], ".abi0)") == 0) {
			register_indexes = golang_abi0_argument_abi_register_indexes;
			argc = sizeof(golang_abi0_argument_abi_register_indexes) / sizeof(golang_abi0_argument_abi_register_indexes[0]);
		} else {
			register_indexes = golang_internal_argument_abi_register_indexes;
			argc = sizeof(golang_internal_argument_abi_register_indexes) / sizeof(golang_internal_argument_abi_register_indexes[0]);
		}
	} else {
		register_indexes = sysv_argument_abi_register_indexes;
		argc = sizeof(sysv_argument_abi_register_indexes) / sizeof(sysv_argument_abi_register_indexes[0]);
	}
	struct syscall_info info = {
		.attributes = argc,
		.arguments = {0},
	};
	char *result = copy_call_description(context, name, registers, register_indexes, info, true);
	free(name);
	return result;
}

__attribute__((nonnull(1, 2, 3))) void vary_effects_by_registers(struct searched_instructions *search, const struct loader_context *loader, const struct analysis_frame *self, register_mask relevant_registers,
                                                                        register_mask preserved_registers, register_mask preserved_and_kept_registers, function_effects required_effects)
{
	// mark ancestor functions as varying by registers until we find one that no longer passes data into the call site
	const struct analysis_frame *ancestor = self;
	for (;;) {
		register_mask new_relevant_registers = 0;
		register_mask new_preserved_registers = 0;
		register_mask new_preserved_and_kept_registers = 0;
		{
			for_each_bit (relevant_registers, bit, i) {
				if (register_is_partially_known(&ancestor->current_state.registers[i])) {
					new_relevant_registers |= ancestor->current_state.sources[i];
				}
			}
		}
		new_relevant_registers &= ~mask_for_register(REGISTER_SP);
		register_mask discarded_registers = mask_for_register(REGISTER_SP);
		{
			for_each_bit (new_relevant_registers, bit, i) {
				if (!register_is_partially_known(&ancestor->entry_state->registers[i])) {
					LOG("register ", name_for_register(i), " is not known, skipping requiring");
					new_relevant_registers &= ~bit;
					discarded_registers |= bit;
				}
			}
		}
		if (new_relevant_registers == 0) {
			if (SHOULD_LOG) {
				ERROR_NOPREFIX("first entry point without varying arguments", temp_str(copy_address_description(loader, ancestor->entry)));
				for_each_bit (relevant_registers, bit, i) {
					ERROR_NOPREFIX("relevant register", name_for_register(i));
				}
			}
			break;
		}
		{
			for_each_bit (preserved_registers, bit, i) {
				new_preserved_registers |= ancestor->current_state.sources[i];
			}
		}
		new_preserved_registers &= ~discarded_registers;
		{
			for_each_bit (preserved_and_kept_registers, bit, i) {
				new_preserved_and_kept_registers |= ancestor->current_state.sources[i];
			}
		}
		new_preserved_and_kept_registers &= ~mask_for_register(REGISTER_SP);
		if (SHOULD_LOG) {
			ERROR_NOPREFIX("marking", temp_str(copy_address_description(loader, ancestor->entry)));
			for_each_bit (new_relevant_registers, bit, i) {
				if (new_preserved_and_kept_registers & bit) {
					ERROR_NOPREFIX("as preserving and keeping", name_for_register(i), ": ", temp_str(copy_register_state_description(loader, ancestor->entry_state->registers[i])));
				} else if (new_preserved_registers & bit) {
					ERROR_NOPREFIX("as preserving", name_for_register(i), ": ", temp_str(copy_register_state_description(loader, ancestor->entry_state->registers[i])));
				} else {
					ERROR_NOPREFIX("as requiring", name_for_register(i), ": ", temp_str(copy_register_state_description(loader, ancestor->entry_state->registers[i])));
				}
			}
			ERROR_NOPREFIX("from ins at", temp_str(copy_address_description(loader, ancestor->address)));
		}
		struct previous_register_masks existing =
			add_relevant_registers(search, loader, ancestor->entry, ancestor->entry_state, required_effects, new_relevant_registers, new_preserved_registers, new_preserved_and_kept_registers, (struct effect_token *)&ancestor->token);
		if (((existing.relevant_registers & new_relevant_registers) == new_relevant_registers) && ((existing.preserved_registers & new_preserved_registers) == new_preserved_registers) &&
		    ((existing.preserved_and_kept_registers & new_preserved_and_kept_registers) == new_preserved_and_kept_registers))
		{
			if ((existing.data->sticky_effects & EFFECT_TEMPORARY_IN_VARY_EFFECTS) == 0) {
				if (SHOULD_LOG) {
					if (ancestor->next != NULL) {
						ERROR_NOPREFIX("relevant and preserved registers already added, stopping before", temp_str(copy_address_description(loader, ancestor->next->entry)));
					} else {
						ERROR_NOPREFIX("relevant and preserved registers already added, stopping");
					}
				}
				break;
			}
			if (SHOULD_LOG) {
				ERROR_NOPREFIX("ancestor is processing, continuing even though relevant and preserved registers were already added");
			}
		}
		existing.data->sticky_effects |= EFFECT_TEMPORARY_IN_VARY_EFFECTS;
		ancestor = ancestor->next;
		if (ancestor == NULL) {
			if (SHOULD_LOG) {
				ERROR_NOPREFIX("all ancestors had arguments");
			}
			break;
		}
		relevant_registers = new_relevant_registers;
		preserved_registers = new_preserved_registers;
		preserved_and_kept_registers = new_preserved_and_kept_registers;
	}
	// clean up EFFECT_TEMPORARY_IN_VARY_EFFECTS
	for (const struct analysis_frame *ancestor_clean = self; ancestor_clean != ancestor; ancestor_clean = ancestor_clean->next) {
		struct searched_instruction_data *data = search->table[ancestor_clean->token.index].data;
		data->sticky_effects &= ~EFFECT_TEMPORARY_IN_VARY_EFFECTS;
	}
}

__attribute__((nonnull(1))) static inline void add_syscall(struct recorded_syscalls *syscalls, struct recorded_syscall syscall)
{
	int index = syscalls->count++;
	if (syscalls->list == NULL) {
		syscalls->capacity = 8;
		syscalls->list = malloc(syscalls->capacity * sizeof(struct recorded_syscall));
	} else if (index >= syscalls->capacity) {
		syscalls->capacity = syscalls->capacity << 1;
		syscalls->list = realloc(syscalls->list, syscalls->capacity * sizeof(struct recorded_syscall));
	}
	syscalls->list[index] = syscall;
}

static char *record_syscall_trace_callback(const struct loader_context *loader, const struct analysis_frame *frame, void *callback_data)
{
	register_mask *relevant = callback_data;
	char buf[1024 * 8];
	size_t i = 0;
	register_mask new_relevant = 0;
	for_each_bit (*relevant, bit, r) {
		if (register_is_partially_known(&frame->current_state.registers[r])) {
			buf[i++] = ' ';
			const char *name = name_for_register(r);
			size_t len = fs_strlen(name);
			memcpy(&buf[i], name, len);
			i += len;
			buf[i++] = '=';
			char *description = copy_register_state_description(loader, frame->current_state.registers[r]);
			len = fs_strlen(description);
			memcpy(&buf[i], description, len);
			i += len;
			free(description);
			register_mask sources = frame->current_state.sources[r];
			new_relevant |= sources;
			if (sources != 0) {
				buf[i++] = '(';
				buf[i++] = 'f';
				buf[i++] = 'r';
				buf[i++] = 'o';
				buf[i++] = 'm';
				for_each_bit (sources, bit2, r2) {
					buf[i++] = ' ';
					name = name_for_register(r2);
					len = fs_strlen(name);
					fs_memcpy(&buf[i], name, len);
					i += len;
				}
				buf[i++] = ')';
			}
		}
	}
	*relevant = new_relevant;
	if (i == 0) {
		return NULL;
	}
	buf[i] = '\0';
	return strdup(buf);
}

void record_syscall(struct program_state *analysis, uintptr_t nr, struct analysis_frame self, function_effects effects)
{
	struct recorded_syscalls *syscalls = &analysis->syscalls;
	uint8_t config = nr < SYSCALL_COUNT ? syscalls->config[nr] : 0;
	struct syscall_info info = info_for_syscall(nr);
	for (int i = 0; i < (info.attributes & SYSCALL_ARGC_MASK); i++) {
		if (i != 0 && (info.arguments[i] & SYSCALL_ARG_TYPE_MASK) == SYSCALL_ARG_IS_MODEFLAGS) {
			// argument is modeflags, previous is mode. check if mode is used and if not, convert to any
			const struct register_state *arg = &self.current_state.registers[syscall_argument_abi_register_indexes[i - 1]];
			if (register_is_exactly_known(arg)) {
				if ((arg->value & LINUX_O_TMPFILE) == LINUX_O_TMPFILE) {
					continue;
				}
				if ((arg->value & LINUX_O_CREAT) == LINUX_O_CREAT) {
					continue;
				}
			}
			clear_register(&self.current_state.registers[syscall_argument_abi_register_indexes[i]]);
		}
	}
	// debug logging
	LOG("syscall is ", temp_str(copy_call_description(&analysis->loader, name_for_syscall(nr), &self.current_state, syscall_argument_abi_register_indexes, info, true)));
	bool should_record = ((config & SYSCALL_CONFIG_BLOCK) == 0) && (((effects & EFFECT_AFTER_STARTUP) == EFFECT_AFTER_STARTUP) || nr == LINUX_SYS_exit || nr == LINUX_SYS_exit_group);
	if (should_record) {
		LOG("recorded syscall");
		add_syscall(syscalls,
		            (struct recorded_syscall){
						.nr = nr,
						.ins = self.address,
						.entry = self.entry,
						.registers = self.current_state,
					});
		if (info.attributes & SYSCALL_IS_RESTARTABLE) {
			struct registers restart = self.current_state;
			set_register(&restart.registers[REGISTER_SYSCALL_NR], LINUX_SYS_restart_syscall);
			add_syscall(syscalls,
			            (struct recorded_syscall){
							.nr = LINUX_SYS_restart_syscall,
							.ins = self.address,
							.entry = self.entry,
							.registers = restart,
						});
		}
	} else {
		if ((config & SYSCALL_CONFIG_BLOCK) == 0) {
			LOG("skipped recording syscall because not after startup");
		} else {
			LOG("skipped recording syscall because blocked");
		}
	}
	if ((config & SYSCALL_CONFIG_DEBUG) && (should_record || SHOULD_LOG)) {
		if (should_record) {
			ERROR("found ", temp_str(copy_syscall_description(&analysis->loader, nr, &self.current_state, true)), " syscall");
		} else {
			ERROR("found ", temp_str(copy_syscall_description(&analysis->loader, nr, &self.current_state, true)), " startup syscall");
		}
		ERROR("from entry: ", temp_str(copy_address_description(&analysis->loader, self.entry)));
		if (SHOULD_LOG) {
			for (int i = 0; i < (info.attributes & SYSCALL_ARGC_MASK); i++) {
				int reg = syscall_argument_abi_register_indexes[i];
				for_each_bit (self.current_state.sources[reg], bit, j) {
					ERROR("argument ", i, " using block input from", name_for_register(j));
				}
			}
		}
		register_mask relevant = syscall_argument_abi_used_registers_for_argc[info.attributes & SYSCALL_ARGC_MASK];
		ERROR("at: ", temp_str(copy_call_trace_description_with_additional(&analysis->loader, &self, record_syscall_trace_callback, &relevant)));
	}
	// figure out which, if any, arguments to the function were used in the syscall
	register_mask relevant_registers = syscall_argument_abi_used_registers_for_argc[info.attributes & SYSCALL_ARGC_MASK];
	// determine which registers to preserve
	register_mask preserved_registers = syscall_argument_abi_used_registers_for_argc[0];
	for (int i = 0; i < (info.attributes & SYSCALL_ARGC_MASK); i++) {
		if (info.arguments[i] & SYSCALL_ARG_IS_PRESERVED) {
			preserved_registers |= mask_for_register(syscall_argument_abi_register_indexes[i]);
		}
	}
	// vary effects by following control flow that produced any used values
	vary_effects_by_registers(&analysis->search, &analysis->loader, &self, relevant_registers, preserved_registers, preserved_registers, 0);
}

#ifdef STATS
intptr_t analyzed_instruction_count;
#endif

void record_stack_address_taken(__attribute__((unused)) const struct loader_context *loader, __attribute__((unused)) ins_ptr addr, struct registers *regs)
{
	LOG("taking address of stack at ", temp_str(copy_address_description(loader, addr)));
#if RECORD_WHERE_STACK_ADDRESS_TAKEN
	if (regs->stack_address_taken == NULL) {
		regs->stack_address_taken = addr;
	}
#else
	regs->stack_address_taken = true;
#endif
}

uintptr_t read_memory(const void *addr, enum ins_operand_size size)
{
	switch (size) {
		case OPERATION_SIZE_BYTE:
			return *(const uint8_t *)addr;
		case OPERATION_SIZE_HALF:
			return *(const ins_uint16 *)addr;
		case OPERATION_SIZE_WORD:
			return *(const ins_uint32 *)addr;
		case OPERATION_SIZE_DWORD:
		default:
			return *(const ins_uint64 *)addr;
	}
}

intptr_t read_memory_signed(const void *addr, enum ins_operand_size size)
{
	switch (size) {
		case OPERATION_SIZE_BYTE:
			return *(const int8_t *)addr;
		case OPERATION_SIZE_HALF:
			return *(const ins_int16 *)addr;
		case OPERATION_SIZE_WORD:
			return *(const ins_int32 *)addr;
		case OPERATION_SIZE_DWORD:
		default:
			return *(const ins_int64 *)addr;
	}
}

void add_registers(struct register_state *dest, const struct register_state *source)
{
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		dest->value = dest->max = dest->value + source->value;
	} else if (__builtin_add_overflow(dest->value, source->value, &dest->value) || __builtin_add_overflow(dest->max, source->max, &dest->max)) {
		clear_register(dest);
	}
}

enum
{
	NO_COMPARISON = 0,
	INVALID_COMPARISON = 1,
	SUPPORTED_COMPARISON = 2,
};

enum basic_op_usage basic_op_unknown(BASIC_OP_ARGS)
{
	(void)source;
	clear_register(dest);
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_add(BASIC_OP_ARGS)
{
	add_registers(dest, source);
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_or(BASIC_OP_ARGS)
{
	if (dest->value == ~(uintptr_t)0) {
		return BASIC_OP_USED_LEFT;
	}
	if (source->value == ~(uintptr_t)0) {
		dest->value = dest->max = ~(uintptr_t)0;
		return BASIC_OP_USED_RIGHT;
	}
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		dest->value = dest->max = dest->value | source->value;
		return BASIC_OP_USED_BOTH;
	}
	if (source->value > dest->value) {
		dest->value = source->value;
	}
	dest->max |= source->max;
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_adc(BASIC_OP_ARGS)
{
	if (__builtin_add_overflow(dest->max, source->max, &dest->max)) {
		clear_register(dest);
		return BASIC_OP_USED_BOTH;
	}
	if (__builtin_add_overflow(dest->max, 1, &dest->max)) {
		clear_register(dest);
		return BASIC_OP_USED_BOTH;
	}
	if (__builtin_add_overflow(dest->value, source->value, &dest->value)) {
		clear_register(dest);
	}
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_and(BASIC_OP_ARGS)
{
	if (register_is_exactly_known(source)) {
		if (register_is_exactly_known(dest)) {
			// both are known, compute exact value
			dest->max = dest->value = dest->value & source->value;
			return BASIC_OP_USED_BOTH;
		}
		if ((source->value & (source->value - 1)) == 0 && source->value != 0 && dest->max >= source->value) {
			if (source->value == 1) {
				dest->value = 0;
				dest->max = 1;
				return BASIC_OP_USED_BOTH;
			}
			// source is known and has single bit set, branch
			set_register(dest, source->value);
			set_register(&additional->state, 0);
			additional->used = true;
			return BASIC_OP_USED_BOTH;
		}
	} else if (register_is_exactly_known(dest)) {
		if ((dest->value & (dest->value - 1)) == 0 && dest->value != 0 && source->max >= dest->value) {
			if (dest->value == 1) {
				dest->value = 0;
				dest->max = 1;
				return BASIC_OP_USED_BOTH;
			}
			// source is known and has single bit set, branch
			set_register(&additional->state, 0);
			additional->used = true;
			return BASIC_OP_USED_BOTH;
		}
	}
	// use the smallest maximum, but not if it looks like an alignment operation
	dest->value = 0;
	if (source->max < dest->max && source->max < (uintptr_t)0xfffffffffffffff0) {
		dest->max = source->max;
	}
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_sbb(BASIC_OP_ARGS)
{
	if (dest_reg == source_reg) {
		set_register(dest, 0);
		set_register(&additional->state, ~(uintptr_t)0);
		additional->used = true;
		return BASIC_OP_USED_NEITHER;
	}
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		uintptr_t dest_value = dest->value;
		dest->value = dest_value - (source->value + 1);
		dest->max = dest_value - source->value;
	} else {
		clear_register(dest);
	}
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_sub(BASIC_OP_ARGS)
{
	bool value_overflowed = __builtin_sub_overflow(dest->value, source->max, &dest->value);
	bool max_overflowed = __builtin_sub_overflow(dest->max, source->value, &dest->max);
	if (value_overflowed || max_overflowed) {
		if (value_overflowed && !max_overflowed && (register_is_exactly_known(source) ^ register_is_exactly_known(dest))) {
			additional->used = true;
			additional->state.value = dest->value;
			additional->state.max = ~(uintptr_t)0;
			dest->value = 0;
		} else {
			clear_register(dest);
		}
	}
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_xor(BASIC_OP_ARGS)
{
	if (dest_reg == source_reg) {
		set_register(dest, 0);
		return BASIC_OP_USED_NEITHER;
	}
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		dest->max = dest->value = dest->value ^ source->value;
	} else {
		if (source->max > dest->max) {
			dest->max = source->max;
		}
		dest->value = 0;
	}
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_shr(BASIC_OP_ARGS)
{
	if (source->value > operand_size * 8) {
		clear_register(dest);
		return BASIC_OP_USED_BOTH;
	}
	if (register_is_exactly_known(source) && source->value < 64) {
		dest->value = dest->value >> source->value;
	} else {
		dest->value = 0;
	}
	if (source->value < 64) {
		dest->max = dest->max >> source->value;
	} else {
		dest->max = 0;
	}
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_shl(BASIC_OP_ARGS)
{
	if (register_is_exactly_known(source) && register_is_exactly_known(dest)) {
		if (source->value > operand_size * 8) {
			dest->value = dest->max = 0;
		} else {
			dest->value = dest->max = dest->value << source->value;
		}
	} else {
		clear_register(dest);
	}
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_sar(BASIC_OP_ARGS)
{
	if (source->value > operand_size * 8) {
#ifdef __x86_64__
		// shifts are masked on x86_64
		clear_register(dest);
#else
		set_register(dest, 0);
#endif
		return BASIC_OP_USED_BOTH;
	}
	if (register_is_exactly_known(source)) {
		dest->value = (uintptr_t)(sign_extend(dest->value, operand_size) >> (intptr_t)source->value);
	} else {
		dest->value = 0;
	}
	dest->max = (uintptr_t)(sign_extend(dest->max, operand_size) >> source->value);
	return BASIC_OP_USED_BOTH;
}

enum basic_op_usage basic_op_ror(BASIC_OP_ARGS)
{
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		uintptr_t low = dest->value >> source->value;
		uintptr_t high = dest->value << (8 * operand_size - source->value);
		set_register(dest, low | high);
		return BASIC_OP_USED_BOTH;
	} else {
		clear_register(dest);
		return BASIC_OP_USED_NEITHER;
	}
}

enum basic_op_usage basic_op_mul(BASIC_OP_ARGS)
{
	if (register_is_exactly_known(dest)) {
		switch (dest->value) {
			case 0:
				return BASIC_OP_USED_LEFT;
			case 1:
				*dest = *source;
				return BASIC_OP_USED_BOTH;
		}
		if (register_is_exactly_known(source)) {
			dest->value = dest->max = dest->value * source->value;
			return BASIC_OP_USED_BOTH;
		}
		if (__builtin_mul_overflow(dest->value, source->value, &dest->value) || __builtin_mul_overflow(dest->max, source->max, &dest->max)) {
			clear_register(dest);
		}
		return BASIC_OP_USED_BOTH;
	} else if (register_is_exactly_known(source)) {
		if (source->value == 0) {
			set_register(dest, 0);
			return BASIC_OP_USED_RIGHT;
		} else {
			if (__builtin_mul_overflow(dest->value, source->value, &dest->value) || __builtin_mul_overflow(dest->max, source->max, &dest->max)) {
				clear_register(dest);
			}
			return BASIC_OP_USED_BOTH;
		}
	}
	clear_register(dest);
	return BASIC_OP_USED_BOTH;
}

void merge_and_log_additional_result(__attribute__((unused)) struct loader_context *loader, struct register_state *dest, struct additional_result *additional, int reg)
{
	LOG("primary result: ", temp_str(copy_register_state_description(loader, *dest)), " additional: ", temp_str(copy_register_state_description(loader, additional->state)));
	if (combine_register_states(dest, &additional->state, reg)) {
		additional->used = false;
		LOG("merged result: ", temp_str(copy_register_state_description(loader, *dest)));
	}
}

static inline bool operation_result_crossed_binary_bounds(struct loader_context *loader, struct register_state *state, uintptr_t orig_value)
{
	if (state->value > PAGE_SIZE) {
		struct loaded_binary *binary = binary_for_address(loader, (const void *)orig_value);
		if (binary != NULL && (binary != binary_for_address(loader, (const void *)state->value) || binary != binary_for_address(loader, (const void *)state->max))) {
			return true;
		}
	}
	return false;
}

void widen_cross_binary_bound_operation(struct loader_context *loader, struct register_state *state, struct additional_result *additional, uintptr_t orig_value)
{
	if (operation_result_crossed_binary_bounds(loader, state, orig_value) || (additional->used && operation_result_crossed_binary_bounds(loader, &additional->state, orig_value))) {
		additional->used = false;
		clear_register(state);
	}
}

void set_compare_from_operation(struct registers *regs, int reg, uintptr_t mask)
{
	regs->compare_state = (struct register_comparison){
		.target_register = reg,
		.value = 0,
		.mask = mask,
		.mem_ref = regs->mem_ref,
		.sources = 0,
		.validity = reg == REGISTER_INVALID ? COMPARISON_IS_INVALID : COMPARISON_SUPPORTS_EQUALITY,
	};
}

static bool find_skipped_symbol_for_address(struct loader_context *loader, struct loaded_binary *binary, const void *address, struct address_and_size *out_symbol);

static void print_debug_symbol_requirement(const struct loaded_binary *binary)
{
	ERROR("failed to load debug symbols for ", binary->path);
	ERROR("install debug symbols using your system's package manager or rebuild with debug symbols if this is software you compiled yourself");
	ERROR("on debian-based systems find-dbgsym-packages can help you discover debug symbol packages");
}

static inline bool bsearch_address_callback(int index, void *ordered_addresses, void *needle)
{
	const uintptr_t *ordered = (const uintptr_t *)ordered_addresses;
	return ordered[index] > (uintptr_t)needle;
}

uintptr_t search_find_next_address(struct address_list *list, uintptr_t address)
{
	int count = list->count;
	uintptr_t *addresses = list->addresses;
	int i = bsearch_bool(count, addresses, (void *)address, bsearch_address_callback);
	return i < count ? addresses[i] : ~(uintptr_t)0;
}

void add_address_to_list(struct address_list *list, uintptr_t address)
{
	size_t old_count = list->count;
	uintptr_t *addresses = list->addresses;
	int i = bsearch_bool(old_count, addresses, (void *)address, bsearch_address_callback);
	if (i != 0) {
		if (addresses[i - 1] == address) {
			// already loaded, skip adding
			return;
		}
	}
	size_t new_count = old_count + 1;
	list->count = new_count;
	addresses = list->addresses = realloc(addresses, sizeof(uintptr_t) * new_count);
	for (int j = old_count; j > i; j--) {
		addresses[j] = addresses[j - 1];
	}
	addresses[i] = address;
}

static inline ins_ptr skip_prefix_jumps(struct program_state *analysis, ins_ptr ins, struct decoded_ins *decoded, __attribute__((unused)) function_effects required_effects)
{
	// skip over function stubs that simply call into a target function
	ins_ptr ret = ins;
	if (UNLIKELY(!decode_ins(ins, decoded))) {
		return NULL;
	}
	for (;;) {
		if (is_landing_pad_ins(decoded)) {
			ins_ptr next = next_ins(ins, decoded);
			if (required_effects & EFFECT_AFTER_STARTUP) {
				push_reachable_region(&analysis->loader, &analysis->reachable, ins, next);
			}
			ins = next;
			if (UNLIKELY(!decode_ins(ins, decoded))) {
				return NULL;
			}
		} else {
			ins_ptr jump_target;
			enum ins_jump_behavior jump = ins_interpret_jump_behavior(decoded, &jump_target);
			if (jump != INS_JUMPS_ALWAYS && jump != INS_JUMPS_ALWAYS_INDIRECT) {
				break;
			}
			if (jump_target == NULL || jump_target == ins || jump_target == ret) {
				break;
			}
			struct loaded_binary *binary;
			if ((protection_for_address(&analysis->loader, jump_target, &binary, NULL) & PROT_EXEC) == 0) {
				break;
			}
			if (required_effects & EFFECT_AFTER_STARTUP) {
				push_reachable_region(&analysis->loader, &analysis->reachable, ret, next_ins(ins, decoded));
			}
			ins = jump_target;
			ret = jump_target;
			if (UNLIKELY(!decode_ins(ins, decoded))) {
				return NULL;
			}
		}
	}
	if (UNLIKELY(ins != ret)) {
		if (UNLIKELY(!decode_ins(ret, decoded))) {
			return NULL;
		}
		if (required_effects & EFFECT_AFTER_STARTUP) {
			push_reachable_region(&analysis->loader, &analysis->reachable, ret, next_ins(ins, decoded));
		}
	}
	return ret;
}

__attribute__((noinline)) static void analyze_libcrypto_dlopen(struct program_state *analysis)
{
	if (analysis->loader.libcrypto_dlopen != NULL) {
		struct registers state = empty_registers;
		analysis->loader.searching_libcrypto_dlopen = true;
		struct effect_token token;
		*get_or_populate_effects(analysis, analysis->loader.libcrypto_dlopen, &state, EFFECT_NONE, &token) = EFFECT_NONE;
	}
}

function_effects analyze_call(struct program_state *analysis, function_effects required_effects, struct loaded_binary *binary, ins_ptr ins, ins_ptr call_target, struct analysis_frame *self)
{
#ifdef __x86_64__
	int call_push_count = 2;
#else
	int call_push_count = 0;
#endif
	push_stack(&analysis->loader, &self->current_state, call_push_count, ins);
	struct registers call_state = copy_call_argument_registers(&analysis->loader, &self->current_state, ins);
	dump_nonempty_registers(&analysis->loader, &call_state, ALL_REGISTERS);
	call_state.modified = 0;
	function_effects more_effects = analyze_function(analysis, required_effects & ~EFFECT_ENTRY_POINT, &call_state, call_target, self);
	if (more_effects & EFFECT_PROCESSING) {
		queue_instruction(&analysis->search.queue, call_target, required_effects & ~EFFECT_ENTRY_POINT, &call_state, call_target, self->description);
		more_effects = (more_effects & ~EFFECT_PROCESSING) | EFFECT_RETURNS;
		call_state.modified = ALL_REGISTERS;
	}
	register_mask modified = (call_state.modified & ~STACK_REGISTERS) | (((call_state.modified & STACK_REGISTERS) >> call_push_count) & ALL_REGISTERS);
	if (is_stack_preserving_function(&analysis->loader, binary, call_target)) {
		modified &= ~STACK_REGISTERS;
	}
	pop_stack(&analysis->loader, &self->current_state, call_push_count, ins);
	clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, modified);
	return more_effects;
}

void encountered_non_executable_address(__attribute__((unused)) struct loader_context *loader, __attribute__((unused)) const char *description, __attribute__((unused)) struct analysis_frame *frame,
                                               __attribute__((unused)) ins_ptr target)
{
#if ABORT_AT_NON_EXECUTABLE_ADDRESS
	ERROR("attempted to execute non-executable address: ", temp_str(copy_address_description(loader, target)));
	frame->description = description;
	DIE("at: ", temp_str(copy_call_trace_description(loader, frame)));
#endif
}

static inline bool has_sign_bit(uintptr_t value, uintptr_t mask)
{
	uintptr_t sign_bit = mask & ~(mask >> 1);
	return (value & sign_bit) != 0;
}

__attribute__((always_inline)) static inline bool split_signed_alternate(struct register_state *jump_state, struct register_state *continue_state, struct register_state *alternate_state, const struct register_comparison *comparison)
{
	uintptr_t mask = comparison->mask;
	if (has_sign_bit(jump_state->max, mask) && !has_sign_bit(jump_state->value, mask)) {
		LOG("signed comparison on potentially negative value, splitting");
		alternate_state->max = mask;
		alternate_state->value = mask & ~(mask >> 1);
		continue_state->max = jump_state->max = mask >> 1;
		return true;
	}
	return false;
}

enum alternate_type
{
	ALTERNATE_UNUSED = 0,
	ALTERNATE_CONTINUE,
	ALTERNATE_JUMP,
};

__attribute__((always_inline)) static inline function_effects analyze_conditional_branch(struct program_state *analysis, function_effects required_effects, __attribute__((unused)) ins_ptr ins, struct decoded_ins *decoded,
                                                                                         ins_ptr jump_target, ins_ptr continue_target, struct analysis_frame *self, trace_flags flags)
{
	bool skip_jump = false;
	bool skip_continue = false;
	LOG("found conditional jump to ", temp_str(copy_address_description(&analysis->loader, jump_target)));
	struct loaded_binary *jump_binary = NULL;
	int jump_prot = protection_for_address(&analysis->loader, jump_target, &jump_binary, NULL);
	struct register_comparison compare_state = self->current_state.compare_state;
	ins_conditional_type conditional_type = ins_get_conditional_type(decoded, &compare_state);
	struct register_state jump_state;
	struct register_state continue_state;
	struct register_state alternate_state;
	enum alternate_type uses_alternate_state = ALTERNATE_UNUSED;
	register_mask target_registers = 0;
	register_mask additional_sources = 0;
	if ((compare_state.validity != COMPARISON_IS_INVALID) && register_is_exactly_known(&compare_state.value)) {
		// include matching registers
		if (compare_state.target_register == REGISTER_MEM && !memory_ref_equal(&compare_state.mem_ref, &self->current_state.mem_ref)) {
			LOG("replacing mem r/m for conditional of ", temp_str(copy_memory_ref_description(&analysis->loader, self->current_state.mem_ref)), " with ", temp_str(copy_memory_ref_description(&analysis->loader, compare_state.mem_ref)));
			self->current_state.mem_ref = compare_state.mem_ref;
			self->current_state.registers[REGISTER_MEM].value = 0;
			self->current_state.registers[REGISTER_MEM].max = compare_state.mask;
			clear_match(&analysis->loader, &self->current_state, REGISTER_MEM, self->address);
		}
		jump_state = self->current_state.registers[compare_state.target_register];
		if ((jump_state.value & ~compare_state.mask) != (jump_state.max & ~compare_state.mask)) {
			jump_state.value = 0;
			jump_state.max = compare_state.mask;
		} else {
			jump_state.value &= compare_state.mask;
			jump_state.max &= compare_state.mask;
		}
		continue_state = jump_state;
		target_registers = self->current_state.matches[compare_state.target_register];
		for_each_bit (target_registers, bit, r) {
			// ignore registers that don't exactly match
			// this can happen with partial register moves
			if ((self->current_state.registers[r].value != jump_state.value) || (self->current_state.registers[r].max != jump_state.max)) {
				target_registers &= ~bit;
				LOG("rejecting matching register ", name_for_register(r), " because its range differs");
				dump_registers(&analysis->loader, &self->current_state, bit | mask_for_register(compare_state.target_register));
				LOG("mask: ", compare_state.mask);
			}
		}
		target_registers |= mask_for_register(compare_state.target_register);
		if (SHOULD_LOG) {
			for_each_bit (target_registers, bit, target_register) {
				ERROR_NOPREFIX("comparing ", name_for_register(target_register));
			}
		}
		switch (conditional_type) {
			case INS_CONDITIONAL_TYPE_BELOW:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jb comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					// cmp %target_register; jb
					if (jump_state.value >= compare_state.value.value) {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					} else if (jump_state.max >= compare_state.value.value) {
						jump_state.max = compare_state.value.value - 1;
					}
					if (continue_state.max < compare_state.value.value) {
						skip_continue = true;
						LOG("continue jump with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					} else if (continue_state.value < compare_state.value.value) {
						continue_state.value = compare_state.value.value;
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_ABOVE_OR_EQUAL:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jae comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					// cmp %target_register; jae
					if (jump_state.max < compare_state.value.value) {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					} else if (jump_state.value < compare_state.value.value) {
						jump_state.value = compare_state.value.value;
					}
					if (continue_state.value >= compare_state.value.value) {
						skip_continue = true;
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					} else if (continue_state.max >= compare_state.value.value) {
						continue_state.max = compare_state.value.value - 1;
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_EQUAL:
				if (compare_state.validity & COMPARISON_SUPPORTS_EQUALITY) {
					LOG("found je comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					// test %target_register; je
					if (jump_state.value <= compare_state.value.value && compare_state.value.value <= jump_state.max) {
						jump_state = compare_state.value;
						additional_sources = compare_state.sources;
						// remove value from edge of ranges
						if (continue_state.value == compare_state.value.value) {
							if (register_is_exactly_known(&continue_state)) {
								skip_continue = true;
								LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
							} else {
								continue_state.value++;
							}
						} else if (continue_state.max == compare_state.value.value) {
							continue_state.max--;
						} else {
							uses_alternate_state = ALTERNATE_CONTINUE;
							alternate_state.value = compare_state.value.value + 1;
							alternate_state.max = continue_state.max;
							continue_state.max = compare_state.value.value - 1;
						}
					} else {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_NOT_EQUAL:
				if (compare_state.validity & COMPARISON_SUPPORTS_EQUALITY) {
					LOG("found jne comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					// test %target_register; jne
					if (continue_state.value <= compare_state.value.value && compare_state.value.value <= continue_state.max) {
						continue_state = compare_state.value;
						additional_sources |= compare_state.sources;
						// remove value from edge of ranges
						if (jump_state.value == compare_state.value.value) {
							if (register_is_exactly_known(&jump_state)) {
								skip_jump = true;
								LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
							} else {
								jump_state.value++;
							}
						} else if (jump_state.max == compare_state.value.value) {
							jump_state.max--;
						} else {
							uses_alternate_state = ALTERNATE_JUMP;
							alternate_state.value = compare_state.value.value + 1;
							alternate_state.max = jump_state.max;
							jump_state.max = compare_state.value.value - 1;
						}
					} else {
						skip_continue = true;
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_BELOW_OR_EQUAL:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jbe comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					// cmp %target_register; jbe
					if (jump_state.value > compare_state.value.value) {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					} else if (jump_state.max > compare_state.value.value) {
						jump_state.max = compare_state.value.value;
					}
					if (continue_state.max <= compare_state.value.value) {
						skip_continue = true;
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					} else if (continue_state.value <= compare_state.value.value) {
						continue_state.value = compare_state.value.value + 1;
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_ABOVE:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found ja comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					// cmp %target_register; ja
					if (jump_state.max <= compare_state.value.value) {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					} else if (jump_state.value <= compare_state.value.value) {
						jump_state.value = compare_state.value.value + 1;
					}
					if (continue_state.value > compare_state.value.value) {
						skip_continue = true;
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					} else if (continue_state.max > compare_state.value.value) {
						continue_state.max = compare_state.value.value;
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_SIGN:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found js comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					if (compare_state.value.value == 0) {
						uintptr_t msb = most_significant_bit(compare_state.mask);
						// cmp %target_register; ja
						if (jump_state.max < msb) {
							skip_jump = true;
							LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
						} else if (jump_state.value < msb) {
							jump_state.value = msb;
						}
						if (continue_state.value >= msb) {
							skip_continue = true;
							LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
						} else if (continue_state.max >= msb) {
							continue_state.max = msb - 1;
						}
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_NOT_SIGN:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jns comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					if (compare_state.value.value == 0) {
						uintptr_t msb = most_significant_bit(compare_state.mask);
						// cmp %target_register; ja
						if (jump_state.value >= msb) {
							skip_jump = true;
							LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
						} else if (jump_state.max >= msb) {
							jump_state.max = msb - 1;
						}
						if (continue_state.max < msb) {
							skip_continue = true;
							LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
						} else if (continue_state.value < msb) {
							continue_state.value = msb;
						}
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_LOWER:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jl comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					// cmp %target_register; jl
					if (split_signed_alternate(&jump_state, &continue_state, &alternate_state, &compare_state)) {
						uses_alternate_state = ALTERNATE_JUMP;
					}
					if (jump_state.value >= compare_state.value.value) {
						if (uses_alternate_state) {
							uses_alternate_state = ALTERNATE_UNUSED;
							jump_state = alternate_state;
						} else {
							skip_jump = true;
							LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
						}
					} else if (jump_state.max > compare_state.value.value) {
						jump_state.max = compare_state.value.value;
					}
					if (continue_state.max < compare_state.value.value) {
						skip_continue = true;
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					} else if (continue_state.value < compare_state.value.value) {
						continue_state.value = compare_state.value.value;
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_GREATER_OR_EQUAL:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jge comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					if (split_signed_alternate(&jump_state, &continue_state, &alternate_state, &compare_state)) {
						uses_alternate_state = ALTERNATE_CONTINUE;
					}
					// cmp %target_register; jge
					if (jump_state.max < compare_state.value.value) {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					} else if (jump_state.value < compare_state.value.value) {
						jump_state.value = compare_state.value.value;
					}
					if (continue_state.value >= compare_state.value.value) {
						if (uses_alternate_state) {
							uses_alternate_state = ALTERNATE_UNUSED;
							continue_state = alternate_state;
						} else {
							skip_continue = true;
							LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
						}
					} else if (continue_state.max >= compare_state.value.value) {
						continue_state.max = compare_state.value.value - 1;
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_NOT_GREATER:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jng comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					if (split_signed_alternate(&jump_state, &continue_state, &alternate_state, &compare_state)) {
						uses_alternate_state = ALTERNATE_JUMP;
					}
					// cmp %target_register; jng
					if (jump_state.value > compare_state.value.value) {
						if (uses_alternate_state) {
							uses_alternate_state = ALTERNATE_UNUSED;
							jump_state = alternate_state;
						} else {
							LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
							skip_jump = true;
						}
					} else if (continue_state.max < compare_state.value.value) {
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
						skip_continue = true;
					} else {
						if (jump_state.max > compare_state.value.value) {
							jump_state.max = compare_state.value.value;
						}
						if (jump_state.value > compare_state.value.value) {
							jump_state.value = compare_state.value.value;
						}
						if (continue_state.max < compare_state.value.value) {
							continue_state.max = compare_state.value.value;
						}
						if (continue_state.value < compare_state.value.value) {
							continue_state.value = compare_state.value.value;
						}
					}
				}
				break;
			case INS_CONDITIONAL_TYPE_GREATER:
				if (compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
					LOG("found jg comparing ", name_for_register(compare_state.target_register), " with ", temp_str(copy_register_state_description(&analysis->loader, compare_state.value)), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					if (split_signed_alternate(&jump_state, &continue_state, &alternate_state, &compare_state)) {
						uses_alternate_state = ALTERNATE_CONTINUE;
					}
					// cmp %target_register; jg
					if (continue_state.value > compare_state.value.value) {
						if (uses_alternate_state) {
							uses_alternate_state = ALTERNATE_UNUSED;
							continue_state = alternate_state;
						} else {
							LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
							skip_continue = true;
						}
					} else if (jump_state.max < compare_state.value.value) {
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
						skip_jump = true;
					} else {
						if (continue_state.max > compare_state.value.value) {
							continue_state.max = compare_state.value.value;
						}
						if (continue_state.value > compare_state.value.value) {
							continue_state.value = compare_state.value.value;
						}
						if (jump_state.max < compare_state.value.value) {
							jump_state.max = compare_state.value.value;
						}
						if (jump_state.value < compare_state.value.value) {
							jump_state.value = compare_state.value.value;
						}
					}
				}
				break;
#ifdef INS_CONDITIONAL_TYPE_BIT_CLEARED
			case INS_CONDITIONAL_TYPE_BIT_CLEARED: {
				uintptr_t bit = (uintptr_t)1 << compare_state.value.value;
				LOG("found tbz comparing ", name_for_register(compare_state.target_register), ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
				// tbz %target_register
				if (register_is_exactly_known(&continue_state)) {
					if ((continue_state.value & bit) == 0) {
						skip_continue = true;
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					} else {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					}
					break;
				}
				// check if bit couldn't ever be set
				if (continue_state.max < bit) {
					skip_continue = true;
					LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					break;
				}
				// check if bit couldn't ever be cleared
				if ((continue_state.value & bit) && ((continue_state.value | (bit - 1)) <= continue_state.max)) {
					skip_jump = true;
					LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					break;
				}
				// check if testing the top bit in the range
				if ((continue_state.max >> compare_state.value.value) == 0) {
					continue_state.value = bit;
					jump_state.max = bit - 1;
					break;
				}
				if (continue_state.value < bit && (continue_state.max & bit)) {
					continue_state.value = bit;
				}
				break;
			}
#endif
#ifdef INS_CONDITIONAL_TYPE_BIT_SET
			case INS_CONDITIONAL_TYPE_BIT_SET: {
				uintptr_t bit = (uintptr_t)1 << compare_state.value.value;
				LOG("found tbnz comparing bit ", compare_state.value.value, ": ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
				// tbnz %target_register
				if (register_is_exactly_known(&continue_state)) {
					if ((continue_state.value & bit) == 0) {
						skip_jump = true;
						LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					} else {
						skip_continue = true;
						LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
					}
					break;
				}
				// check if bit couldn't ever be set
				if (continue_state.max < bit) {
					skip_jump = true;
					LOG("skipping jump with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					break;
				}
				// check if bit couldn't ever be cleared
				if ((continue_state.value & bit) && ((continue_state.value | (bit - 1)) <= continue_state.max)) {
					skip_continue = true;
					LOG("skipping continue with ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
					break;
				}
				// check if testing the top bit in the range
				if ((continue_state.max >> compare_state.value.value) == 0) {
					jump_state.value = bit;
					continue_state.max = bit - 1;
					break;
				}
				if (continue_state.value < bit && (continue_state.max & bit)) {
					jump_state.value = bit;
				}
				break;
			}
#endif
			default:
				break;
		}
		canonicalize_register(&jump_state);
		canonicalize_register(&continue_state);
		if (skip_jump) {
			LOG("skipping jump to ", temp_str(copy_address_description(&analysis->loader, jump_target)), " because value wasn't possible");
			self->description = "skip conditional jump";
			vary_effects_by_registers(&analysis->search, &analysis->loader, self, target_registers | compare_state.sources, 0, 0, required_effects);
		} else {
			LOG("jump value is ", temp_str(copy_register_state_description(&analysis->loader, jump_state)));
			if (uses_alternate_state == ALTERNATE_JUMP) {
				LOG("additional jump value is ", temp_str(copy_register_state_description(&analysis->loader, alternate_state)));
			}
		}
		if (skip_continue) {
			LOG("skipping continue to ", temp_str(copy_address_description(&analysis->loader, continue_target)), " because value wasn't possible");
			self->description = "skip conditional continue";
			vary_effects_by_registers(&analysis->search, &analysis->loader, self, target_registers | compare_state.sources, 0, 0, required_effects);
		} else {
			LOG("continue value is ", temp_str(copy_register_state_description(&analysis->loader, continue_state)));
			if (uses_alternate_state == ALTERNATE_CONTINUE) {
				LOG("additional continue value is ", temp_str(copy_register_state_description(&analysis->loader, alternate_state)));
			}
		}
		if (!(skip_jump || skip_continue) && compare_state.sources != 0) {
			self->description = "conditional jump predicate";
			vary_effects_by_registers(&analysis->search, &analysis->loader, self, target_registers | compare_state.sources, 0, 0, required_effects);
		}
	} else {
		LOG("comparison state is not valid");
	}
	function_effects jump_effects;
	function_effects continue_effects = EFFECT_NONE;
	{
		for_each_bit (target_registers, bit, r) {
			self->current_state.sources[r] |= additional_sources;
		}
	}
	bool continue_first = continue_target < jump_target;
	if (continue_first) {
		if (skip_continue) {
		} else {
			LOG("taking continue to ", temp_str(copy_address_description(&analysis->loader, continue_target)));
			for_each_bit (target_registers, bit, r) {
				self->current_state.registers[r] = continue_state;
			}
			// set_effects(&analysis->search, self->entry, &self->token, effects | EFFECT_PROCESSING, 0);
			self->description = skip_jump ? "conditional continue (no jump)" : "conditional continue";
			continue_effects = analyze_instructions(analysis, required_effects, &self->current_state, continue_target, self, flags);
			LOG("resuming from conditional continue of ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			if (uses_alternate_state == ALTERNATE_CONTINUE) {
				LOG("taking additional continue of ", temp_str(copy_address_description(&analysis->loader, continue_target)));
				for_each_bit (target_registers, bit, r) {
					self->current_state.registers[r] = alternate_state;
				}
				// set_effects(&analysis->search, self->entry, &self->token, effects | EFFECT_PROCESSING, 0);
				self->description = skip_jump ? "additional conditional continue (no jump)" : "additional conditional continue";
				continue_effects |= analyze_instructions(analysis, required_effects, &self->current_state, continue_target, self, flags);
				LOG("resuming from additional conditional continue of ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			}
		}
	}
	if (skip_jump) {
		jump_effects = EFFECT_NONE;
	} else if ((jump_prot & PROT_EXEC) == 0) {
		encountered_non_executable_address(&analysis->loader, "conditional jump", self, jump_target);
		LOG("found conditional jump to non-executable address, assuming default effects");
		jump_effects = DEFAULT_EFFECTS;
	} else {
		LOG("taking jump to ", temp_str(copy_address_description(&analysis->loader, jump_target)));
		for_each_bit (target_registers, bit, r) {
			self->current_state.registers[r] = jump_state;
		}
		self->description = skip_continue ? "conditional jump (no continue)" : "conditional jump";
		jump_effects = analyze_instructions(analysis, required_effects, &self->current_state, jump_target, self, flags);
		if (uses_alternate_state == ALTERNATE_JUMP) {
			LOG("completing conditional jump of ", temp_str(copy_address_description(&analysis->loader, ins)), ", taking additional jump", temp_str(copy_address_description(&analysis->loader, jump_target)));
			for_each_bit (target_registers, bit, r) {
				self->current_state.registers[r] = alternate_state;
			}
			self->description = skip_continue ? "additional conditional jump (no continue)" : "additional conditional jump";
			jump_effects |= analyze_instructions(analysis, required_effects, &self->current_state, jump_target, self, flags);
		}
	}
	if (continue_first) {
		LOG("completing conditional jump after branch at ", temp_str(copy_address_description(&analysis->loader, ins)));
	} else {
		LOG("resuming from conditional jump at ", temp_str(copy_address_description(&analysis->loader, ins)));
		if (skip_continue) {
		} else {
			LOG("taking continue of ", temp_str(copy_address_description(&analysis->loader, continue_target)));
			for_each_bit (target_registers, bit, r) {
				self->current_state.registers[r] = continue_state;
			}
			// set_effects(&analysis->search, self->entry, &self->token, effects | EFFECT_PROCESSING, 0);
			self->description = skip_jump ? "conditional continue (no jump)" : "conditional continue";
			continue_effects = analyze_instructions(analysis, required_effects, &self->current_state, continue_target, self, flags);
			LOG("completing conditional jump after continue of ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			if (uses_alternate_state == ALTERNATE_CONTINUE) {
				LOG("taking additional continue of ", temp_str(copy_address_description(&analysis->loader, continue_target)));
				for_each_bit (target_registers, bit, r) {
					self->current_state.registers[r] = alternate_state;
				}
				// set_effects(&analysis->search, self->entry, &self->token, effects | EFFECT_PROCESSING, 0);
				self->description = skip_jump ? "additional conditional continue (no jump)" : "additional conditional continue";
				continue_effects |= analyze_instructions(analysis, required_effects, &self->current_state, continue_target, self, flags);
				LOG("completing additional conditional jump after continue of ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			}
		}
	}
	if (continue_effects & EFFECT_PROCESSING) {
		LOG("continue of ", temp_str(copy_address_description(&analysis->loader, continue_target)), " is processing");
		continue_effects = (continue_effects & EFFECT_STICKY_EXITS) ? EFFECT_EXITS : EFFECT_NONE;
	}
	if (jump_effects & EFFECT_PROCESSING) {
		LOG("jump of ", temp_str(copy_address_description(&analysis->loader, jump_target)), " is processing");
		jump_effects = (jump_effects & EFFECT_STICKY_EXITS) ? EFFECT_EXITS : EFFECT_NONE;
	}
	return jump_effects | continue_effects;
}

__attribute__((warn_unused_result)) __attribute__((nonnull(1))) static int find_string(const char **haystack, const char *needle)
{
	if (needle != NULL) {
		for (int i = 0; haystack[i] != NULL; i++) {
			if (fs_strcmp(haystack[i], needle) == 0) {
				return i;
			}
		}
	}
	return -1;
}

__attribute__((warn_unused_result)) __attribute__((nonnull(1))) static int find_first_prefix(const char **haystack, const char *needle)
{
	if (needle != NULL) {
		for (int i = 0; haystack[i] != NULL; i++) {
			if (fs_strncmp(haystack[i], needle, fs_strlen(haystack[i])) == 0) {
				return i;
			}
		}
	}
	return -1;
}

static const char *setxid_names[] = {
	"setuid",
	"setgid",
	"seteuid",
	"setegid",
	"setreuid",
	"setregid",
	"setresuid",
	"setresgid",
	"setgroups",
	NULL,
};

static bool is_setxid_name(const char *name)
{
	return find_string(setxid_names, name) != -1;
}

__attribute__((noinline)) static bool is_landing_pad_ins_decode(ins_ptr addr)
{
	struct decoded_ins decoded;
	if (decode_ins(addr, &decoded)) {
		return is_landing_pad_ins(&decoded);
	}
	return false;
}

enum possible_conditions calculate_possible_conditions(__attribute__((unused)) const struct loader_context *loader, ins_conditional_type cond, struct registers *current_state)
{
	LOG("calculating possible conditions for ", temp_str(copy_register_state_description(loader, current_state->compare_state.value)));
	switch (cond) {
		case INS_CONDITIONAL_TYPE_BELOW:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].value >= current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].max < current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case INS_CONDITIONAL_TYPE_ABOVE_OR_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].max < current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].value >= current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case INS_CONDITIONAL_TYPE_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_EQUALITY) {
				if (current_state->registers[current_state->compare_state.target_register].value <= current_state->compare_state.value.value &&
				    current_state->compare_state.value.value <= current_state->registers[current_state->compare_state.target_register].max)
				{
					if (current_state->registers[current_state->compare_state.target_register].value == current_state->compare_state.value.value) {
						if (register_is_exactly_known(&current_state->registers[current_state->compare_state.target_register])) {
							return ALWAYS_MATCHES;
						}
					}
				} else {
					return NEVER_MATCHES;
				}
			}
			break;
		case INS_CONDITIONAL_TYPE_NOT_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_EQUALITY) {
				if (current_state->registers[current_state->compare_state.target_register].value <= current_state->compare_state.value.value &&
				    current_state->compare_state.value.value <= current_state->registers[current_state->compare_state.target_register].max)
				{
					if (current_state->registers[current_state->compare_state.target_register].value == current_state->compare_state.value.value) {
						if (register_is_exactly_known(&current_state->registers[current_state->compare_state.target_register])) {
							return NEVER_MATCHES;
						}
					}
				} else {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case INS_CONDITIONAL_TYPE_BELOW_OR_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].value > current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].max <= current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case INS_CONDITIONAL_TYPE_ABOVE:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].max <= current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].value > current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case INS_CONDITIONAL_TYPE_SIGN:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->compare_state.value.value == 0) {
					uintptr_t msb = most_significant_bit(current_state->compare_state.mask);
					if (current_state->registers[current_state->compare_state.target_register].max < msb) {
						return NEVER_MATCHES;
					}
					if (current_state->registers[current_state->compare_state.target_register].value >= msb) {
						return ALWAYS_MATCHES;
					}
				}
			}
			break;
		case INS_CONDITIONAL_TYPE_NOT_SIGN:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->compare_state.value.value == 0) {
					uintptr_t msb = most_significant_bit(current_state->compare_state.mask);
					if (current_state->registers[current_state->compare_state.target_register].value >= msb) {
						return NEVER_MATCHES;
					}
					if (current_state->registers[current_state->compare_state.target_register].max < msb) {
						return ALWAYS_MATCHES;
					}
				}
			}
			break;
		default:
			break;
	}
	return POSSIBLY_MATCHES;
}

bool is_stack_preserving_function(struct loader_context *loader, struct loaded_binary *binary, ins_ptr addr)
{
	if (binary_has_flags(binary, BINARY_IS_LIBCRYPTO)) {
		return true;
	}
	if (binary_has_flags(binary, BINARY_IS_GOLANG)) {
		const char *name = find_any_symbol_name_by_address(loader, binary, addr, NORMAL_SYMBOL | LINKER_SYMBOL);
		if (name != NULL) {
			if (fs_strcmp(name, "runtime.entersyscall") == 0 || fs_strcmp(name, "runtime.exitsyscall") == 0 || fs_strcmp(name, "runtime.Syscall6") == 0 || fs_strcmp(name, "runtime.RawSyscall6") == 0 ||
			    fs_strcmp(name, "runtime/internal/syscall.Syscall6") == 0)
			{
				LOG("found golang stack preserving function: ", temp_str(copy_address_description(loader, addr)));
				return true;
			}
		} else {
			// TODO: find a better way to annotate known stack preserving go runtime functions properly without symbols
			return true;
		}
	}
	if (binary_has_flags(binary, BINARY_IS_LIBC | BINARY_IS_PTHREAD)) {
		if (addr == loader->enable_async_cancel) {
			LOG("found enable_async_cancel stack preserving function");
			return true;
		}
		const char *name = find_any_symbol_name_by_address(loader, binary, addr, NORMAL_SYMBOL | LINKER_SYMBOL);
		if (name != NULL) {
			if (fs_strcmp(name, "read_int") == 0 || fs_strcmp(name, "__printf_buffer_write") == 0 || fs_strcmp(name, "__pthread_enable_asynccancel") == 0 || fs_strcmp(name, "__libc_enable_asynccancel") == 0) {
				return true;
			}
		}
		return false;
	}
	return false;
}

void clear_comparison_state(struct registers *state)
{
	if (UNLIKELY(state->compare_state.validity != COMPARISON_IS_INVALID)) {
		state->compare_state.validity = COMPARISON_IS_INVALID;
		LOG("clearing comparison");
	}
}

void set_comparison_state(__attribute__((unused)) struct loader_context *loader, struct registers *state, struct register_comparison comparison)
{
	state->compare_state = comparison;
	LOG("comparing ", name_for_register(state->compare_state.target_register), " containing ", temp_str(copy_register_state_description(loader, state->registers[state->compare_state.target_register])), " with", temp_str(copy_register_state_description(loader, state->compare_state.value)));
}

static bool is_musl_cp_begin(ins_ptr entry)
{
	// a giant hack -- this is for musl's cancel_handler comparing the interrupted pc to __cp_begin and __cp_end
#ifdef __x86_64__
	if (entry[0] == 0x49 && entry[1] == 0x89 && entry[2] == 0xfb) {
		if (entry[3] == 0x48 && entry[4] == 0x89 && entry[5] == 0xf0) {
			if (entry[6] == 0x48 && entry[7] == 0x89 && entry[8] == 0xd7) {
				if (entry[9] == 0x48 && entry[10] == 0x89 && entry[11] == 0xce) {
					if (entry[12] == 0x4C && entry[13] == 0x89 && entry[14] == 0xc2) {
						if (entry[15] == 0x4D && entry[16] == 0x89 && entry[17] == 0xca) {
							return true;
						}
					}
				}
			}
		}
	}
	return false;
#endif
#ifdef __aarch64__
	if (entry[0] == 0xaa0103e8) {
		if (entry[1] == 0xaa0203e0) {
			if (entry[2] == 0xaa0303e1) {
				if (entry[3] == 0xaa0403e2) {
					if (entry[4] == 0xaa0503e3) {
						if (entry[5] == 0xaa0603e4) {
							if (entry[6] == 0xaa0703e5) {
								return true;
							}
						}
					}
				}
			}
		}
	}
	return false;
#endif
}

uint8_t analyze_syscall_instruction(struct program_state *analysis, struct analysis_frame *self, struct additional_result *additional, const struct analysis_frame *caller, ins_ptr ins,
                                    function_effects required_effects, function_effects *effects)
{
	// clear registers that are clobbered upon syscall entry
	for_each_bit ((register_mask)REGISTER_SYSCALL_ADDITIONAL_CLEARED, bit, r) {
		clear_register(&self->current_state.registers[r]);
		self->current_state.sources[r] = 0;
		clear_match(&analysis->loader, &self->current_state, r, ins);
	}
	additional->used = false;
	clear_comparison_state(&self->current_state);
	if (register_is_exactly_known(&self->current_state.registers[REGISTER_SYSCALL_NR])) {
	syscall_nr_is_known:;
		uintptr_t value = self->current_state.registers[REGISTER_SYSCALL_NR].value;
		self->description = NULL;
		LOG("found syscall with known number ", (int)value, " named ", name_for_syscall(value), " at ", temp_str(copy_call_trace_description(&analysis->loader, self)));
		self->description = "syscall";
		// special case musl's fopen
#ifdef __x86_64__
		uintptr_t musl_fopen_syscall = LINUX_SYS_open;
		uintptr_t musl_fopen_mode_arg = 1;
#endif
#ifdef __aarch64__
		uintptr_t musl_fopen_syscall = LINUX_SYS_openat;
		uintptr_t musl_fopen_mode_arg = 2;
#endif
		if (value == musl_fopen_syscall && !register_is_partially_known(&self->current_state.registers[syscall_argument_abi_register_indexes[musl_fopen_mode_arg]])) {
			struct loaded_binary *binary = binary_for_address(&analysis->loader, ins);
			if (binary != NULL && (binary->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_MAIN))) {
				const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, ins, NORMAL_SYMBOL | LINKER_SYMBOL);
				if (name != NULL && (fs_strcmp(name, "fopen") == 0 || fs_strcmp(name, "fopen64") == 0)) {
					size_t count = analysis->search.fopen_mode_count;
					if (count != 0 && register_is_exactly_known(&analysis->search.fopen_modes[count - 1])) {
						const char *mode_str = (const char *)analysis->search.fopen_modes[count - 1].value;
						struct loaded_binary *mode_binary;
						int prot = protection_for_address(&analysis->loader, mode_str, &mode_binary, NULL);
						if ((prot & (PROT_READ | PROT_WRITE)) == PROT_READ) {
							int mode = musl_fmodeflags(mode_str);
							set_register(&self->current_state.registers[syscall_argument_abi_register_indexes[musl_fopen_mode_arg]], mode);
						}
					}
				}
			}
		}
		record_syscall(analysis, value, *self, required_effects);
		// syscalls always populate the result
		// errors between -4095 and -1
		additional->used = true;
		additional->state.value = -4095;
		additional->state.max = -1;
		// success values >= 0
		self->current_state.registers[REGISTER_SYSCALL_RESULT].value = 0;
		self->current_state.registers[REGISTER_SYSCALL_RESULT].max = (~(uintptr_t)0) >> 1;
		self->current_state.sources[REGISTER_SYSCALL_RESULT] = 0;
		clear_match(&analysis->loader, &self->current_state, REGISTER_SYSCALL_RESULT, ins);
		switch (info_for_syscall(value).attributes & SYSCALL_RETURN_MASK) {
			case SYSCALL_RETURNS_SELF_PID:
				// getpid fills the pid into the result
				if (analysis->loader.pid) {
					set_register(&self->current_state.registers[REGISTER_SYSCALL_RESULT], analysis->loader.pid);
				}
				additional->used = false;
				break;
			case SYSCALL_RETURNS_NEVER:
				// exit and exitgroup always exit the thread, rt_sigreturn always perform a non-local jump
				*effects |= EFFECT_EXITS;
				LOG("completing from exit or rt_sigreturn syscall: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
				additional->used = false;
				return SYSCALL_ANALYSIS_UPDATE_AND_RETURN;
			case SYSCALL_RETURNS_ERROR:
				self->current_state.registers[REGISTER_SYSCALL_RESULT].max = 0;
				break;
			case SYSCALL_RETURNS_ALWAYS_VALID:
				additional->used = false;
				break;
		}
	} else if (caller->description != NULL && fs_strcmp(caller->description, ".data.rel.ro") == 0 && binary_has_flags(analysis->loader.main, BINARY_IS_GOLANG)) {
		vary_effects_by_registers(&analysis->search, &analysis->loader, self, syscall_argument_abi_used_registers_for_argc[6], syscall_argument_abi_used_registers_for_argc[0], syscall_argument_abi_used_registers_for_argc[0], 0);
	} else if (analysis->loader.searching_setxid && analysis->loader.setxid_syscall == NULL) {
		self->description = "syscall";
		analysis->loader.setxid_syscall = self->address;
		analysis->loader.setxid_syscall_entry = self->entry;
		LOG("found setxid dynamic syscall: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
	} else if (analysis->loader.searching_setxid_sighandler && analysis->loader.setxid_sighandler_syscall == NULL) {
		self->description = "syscall";
		analysis->loader.setxid_sighandler_syscall = self->address;
		analysis->loader.setxid_sighandler_syscall_entry = self->entry;
		LOG("found setxid_sighandler dynamic syscall: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
	} else if (self->address == analysis->loader.setxid_sighandler_syscall) {
		self->description = NULL;
		LOG("unknown setxid_sighandler syscall, assumed covered by set*id handlers: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
	} else if (self->address == analysis->loader.setxid_syscall) {
		self->description = NULL;
		LOG("unknown setxid syscall, assumed covered by set*id handlers: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
	} else {
		struct loaded_binary *binary = binary_for_address(&analysis->loader, ins);
		if (binary != NULL) {
			if (binary->special_binary_flags & BINARY_IS_INTERPRETER && is_musl_cp_begin(self->entry)) {
				// a giant hack -- this is for musl's cancel_handler comparing the interrupted pc to __cp_begin and __cp_end
				self->description = NULL;
				LOG("found musl __cp_begin: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
				return SYSCALL_ANALYSIS_EXIT;
			}
			if (binary->special_binary_flags & (BINARY_IS_LIBC | BINARY_IS_INTERPRETER | BINARY_IS_MAIN)) {
				const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, ins, NORMAL_SYMBOL | LINKER_SYMBOL);
				if (name != NULL && fs_strcmp(name, "next_line") == 0) {
					// this is a giant hack
					self->current_state.registers[REGISTER_SYSCALL_NR].value = self->current_state.registers[REGISTER_SYSCALL_NR].max = LINUX_SYS_read;
					goto syscall_nr_is_known;
				}
				if (analysis->loader.setxid_syscall == NULL || analysis->loader.setxid_sighandler_syscall == NULL) {
					for (const struct analysis_frame *frame = self->next; frame != NULL; frame = frame->next) {
						name = find_any_symbol_name_by_address(&analysis->loader, binary, frame->entry, NORMAL_SYMBOL | LINKER_SYMBOL);
						if (name != NULL) {
							if (is_setxid_name(name)) {
								if (analysis->loader.setxid_syscall == NULL) {
									self->description = NULL;
									analysis->loader.setxid_syscall = self->address;
									analysis->loader.setxid_syscall_entry = self->entry;
									LOG("found __nptl_setxid/do_setxid: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
									return SYSCALL_ANALYSIS_CONTINUE;
								}
							} else if (fs_strcmp(name, "pthread_create") == 0) {
								if (analysis->loader.setxid_sighandler_syscall == NULL) {
									self->description = NULL;
									analysis->loader.setxid_sighandler_syscall = self->address;
									analysis->loader.setxid_sighandler_syscall_entry = self->entry;
									LOG("found __nptl_setxid_sighandler: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
									return SYSCALL_ANALYSIS_CONTINUE;
								}
							}
						}
					}
				}
				if (analysis->loader.setxid_syscall == self->address || analysis->loader.setxid_sighandler_syscall == self->address) {
					return SYSCALL_ANALYSIS_CONTINUE;
				}
			}
		}
		self->description = NULL;
		if (binary_has_flags(binary_for_address(&analysis->loader, self->next->address), BINARY_IS_PERL)) {
			LOG("found perl syscall with unknown number: ", temp_str(copy_register_state_description(&analysis->loader, self->current_state.registers[REGISTER_SYSCALL_NR])));
			clear_register(&self->current_state.registers[REGISTER_SYSCALL_RESULT]);
			self->current_state.sources[REGISTER_SYSCALL_RESULT] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_SYSCALL_RESULT, ins);
			return SYSCALL_ANALYSIS_CONTINUE;
		}
		if (analysis->loader.searching_for_internal_syscall_cancel) {
			for (int i = 0; i < CANCEL_SYSCALL_SLOT_COUNT; i++) {
				if (analysis->loader.internal_syscall_cancel_syscall[i] == NULL) {
					analysis->loader.internal_syscall_cancel_syscall[i] = self->address;
					LOG("found internal_syscall_cancel_syscall: ", temp_str(copy_address_description(&analysis->loader, self->address)));
					return SYSCALL_ANALYSIS_CONTINUE;
				}
			}
		}
		for (int i = 0; i < CANCEL_SYSCALL_SLOT_COUNT; i++) {
			if (analysis->loader.internal_syscall_cancel_syscall[i] == self->address) {
				LOG("ignoring unknown syscall inside internal_syscall_cancel: ", temp_str(copy_register_state_description(&analysis->loader, self->current_state.registers[REGISTER_SYSCALL_NR])));
				return SYSCALL_ANALYSIS_CONTINUE;
			}
		}
		if (required_effects & EFFECT_AFTER_STARTUP) {
			ERROR("found syscall with unknown number at ", temp_str(copy_register_state_description(&analysis->loader, self->current_state.registers[REGISTER_SYSCALL_NR])));
		} else {
			LOG("found syscall with unknown number at ", temp_str(copy_register_state_description(&analysis->loader, self->current_state.registers[REGISTER_SYSCALL_NR])));
		}
		if (SHOULD_LOG) {
			register_mask relevant_registers = mask_for_register((enum register_index)REGISTER_SYSCALL_NR);
			for (const struct analysis_frame *ancestor = self;;) {
				ERROR_NOPREFIX("from call site", temp_str(copy_address_description(&analysis->loader, ancestor->address)));
				register_mask new_relevant_registers = 0;
				for_each_bit (relevant_registers, bit, i) {
					new_relevant_registers |= ancestor->current_state.sources[i];
				}
				if (new_relevant_registers == 0) {
					ERROR_NOPREFIX("using no registers from block entry", temp_str(copy_address_description(&analysis->loader, ancestor->entry)));
					break;
				}
				ERROR_NOPREFIX("using registers from block entry", temp_str(copy_address_description(&analysis->loader, ancestor->entry)));
				dump_registers(&analysis->loader, &ancestor->current_state, new_relevant_registers);
				ancestor = (struct analysis_frame *)ancestor->next;
				if (ancestor == NULL) {
					break;
				}
				relevant_registers = new_relevant_registers;
			}
		}
		self->description = NULL;
		if (required_effects & EFFECT_AFTER_STARTUP) {
			ERROR("full call stack: ", temp_str(copy_call_trace_description_with_additional(&analysis->loader, self, blocked_function_trace_callback, NULL)));
		} else {
			LOG("full call stack: ", temp_str(copy_call_trace_description_with_additional(&analysis->loader, self, blocked_function_trace_callback, NULL)));
		}
		dump_nonempty_registers(&analysis->loader, &self->current_state, ALL_REGISTERS);
		clear_register(&self->current_state.registers[REGISTER_SYSCALL_NR]);
		self->current_state.sources[REGISTER_SYSCALL_NR] = 0;
		clear_match(&analysis->loader, &self->current_state, REGISTER_SYSCALL_NR, ins);
		if (required_effects & EFFECT_AFTER_STARTUP) {
			DIE("try blocking a function from the call stack using --block-function or --block-debug-function");
		}
	}
	return SYSCALL_ANALYSIS_CONTINUE;
}


static void handle_internal_syscall_cancel(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller,
                                    __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("received __internal_syscall_cancel: ", temp_str(copy_function_call_description(&analysis->loader, ins, state)));
	dump_registers(&analysis->loader, state, mask_for_register(REGISTER_STACK_8));
	for (int i = 0; i < CANCEL_SYSCALL_SLOT_COUNT; i++) {
		if (analysis->loader.internal_syscall_cancel_syscall[i] != NULL) {
			struct analysis_frame self = (struct analysis_frame){
				.next = caller,
				.address = analysis->loader.internal_syscall_cancel_syscall[i],
				.description = "internal_syscall",
				.current_state = empty_registers,
				.entry = ins,
				.entry_state = state,
			};
			for (int i = 0; i < 6; i++) {
				int source_reg = sysv_argument_abi_register_indexes[i];
				int dest_reg = syscall_argument_abi_register_indexes[i];
				self.current_state.registers[dest_reg] = state->registers[source_reg];
				self.current_state.sources[dest_reg] = mask_for_register(source_reg);
		#if STORE_LAST_MODIFIED
				self.current_state.last_modify_ins[dest_reg] = state->last_modify_ins[source_reg];
		#endif
			}
			self.current_state.registers[REGISTER_SYSCALL_NR] = state->registers[REGISTER_STACK_8];
			self.current_state.sources[REGISTER_SYSCALL_NR] = mask_for_register(REGISTER_STACK_8);
		#if STORE_LAST_MODIFIED
			self.current_state.last_modify_ins[REGISTER_SYSCALL_NR] = state->last_modify_ins[REGISTER_STACK_8];
		#endif
			LOG("redirecting to syscall at ", temp_str(copy_address_description(&analysis->loader, self.address)));
			dump_nonempty_registers(&analysis->loader, &self.current_state, ALL_REGISTERS);
			struct additional_result additional;
			analyze_syscall_instruction(analysis, &self, &additional, caller, analysis->loader.internal_syscall_cancel_syscall[i], effects, &effects);
		}
	}
	LOG("finished __internal_syscall_cancel: ", temp_str(copy_function_call_description(&analysis->loader, ins, state)));
}

void analyze_memory_read(struct program_state *analysis, struct analysis_frame *self, ins_ptr ins, function_effects effects, struct loaded_binary *binary, const void *address)
{
	if (binary_for_address(&analysis->loader, ins) != binary) {
		return;
	}
	if ((effects & EFFECT_ENTER_CALLS) == 0) {
		if (analysis->address_loaded != NULL) {
			analysis->address_loaded(analysis, address, self, analysis->address_loaded_data);
		}
	} else {
		add_address_to_list(&analysis->search.loaded_addresses, (uintptr_t)address);
		LOG("formed address is readable, assuming it is data");
		struct address_and_size symbol;
		if (find_skipped_symbol_for_address(&analysis->loader, binary, address, &symbol)) {
			if (binary->special_binary_flags & BINARY_IS_LIBCRYPTO) {
				analysis->loader.searching_libcrypto_dlopen = true;
			}
			typedef uintptr_t unaligned_uintptr __attribute__((aligned(1)));
			const unaligned_uintptr *symbol_data = (const unaligned_uintptr *)symbol.address;
			int size = symbol.size / sizeof(uintptr_t);
			for (int i = 0; i < size; i++) {
				uintptr_t data = symbol_data[i];
				if (address_is_call_aligned(data) && protection_for_address_in_binary(binary, data, NULL) & PROT_EXEC) {
					LOG("found reference to executable address ", temp_str(copy_address_description(&analysis->loader, (ins_ptr)data)), " at ", temp_str(copy_address_description(&analysis->loader, &symbol_data[i])), ", assuming callable");
					LOG("from: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
					queue_instruction(&analysis->search.queue, (ins_ptr)data, effects, &empty_registers, ins, "skipped symbol in data section");
				}
			}
			if (binary->special_binary_flags & BINARY_IS_LIBCRYPTO) {
				analyze_libcrypto_dlopen(analysis);
				analysis->loader.searching_libcrypto_dlopen = false;
			}
		}
	}
}

bool check_for_searched_function(struct loader_context *loader, ins_ptr address)
{
	if (loader->searching_do_setxid && loader->do_setxid == NULL) {
		LOG("found do_setxid: ", temp_str(copy_address_description(loader, address)));
		loader->do_setxid = address;
		return true;
	}
	if (loader->searching_enable_async_cancel && loader->enable_async_cancel == NULL) {
		LOG("found enable_async_cancel: ", temp_str(copy_address_description(loader, address)));
		loader->enable_async_cancel = address;
		return true;
	}
	if (loader->searching_for_internal_syscall_cancel && loader->internal_syscall_cancel == NULL) {
		LOG("found __internal_syscall_cancel: ", temp_str(copy_address_description(loader, address)));
		loader->internal_syscall_cancel = address;
		return true;
	}
	return false;
}

function_effects analyze_instructions(struct program_state *analysis, function_effects required_effects, struct registers *entry_state, ins_ptr ins, const struct analysis_frame *caller, trace_flags trace_flags)
{
	struct decoded_ins decoded;
	ins = skip_prefix_jumps(analysis, ins, &decoded, required_effects);
	if (ins == NULL) {
		return DEFAULT_EFFECTS;
	}
	struct analysis_frame self;
	function_effects effects;
	{
		struct searched_instructions *search = &analysis->search;
		struct searched_instruction_entry *table_entry = find_searched_instruction_table_entry(search, ins, &self.token);
		bool wrote_registers = false;
		int entry_offset = entry_offset_for_registers(table_entry, entry_state, analysis, required_effects, ins, &self.current_state, &wrote_registers);
		if (UNLIKELY(table_entry->data->callback_index != 0)) {
			LOG("invoking callback for ", temp_str(copy_address_description(&analysis->loader, ins)));
			self.token.entry_offset = entry_offset;
			if (!wrote_registers) {
				wrote_registers = true;
				self.current_state = *entry_state;
			}
			search->callbacks[table_entry->data->callback_index].callback(analysis, ins, &self.current_state, required_effects, caller, &self.token, search->callbacks[table_entry->data->callback_index].data);
			if (UNLIKELY(self.token.generation != search->generation)) {
				table_entry = find_searched_instruction_table_entry(search, ins, &self.token);
			}
		}
		self.token.entry_offset = entry_offset;
		register_mask relevant_registers = table_entry->data->relevant_registers;
		if (relevant_registers != 0 /* && (data->entries[entry_index].effects & ~EFFECT_STICKY_EXITS) != 0*/) {
			vary_effects_by_registers(search, &analysis->loader, caller, relevant_registers, table_entry->data->preserved_registers, table_entry->data->preserved_and_kept_registers, 0);
			if (UNLIKELY(self.token.generation != search->generation)) {
				table_entry = find_searched_instruction_table_entry(search, ins, &self.token);
			}
		}
		// gdb command to get the data entry: p *(struct searched_instruction_data_entry *)((uintptr_t)analysis->search.table[self.token.index].data->entries + self.token.entry_offset)
		struct searched_instruction_data_entry *entry = entry_for_offset(table_entry->data, entry_offset);
		self.token.entry_generation = entry->generation;
		if (entry->effects & EFFECT_PROCESSING) {
			if (!registers_are_subset_of_entry_registers(entry_state->registers, entry, ~table_entry->data->relevant_registers)) {
				LOG("queuing because subset of existing processing entry, but expanded set of registers are not subset");
				dump_nonempty_registers(&analysis->loader, &self.current_state, ~table_entry->data->relevant_registers);
				queue_instruction(&analysis->search.queue, ins, required_effects & ~EFFECT_PROCESSING, entry_state, ins, "in progress");
			} else {
				LOG("not queuing processing because irrelevant registers are a subset");
			}
		}
		entry_state->modified |= entry->modified;
		effects = entry->effects;
		if ((effects & required_effects) == required_effects) {
			if (SHOULD_LOG) {
				LOG("skip: ", temp_str(copy_block_entry_description(&analysis->loader, ins, entry_state)));
				expand_registers(self.current_state.registers, entry);
				LOG("existing ", temp_str(copy_block_entry_description(&analysis->loader, ins, &self.current_state)), " has effects ", effects_description(effects), " (was searching for ", effects_description(required_effects), ")");
			}
			vary_effects_by_registers(search, &analysis->loader, caller, table_entry->data->relevant_registers, table_entry->data->preserved_registers, table_entry->data->preserved_and_kept_registers, required_effects);
			return (effects & EFFECT_STICKY_EXITS) ? (effects & ~(EFFECT_STICKY_EXITS | EFFECT_RETURNS)) : effects;
		}
		if (!wrote_registers) {
			self.current_state = *entry_state;
		}
		if (UNLIKELY(effects & EFFECT_STICKY_EXITS)) {
			effects = required_effects | EFFECT_EXITS | EFFECT_STICKY_EXITS;
			entry->effects = effects;
		} else {
			effects = required_effects;
			entry->effects = effects /* | EFFECT_RETURNS*/ | EFFECT_PROCESSING;
		}
	};
	self.entry_state = entry_state;
	self.next = caller;
	self.entry = ins;
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		self.current_state.sources[i] = mask_for_register(i);
	}
	analysis->current_frame = &self;
	if (required_effects & EFFECT_AFTER_STARTUP) {
		LOG("entering block: ", temp_str(copy_block_entry_description(&analysis->loader, ins, &self.current_state)));
	} else {
		LOG("entering init block: ", temp_str(copy_block_entry_description(&analysis->loader, ins, &self.current_state)));
	}
	self.pending_stack_clear = 0;
	for (;;) {
		self.address = ins;
#ifdef STATS
		analyzed_instruction_count++;
#endif
		if (is_return_ins(&decoded)) {
			effects |= EFFECT_RETURNS;
			LOG("completing from return: ", temp_str(copy_address_description(&analysis->loader, self.entry)));
			break;
		}
		ins_ptr jump_target;
		switch (ins_interpret_jump_behavior(&decoded, &jump_target)) {
			case INS_JUMPS_NEVER:
				break;
			case INS_JUMPS_ALWAYS_INDIRECT:
				// treat indirect jumps like calls for the purpose of the enter calls state
				if ((required_effects & EFFECT_ENTER_CALLS) == 0) {
					analysis->skipped_call = jump_target;
					effects |= DEFAULT_EFFECTS;
					goto update_and_return;
				}
				// fallthrough
			case INS_JUMPS_ALWAYS: {
				LOG("found single jump");
				struct loaded_binary *jump_binary;
				if (jump_target == NULL) {
					LOG("found jump to unfilled address, assuming either exit or return!");
					effects |= DEFAULT_EFFECTS;
				} else if (jump_target == next_ins(ins, &decoded)) {
					LOG("jumping to next instruction, continuing");
					goto next_ins;
				} else if ((protection_for_address(&analysis->loader, jump_target, &jump_binary, NULL) & PROT_EXEC) == 0) {
					encountered_non_executable_address(&analysis->loader, "jump", &self, jump_target);
					LOG("completing from jump to non-executable address: ", temp_str(copy_address_description(&analysis->loader, self.entry)));
					effects |= DEFAULT_EFFECTS;
				} else if (jump_target >= self.entry && jump_target <= ins) {
					// infinite loop, consider this an exit
					LOG("appears to be an infinite loop");
					effects |= EFFECT_EXITS;
				} else {
					self.description = "jump";
					// TODO: support non-x86 here
					if (ins == self.entry || (ins == &self.entry[4] && is_landing_pad_ins_decode(self.entry))) {
						set_effects(&analysis->search, self.entry, &self.token, EFFECT_NONE, 0);
					}
					effects |= analyze_instructions(analysis, required_effects, &self.current_state, jump_target, &self, trace_flags) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
					LOG("completing from jump: ", temp_str(copy_address_description(&analysis->loader, self.entry)));
					if (caller->entry == jump_target) {
						goto update_and_return_preserving_effects;
					}
				}
				goto update_and_return;
			}
			case INS_JUMPS_OR_CONTINUES: {
				effects |=
					analyze_conditional_branch(analysis, required_effects, ins, &decoded, jump_target, next_ins(ins, &decoded), &self, trace_flags) & ~(EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
				goto update_and_return;
			}
		}
		if (analyze_instructions_arch(analysis, required_effects, &effects, ins, caller, trace_flags, &self, &decoded)) {
			break;
		}
	next_ins:
		ins = next_ins(ins, &decoded);
		LOG("instruction: ", temp_str(copy_address_description(&analysis->loader, ins)));
		if (UNLIKELY(!decode_ins(ins, &decoded))) {
			LOG("invalid instruction, assuming all effects");
			effects |= DEFAULT_EFFECTS;
			LOG("completing from invalid: ", temp_str(copy_address_description(&analysis->loader, self.entry)));
			decoded = (struct decoded_ins){0};
			break;
		}
	}
update_and_return:
	if (LIKELY((effects & EFFECT_STICKY_EXITS) == 0)) {
		if (UNLIKELY((effects & (EFFECT_RETURNS | EFFECT_EXITS)) == 0)) {
			effects |= EFFECT_RETURNS;
		}
	update_and_return_preserving_effects:
		effects &= ~EFFECT_PROCESSING;
		LOG("final ", effects_description(effects), " effects for ", temp_str(copy_address_description(&analysis->loader, self.entry)));
		set_effects(&analysis->search, self.entry, &self.token, effects, self.current_state.modified)->next_ins = next_ins(ins, &decoded);
	} else {
		effects &= ~(EFFECT_PROCESSING | EFFECT_RETURNS);
		LOG("final ", effects_description(effects), " effects for ", temp_str(copy_address_description(&analysis->loader, self.entry)));
		set_effects(&analysis->search, self.entry, &self.token, effects, self.current_state.modified)->next_ins = next_ins(ins, &decoded);
		effects &= ~EFFECT_STICKY_EXITS;
	}
	if (SHOULD_LOG) {
		if ((effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
			ERROR("exit-only block: ", temp_str(copy_address_description(&analysis->loader, self.entry)));
		}
	}
	entry_state->modified |= self.current_state.modified;
	analysis->current_frame = self.next;
	return effects;
}

static int apply_relocation_table(const struct loader_context *context, struct loaded_binary *binary, uintptr_t rela, uintptr_t relaent, uintptr_t relasz)
{
	uintptr_t rela_base = (uintptr_t)apply_base_address(&binary->info, rela);
	for (uintptr_t rel_off = 0; rel_off < relasz; rel_off += relaent) {
		const ElfW(Rela) *rel = (const ElfW(Rela) *)(rela_base + rel_off);
		uintptr_t info = rel->r_info;
		uintptr_t offset = rel->r_offset;
		uintptr_t addend = rel->r_addend;
		Elf64_Word type = ELF64_R_TYPE(info);
		Elf64_Word symbol_index = ELF64_R_SYM(info);
		uintptr_t relo_target = apply_base_address(&binary->info, offset);
		LOG("processing relocation: ", temp_str(copy_address_description(context, (const void *)rel)), " of type ", (int)type, " at ", temp_str(copy_address_description(context, (const void *)relo_target)), " for symbol index ", symbol_index, " with addend ", addend);
		const char *textual_name;
		uintptr_t value;
		size_t size;
		if (binary->has_symbols) {
			const ElfW(Sym) *symbol = (const ElfW(Sym) *)(binary->symbols.symbols + symbol_index * binary->symbols.symbol_stride);
			textual_name = symbol_name(&binary->symbols, symbol);
			if (symbol->st_value != 0 && symbol->st_shndx != SHN_UNDEF) {
				value = apply_base_address(&binary->info, symbol->st_value);
			} else if (ins_relocation_type_requires_symbol(type)) {
				struct loaded_binary *other_binary = NULL;
				struct symbol_version_info version = binary->symbols.symbol_versions != NULL ? symbol_version_for_index(&binary->symbols, binary->symbols.symbol_versions[symbol_index] & 0x7fff) : (struct symbol_version_info){0};
				value = (uintptr_t)resolve_loaded_symbol(context, textual_name, version.version_name, NORMAL_SYMBOL, &other_binary, NULL);
				if (value == 0) {
					if ((ELF64_ST_BIND(symbol->st_info) == STB_WEAK) || (type == INS_R_NONE)) {
						LOG("symbol value is NULL");
					} else {
						ERROR("symbol ", textual_name, " of type ", type, " is in another castle");
						if (version.version_name != NULL) {
							ERROR("version: ", version.version_name);
							if (version.library_name != NULL) {
								ERROR("in library: ", version.library_name);
							}
						}
						DIE("from: ", binary->path);
					}
				}
				LOG("resolving: ", textual_name);
				if (version.version_name != NULL) {
					LOG("version: ", version.version_name);
					if (version.library_name != NULL) {
						LOG("in library: ", version.library_name);
					}
				}
				LOG("from: ", binary->path);
				if (other_binary) {
					LOG("to: ", other_binary->path);
				}
			} else {
				value = 0;
			}
			size = symbol->st_size;
		} else {
			value = 0;
			size = 0;
			textual_name = "";
		}
		LOG("relocation is for value: ", value);
		switch (type) {
			case INS_R_NONE:
				// why does this exist?
				break;
			case INS_R_64:
				LOG("64 relocation for ", textual_name);
				*(ins_uint64 *)relo_target = value + addend;
				break;
#ifdef INS_R_PC32
			case INS_R_PC32:
				LOG("pc32 relocation for ", textual_name);
				*(ins_uint32 *)relo_target = value + addend - relo_target;
				break;
#endif
#ifdef INS_R_GOT32
			case INS_R_GOT32:
				LOG("got32 relocation for, not supported: ", textual_name);
				// TODO
				break;
#endif
#ifdef INS_R_PLT32
			case INS_R_PLT32:
				LOG("plt32 relocation for, not supported: ", textual_name);
				// TODO
				break;
#endif
			case INS_R_COPY:
				LOG("copy relocation for ", textual_name);
				fs_memcpy((void *)relo_target, (const void *)value, size);
				break;
			case INS_R_GLOB_DAT:
				LOG("glob dat relocation for ", textual_name);
				*(ins_uint64 *)relo_target = value;
				break;
			case INS_R_JUMP_SLOT:
				LOG("jump slot relocation for ", textual_name);
				*(ins_uint64 *)relo_target = value;
				break;
#ifdef INS_R_RELATIVE64
			case INS_R_RELATIVE64:
#endif
			case INS_R_RELATIVE: {
				uintptr_t result = (uintptr_t)binary->info.base + addend;
				*(uintptr_t *)relo_target = result;
				LOG("relative relocation: ", temp_str(copy_address_description(context, (const void *)result)));
				break;
			}
			case INS_R_TLSDESC:
				LOG("tlsdesc relocation for, not supported: ", textual_name);
				*(ins_uint64 *)relo_target = TLSDESC_ADDR;
				break;
			case INS_R_TLS_DTPREL:
				LOG("tls dtprel relocation for, not supported: ", textual_name);
				break;
			case INS_R_TLS_DTPMOD:
				LOG("tls dtpmod relocation for, not supported: ", textual_name);
				break;
			case INS_R_TLS_TPREL:
				LOG("tls tprel relocation for, not supported: ", textual_name);
				break;
			case INS_R_IRELATIVE:
				LOG("GNU magic to support STT_GNU_IFUNC/__attribute__((ifunc(\"...\"))), not supported", textual_name);
				// TODO: figure out how to trace these
				*(ins_uint64 *)relo_target = value;
				break;
#if defined(__x86_64__)
			case R_X86_64_GOTPCREL:
				LOG("gotpcrel relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_32:
				LOG("32 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_32S:
				LOG("32s relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_16:
				LOG("16 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_PC16:
				LOG("pc16 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_8:
				LOG("8 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_PC8:
				LOG("pc8 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_PC64:
				LOG("pc64 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_SIZE32:
				LOG("size32 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_SIZE64:
				LOG("size64 relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_TLSDESC_CALL:
				LOG("tlsdesc call relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_TLSGD:
				LOG("tlsgd relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_TLSLD:
				LOG("tlsld relocation for, not supported: ", textual_name);
				break;
			case R_X86_64_TPOFF32:
				LOG("thread pointer offset 32 relocation for, not supported: ", textual_name);
				break;
#endif
#if defined(__aarch64__)
			case R_AARCH64_ABS32:
				LOG("abs32 relocation for, not supported: ", textual_name);
				break;
			case R_AARCH64_ABS16:
				LOG("abs16 relocation for, not supported: ", textual_name);
				break;
			case R_AARCH64_PREL64:
				LOG("prel64 relocation for, not supported: ", textual_name);
				break;
			case R_AARCH64_PREL32:
				LOG("prel32 relocation for, not supported: ", textual_name);
				break;
			case R_AARCH64_PREL16:
				LOG("prel16 relocation for, not supported: ", textual_name);
				break;
#endif
			default:
				DIE("unknown relocation type ", (intptr_t) type, " for ", textual_name, " at ", (intptr_t)(rel_off / relaent), " from ", binary->path);
				break;
		}
	}
	return 0;
}

void *find_any_symbol_by_address(__attribute__((unused)) const struct loader_context *loader, struct loaded_binary *binary, const void *addr, int symbol_types, const struct symbol_info **out_used_symbols,
                                        const ElfW(Sym) * *out_symbol)
{
	if ((symbol_types & NORMAL_SYMBOL) && binary->has_symbols) {
		const struct symbol_info *symbols = &binary->symbols;
		void *start = find_symbol_by_address(&binary->info, symbols, addr, out_symbol);
		if (start != NULL) {
			if (out_used_symbols != NULL) {
				*out_used_symbols = symbols;
			}
			return start;
		}
	}
	if ((symbol_types & LINKER_SYMBOL) && binary->has_linker_symbols) {
		const struct symbol_info *symbols = &binary->linker_symbols;
		void *start = find_symbol_by_address(&binary->info, symbols, addr, out_symbol);
		if (start != NULL) {
			if (out_used_symbols != NULL) {
				*out_used_symbols = symbols;
			}
			return start;
		}
	}
	if (symbol_types & DEBUG_SYMBOL) {
		if (!binary->has_debuglink_symbols) {
			if ((symbol_types & DEBUG_SYMBOL_FORCING_LOAD) == DEBUG_SYMBOL_FORCING_LOAD) {
				// cast away const, since logically this function can be thought of as not really
				// modifying loader
				if (load_debuglink((struct loader_context *)loader, binary, true) != 0) {
					return NULL;
				}
			} else {
				return NULL;
			}
		}
		const struct symbol_info *symbols = &binary->debuglink_symbols;
		void *start = find_symbol_by_address(&binary->info, symbols, addr, out_symbol);
		if (start != NULL) {
			if (out_used_symbols != NULL) {
				*out_used_symbols = symbols;
			}
			return start;
		}
	}
	return NULL;
}

static const char *special_binary_names[] = {
	"libc.",
	"libcrypto.",
	"libcap.",
	"libpthread.",
	"libpython",
	"libperl",
	"libp11kit.",
	"libseccomp.",
	"libsasl2.",
	"libnss_systemd.",
	"libkrb5.",
	"libkrb5s",
	"libruby.",
	"libruby-",
	"libruby2",
	"ubuntu-core-launcher",
	"ruby",
	"perl",
	NULL,
};

static int special_binary_flags[] = {
	0,
	BINARY_IS_LIBC,
	BINARY_IS_LIBCRYPTO,
	BINARY_IS_LIBCAP,
	BINARY_IS_PTHREAD,
	BINARY_IS_LIBPYTHON,
	BINARY_IS_PERL,
	BINARY_IS_LIBP11KIT,
	BINARY_IS_SECCOMP,
	BINARY_IS_LIBSASL2,
	BINARY_IS_LIBNSS_SYSTEMD,
	BINARY_IS_LIBKRB5,
	BINARY_IS_LIBKRB5,
	BINARY_IS_RUBY,
	BINARY_IS_RUBY,
	BINARY_IS_RUBY,
	BINARY_IS_LIBCAP,
	BINARY_IS_RUBY,
	BINARY_IS_PERL,
};

static int special_binary_flags_for_path(const char *path)
{
	const char *slash = fs_strrchr(path, '/');
	const char *name = slash != NULL ? &slash[1] : path;
	int index = find_first_prefix(special_binary_names, name);
	return special_binary_flags[index + 1];
}

struct loaded_binary_stub
{
	void *base;
	struct loaded_binary *binary;
};

static inline int compare_loaded_binary_stubs(const void *left, const void *right, __attribute__((unused)) void *data)
{
	struct loaded_binary_stub const *left_stub = left;
	struct loaded_binary_stub const *right_stub = right;
	if (left_stub->base < right_stub->base) {
		return 1;
	}
	if (left_stub->base > right_stub->base) {
		return -1;
	}
	return 0;
}

int load_binary_into_analysis(struct program_state *analysis, const char *path, const char *full_path, int fd, const void *existing_base_address, struct loaded_binary **out_binary)
{
	struct binary_info info;
	unsigned long hash = elf_hash((const unsigned char *)path);
	intptr_t result;
	struct fs_stat stat;
	if (fd != -1) {
		result = fs_fstat(fd, &stat);
		if (result < 0) {
			return result;
		}
		for (struct loaded_binary *other = analysis->loader.binaries; other != NULL; other = other->next) {
			if (other->inode == stat.st_ino && other->device == stat.st_dev) {
				*out_binary = other;
				return 0;
			}
		}
	}
	if (existing_base_address != NULL) {
		load_existing(&info, (uintptr_t)existing_base_address);
	} else {
		result = load_binary(fd, &info, /*(uintptr_t)hash * PAGE_SIZE*/ 0, false);
		if (result != 0) {
			return result;
		}
		relocate_binary(&info);
	}
	LOG("loading ", path);
	if (full_path == NULL) {
		full_path = path;
	}
	size_t full_path_len = fs_strlen(full_path);
	struct loaded_binary *new_binary = malloc(sizeof(struct loaded_binary) + full_path_len + 1);
	*new_binary = (struct loaded_binary){0};
	fs_memcpy(new_binary->loaded_path, full_path, full_path_len + 1);
	new_binary->id = analysis->loader.binary_count++;
	new_binary->path = path;
	new_binary->path_hash = hash;
	new_binary->info = info;
	new_binary->next = analysis->loader.binaries;
	new_binary->previous = NULL;
	new_binary->has_symbols = false;
	new_binary->has_linker_symbols = false;
	new_binary->has_debuglink_info = false;
	new_binary->has_forced_debuglink_info = false;
	new_binary->has_debuglink_symbols = false;
	new_binary->debuglink_error = 0;
	new_binary->has_loaded_needed_libraries = false;
	new_binary->has_applied_relocation = false;
	new_binary->has_finished_loading = false;
	if (fd != -1) {
		new_binary->has_sections = load_section_info(fd, &new_binary->info, &new_binary->sections) == 0;
	}
	const ElfW(Phdr) *phdr = info.program_header;
	for (size_t i = 0; i < info.header_entry_count; i++, phdr = (const void *)phdr + info.header_entry_size) {
		switch (phdr->p_type) {
			case PT_GNU_EH_FRAME:
				new_binary->has_frame_info = load_frame_info_from_program_header(&new_binary->info, (const void *)apply_base_address(&info, phdr->p_vaddr), &new_binary->frame_info) == 0;
				break;
		}
	}
	new_binary->owns_binary_info = existing_base_address == NULL;
	new_binary->owns_path = false;
	if (fd != -1) {
		new_binary->device = stat.st_dev;
		new_binary->inode = stat.st_ino;
		new_binary->mode = stat.st_mode;
		new_binary->uid = stat.st_uid;
		new_binary->gid = stat.st_gid;
		new_binary->size = stat.st_size;
	} else {
		new_binary->device = 0;
		new_binary->inode = 0;
		new_binary->mode = 0;
		new_binary->uid = 0;
		new_binary->gid = 0;
		new_binary->size = 0;
	}
	new_binary->child_base = 0;
	new_binary->special_binary_flags = special_binary_flags_for_path(path);
	char *debuglink = NULL;
	char *build_id = NULL;
	if (new_binary->has_sections) {
		for (size_t i = 0; i < info.section_entry_count; i++) {
			const ElfW(Shdr) *section = (const ElfW(Shdr) *)((char *)new_binary->sections.sections + i * new_binary->info.section_entry_size);
			switch (section->sh_type) {
				case SHT_PROGBITS: {
					const char *name = &new_binary->sections.strings[section->sh_name];
					if (fs_strcmp(name, ".go.buildinfo") == 0) {
						new_binary->special_binary_flags |= BINARY_IS_GOLANG;
					}
					if (debuglink == NULL) {
						if (fs_strcmp(name, ".gnu_debuglink") == 0) {
							debuglink = malloc(section->sh_size);
							result = fs_pread_all(fd, debuglink, section->sh_size, section->sh_offset);
							if (result != (int)section->sh_size) {
								if (result >= 0) {
									result = -EINVAL;
								}
								return result;
							}
						}
					}
					break;
				}
				case SHT_NOTE:
					if (build_id == NULL) {
						const char *name = &new_binary->sections.strings[section->sh_name];
						if (fs_strcmp(name, ".note.gnu.build-id") == 0) {
							build_id = malloc(section->sh_size);
							result = fs_pread_all(fd, build_id, section->sh_size, section->sh_offset);
							if (result != (int)section->sh_size) {
								free(build_id);
								if (result >= 0) {
									result = -EINVAL;
								}
								return result;
							}
							new_binary->build_id_size = section->sh_size;
						}
					}
					break;
			}
		}
		// try to load the linker symbol table
		if (fd != -1) {
			new_binary->has_linker_symbols = load_section_symbols(fd, &new_binary->info, &new_binary->sections, false, &new_binary->linker_symbols) == 0;
		}
	}
	new_binary->debuglink = debuglink;
	new_binary->build_id = build_id;
	// try dynamic symbols
	new_binary->has_symbols = parse_dynamic_symbols(&new_binary->info, new_binary->info.base, &new_binary->symbols) == 0;
	if (analysis->loader.binaries == NULL) {
		new_binary->special_binary_flags |= BINARY_IS_MAIN;
	}
	if (INTERNAL_COMMON_SYMBOL & DEBUG_SYMBOL_FORCING_LOAD) {
		if (new_binary->special_binary_flags & (BINARY_IS_LIBC | BINARY_IS_LIBNSS_SYSTEMD)) {
			result = load_debuglink(&analysis->loader, new_binary, false);
			if (result < 0) {
				if (result == -ENOENT || result == -ENOEXEC) {
					print_debug_symbol_requirement(new_binary);
				} else {
					ERROR("failed to load debug symbols for ", new_binary->path, " with error: ", as_errno(result));
				}
				free(new_binary);
				return result;
			}
		}
	}
	analysis->loader.sorted_binaries = realloc(analysis->loader.sorted_binaries, analysis->loader.binary_count * sizeof(struct loaded_binary_stub));
	analysis->loader.sorted_binaries[new_binary->id] = (struct loaded_binary_stub){
		.binary = new_binary,
		.base = new_binary->info.base,
	};
	qsort_r_freestanding(analysis->loader.sorted_binaries, analysis->loader.binary_count, sizeof(struct loaded_binary_stub), compare_loaded_binary_stubs, NULL);
	if (analysis->loader.binaries == NULL) {
		analysis->loader.last = new_binary;
		analysis->loader.main = new_binary;
	} else {
		analysis->loader.binaries->previous = new_binary;
	}
	analysis->loader.binaries = new_binary;
	*out_binary = new_binary;
	return 0;
}

static int load_debuglink(const struct loader_context *loader, struct loaded_binary *binary, bool force_loading)
{
	if (binary->has_debuglink_info || binary->debuglink_error != 0) {
		return binary->debuglink_error;
	}
	if (binary->has_forced_debuglink_info) {
		if (!force_loading) {
			binary->has_debuglink_info = true;
		}
		return 0;
	}
	const char *debuglink = binary->debuglink;
	if (debuglink == NULL) {
		return 0;
	}
#define DEBUGLINK_ARCH_SEARCH_PATH "/usr/lib/debug/lib/" ARCH_NAME "-linux-gnu"
#define DEBUGLINK_BASE_SEARCH_PATH "/usr/lib/debug/usr/bin:/usr/lib/debug/lib:/usr/lib/debug/usr/lib:/lib/debug/usr/lib64:/usr/lib/debug/lib64"
#define DEBUGLINK_BUILD_ID_SEARCH_PATH "/usr/lib/debug/.build-id/XX"
	const char *debuglink_search_paths = DEBUGLINK_ARCH_SEARCH_PATH ":" DEBUGLINK_BASE_SEARCH_PATH;
	char buf[sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH ":" DEBUGLINK_ARCH_SEARCH_PATH ":" DEBUGLINK_BASE_SEARCH_PATH)];
	const char *build_id = binary->build_id;
	if (build_id != NULL) {
		memcpy(buf, DEBUGLINK_BUILD_ID_SEARCH_PATH ":" DEBUGLINK_ARCH_SEARCH_PATH ":" DEBUGLINK_BASE_SEARCH_PATH, sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH ":" DEBUGLINK_ARCH_SEARCH_PATH ":" DEBUGLINK_BASE_SEARCH_PATH));
		buf[sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH) - 3] = "0123456789abcdef"[(uint8_t)build_id[16] >> 4];
		buf[sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH) - 2] = "0123456789abcdef"[(uint8_t)build_id[16] & 0xf];
		debuglink_search_paths = buf;
	}
	LOG("searching for debuglink ", debuglink, " in ", debuglink_search_paths);
	char path_buf[PATH_MAX];
	const char *debuginfo_path;
	int debuglink_fd = loader_find_executable_in_sysrooted_paths(loader, debuglink, debuglink_search_paths, false, path_buf, &debuginfo_path);
	if (debuglink_fd < 0) {
		LOG("failed to open debuglink: ", as_errno(debuglink_fd));
		return binary->debuglink_error = debuglink_fd;
	}
	int result = load_binary(debuglink_fd, &binary->debuglink_info, 0, true);
	if (result != 0) {
		LOG("failed to load debuglink: ", as_errno(result));
		goto return_and_exit;
	}
	if (force_loading) {
		binary->has_forced_debuglink_info = true;
	} else {
		binary->has_debuglink_info = true;
	}
	struct section_info debuglink_sections;
	result = load_section_info(debuglink_fd, &binary->debuglink_info, &debuglink_sections);
	if (result != 0) {
		LOG("failed to read sections from debuglink: ", as_errno(result));
		goto return_and_exit;
	}
	// try to load the linker symbol table
	result = load_section_symbols(debuglink_fd, &binary->debuglink_info, &debuglink_sections, false, &binary->debuglink_symbols);
	if (result != 0) {
		LOG("error loading debuglink section symbols: ", as_errno(result));
		result = 0;
	} else {
		LOG("loaded debuglink successfully");
		binary->has_debuglink_symbols = true;
	}
	free_section_info(&debuglink_sections);
return_and_exit:
	fs_close(debuglink_fd);
	return binary->debuglink_error = result;
}

__attribute__((warn_unused_result)) static int load_needed_libraries(struct program_state *analysis, struct loaded_binary *new_binary)
{
	if (new_binary->has_loaded_needed_libraries) {
		return 0;
	}
	new_binary->has_loaded_needed_libraries = true;
	const ElfW(Dyn) *dynamic = new_binary->info.dynamic;
	size_t dynamic_size = new_binary->info.dynamic_size;
	if (new_binary->special_binary_flags & BINARY_IS_MAIN) {
		if (new_binary->info.interpreter) {
			const char *interpreter_path = new_binary->info.interpreter;
			char buf[PATH_MAX];
			const char *sysrooted_interpreter_path = apply_loader_sysroot(&analysis->loader, interpreter_path, buf);
			int interpreter_fd = open_executable_in_paths(sysrooted_interpreter_path, NULL, true, analysis->loader.uid, analysis->loader.gid);
			if (interpreter_fd < 0) {
				ERROR("failed to find interpreter: ", interpreter_path);
				return interpreter_fd;
			}
			const char *interpreter_filename = fs_strrchr(interpreter_path, '/');
			if (interpreter_filename) {
				interpreter_filename++;
			} else {
				interpreter_filename = interpreter_path;
			}
			int result = load_binary_into_analysis(analysis, interpreter_filename, interpreter_path, interpreter_fd, NULL, &analysis->loader.interpreter);
			fs_close(interpreter_fd);
			if (result < 0) {
				ERROR("failed to load interpreter: ", interpreter_path);
				return result;
			}
			analysis->loader.interpreter->special_binary_flags |= BINARY_IS_INTERPRETER;
		}
	}
	if (new_binary->has_symbols) {
		const char *additional_run_path = NULL;
		for (size_t i = 0; i < dynamic_size; i++) {
			switch (dynamic[i].d_tag) {
				case DT_RPATH:
					additional_run_path = new_binary->symbols.strings + dynamic[i].d_un.d_val;
					break;
				case DT_RUNPATH:
					additional_run_path = new_binary->symbols.strings + dynamic[i].d_un.d_val;
					break;
			}
		}
#define STANDARD_RUN_PATH "/lib64:/lib/" ARCH_NAME "-linux-gnu:/lib:/usr/lib:/usr/lib64:/usr/lib/perl5/core_perl/CORE"
		// TODO: support path virtualization to a "linux sysroot"
		const char *standard_run_path = STANDARD_RUN_PATH;
		size_t standard_run_path_sizeof = sizeof(STANDARD_RUN_PATH);
		char *new_run_path = NULL;
		if (additional_run_path != NULL) {
			if (fs_strncmp(additional_run_path, "$ORIGIN", sizeof("$ORIGIN") - 1) == 0) {
				const char *after_origin = &additional_run_path[sizeof("$ORIGIN") - 1];
				size_t suffix_len = fs_strlen(after_origin);
				const char *pos = fs_strrchr(new_binary->path, '/');
				if (pos != NULL) {
					size_t prefix_len = pos - new_binary->path;
					new_run_path = malloc(prefix_len + suffix_len + (1 + standard_run_path_sizeof));
					fs_memcpy(new_run_path, new_binary->path, prefix_len);
					fs_memcpy(&new_run_path[prefix_len], after_origin, suffix_len);
					new_run_path[prefix_len + suffix_len] = ':';
					fs_memcpy(&new_run_path[prefix_len + suffix_len + 1], standard_run_path, standard_run_path_sizeof);
				}
			} else {
				size_t prefix_len = fs_strlen(additional_run_path);
				new_run_path = malloc(prefix_len + (1 + standard_run_path_sizeof));
				fs_memcpy(new_run_path, additional_run_path, prefix_len);
				new_run_path[prefix_len] = ':';
				fs_memcpy(&new_run_path[prefix_len + 1], standard_run_path, standard_run_path_sizeof);
			}
		}
		for (size_t i = 0; i < dynamic_size; i++) {
			switch (dynamic[i].d_tag) {
				case DT_NEEDED: {
					const char *needed_path = new_binary->symbols.strings + dynamic[i].d_un.d_val;
					LOG("needed: ", needed_path);
					if (find_loaded_binary(&analysis->loader, needed_path) == NULL) {
						char buf[PATH_MAX];
						const char *full_path;
						int needed_fd = loader_find_executable_in_sysrooted_paths(&analysis->loader, needed_path, additional_run_path != NULL ? new_run_path : standard_run_path, false, buf, &full_path);
						if (needed_fd < 0) {
							ERROR("failed to find ", needed_path);
							if (new_run_path != NULL) {
								free(new_run_path);
							}
							return needed_fd;
						}
						struct loaded_binary *additional_binary;
						int result = load_binary_into_analysis(analysis, needed_path, full_path, needed_fd, NULL, &additional_binary);
						fs_close(needed_fd);
						if (result < 0) {
							ERROR("failed to load ", needed_path);
							if (new_run_path != NULL) {
								free(new_run_path);
							}
							return result;
						}
					}
					break;
				}
			}
		}
		if (new_run_path != NULL) {
			free(new_run_path);
		}
	}
	return 0;
}

__attribute__((warn_unused_result)) static int relocate_loaded_library(struct program_state *analysis, struct loaded_binary *new_binary)
{
	if (new_binary->has_applied_relocation) {
		return 0;
	}
	new_binary->has_applied_relocation = true;
	const ElfW(Dyn) *dynamic = new_binary->info.dynamic;
	size_t dynamic_size = new_binary->info.dynamic_size;
	if (new_binary->has_symbols) {
		uintptr_t rela = 0;
		uintptr_t relasz = 0;
		uintptr_t relaent = 0;
		uintptr_t jmprel = 0;
		uintptr_t pltrelsz = 0;
		for (size_t i = 0; i < dynamic_size; i++) {
			switch (dynamic[i].d_tag) {
				case DT_RELA:
					rela = dynamic[i].d_un.d_ptr;
					break;
				case DT_RELASZ:
					relasz = dynamic[i].d_un.d_val;
					break;
				case DT_RELAENT:
					relaent = dynamic[i].d_un.d_val;
					break;
				case DT_JMPREL:
					jmprel = dynamic[i].d_un.d_val;
					break;
				case DT_PLTRELSZ:
					pltrelsz = dynamic[i].d_un.d_val;
					break;
			}
		}
		LOG("DT_RELA");
		// apply .rela.dyn relocation table
		int result = apply_relocation_table(&analysis->loader, new_binary, rela, relaent, relasz);
		if (result < 0) {
			return result;
		}
		// apply .rela.plt relocation table
		// TODO: handle DT_PLTREL != RELA
		LOG("DT_JMPREL");
		result = apply_relocation_table(&analysis->loader, new_binary, jmprel, relaent, pltrelsz);
		if (result < 0) {
			return result;
		}
	}
	return 0;
}

int load_all_needed_and_relocate(struct program_state *analysis)
{
	for (struct loaded_binary *b = analysis->loader.last; b != NULL; b = b->previous) {
		int result = load_needed_libraries(analysis, b);
		if (result < 0) {
			return result;
		}
	}
	for (struct loaded_binary *b = analysis->loader.last; b != NULL; b = b->previous) {
		int result = relocate_loaded_library(analysis, b);
		if (result < 0) {
			return result;
		}
	}
	return 0;
}

static bool find_skipped_symbol_for_address(struct loader_context *loader, struct loaded_binary *binary, const void *address, struct address_and_size *out_symbol)
{
	if ((binary->special_binary_flags & (BINARY_IS_MAIN | BINARY_IS_INTERPRETER | BINARY_IS_LIBC | BINARY_IS_PTHREAD | BINARY_IS_LIBNSS_SYSTEMD | BINARY_IS_LIBCRYPTO | BINARY_IS_LIBPYTHON)) == 0) {
		return false;
	}
	for (size_t i = 0; i < binary->skipped_symbol_count; i++) {
		if (address >= (const void *)binary->skipped_symbols[i].address && address < (const void *)binary->skipped_symbols[i].address + binary->skipped_symbols[i].size) {
			*out_symbol = binary->skipped_symbols[i];
			return true;
		}
	}
	const struct symbol_info *symbols = NULL;
	const ElfW(Sym) *symbol = NULL;
	if (find_any_symbol_by_address(loader, binary, address, NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL, &symbols, &symbol) == NULL) {
		return false;
	}
	const char *name = symbol_name(symbols, symbol);
	if (fs_strcmp(name, "pthread_functions") == 0) {
		LOG("skipping pthread_functions, since it's assumed pthread_functions will be called properly");
	} else if (fs_strcmp(name, "_rtld_global_ro") == 0) {
		LOG("skipping _rtld_global_ro, since it's assumed dlopen and dlclose won't be called");
	} else if (fs_strcmp(name, "link_hash_ops") == 0) {
		LOG("skipping link_hash_ops, since it's assumed that it will be referenced");
	} else if (fs_strcmp(name, "_PyEval_EvalFrameDefault") == 0) {
		LOG("skipping _PyEval_EvalFrameDefault, since it's assumed that it will be referenced");
	} else {
		LOG("callable address in symbol ", name, " of ", binary->path);
		return false;
	}
	*out_symbol = (struct address_and_size){
		.address = (ins_ptr)((uintptr_t)binary->info.base + symbol->st_value - (uintptr_t)binary->info.default_base),
		.size = symbol->st_size,
	};
	return true;
}

struct golang_legacy_init_task
{
	uintptr_t state;
	uintptr_t ndeps;
	uintptr_t nfns;
	const void *data[0];
};

static void analyze_legacy_golang_init_task(struct program_state *analysis, function_effects effects, const struct golang_legacy_init_task *task)
{
	struct effect_token token;
	struct registers registers = empty_registers;
	function_effects *entry = get_or_populate_effects(analysis, (void *)task, &registers, EFFECT_NONE, &token);
	if ((*entry & effects) == effects) {
		return;
	}
	*entry |= effects & ~EFFECT_PROCESSING;
	LOG("analyzing legacy golang task: ", temp_str(copy_address_description(&analysis->loader, task)));
	uintptr_t ndeps = task->ndeps;
	uintptr_t nfns = task->nfns;
	LOG("ndeps: ", (intptr_t)ndeps, " nfns: ", (intptr_t)nfns);
	for (uintptr_t i = 0; i < ndeps; i++) {
		analyze_legacy_golang_init_task(analysis, effects, task->data[i]);
	}
	for (uintptr_t i = 0; i < nfns; i++) {
		LOG("found golang init function: ", temp_str(copy_address_description(&analysis->loader, task->data[ndeps + i])));
		struct analysis_frame new_caller = {.address = &task->data[ndeps + i], .description = "golang task init", .next = NULL, .current_state = registers, .entry = (const void *)task, .entry_state = &registers, .token = {0}};
		analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, task->data[ndeps + i], &new_caller);
	}
}

struct golang_modern_init_task
{
	uint32_t state;
	uint32_t nfns;
	const void *data[0];
};

__attribute__((noinline)) static void analyze_golang_init_task(struct program_state *analysis, function_effects effects, const struct golang_modern_init_task *task)
{
	struct effect_token token;
	struct registers registers = empty_registers;
	function_effects *entry = get_or_populate_effects(analysis, (void *)task, &registers, EFFECT_NONE, &token);
	if ((*entry & effects) == effects) {
		return;
	}
	*entry |= effects & ~EFFECT_PROCESSING;
	LOG("analyzing golang task: ", temp_str(copy_address_description(&analysis->loader, task)));
	uintptr_t nfns = task->nfns;
	LOG("nfns:", (intptr_t)nfns);
	for (uintptr_t i = 0; i < nfns; i++) {
		LOG("found golang init function: ", temp_str(copy_address_description(&analysis->loader, task->data[i])));
		struct analysis_frame new_caller = {.address = &task->data[i], .description = "golang task init", .next = NULL, .current_state = registers, .entry = (const void *)task, .entry_state = &registers, .token = {0}};
		analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, task->data[i], &new_caller);
	}
}

__attribute__((warn_unused_result)) int finish_loading_binary(struct program_state *analysis, struct loaded_binary *new_binary, function_effects effects, bool skip_analysis)
{
	if (new_binary->has_finished_loading) {
		return 0;
	}
	new_binary->has_finished_loading = true;
	int result = load_all_needed_and_relocate(analysis);
	if (result < 0) {
		return result;
	}
	LOG("finishing: ", new_binary->path);
	update_known_symbols(analysis, new_binary);
	result = apply_postrelocation_readonly(&new_binary->info);
	if (result < 0) {
		return result;
	}
	if (new_binary->special_binary_flags & BINARY_IS_MAIN) {
		bool found_interpreter = false;
		for (struct loaded_binary *other = analysis->loader.binaries; other != NULL; other = other->next) {
			if (other->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_LIBC)) {
				if (other->special_binary_flags & BINARY_IS_INTERPRETER) {
					found_interpreter = true;
				}
				result = finish_loading_binary(analysis, other, effects, skip_analysis);
				if (result != 0) {
					return result;
				}
			}
		}
		if (new_binary->info.interpreter && !found_interpreter) {
			DIE("could not find interpreter");
		}
	}
	const ElfW(Dyn) *dynamic = new_binary->info.dynamic;
	size_t dynamic_size = new_binary->info.dynamic_size;
	struct registers registers = empty_registers;
	uintptr_t init_array_ptr = 0;
	size_t init_array_count = 0;
	uintptr_t init = 0;
	uintptr_t fini_array_ptr = 0;
	size_t fini_array_count = 0;
	uintptr_t fini = 0;
	for (size_t i = 0; i < dynamic_size; i++) {
		switch (dynamic[i].d_tag) {
			case DT_NEEDED:
				if (new_binary->has_symbols) {
					const char *needed_path = new_binary->symbols.strings + dynamic[i].d_un.d_val;
					LOG("needed finishing: ", needed_path);
					struct loaded_binary *additional_binary = find_loaded_binary(&analysis->loader, needed_path);
					if (additional_binary) {
						result = finish_loading_binary(analysis, additional_binary, effects, skip_analysis);
						if (result != 0) {
							LOG("failed to finish loading: ", needed_path);
							return result;
						}
					}
				}
				break;
			case DT_INIT_ARRAY:
				init_array_ptr = dynamic[i].d_un.d_ptr;
				break;
			case DT_INIT_ARRAYSZ:
				init_array_count = dynamic[i].d_un.d_val / sizeof(ElfW(Addr));
				break;
			case DT_INIT:
				init = dynamic[i].d_un.d_ptr;
				break;
			case DT_FINI_ARRAY:
				fini_array_ptr = dynamic[i].d_un.d_ptr;
				break;
			case DT_FINI_ARRAYSZ:
				fini_array_count = dynamic[i].d_un.d_val / sizeof(ElfW(Addr));
				break;
			case DT_FINI:
				fini = dynamic[i].d_un.d_ptr;
				break;
		}
	}
	LOG("resuming: ", new_binary->path);
	if (skip_analysis) {
		return 0;
	}
	if (init_array_ptr != 0) {
		const uintptr_t *inits = (const uintptr_t *)apply_base_address(&new_binary->info, init_array_ptr);
		for (size_t i = 0; i < init_array_count; i++) {
			ins_ptr init_function = (ins_ptr)(inits[i] < (uintptr_t)new_binary->info.base ? (uintptr_t)apply_base_address(&new_binary->info, inits[i]) : inits[i]);
			LOG("analyzing initializer function: ", temp_str(copy_address_description(&analysis->loader, init_function)));
			struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "init", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
			analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, init_function, &new_caller);
		}
	}
	if (init != 0) {
		ins_ptr init_function = (ins_ptr)apply_base_address(&new_binary->info, init);
		LOG("analyzing initializer function: ", temp_str(copy_address_description(&analysis->loader, init_function)));
		struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "init", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
		analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, init_function, &new_caller);
	}
	if (fini_array_ptr != 0) {
		const uintptr_t *finis = (const uintptr_t *)apply_base_address(&new_binary->info, fini_array_ptr);
		for (size_t i = 0; i < fini_array_count; i++) {
			ins_ptr fini_function = (ins_ptr)(finis[i] < (uintptr_t)new_binary->info.base ? (uintptr_t)apply_base_address(&new_binary->info, finis[i]) : finis[i]);
			LOG("analyzing finalizer function: ", temp_str(copy_address_description(&analysis->loader, fini_function)));
			struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "fini", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
			analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, fini_function, &new_caller);
		}
	}
	if (fini != 0) {
		ins_ptr fini_function = (ins_ptr)apply_base_address(&new_binary->info, fini);
		LOG("analyzing finalizer function: ", temp_str(copy_address_description(&analysis->loader, fini_function)));
		struct analysis_frame new_caller = {.address = new_binary->info.base, .description = "fini", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
		analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, fini_function, &new_caller);
	}
	if (binary_has_flags(new_binary, BINARY_IS_GOLANG)) {
		void *legacy_init_task = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "main..inittask", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (legacy_init_task) {
			analyze_legacy_golang_init_task(analysis, effects | EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, legacy_init_task);
		} else {
			const ElfW(Sym) * symbol;
			struct golang_modern_init_task **modern_init_task_list = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "go:main.inittasks", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, &symbol);
			if (modern_init_task_list) {
				LOG("found golang init tasks: ", (intptr_t)(symbol->st_size / sizeof(*modern_init_task_list)));
				for (size_t i = 0; i < symbol->st_size / sizeof(*modern_init_task_list); i++) {
					analyze_golang_init_task(analysis, effects | EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, modern_init_task_list[i]);
				}
			}
		}
	}
	// search for vtables that should go unsearched until they're referenced explicitly
	static const struct
	{
		const char *name;
		size_t size;
		bool inner_call;
	} function_pointer_ignore_sources[] = {
		// glibc
		{"authdes_pk_create", sizeof(uintptr_t) * 6, false}, // authdes_ops
		{"authunix_create", sizeof(uintptr_t) * 6, false}, // auth_unix_ops
		{"svctcp_create", sizeof(uintptr_t) * 6, false}, // svctcp_rendezvous_op
		{"svcunix_create", sizeof(uintptr_t) * 6, false}, // svcunix_rendezvous_op
		{"svcudp_bufcreate", sizeof(uintptr_t) * 6, false}, // svcudp_op
		{"svcunixfd_create", sizeof(uintptr_t) * 6, false}, // svcunix_op
		{"svcfd_create", sizeof(uintptr_t) * 6, false}, // svctcp_op
		{"clntudp_create", sizeof(uintptr_t) * 6, false}, // udp_ops
		{"__libc_clntudp_bufcreate", sizeof(uintptr_t) * 6, false}, // udp_ops
		{"_authenticate", sizeof(uintptr_t) * 4, false}, // svcauthsw
		{"clntraw_create", sizeof(uintptr_t) * 6, false}, // client_ops
		{"_IO_cookie_init", sizeof(uintptr_t) * 22, false}, // _IO_cookie_jumps
		{"fopencookie", sizeof(uintptr_t) * 22, true}, // _IO_cookie_jumps
		{"_IO_popen", sizeof(uintptr_t) * 22, false}, // _IO_proc_jumps
		// {"fdopen", sizeof(uintptr_t) * 22, false}, // _IO_wfile_jumps_maybe_mmap
		{"__gen_tempname", sizeof(uintptr_t) * 3, false}, // tryfunc.0
		{"gen_tempname_len", sizeof(uintptr_t) * 3, false}, // tryfunc.0
		{"mkstemp64", sizeof(uintptr_t) * 3, false}, // tryfunc.0
		// gnulib
		{"__argp_parse", sizeof(uintptr_t) * 2, false}, // argp_default_argp
	};
	analysis->skipped_call = NULL;
	for (size_t i = 0; i < sizeof(function_pointer_ignore_sources) / sizeof(function_pointer_ignore_sources[0]); i++) {
		void *func = resolve_binary_loaded_symbol(&analysis->loader, new_binary, function_pointer_ignore_sources[i].name, NULL, NORMAL_SYMBOL, NULL);
		if (func != NULL) {
			LOG("found: ", function_pointer_ignore_sources[i].name, " at ", temp_str(copy_address_description(&analysis->loader, func)));
			struct analysis_frame new_caller = {
				.address = new_binary->info.base, .description = function_pointer_ignore_sources[i].name, .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = {0}};
			analyze_function_for_ignored_load(analysis, &new_caller.current_state, func, &new_caller, function_pointer_ignore_sources[i].size);
			if (function_pointer_ignore_sources[i].inner_call) {
				if (analysis->skipped_call) {
					LOG("found skipped call in: ", function_pointer_ignore_sources[i].name, " to ", temp_str(copy_address_description(&analysis->loader, analysis->skipped_call)));
					new_caller.current_state = empty_registers;
					analyze_function_for_ignored_load(analysis, &new_caller.current_state, analysis->skipped_call, &new_caller, function_pointer_ignore_sources[i].size);
				} else {
					LOG("missing skipped call in: ", function_pointer_ignore_sources[i].name);
				}
			}
			analysis->skipped_call = NULL;
		}
	}
	// search sections for function pointers, ignoring vtables we discovered earlier
	if (new_binary->has_sections) {
		for (size_t i = 0; i < new_binary->info.section_entry_count; i++) {
			const ElfW(Shdr) *section = (const ElfW(Shdr) *)((char *)new_binary->sections.sections + i * new_binary->info.section_entry_size);
			if (section->sh_type == SHT_PROGBITS && section->sh_addr != 0 && (section->sh_flags & SHF_EXECINSTR) != SHF_EXECINSTR) {
				const char *name = &new_binary->sections.strings[section->sh_name];
				bool should_search;
				if (name[0] == '.') {
					should_search = fs_strcmp(name, ".data") == 0 || fs_strcmp(name, ".rodata") == 0 || fs_strcmp(name, ".data.rel.ro") == 0 || fs_strcmp(name, ".tdata") == 0;
				} else {
					should_search = fs_strcmp(name, "__libc_subfreeres") != 0 && fs_strcmp(name, "__patchable_function_entries") != 0;
				}
				if (should_search) {
					LOG("scanning section for addresses: ", name);
					const uintptr_t *section_data = (const uintptr_t *)apply_base_address(&new_binary->info, section->sh_addr);
					int size = section->sh_size / sizeof(uintptr_t);
					for (int j = 0; j < size; j++) {
						uintptr_t data = section_data[j];
						if (address_is_call_aligned(data) && protection_for_address_in_binary(new_binary, data, NULL) & PROT_EXEC) {
							LOG("found reference to executable address ", data, " at ", temp_str(copy_address_description(&analysis->loader, &section_data[j])), ", assuming callable");
							struct address_and_size symbol;
							if (!find_skipped_symbol_for_address(&analysis->loader, new_binary, &section_data[j], &symbol) && !find_skipped_symbol_for_address(&analysis->loader, new_binary, (const void *)data, &symbol)) {
								struct analysis_frame new_caller = {
									.address = &section_data[j], .description = name, .next = NULL, .current_state = empty_registers, .entry = (void *)&section_data[j], .entry_state = &empty_registers, .token = {0}};
								analyze_function(analysis, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS | effects, &registers, (ins_ptr)data, &new_caller);
							}
						}
					}
				} else {
					LOG("skipping scanning section for addresses: ", name);
				}
			}
		}
	}
	return 0;
}

void free_loader_context(struct loader_context *loader)
{
	struct loaded_binary *binary = loader->binaries;
	while (binary != NULL) {
		struct loaded_binary *next = binary->next;
		if (binary->has_symbols) {
			free_symbols(&binary->symbols);
		}
		if (binary->has_linker_symbols) {
			free_symbols(&binary->linker_symbols);
		}
		if (binary->has_sections) {
			free_section_info(&binary->sections);
		}
		if (binary->has_debuglink_symbols) {
			free_symbols(&binary->debuglink_symbols);
		}
		if (binary->has_debuglink_info || binary->has_forced_debuglink_info) {
			unload_binary(&binary->debuglink_info);
		}
		if (binary->debuglink) {
			free(binary->debuglink);
		}
		if (binary->build_id) {
			free(binary->build_id);
		}
		if (binary->owns_binary_info) {
			unload_binary(&binary->info);
		}
		if (binary->owns_path) {
			free((void *)binary->path);
		}
		if (binary->skipped_symbols) {
			free(binary->skipped_symbols);
		}
		free(binary);
		binary = next;
	}
	free(loader->sorted_binaries);
}

__attribute__((noinline)) static int protection_for_address_definitely_in_binary(const struct loaded_binary *binary, uintptr_t addr, const ElfW(Shdr) * *out_section)
{
	if (LIKELY(binary->has_sections)) {
		size_t count = binary->info.section_entry_count;
		size_t entry_size = binary->info.section_entry_size;
		const char *sections = (const char *)binary->sections.sections;
		for (size_t i = 0; i < count; i++) {
			const ElfW(Shdr) *section = (const ElfW(Shdr) *)(sections + i * entry_size);
			if (section->sh_addr != 0) {
				uintptr_t section_base = apply_base_address(&binary->info, section->sh_addr);
				if (section_base <= addr && addr < section_base + section->sh_size) {
					uint64_t flags = section->sh_flags;
					if (flags & SHF_ALLOC) {
						const char *section_name = &binary->sections.strings[section->sh_name];
						LOG("found address in section: ", section_name, " of ", binary->path);
						if (out_section != NULL) {
							*out_section = section;
						}
						for (int j = 0; j < OVERRIDE_ACCESS_SLOT_COUNT; j++) {
							if (UNLIKELY(addr >= (uintptr_t)binary->override_access_ranges[j].address && addr < (uintptr_t)binary->override_access_ranges[j].address + binary->override_access_ranges[j].size)) {
								LOG("using override: ", j);
								return binary->override_access_permissions[j];
							}
						}
						int result = PROT_READ;
						if (flags & SHF_EXECINSTR) {
							result |= PROT_EXEC;
						}
						if ((flags & SHF_WRITE) && (fs_strcmp(section_name, ".data.rel.ro") != 0 || (binary->special_binary_flags & BINARY_IS_INTERPRETER)) && (fs_strcmp(section_name, ".got") != 0) &&
						    (fs_strcmp(section_name, ".got.plt") != 0))
						{
							result |= PROT_WRITE;
						}
						return result;
					}
				}
			}
		}
	} else {
		// this is more efficient, but would make it impossible to support read-only relocation sections,
		// so it is used only when loading binaries already in memory
		for (size_t i = 0; i < binary->info.header_entry_count; i++) {
			const ElfW(Phdr) *ph = (const ElfW(Phdr) *)((uintptr_t)binary->info.program_header + binary->info.header_entry_size * i);
			if (ph->p_type != PT_LOAD) {
				continue;
			}
			uintptr_t load_base = apply_base_address(&binary->info, ph->p_vaddr);
			if ((load_base <= addr) && (addr < (load_base + ph->p_memsz))) {
				int result = 0;
				if (ph->p_flags & PF_R) {
					result |= PROT_READ;
				}
				if (ph->p_flags & PF_W) {
					result |= PROT_WRITE;
				}
				if (ph->p_flags & PF_X) {
					result |= PROT_EXEC;
				}
				if (out_section != NULL) {
					*out_section = NULL;
				}
				return result;
			}
		}
	}
	if (out_section != NULL) {
		*out_section = NULL;
	}
	return 0;
}

int protection_for_address_in_binary(const struct loaded_binary *binary, uintptr_t addr, const ElfW(Shdr) * *out_section)
{
	if (binary != NULL) {
		uintptr_t base = (uintptr_t)binary->info.base;
		if (addr >= base && addr < base + binary->info.size) {
			return protection_for_address_definitely_in_binary(binary, addr, out_section);
		}
	}
	if (out_section != NULL) {
		*out_section = NULL;
	}
	return 0;
}

__attribute__((nonnull(1, 3))) int protection_for_address(const struct loader_context *context, const void *address, struct loaded_binary **out_binary, const ElfW(Shdr) * *out_section)
{
	uintptr_t addr = (uintptr_t)address;
	struct loaded_binary *binary = binary_for_address(context, address);
	if (LIKELY(binary != NULL)) {
		*out_binary = binary;
		return protection_for_address_definitely_in_binary(binary, addr, out_section);
	}
	if ((intptr_t)addr >= (intptr_t)PAGE_SIZE) {
		for (const struct loader_stub *stub = context->stubs; stub != NULL; stub = stub->next) {
			if (address == stub) {
				*out_binary = NULL;
				return PROT_EXEC;
			}
		}
	}
	*out_binary = NULL;
	return 0;
}

static inline bool binary_for_address_callback(int index, void *ordered, void *needle)
{
	const struct loaded_binary_stub *sorted_binaries = ordered;
	return sorted_binaries[index].base <= needle;
}

struct loaded_binary *binary_for_address(const struct loader_context *context, const void *addr)
{
	if ((uintptr_t)addr >= PAGE_SIZE) {
		int count = context->binary_count;
		struct loaded_binary_stub *sorted_binaries = context->sorted_binaries;
		int i = bsearch_bool(count, sorted_binaries, (void *)addr, binary_for_address_callback);
		if (i < count) {
			struct loaded_binary *binary = sorted_binaries[i].binary;
			if (addr < sorted_binaries[i].base + binary->info.size) {
				return binary;
			}
		}
	}
	return NULL;
}

char *copy_address_details(const struct loader_context *context, const void *addr, bool include_symbol)
{
	if (addr == NULL && include_symbol) {
		char *null_str = malloc(sizeof("NULL"));
		memcpy(null_str, "NULL", sizeof("NULL"));
		return null_str;
	}
	struct loaded_binary *binary = binary_for_address(context, addr);
	if (!binary || (!include_symbol && binary->info.default_base != NULL)) {
		char buf[20];
		size_t count = fs_utoah((uintptr_t)addr, buf);
		char *result = malloc(count + 1);
		fs_utoah((uintptr_t)addr, result);
		return result;
	}
	size_t path_len = fs_strlen(binary->path);
	const struct symbol_info *symbols;
	const ElfW(Sym) * symbol;
	void *start = NULL;
	bool add_star = false;
	if (include_symbol && addr > binary->info.base) {
		start = find_any_symbol_by_address(context, binary, addr, NORMAL_SYMBOL | LINKER_SYMBOL, &symbols, &symbol);
		if (start == NULL) {
			start = find_any_symbol_by_address(context, binary, addr, DEBUG_SYMBOL_FORCING_LOAD, &symbols, &symbol);
			add_star = start != NULL;
		}
	}
	const char *name = start ? symbol_name(symbols, symbol) : NULL;
	size_t name_len = name ? fs_strlen(name) : 0;
	char *result = malloc(path_len + name_len + add_star + 60);
	char *dest = result;
	fs_memcpy(dest, binary->path, path_len);
	dest += path_len;
	if (UNLIKELY(binary->info.default_base != NULL)) {
		*dest++ = ':';
		dest += fs_utoah((uintptr_t)addr, dest);
	} else if (LIKELY(addr != binary->info.base)) {
		*dest++ = '+';
		dest += fs_utoah((uintptr_t)addr - (uintptr_t)binary->info.base, dest);
	}
	if (name_len) {
		*dest++ = '(';
		memcpy(dest, name, name_len);
		dest += name_len;
		if (add_star) {
			*dest++ = '*';
		}
		if (addr != start) {
			*dest++ = '+';
			dest += fs_utoa((uintptr_t)addr - (uintptr_t)start, dest);
		}
		*dest++ = ')';
	}
	*dest++ = '\0';
	return result;
}

char *copy_address_description(const struct loader_context *context, const void *addr)
{
	return copy_address_details(context, addr, true);
}

uintptr_t translate_analysis_address_to_child(struct loader_context *loader, ins_ptr addr)
{
	struct loaded_binary *binary = binary_for_address(loader, addr);
	if (binary == NULL) {
		return (uintptr_t)addr;
	}
	if (binary->child_base == 0) {
		return (uintptr_t)addr;
	}
	return (uintptr_t)addr - (uintptr_t)binary->info.base + binary->child_base;
}

struct register_state translate_register_state_to_child(struct loader_context *loader, struct register_state state)
{
	if (register_is_partially_known(&state)) {
		struct loaded_binary *binary = binary_for_address(loader, (const void *)state.value);
		if (!register_is_exactly_known(&state) && binary_for_address(loader, (const void *)state.max) != binary) {
			clear_register(&state);
		} else if (binary != NULL) {
			state.value = state.value - (uintptr_t)binary->info.base + binary->child_base;
			state.max = state.max - (uintptr_t)binary->info.base + binary->child_base;
		}
	}
	return state;
}

static int compare_found_syscalls(const void *a, const void *b, void *data)
{
	struct loader_context *loader = data;
	const struct recorded_syscall *syscalla = a;
	const struct recorded_syscall *syscallb = b;
	if (syscalla->nr < syscallb->nr) {
		return -1;
	}
	if (syscalla->nr > syscallb->nr) {
		return 1;
	}
	int attributes = info_for_syscall(syscalla->nr).attributes;
	if ((attributes & SYSCALL_CAN_BE_FROM_ANYWHERE) == 0) {
		uintptr_t ins_a = (uintptr_t)syscalla->ins;
		struct loaded_binary *binary_a = binary_for_address(loader, syscalla->ins);
		if (binary_a != NULL) {
			ins_a += ((uintptr_t)binary_a->id << 48) - (uintptr_t)binary_a->info.base;
		}
		uintptr_t ins_b = (uintptr_t)syscallb->ins;
		struct loaded_binary *binary_b = binary_for_address(loader, syscallb->ins);
		if (binary_b != NULL) {
			ins_b += ((uintptr_t)binary_b->id << 48) - (uintptr_t)binary_b->info.base;
		}
		if (ins_a < ins_b) {
			return -1;
		}
		if (ins_a > ins_b) {
			return 1;
		}
	}
	for (int i = 0; i < (attributes & SYSCALL_ARGC_MASK); i++) {
		int reg = syscall_argument_abi_register_indexes[i];
		const struct register_state register_a = syscalla->registers.registers[reg];
		const struct register_state register_b = syscallb->registers.registers[reg];
		struct loaded_binary *binary_a = binary_for_address(loader, (void *)register_a.value);
		struct loaded_binary *binary_b = binary_for_address(loader, (void *)register_b.value);
		if (binary_a != binary_b) {
			int id_a = binary_a != NULL ? binary_a->id : -1;
			int id_b = binary_b != NULL ? binary_b->id : -1;
			if (id_a < id_b) {
				return -1;
			}
			if (id_a > id_b) {
				return 1;
			}
		}
		if (register_a.value < register_b.value) {
			return -1;
		}
		if (register_a.value > register_b.value) {
			return 1;
		}
		binary_a = binary_for_address(loader, (void *)register_a.max);
		binary_b = binary_for_address(loader, (void *)register_b.max);
		if (binary_a != binary_b) {
			int id_a = binary_a != NULL ? binary_a->id : -1;
			int id_b = binary_b != NULL ? binary_b->id : -1;
			if (id_a < id_b) {
				return -1;
			}
			if (id_a > id_b) {
				return 1;
			}
		}
		if (register_a.max < register_b.max) {
			return -1;
		}
		if (register_a.max > register_b.max) {
			return 1;
		}
	}
	return 0;
}

static bool merge_recorded_syscall(const struct recorded_syscall *source, struct recorded_syscall *target, register_mask relevant_registers)
{
	if (registers_are_subset_of_registers(source->registers.registers, target->registers.registers, relevant_registers)) {
		// source is already a subset of target
		return true;
	}
	if (registers_are_subset_of_registers(target->registers.registers, source->registers.registers, relevant_registers)) {
		// target is a subset of source
		target->registers = source->registers;
		return true;
	}
	// find a lone mismatch
	int mismatch_index = -1;
	for_each_bit (relevant_registers, bit, i) {
		if ((target->registers.registers[i].value != source->registers.registers[i].value) || (target->registers.registers[i].max != source->registers.registers[i].max)) {
			if (mismatch_index == -1) {
				mismatch_index = i;
			} else {
				return false;
			}
		}
	}
	if (mismatch_index != -1) {
		// source and target differ by only a single register
		return combine_register_states(&target->registers.registers[mismatch_index], &source->registers.registers[mismatch_index], mismatch_index);
	}
	return false;
}

static int coalesce_syscalls(struct recorded_syscall *out, const struct recorded_syscall *list, int count, int attributes, struct loader_context *loader)
{
	register_mask relevant_registers = syscall_argument_abi_used_registers_for_argc[attributes & SYSCALL_ARGC_MASK];
	*out = *list;
	for (;;) {
		int new_count = 1;
		for (int i = 1; i < count; i++) {
			for (int j = 0; j < new_count; j++) {
				// find a syscall to merge with
				if (merge_recorded_syscall(&list[i], &out[j], relevant_registers)) {
					goto merged;
				}
			}
			// else copy it to the output buffer
			out[new_count++] = list[i];
		merged:;
		}
		// keep trying until there are no possible merges
		if (new_count == count) {
			break;
		}
		list = out;
		count = new_count;
	}
	// sort the output so that it's stable
	qsort_r_freestanding(out, count, sizeof(*out), compare_found_syscalls, loader);
	return count;
}

void sort_and_coalesce_syscalls(struct recorded_syscalls *syscalls, struct loader_context *loader)
{
	int count = syscalls->count;
	if (loader->setxid_syscall != NULL || loader->setxid_sighandler_syscall != NULL) {
		// make __nptl_setxid syscall thread broaddcasting work
		for (int i = 0; i < count; i++) {
			struct recorded_syscall *syscall = &syscalls->list[i];
			switch (syscall->nr) {
				case LINUX_SYS_setuid:
				case LINUX_SYS_setgid:
				case LINUX_SYS_setreuid:
				case LINUX_SYS_setregid:
				case LINUX_SYS_setgroups:
				case LINUX_SYS_setresuid:
				case LINUX_SYS_setresgid:
				case LINUX_SYS_setfsuid:
				case LINUX_SYS_setfsgid: {
					struct recorded_syscall copy = *syscall;
					if (loader->setxid_syscall != NULL) {
						copy.ins = loader->setxid_syscall;
						copy.entry = loader->setxid_syscall_entry;
						add_syscall(syscalls, copy);
					}
					if (loader->setxid_sighandler_syscall != NULL) {
						copy.ins = loader->setxid_sighandler_syscall;
						copy.entry = loader->setxid_sighandler_syscall_entry;
						add_syscall(syscalls, copy);
					}
					break;
				}
				default:
					break;
			}
		}
		count = syscalls->count;
	}
	qsort_r_freestanding(syscalls->list, count, sizeof(*syscalls->list), compare_found_syscalls, loader);
	if (count > 1) {
		struct recorded_syscall *list = syscalls->list;
		int out_pos = 0;
		int in_pos = 0;
		int attributes = info_for_syscall(list[0].nr).attributes;
		for (int i = 1; i < count; i++) {
			if (list[i].nr != list[in_pos].nr) {
				// numbers don't match, coalesce the batch of syscalls we just discovered
				out_pos += coalesce_syscalls(&list[out_pos], &list[in_pos], i - in_pos, attributes, loader);
				in_pos = i;
				attributes = info_for_syscall(list[i].nr).attributes;
				continue;
			}
			if ((attributes & SYSCALL_CAN_BE_FROM_ANYWHERE) == 0) {
				if (list[i].ins != list[in_pos].ins) {
					// addresses don't match, coalesce the batch of syscalls we just discovered
					out_pos += coalesce_syscalls(&list[out_pos], &list[in_pos], i - in_pos, attributes, loader);
					in_pos = i;
					continue;
				}
			}
		}
		// coalesce the final batch
		out_pos += coalesce_syscalls(&list[out_pos], &list[in_pos], count - in_pos, attributes, loader);
		syscalls->count = out_pos;
	}
}

char *copy_used_syscalls(const struct loader_context *context, const struct recorded_syscalls *syscalls, bool log_arguments, bool log_caller, bool include_symbol)
{
	int count = syscalls->count;
	struct recorded_syscall *list = syscalls->list;
	size_t log_len = 1;
	for (int i = 0; i < count; i++) {
		uintptr_t nr = list[i].nr;
		if (log_arguments || i == 0 || list[i - 1].nr != nr) {
			if (i != 0) {
				log_len++; // '\n'
			}
			if (log_arguments) {
				char *description = copy_syscall_description(context, nr, &list[i].registers, include_symbol);
				log_len += fs_strlen(description);
				free(description);
			} else {
				log_len += fs_strlen(name_for_syscall(nr));
			}
			if (log_caller && (info_for_syscall(nr).attributes & SYSCALL_CAN_BE_FROM_ANYWHERE) == 0) {
				log_len += 3; // " @ ";
				char *description = copy_address_details(context, list[i].ins, include_symbol);
				log_len += fs_strlen(description);
				free(description);
			}
		}
	}
	char *logbuf = malloc(log_len);
	int logpos = 0;
	for (int i = 0; i < count; i++) {
		uintptr_t nr = list[i].nr;
		if (log_arguments || i == 0 || list[i - 1].nr != list[i].nr) {
			if (i != 0) {
				logbuf[logpos++] = '\n';
			}
			if (log_arguments) {
				char *description = copy_syscall_description(context, nr, &list[i].registers, include_symbol);
				int description_len = fs_strlen(description);
				fs_memcpy(&logbuf[logpos], description, description_len);
				free(description);
				logpos += description_len;
			} else {
				const char *name = name_for_syscall(nr);
				int name_len = fs_strlen(name);
				fs_memcpy(&logbuf[logpos], name, name_len);
				logpos += name_len;
			}
			if (log_caller && (info_for_syscall(nr).attributes & SYSCALL_CAN_BE_FROM_ANYWHERE) == 0) {
				logbuf[logpos++] = ' ';
				logbuf[logpos++] = '@';
				logbuf[logpos++] = ' ';
				char *description = copy_address_details(context, list[i].ins, include_symbol);
				size_t description_len = fs_strlen(description);
				fs_memcpy(&logbuf[logpos], description, description_len);
				logpos += description_len;
				free(description);
			}
		}
	}
	logbuf[logpos] = '\0';
	return logbuf;
}

char *copy_used_binaries(const struct loader_context *loader)
{
	size_t len = 1;
	for (struct loaded_binary *binary = loader->last; binary != NULL; binary = binary->previous) {
		len += fs_strlen(binary->path) + 1;
		if (binary->special_binary_flags & BINARY_IS_LOADED_VIA_DLOPEN) {
			len++;
		}
		len += fs_strlen(binary->loaded_path) + 1;
		if (binary->build_id_size > 16) {
			len += ((binary->build_id_size - 16) * 2) + 1;
		}
	}
	char *message = malloc(len);
	char *buf = message;
	for (struct loaded_binary *binary = loader->last; binary != NULL; binary = binary->previous) {
		if (buf != message) {
			*buf++ = '\n';
		}
		len = fs_strlen(binary->path);
		fs_memcpy(buf, binary->path, len);
		buf += len;
		if (binary->special_binary_flags & BINARY_IS_LOADED_VIA_DLOPEN) {
			*buf++ = '*';
		}
		*buf++ = ' ';
		len = fs_strlen(binary->loaded_path);
		fs_memcpy(buf, binary->loaded_path, len);
		buf += len;
		if (binary->build_id_size > 16) {
			*buf++ = ' ';
			for (size_t i = 16; i < binary->build_id_size; i++) {
				*buf++ = "0123456789abcdef"[(uint8_t)binary->build_id[i] >> 4];
				*buf++ = "0123456789abcdef"[(uint8_t)binary->build_id[i] & 0xf];
			}
		}
	}
	*buf = '\0';
	return message;
}

struct loaded_binary *register_dlopen(struct program_state *analysis, const char *path, const struct analysis_frame *caller, enum dlopen_options options)
{
	if ((options & DLOPEN_OPTION_RECURSE_INTO_FOLDERS) == 0) {
		return register_dlopen_file(analysis, path, caller, options);
	}
	char path_buf[PATH_MAX];
	int fd = fs_open(apply_loader_sysroot(&analysis->loader, path, path_buf), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	if (fd == -ENOENT && (options & DLOPEN_OPTION_IGNORE_ENOENT)) {
		return NULL;
	} else if (fd == -ENOTDIR) {
		struct loaded_binary *binary = register_dlopen_file(analysis, path, caller, options);
		if (binary == NULL) {
			DIE("failed to load shared object at ", path, " specified via --dlopen");
		}
		return binary;
	} else if (fd < 0) {
		DIE("failed to load shared object at ", path, " specified via --dlopen; error is ", as_errno(fd));
	}
	size_t prefix_len = fs_strlen(path);
	if (path[prefix_len - 1] == '/') {
		prefix_len--;
	}
	for (;;) {
		char buf[8192];
		int count = fs_getdents(fd, (struct fs_dirent *)&buf[0], sizeof(buf));
		if (count <= 0) {
			if (count < 0) {
				ERROR("failed to read directory at ", path, " specified via --dlopen; error is", as_errno(count));
			}
			break;
		}
		for (int offset = 0; offset < count;) {
			const struct fs_dirent *ent = (const struct fs_dirent *)&buf[offset];
			const char *name = ent->d_name;
			const char *needle = ".so";
			for (const char *haystack = name;;) {
				if (*haystack == *needle) {
					if (*needle == '\0') {
						size_t suffix_len = haystack - name;
						char *subpath = malloc(prefix_len + 1 + suffix_len + 1);
						char *subpath_buf = subpath;
						fs_memcpy(subpath_buf, path, prefix_len);
						subpath_buf += prefix_len;
						*subpath_buf++ = '/';
						fs_memcpy(subpath_buf, name, suffix_len + 1);
						register_dlopen(analysis, subpath, caller, options & ~DLOPEN_OPTION_IGNORE_ENOENT);
					}
					needle++;
				} else {
					needle = ".so";
				}
				if (*haystack == '\0') {
					break;
				}
				haystack++;
			}
			offset += ent->d_reclen;
		}
	}
	fs_close(fd);
	return NULL;
}

void finish_analysis(struct program_state *analysis)
{
	struct queued_instruction ins;
	while (dequeue_instruction(&analysis->search.queue, &ins)) {
		LOG("dequeuing: ", temp_str(copy_block_entry_description(&analysis->loader, ins.ins, &ins.registers)), " with requiring ", effects_description(ins.effects));
		struct analysis_frame queued_caller = {.address = ins.caller, .description = ins.description, .next = NULL, .current_state = empty_registers, .entry = ins.caller, .entry_state = &empty_registers, .token = {0}};
		analyze_function(analysis, ins.effects, &ins.registers, ins.ins, &queued_caller);
	}

	sort_and_coalesce_syscalls(&analysis->syscalls, &analysis->loader);
}
