#define _GNU_SOURCE
#include "freestanding.h"

#include "axon.h"

#include <errno.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/binfmts.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>

#include "callander.h"
#include "callander_print.h"

#include "bpf_debug.h"
#include "loader.h"
#include "qsort.h"
#include "search.h"

#if defined(__x86_64__)
#include "x86.h"
#define ARCH_NAME "x86_64"
#else
#if defined(__aarch64__)
#define ARCH_NAME "aarch64"
#else
#error "Unknown architecture"
#endif
#endif

#define SKIP_SHIFT

#define CLEAR_PROCESSED_ENTRIES

#ifdef LOGGING
bool should_log;
#endif

#define SYSCALL_ARG_IS_RELATED(relation, related_arg) ((relation) | (SYSCALL_ARG_RELATED_ARGUMENT_BASE << (related_arg)))
#define SYSCALL_ARG_IS_SIZE_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_SIZE, related_arg_index)
#define SYSCALL_ARG_IS_COUNT_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_COUNT, related_arg_index)
#define SYSCALL_ARG_IS_MODEFLAGS_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_MODEFLAGS, related_arg_index)
#define SYSCALL_ARG_IS_PRESERVED(underlying) (SYSCALL_ARG_IS_PRESERVED | (underlying))

#define SYSCALL_DEF_(_0, _1, _2, _3, _4, _5, _6, N, ...) N
#define SYSCALL_DEF(name, attributes, ...) { #name, { SYSCALL_DEF_(0, ##__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0) | ((attributes) & ~SYSCALL_ARGC_MASK), { __VA_ARGS__ } } },
#define SYSCALL_DEF_EMPTY() {NULL, 6, {}},
struct syscall_decl const syscall_list[] = {
#include "syscall_defs_x86_64.h"
};
#undef SYSCALL_DEF
#undef SYSCALL_DEF_EMPTY

const char *name_for_syscall(uintptr_t nr) {
	if (nr < sizeof(syscall_list) / sizeof(syscall_list[0])) {
		const char *name = syscall_list[nr].name;
		if (name != NULL) {
			return name;
		}
	}
	char buf[100];
	int count = fs_utoa(nr, buf);
	char *result = malloc(count + 1);
	fs_memcpy(result, buf, count + 1);
	return result;
}

struct syscall_info info_for_syscall(uintptr_t nr)
{
	if (nr < sizeof(syscall_list) / sizeof(syscall_list[0])) {
		return syscall_list[nr].info;
	}
	return (struct syscall_info){
		.attributes = 6,
		.arguments = { 0 },
	};
}

#define ABORT_AT_NON_EXECUTABLE_ADDRESS 0

#define INS_MOVL_START 0xb8
#define INS_MOVL_END 0xbf

#define INS_LEA 0x8d

#define INS_REX_W_PREFIX 0x48
#define INS_REX_WR_PREFIX 0x4c
#define INS_REX_WRXB_PREFIX 0x4f

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline void canonicalize_register(struct register_state *reg) {
	if (reg->value > reg->max) {
		clear_register(reg);
	}
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline bool register_is_partially_known_8bit(const struct register_state *reg) {
	return reg->value != (uintptr_t)0 || reg->max < 0xff;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline bool register_is_partially_known_16bit(const struct register_state *reg) {
	return reg->value != (uintptr_t)0 || reg->max < 0xffff;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline bool register_is_partially_known_32bit(const struct register_state *reg) {
	return reg->value != (uintptr_t)0 || reg->max < 0xffffffff;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline void truncate_to_8bit(struct register_state *reg) {
	if ((reg->max >> 8) == (reg->value >> 8)) {
		reg->value &= 0xff;
		reg->max &= 0xff;
		if (reg->value <= reg->max) {
			return;
		}
	}
	reg->value = 0;
	reg->max = 0xff;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline void truncate_to_16bit(struct register_state *reg) {
	if ((reg->max >> 16) == (reg->value >> 16)) {
		reg->value &= 0xffff;
		reg->max &= 0xffff;
		if (reg->value <= reg->max) {
			return;
		}
	}
	reg->value = 0;
	reg->max = 0xffff;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline void truncate_to_32bit(struct register_state *reg) {
	if ((reg->max >> 32) == (reg->value >> 32)) {
		reg->value &= 0xffffffff;
		reg->max &= 0xffffffff;
		if (reg->value <= reg->max) {
			return;
		}
	}
	reg->value = 0;
	reg->max = 0xffffffff;
}

__attribute__((nonnull(1, 2))) __attribute__((always_inline))
static inline bool register_is_subset_of_register(const struct register_state *potential_subset, const struct register_state *potential_superset)
{
	return potential_subset->value >= potential_superset->value && potential_subset->max <= potential_superset->max;
}

__attribute__((always_inline))
static inline struct register_state union_of_register_states(struct register_state a, struct register_state b)
{
	return (struct register_state) {
		.value = a.value < b.value ? a.value : b.value,
		.max = a.max > b.max ? a.max : b.max,
	};
}

struct register_state_and_source {
	struct register_state state;
	register_mask source;
};


static const struct decoded_rm invalid_decoded_rm = {
#if defined(__x86_64__)
	.rm = REGISTER_R12,
	.base = 0,
	.index = 0,
	.scale = 0,
	.addr = 0,
#endif
};

__attribute__((nonnull(1)))
static bool decoded_rm_references_register(const struct decoded_rm *rm, int register_index)
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

static inline const char *name_for_register(int register_index);

__attribute__((nonnull(1)))
static bool decoded_rm_cannot_reference_stack_slot(const struct decoded_rm *rm)
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
	return val & ((~val >> 1)^0x8000000000000000);
}

const int sysv_argument_abi_register_indexes[] = {
#if defined(__x86_64__)
	REGISTER_RDI,
	REGISTER_RSI,
	REGISTER_RDX,
	REGISTER_RCX,
	REGISTER_R8,
	REGISTER_R9,
#else
#if defined(__aarch64__)
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
#else
#if defined(__aarch64__)
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

const int syscall_argument_abi_register_indexes[6] = {
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

static inline ssize_t seccomp_data_offset_for_register(enum register_index reg) {
	switch (reg) {
		case REGISTER_SYSCALL_NR:
			return offsetof(struct seccomp_data, nr);
		case REGISTER_SYSCALL_ARG0:
			return offsetof(struct seccomp_data, args);
		case REGISTER_SYSCALL_ARG1:
			return offsetof(struct seccomp_data, args) + sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG2:
			return offsetof(struct seccomp_data, args) + 2 * sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG3:
			return offsetof(struct seccomp_data, args) + 3 * sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG4:
			return offsetof(struct seccomp_data, args) + 4 * sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG5:
			return offsetof(struct seccomp_data, args) + 5 * sizeof(uint64_t);
		default:
			return -1;
	}
}

const struct registers empty_registers = {
	.registers = {
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
		{ .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
#define PER_STACK_REGISTER_IMPL(offset) { .value = (uintptr_t)0, .max = ~(uintptr_t)0 },
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
	},
	.sources = { 0 },
	.matches = { 0 },
#if STORE_LAST_MODIFIED
	.last_modify_ins = { 0 },
#else
	.last_modify_syscall_register = NULL,
#endif
#if defined(__x86_64__)
	.mem_rm = invalid_decoded_rm,
#endif
	.compare_state = { 0 },
	.stack_address_taken = NULL,
};

static inline bool registers_are_subset_of_registers(const struct register_state potential_subset[REGISTER_COUNT], const struct register_state potential_superset[REGISTER_COUNT], register_mask valid_registers)
{
#if 0
	if (valid_registers != 0) {
#pragma GCC unroll 64
		for (int i = 0; i < REGISTER_COUNT; i++) {
			if (valid_registers & ((register_mask)1 << i)) {
				if (!register_is_subset_of_register(&potential_subset[i], &potential_superset[i])) {
					return false;
				}
			}
		}
	}
#else
	for_each_bit(valid_registers, bit, i) {
		if (!register_is_subset_of_register(&potential_subset[i], &potential_superset[i])) {
			return false;
		}
	}
#endif
	return true;
}

static inline register_mask matching_registers(const struct register_state a[REGISTER_COUNT], const struct register_state b[REGISTER_COUNT])
{
	register_mask result = 0;
	for (int i = 0; i < REGISTER_COUNT; i++) {
		result |= (register_mask)((a[i].value == b[i].value) && (a[i].max == b[i].max)) << i;
	}
	return result;
}

__attribute__((nonnull(1, 2)))
static bool decoded_rm_equal(const struct decoded_rm *l, const struct decoded_rm *r);

__attribute__((nonnull(1, 3)))
static void register_changed(struct registers *regs, int register_index, __attribute__((unused)) ins_ptr ins)
{
#if STORE_LAST_MODIFIED
	regs->last_modify_ins[register_index] = ins;
#else
	if (register_index == REGISTER_SYSCALL_NR) {
		regs->last_modify_syscall_register = ins;
	}
#endif
	if (regs->compare_state.validity != COMPARISON_IS_INVALID) {
		int compare_register = regs->compare_state.target_register;
		if (UNLIKELY(compare_register == register_index)) {
			if (compare_register != REGISTER_MEM || decoded_rm_equal(&regs->mem_rm, &regs->compare_state.mem_rm)) {
				LOG("clearing comparison since register changed", name_for_register(register_index));
				regs->compare_state.validity = COMPARISON_IS_INVALID;
			}
		} else if (decoded_rm_references_register(&regs->compare_state.mem_rm, register_index)) {
			LOG("clearing comparison since referenced register changed", name_for_register(register_index));
			regs->compare_state.validity = COMPARISON_IS_INVALID;
		}
	}
	if (LIKELY(register_index != REGISTER_MEM)) {
		if (UNLIKELY(decoded_rm_references_register(&regs->mem_rm, register_index))) {
			if (SHOULD_LOG) {
				if (register_is_partially_known(&regs->registers[REGISTER_MEM])) {
					ERROR("clearing mem since register changed", name_for_register(register_index));
				}
			}
			clear_register(&regs->registers[REGISTER_MEM]);
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[REGISTER_MEM] = ins;
#endif
		}
	}
}

__attribute__((nonnull(1)))
static char *copy_decoded_rm_description(const struct loader_context *loader, struct decoded_rm rm);

// __attribute__((always_inline))
__attribute__((nonnull(1, 2, 4)))
static inline void clear_match(const struct loader_context *loader, struct registers *regs, int register_index, __attribute__((unused)) ins_ptr ins)
{
	register_mask mask = regs->matches[register_index];
	if (UNLIKELY(register_index == REGISTER_SP || (register_index == REGISTER_MEM && regs->stack_address_taken && !decoded_rm_cannot_reference_stack_slot(&regs->mem_rm)))) {
		for (int i = REGISTER_STACK_0; i < REGISTER_COUNT; i++) {
			if (SHOULD_LOG) {
				if (register_is_partially_known(&regs->registers[i])) {
					if (register_index == REGISTER_SP) {
						ERROR("clearing stack slot since stack pointer changed", name_for_register(i));
					} else {
						ERROR("clearing stack slot since memory was written", name_for_register(i));
						ERROR("memory r/m is", temp_str(copy_decoded_rm_description(loader, regs->mem_rm)));
#if RECORD_WHERE_STACK_ADDRESS_TAKEN
						ERROR("stack address was taken previously at", temp_str(copy_address_description(loader, regs->stack_address_taken)));
#else
						ERROR("stack address was taken previously");
#endif
					}
				}
			}
			clear_register(&regs->registers[i]);
			mask |= regs->matches[i];
			regs->matches[i] = 0;
		}
	}
	if (UNLIKELY(mask != 0)) {
		LOG("clearing matches for", name_for_register(register_index));
		regs->matches[register_index] = 0;
		register_mask mask_off = ~((register_mask)1 << register_index);
		for_each_bit(mask & ALL_REGISTERS, bit, i) {
			if (SHOULD_LOG) {
				if (regs->matches[i] & ~mask_off) {
					ERROR("clearing match", name_for_register(i));
				}
			}
			regs->matches[i] &= mask_off;
		}
	}
	register_changed(regs, register_index, ins);
}

// add_match_and_copy_sources maintains the mapping table describing which registers have identical values
__attribute__((nonnull(1, 2, 5)))
static void add_match_and_copy_sources(const struct loader_context *loader, struct registers *regs, int dest_reg, int source_reg, __attribute__((unused)) ins_ptr ins)
{
	clear_match(loader, regs, dest_reg, ins);
	register_mask mask = regs->matches[source_reg];
	regs->matches[source_reg] = mask | ((register_mask)1 << dest_reg);
	regs->matches[dest_reg] = mask | ((register_mask)1 << source_reg);
	LOG("matching", name_for_register(source_reg));
	LOG("to", name_for_register(dest_reg));
	for_each_bit(mask & ALL_REGISTERS, bit, i) {
		LOG("existing match", name_for_register(i));
		regs->matches[i] |= (register_mask)1 << dest_reg;
	}
	regs->sources[dest_reg] = regs->sources[source_reg];
}

__attribute__((nonnull(1)))
static inline void clear_stack(struct registers *regs)
{
	for (int i = REGISTER_STACK_0; i < REGISTER_COUNT; i++) {
		clear_register(&regs->registers[i]);
		regs->sources[i] = 0;
		regs->matches[i] = 0;
	}
	for (int i = 0; i < REGISTER_STACK_0; i++) {
		regs->matches[i] &= ~STACK_REGISTERS;
	}
}

__attribute__((always_inline))
static inline bool binary_has_flags(const struct loaded_binary *binary, int flags)
{
	return (binary != NULL) && ((binary->special_binary_flags & flags) == flags);
}

__attribute__((nonnull(1, 2, 4)))
static inline void clear_call_dirtied_registers(const struct loader_context *loader, struct registers *regs, struct loaded_binary *binary, __attribute__((unused)) ins_ptr ins) {
#if defined(__x86_64__)
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_RAX])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_RAX));
	}
	clear_register(&regs->registers[REGISTER_RAX]);
	regs->sources[REGISTER_RAX] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_RCX])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_RCX));
	}
	clear_register(&regs->registers[REGISTER_RCX]);
	regs->sources[REGISTER_RCX] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_RDX])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_RDX));
	}
	clear_register(&regs->registers[REGISTER_RDX]);
	regs->sources[REGISTER_RDX] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_RSI])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_RSI));
	}
	clear_register(&regs->registers[REGISTER_RSI]);
	regs->sources[REGISTER_RSI] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_RDI])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_RDI));
	}
	clear_register(&regs->registers[REGISTER_RDI]);
	regs->sources[REGISTER_RDI] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_R8])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_R8));
	}
	clear_register(&regs->registers[REGISTER_R8]);
	regs->sources[REGISTER_R8] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_R9])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_R9));
	}
	clear_register(&regs->registers[REGISTER_R9]);
	regs->sources[REGISTER_R9] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_R10])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_R10));
	}
	clear_register(&regs->registers[REGISTER_R10]);
	regs->sources[REGISTER_R10] = 0;
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_R11])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_R11));
	}
	clear_register(&regs->registers[REGISTER_R11]);
	regs->sources[REGISTER_R11] = 0;
	if (binary_has_flags(binary, BINARY_IS_GOLANG)) {
		if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_RBX])) {
			LOG("clearing call dirtied register", name_for_register(REGISTER_RBX));
		}
		clear_register(&regs->registers[REGISTER_RBX]);
		regs->sources[REGISTER_RBX] = 0;
		if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_RSI])) {
			LOG("clearing call dirtied register", name_for_register(REGISTER_RSI));
		}
		clear_register(&regs->registers[REGISTER_RSI]);
		regs->sources[REGISTER_RSI] = 0;
	}
	if (SHOULD_LOG && register_is_partially_known(&regs->registers[REGISTER_MEM])) {
		LOG("clearing call dirtied register", name_for_register(REGISTER_MEM));
	}
#else
#if defined(__aarch64__)
	// TODO: clear call dirtied registers
#else
#error "Unknown architecture"
#endif
#endif
	clear_register(&regs->registers[REGISTER_MEM]);
	regs->sources[REGISTER_MEM] = 0;
#if defined(__x86_64__)
	clear_match(loader, regs, REGISTER_RAX, ins);
	clear_match(loader, regs, REGISTER_RCX, ins);
	clear_match(loader, regs, REGISTER_RDX, ins);
	clear_match(loader, regs, REGISTER_RSI, ins);
	clear_match(loader, regs, REGISTER_RDI, ins);
	clear_match(loader, regs, REGISTER_R8, ins);
	clear_match(loader, regs, REGISTER_R9, ins);
	clear_match(loader, regs, REGISTER_R10, ins);
	clear_match(loader, regs, REGISTER_R11, ins);
#else
#if defined(__aarch64__)
	// TODO: clear matches for call dirtied registers
#else
#error "Unknown architecture"
#endif
#endif
	clear_match(loader, regs, REGISTER_MEM, ins);
	regs->compare_state.validity = COMPARISON_IS_INVALID;
	regs->mem_rm = invalid_decoded_rm;
}

__attribute__((nonnull(1)))
static inline void push_stack(struct registers *regs, int push_count)
{
	LOG("push stack", push_count);
	if (push_count > REGISTER_COUNT - REGISTER_STACK_0) {
		push_count = REGISTER_COUNT - REGISTER_STACK_0;
	} else {
		for (int i = REGISTER_COUNT - 1; i >= REGISTER_STACK_0 + push_count; i--) {
			regs->registers[i] = regs->registers[i-push_count];
			regs->sources[i] = regs->sources[i-push_count];
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[i] = regs->last_modify_ins[i-push_count];
#endif
		}
	}
	for (int i = 0; i < push_count; i++) {
		clear_register(&regs->registers[REGISTER_STACK_0 + i]);
		regs->sources[REGISTER_STACK_0 + i] = 0;
#if STORE_LAST_MODIFIED
		regs->last_modify_ins[REGISTER_STACK_0 + i] = NULL;
#endif
	}
	// shift the matching bits around
	for (int i = 0; i < REGISTER_COUNT; i++) {
		regs->matches[i] = (regs->matches[i] & ~STACK_REGISTERS) | ((regs->matches[i] & STACK_REGISTERS) << push_count);
	}
}

__attribute__((nonnull(1)))
static inline void pop_stack(struct registers *regs, int pop_count)
{
	LOG("pop stack", pop_count);
	for (int i = REGISTER_STACK_0; i < REGISTER_COUNT; i++) {
		if (i + pop_count >= REGISTER_COUNT) {
			clear_register(&regs->registers[i]);
			regs->sources[i] = 0;
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[i] = NULL;
#endif
		} else {
			regs->registers[i] = regs->registers[i+pop_count];
			regs->sources[i] = regs->sources[i+pop_count];
#if STORE_LAST_MODIFIED
			regs->last_modify_ins[i] = regs->last_modify_ins[i+pop_count];
#endif
		}
	}
	// shift the matching bits around
	for (int i = 0; i < REGISTER_COUNT; i++) {
		regs->matches[i] = (regs->matches[i] & ~STACK_REGISTERS) | ((regs->matches[i] >> pop_count) & STACK_REGISTERS);
	}
}

__attribute__((nonnull(1, 2, 3)))
static inline struct registers copy_call_argument_registers(const struct loader_context *loader, const struct registers *regs, __attribute__((unused)) ins_ptr ins) {
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
	// Clear match state for REGISTER_MEM without invalidating stack
	// clear_match(loader, &result, REGISTER_MEM, ins);
#else
#if defined(__aarch64__)
	// TODO: clear call dirtied registers
	for (int i = REGISTER_X0; i <= REGISTER_X18; i++) {
		clear_register(&result.registers[i]);
		result.sources[i] = 0;
	}
	clear_register(&result.registers[REGISTER_SP]);
	result.sources[REGISTER_SP] = 0;
	clear_register(&result.registers[REGISTER_MEM]);
	result.sources[REGISTER_MEM] = 0;
	for (int i = REGISTER_X0; i <= REGISTER_X18; i++) {
		clear_match(loader, &result, i, ins);
	}
#else
#error "Unknown architecture"
#endif
#endif
	register_mask mask = result.matches[REGISTER_MEM];
	if (UNLIKELY(mask != 0)) {
		LOG("clearing matches for", name_for_register(REGISTER_MEM));
		result.matches[REGISTER_MEM] = 0;
		mask = ~((register_mask)1 << REGISTER_MEM);
#pragma GCC unroll 64
		for (int i = 0; i < REGISTER_COUNT; i++) {
			if (SHOULD_LOG) {
				if (result.matches[i] &~mask) {
					ERROR("clearing match", name_for_register(i));
				}
			}
			result.matches[i] &= mask;
		}
	}
#if STORE_LAST_MODIFIED
	result.last_modify_ins[REGISTER_MEM] = ins;
#endif
	result.mem_rm = invalid_decoded_rm;
	result.stack_address_taken = NULL;
	result.compare_state.validity = COMPARISON_IS_INVALID;
	return result;
}

static inline const char *name_for_register(int register_index)
{
	switch (register_index) {
#if defined(__x86_64__)
		case REGISTER_RAX:
			return "ax";
		case REGISTER_RCX:
			return "cx";
		case REGISTER_RDX:
			return "dx";
		case REGISTER_RBX:
			return "bx";
		case REGISTER_SP:
			return "sp";
		case REGISTER_RBP:
			return "bp";
		case REGISTER_RSI:
			return "si";
		case REGISTER_RDI:
			return "di";
		case REGISTER_R8:
			return "r8";
		case REGISTER_R9:
			return "r9";
		case REGISTER_R10:
			return "r10";
		case REGISTER_R11:
			return "r11";
		case REGISTER_R12:
			return "r12";
		case REGISTER_R13:
			return "r13";
		case REGISTER_R14:
			return "r14";
		case REGISTER_R15:
			return "r15";
#else
#if defined(__aarch64__)
		case REGISTER_X0:
			return "r0";
		case REGISTER_X1:
			return "r1";
		case REGISTER_X2:
			return "r2";
		case REGISTER_X3:
			return "r3";
		case REGISTER_X4:
			return "r4";
		case REGISTER_X5:
			return "r5";
		case REGISTER_X6:
			return "r6";
		case REGISTER_X7:
			return "r7";
		case REGISTER_X8:
			return "r8";
		case REGISTER_X9:
			return "r9";
		case REGISTER_X10:
			return "r10";
		case REGISTER_X11:
			return "r11";
		case REGISTER_X12:
			return "r12";
		case REGISTER_X13:
			return "r13";
		case REGISTER_X14:
			return "r14";
		case REGISTER_X15:
			return "r15";
		case REGISTER_X16:
			return "r16";
		case REGISTER_X17:
			return "r17";
		case REGISTER_X18:
			return "r18";
		case REGISTER_X19:
			return "r19";
		case REGISTER_X20:
			return "r20";
		case REGISTER_X21:
			return "r21";
		case REGISTER_X22:
			return "r22";
		case REGISTER_X23:
			return "r23";
		case REGISTER_X24:
			return "r24";
		case REGISTER_X25:
			return "r25";
		case REGISTER_X26:
			return "r26";
		case REGISTER_X27:
			return "r27";
		case REGISTER_X28:
			return "r28";
		case REGISTER_X29:
			return "r29";
		case REGISTER_X30:
			return "r30";
		case REGISTER_SP:
			return "sp";
#else
#error "Unknown architecture"
#endif
#endif
		case REGISTER_MEM:
			return "mem";
#define PER_STACK_REGISTER_IMPL(offset) case REGISTER_STACK_##offset: return "stack+" #offset;
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
		default:
			return "invalid";
	}
}

__attribute__((always_inline))
__attribute__((nonnull(1)))
static inline void dump_register(__attribute__((unused)) const struct loader_context *loader, __attribute__((unused)) struct register_state state)
{
	if (SHOULD_LOG) {
		LOG("value", temp_str(copy_register_state_description(loader, state)));
	}
}

__attribute__((nonnull(1, 2)))
static inline void dump_registers(const struct loader_context *loader, const struct registers *state, register_mask registers)
{
	if (SHOULD_LOG) {
		for (int i = 0; i < REGISTER_COUNT; i++) {
			if (registers & ((register_mask)1 << i)) {
				switch (i) {
#if defined(__x86_64__)
					case REGISTER_RAX:
						ERROR("rax", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_RCX:
						ERROR("rcx", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_RDX:
						ERROR("rdx", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_RBX:
						ERROR("rbx", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_RBP:
						ERROR("rbp", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_RSI:
						ERROR("rsi", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_RDI:
						ERROR("rdi", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R8:
						ERROR("r8", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R9:
						ERROR("r9", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R10:
						ERROR("r10", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R11:
						ERROR("r11", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R12:
						ERROR("r12", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R13:
						ERROR("r13", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R14:
						ERROR("r14", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_R15:
						ERROR("r15", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
#else
#if defined(__aarch64__)
					case REGISTER_X0:
						ERROR("x0", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X1:
						ERROR("x1", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X2:
						ERROR("x2", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X3:
						ERROR("x3", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X4:
						ERROR("x4", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X5:
						ERROR("x5", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X6:
						ERROR("x6", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X7:
						ERROR("x7", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X8:
						ERROR("x8", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X9:
						ERROR("x9", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X10:
						ERROR("x10", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X11:
						ERROR("x11", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X12:
						ERROR("x12", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X13:
						ERROR("x13", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X14:
						ERROR("x14", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X15:
						ERROR("x15", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X16:
						ERROR("x16", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X17:
						ERROR("x17", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X18:
						ERROR("x18", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X19:
						ERROR("x19", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X20:
						ERROR("x20", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X21:
						ERROR("x21", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X22:
						ERROR("x22", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X23:
						ERROR("x23", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X24:
						ERROR("x24", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X25:
						ERROR("x25", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X26:
						ERROR("x26", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X27:
						ERROR("x27", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X28:
						ERROR("x28", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X29:
						ERROR("x29", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_X30:
						ERROR("x30", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
#else
#error "Unsupported architecture"
#endif
#endif
					case REGISTER_SP:
						ERROR("sp", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
					case REGISTER_MEM:
						ERROR("mem", temp_str(copy_register_state_description(loader, state->registers[i])));
						break;
#define PER_STACK_REGISTER_IMPL(offset) case REGISTER_STACK_##offset: ERROR("stack+"#offset, temp_str(copy_register_state_description(loader, state->registers[i]))); break;
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
				}
#if STORE_LAST_MODIFIED
				if (state->last_modify_ins[i] != NULL) {
					ERROR("last modified at", temp_str(copy_address_description(loader, state->last_modify_ins[i])));
				}
#else
				if (i == REGISTER_SYSCALL_NR) {
					if (state->last_modify_syscall_register != NULL) {
						ERROR("last modified at", temp_str(copy_address_description(loader, state->last_modify_syscall_register)));
					}
				}
#endif
			}
		}
	}
}

__attribute__((nonnull(1, 2)))
static inline void dump_nonempty_registers(const struct loader_context *loader, const struct registers *state, register_mask registers)
{
	if (SHOULD_LOG) {
		for_each_bit(registers, bit, i) {
			if (!register_is_partially_known(&state->registers[i])) {
				registers &= ~bit;
			}
		}
		dump_registers(loader, state, registers);
	}
}

__attribute__((nonnull(1, 2)))
static bool decoded_rm_equal(const struct decoded_rm *l, const struct decoded_rm *r)
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

__attribute__((unused))
__attribute__((nonnull(1)))
static char *copy_decoded_rm_description(const struct loader_context *loader, struct decoded_rm rm)
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

static inline const char *name_for_effect(function_effects effects)
{
	effects &= ~(EFFECT_PROCESSED | EFFECT_PROCESSING | EFFECT_STICKY_EXITS | EFFECT_ENTER_CALLS) & VALID_EFFECTS;
	if (effects == EFFECT_NONE) {
		return "none";
	}
	if (effects == EFFECT_RETURNS) {
		return "returns";
	}
	if (effects == EFFECT_EXITS) {
		return "exits";
	}
	if (effects == (EFFECT_EXITS | EFFECT_RETURNS)) {
		return "returns or exits";
	}
	if (effects == (EFFECT_AFTER_STARTUP | EFFECT_NONE)) {
		return "none, potentially after startup";
	}
	if (effects == (EFFECT_AFTER_STARTUP | EFFECT_RETURNS)) {
		return "returns, potentially after startup";
	}
	if (effects == (EFFECT_AFTER_STARTUP | EFFECT_EXITS)) {
		return "exits, potentially after startup";
	}
	if (effects == (EFFECT_AFTER_STARTUP | EFFECT_EXITS | EFFECT_RETURNS)) {
		return "returns or exits, potentially after startup";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_NONE)) {
		return "none, inside entrypoint";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_RETURNS)) {
		return "returns, inside entrypoint";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_EXITS)) {
		return "exits, inside entrypoint";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_EXITS | EFFECT_RETURNS)) {
		return "returns or exits, inside entrypoint";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_AFTER_STARTUP | EFFECT_NONE)) {
		return "none, inside entrypoint and potentially after startup";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_AFTER_STARTUP | EFFECT_RETURNS)) {
		return "returns, inside entrypoint and potentially after startup";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_AFTER_STARTUP | EFFECT_EXITS)) {
		return "exits, inside entrypoint and potentially after startup";
	}
	if (effects == (EFFECT_ENTRY_POINT | EFFECT_AFTER_STARTUP | EFFECT_EXITS | EFFECT_RETURNS)) {
		return "returns or exits, inside entrypoint and potentially after startup";
	}
	return "invalid effects";
}

struct queued_instruction {
	ins_ptr ins;
	struct registers registers;
	ins_ptr caller;
	const char *description;
	function_effects effects;
};

__attribute__((nonnull(1, 2, 4)))
static void queue_instruction(struct queued_instructions *queue, ins_ptr ins, function_effects effects, const struct registers *registers, ins_ptr caller, const char *description)
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

__attribute__((nonnull(1, 2)))
static bool dequeue_instruction(struct queued_instructions *queue, struct queued_instruction *out_instruction)
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

struct lookup_base_address {
	ins_ptr ins;
	uintptr_t base;
};

__attribute__((nonnull(1, 2)))
static void add_lookup_table_base_address(struct lookup_base_addresses *addresses, ins_ptr ins, uintptr_t base)
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

__attribute__((nonnull(1, 2)))
static uintptr_t find_lookup_table_base_address(const struct lookup_base_addresses *addresses, ins_ptr ins)
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

struct searched_instruction_data_entry {
	register_mask used_registers;
	function_effects effects;
	uint8_t widen_count[REGISTER_COUNT];
	uint8_t used_count;
	uint16_t generation;
	struct register_state registers[];
};

struct searched_instruction_data {
	register_mask relevant_registers;
	register_mask preserved_registers;
	register_mask preserved_and_kept_registers;
	uint32_t end_offset;
	function_effects sticky_effects;
	uint16_t callback_index;
	struct searched_instruction_data_entry entries[];
};

struct searched_instruction_entry {
	ins_ptr address;
	struct searched_instruction_data *data;
};

__attribute__((nonnull(1)))
static size_t sizeof_searched_instruction_data_entry(struct searched_instruction_data_entry *entry)
{
	return sizeof(struct searched_instruction_data_entry) + entry->used_count * sizeof(struct register_state);
}

__attribute__((nonnull(1, 2)))
static char *copy_call_trace_description(const struct loader_context *context, const struct analysis_frame *head);

void init_searched_instructions(struct searched_instructions *search)
{
	search->table = calloc(8, sizeof(*search->table));
#ifdef SKIP_SHIFT
	search->mask = 7 * sizeof(struct searched_instruction_entry);
#else
	search->mask = 7;
#endif
	search->remaining_slots = 7;
	search->generation = 0;
	search->queue = (struct queued_instructions){ 0 };
	search->lookup_base_addresses = (struct lookup_base_addresses){ 0 };
	search->fopen_modes = NULL;
	search->fopen_mode_count = 0;
}

void cleanup_searched_instructions(struct searched_instructions *search)
{
	uint32_t mask = search->mask;
	struct searched_instruction_entry *table = search->table;
	uint32_t count = 0;
#ifdef SKIP_SHIFT
	uint32_t last_index = mask / sizeof(struct searched_instruction_entry);
#else
	uint32_t last_index = mask;
#endif
	for (uint32_t i = 0; i <= last_index; i++) {
		struct searched_instruction_data *data = table[i].data;
		if (data != NULL) {
			count++;
			free(data);
		}
	}
	LOG("block count", (intptr_t)count);
	free(search->fopen_modes);
	search->fopen_mode_count = 0;
	free(table);
	free(search->queue.queue);
	search->table = NULL;
	search->queue.queue = NULL;
	free(search->lookup_base_addresses.addresses);
	free(search->loaded_addresses);
	search->loaded_addresses = NULL;
	free(search->callbacks);
}

__attribute__((always_inline))
static inline uint32_t hash_instruction_address(ins_ptr addr)
{
	// I don't know why this hash function is so effective at distributing keys, but it is
	uint32_t truncated = (uintptr_t)addr;
	return ((truncated >> 16) ^ truncated) * 0x119de1f3;
}

__attribute__((always_inline))
static inline uint32_t next_index(uint32_t index)
{
#ifdef SKIP_SHIFT
	return index + sizeof(struct searched_instruction_entry);
#else
	return index + 1;
#endif
}

__attribute__((always_inline))
static inline struct searched_instruction_entry *entry_for_index(struct searched_instruction_entry *table, uint32_t index)
{
#ifdef SKIP_SHIFT
	return (struct searched_instruction_entry *)((uintptr_t)table + index);
#else
	return &table[index];
#endif
}

__attribute__((noinline))
__attribute__((nonnull(1)))
static void grow_already_searched_instructions(struct searched_instructions *search)
{
	struct searched_instruction_entry *old_table = search->table;
#ifdef SKIP_SHIFT
	uint32_t old_size = (search->mask / sizeof(struct searched_instruction_entry)) + 1;
#else
	uint32_t old_size = search->mask + 1;
#endif
	uint32_t new_size = old_size * 2;
	uint32_t mask = (new_size - 1) * sizeof(struct searched_instruction_entry);
	struct searched_instruction_entry *new_table = calloc(new_size, sizeof(*new_table));
	uint32_t remaining_slots = (new_size * 3) / 4;
	for (uint32_t i = 0; i < old_size; i++) {
		struct searched_instruction_entry *value = &old_table[i];
		if (value->address != NULL) {
			uint32_t index = hash_instruction_address(value->address);
			for (;; index = next_index(index)) {
				index &= mask;
				struct searched_instruction_entry *entry = entry_for_index(new_table, index);
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

__attribute__((nonnull(1, 2, 3)))
static void vary_effects_by_registers(struct searched_instructions *search, const struct loader_context *loader, const struct analysis_frame *self, register_mask relevant_registers, register_mask preserved_registers, register_mask preserved_and_kept_registers, function_effects required_effects);

struct loader_stub {
	struct loader_stub *next;
};

__attribute__((always_inline))
__attribute__((nonnull(1, 2)))
static inline void push_unreachable_breakpoint(__attribute__((unused)) struct unreachable_instructions *unreachables, __attribute__((unused)) ins_ptr breakpoint)
{
#if BREAK_ON_UNREACHABLES
	size_t old_count = unreachables->breakpoint_count;
	size_t new_count = old_count + 1;
	if (new_count > unreachables->breakpoint_buffer_size) {
		unreachables->breakpoint_buffer_size = (new_count * 2);
		unreachables->breakpoints = realloc(unreachables->breakpoints, unreachables->breakpoint_buffer_size * sizeof(*unreachables->breakpoints));
	}
	unreachables->breakpoints[old_count] = breakpoint;
	unreachables->breakpoint_count = new_count;
#endif
}

#if BREAK_ON_UNREACHABLES
__attribute__((always_inline))
__attribute__((nonnull(1, 2, 3, 4)))
static inline void push_reachable_region(const struct loader_context *loader, struct unreachable_instructions *unreachables, ins_ptr entry, ins_ptr exit)
{
	LOG("reachable entry", temp_str(copy_address_description(loader, entry)));
	LOG("reachable exit", temp_str(copy_address_description(loader, exit)));
	size_t old_count = unreachables->reachable_region_count;
	size_t new_count = old_count + 1;
	if (new_count > unreachables->reachable_region_buffer_size) {
		unreachables->reachable_region_buffer_size = (new_count * 2);
		unreachables->reachable_regions = realloc(unreachables->reachable_regions, unreachables->reachable_region_buffer_size * sizeof(*unreachables->reachable_regions));
	}
	unreachables->reachable_regions[old_count].entry = entry;
	unreachables->reachable_regions[old_count].exit = exit;
	unreachables->reachable_region_count = new_count;
}
#endif

__attribute__((always_inline))
__attribute__((nonnull(2)))
static inline void expand_registers(struct register_state full[REGISTER_COUNT], const struct searched_instruction_data_entry *entry)
{
	register_mask used_registers = entry->used_registers;
	int j = 0;
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		if (used_registers & ((register_mask)1 << i)) {
			full[i] = entry->registers[j++];
		} else {
			clear_register(&full[i]);
		}
	}
}

__attribute__((always_inline))
__attribute__((nonnull(1)))
static inline bool collapse_registers(struct searched_instruction_data_entry *entry, const struct register_state full[REGISTER_COUNT])
{
#if 0
	register_mask used_registers = entry->used_registers;
	int j = 0;
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		if (used_registers & ((register_mask)1 << i)) {
			entry->registers[j++] = full[i];
		}
	}
	return true;
#else
	int old_count = entry->used_count;
	int new_count = 0;
	register_mask used_registers = 0;
	for (int i = 0; i < REGISTER_COUNT; i++) {
		if (register_is_partially_known(&full[i])) {
			if (new_count == old_count) {
				LOG("too many registers to collapse", new_count);
				return false;
			}
			new_count++;
			used_registers |= (register_mask)1 << i;
		}
	}
	entry->used_registers = used_registers;
	int j = 0;
	for_each_bit(used_registers, bit, i) {
		entry->registers[j++] = full[i];
	}
	return true;
#endif
}

__attribute__((always_inline))
__attribute__((nonnull(2)))
static inline bool registers_are_subset_of_entry_registers(const struct register_state potential_subset[REGISTER_COUNT], const struct searched_instruction_data_entry *entry, register_mask valid_registers)
{
	register_mask used_registers = entry->used_registers;
	valid_registers &= used_registers;
	if (UNLIKELY(valid_registers != 0)) {
		int j = 0;
		for_each_bit(used_registers, bit, i) {
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

__attribute__((always_inline))
__attribute__((nonnull(1)))
static inline bool entry_registers_are_subset_of_registers(const struct searched_instruction_data_entry *entry, const struct register_state potential_superset[REGISTER_COUNT], register_mask valid_registers)
{
	register_mask used_registers = entry->used_registers;
	if (valid_registers != 0) {
		int j = 0;
#pragma GCC unroll 64
		for_each_bit(used_registers | valid_registers, bit, i) {
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

__attribute__((always_inline))
static inline struct searched_instruction_data_entry *entry_for_offset(struct searched_instruction_data *data, size_t offset)
{
	return (struct searched_instruction_data_entry *)((uintptr_t)&data->entries[0] + offset);
}

__attribute__((nonnull(1, 2)))
static void add_new_entry_with_registers(struct searched_instruction_entry *table_entry, const struct registers *registers)
{
	register_mask used_registers = 0;
	int used_count = 0;
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		if (register_is_partially_known(&registers->registers[i])) {
			used_registers |= (register_mask)1 << i;
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
	int j = 0;
	for_each_bit(used_registers, bit, i) {
		entry->registers[j++] = registers->registers[i];
	}
	data->end_offset = new_end_offset;
}

static inline bool combine_register_states(struct register_state *out_state, const struct register_state *combine_state, __attribute__((unused)) int register_index)
{
	if (combine_state->max == out_state->value - 1 && combine_state->value < out_state->value) {
		out_state->value = combine_state->value;
		LOG("widening down", name_for_register(register_index));
		return true;
	}
	if (combine_state->value == out_state->max + 1 && combine_state->max > out_state->max) {
		out_state->max = combine_state->max;
		LOG("widening up", name_for_register(register_index));
		return true;
	}
	if ((combine_state->value >= out_state->value && combine_state->value <= out_state->max) ||
		(out_state->value >= combine_state->value && out_state->value <= combine_state->max)) {
		*out_state = union_of_register_states(*out_state, *combine_state);
		LOG("combining overlapping", name_for_register(register_index));
		return true;
	}
	return false;
}

__attribute__((nonnull(1, 2, 3, 5, 6, 7))) __attribute__((always_inline))
static inline size_t entry_offset_for_registers(struct searched_instruction_entry *table_entry, const struct registers *registers, struct program_state *analysis, function_effects required_effects, __attribute__((unused)) ins_ptr addr, struct registers *out_registers, bool *out_wrote_registers)
{
	struct searched_instruction_data *data = table_entry->data;
	const struct loader_context *loader = &analysis->loader;
	register_mask relevant_registers = data->relevant_registers;
	size_t end_offset = data->end_offset;
	size_t count = 0;
	*out_wrote_registers = false;
	size_t total_processing_count = 0;
	for (size_t offset = 0; offset < end_offset; ) {
		struct searched_instruction_data_entry *entry = entry_for_offset(data, offset);
		total_processing_count += (entry->effects & EFFECT_PROCESSING) == EFFECT_PROCESSING;
		if ((entry->effects & required_effects) != required_effects) {
			goto continue_search_initial;
		}
		if (registers_are_subset_of_entry_registers(registers->registers, entry, relevant_registers)) {
			// new register values are a subset of an existing entry, reuse it
			if (SHOULD_LOG) {
				ERROR("subset of existing at offset, reusing effects", (intptr_t)offset);
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
#if !STORE_LAST_MODIFIED
			out_registers->last_modify_syscall_register = registers->last_modify_syscall_register;
#endif
#pragma GCC unroll 64
			for (int i = 0; i < REGISTER_COUNT; i++) {
				out_registers->matches[i] = registers->matches[i];
			}
			out_registers->mem_rm = registers->mem_rm;
			out_registers->stack_address_taken = registers->stack_address_taken;
			out_registers->compare_state = registers->compare_state;
			*out_wrote_registers = true;
			return offset;
		}
		if (entry_registers_are_subset_of_registers(entry, registers->registers, relevant_registers)) {
			// new register values are a superset of an existing entry, widen and reuse it
			for_each_bit(relevant_registers & ALL_REGISTERS, bit, i) {
				if (entry->widen_count[i] >= 15) {
					// widened too many times
					goto continue_search_initial;
				}
				entry->widen_count[i]++;
			}
			if (!collapse_registers(entry, registers->registers)) {
				goto continue_search_initial;
			}
			entry->effects = data->sticky_effects;
			LOG("superset of existing at offset, reprocessing effects", (intptr_t)offset);
			if (entry->effects & EFFECT_PROCESSING) {
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
	if (widenable_registers != 0 || total_processing_count > 50) {
		LOG("loop heuristics");
		dump_registers(loader, registers, widenable_registers);
		out_registers->compare_state.validity = COMPARISON_IS_INVALID;
		size_t processing_count = 0;
		for (size_t offset = 0; offset < end_offset; ) {
			struct searched_instruction_data_entry *entry = entry_for_offset(data, offset);
			if ((entry->effects & required_effects) != required_effects) {
				goto continue_search;
			}
			if (entry->effects & EFFECT_PROCESSING) {
				processing_count++;
			}
			expand_registers(out_registers->registers, entry);
#pragma GCC unroll 64
			for (int i = 0; i < REGISTER_COUNT; i++) {
				out_registers->sources[i] = registers->sources[i];
#if STORE_LAST_MODIFIED
				out_registers->last_modify_ins[i] = registers->last_modify_ins[i];
#endif
			}
#if !STORE_LAST_MODIFIED
			out_registers->last_modify_syscall_register = registers->last_modify_syscall_register;
#endif
#pragma GCC unroll 64
			for (int i = 0; i < REGISTER_COUNT; i++) {
				out_registers->matches[i] = registers->matches[i];
			}
			out_registers->mem_rm = registers->mem_rm;
			out_registers->stack_address_taken = registers->stack_address_taken;
			out_registers->compare_state = registers->compare_state;
			register_mask widened = 0;
			for_each_bit(relevant_registers & ALL_REGISTERS, bit, r) {
				if (register_is_subset_of_register(&registers->registers[r], &out_registers->registers[r])) {
					continue;
				}
				if (((widenable_registers & bit) == 0) && (processing_count < 25)) {
					goto continue_search;
				}
				if (entry->widen_count[r] < 4) {
					if (combine_register_states(&out_registers->registers[r], &registers->registers[r], r)) {
						dump_register(loader, out_registers->registers[r]);
					} else if (UNLIKELY(processing_count > 40) && register_is_exactly_known(&registers->registers[r])) {
						LOG("too many actively unwidened exact", name_for_register(r));
						dump_register(loader, out_registers->registers[r]);
						clear_register(&out_registers->registers[r]);
						out_registers->sources[r] = 0;
						register_mask match_mask = out_registers->matches[r];
						if (match_mask != 0) {
							if ((widenable_registers & match_mask) == match_mask) {
								LOG("widening a register in tandem with another, preserving match", name_for_register(r));
							} else {
								clear_match(&analysis->loader, out_registers, r, addr);
							}
						}
					} else if (UNLIKELY(processing_count > 50)) {
						LOG("too many actively unwidened inexact", name_for_register(r));
						dump_register(loader, out_registers->registers[r]);
						clear_register(&out_registers->registers[r]);
						out_registers->sources[r] = 0;
						register_mask match_mask = out_registers->matches[r];
						if (match_mask != 0) {
							if ((widenable_registers & match_mask) == match_mask) {
								LOG("widening a register in tandem with another, preserving match", name_for_register(r));
							} else {
								clear_match(&analysis->loader, out_registers, r, addr);
							}
						}
					} else {
						LOG("couldn't widen", name_for_register(r));
						dump_register(loader, registers->registers[r]);
						goto continue_search;
					}
				} else {
					LOG("widened too many times", name_for_register(r));
					dump_register(loader, out_registers->registers[r]);
					clear_register(&out_registers->registers[r]);
					out_registers->sources[r] = 0;
					register_mask match_mask = out_registers->matches[r];
					if (match_mask != 0) {
						if ((widenable_registers & match_mask) == match_mask) {
							LOG("widening a register in tandem with another, preserving match", name_for_register(r));
						} else {
							clear_match(&analysis->loader, out_registers, r, addr);
						}
					}
				}
				widened |= bit;
			}
			for (int r = 0; r < REGISTER_COUNT; r++) {
				if (widened & ((register_mask)1 << r)) {
					entry->widen_count[r]++;
				} else {
					out_registers->registers[r] = union_of_register_states(registers->registers[r], out_registers->registers[r]);
				}
			}
			if (!collapse_registers(entry, out_registers->registers)) {
				goto continue_search;
			}
			entry->effects = data->sticky_effects;
			LOG("loop heuristic chose existing at offset, reprocessing effects", (intptr_t)offset);
			LOG("widened for", temp_str(copy_address_description(loader, addr)));
			dump_registers(loader, out_registers, widened);
			register_mask unwidened = relevant_registers & ~widened;
			if (unwidened) {
				LOG("registers left as-is", temp_str(copy_address_description(loader, addr)));
				dump_registers(loader, out_registers, unwidened);
			}
			if (entry->effects & EFFECT_PROCESSING) {
				entry->generation++;
				LOG("processing, so bumping the generation counter");
			}
			*out_wrote_registers = true;
			return offset;
		continue_search:
			offset += sizeof_searched_instruction_data_entry(entry);
		}
	}
	if (count > 60) {
		LOG("too many entries, widening all registers");
		if (widenable_registers != 0) {
			*out_registers = *registers;
			if (SHOULD_LOG) {
				for (int i = 0; i < REGISTER_COUNT; i++) {
					if (widenable_registers & ((register_mask)1 << i)) {
						LOG("widening register", name_for_register(i));
					} else if (relevant_registers & ((register_mask)1 << i)) {
						LOG("skipping widening register", name_for_register(i));
					}
				}
			}
			for_each_bit(widenable_registers & ALL_REGISTERS, bit, i) {
				clear_register(&out_registers->registers[i]);
				out_registers->sources[i] = 0;
			}
			*out_wrote_registers = true;
		} else {
			if (SHOULD_LOG) {
				for_each_bit(relevant_registers, bit, i) {
					ERROR("skipping widening register", name_for_register(i));
				}
			}
		}
	}
	size_t result = data->end_offset;
	add_new_entry_with_registers(table_entry, *out_wrote_registers ? out_registers : registers);
	LOG("new entry at offset", (intptr_t)result);
	return result;
}

__attribute__((always_inline))
__attribute__((nonnull(1, 2, 3)))
static inline struct searched_instruction_entry *find_searched_instruction_table_entry(struct searched_instructions *search, ins_ptr addr, struct effect_token *token)
{
	token->entry_offset = 0;
	token->entry_generation = 0;
	uint32_t original_index = hash_instruction_address(addr);
retry:
	;
	struct searched_instruction_entry *table = search->table;
	uint32_t mask = search->mask;
	uint32_t index = original_index & mask;
	token->generation = search->generation;
	for (;; index = next_index(index) & mask) {
		struct searched_instruction_entry *entry = entry_for_index(table, index);
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
			*result = (struct searched_instruction_data){ 0 };
			entry->data = result;
			return entry;
		}
	}
}

static inline bool validate_offset(__attribute__((unused)) struct searched_instruction_data *data, __attribute__((unused)) int entry_offset)
{
#ifdef CLEAR_PROCESSED_ENTRIES
#if 0
	return LIKELY(data->end_offset > (uint32_t)entry_offset);
#else
	if (LIKELY(data->end_offset >= (uint32_t)entry_offset + sizeof(struct searched_instruction_data_entry))) {
		struct searched_instruction_data_entry *entry = entry_for_offset(data, entry_offset);
		return LIKELY(data->end_offset >= (uint32_t)entry_offset + sizeof(struct searched_instruction_data_entry) + entry->used_count * sizeof(entry->registers[0]));
	}
	return false;
#endif
#else
	return true;
#endif
}

__attribute__((always_inline))
__attribute__((nonnull(1, 2, 3, 5)))
static inline function_effects *get_or_populate_effects(struct program_state *analysis, ins_ptr addr, struct registers *registers, function_effects required_effects, struct effect_token *token)
{
	struct searched_instructions *search = &analysis->search;
	struct searched_instruction_entry *table_entry = find_searched_instruction_table_entry(search, addr, token);
	bool wrote_registers;
	int entry_offset = entry_offset_for_registers(table_entry, registers, analysis, required_effects, addr, registers, &wrote_registers);
	token->entry_offset = entry_offset;
	if (!validate_offset(table_entry->data, entry_offset)) {
		return &table_entry->data->sticky_effects;
	}
	struct searched_instruction_data_entry *entry = entry_for_offset(table_entry->data, entry_offset);
	token->entry_generation = entry->generation;
	return &entry->effects;
}

__attribute__((always_inline))
static inline void set_effects(struct searched_instructions *search, ins_ptr addr, struct effect_token *token, function_effects new_effects)
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
		for (;; index = next_index(index)) {
			index &= mask;
			if (entry_for_index(table, index)->address == addr) {
				token->index = index;
				break;
			}
		}
	}
	uint32_t entry_offset = token->entry_offset;
	struct searched_instruction_entry *table_entry = entry_for_index(table, index);
	if (!validate_offset(table_entry->data, entry_offset)) {
		// deleted by hack for lower memory usage!
		return;
	}
	struct searched_instruction_data_entry *entry = entry_for_offset(table_entry->data, entry_offset);
	if (token->entry_generation == entry->generation) {
		entry->effects = new_effects;
#ifdef CLEAR_PROCESSED_ENTRIES
		// hack for lower memory usage
		if (LIKELY((new_effects & EFFECT_PROCESSING) == 0)) {
			if (UNLIKELY(table_entry->data->relevant_registers == 0)) {
				size_t size = sizeof_searched_instruction_data_entry(entry);
				if (table_entry->data->end_offset == entry_offset + size) {
					table_entry->data->sticky_effects = entry->effects;
					table_entry->data->end_offset = entry_offset;
					table_entry->data = realloc(table_entry->data, sizeof(*table_entry->data) + entry_offset);
				}
			}
		}
#endif
	} else {
		LOG("skipping setting effects because the generation changed");
	}
}

struct previous_register_masks {
	register_mask relevant_registers;
	register_mask preserved_and_kept_registers;
};

static inline struct previous_register_masks add_relevant_registers(struct searched_instructions *search, const struct loader_context *loader, ins_ptr addr, const struct registers *registers, function_effects required_effects, register_mask relevant_registers, register_mask preserved_registers, register_mask preserved_and_kept_registers, struct effect_token *token)
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
		for (;; index = next_index(index)) {
			index &= mask;
			ins_ptr value = entry_for_index(table, index)->address;
			if (value == addr) {
				token->index = index;
				break;
			}
		}
	}
	struct searched_instruction_data *data = entry_for_index(table, index)->data;
	struct previous_register_masks result = (struct previous_register_masks){
		.relevant_registers = data->relevant_registers,
		.preserved_and_kept_registers = data->preserved_and_kept_registers,
	};
	data->relevant_registers = result.relevant_registers | relevant_registers;
	data->preserved_registers |= preserved_registers;
	data->preserved_and_kept_registers = result.preserved_and_kept_registers | preserved_and_kept_registers;
	int entry_offset = token->entry_offset;
	if (!validate_offset(data, entry_offset)) {
		// entry was deleted!
		return result;
	}
	struct searched_instruction_data_entry *entry = entry_for_offset(data, entry_offset);
	if (SHOULD_LOG) {
#if 0
		for (uint32_t i = 0; i < data->count; i++) {
			if (i == token->entry_index) {
				ERROR("existing values (index)", (intptr_t)i);
			} else {
				ERROR("existing values", (intptr_t)i);
			}
			dump_registers(loader, &data->entries[i], data->relevant_registers);
		}
#else
		ERROR("existing values (index)", (intptr_t)token->entry_offset);
		struct registers regs = { 0 };
		expand_registers(regs.registers, entry);
		dump_registers(loader, &regs, data->relevant_registers);
#endif
	}
	function_effects effects;
	if (registers_are_subset_of_entry_registers(registers->registers, entry, data->relevant_registers)) {
		effects = entry->effects;
	} else {
		effects = EFFECT_NONE;
	}
	if ((effects & required_effects) != required_effects) {
		struct registers copy;
		expand_registers(copy.registers, entry);
		for (int i = 0; i < REGISTER_COUNT; i++) {
			copy.sources[i] = registers->sources[i];
			copy.matches[i] = registers->matches[i];
#if STORE_LAST_MODIFIED
			copy.last_modify_ins[i] = registers->last_modify_ins[i];
#endif
		}
#if !STORE_LAST_MODIFIED
		copy.last_modify_syscall_register = registers->last_modify_syscall_register;
#endif
		copy.mem_rm = registers->mem_rm;
		copy.compare_state = registers->compare_state;
		copy.stack_address_taken = registers->stack_address_taken;
		queue_instruction(&search->queue, addr, required_effects, &copy, addr, "varying ancestors");
	}
	return result;
}

__attribute__((nonnull(1, 2)))
static uint16_t index_for_callback_and_data(struct searched_instructions *search, instruction_reached_callback callback, void *callback_data)
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

__attribute__((unused))
__attribute__((nonnull(1, 2)))
static char *copy_function_call_description(const struct loader_context *context, ins_ptr target, struct registers registers);

__attribute__((nonnull(1, 2, 7)))
static void find_and_add_callback(struct program_state *analysis, ins_ptr addr, register_mask relevant_registers, register_mask preserved_registers, register_mask preserved_and_kept_registers, function_effects additional_effects, instruction_reached_callback callback, void *callback_data)
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
			.token = { 0 },
			.current_state = empty_registers,
			.is_entry = true,
		};
		self.entry_state = &self.current_state;
		char *copy = malloc(end_offset);
		memcpy(copy, data->entries, end_offset);
		for (uint32_t offset = 0; offset < end_offset; ) {
			token.entry_offset = offset;
			struct searched_instruction_data_entry *entry = (struct searched_instruction_data_entry *)&copy[offset];
			token.entry_generation = entry->generation;
			expand_registers(self.current_state.registers, entry);
			LOG("invoking callback on existing entry", temp_str(copy_function_call_description(&analysis->loader, addr, self.current_state)));
			callback(analysis, addr, &self.current_state, entry->effects, &self, &token, callback_data);
			offset += sizeof_searched_instruction_data_entry(entry);
		}
		free(copy);
	}
}

#ifdef __x86_64__
static inline void dump_x86_ins_prefixes(__attribute__((unused)) struct x86_ins_prefixes prefixes)
{
	LOG("decoded.prefixes.w", prefixes.has_w ? "true" : "false");
	LOG("decoded.prefixes.r", prefixes.has_r ? "true" : "false");
	LOG("decoded.prefixes.x", prefixes.has_x ? "true" : "false");
	LOG("decoded.prefixes.b", prefixes.has_b ? "true" : "false");
	// LOG("notrack", prefixes.has_notrack ? "true" : "false");
}
#endif

#ifdef __x86_64__
__attribute__((always_inline))
__attribute__((nonnull(2)))
static inline bool register_is_legacy_8bit_high(struct x86_ins_prefixes prefixes, int *register_index)
{
	if (UNLIKELY(*register_index >= REGISTER_SP && *register_index < REGISTER_R8 && !prefixes.has_any_rex)) {
		*register_index -= 4;
		LOG("found legacy 8bit register", name_for_register(*register_index));
		return true;
	}
	return false;
}

__attribute__((nonnull(1)))
static inline void truncate_to_size_prefixes(struct register_state *reg, struct x86_ins_prefixes prefixes)
{
	if (prefixes.has_w) {
		canonicalize_register(reg);
	} else if (prefixes.has_operand_size_override) {
		truncate_to_16bit(reg);
	} else {
		truncate_to_32bit(reg);
	}
}

__attribute__((nonnull(1)))
static inline bool register_is_partially_known_size_prefixes(struct register_state *reg, struct x86_ins_prefixes prefixes)
{
	if (prefixes.has_w) {
		return register_is_partially_known(reg);
	} else if (prefixes.has_operand_size_override) {
		return register_is_partially_known_16bit(reg);
	} else {
		return register_is_partially_known_32bit(reg);
	}
}
#endif

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

__attribute__((nonnull(1, 3)))
static int protection_for_address(const struct loader_context *context, const void *address, struct loaded_binary **out_binary, const ElfW(Shdr) **out_section);
static int protection_for_address_in_binary(const struct loaded_binary *binary, uintptr_t addr, const ElfW(Shdr) **out_section);

__attribute__((nonnull(1)))
const struct recorded_syscall *find_recorded_syscall(const struct recorded_syscalls *syscalls, uintptr_t nr)
{
	for (int i = 0; i < syscalls->count; i++) {
		if (syscalls->list[i].nr == nr) {
			return &syscalls->list[i];
		}
	}
	return NULL;
}

__attribute__((nonnull(1, 2)))
static int load_debuglink(const struct loader_context *loader, struct loaded_binary *binary, bool force_loading);

__attribute__((nonnull(1, 2, 3)))
void *resolve_binary_loaded_symbol(const struct loader_context *loader, struct loaded_binary *binary, const char *name, const char *version_name, int symbol_types, const ElfW(Sym) **out_symbol) {
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

void *resolve_loaded_symbol(const struct loader_context *context, const char *name, const char *version_name, int symbol_types, struct loaded_binary **out_binary, const ElfW(Sym) **out_symbol) {
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

__attribute__((nonnull(1, 2)))
static void *resolve_next_binary_loaded_symbol(struct loaded_binary *binary, const char *name, int symbol_types, const ElfW(Sym) **symbol) {
	if ((symbol_types & NORMAL_SYMBOL) && binary->has_symbols && (*symbol == NULL || symbol_info_contains_symbol(&binary->symbols, *symbol))) {
		const struct symbol_info *symbols = &binary->symbols;
		void *result = find_next_symbol(&binary->info, symbols, name, symbol);
		if (result != NULL) {
			return result;
		}
		*symbol = NULL;
	}
	if ((symbol_types & LINKER_SYMBOL) && binary->has_linker_symbols && (*symbol == NULL || symbol_info_contains_symbol(&binary->linker_symbols, *symbol))) {
		const struct symbol_info *symbols = &binary->linker_symbols;
		void *result = find_next_symbol(&binary->info, symbols, name, symbol);
		if (result != NULL) {
			return result;
		}
		*symbol = NULL;
	}
	if ((symbol_types & DEBUG_SYMBOL) && binary->has_debuglink_symbols && (*symbol == NULL || symbol_info_contains_symbol(&binary->debuglink_symbols, *symbol))) {
		const struct symbol_info *symbols = &binary->debuglink_symbols;
		void *result = find_next_symbol(&binary->info, symbols, name, symbol);
		if (result != NULL) {
			return result;
		}
	}
	return NULL;
}

__attribute__((nonnull(1, 2, 3)))
static inline ins_ptr update_known_function(struct program_state *analysis, struct loaded_binary *binary, const char *name, int symbol_locations, function_effects effects)
{
	ins_ptr addr = resolve_binary_loaded_symbol(&analysis->loader, binary, name, NULL, symbol_locations, NULL);
	if (addr == NULL) {
		return addr;
	}
	LOG("found known function", name);
	LOG("at", temp_str(copy_address_description(&analysis->loader, addr)));
	struct effect_token token;
	if (effects == EFFECT_STICKY_EXITS) {
		struct searched_instruction_entry *table_entry = find_searched_instruction_table_entry(&analysis->search, addr, &token);
		table_entry->data->sticky_effects |= EFFECT_STICKY_EXITS;
		for (uint32_t offset = 0; offset < table_entry->data->end_offset; ) {
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

__attribute__((nonnull(1, 2, 3)))
static inline void skip_lea_on_known_symbol(struct program_state *analysis, struct loaded_binary *binary, const char *name, size_t default_size)
{
	const ElfW(Sym) *symbol = NULL;
	ins_ptr value;
	while ((value = resolve_next_binary_loaded_symbol(binary, name, NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL, &symbol)) != NULL) {
		LOG("found symbol to skip", name);
		LOG("symbol address is", temp_str(copy_address_description(&analysis->loader, value)));
		struct known_symbols *known_symbols = &analysis->known_symbols;
		for (int i = 0; i < SKIPPED_LEA_AREA_COUNT; i++) {
			if (known_symbols->skipped_lea_areas[i].address == NULL) {
				known_symbols->skipped_lea_areas[i].address = value;
				known_symbols->skipped_lea_areas[i].size = symbol->st_size != 0 ? symbol->st_size : default_size;
				break;
			}
		}
	}
}

static void handle_forkAndExecInChild1(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered forkAndExecInChild1 call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	if ((analysis->syscalls.config[SYS_execve] & SYSCALL_CONFIG_BLOCK) == 0) {
		ERROR("program calls execve. unable to analyze through execs. if you know your use of this program doesn't result in new programs being executed specify --block-syscall execve");
		ERROR_FLUSH();
		fs_exit(1);
	}
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_EXITS | EFFECT_ENTER_CALLS);
	add_blocked_symbol(&analysis->known_symbols, "syscall.forkAndExecInChild1", 0, true)->value = ins;
}

static void handle_musl_setxid(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered musl __setxid call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	if (analysis->loader.setxid_sighandler_syscall != NULL) {
		int arg0index = sysv_argument_abi_register_indexes[0];
		if (!register_is_exactly_known(&state->registers[arg0index])) {
			DIE("musl __setxid with unknown nr argument", temp_str(copy_call_trace_description(&analysis->loader, caller)));
		}
		struct analysis_frame self = {
			.address = analysis->loader.setxid_sighandler_syscall,
			.description = "syscall",
			.next = caller,
			.entry = caller->address,
			.entry_state = &caller->current_state,
			.token = { 0 },
			.current_state = empty_registers,
			.is_entry = false,
		};
		self.current_state.registers[REGISTER_SYSCALL_NR] = caller->current_state.registers[arg0index];
		for (int i = 0; i < 3; i++) {
			self.current_state.registers[syscall_argument_abi_register_indexes[i]] = caller->current_state.registers[sysv_argument_abi_register_indexes[i+1]];
		}
		record_syscall(analysis, caller->current_state.registers[arg0index].value, self, effects);
	}
}

__attribute__((nonnull(1)))
static struct loaded_binary *binary_for_address(const struct loader_context *context, const void *addr);

__attribute__((nonnull(1, 2, 3)))
void analyze_function_symbols(struct program_state *analysis, const struct loaded_binary *binary, const struct symbol_info *symbols, struct analysis_frame *caller)
{
	for (size_t i = 0; i < symbols->symbol_count; i++) {
		const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbols->symbols + i * symbols->symbol_stride);
		if (ELF64_ST_BIND(symbol->st_info) == STB_GLOBAL && ELF64_ST_TYPE(symbol->st_info) == STT_FUNC) {
			ins_ptr ins = (ins_ptr)apply_base_address(&binary->info, symbol->st_value);
			if (protection_for_address_in_binary(binary, (uintptr_t)ins, NULL) & PROT_EXEC) {
				LOG("symbol contains executable code that might be dlsym'ed", symbol_name(symbols, symbol));
				struct analysis_frame new_caller = { .address = ins, .description = symbol_name(symbols, symbol), .next = caller, .current_state = empty_registers, .entry = binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = false, };
				analyze_function(analysis, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, ins, &new_caller);
			} else {
				LOG("symbol is not executable", symbol_name(symbols, symbol));
			}
		} else {
			if (ELF64_ST_BIND(symbol->st_info) != STB_GLOBAL) {
				LOG("symbol is not global", symbol_name(symbols, symbol));
			} else {
				LOG("symbol is not a function", symbol_name(symbols, symbol));
			}
		}
	}
}

static int load_all_needed_and_relocate(struct program_state *analysis);

static struct loaded_binary *register_dlopen_file(struct program_state *analysis, const char *path, const struct analysis_frame *caller, bool skip_analysis, bool skip_analyzing_symbols)
{
	struct loaded_binary *binary = find_loaded_binary(&analysis->loader, path);
	if (binary == NULL) {
		char buf[PATH_MAX];
		const char *full_path;
		int needed_fd = find_executable_in_paths(path, "/lib/"ARCH_NAME"-linux-gnu:/lib:/usr/lib", false, analysis->loader.uid, analysis->loader.gid, buf, &full_path);
		if (needed_fd < 0) {
			LOG("failed to find dlopen'ed path, assuming it will fail at runtime", path);
			return NULL;
		}
		struct loaded_binary *new_binary;
		int result = load_binary_into_analysis(analysis, path, full_path, needed_fd, NULL, &new_binary);
		fs_close(needed_fd);
		if (result < 0) {
			LOG("failed to load dlopen'ed path, assuming it will fail at runtime", path);
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
				result = finish_loading_binary(analysis, other, EFFECT_NONE, skip_analysis);
				if (result != 0) {
					ERROR("failed to load interpreter or libc", other->path);
					return NULL;
				}
			}
		}
		result = finish_loading_binary(analysis, new_binary, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, skip_analysis);
		if (result != 0) {
			LOG("failed to finish loading dlopen'ed path, assuming it will fail at runtime", path);
			return NULL;
		}
		binary = new_binary;
	} else if (binary->special_binary_flags & BINARY_HAS_FUNCTION_SYMBOLS_ANALYZED) {
		return binary;
	}
	if (skip_analyzing_symbols) {
		LOG("skipping analysis for", path);
	} else {
		binary->special_binary_flags |= BINARY_HAS_FUNCTION_SYMBOLS_ANALYZED;
		struct analysis_frame dlopen_caller = { .address = binary->info.base, .description = "dlopen", .next = caller, .current_state = empty_registers, .entry = binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
		if (binary->has_symbols) {
			LOG("analyzing symbols for", path);
			analyze_function_symbols(analysis, binary, &binary->symbols, &dlopen_caller);
		} else {
			LOG("skipping analyzing symbols for", path);
		}
		if (binary->has_linker_symbols) {
			LOG("analyzing linker symbols for", path);
			analyze_function_symbols(analysis, binary, &binary->linker_symbols, &dlopen_caller);
		} else {
			LOG("skipping linker analyzing symbols for", path);
		}
	}
	return binary;
}

struct loaded_binary *register_dlopen_file_owning_path(struct program_state *analysis, char *path, const struct analysis_frame *caller, bool skip_analysis, bool skip_analyzing_symbols)
{
	struct loaded_binary *binary = register_dlopen_file(analysis, path, caller, skip_analysis, skip_analyzing_symbols);
	if (!binary) {
		free(path);
	} else if (binary->path == path) {
		binary->owns_path = true;
	} else {
		free(path);
	}
	return binary;
}


static void handle_gconv_find_shlib(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data);

__attribute__((nonnull(1, 2)))
static ins_ptr find_function_entry(struct loader_context *loader, ins_ptr ins)
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

static void handle_dlopen(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	if (effects == EFFECT_NONE) {
		LOG("encountered dlopen call with no effects", temp_str(copy_call_trace_description(&analysis->loader, caller)));
		return;
	}
	LOG("encountered dlopen call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	LOG("with effects", (uintptr_t)effects);
	struct register_state *first_arg = &state->registers[sysv_argument_abi_register_indexes[0]];
	if (!register_is_exactly_known(first_arg)) {
		// check if we're searching for gconv and if so attach handle_gconv_find_shlib as callback
		if (analysis->loader.searching_gconv_dlopen || analysis->loader.searching_libcrypto_dlopen) {
			struct analysis_frame self = {
				.address = ins,
				.description = NULL,
				.next = caller,
				.entry = ins,
				.entry_state = state,
				.token = *token,
				.is_entry = true,
			};
			vary_effects_by_registers(&analysis->search, &analysis->loader, &self, (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], EFFECT_PROCESSED);
			find_and_add_callback(analysis, find_function_entry(&analysis->loader, caller->entry) ?: caller->entry, 0, 0, 0, EFFECT_NONE, handle_gconv_find_shlib, NULL);
			if (analysis->loader.searching_gconv_dlopen) {
				analysis->loader.gconv_dlopen = ins;
			}
			if (analysis->loader.searching_libcrypto_dlopen) {
				analysis->loader.libcrypto_dlopen = ins;
				if (fs_access("/lib/"ARCH_NAME"-linux-gnu/ossl-modules", R_OK) == 0) {
					register_dlopen(analysis, "/lib/"ARCH_NAME"-linux-gnu/ossl-modules", caller, false, false, true);
				}
				if (fs_access("/lib/engines-3", R_OK) == 0) {
					register_dlopen(analysis, "/lib/engines-3", caller, false, false, true);
				}
				if (fs_access("/lib64/engines-3", R_OK) == 0) {
					register_dlopen(analysis, "/lib64/engines-3", caller, false, false, true);
				}
				if (fs_access("/usr/lib64/openssl/engines", R_OK) == 0) {
					register_dlopen(analysis, "/usr/lib64/openssl/engines", caller, false, false, true);
				}
			}
			analysis->loader.searching_gconv_dlopen = analysis->loader.searching_libcrypto_dlopen = false;
			return;
		}
		if (analysis->loader.ignore_dlopen) {
			LOG("dlopen with indeterminate value", temp_str(copy_register_state_description(&analysis->loader, *first_arg)));
			LOG("dlopen call stack", temp_str(copy_call_trace_description(&analysis->loader, caller)));
			return;
		}
		ERROR("dlopen with indeterminate value", temp_str(copy_register_state_description(&analysis->loader, *first_arg)));
		DIE("dlopen call stack", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	}
	const char *needed_path = (const char *)first_arg->value;
	if (needed_path == NULL) {
		LOG("dlopen with NULL");
		return;
	}
	struct loaded_binary *binary;
	int prot = protection_for_address(&analysis->loader, needed_path, &binary, NULL);
	if ((prot & PROT_READ) == 0) {
		ERROR("dlopen with constant, but unreadable value", temp_str(copy_address_description(&analysis->loader, needed_path)));
		DIE("dlopen call stack", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	}
	LOG("dlopen with constant path", needed_path);
	struct analysis_frame self = {
		.description = NULL,
		.next = caller,
		.entry = ins,
		.entry_state = state,
		.token = *token,
		.is_entry = true,
	};
	vary_effects_by_registers(&analysis->search, &analysis->loader, &self, (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS);
	register_dlopen_file(analysis, needed_path, caller, false, false);
}

static void handle_gconv_find_shlib(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered gconv_find_shlib call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	struct analysis_frame self = {
		.description = NULL,
		.next = caller,
		.entry = ins,
		.entry_state = state,
		.token = *token,
		.is_entry = true,
	};
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_RETURNS | EFFECT_ENTER_CALLS);
	*token = self.token;
	if (analysis->loader.loaded_gconv_libraries) {
		return;
	}
	analysis->loader.loaded_gconv_libraries = true;
	int dirfd = fs_open("/usr/lib/"ARCH_NAME"-linux-gnu/gconv", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	if (dirfd < 0) {
		if (dirfd == -ENOENT) {
			dirfd = fs_open("/lib64/gconv", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
		}
		if (dirfd == -ENOENT) {
			dirfd = fs_open("/usr/lib64/gconv", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
		}
		if (dirfd < 0) {
			if (dirfd == -ENOENT) {
				return;
			}
			DIE("failed to open gconv library path", fs_strerror(dirfd));
		}
	}
	for (;;) {
		char buf[8192];
		int count = fs_getdents(dirfd, (struct fs_dirent *)&buf[0], sizeof(buf));
		if (count <= 0) {
			if (count < 0) {
				DIE("failed to read gconv library entries", fs_strerror(count));
			}
			break;
		}
		for (int offset = 0; offset < count; ) {
			const struct fs_dirent *ent = (const struct fs_dirent *)&buf[offset];
			const char *name = ent->d_name;
			const char *needle = ".so";
			if (name[0] != 'l' || name[1] != 'i' || name[2] != 'b') {
				for (const char *haystack = name;;) {
					if (*haystack == *needle) {
						if (*needle == '\0') {
							size_t suffix_len = haystack - name;
							char *path = malloc(sizeof("/usr/lib/"ARCH_NAME"-linux-gnu/gconv/") + suffix_len);
							char *path_buf = path;
							fs_memcpy(path_buf, "/usr/lib/"ARCH_NAME"-linux-gnu/gconv/", sizeof("/usr/lib/"ARCH_NAME"-linux-gnu/gconv/") - 1);
							path_buf += sizeof("/usr/lib/"ARCH_NAME"-linux-gnu/gconv/") - 1;
							fs_memcpy(path_buf, name, suffix_len + 1);
							LOG("found gconv library", path);
							register_dlopen_file_owning_path(analysis, path, caller, true, true);
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

__attribute__((nonnull(1, 2, 3)))
static void discovered_nss_provider(struct program_state *analysis, const struct analysis_frame *caller, const char *provider)
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
	register_dlopen_file_owning_path(analysis, library_name, caller, false, false);
}

__attribute__((nonnull(1, 2)))
static void load_nss_libraries(struct program_state *analysis, const struct analysis_frame *caller)
{
	if (analysis->loader.loaded_nss_libraries) {
		return;
	}
	analysis->loader.loaded_nss_libraries = true;
	int nsswitch_fd = fs_open("/etc/nsswitch.conf", O_RDONLY | O_CLOEXEC, 0);
	if (nsswitch_fd < 0) {
		DIE("nsswitch used, but unable to open nsswitch configuration", fs_strerror(nsswitch_fd));
	}
	struct fs_stat stat;
	int result = fs_fstat(nsswitch_fd, &stat);
	if (result < 0) {
		DIE("nsswitch used, but unable to stat nsswitch configuration", fs_strerror(result));
	}
	char *buf = malloc(stat.st_size + 1);
	result = fs_read(nsswitch_fd, buf, stat.st_size);
	fs_close(nsswitch_fd);
	if (result != stat.st_size) {
		if (result < 0) {
			DIE("nsswitch used, but unable to read nsswitch configuration", fs_strerror(result));
		}
		DIE("nsswitch used, but wrong number of bytes read for nsswitch configuration", result);
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

static void handle_nss_usage(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered nss call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	load_nss_libraries(analysis, caller);
	struct analysis_frame self = {
		.description = NULL,
		.next = caller,
		.entry = ins,
		.entry_state = state,
		.token = *token,
		.is_entry = true,
	};
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTER_CALLS);
	*token = self.token;
}

static void *find_any_symbol_by_address(const struct loader_context *loader, struct loaded_binary *binary, const void *addr, int symbol_types, const struct symbol_info **out_used_symbols, const ElfW(Sym) **out_symbol);

static const char *find_any_symbol_name_by_address(const struct loader_context *loader, struct loaded_binary *binary, const void *addr, int symbol_types)
{
	if (binary != NULL) {
		const struct symbol_info *symbols;
		const ElfW(Sym) *symbol;
		if (find_any_symbol_by_address(loader, binary, addr, symbol_types, &symbols, &symbol) != NULL) {
			return symbol_name(symbols, symbol);
		}
	}
	return NULL;
}

static void handle_mprotect(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// block creating executable stacks
	int third_arg = sysv_argument_abi_register_indexes[2];
	if (!register_is_exactly_known(&state->registers[third_arg])) {
		if (caller != NULL) {
			struct loaded_binary *binary = binary_for_address(&analysis->loader, caller->entry);
			const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, caller->entry, NORMAL_SYMBOL);
			if (name != NULL && fs_strcmp(name, "pthread_create") == 0) {
				set_register(&state->registers[third_arg], PROT_READ | PROT_WRITE);
			}
		}
	}
}

static void handle_mmap(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// block creating executable stacks
	int third_arg = sysv_argument_abi_register_indexes[2];
	int fourth_arg = sysv_argument_abi_register_indexes[3];
	if (!register_is_exactly_known(&state->registers[third_arg])) {
		if (register_is_exactly_known(&state->registers[fourth_arg]) && (state->registers[fourth_arg].value & MAP_STACK) == MAP_STACK) {
			if (caller != NULL) {
				struct loaded_binary *binary = binary_for_address(&analysis->loader, caller->entry);
				const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, caller->entry, NORMAL_SYMBOL);
				if (name != NULL && fs_strcmp(name, "pthread_create") == 0) {
					set_register(&state->registers[third_arg], PROT_READ | PROT_WRITE);
				}
			}
		}
	}
}

static void handle_IO_file_fopen(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// record fopen mode arguments
	size_t i = analysis->search.fopen_mode_count;
	size_t count = i + 1;
	analysis->search.fopen_modes = realloc(analysis->search.fopen_modes, sizeof(*analysis->search.fopen_modes) * count);
	analysis->search.fopen_mode_count = count;
	int mode_arg = sysv_argument_abi_register_indexes[2];
	analysis->search.fopen_modes[i] = state->registers[mode_arg];
}

static void handle_IO_file_open(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	// parse previously recorded fopen mode
	size_t count = analysis->search.fopen_mode_count;
	if (count == 0) {
		return;
	}
	if (!register_is_exactly_known(&analysis->search.fopen_modes[count-1])) {
		return;
	}
	const char *mode_str = (const char *)analysis->search.fopen_modes[count-1].value;
	struct loaded_binary *binary;
	int prot = protection_for_address(&analysis->loader, mode_str, &binary, NULL);
	if ((prot & (PROT_READ | PROT_WRITE)) != PROT_READ) {
		return;
	}
	int mode;
	int flags = 0;
	switch (mode_str[0]) {
		case 'r':
			mode = O_RDONLY;
			break;
		case 'w':
			mode = O_WRONLY;
			break;
		case 'a':
			mode = O_WRONLY;
			flags = O_CREAT|O_APPEND;
			break;
		default:
			return;
	}
	for (int i = 1; i < 7; ++i) {
		switch (mode_str[i]) {
			case '\0':
				break;
			case '+':
				mode = O_RDWR;
				continue;
			case 'x':
				flags |= O_EXCL;
				continue;
			case 'b':
				continue;
			case 'm':
				continue;
			case 'c':
				continue;
			case 'e':
				flags |= O_CLOEXEC;
				continue;
			default:
				continue;
		}
		break;
	}
	int mode_arg = sysv_argument_abi_register_indexes[2];
	set_register(&state->registers[mode_arg], mode|flags);
}

static void handle_fopen(struct program_state *analysis, __attribute__((unused)) ins_ptr ins, struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
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
	if (*fs_strchr(mode, '+')) flags = O_RDWR;
	else if (*mode == 'r') flags = O_RDONLY;
	else flags = O_WRONLY;
	if (*fs_strchr(mode, 'x')) flags |= O_EXCL;
	if (*fs_strchr(mode, 'e')) flags |= O_CLOEXEC;
	if (*mode != 'r') flags |= O_CREAT;
	if (*mode == 'w') flags |= O_TRUNC;
	if (*mode == 'a') flags |= O_APPEND;
	return flags;
}

static void handle_libseccomp_syscall(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects required_effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, void *syscall_function)
{
	LOG("encountered libseccomp syscall function call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	// if first syscall argument is unbounded, assume it's __NR_seccomp
	struct analysis_frame self = { .address = ins, .description = "libseccomp syscall", .next = caller, .current_state = *state, .entry = ins, .entry_state = state, .token = { 0 }, .is_entry = true };
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		self.current_state.sources[i] = (register_mask)1 << i;
	}
	int first_arg = sysv_argument_abi_register_indexes[0];
	if (!register_is_partially_known_32bit(&self.current_state.registers[first_arg])) {
		set_register(&self.current_state.registers[first_arg], __NR_seccomp);
		clear_match(&analysis->loader, &self.current_state, first_arg, ins);
		self.current_state.sources[first_arg] = 0;
	}
	function_effects effects = analyze_function(analysis, required_effects, &self.current_state, syscall_function, &self);
	set_effects(&analysis->search, ins, token, (effects & ~EFFECT_PROCESSING) | EFFECT_PROCESSED | EFFECT_ENTER_CALLS);
}

static void handle_libcap_syscall(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects required_effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, void *syscall_function)
{
	LOG("encountered libcap syscall function call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	// if first syscall argument is unbounded, assume it's __NR_seccomp
	struct registers new_state = *state;
	function_effects effects = 0;
	if (register_is_partially_known_32bit(&new_state.registers[sysv_argument_abi_register_indexes[0]])) {
		effects = analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
	} else {
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], __NR_capset);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], __NR_prctl);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], __NR_setuid);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], __NR_setgid);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], __NR_setgroups);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
		set_register(&new_state.registers[sysv_argument_abi_register_indexes[0]], __NR_chroot);
		effects |= analyze_function(analysis, required_effects, &new_state, syscall_function, caller);
	}
	set_effects(&analysis->search, ins, token, (effects & ~EFFECT_PROCESSING) | EFFECT_PROCESSED | EFFECT_ENTER_CALLS);
}

static void handle_ruby_syscall(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *syscall_function)
{
	LOG("encountered ruby syscall function call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	if (!register_is_partially_known_32bit(&state->registers[sysv_argument_abi_register_indexes[0]])) {
		add_blocked_symbol(&analysis->known_symbols, "rb_f_syscall", 0, false)->value = caller->address;
		set_effects(&analysis->search, ins, token, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS);
	}
}

static void handle_golang_unix_sched_affinity(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("encountered unix.schedAffinity call", temp_str(copy_call_trace_description(&analysis->loader, caller)));
	// skip affinity
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS);
	LOG("skipping unix.schedAffinity");
}

static void handle_openssl_dso_load(struct program_state *analysis, ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, struct effect_token *token, __attribute__((unused)) void *data)
{
	set_effects(&analysis->search, ins, token, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_EXITS | EFFECT_ENTER_CALLS);
	if (fs_access("/usr/lib/"ARCH_NAME"-linux-gnu/ossl-modules", R_OK) == 0) {
		register_dlopen(analysis, "/usr/lib/"ARCH_NAME"-linux-gnu/ossl-modules", caller, false, false, true);
	}
}

__attribute__((nonnull(1, 2, 3, 4)))
static void intercept_jump_slot(struct program_state *analysis, struct loaded_binary *binary, const char *slot_name, instruction_reached_callback callback)
{
	const ElfW(Dyn) *dynamic = binary->info.dynamic;
	size_t dynamic_size = binary->info.dynamic_size;
	uintptr_t relaent = 0;
	uintptr_t jmprel = 0;
	uintptr_t pltrelsz = 0;
	for (size_t i = 0; i < dynamic_size; i++) {
		switch (dynamic[i].d_tag) {
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
	if (relaent && jmprel && pltrelsz) {
		uintptr_t rela_base = (uintptr_t)apply_base_address(&binary->info, jmprel);
		for (uintptr_t rel_off = 0; rel_off < pltrelsz; rel_off += relaent) {
			const ElfW(Rela) *rel = (const ElfW(Rela) *)(rela_base + rel_off);
			uintptr_t info = rel->r_info;
			if (ELF64_R_TYPE(info) == R_X86_64_JUMP_SLOT) {
				Elf64_Word symbol_index = ELF64_R_SYM(info);
				const ElfW(Sym) *symbol = (const ElfW(Sym) *)(binary->symbols.symbols + symbol_index * binary->symbols.symbol_stride);
				const char *textual_name = symbol_name(&binary->symbols, symbol);
				if (fs_strcmp(textual_name, slot_name) == 0) {
					uintptr_t offset = rel->r_offset;
					uintptr_t *target = (uintptr_t *)apply_base_address(&binary->info, offset);
					uintptr_t old_value = *target;
					struct loader_stub *stub = malloc(sizeof(struct loader_stub));
					stub->next = analysis->loader.stubs;
					analysis->loader.stubs = stub;
					*target = (uintptr_t)stub;
					find_and_add_callback(analysis, (ins_ptr)stub, 0, 0, 0, EFFECT_NONE, callback, (void *)old_value);
					break;
				}
			}
		}
	}
}

static void blocked_function_called(__attribute__((unused)) struct program_state *analysis, __attribute__((unused)) ins_ptr ins, __attribute__((unused)) struct registers *state, __attribute__((unused)) function_effects effects, __attribute__((unused)) const struct analysis_frame *caller, __attribute__((unused)) struct effect_token *token, __attribute__((unused)) void *data)
{
	LOG("blocked function called", (const char *)data);
	LOG("stack", temp_str(copy_call_trace_description(&analysis->loader, caller)));
}

__attribute__((nonnull(1, 2, 3)))
static void force_protection_for_symbol(const struct loader_context *loader, struct loaded_binary *binary, const char *symbol_name, int symbol_types, int prot)
{
	const ElfW(Sym) *symbol;
	void *address = resolve_binary_loaded_symbol(loader, binary, symbol_name, NULL, symbol_types, &symbol);
	if (address != NULL) {
		for (int i = 0; i < OVERRIDE_ACCESS_SLOT_COUNT; i++) {
			if (binary->override_access_ranges[i].address == 0) {
				binary->override_access_ranges[i].address = address;
				binary->override_access_ranges[i].size = symbol->st_size;
				binary->override_access_permissions[i] = prot;
				return;
			}
		}
		DIE("too many override access symbols in", binary->path);
	}
}

static void ignored_load_callback(struct program_state *analysis, ins_ptr address, __attribute__((unused)) const struct analysis_frame *frame, void *callback_data)
{
	struct loaded_binary *binary = binary_for_address(&analysis->loader, address);
	if (binary != NULL) {
		LOG("skipping function pointers at", temp_str(copy_address_description(&analysis->loader, address)));
		LOG("and size", (intptr_t)callback_data);
		LOG("referenced from", temp_str(copy_address_description(&analysis->loader, frame->address)));
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

__attribute__((always_inline))
__attribute__((nonnull(1, 2, 3, 4)))
static inline function_effects analyze_function_for_ignored_load(struct program_state *analysis, const struct registers *entry_state, ins_ptr ins, const struct analysis_frame *caller, size_t ignored_load_size)
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

__attribute__((nonnull(1, 2)))
static void update_known_symbols(struct program_state *analysis, struct loaded_binary *new_binary)
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
			find_and_add_callback(analysis, value, 0, 0, 0, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_EXITS | EFFECT_ENTER_CALLS, blocked_function_called, (void *)blocked_symbols[i].name);
		}
	}
	update_known_function(analysis, new_binary, "Perl_die_unwind", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_STICKY_EXITS);
	update_known_function(analysis, new_binary, "__cxa_throw", NORMAL_SYMBOL | LINKER_SYMBOL, EFFECT_STICKY_EXITS);
	ins_ptr dlopen_mode = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__libc_dlopen_mode", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
	if (dlopen_mode) {
		register_mask arg0 = (register_mask)1 << sysv_argument_abi_register_indexes[0];
		find_and_add_callback(analysis, dlopen_mode, arg0, arg0, arg0, EFFECT_NONE, handle_dlopen, NULL);
	}
	ins_ptr dlopen = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "dlopen", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
	if (dlopen != NULL && dlopen != dlopen_mode) {
		register_mask arg0 = (register_mask)1 << sysv_argument_abi_register_indexes[0];
		find_and_add_callback(analysis, dlopen, arg0, arg0, arg0, EFFECT_NONE, handle_dlopen, NULL);
	}
	if (new_binary->special_binary_flags & BINARY_IS_LIBC) {
		// detect gconv and load libraries upfront via LD_PRELOAD
		ins_ptr gconv_open = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__gconv_open", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (gconv_open) {
			// search for __gconv_find_shlib so that handle_gconv_find_shlib can be attached to it
			struct registers registers = empty_registers;
			struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "__gconv_open", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
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
		// update_known_function(analysis, new_binary, &known_symbols->gconv_find_shlib, "__gconv_find_shlib", NULL, NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL, EFFECT_RETURNS | EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
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
		if (analysis->ld_profile != NULL) {
			ins_ptr dl_start_profile = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "_dl_start_profile", NULL, INTERNAL_COMMON_SYMBOL, NULL);
			// search for __gconv_find_shlib so that handle_gconv_find_shlib can be attached to it
			if (dl_start_profile != NULL) {
				struct registers registers = empty_registers;
				struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "_dl_start_profile", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
				analyze_function(analysis, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, dl_start_profile, &new_caller);
			}
		}
		ins_ptr error = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "error", NULL, NORMAL_SYMBOL, NULL);
		if (error) {
			LOG("found error", temp_str(copy_address_description(&analysis->loader, error)));
			struct effect_token token;
			struct registers empty = empty_registers;
			empty.registers[sysv_argument_abi_register_indexes[0]].value = 1;
			*get_or_populate_effects(analysis, error, &empty, EFFECT_NONE, &token) |= EFFECT_EXITS | EFFECT_STICKY_EXITS | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS;
			add_relevant_registers(&analysis->search, &analysis->loader, error, &empty, 0, (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], &token);
		}
		ins_ptr error_at_line = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "error_at_line", NULL, NORMAL_SYMBOL, NULL);
		if (error_at_line) {
			LOG("found error_at_line", temp_str(copy_address_description(&analysis->loader, error_at_line)));
			struct effect_token token;
			struct registers empty = empty_registers;
			empty.registers[sysv_argument_abi_register_indexes[0]].value = 1;
			*get_or_populate_effects(analysis, error, &empty, EFFECT_NONE, &token) |= EFFECT_EXITS | EFFECT_STICKY_EXITS | EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS;
			add_relevant_registers(&analysis->search, &analysis->loader, error_at_line, &empty, 0, (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], &token);
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
		// temporary workaround for musl
		ins_ptr do_setxid = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "do_setxid", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (do_setxid != NULL) {
			struct registers registers = empty_registers;
			struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "do_setxid", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
			analysis->loader.searching_setxid_sighandler = true;
			analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, do_setxid, &new_caller);
			analysis->loader.searching_setxid_sighandler = false;
		}
		ins_ptr setxid = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "__setxid", NULL, INTERNAL_COMMON_SYMBOL, NULL);
		if (setxid != NULL) {
			find_and_add_callback(analysis, setxid, (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], (register_mask)1 << sysv_argument_abi_register_indexes[0], EFFECT_NONE, handle_musl_setxid, NULL);
		}
		update_known_function(analysis, new_binary, "cancel_handler", INTERNAL_COMMON_SYMBOL, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_RETURNS | EFFECT_ENTRY_POINT | EFFECT_ENTER_CALLS);
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
		struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "sighandler_setxid", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
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
			register_mask stack_4 = (register_mask)1 << REGISTER_STACK_4;
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
			struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "DSO_METHOD_openssl", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
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

__attribute__((nonnull(1)))
static struct loaded_binary *binary_for_address(const struct loader_context *context, const void *addr);

__attribute__((nonnull(1, 2)))
static char *copy_call_trace_description(const struct loader_context *context, const struct analysis_frame *head)
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
	struct {
		size_t length;
		char *description;
	}* list = malloc(count * sizeof(*list));
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
			memcpy(&description[length+1], additional_description, additional_length + 1);
			length = new_length;
		}
#endif
		if (node->description) {
			size_t additional_length = fs_strlen(node->description);
			size_t new_length = length + 2 + additional_length + 1;
			description = realloc(description, new_length + 1);
			description[length] = ' ';
			description[length+1] = '(';
			memcpy(&description[length+2], node->description, additional_length + 1);
			description[new_length-1] = ')';
			description[new_length] = '\0';
			length = new_length;
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

__attribute__((nonnull(1)))
char *copy_syscall_description(const struct loader_context *context, uintptr_t nr, struct registers registers, bool include_symbol)
{
	return copy_call_description(context, name_for_syscall(nr), registers, syscall_argument_abi_register_indexes, info_for_syscall(nr), include_symbol);
}

__attribute__((unused))
__attribute__((nonnull(1, 2)))
static char *copy_function_call_description(const struct loader_context *context, ins_ptr target, struct registers registers)
{
	char *name = copy_address_description(context, target);
	struct loaded_binary *binary = binary_for_address(context, target);
	int argc;
	const int *register_indexes;
	if (binary_has_flags(binary, BINARY_IS_GOLANG)) {
		size_t name_len = fs_strlen(name);
		if (name[name_len-1] == ')' && name[name_len-2] == '0' && name[name_len-3] == 'i' && name[name_len-4] == 'b' && name[name_len-5] == 'a' && name[name_len-6] == '.') {
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
		.arguments = { 0 },
	};
	char *result = copy_call_description(context, name, registers, register_indexes, info, true);
	free(name);
	return result;
}

__attribute__((nonnull(1, 2, 3)))
static void vary_effects_by_registers(struct searched_instructions *search, const struct loader_context *loader, const struct analysis_frame *self, register_mask relevant_registers, register_mask preserved_registers, register_mask preserved_and_kept_registers, function_effects required_effects)
{
	// mark ancestor functions as varying by registers until we find one that no longer passes data into the call site
	for (const struct analysis_frame *ancestor = self;;) {
		register_mask new_relevant_registers = 0;
		register_mask new_preserved_registers = 0;
		register_mask new_preserved_and_kept_registers = 0;
		for_each_bit(relevant_registers & ALL_REGISTERS, bit, i) {
			if (register_is_partially_known(&ancestor->current_state.registers[i])) {
				new_relevant_registers |= ancestor->current_state.sources[i];
			}
		}
		new_relevant_registers &= ~((register_mask)1 << REGISTER_SP);
		register_mask discarded_registers = (register_mask)1 << REGISTER_SP;
		for_each_bit(new_relevant_registers & ALL_REGISTERS, bit, i) {
			if (!register_is_partially_known(&ancestor->entry_state->registers[i])) {
				LOG("register is not known, skipping requiring", name_for_register(i));
				new_relevant_registers &= ~bit;
				discarded_registers |= bit;
			}
		}
		if (new_relevant_registers == 0) {
			if (SHOULD_LOG) {
				ERROR("first entry point without varying arguments", temp_str(copy_address_description(loader, ancestor->entry)));
				for_each_bit(relevant_registers, bit, i) {
					ERROR("relevant register", name_for_register(i));
				}
			}
			break;
		}
		for_each_bit(preserved_registers, bit, i) {
			new_preserved_registers |= ancestor->current_state.sources[i];
		}
		new_preserved_registers &= ~discarded_registers;
		for_each_bit(preserved_and_kept_registers, bit, i) {
			new_preserved_and_kept_registers |= ancestor->current_state.sources[i];
		}
		new_preserved_and_kept_registers &= ~((register_mask)1 << REGISTER_SP);
		if (SHOULD_LOG) {
			ERROR("marking", temp_str(copy_address_description(loader, ancestor->entry)));
			for_each_bit(new_relevant_registers, bit, i) {
				if (new_preserved_and_kept_registers & bit) {
					ERROR("as preserving and keeping", name_for_register(i));
				} else if (new_preserved_registers & bit) {
					ERROR("as preserving", name_for_register(i));
				} else {
					ERROR("as requiring", name_for_register(i));
				}
				dump_register(loader, ancestor->entry_state->registers[i]);
			}
			ERROR("from ins at", temp_str(copy_address_description(loader, ancestor->address)));
		}
		struct previous_register_masks existing = add_relevant_registers(search, loader, ancestor->entry, ancestor->entry_state, required_effects, new_relevant_registers, new_preserved_registers, new_preserved_and_kept_registers, (struct effect_token *)&ancestor->token);
		if ((existing.relevant_registers & new_relevant_registers) == new_relevant_registers && (existing.preserved_and_kept_registers & new_preserved_and_kept_registers) == new_preserved_and_kept_registers) {
			if (SHOULD_LOG) {
				ERROR("relevant and preserved registers have already been added");
			}
			break;
		}
		ancestor = ancestor->next;
		if (ancestor == NULL) {
			if (SHOULD_LOG) {
				ERROR("all ancestors had arguments");
			}
			break;
		}
		relevant_registers = new_relevant_registers;
		preserved_registers = new_preserved_and_kept_registers;
		preserved_and_kept_registers = new_preserved_and_kept_registers;
	}
}

__attribute__((nonnull(1)))
static inline void add_syscall(struct recorded_syscalls *syscalls, struct recorded_syscall syscall)
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

void record_syscall(struct program_state *analysis, uintptr_t nr, struct analysis_frame self, function_effects effects)
{
	struct recorded_syscalls *syscalls = &analysis->syscalls;
	uint8_t config = nr < SYSCALL_COUNT ? syscalls->config[nr] : 0;
	struct syscall_info info = info_for_syscall(nr);
	for (int i = 0; i < (info.attributes & SYSCALL_ARGC_MASK); i++) {
		if (i != 0 && (info.arguments[i] & SYSCALL_ARG_TYPE_MASK) == SYSCALL_ARG_IS_MODEFLAGS) {
			// argument is modeflags, previous is mode. check if mode is used and if not, convert to any
			const struct register_state *arg = &self.current_state.registers[syscall_argument_abi_register_indexes[i-1]];
			if (register_is_exactly_known(arg)) {
				if ((arg->value & O_TMPFILE) == O_TMPFILE) {
					continue;
				}
				if ((arg->value & O_CREAT) == O_CREAT) {
					continue;
				}
			}
			clear_register(&self.current_state.registers[syscall_argument_abi_register_indexes[i]]);
		}
	}
	// debug logging
	LOG("syscall is", temp_str(copy_call_description(&analysis->loader, name_for_syscall(nr), self.current_state, syscall_argument_abi_register_indexes, info, true)));
	bool should_record = ((config & SYSCALL_CONFIG_BLOCK) == 0) && (((effects & EFFECT_AFTER_STARTUP) == EFFECT_AFTER_STARTUP) || nr == __NR_exit || nr == __NR_exit_group);
	if (should_record) {
#if RECORDED_SYSCALL_INCLUDES_FUNCTION_ENTRY
		const struct analysis_frame *function = &self;
		while (!function->is_entry && function->next != NULL) {
			function = function->next;
		}
#endif
		LOG("recorded syscall");
		add_syscall(syscalls, (struct recorded_syscall){
			.nr = nr,
			.ins = self.address,
			.entry = self.entry,
#if RECORDED_SYSCALL_INCLUDES_FUNCTION_ENTRY
			.function_entry = function->entry,
#endif
			.registers = self.current_state,
		});
		if (info.attributes & SYSCALL_IS_RESTARTABLE) {
			struct registers restart = self.current_state;
			set_register(&restart.registers[REGISTER_SYSCALL_NR], __NR_restart_syscall);
			add_syscall(syscalls, (struct recorded_syscall){
				.nr = __NR_restart_syscall,
				.ins = self.address,
				.entry = self.entry,
#if RECORDED_SYSCALL_INCLUDES_FUNCTION_ENTRY
				.function_entry = function->entry,
#endif
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
			ERROR("found syscall", temp_str(copy_syscall_description(&analysis->loader, nr, self.current_state, true)));
		} else {
			ERROR("found startup syscall", temp_str(copy_syscall_description(&analysis->loader, nr, self.current_state, true)));
		}
		ERROR("from entry", temp_str(copy_address_description(&analysis->loader, self.entry)));
		if (SHOULD_LOG) {
			for (int i = 0; i < (info.attributes & SYSCALL_ARGC_MASK); i++) {
				int reg = syscall_argument_abi_register_indexes[i];
				for_each_bit(self.current_state.sources[reg], bit, j) {
					ERROR("argument", i);
					ERROR("using block input from", name_for_register(j));
				}
			}
		}
		ERROR("at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
	}
	// figure out which, if any, arguments to the function were used in the syscall
	register_mask relevant_registers = syscall_argument_abi_used_registers_for_argc[info.attributes & SYSCALL_ARGC_MASK];
	// determine which registers to preserve
	register_mask preserved_registers = syscall_argument_abi_used_registers_for_argc[0];
	for (int i = 0; i < (info.attributes & SYSCALL_ARGC_MASK); i++) {
		if (info.arguments[i] & SYSCALL_ARG_IS_PRESERVED) {
			preserved_registers |= (register_mask)1 << syscall_argument_abi_register_indexes[i];
		}
	}
	// vary effects by following control flow that produced any used values
	vary_effects_by_registers(&analysis->search, &analysis->loader, &self, relevant_registers, preserved_registers, preserved_registers, 0);
}

#ifdef STATS
intptr_t analyzed_instruction_count;
#endif

#if defined(__x86_64__)
static inline struct register_state_and_source address_for_indirect(struct x86_instruction decoded, x86_mod_rm_t modrm, struct registers *state, const uint8_t *data, const struct loader_context *loader, ins_ptr ins, bool *out_base_is_null) {
	struct register_state_and_source result;
	result.source = 0;
	clear_register(&result.state);
	int rm = x86_read_rm(modrm, decoded.prefixes);
	switch (rm) {
		case REGISTER_SP:
		case REGISTER_R12: {
			// decode SIB
			x86_sib_t sib = x86_read_sib(data++);
			int base_reg = x86_read_base(sib, decoded.prefixes);
			struct register_state base;
			if (modrm.mod == 0 && (base_reg == REGISTER_RBP || base_reg == REGISTER_R13)) {
				LOG("processing SIB without base");
				base.value = 0;
				base.max = 0;
				// force disp32
				modrm.mod = 2;
			} else {
				LOG("processing SIB from base", name_for_register(base_reg));
				base = state->registers[base_reg];
				dump_register(loader, base);
				result.source |= state->sources[base_reg];
			}
			if (out_base_is_null) {
				*out_base_is_null = register_is_exactly_known(&base) && base.value == 0;
			}
			int index_reg = x86_read_index(sib, decoded.prefixes);
			if (index_reg == REGISTER_SP) {
				LOG("without index");
				result.state = base;
				break;
			}
			LOG("and index", name_for_register(index_reg));
			result.source |= state->sources[index_reg];
			struct register_state index = state->registers[index_reg];
			dump_register(loader, index);
			LOG("with scale", 1 << sib.scale);
			struct register_state scaled;
			scaled.value = index.value << sib.scale;
			scaled.max = index.max << sib.scale;
			if (((scaled.value >> sib.scale) == index.value) && ((scaled.max >> sib.scale) == index.max)) {
				struct register_state proposed;
				proposed.value = base.value + index.value;
				proposed.max = base.max + index.max;
				if (scaled.value >= base.value && scaled.max >= base.max) {
					result.state = proposed;
					break;
				}
			}
			result.source = 0;
			LOG("overflow when calculating SIB");
			break;
		}
		case REGISTER_RBP:
		case REGISTER_R13:
			if (modrm.mod == 0) {
				// decode RIP+disp32
				set_register(&result.state, (uintptr_t)data + 4 + *(const x86_int32 *)data);
				LOG("decoded rip-relative");
				if (out_base_is_null) {
					*out_base_is_null = false;
				}
				break;
			}
			// fallthrough
		default:
			// use register
			result.state = state->registers[rm];
			result.source = state->sources[rm];
			LOG("taking address in register", name_for_register(rm));
			dump_register(loader, result.state);
			if (out_base_is_null) {
				*out_base_is_null = register_is_exactly_known(&result.state) && result.state.value == 0;
			}
			break;
	}
	switch (modrm.mod) {
		case 1:
			if (register_is_partially_known(&result.state)) {
				// add 8-bit displacement
				int8_t disp = *(const int8_t *)data;
				result.state.value += disp;
				result.state.max += disp;
				LOG("adding 8-bit displacement", (intptr_t)disp);
			}
			break;
		case 2:
			if (register_is_partially_known(&result.state)) {
				// add 32-bit displacement
				int32_t disp = *(const x86_int32 *)data;
				result.state.value += disp;
				result.state.max += disp;
				LOG("adding 32-bit displacement", (intptr_t)disp);
			}
			break;
		case 3:
			DIE("modrm is not indirect at", temp_str(copy_address_description(loader, ins)));
			break;
	}
	canonicalize_register(&result.state);
	return result;
}

struct decoded_rm decode_rm(const uint8_t **ins_modrm, struct x86_ins_prefixes prefixes, uint8_t imm_size) {
	x86_mod_rm_t modrm = x86_read_modrm(*ins_modrm);
	*ins_modrm += sizeof(x86_mod_rm_t);
	struct decoded_rm result = (struct decoded_rm){ 0 };
	if (prefixes.has_segment_override) {
		result.rm = REGISTER_STACK_4;
		result.base = 0;
		result.index = 0;
		result.scale = 0;
		result.addr = 0;
	} else {
		switch ((result.rm = x86_read_rm(modrm, prefixes))) {
			case REGISTER_SP:
			case REGISTER_R12: {
				// decode SIB
				x86_sib_t sib = x86_read_sib(*ins_modrm);
				*ins_modrm += sizeof(x86_sib_t);
				result.base = x86_read_base(sib, prefixes);
				result.index = x86_read_index(sib, prefixes);
				result.scale = sib.scale;
				result.addr = 0;
				result.rm = REGISTER_STACK_0;
				break;
			}
			case REGISTER_RBP:
			case REGISTER_R13:
				if (modrm.mod == 0) {
					// decode RIP+disp32
					result.base = 0;
					result.index = 0;
					result.scale = 0;
					result.addr = (uintptr_t)*ins_modrm + sizeof(int32_t) + *(const x86_int32 *)*ins_modrm + imm_size;
					result.rm = REGISTER_MEM;
					*ins_modrm += sizeof(int32_t);
					break;
				}
				// fallthrough
			default:
				result.base = 0;
				result.index = 0;
				result.scale = 0;
				result.addr = 0;
				break;
		}
	}
	switch (modrm.mod) {
		case 1: {
			int8_t disp = *(const int8_t *)*ins_modrm;
			result.addr += disp;
			*ins_modrm += sizeof(int8_t);
			break;
		}
		case 2: {
			int32_t disp = *(const x86_int32 *)*ins_modrm;
			result.addr += disp;
			*ins_modrm += sizeof(int32_t);
			break;
		}
	}
	return result;
}

static uintptr_t read_imm(struct x86_ins_prefixes prefixes, ins_ptr imm)
{
	if (prefixes.has_w) { // imm32 sign-extended
		return *(const x86_int32 *)imm;
	} else if (prefixes.has_operand_size_override) { // imm16
		return *(const x86_uint16 *)imm;
	} else { // imm32
		return *(const x86_uint32 *)imm;
	}
}

#endif

enum {
	OPERATION_SIZE_DEFAULT = 0,
	OPERATION_SIZE_8BIT = sizeof(uint8_t),
	OPERATION_SIZE_16BIT = sizeof(uint16_t),
	OPERATION_SIZE_32BIT = sizeof(uint32_t),
	OPERATION_SIZE_64BIT = sizeof(uint64_t),
};

static void record_stack_address_taken(__attribute__((unused)) const struct loader_context *loader, __attribute__((unused)) ins_ptr addr, struct registers *regs)
{
	LOG("taking address of stack", temp_str(copy_address_description(loader, addr)));
#if RECORD_WHERE_STACK_ADDRESS_TAKEN
	if (regs->stack_address_taken == NULL) {
		regs->stack_address_taken = addr;
	}
#else
	regs->stack_address_taken = true;
#endif
}

#if defined(__x86_64__)

enum {
	READ_RM_REPLACE_MEM = 0,
	READ_RM_KEEP_MEM = 1,
};

static inline int read_rm_ref(const struct loader_context *loader, struct x86_ins_prefixes prefixes, ins_ptr *ins_modrm, size_t imm_size, struct registers *regs, int operation_size, int flags, struct register_state *out_state)
{
	if (UNLIKELY(prefixes.has_segment_override) && (flags & READ_RM_KEEP_MEM)) {
	return_invalid:
		if (out_state != NULL) {
			clear_register(out_state);
			switch (operation_size) {
				case OPERATION_SIZE_DEFAULT:
					truncate_to_size_prefixes(out_state, prefixes);
					break;
				case OPERATION_SIZE_8BIT:
					truncate_to_8bit(out_state);
					break;
				case OPERATION_SIZE_16BIT:
					truncate_to_16bit(out_state);
					break;
				case OPERATION_SIZE_32BIT:
					truncate_to_32bit(out_state);
					break;
				case OPERATION_SIZE_64BIT:
					break;
			}
		}
		return REGISTER_INVALID;
	}
	x86_mod_rm_t modrm = x86_read_modrm(*ins_modrm);
	int result;
	if (x86_modrm_is_direct(modrm)) {
		*ins_modrm += sizeof(x86_mod_rm_t);
		result = x86_read_rm(modrm, prefixes);
		goto return_result;
	}
	struct decoded_rm decoded = decode_rm(ins_modrm, prefixes, imm_size);
	if (decoded.rm == REGISTER_STACK_0 && decoded.base == REGISTER_SP && decoded.index == REGISTER_SP) {
		switch (decoded.addr) {
#define PER_STACK_REGISTER_IMPL(offset) case offset: \
			LOG("stack slot of", name_for_register(REGISTER_STACK_##offset)); \
			result = REGISTER_STACK_##offset; \
			goto return_result;
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
		}
		LOG("stack offset of", (intptr_t)decoded.addr);
	}
	if (decoded_rm_equal(&decoded, &regs->mem_rm)) {
		result = REGISTER_MEM;
		goto return_result;
	}
	register_mask sources = 0;
	uintptr_t addr = decoded.addr;
	bool valid = false;
	switch (decoded.rm) {
		case REGISTER_STACK_0:
			if (decoded.index == REGISTER_SP) {
				if (register_is_exactly_known(&regs->registers[decoded.base])) {
					addr += regs->registers[decoded.base].value;
					sources = ((register_mask)1 << decoded.base);
					valid = true;
				}
			} else {
				if (decoded.base == REGISTER_SP) {
					record_stack_address_taken(loader, *ins_modrm, regs);
				}
				if (register_is_exactly_known(&regs->registers[decoded.base]) && register_is_exactly_known(&regs->registers[decoded.index])) {
					addr += regs->registers[decoded.base].value + (regs->registers[decoded.index].value << decoded.scale);
					sources = ((register_mask)1 << decoded.base) | ((register_mask)1 << decoded.index);
					valid = true;
				}
			}
			break;
		case REGISTER_MEM:
			valid = true;
			break;
		default:
			if (decoded.rm == REGISTER_SP) {
				record_stack_address_taken(loader, *ins_modrm, regs);
			}
			if (register_is_exactly_known(&regs->registers[decoded.rm])) {
				sources = (register_mask)1 << decoded.rm;
				addr += regs->registers[decoded.rm].value;
				valid = true;
			}
			break;
	}
	if (valid) {
		struct loaded_binary *binary;
		int prot = protection_for_address(loader, (const void *)addr, &binary, NULL);
		if (prot & PROT_READ) {
			uintptr_t value;
			if (operation_size == OPERATION_SIZE_DEFAULT) {
				if (prefixes.has_w) {
					operation_size = OPERATION_SIZE_64BIT;
				} else if (prefixes.has_operand_size_override) {
					operation_size = OPERATION_SIZE_16BIT;
				} else {
					operation_size = OPERATION_SIZE_32BIT;
				}
			}
			switch (operation_size) {
				case OPERATION_SIZE_8BIT:
					value = *(ins_ptr)addr;
					LOG("read 8 bit", value);
					break;
				case OPERATION_SIZE_16BIT:
					value = *(const x86_uint16 *)addr;
					LOG("read 16 bit", value);
					break;
				case OPERATION_SIZE_32BIT:
					value = *(const x86_uint32 *)addr;
					LOG("read 32 bit", value);
					break;
				case OPERATION_SIZE_64BIT:
					value = *(const x86_uint64 *)addr;
					LOG("read 64 bit", value);
					break;
				default:
					__builtin_unreachable();
					break;
			}
			if ((prot & PROT_WRITE) == 0 || (value == SYS_fcntl && (binary->special_binary_flags & BINARY_IS_GOLANG))) { // workaround for golang's syscall.fcntl64Syscall
				if (flags & READ_RM_KEEP_MEM && !register_is_partially_known(&regs->registers[REGISTER_MEM])) {
					if (out_state != NULL) {
						set_register(out_state, value);
					}
					LOG("loaded memory constant", temp_str(copy_register_state_description(loader, (struct register_state){ .value = value, .max = value })));
					LOG("from", temp_str(copy_address_description(loader, (const void *)addr)));
					return REGISTER_INVALID;
				}
				LOG("clearing old mem r/m", temp_str(copy_decoded_rm_description(loader, regs->mem_rm)));
				LOG("replacing with new mem r/m", temp_str(copy_decoded_rm_description(loader, decoded)));
				regs->mem_rm = decoded;
				result = REGISTER_MEM;
				set_register(&regs->registers[REGISTER_MEM], value);
				regs->sources[REGISTER_MEM] = sources;
				LOG("loaded memory constant", temp_str(copy_register_state_description(loader, regs->registers[REGISTER_MEM])));
				LOG("from", temp_str(copy_address_description(loader, (const void *)addr)));
				clear_match(loader, regs, REGISTER_MEM, *ins_modrm);
				goto return_result;
			}
			LOG("region is writable, assuming it might not be constant", value);
		}
	}
	if (flags & READ_RM_KEEP_MEM && !register_is_partially_known(&regs->registers[REGISTER_MEM])) {
		goto return_invalid;
	}
	LOG("clearing old mem r/m", temp_str(copy_decoded_rm_description(loader, regs->mem_rm)));
	LOG("replacing with new mem r/m", temp_str(copy_decoded_rm_description(loader, decoded)));
	regs->mem_rm = decoded;
	clear_match(loader, regs, REGISTER_MEM, *ins_modrm);
	result = REGISTER_MEM;
	clear_register(&regs->registers[REGISTER_MEM]);
	switch (operation_size) {
		case OPERATION_SIZE_DEFAULT:
			truncate_to_size_prefixes(&regs->registers[REGISTER_MEM], prefixes);
			break;
		case OPERATION_SIZE_8BIT:
			truncate_to_8bit(&regs->registers[REGISTER_MEM]);
			break;
		case OPERATION_SIZE_16BIT:
			truncate_to_16bit(&regs->registers[REGISTER_MEM]);
			break;
		case OPERATION_SIZE_32BIT:
			truncate_to_32bit(&regs->registers[REGISTER_MEM]);
			break;
		case OPERATION_SIZE_64BIT:
			break;
	}
	regs->sources[REGISTER_MEM] = 0;
	if (valid) {
		LOG("unknown memory value", temp_str(copy_register_state_description(loader, regs->registers[REGISTER_MEM])));
	} else {
		LOG("unknown memory address", temp_str(copy_register_state_description(loader, regs->registers[REGISTER_MEM])));
	}
return_result:
	if (out_state != NULL) {
		*out_state = regs->registers[result];
		switch (operation_size) {
			case OPERATION_SIZE_DEFAULT:
				truncate_to_size_prefixes(out_state, prefixes);
				break;
			case OPERATION_SIZE_8BIT:
				truncate_to_8bit(out_state);
				break;
			case OPERATION_SIZE_16BIT:
				truncate_to_16bit(out_state);
				break;
			case OPERATION_SIZE_32BIT:
				truncate_to_32bit(out_state);
				break;
			case OPERATION_SIZE_64BIT:
				break;
		}
	}
	return result;
}

__attribute__((always_inline))
static inline uintptr_t mask_for_size_prefixes(struct x86_ins_prefixes prefixes)
{
	return prefixes.has_w ? (uintptr_t)0xffffffffffffffff : (prefixes.has_operand_size_override ? (uintptr_t)0xffff : (uintptr_t)0xffffffff);
}

#endif

enum {
	NO_COMPARISON = 0,
	INVALID_COMPARISON = 1,
	SUPPORTED_COMPARISON = 2,
};

#if defined(__x86_64__)

__attribute__((always_inline))
static inline int decode_x86_comparisons(struct x86_instruction decoded, struct registers *state, struct loader_context *loader, struct x86_comparison *out_comparison)
{
	switch (*decoded.unprefixed) {
		case 0x0f: {
			if (decoded.unprefixed[1] == 0x38 && decoded.unprefixed[2] == 0x17) { // ptest
				return INVALID_COMPARISON;
			}
			break;
		}
		case 0x38: {
			// found cmp r/m8, r8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded.prefixes);
			if (register_is_legacy_8bit_high(decoded.prefixes, &reg)) {
				return INVALID_COMPARISON;
			}
			struct register_state comparator = state->registers[reg];
			truncate_to_8bit(&comparator);
			ins_ptr remaining = &decoded.unprefixed[1];
			int rm = read_rm_ref(loader, decoded.prefixes, &remaining, 0, state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
			if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
				return INVALID_COMPARISON;
			}
			*out_comparison = (struct x86_comparison){
				.target_register = rm,
				.value = comparator,
				.mask = 0xff,
				.mem_rm = state->mem_rm,
				.sources = state->sources[reg],
				.validity = COMPARISON_SUPPORTS_ANY,
			};
			return SUPPORTED_COMPARISON;
		}
		case 0x39: {
			// found cmp r/m, r
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded.prefixes);
			struct register_state comparator = state->registers[reg];
			truncate_to_size_prefixes(&comparator, decoded.prefixes);
			ins_ptr remaining = &decoded.unprefixed[1];
			int rm = read_rm_ref(loader, decoded.prefixes, &remaining, 0, state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
			uintptr_t mask = mask_for_size_prefixes(decoded.prefixes);
			*out_comparison = (struct x86_comparison){
				.target_register = rm,
				.value = comparator,
				.mask = mask,
				.mem_rm = state->mem_rm,
				.sources = state->sources[reg],
				.validity = COMPARISON_SUPPORTS_ANY,
			};
			return SUPPORTED_COMPARISON;
		}
		case 0x3a: {
			// found cmp r8, r/m8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			ins_ptr remaining = &decoded.unprefixed[1];
			int rm = read_rm_ref(loader, decoded.prefixes, &remaining, 0, state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
			if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
				return INVALID_COMPARISON;
			}
			struct register_state comparator = state->registers[rm];
			truncate_to_8bit(&comparator);
			int reg = x86_read_reg(modrm, decoded.prefixes);
			if (register_is_legacy_8bit_high(decoded.prefixes, &reg)) {
				return INVALID_COMPARISON;
			}
			*out_comparison = (struct x86_comparison){
				.target_register = reg,
				.value = comparator,
				.mask = 0xff,
				.mem_rm = state->mem_rm,
				.sources = state->sources[rm],
				.validity = COMPARISON_SUPPORTS_ANY,
			};
			return SUPPORTED_COMPARISON;
		}
		case 0x3b: {
			// found cmp r, r/m
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			ins_ptr remaining = &decoded.unprefixed[1];
			int rm = read_rm_ref(loader, decoded.prefixes, &remaining, 0, state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
			struct register_state comparator = state->registers[rm];
			truncate_to_size_prefixes(&comparator, decoded.prefixes);
			int reg = x86_read_reg(modrm, decoded.prefixes);
			uintptr_t mask = mask_for_size_prefixes(decoded.prefixes);
			*out_comparison = (struct x86_comparison){
				.target_register = reg,
				.value = comparator,
				.mask = mask,
				.mem_rm = state->mem_rm,
				.sources = state->sources[rm],
				.validity = COMPARISON_SUPPORTS_ANY,
			};
			return SUPPORTED_COMPARISON;
		}
		case 0x3c: {
			// found cmp al, imm8
			struct register_state comparator;
			comparator.value = comparator.max = (uintptr_t)*(const int8_t *)&decoded.unprefixed[1] & 0xff;
			*out_comparison = (struct x86_comparison){
				.target_register = REGISTER_RAX,
				.value = comparator,
				.mask = 0xff,
				.mem_rm = state->mem_rm,
				.sources = 0,
				.validity = COMPARISON_SUPPORTS_ANY,
			};
			return SUPPORTED_COMPARISON;
		}
		case 0x3d: {
			// found cmp ax, imm
			uintptr_t mask = mask_for_size_prefixes(decoded.prefixes);
			struct register_state comparator;
			if (decoded.prefixes.has_operand_size_override) {
				comparator.value = (*(const x86_uint16 *)&decoded.unprefixed[1]) & mask;
			} else {
				comparator.value = (decoded.prefixes.has_w ? (uintptr_t)*(const x86_int32 *)&decoded.unprefixed[1] : (uintptr_t)*(const x86_uint32 *)&decoded.unprefixed[1]) & mask;
			}
			comparator.max = comparator.value;
			*out_comparison = (struct x86_comparison){
				.target_register = REGISTER_RAX,
				.value = comparator,
				.mask = mask,
				.mem_rm = state->mem_rm,
				.sources = 0,
				.validity = COMPARISON_SUPPORTS_ANY,
			};
			return SUPPORTED_COMPARISON;
		}
		case 0x80: { // 8-bit cmp with 8-bit immediate
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			if (modrm.reg == 0x7) {
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(loader, decoded.prefixes, &remaining, sizeof(uint8_t), state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
				if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
					return INVALID_COMPARISON;
				}
				struct register_state comparator;
				comparator.value = comparator.max = *(ins_ptr)remaining;
				*out_comparison = (struct x86_comparison){
					.target_register = rm,
					.value = comparator,
					.mask = 0xff,
					.mem_rm = state->mem_rm,
					.sources = 0,
					.validity = COMPARISON_SUPPORTS_ANY,
				};
				return SUPPORTED_COMPARISON;
			}
			break;
		}
		case 0x81: { // 64-bit cmp with 32-bit immediate
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			if (modrm.reg == 0x7) {
				ins_ptr remaining = &decoded.unprefixed[1];
				uintptr_t mask = mask_for_size_prefixes(decoded.prefixes);
				if (decoded.prefixes.has_operand_size_override) {
					int rm = read_rm_ref(loader, decoded.prefixes, &remaining, sizeof(int16_t), state, OPERATION_SIZE_16BIT, READ_RM_REPLACE_MEM, NULL);
					struct register_state comparator;
					comparator.value = comparator.max = (uintptr_t)*(const x86_uint16 *)remaining & mask;
					*out_comparison = (struct x86_comparison){
						.target_register = rm,
						.value = comparator,
						.mask = mask,
						.mem_rm = state->mem_rm,
						.sources = 0,
						.validity = COMPARISON_SUPPORTS_ANY,
					};
				} else {
					int rm = read_rm_ref(loader, decoded.prefixes, &remaining, sizeof(int32_t), state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
					struct register_state comparator;
					comparator.value = comparator.max = (decoded.prefixes.has_w ? (uintptr_t)*(const x86_int32 *)remaining : (uintptr_t)*(const x86_uint32 *)remaining) & mask;
					*out_comparison = (struct x86_comparison){
						.target_register = rm,
						.value = comparator,
						.mask = mask,
						.mem_rm = state->mem_rm,
						.sources = 0,
						.validity = COMPARISON_SUPPORTS_ANY,
					};
				}
				return SUPPORTED_COMPARISON;
			}
			break;
		}
		case 0x83: { // 32/64-bit cmp with 8-bit immediate
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			if (modrm.reg == 0x7) {
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(loader, decoded.prefixes, &remaining, sizeof(int8_t), state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
				uintptr_t mask = mask_for_size_prefixes(decoded.prefixes);
				struct register_state comparator;
				comparator.value = comparator.max = (uintptr_t)*(const int8_t *)remaining & mask;
				*out_comparison = (struct x86_comparison){
					.target_register = rm,
					.value = comparator,
					.mask = mask,
					.mem_rm = state->mem_rm,
					.sources = 0,
					.validity = COMPARISON_SUPPORTS_ANY,
				};
				return SUPPORTED_COMPARISON;
			}
			break;
		}
		case 0x84: {
			// test r/m8, r8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded.prefixes);
			if (x86_modrm_is_direct(modrm) && reg == x86_read_rm(modrm, decoded.prefixes)) {
				if (register_is_legacy_8bit_high(decoded.prefixes, &reg)) {
					return INVALID_COMPARISON;
				}
				LOG("found test", name_for_register(reg));
				struct register_state comparator;
				comparator.value = comparator.max = 0;
				*out_comparison = (struct x86_comparison){
					.target_register = reg,
					.value = comparator,
					.mask = 0xff,
					.mem_rm = state->mem_rm,
					.sources = 0,
					.validity = COMPARISON_SUPPORTS_EQUALITY,
				};
				return SUPPORTED_COMPARISON;
			}
			return INVALID_COMPARISON;
		}
		case 0x85: {
			// test r/m, r
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded.prefixes);
			if (x86_modrm_is_direct(modrm) && reg == x86_read_rm(modrm, decoded.prefixes)) {
				LOG("found test", name_for_register(reg));
				struct register_state comparator;
				comparator.value = comparator.max = 0;
				*out_comparison = (struct x86_comparison){
					.target_register = reg,
					.value = comparator,
					.mask = mask_for_size_prefixes(decoded.prefixes),
					.mem_rm = state->mem_rm,
					.sources = 0,
					.validity = COMPARISON_SUPPORTS_EQUALITY,
				};
				return SUPPORTED_COMPARISON;
			}
			return INVALID_COMPARISON;
		}
		case 0xa8: {
			// test al, imm8
			// LOG("found test", name_for_register(REGISTER_RAX));
			return INVALID_COMPARISON;
		}
		case 0xa9: {
			// test ax, imm
			// LOG("found test", name_for_register(REGISTER_RAX));
			return INVALID_COMPARISON;
		}
		case 0xf6: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			if (modrm.reg == 0) { // test r/m8, imm8
				return INVALID_COMPARISON;
			}
			break;
		}
		case 0xf7: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			if (modrm.reg == 0) { // test r/m, imm
				return INVALID_COMPARISON;
			}
			break;
		}
	}
	return NO_COMPARISON;
}

static uint8_t imm_size_for_prefixes(struct x86_ins_prefixes prefixes)
{
	if (prefixes.has_w) { // imm32 sign-extended
		return sizeof(int32_t);
	} else if (prefixes.has_operand_size_override) { // imm16
		return sizeof(uint16_t);
	} else { // imm32
		return sizeof(uint32_t);
	}
}

#endif

typedef void (*basic_op)(struct register_state *dest, const struct register_state *source, int dest_reg, int source_reg);

static void basic_op_unknown(struct register_state *dest, __attribute__((unused)) const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	clear_register(dest);
}

static void basic_op_add(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		dest->value = dest->max = dest->value + source->value;
	} else if (__builtin_add_overflow(dest->value, source->value, &dest->value) || __builtin_add_overflow(dest->max, source->max, &dest->max)) {
		clear_register(dest);
	}
}

static void basic_op_or(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		dest->value = dest->max = dest->value | source->value;
		return;
	}
	if (source->value == ~(uintptr_t)0) {
		dest->value = dest->max = ~(uintptr_t)0;
		return;
	}
	if (source->value < dest->value) {
		dest->value = source->value;
	}
	dest->max |= source->max;
}

static void basic_op_adc(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (__builtin_add_overflow(dest->max, source->max, &dest->max)) {
		clear_register(dest);
		return;
	}
	if (__builtin_add_overflow(dest->max, 1, &dest->max)) {
		clear_register(dest);
		return;
	}
	dest->value += source->value;
}

static void basic_op_and(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		dest->max = dest->value = dest->value & source->value;
	} else {
		dest->value = 0;
		if (source->max < dest->max) {
			dest->max = source->max;
		}
	}
}

static void basic_op_sbb(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		uintptr_t dest_value = dest->value;
		dest->value = dest_value - (source->value + 1);
		dest->max = dest_value - source->value;
	} else {
		clear_register(dest);
	}
}

static void basic_op_sub(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (__builtin_sub_overflow(dest->value, source->max, &dest->value) || __builtin_sub_overflow(dest->max, source->value, &dest->max)) {
		clear_register(dest);
	}
}

static void basic_op_xor(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (register_is_exactly_known(dest) && register_is_exactly_known(source)) {
		dest->max = dest->value = dest->value ^ source->value;
	} else {
		clear_register(dest);
	}
}

static void basic_op_shr(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (source->value > 64) {
		clear_register(dest);
		return;
	}
	if (register_is_exactly_known(source)) {
		dest->value = dest->value >> source->value;
	} else {
		dest->value = 0;
	}
	dest->max = dest->max >> source->value;
}

static void basic_op_shl(struct register_state *dest, const struct register_state *source, __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg)
{
	if (register_is_exactly_known(source) && register_is_exactly_known(dest)) {
		if (source->value > 64) {
			dest->value = dest->max = 0;
		} else {
			dest->value = dest->max = dest->value << source->value;
		}
	} else {
		clear_register(dest);
	}
}

#if defined(__x86_64__)

static int perform_basic_op_rm_r_8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, ins_ptr ins_modrm)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct register_state dest;
	int rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, &dest);
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(rm));
	LOG("basic operand", name_for_register(reg));
	dump_registers(loader, regs, ((register_mask)1 << reg) | ((register_mask)1 << rm));
	if (register_is_legacy_8bit_high(prefixes, &rm) || register_is_legacy_8bit_high(prefixes, &reg)) {
		clear_register(&dest);
		truncate_to_16bit(&dest);
	} else {
		struct register_state src = regs->registers[reg];
		truncate_to_8bit(&src);
		truncate_to_8bit(&dest);
		op(&dest, &src, rm, reg);
		truncate_to_8bit(&dest);
	}
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[rm] = dest;
	if (register_is_partially_known_8bit(&dest)) {
		regs->sources[rm] |= regs->sources[reg];
	} else {
		regs->sources[rm] = 0;
	}
	clear_match(loader, regs, rm, ins_modrm);
	return rm;
}

static int perform_basic_op_rm_r(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, ins_ptr ins_modrm)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct register_state dest;
	int rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, &dest);
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(rm));
	LOG("basic operand", name_for_register(reg));
	dump_registers(loader, regs, ((register_mask)1 << reg) | ((register_mask)1 << rm));
	struct register_state src = regs->registers[reg];
	truncate_to_size_prefixes(&src, prefixes);
	truncate_to_size_prefixes(&dest, prefixes);
	op(&dest, &src, rm, reg);
	truncate_to_size_prefixes(&dest, prefixes);
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[rm] = dest;
	if (register_is_partially_known_size_prefixes(&dest, prefixes)) {
		regs->sources[rm] |= regs->sources[reg];
	} else {
		regs->sources[rm] = 0;
	}
	clear_match(loader, regs, rm, ins_modrm);
	return rm;
}

static int perform_basic_op_r_rm_8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, ins_ptr ins_modrm)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct register_state src;
	int rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, &src);
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(reg));
	LOG("basic operand", name_for_register(rm));
	struct register_state dest = regs->registers[reg];
	if (register_is_legacy_8bit_high(prefixes, &rm) || register_is_legacy_8bit_high(prefixes, &reg)) {
		clear_register(&dest);
		truncate_to_16bit(&dest);
	} else {
		truncate_to_8bit(&src);
		truncate_to_8bit(&dest);
		op(&dest, &src, reg, rm);
		truncate_to_8bit(&dest);
	}
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[reg] = dest;
	if (register_is_partially_known_8bit(&dest)) {
		regs->sources[reg] |= regs->sources[rm];
	} else {
		regs->sources[reg] = 0;
	}
	clear_match(loader, regs, reg, ins_modrm);
	return reg;
}

static int perform_basic_op_r_rm(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, ins_ptr ins_modrm)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct register_state src;
	int rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, &src);
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(reg));
	LOG("basic operand", name_for_register(rm));
	struct register_state dest = regs->registers[reg];
	dump_registers(loader, regs, ((register_mask)1 << reg) | ((register_mask)1 << rm));
	truncate_to_size_prefixes(&src, prefixes);
	truncate_to_size_prefixes(&dest, prefixes);
	op(&dest, &src, reg, rm);
	truncate_to_size_prefixes(&dest, prefixes);
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[reg] = dest;
	if (register_is_partially_known_size_prefixes(&dest, prefixes)) {
		regs->sources[reg] |= regs->sources[rm];
	} else {
		regs->sources[reg] = 0;
	}
	clear_match(loader, regs, reg, ins_modrm);
	return reg;
}

static int perform_basic_op_rm8_imm8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, ins_ptr ins_modrm)
{
	struct register_state dest;
	int rm = read_rm_ref(loader, prefixes, &ins_modrm, sizeof(uint8_t), regs, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, &dest);
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(rm));
	dump_registers(loader, regs, (register_mask)1 << rm);
	if (register_is_legacy_8bit_high(prefixes, &rm)) {
		LOG("legacy 8 bit high");
		clear_register(&dest);
		truncate_to_16bit(&dest);
	} else {
		truncate_to_8bit(&dest);
		struct register_state src;
		set_register(&src, *ins_modrm);
		LOG("basic immediate", src.value);
		op(&dest, &src, rm, -1);
		truncate_to_8bit(&dest);
	}
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[rm] = dest;
	if (!register_is_partially_known_8bit(&dest)) {
		regs->sources[rm] = 0;
	}
	clear_match(loader, regs, rm, ins_modrm);
	return rm;
}

static void perform_basic_op_al_imm8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, ins_ptr imm)
{
	LOG("basic operation", name);
	int reg = REGISTER_RAX;
	LOG("basic destination", name_for_register(reg));
	dump_registers(loader, regs, (register_mask)1 << reg);
	struct register_state dest = regs->registers[reg];
	truncate_to_8bit(&dest);
	struct register_state src;
	set_register(&src, *imm);
	LOG("basic immediate", src.value);
	op(&dest, &src, reg, -1);
	truncate_to_8bit(&dest);
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[reg] = dest;
	if (!register_is_partially_known_8bit(&dest)) {
		regs->sources[reg] = 0;
	}
	clear_match(loader, regs, reg, imm);
}

static int perform_basic_op_rm_imm(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, ins_ptr ins_modrm)
{
	struct register_state dest;
	int rm = read_rm_ref(loader, prefixes, &ins_modrm, imm_size_for_prefixes(prefixes), regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, &dest);
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(rm));
	dump_registers(loader, regs, (register_mask)1 << rm);
	truncate_to_size_prefixes(&dest, prefixes);
	struct register_state src;
	set_register(&src, read_imm(prefixes, ins_modrm));
	LOG("basic immediate", src.value);
	op(&dest, &src, rm, -1);
	truncate_to_size_prefixes(&dest, prefixes);
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[rm] = dest;
	if (!register_is_partially_known_size_prefixes(&dest, prefixes)) {
		regs->sources[rm] = 0;
	}
	clear_match(loader, regs, rm, ins_modrm);
	return rm;
}

static int perform_basic_op_imm(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, int reg, ins_ptr imm)
{
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(reg));
	dump_registers(loader, regs, (register_mask)1 << reg);
	struct register_state dest = regs->registers[reg];
	truncate_to_size_prefixes(&dest, prefixes);
	struct register_state src;
	set_register(&src, read_imm(prefixes, imm));
	LOG("basic immediate", src.value);
	op(&dest, &src, reg, -1);
	truncate_to_size_prefixes(&dest, prefixes);
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[reg] = dest;
	if (!register_is_partially_known_size_prefixes(&dest, prefixes)) {
		regs->sources[reg] = 0;
	}
	clear_match(loader, regs, reg, imm);
	return reg;
}

static int perform_basic_op_rm_imm8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, ins_ptr ins_modrm)
{
	struct register_state dest;
	int rm = read_rm_ref(loader, prefixes, &ins_modrm, sizeof(int8_t), regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, &dest);
	LOG("basic operation", name);
	LOG("basic destination", name_for_register(rm));
	dump_registers(loader, regs, (register_mask)1 << rm);
	truncate_to_size_prefixes(&dest, prefixes);
	struct register_state src;
	if (prefixes.has_w) { // sign extend to 64-bits
		set_register(&src, (int64_t)*(const int8_t *)ins_modrm);
	} else if (prefixes.has_operand_size_override) {  // sign extend to 16-bits
		set_register(&src, (int16_t)*(const int8_t *)ins_modrm);
	} else { // sign extend to 32-bits
		set_register(&src, (int32_t)*(const int8_t *)ins_modrm);
	}
	LOG("basic immediate", src.value);
	op(&dest, &src, rm, -1);
	truncate_to_size_prefixes(&dest, prefixes);
	LOG("result", temp_str(copy_register_state_description(loader, dest)));
	regs->registers[rm] = dest;
	if (!register_is_partially_known_size_prefixes(&dest, prefixes)) {
		regs->sources[rm] = 0;
	}
	clear_match(loader, regs, rm, ins_modrm);
	return rm;
}

#endif

static void set_compare_from_operation(struct registers *regs, int reg, uintptr_t mask)
{
	regs->compare_state = (struct x86_comparison){
		.target_register = reg,
		.value = 0,
		.mask = mask,
		.mem_rm = regs->mem_rm,
		.sources = 0,
		.validity = COMPARISON_SUPPORTS_EQUALITY,
	};
}

static bool find_skipped_symbol_for_address(struct loader_context *loader, struct loaded_binary *binary, const void *address, struct address_and_size *out_symbol);

static uintptr_t size_of_jump_table_from_metadata(struct loader_context *loader, struct loaded_binary *binary, const void *table, ins_ptr ins, int debug_symbol_types, const ElfW(Sym) **out_function_symbol)
{
	if (binary == NULL) {
		return 0;
	}
	const struct symbol_info *symbols;
	bool has_symbol = find_any_symbol_by_address(loader, binary, ins, NORMAL_SYMBOL | LINKER_SYMBOL | (debug_symbol_types & INTERNAL_COMMON_SYMBOL), &symbols, out_function_symbol) != NULL;
	if ((binary->special_binary_flags & BINARY_HAS_CUSTOM_JUMPTABLE_METADATA) == 0) {
		LOG("binary does not have jump table metadata", binary ? binary->path : "none");
		return 0;
	}
	if (has_symbol) {
		const char *name = symbol_name(symbols, *out_function_symbol);
		if (fs_strcmp(name, "strncmp") == 0) {
			return 16;
		} else if (fs_strcmp(name, "__memcmp_sse4_1") == 0) {
			return 81;
		} else if (fs_strcmp(name, "__memcpy_ssse3_back") == 0 || fs_strcmp(name, "__memmove_ssse3_back") == 0) {
			return 16;
		} else if (fs_strcmp(name, "__stpncpy_sse2_unaligned") == 0) {
			return 17;
		} else if (fs_strcmp(name, "DES_ede3_cfb_encrypt") == 0) {
			return 9;
		} else if (fs_strcmp(name, "krb5int_get_fq_local_hostname") == 0) {
			return 12;
		} else if (fs_strcmp(name, "rb_external_str_new_with_enc") == 0) {
			return 8;
		} else if (fs_strcmp(name, "coderange_scan") == 0) {
			return 8;
		} else if (fs_strcmp(name, "rb_str_coderange_scan_restartable") == 0) {
			return 8;
		} else if (fs_strcmp(name, "rb_enc_cr_str_copy_for_substr") == 0) {
			return 8;
		} else if (fs_strcmp(name, "rb_enc_strlen_cr") == 0) {
			return 8;
		} else if (fs_strcmp(name, "str_nth_len") == 0) {
			return 8;
		} else if (fs_strcmp(name, "enc_str_scrub") == 0) {
			return 8;
		} else if (fs_strcmp(name, "str_strlen") == 0) {
			return 8;
		} else if (fs_strcmp(name, "rb_str_sublen") == 0) {
			return 8;
		}
		LOG("symbol does not have jump table metadata", name);
	}
	// workaround for manual jump table in libc's __vfprintf_internal implementation
	if (binary->special_binary_flags & BINARY_IS_LIBC) {
		const char *name = find_any_symbol_name_by_address(loader, binary, table, INTERNAL_COMMON_SYMBOL & DEBUG_SYMBOL_FORCING_LOAD);
		if (name != NULL && fs_strncmp(name, "step", sizeof("step")-1) == 0) {
			const char *jumps_text = &name[5];
			switch (name[4]) {
				case '3':
					if (*jumps_text != 'a' && *jumps_text != 'b') {
						break;
					}
					jumps_text++;
					// fallthrough
				case '0':
				case '1':
				case '2':
				case '4':
					if (fs_strncmp(jumps_text, "_jumps", sizeof("_jumps")-1) == 0) {
						return 30;
					}
					break;
			}
		}
	}
	return 0;
}

static bool lookup_table_jump_is_valid(const struct loaded_binary *binary, const struct frame_details *frame_details, const ElfW(Sym) *function_symbol, ins_ptr jump)
{
	if (frame_details != NULL) {
		return (frame_details->address <= (const void *)jump) && ((const void *)jump < frame_details->address + frame_details->size);
	} else if (function_symbol != NULL) {
		return (binary->info.base + function_symbol->st_value <= (const void *)jump) && ((const void *)jump < binary->info.base + function_symbol->st_value + function_symbol->st_size);
	} else {
		return (binary->info.base <= (const void *)jump) && ((const void *)jump < binary->info.base + binary->info.size);
	}
}


static void print_debug_symbol_requirement(const struct loaded_binary *binary)
{
	ERROR("failed to load debug symbols for", binary->path);
	ERROR("install debug symbols using your system's package manager or rebuild with debug symbols if this is software you compiled yourself");
	ERROR("on debian-based systems find-dbgsym-packages can help you discover debug symbol packages");
}

static inline bool bsearch_address_callback(int index, void *ordered_addresses, void *needle)
{
	const uintptr_t *ordered = (const uintptr_t *)ordered_addresses;
	return ordered[index] > (uintptr_t)needle;
}

static inline uintptr_t search_find_next_loaded_address(struct searched_instructions *search, uintptr_t address)
{
	int count = search->loaded_address_count;
	uintptr_t *addresses = search->loaded_addresses;
	int i = bsearch_bool(count, addresses, (void *)address, bsearch_address_callback);
	return i < count ? addresses[i] : ~(uintptr_t)0;
}

static inline void add_loaded_address(__attribute__((unused)) struct searched_instructions *search, __attribute__((unused)) uintptr_t address)
{
	int old_count = search->loaded_address_count;
	uintptr_t *addresses = search->loaded_addresses;
	int i = bsearch_bool(old_count, addresses, (void *)address, bsearch_address_callback);
	if (i != 0) {
		if (addresses[i-1] == address) {
			// already loaded, skip adding
			return;
		}
	}
	int new_count = old_count + 1;
	search->loaded_address_count = new_count;
	addresses = search->loaded_addresses = realloc(addresses, sizeof(uintptr_t) * new_count);
	for (int j = old_count; j > i; j--) {
		addresses[j] = addresses[j-1];
	}
	addresses[i] = address;
}

enum {
	MAX_LOOKUP_TABLE_SIZE = 0x408,
};

static inline ins_ptr skip_prefix_jumps(struct program_state *analysis, ins_ptr ins, struct decoded_ins *decoded)
{
	// skip over function stubs that simply call into a target function
	ins_ptr ret = ins;
	struct decoded_ins peek;
	if (!x86_decode_instruction(ins, &peek)) {
		return NULL;
	}
	*decoded = peek;
	for (;;) {
		if (is_landing_pad_ins(&peek)) {
			ins_ptr next = next_ins(ins, &peek);
#if BREAK_ON_UNREACHABLES
			push_reachable_region(&analysis->loader, &analysis->unreachables, ins, next);
#endif
			ins = next;
			if (!x86_decode_instruction(ins, &peek)) {
				return NULL;
			}
		} else {
			ins_ptr jump_target;
			enum ins_jump_behavior jump = ins_interpret_jump_behavior(&peek, &jump_target);
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
#if BREAK_ON_UNREACHABLES
			push_reachable_region(&analysis->loader, &analysis->unreachables, ins, next_ins(ins, &peek));
#endif
			ins = jump_target;
			ret = jump_target;
			if (!x86_decode_instruction(ins, decoded)) {
				return NULL;
			}
		}
	}
	return ret;
}

__attribute__((noinline))
static void analyze_libcrypto_dlopen(struct program_state *analysis)
{
	if (analysis->loader.libcrypto_dlopen != NULL) {
		struct registers state = empty_registers;
		analysis->loader.searching_libcrypto_dlopen = true;
		struct effect_token token;
		*get_or_populate_effects(analysis, analysis->loader.libcrypto_dlopen, &state, EFFECT_NONE, &token) = EFFECT_NONE;
	}
}

__attribute__((always_inline))
static inline function_effects analyze_call(struct program_state *analysis, function_effects required_effects, ins_ptr ins, ins_ptr call_target, struct analysis_frame *self)
{
	push_stack(&self->current_state, 2);
	struct registers call_state = copy_call_argument_registers(&analysis->loader, &self->current_state, ins);
	dump_nonempty_registers(&analysis->loader, &call_state, ALL_REGISTERS);
	function_effects more_effects = analyze_function(analysis, required_effects & ~EFFECT_ENTRY_POINT, &call_state, call_target, self);
	pop_stack(&self->current_state, 2);
	if (more_effects & EFFECT_PROCESSING) {
		queue_instruction(&analysis->search.queue, call_target, required_effects & ~EFFECT_ENTRY_POINT, &call_state, call_target, self->description);
		more_effects = (more_effects & ~EFFECT_PROCESSING) | EFFECT_RETURNS;
	}
	return more_effects;
}

__attribute__((noinline))
static function_effects analyze_conditional_branch(struct program_state *analysis, function_effects required_effects, __attribute__((unused)) ins_ptr ins, struct decoded_ins *decoded, ins_ptr jump_target, ins_ptr continue_target, struct analysis_frame *self)
{
	bool skip_jump = false;
	bool skip_continue = false;
	struct registers jump_state = self->current_state;
	// struct registers continue_state = self->current_state;
#define continue_state (self->current_state)
	LOG("found conditional jump", temp_str(copy_address_description(&analysis->loader, jump_target)));
	struct loaded_binary *jump_binary = NULL;
	int jump_prot = protection_for_address(&analysis->loader, jump_target, &jump_binary, NULL);
	if ((self->current_state.compare_state.validity != COMPARISON_IS_INVALID) && register_is_exactly_known(&self->current_state.compare_state.value)) {
		// include matching registers
		if (jump_state.compare_state.target_register == REGISTER_MEM && !decoded_rm_equal(&jump_state.compare_state.mem_rm, &jump_state.mem_rm)) {
			LOG("clearing old mem r/m for conditional", temp_str(copy_decoded_rm_description(&analysis->loader, jump_state.mem_rm)));
			LOG("replacing with new mem r/m", temp_str(copy_decoded_rm_description(&analysis->loader, jump_state.compare_state.mem_rm)));
			jump_state.mem_rm = continue_state.mem_rm = jump_state.compare_state.mem_rm;
			jump_state.registers[REGISTER_MEM].value = continue_state.registers[REGISTER_MEM].value = 0;
			jump_state.registers[REGISTER_MEM].max = continue_state.registers[REGISTER_MEM].max = jump_state.compare_state.mask;
			clear_match(&analysis->loader, &jump_state, REGISTER_MEM, self->address);
		}
		register_mask target_registers = jump_state.matches[self->current_state.compare_state.target_register] | ((register_mask)1 << self->current_state.compare_state.target_register);
		register_mask skip_jump_mask = 0;
		register_mask skip_continue_mask = 0;
		if (SHOULD_LOG) {
			for (int target_register = 0; target_register < REGISTER_COUNT; target_register++) {
				if (target_registers & ((register_mask)1 << target_register)) {
					LOG("comparing", name_for_register(target_register));
				}
			}
		}
		for (int target_register = 0; target_register < REGISTER_COUNT; target_register++) {
			if ((target_registers & ((register_mask)1 << target_register)) == 0) {
				continue;
			}
			uintptr_t compare_mask = self->current_state.compare_state.mask;
			if ((jump_state.registers[target_register].value & ~compare_mask) != (jump_state.registers[target_register].max & ~compare_mask)) {
				jump_state.registers[target_register].value = 0;
				jump_state.registers[target_register].max = compare_mask;
			} else {
				jump_state.registers[target_register].value &= compare_mask;
				jump_state.registers[target_register].max &= compare_mask;
			}
			if ((continue_state.registers[target_register].value & ~compare_mask) != (continue_state.registers[target_register].max & ~compare_mask)) {
				continue_state.registers[target_register].value = 0;
				continue_state.registers[target_register].max = compare_mask;
			} else {
				continue_state.registers[target_register].value &= compare_mask;
				continue_state.registers[target_register].max &= compare_mask;
			}
			if (is_jb_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found jb comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				// test %target_register; jb
				if (jump_state.registers[target_register].value >= self->current_state.compare_state.value.value) {
					skip_jump_mask |= (register_mask)1 << target_register;
					LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
				} else if (jump_state.registers[target_register].max >= self->current_state.compare_state.value.value) {
					jump_state.registers[target_register].max = self->current_state.compare_state.value.value - 1;
				}
				if (continue_state.registers[target_register].max < self->current_state.compare_state.value.value) {
					skip_continue_mask |= (register_mask)1 << target_register;
					LOG("continue jump", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
				} else if (continue_state.registers[target_register].value < self->current_state.compare_state.value.value) {
					continue_state.registers[target_register].value = self->current_state.compare_state.value.value;
				}
			}
			if (is_jae_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found jae comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				// test %target_register; jae
				if (jump_state.registers[target_register].max < self->current_state.compare_state.value.value) {
					skip_jump_mask |= (register_mask)1 << target_register;
					LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
				} else if (jump_state.registers[target_register].value < self->current_state.compare_state.value.value) {
					jump_state.registers[target_register].value = self->current_state.compare_state.value.value;
				}
				if (continue_state.registers[target_register].value >= self->current_state.compare_state.value.value) {
					skip_continue_mask |= (register_mask)1 << target_register;
					LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
				} else if (continue_state.registers[target_register].max >= self->current_state.compare_state.value.value) {
					continue_state.registers[target_register].max = self->current_state.compare_state.value.value - 1;
				}
			}
			if (is_je_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_EQUALITY)) {
				LOG("found je comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				// test %target_register; je
				if (jump_state.registers[target_register].value <= self->current_state.compare_state.value.value && self->current_state.compare_state.value.value <= jump_state.registers[target_register].max) {
					jump_state.registers[target_register] = self->current_state.compare_state.value;
					jump_state.sources[target_register] = self->current_state.compare_state.sources;
					// remove value from edge of ranges
					if (continue_state.registers[target_register].value == self->current_state.compare_state.value.value) {
						if (register_is_exactly_known(&continue_state.registers[target_register])) {
							skip_continue_mask |= (register_mask)1 << target_register;
							LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
						} else {
							continue_state.registers[target_register].value++;
						}
					} else if (continue_state.registers[target_register].max == self->current_state.compare_state.value.value) {
						continue_state.registers[target_register].max--;
					}
				} else {
					skip_jump_mask |= (register_mask)1 << target_register;
					LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
				}
			}
			if (is_jne_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_EQUALITY)) {
				LOG("found jne comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				// test %target_register; jne
				if (continue_state.registers[target_register].value <= self->current_state.compare_state.value.value && self->current_state.compare_state.value.value <= continue_state.registers[target_register].max) {
					continue_state.registers[target_register] = self->current_state.compare_state.value;
					continue_state.sources[target_register] = self->current_state.compare_state.sources;
					// remove value from edge of ranges
					if (jump_state.registers[target_register].value == self->current_state.compare_state.value.value) {
						if (register_is_exactly_known(&jump_state.registers[target_register])) {
							skip_jump_mask |= (register_mask)1 << target_register;
							LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
						} else {
							jump_state.registers[target_register].value++;
						}
					} else if (jump_state.registers[target_register].max == self->current_state.compare_state.value.value) {
						jump_state.registers[target_register].max--;
					}
				} else {
					skip_continue_mask |= (register_mask)1 << target_register;
					LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
				}
			}
			if (is_jbe_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found jbe comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				// test %target_register; jbe
				if (jump_state.registers[target_register].value > self->current_state.compare_state.value.value) {
					skip_jump_mask |= (register_mask)1 << target_register;
					LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
				} else if (jump_state.registers[target_register].max > self->current_state.compare_state.value.value) {
					jump_state.registers[target_register].max = self->current_state.compare_state.value.value;
				}
				if (continue_state.registers[target_register].max <= self->current_state.compare_state.value.value) {
					skip_continue_mask |= (register_mask)1 << target_register;
					LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
				} else if (continue_state.registers[target_register].value <= self->current_state.compare_state.value.value) {
					continue_state.registers[target_register].value = self->current_state.compare_state.value.value + 1;
				}
			}
			if (is_ja_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found ja comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				// test %target_register; ja
				if (jump_state.registers[target_register].max <= self->current_state.compare_state.value.value) {
					skip_jump_mask |= (register_mask)1 << target_register;
					LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
				} else if (jump_state.registers[target_register].value <= self->current_state.compare_state.value.value) {
					jump_state.registers[target_register].value = self->current_state.compare_state.value.value + 1;
				}
				if (continue_state.registers[target_register].value > self->current_state.compare_state.value.value) {
					skip_continue_mask |= (register_mask)1 << target_register;
					LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
				} else if (continue_state.registers[target_register].max > self->current_state.compare_state.value.value) {
					continue_state.registers[target_register].max = self->current_state.compare_state.value.value;
				}
			}
			if (is_js_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found js comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				if (self->current_state.compare_state.value.value == 0) {
					uintptr_t msb = most_significant_bit(self->current_state.compare_state.mask);
					// test %target_register; ja
					if (jump_state.registers[target_register].max < msb) {
						skip_jump_mask |= (register_mask)1 << target_register;
						LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
					} else if (jump_state.registers[target_register].value < msb) {
						jump_state.registers[target_register].value = msb;
					}
					if (continue_state.registers[target_register].value >= msb) {
						skip_continue_mask |= (register_mask)1 << target_register;
						LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
					} else if (continue_state.registers[target_register].max >= msb) {
						continue_state.registers[target_register].max = msb - 1;
					}
				}
			}
			if (is_jns_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found jns comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				if (self->current_state.compare_state.value.value == 0) {
					uintptr_t msb = most_significant_bit(self->current_state.compare_state.mask);
					// test %target_register; ja
					if (jump_state.registers[target_register].value >= msb) {
						skip_jump_mask |= (register_mask)1 << target_register;
						LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
					} else if (jump_state.registers[target_register].max >= msb) {
						jump_state.registers[target_register].max = msb - 1;
					}
					if (continue_state.registers[target_register].max < msb) {
						skip_continue_mask |= (register_mask)1 << target_register;
						LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
					} else if (continue_state.registers[target_register].value < msb) {
						continue_state.registers[target_register].value = msb;
					}
				}
			}
			if (is_jl_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found jl comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				// test %target_register; jl
				if ((intptr_t)jump_state.registers[target_register].max < 0 && !binary_has_flags(jump_binary, BINARY_IGNORES_SIGNEDNESS)) {
					LOG("signed comparison on potentially negative value, skipping narrowing");
				} else {
					if (jump_state.registers[target_register].value >= self->current_state.compare_state.value.value) {
						skip_jump_mask |= (register_mask)1 << target_register;
						LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
					} else if (jump_state.registers[target_register].max > self->current_state.compare_state.value.value) {
						jump_state.registers[target_register].max = self->current_state.compare_state.value.value;
					}
					if (continue_state.registers[target_register].max < self->current_state.compare_state.value.value) {
						skip_continue_mask |= (register_mask)1 << target_register;
						LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
					} else if (continue_state.registers[target_register].value <= self->current_state.compare_state.value.value) {
						continue_state.registers[target_register].value = self->current_state.compare_state.value.value + 1;
					}
				}
			}
			if (is_jge_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found jge comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				if ((intptr_t)jump_state.registers[target_register].max < 0 && !binary_has_flags(jump_binary, BINARY_IGNORES_SIGNEDNESS)) {
					LOG("signed comparison on potentially negative value, skipping narrowing");
				} else {
					// test %target_register; jge
					if (jump_state.registers[target_register].max < self->current_state.compare_state.value.value) {
						skip_jump_mask |= (register_mask)1 << target_register;
						LOG("skipping jump", temp_str(copy_register_state_description(&analysis->loader, jump_state.registers[target_register])));
					} else if (jump_state.registers[target_register].value < self->current_state.compare_state.value.value) {
						jump_state.registers[target_register].value = self->current_state.compare_state.value.value;
					}
					if (continue_state.registers[target_register].value >= self->current_state.compare_state.value.value) {
						skip_continue_mask |= (register_mask)1 << target_register;
						LOG("skipping continue", temp_str(copy_register_state_description(&analysis->loader, continue_state.registers[target_register])));
					} else if (continue_state.registers[target_register].max >= self->current_state.compare_state.value.value) {
						continue_state.registers[target_register].max = self->current_state.compare_state.value.value - 1;
					}
				}
			}
			if (is_jg_ins(decoded) && (self->current_state.compare_state.validity & COMPARISON_SUPPORTS_RANGE)) {
				LOG("found jg comparing", name_for_register(target_register));
				dump_register(&analysis->loader, continue_state.registers[target_register]);
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self->current_state.compare_state.value)));
				if ((intptr_t)jump_state.registers[target_register].max < 0 && !binary_has_flags(jump_binary, BINARY_IGNORES_SIGNEDNESS)) {
					LOG("signed comparison on potentially negative value, skipping narrowing");
				} else {
					// test %target_register; jg
					if (register_is_partially_known(&continue_state.registers[target_register])) {
						if (continue_state.registers[target_register].max > self->current_state.compare_state.value.value) {
							continue_state.registers[target_register].max = self->current_state.compare_state.value.value;
						}
						if (continue_state.registers[target_register].value > self->current_state.compare_state.value.value) {
							continue_state.registers[target_register].value = self->current_state.compare_state.value.value;
						}
						if (jump_state.registers[target_register].max < self->current_state.compare_state.value.value) {
							jump_state.registers[target_register].max = self->current_state.compare_state.value.value;
						}
						if (jump_state.registers[target_register].value < self->current_state.compare_state.value.value) {
							jump_state.registers[target_register].value = self->current_state.compare_state.value.value;
						}
					} else {
						continue_state.registers[target_register].value = 0;
						continue_state.registers[target_register].max = self->current_state.compare_state.value.value;
						jump_state.registers[target_register].value = self->current_state.compare_state.value.value + 1;
						jump_state.registers[target_register].max = ~(uintptr_t)0;
					}
				}
			}
			canonicalize_register(&jump_state.registers[target_register]);
			canonicalize_register(&continue_state.registers[target_register]);
			// if (SHOULD_LOG) {
			// 	if (self->current_state.registers[target_register].value != jump_state.registers[target_register].value || self->current_state.registers[target_register].max != jump_state.registers[target_register].max) {
			// 		ERROR("narrowed register for jump", name_for_register(target_register));
			// 		dump_register(&analysis->loader, jump_state.registers[target_register]);
			// 	}
			// 	if (self->current_state.registers[target_register].value != continue_state.registers[target_register].value || self->current_state.registers[target_register].max != continue_state.registers[target_register].max) {
			// 		ERROR("narrowed register for continue", name_for_register(target_register));
			// 		dump_register(&analysis->loader, continue_state.registers[target_register]);
			// 	}
			// }
		}
		if (skip_jump_mask) {
			if (skip_jump_mask & (register_mask)1 << self->current_state.compare_state.target_register) {
				skip_jump = true;
				LOG("skipping jump because value wasn't possible", temp_str(copy_address_description(&analysis->loader, jump_target)));
				self->description = "skip conditional jump";
				vary_effects_by_registers(&analysis->search, &analysis->loader, self, target_registers | skip_jump_mask | self->current_state.compare_state.sources, 0, 0, required_effects);
				push_unreachable_breakpoint(&analysis->unreachables, jump_target);
			} else {
				LOG("not all registers skipped for jump");
				dump_registers(&analysis->loader, &jump_state, target_registers);
			}
		}
		if (skip_continue_mask) {
			// if (skip_continue_mask == target_registers) {
			if (skip_continue_mask & (register_mask)1 << self->current_state.compare_state.target_register) {
				skip_continue = true;
				LOG("skipping continue because value wasn't possible", temp_str(copy_address_description(&analysis->loader, continue_target)));
				self->description = "skip conditional continue";
				vary_effects_by_registers(&analysis->search, &analysis->loader, self, target_registers | skip_continue_mask | self->current_state.compare_state.sources, 0, 0, required_effects);
				push_unreachable_breakpoint(&analysis->unreachables, continue_target);
			} else {
				LOG("not all registers skipped for continue");
				dump_registers(&analysis->loader, &continue_state, target_registers);
			}
		}
		if (!(skip_jump || skip_continue) && self->current_state.compare_state.sources != 0) {
			self->description = "conditional jump predicate";
			vary_effects_by_registers(&analysis->search, &analysis->loader, self, target_registers | self->current_state.compare_state.sources, 0, 0, required_effects);
		}
	}
	function_effects jump_effects;
	function_effects continue_effects = EFFECT_NONE;
	bool continue_first = continue_target < jump_target;
	if (continue_first) {
		if (skip_continue) {
		} else {
			LOG("taking continue", temp_str(copy_address_description(&analysis->loader, continue_target)));
			// set_effects(&analysis->search, self->entry, &self->token, effects | EFFECT_PROCESSING);
			self->description = skip_jump ? "conditional continue (no jump)" : "conditional continue";
			continue_effects = analyze_instructions(analysis, required_effects, &continue_state, continue_target, self, ALLOW_JUMPS_INTO_THE_ABYSS, false);
			LOG("resuming from conditional continue", temp_str(copy_address_description(&analysis->loader, self->entry)));
		}
	}
	if (skip_jump) {
		jump_effects = EFFECT_NONE;
	} else if ((jump_prot & PROT_EXEC) == 0) {
#if ABORT_AT_NON_EXECUTABLE_ADDRESS
		self->description = "conditional jump";
		ERROR("found conditional jump at", temp_str(copy_call_trace_description(&analysis->loader, self)));
		DIE("to non-executable address", temp_str(copy_address_description(&analysis->loader, jump_target)));
#endif
		LOG("found conditional jump to non-executable address, assuming all effects");
		jump_effects = EFFECT_EXITS | EFFECT_RETURNS;
	} else {
		LOG("taking jump", temp_str(copy_address_description(&analysis->loader, jump_target)));
		self->description = skip_continue ? "conditional jump (no continue)" : "conditional jump";
		jump_effects = analyze_instructions(analysis, required_effects, &jump_state, jump_target, self, ALLOW_JUMPS_INTO_THE_ABYSS, false);
	}
	if (continue_first) {
		LOG("completing conditional jump after branch", temp_str(copy_address_description(&analysis->loader, ins)));
	} else {
		LOG("resuming from conditional jump", temp_str(copy_address_description(&analysis->loader, ins)));
		if (skip_continue) {
		} else {
			LOG("taking continue", temp_str(copy_address_description(&analysis->loader, continue_target)));
			// set_effects(&analysis->search, self->entry, &self->token, effects | EFFECT_PROCESSING);
			self->description = skip_jump ? "conditional continue (no jump)" : "conditional continue";
			continue_effects = analyze_instructions(analysis, required_effects, &continue_state, continue_target, self, ALLOW_JUMPS_INTO_THE_ABYSS, false);
			LOG("completing conditional jump after continue", temp_str(copy_address_description(&analysis->loader, self->entry)));
		}
	}
	if (continue_effects & EFFECT_PROCESSING) {
		LOG("continue is processing", temp_str(copy_address_description(&analysis->loader, continue_target)));
		continue_effects = (continue_effects & EFFECT_STICKY_EXITS) ? EFFECT_EXITS : (EFFECT_RETURNS | EFFECT_EXITS);
	}
	if (jump_effects & EFFECT_PROCESSING) {
		LOG("jump is processing", temp_str(copy_address_description(&analysis->loader, jump_target)));
		jump_effects = (jump_effects & EFFECT_STICKY_EXITS) ? EFFECT_EXITS : (EFFECT_RETURNS | EFFECT_EXITS);
	}
	return jump_effects | continue_effects;
}

static inline function_effects fallback_effects_if_processing(function_effects effects)
{
	return effects & ~EFFECT_PROCESSING;
	// return effects & EFFECT_PROCESSING ? ((effects & ~EFFECT_PROCESSING) | EFFECT_RETURNS) : effects;
}

static bool is_setxid_name(const char *name)
{
	if (name == NULL) {
		return false;
	}
	if (name[0] != 's' || name[1] != 'e' || name[2] != 't') {
		return false;
	}
	name += 3;
	if (name[0] == 'r' && name[1] == 'e') {
		name += 2;
		if (name[0] == 's') {
			name++;
		}
	} else if (name[0] == 'e') {
		name++;
	} else if (name[0] == 'g' && name[1] == 'r' && name[2] == 'o' && name[3] == 'u' && name[4] == 'p' && name[5] == 's' && name[6] == '\0') {
		return true;
	// } else if (name[0] == 'f' && name[1] == 's') {
	// 	name += 2;
	}
	return (name[0] == 'u' || name[0] == 'g') && name[1] == 'i' && name[2] == 'd' && name[3] == '\0';
}

__attribute__((noinline))
static bool is_landing_pad_ins_decode(ins_ptr addr)
{
	struct decoded_ins decoded;
	if (decode_ins(addr, &decoded)) {
		return is_landing_pad_ins(&decoded);
	}
	return false;
}

enum possible_conditions {
	ALWAYS_MATCHES = 0x1,
	NEVER_MATCHES = 0x2,
	POSSIBLY_MATCHES = 0x3,
};

static inline enum possible_conditions calculate_possible_conditions(enum x86_conditional_type cond, struct registers *current_state)
{
	switch (cond) {
		case X86_CONDITIONAL_TYPE_BELOW:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].value >= current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].max < current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case X86_CONDITIONAL_TYPE_ABOVE_OR_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].max < current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].value >= current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case X86_CONDITIONAL_TYPE_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_EQUALITY) {
				if (current_state->registers[current_state->compare_state.target_register].value <= current_state->compare_state.value.value && current_state->compare_state.value.value <= current_state->registers[current_state->compare_state.target_register].max) {
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
		case X86_CONDITIONAL_TYPE_NOT_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_EQUALITY) {
				if (current_state->registers[current_state->compare_state.target_register].value <= current_state->compare_state.value.value && current_state->compare_state.value.value <= current_state->registers[current_state->compare_state.target_register].max) {
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
		case X86_CONDITIONAL_TYPE_BELOW_OR_EQUAL:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].value > current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].max <= current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case X86_CONDITIONAL_TYPE_ABOVE:
			if (current_state->compare_state.validity & COMPARISON_SUPPORTS_RANGE) {
				if (current_state->registers[current_state->compare_state.target_register].max <= current_state->compare_state.value.value) {
					return NEVER_MATCHES;
				}
				if (current_state->registers[current_state->compare_state.target_register].value > current_state->compare_state.value.value) {
					return ALWAYS_MATCHES;
				}
			}
			break;
		case X86_CONDITIONAL_TYPE_SIGN:
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
		case X86_CONDITIONAL_TYPE_NOT_SIGN:
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

static bool is_stack_preserving_function(struct loader_context *loader, struct loaded_binary *binary, ins_ptr addr)
{
	if (binary_has_flags(binary, BINARY_IS_GOLANG)) {
		const char *name = find_any_symbol_name_by_address(loader, binary, addr, NORMAL_SYMBOL | LINKER_SYMBOL);
		if (name != NULL) {
			if (fs_strcmp(name, "runtime.entersyscall") == 0 || fs_strcmp(name, "runtime.exitsyscall") == 0 || fs_strcmp(name, "runtime.Syscall6") == 0 || fs_strcmp(name, "runtime.RawSyscall6") == 0 || fs_strcmp(name, "runtime/internal/syscall.Syscall6") == 0) {
				LOG("found golang stack preserving function", temp_str(copy_address_description(loader, addr)));
				return true;
			}
		}
		return false;
	}
	if (binary_has_flags(binary, BINARY_IS_LIBC | BINARY_IS_PTHREAD)) {
		// check for __pthread_enable_asynccancel
		struct x86_instruction ins;
		if (!x86_decode_instruction(addr, &ins)) {
			return false;
		}
		if (x86_is_endbr64_instruction(&ins)) {
			addr = x86_next_instruction(addr, &ins);
			if (!x86_decode_instruction(addr, &ins)) {
				return false;
			}
		}
		// check for mov eax, [fs:CANCELHANDLING]
		if (addr[0] == 0x64 && addr[1] == 0x8b && addr[2] == 0x04 && addr[3] == 0x25 && addr[4] == 0x08 && addr[5] == 0x03 && addr[6] == 0x00 && addr[7] == 0x00) {
			LOG("found pthread stack preserving function", temp_str(copy_address_description(loader, addr)));
			return true;
		}
		// check for mov rcx, [fs:CANCELHANDLING]
		if (addr[0] == 0x64 && addr[1] == 0x48 && addr[2] == 0x8b /*&& addr[3] == 0x0c*/ && addr[4] == 0x25 && addr[5] == 0x10 && addr[6] == 0x00 && addr[7] == 0x00 && addr[8] == 0x00) {
			LOG("found pthread stack preserving function", temp_str(copy_address_description(loader, addr)));
			return true;
		}
		return false;
	}
	return false;
}

function_effects analyze_instructions(struct program_state *analysis, function_effects required_effects, const struct registers *entry_state, ins_ptr ins, const struct analysis_frame *caller, enum jump_table_status jump_status, bool is_entry)
{
	struct decoded_ins decoded;
	ins = skip_prefix_jumps(analysis, ins, &decoded);
	if (ins == NULL) {
		return EFFECT_RETURNS | EFFECT_EXITS;
	}
	struct analysis_frame self;
	function_effects effects;
	{
		function_effects *effects_entry;
		struct searched_instructions *search = &analysis->search;
		struct searched_instruction_entry *table_entry = find_searched_instruction_table_entry(search, ins, &self.token);
		bool wrote_registers = false;
		int entry_offset = entry_offset_for_registers(table_entry, entry_state, analysis, required_effects, ins, &self.current_state, &wrote_registers);
		if (UNLIKELY(table_entry->data->callback_index != 0)) {
			LOG("invoking callback for address", temp_str(copy_address_description(&analysis->loader, ins)));
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
		if (relevant_registers != 0/* && (data->entries[entry_index].effects & ~EFFECT_STICKY_EXITS) != 0*/) {
			vary_effects_by_registers(search, &analysis->loader, caller, relevant_registers, table_entry->data->preserved_and_kept_registers, table_entry->data->preserved_and_kept_registers, 0);
			if (UNLIKELY(self.token.generation != search->generation)) {
				table_entry = find_searched_instruction_table_entry(search, ins, &self.token);
			}
		}
		if (!validate_offset(table_entry->data, entry_offset)) {
			effects_entry = &table_entry->data->sticky_effects;
		} else {
			struct searched_instruction_data_entry *entry = entry_for_offset(table_entry->data, entry_offset);
			self.token.entry_generation = entry->generation;
			if (entry->effects & EFFECT_PROCESSING) {
				if (!wrote_registers) {
					wrote_registers = true;
					self.current_state = *entry_state;
				}
				if (!registers_are_subset_of_entry_registers(self.current_state.registers, entry, ~relevant_registers)) {
					LOG("queuing because subset of existing processing entry, but expanded set of registers are not subset");
					dump_nonempty_registers(&analysis->loader, &self.current_state, ~relevant_registers);
					queue_instruction(&analysis->search.queue, ins, required_effects & ~EFFECT_PROCESSING, &self.current_state, ins, "in progress");
				}
			}
			effects_entry = &entry->effects;
		}
		effects = *effects_entry;
		if ((effects & required_effects) == required_effects) {
			LOG("skip", temp_str(copy_function_call_description(&analysis->loader, ins, *entry_state)));
			LOG("effects", name_for_effect(effects));
			LOG("passed search for effects", name_for_effect(required_effects));
			return (effects & EFFECT_STICKY_EXITS) ? (effects & ~(EFFECT_STICKY_EXITS | EFFECT_RETURNS)) : effects;
		}
		if (!wrote_registers) {
			self.current_state = *entry_state;
		}
		if (UNLIKELY(effects & EFFECT_STICKY_EXITS)) {
			effects = required_effects | EFFECT_EXITS | EFFECT_STICKY_EXITS;
			*effects_entry = effects;
		} else {
			effects = required_effects;
			*effects_entry = effects/* | EFFECT_RETURNS*/ | EFFECT_PROCESSING;
		}
	};
	self.entry_state = entry_state;
	self.next = caller;
	self.entry = ins;
	self.is_entry = is_entry;
#pragma GCC unroll 64
	for (int i = 0; i < REGISTER_COUNT; i++) {
		self.current_state.sources[i] = (register_mask)1 << i;
	}
	LOG("entering block", temp_str(copy_function_call_description(&analysis->loader, ins, *self.entry_state)));
	register_mask pending_stack_clear = 0;
	for (;;) {
		self.address = ins;
#ifdef STATS
		analyzed_instruction_count++;
#endif
		if (is_return_ins(&decoded)) {
			effects |= EFFECT_RETURNS;
			LOG("completing from return", temp_str(copy_address_description(&analysis->loader, self.entry)));
			goto update_and_return;
		}
#if 0
		if (is_nop_ins(decoded)) {
			LOG("processing a nop", temp_str(copy_address_description(&analysis->loader, ins)));
		}
#endif
		ins_ptr jump_target;
		switch (ins_interpret_jump_behavior(&decoded, &jump_target)) {
			case INS_JUMPS_NEVER:
				break;
			case INS_JUMPS_ALWAYS_INDIRECT:
				// treat indirect jumps like calls for the purpose of the enter calls state
				if ((required_effects & EFFECT_ENTER_CALLS) == 0) {
					analysis->skipped_call = jump_target;
					effects |= EFFECT_EXITS | EFFECT_RETURNS;
					goto update_and_return;
				}
				// fallthrough
			case INS_JUMPS_ALWAYS: {
				LOG("found single jump");
				struct loaded_binary *jump_binary;
				if (jump_target == NULL) {
					LOG("found jump to unfilled address, assuming either exit or return!");
					effects |= EFFECT_EXITS | EFFECT_RETURNS;
				} else if (jump_target == next_ins(ins, &decoded)) {
					LOG("jumping to next instruction, continuing");
					break;
				} else if ((protection_for_address(&analysis->loader, jump_target, &jump_binary, NULL) & PROT_EXEC) == 0) {
#if ABORT_AT_NON_EXECUTABLE_ADDRESS
					self.description = "jump";
					ERROR("found single jump at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
					DIE("to non-executable address", temp_str(copy_address_description(&analysis->loader, jump_target)));
#endif
					LOG("completing from jump to non-executable address", temp_str(copy_address_description(&analysis->loader, self.entry)));
					effects |= EFFECT_EXITS | EFFECT_RETURNS;
				} else if (jump_target >= self.entry && jump_target <= ins) {
					// infinite loop, consider this an exit
					LOG("appears to be an infinite loop");
					effects |= EFFECT_EXITS;
				} else {
					self.description = "jump";
					if (ins == self.entry || (ins == &self.entry[4] && is_landing_pad_ins_decode(self.entry))) {
						set_effects(&analysis->search, self.entry, &self.token, EFFECT_NONE);
					}
					effects |= analyze_instructions(analysis, required_effects, &self.current_state, jump_target, &self, ALLOW_JUMPS_INTO_THE_ABYSS, false) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
					LOG("completing from jump", temp_str(copy_address_description(&analysis->loader, self.entry)));
				}
				goto update_and_return;
			}
			case INS_JUMPS_OR_CONTINUES: {
				effects |= analyze_conditional_branch(analysis, required_effects, ins, &decoded, jump_target, next_ins(ins, &decoded), &self) & ~(EFFECT_AFTER_STARTUP | EFFECT_ENTRY_POINT | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
				goto update_and_return;
			}
		}
		switch (decode_x86_comparisons(decoded, &self.current_state, &analysis->loader, &self.current_state.compare_state)) {
			case INVALID_COMPARISON:
				if (self.current_state.compare_state.validity != COMPARISON_IS_INVALID) {
					self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
					LOG("clearing comparison");
				}
				break;
			case SUPPORTED_COMPARISON:
				LOG("comparing", name_for_register(self.current_state.compare_state.target_register));
				LOG("value", temp_str(copy_register_state_description(&analysis->loader, self.current_state.registers[self.current_state.compare_state.target_register])));
				LOG("with", temp_str(copy_register_state_description(&analysis->loader, self.current_state.compare_state.value)));
				break;
		}
		if (*decoded.unprefixed == 0xff) {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
			if (modrm.reg == 2) { // TODO: do we need this?
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				LOG("found call*");
				if (x86_modrm_is_direct(modrm)) {
					int reg = x86_read_rm(modrm, decoded.prefixes);
					LOG("call to address in register", name_for_register(reg));
					struct register_state address = self.current_state.registers[reg];
					self.description = "call*";
					vary_effects_by_registers(&analysis->search, &analysis->loader, &self, (register_mask)1 << reg, 0, 0, required_effects);
					struct loaded_binary *call_binary;
					if (!register_is_exactly_known(&address)) {
						LOG("address isn't exactly known, assuming all effects");
						// could have any effect
						// effects |= EFFECT_EXITS | EFFECT_RETURNS;
					} else if ((protection_for_address(&analysis->loader, (const void *)address.value, &call_binary, NULL) & PROT_EXEC) == 0) {
#if ABORT_AT_NON_EXECUTABLE_ADDRESS
						self.description = "call*";
						ERROR("found call* at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
						DIE("to non-executable address", temp_str(copy_address_description(&analysis->loader, (const void *)address.value)));
#endif
						LOG("call* to non-executable address, assuming all effects", address.value);
					} else if ((effects & EFFECT_ENTER_CALLS) == 0) {
						LOG("skipping call when searching for address loads");
						analysis->skipped_call = (ins_ptr)address.value;
					} else {
						self.description = "indirect call";
						function_effects more_effects = analyze_call(analysis, required_effects, ins, (ins_ptr)address.value, &self);
						effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
						LOG("resuming", temp_str(copy_address_description(&analysis->loader, self.entry)));
						LOG("resuming from call*", temp_str(copy_address_description(&analysis->loader, ins)));
						if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
							LOG("completing from call to exit-only function", temp_str(copy_address_description(&analysis->loader, self.entry)));
							push_unreachable_breakpoint(&analysis->unreachables, next_ins(ins, &decoded));
							goto update_and_return;
						}
						LOG("function may return, proceeding", name_for_effect(more_effects));
					}
				} else {
					bool is_null;
					struct register_state_and_source address = address_for_indirect(decoded, modrm, &self.current_state, &decoded.unprefixed[2], &analysis->loader, ins, &is_null);
					self.description = "call*";
					vary_effects_by_registers(&analysis->search, &analysis->loader, &self, address.source, 0, 0, required_effects);
					struct loaded_binary *call_address_binary;
					if (!register_is_exactly_known(&address.state)) {
						LOG("address isn't exactly known, assuming all effects");
						// could have any effect
						// effects |= EFFECT_EXITS | EFFECT_RETURNS;
					} else if (is_null) {
						LOG("indirecting through null, assuming read of data that is populated at runtime");
					} else if ((protection_for_address(&analysis->loader, (const void *)address.state.value, &call_address_binary, NULL) & PROT_READ) == 0) {
						LOG("call* indirect to known, but unreadable address", address.state.value);
					} else {
						ins_ptr dest = (ins_ptr)(uintptr_t)*(const x86_uint64 *)address.state.value;
						LOG("dest is", (uintptr_t)dest);
						if (dest) {
							struct loaded_binary *call_binary;
							if ((protection_for_address(&analysis->loader, dest, &call_binary, NULL) & PROT_EXEC) == 0) {
								dump_nonempty_registers(&analysis->loader, &self.current_state, ALL_REGISTERS);
#if ABORT_AT_NON_EXECUTABLE_ADDRESS
								self.description = "call*";
								ERROR("found call* at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
								DIE("to non-executable address", temp_str(copy_address_description(&analysis->loader, dest)));
#endif
								LOG("call* to non-executable address, assuming all effects", temp_str(copy_address_description(&analysis->loader, ins)));
								effects |= EFFECT_EXITS | EFFECT_RETURNS;
							} else if ((effects & EFFECT_ENTER_CALLS) == 0) {
								LOG("skipping call when searching for address loads");
								analysis->skipped_call = dest;
							} else {
								self.description = "indirect call";
								function_effects more_effects = analyze_call(analysis, required_effects, ins, dest, &self);
								effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
								LOG("resuming", temp_str(copy_address_description(&analysis->loader, self.entry)));
								LOG("resuming from call*", temp_str(copy_address_description(&analysis->loader, ins)));
								if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
									LOG("completing from call to exit-only function", temp_str(copy_address_description(&analysis->loader, self.entry)));
									push_unreachable_breakpoint(&analysis->unreachables, next_ins(ins, &decoded));
									goto update_and_return;
								}
								LOG("function may return, proceeding", name_for_effect(more_effects));
							}
						}
					}
				}
				// set_effects(&analysis->search, self.entry, &self.token, effects | EFFECT_PROCESSING);
				clear_call_dirtied_registers(&analysis->loader, &self.current_state, binary_for_address(&analysis->loader, ins), ins);
				clear_stack(&self.current_state);
			} else if (modrm.reg == 3) {
				LOG("found unsupported call*");
				clear_call_dirtied_registers(&analysis->loader, &self.current_state, binary_for_address(&analysis->loader, ins), ins);
				clear_stack(&self.current_state);
			} else if (modrm.reg == 4) {
				// found jmp*
				int reg = x86_read_rm(modrm, decoded.prefixes);
				LOG("jmpq*", name_for_register(reg));
				dump_nonempty_registers(&analysis->loader, &self.current_state, (register_mask)1 << reg);
				self.description = "indirect jump";
				vary_effects_by_registers(&analysis->search, &analysis->loader, &self, (register_mask)1 << reg, jump_status == ALLOW_JUMPS_INTO_THE_ABYSS ? 0 : (register_mask)1 << reg, 0, required_effects);
				ins_ptr new_ins;
				if (x86_modrm_is_direct(modrm)) {
					if (!register_is_exactly_known(&self.current_state.registers[reg])) {
						switch (jump_status) {
							case DISALLOW_JUMPS_INTO_THE_ABYSS:
								ERROR("jmpq* to unknown address", temp_str(copy_address_description(&analysis->loader, self.address)));
								self.description = "jump*";
								DIE("trace", temp_str(copy_call_trace_description(&analysis->loader, &self)));
								break;
							case ALLOW_JUMPS_INTO_THE_ABYSS:
								LOG("jmpq* to unknown address", temp_str(copy_address_description(&analysis->loader, self.address)));
								dump_nonempty_registers(&analysis->loader, &self.current_state, ALL_REGISTERS);
								break;
							case DISALLOW_AND_PROMPT_FOR_DEBUG_SYMBOLS: {
								print_debug_symbol_requirement(binary_for_address(&analysis->loader, ins));
								ERROR_FLUSH();
								fs_exit(1);
								break;
							}
						}
						// could have any effect
						effects |= EFFECT_EXITS | EFFECT_RETURNS;
						LOG("completing from jmpq*", temp_str(copy_address_description(&analysis->loader, self.entry)));
						goto update_and_return;
					}
					new_ins = (ins_ptr)self.current_state.registers[reg].value;
				} else {
					bool is_null;
					struct register_state_and_source address = address_for_indirect(decoded, modrm, &self.current_state, &decoded.unprefixed[2], &analysis->loader, ins, &is_null);
					if (is_null) {
						LOG("indirecting through null, assuming read of data that is populated at runtime");
						// could have any effect
						effects |= EFFECT_EXITS | EFFECT_RETURNS;
						LOG("completing from jmpq*", temp_str(copy_address_description(&analysis->loader, self.entry)));
						goto update_and_return;
					}
					if (!register_is_exactly_known(&address.state)) {
						LOG("address isn't exactly known, assuming all effects");
						// could have any effect
						effects |= EFFECT_EXITS | EFFECT_RETURNS;
						LOG("completing from jmpq*", temp_str(copy_address_description(&analysis->loader, self.entry)));
						goto update_and_return;
					}
					struct loaded_binary *call_address_binary;
					if ((protection_for_address(&analysis->loader, (const void *)address.state.value, &call_address_binary, NULL) & PROT_READ) == 0) {
						switch (jump_status) {
							case DISALLOW_JUMPS_INTO_THE_ABYSS:
								ERROR("jmpq* indirect to known, but unreadable address", temp_str(copy_address_description(&analysis->loader, (const void *)address.state.value)));
								self.description = NULL;
								DIE("at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
								break;
							case ALLOW_JUMPS_INTO_THE_ABYSS:
								LOG("jmpq* indirect to known, but unreadable address", temp_str(copy_address_description(&analysis->loader, (const void *)address.state.value)));
								self.description = NULL;
								LOG("at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
								break;
							case DISALLOW_AND_PROMPT_FOR_DEBUG_SYMBOLS: {
								print_debug_symbol_requirement(binary_for_address(&analysis->loader, ins));
								ERROR_FLUSH();
								fs_exit(1);
								break;
							}
						}
						// could have any effect
						effects |= EFFECT_EXITS | EFFECT_RETURNS;
						LOG("completing from jmpq*", temp_str(copy_address_description(&analysis->loader, self.entry)));
						goto update_and_return;
					}
					new_ins = *(ins_ptr *)address.state.value;
				}
				struct loaded_binary *call_binary;
				if (new_ins == NULL) {
					LOG("address is known, but only filled at runtime, assuming all effects");
					effects |= EFFECT_EXITS | EFFECT_RETURNS;
					LOG("completing from jmpq* to known, but unfilled address", temp_str(copy_address_description(&analysis->loader, self.entry)));
				} else if ((protection_for_address(&analysis->loader, new_ins, &call_binary, NULL) & PROT_EXEC) == 0) {
					dump_nonempty_registers(&analysis->loader, &self.current_state, ALL_REGISTERS);
					effects |= EFFECT_EXITS | EFFECT_RETURNS;
#if ABORT_AT_NON_EXECUTABLE_ADDRESS
					self.description = "jump*";
					ERROR("found jump* at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
					DIE("to non-executable address", temp_str(copy_address_description(&analysis->loader, new_ins)));
#endif
					LOG("completing from jmpq* to non-executable address", temp_str(copy_address_description(&analysis->loader, self.entry)));
				} else {
					effects |= analyze_instructions(analysis, required_effects, &self.current_state, new_ins, caller, ALLOW_JUMPS_INTO_THE_ABYSS, false) & ~(EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS | EFFECT_PROCESSING);
					LOG("completing from jmpq*", temp_str(copy_address_description(&analysis->loader, self.entry)));
				}
				goto update_and_return;
			}
		}
		switch (*decoded.unprefixed) {
			case 0x00: // add r/m8, r8
				perform_basic_op_rm_r_8("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x01: // add r/m, r
				perform_basic_op_rm_r("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x02: // add r8, r/m8
				perform_basic_op_r_rm_8("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x03: // add r, r/m
				perform_basic_op_r_rm("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x04: // add al, imm8
				perform_basic_op_al_imm8("add", basic_op_add, &analysis->loader, &self.current_state, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x05: // add *ax, imm
				perform_basic_op_imm("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, REGISTER_RAX, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x06:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x07:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x08: // or r/m8, r8
				perform_basic_op_rm_r_8("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x09: // or r/m, r
				perform_basic_op_rm_r("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x0a: // or r8, r/m8
				perform_basic_op_r_rm_8("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x0b: // or r, r/m
				perform_basic_op_r_rm("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x0c: // or al, imm8
				perform_basic_op_al_imm8("or", basic_op_or, &analysis->loader, &self.current_state, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x0d: // or *ax, imm
				perform_basic_op_imm("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, REGISTER_RAX, &decoded.unprefixed[1]);
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x0e:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x0f:
				switch (decoded.unprefixed[1]) {
					case 0x00: {
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						switch (modrm.reg) {
							case 0: // sldt r/m16
							case 1: { // str r/m16
								ins_ptr remaining = &decoded.unprefixed[2];
								int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_16BIT, READ_RM_REPLACE_MEM, NULL);
								struct register_state state;
								clear_register(&state);
								truncate_to_16bit(&state);
								self.current_state.registers[rm] = state;
								self.current_state.sources[rm] = 0;
								clear_match(&analysis->loader, &self.current_state, rm, ins);
								break;
							}
							case 2: // lldt r/m16
								break;
							case 3: // ltr r/m16
								break;
							case 4: // verr r/m16
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								break;
							case 5: // verw r/m16
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								break;
							default:
								LOG("invalid opcode extension for 0x0f00", (int)modrm.reg);
								break;
						}
						break;
					}
					case 0x01: {
						switch (decoded.unprefixed[2]) {
							case 0xf9: // rdtscp
								clear_register(&self.current_state.registers[REGISTER_RAX]);
								truncate_to_32bit(&self.current_state.registers[REGISTER_RAX]);
								clear_register(&self.current_state.registers[REGISTER_RDX]);
								truncate_to_32bit(&self.current_state.registers[REGISTER_RDX]);
								clear_register(&self.current_state.registers[REGISTER_RCX]);
								truncate_to_32bit(&self.current_state.registers[REGISTER_RCX]);
								self.current_state.sources[REGISTER_RAX] = 0;
								self.current_state.sources[REGISTER_RDX] = 0;
								self.current_state.sources[REGISTER_RCX] = 0;
								clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
								clear_match(&analysis->loader, &self.current_state, REGISTER_RDX, ins);
								clear_match(&analysis->loader, &self.current_state, REGISTER_RCX, ins);
								break;
						}
						break;
					}
					case 0x05: { // syscall
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						if (register_is_exactly_known(&self.current_state.registers[REGISTER_RAX])) {
						syscall_nr_is_known:
							;
							uintptr_t value = self.current_state.registers[REGISTER_RAX].value;
							LOG("found syscall with known number", (int)value);
							LOG("syscall name is", name_for_syscall(value));
							self.description = NULL;
							LOG("syscall address", temp_str(copy_call_trace_description(&analysis->loader, &self)));
							self.description = "syscall";
							// special case musl's fopen
							if (value == __NR_open && !register_is_partially_known(&self.current_state.registers[syscall_argument_abi_register_indexes[1]])) {
								struct loaded_binary *binary = binary_for_address(&analysis->loader, ins);
								if (binary != NULL && (binary->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_MAIN))) {
									const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, ins, NORMAL_SYMBOL | LINKER_SYMBOL);
									if (name != NULL && (fs_strcmp(name, "fopen") == 0 || fs_strcmp(name, "fopen64") == 0)) {
										size_t count = analysis->search.fopen_mode_count;
										if (count != 0 && register_is_exactly_known(&analysis->search.fopen_modes[count-1])) {
											const char *mode_str = (const char *)analysis->search.fopen_modes[count-1].value;
											struct loaded_binary *mode_binary;
											int prot = protection_for_address(&analysis->loader, mode_str, &mode_binary, NULL);
											if ((prot & (PROT_READ | PROT_WRITE)) == PROT_READ) {
												int mode = musl_fmodeflags(mode_str);
												set_register(&self.current_state.registers[syscall_argument_abi_register_indexes[1]], mode);
											}
										}
									}
								}
							}
							record_syscall(analysis, value, self, required_effects);
							// syscalls always clear RAX and R11
							clear_register(&self.current_state.registers[REGISTER_RAX]);
							self.current_state.sources[REGISTER_RAX] = 0;
							clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
							clear_register(&self.current_state.registers[REGISTER_R11]);
							self.current_state.sources[REGISTER_R11] = 0;
							clear_match(&analysis->loader, &self.current_state, REGISTER_R11, ins);
							switch (info_for_syscall(value).attributes & SYSCALL_RETURN_MASK) {
								case SYSCALL_RETURNS_SELF_PID:
									// getpid fills the pid into RAX
									if (analysis->loader.pid) {
										set_register(&self.current_state.registers[REGISTER_RAX], analysis->loader.pid);
									}
									break;
								case SYSCALL_RETURNS_NEVER:
									// exit and exitgroup always exit the thread, rt_sigreturn always perform a non-local jump
									effects |= EFFECT_EXITS;
									LOG("completing from exit or rt_sigreturn syscall", temp_str(copy_address_description(&analysis->loader, self.entry)));
									goto update_and_return;
							}
						} else if (caller->description != NULL && fs_strcmp(caller->description, ".data.rel.ro") == 0 && binary_has_flags(analysis->loader.main, BINARY_IS_GOLANG)) {
							vary_effects_by_registers(&analysis->search, &analysis->loader, &self, syscall_argument_abi_used_registers_for_argc[6], syscall_argument_abi_used_registers_for_argc[0], syscall_argument_abi_used_registers_for_argc[0], 0);
						} else if (analysis->loader.searching_setxid && analysis->loader.setxid_syscall == NULL) {
							self.description = "syscall";
							analysis->loader.setxid_syscall = self.address;
							analysis->loader.setxid_syscall_entry = self.entry;
							LOG("found setxid dynamic syscall", temp_str(copy_call_trace_description(&analysis->loader, &self)));
						} else if (analysis->loader.searching_setxid_sighandler && analysis->loader.setxid_sighandler_syscall == NULL) {
							self.description = "syscall";
							analysis->loader.setxid_sighandler_syscall = self.address;
							analysis->loader.setxid_sighandler_syscall_entry = self.entry;
							LOG("found setxid_sighandler dynamic syscall", temp_str(copy_call_trace_description(&analysis->loader, &self)));
						} else if (self.address == analysis->loader.setxid_sighandler_syscall) {
							self.description = NULL;
							LOG("unknown setxid_sighandler syscall, assumed covered by set*id handlers", temp_str(copy_call_trace_description(&analysis->loader, &self)));
						} else if (self.address == analysis->loader.setxid_syscall) {
							self.description = NULL;
							LOG("unknown setxid syscall, assumed covered by set*id handlers", temp_str(copy_call_trace_description(&analysis->loader, &self)));
						} else {
							struct loaded_binary *binary = binary_for_address(&analysis->loader, ins);
							if (binary != NULL) {
								if (binary->special_binary_flags & BINARY_IS_INTERPRETER) {
									// a giant hack -- this is for musl's cancel_handler comparing the interrupted pc to __cp_begin and __cp_end
									if (self.entry[0] == 0x49 && self.entry[1] == 0x89 && self.entry[2] == 0xfb) {
										if (self.entry[3] == 0x48 && self.entry[4] == 0x89 && self.entry[5] == 0xf0) {
											if (self.entry[6] == 0x48 && self.entry[7] == 0x89 && self.entry[8] == 0xd7) {
												if (self.entry[9] == 0x48 && self.entry[10] == 0x89 && self.entry[11] == 0xce) {
													if (self.entry[12] == 0x4C && self.entry[13] == 0x89 && self.entry[14] == 0xc2) {
														if (self.entry[15] == 0x4D && self.entry[16] == 0x89 && self.entry[17] == 0xca) {
															self.description = NULL;
															LOG("found musl __cp_begin", temp_str(copy_call_trace_description(&analysis->loader, &self)));
															return EFFECT_NONE;
														}
													}
												}
											}
										}
									}
								}
								if (binary->special_binary_flags & (BINARY_IS_LIBC | BINARY_IS_INTERPRETER | BINARY_IS_MAIN)) {
									const char *name = find_any_symbol_name_by_address(&analysis->loader, binary, ins, NORMAL_SYMBOL | LINKER_SYMBOL);
									if (name != NULL && fs_strcmp(name, "next_line") == 0) {
										// this is a giant hack
										self.current_state.registers[REGISTER_RAX].value = self.current_state.registers[REGISTER_RAX].max = __NR_read;
										goto syscall_nr_is_known;
									}
									if (analysis->loader.setxid_syscall == NULL || analysis->loader.setxid_sighandler_syscall == NULL) {
										for (const struct analysis_frame *frame = self.next; frame != NULL; frame = frame->next) {
											name = find_any_symbol_name_by_address(&analysis->loader, binary, frame->entry, NORMAL_SYMBOL | LINKER_SYMBOL);
											if (name != NULL) {
												if (is_setxid_name(name)) {
													if (analysis->loader.setxid_syscall == NULL) {
														self.description = NULL;
														analysis->loader.setxid_syscall = self.address;
														analysis->loader.setxid_syscall_entry = self.entry;
														LOG("found __nptl_setxid/do_setxid", temp_str(copy_call_trace_description(&analysis->loader, &self)));
														goto finish_syscall;
													}
												} else if (fs_strcmp(name, "pthread_create") == 0) {
													if (analysis->loader.setxid_sighandler_syscall == NULL) {
														self.description = NULL;
														analysis->loader.setxid_sighandler_syscall = self.address;
														analysis->loader.setxid_sighandler_syscall_entry = self.entry;
														LOG("found __nptl_setxid_sighandler", temp_str(copy_call_trace_description(&analysis->loader, &self)));
														goto finish_syscall;
													}
												}
											}
										}
									}
									if (analysis->loader.setxid_syscall == self.address || analysis->loader.setxid_sighandler_syscall == self.address) {
										goto finish_syscall;
									}
								}
							}
							self.description = NULL;
							ERROR("found syscall with unknown number", temp_str(copy_register_state_description(&analysis->loader, self.current_state.registers[REGISTER_RAX])));
							if (SHOULD_LOG) {
								register_mask relevant_registers = 1 << REGISTER_RAX;
								for (const struct analysis_frame *ancestor = &self;;) {
									ERROR("from call site", temp_str(copy_address_description(&analysis->loader, ancestor->address)));
									register_mask new_relevant_registers = 0;
									for_each_bit(relevant_registers, bit, i) {
										new_relevant_registers |= ancestor->current_state.sources[i];
									}
									if (new_relevant_registers == 0) {
										ERROR("using no registers from block entry", temp_str(copy_address_description(&analysis->loader, ancestor->entry)));
										break;
									}
									ERROR("using registers from block entry", temp_str(copy_address_description(&analysis->loader, ancestor->entry)));
									dump_registers(&analysis->loader, &ancestor->current_state, new_relevant_registers);
									ancestor = (struct analysis_frame *)ancestor->next;
									if (ancestor == NULL) {
										break;
									}
									relevant_registers = new_relevant_registers;
								}
							}
							self.description = NULL;
							ERROR("full call stack", temp_str(copy_call_trace_description(&analysis->loader, &self)));
							dump_nonempty_registers(&analysis->loader, &self.current_state, ALL_REGISTERS);
							clear_register(&self.current_state.registers[REGISTER_RAX]);
							self.current_state.sources[REGISTER_RAX] = 0;
							clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
							clear_register(&self.current_state.registers[REGISTER_R11]);
							self.current_state.sources[REGISTER_R11] = 0;
							clear_match(&analysis->loader, &self.current_state, REGISTER_R11, ins);
							if (required_effects & EFFECT_AFTER_STARTUP) {
								analysis->syscalls.unknown = true;
							}
							DIE("try blocking a function from the call stack using --block-function or --block-debug-function");
						}
					finish_syscall:
						break;
					}
					case 0x0b: // ud2
						effects |= EFFECT_EXITS;
						LOG("completing from ud2", temp_str(copy_address_description(&analysis->loader, self.entry)));
						goto update_and_return;
					case 0x0d: // noop
						break;
					case 0x11: { // movups xmm/m, xmm
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_64BIT, READ_RM_REPLACE_MEM, NULL);
						if (rm >= REGISTER_MEM) {
							LOG("movups to mem", name_for_register(rm));
							struct register_state value;
							x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
							if (x86_read_reg(modrm, decoded.prefixes) == REGISTER_R15 && binary_has_flags(binary_for_address(&analysis->loader, ins), BINARY_IS_GOLANG)) {
								set_register(&value, 0);
								LOG("found golang 0 register");
							} else {
								clear_register(&value);
								LOG("assuming any value");
							}
							self.current_state.registers[rm] = value;
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
							pending_stack_clear &= ~((register_mask)1 << rm);
							if (rm >= REGISTER_STACK_0 && rm < REGISTER_COUNT - 2) {
								self.current_state.registers[rm+2] = value;
								self.current_state.sources[rm+2] = 0;
								clear_match(&analysis->loader, &self.current_state, rm+2, ins);
								pending_stack_clear &= ~((register_mask)1 << (rm + 2));
							}
						}
						goto skip_stack_clear;
					}
					case 0x2c: { // cvttss2si r, xmm
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0x2d: { // cvttsd2si r, xmm
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0x2e: { // ucomiss xmm, xmm/m
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						break;
					}
					case 0x2f: { // comiss xmm, xmm/m
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						break;
					}
					case 0x31: // rdtsc
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						truncate_to_32bit(&self.current_state.registers[REGISTER_RAX]);
						self.current_state.sources[REGISTER_RAX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						clear_register(&self.current_state.registers[REGISTER_RDX]);
						truncate_to_32bit(&self.current_state.registers[REGISTER_RDX]);
						self.current_state.sources[REGISTER_RDX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RDX, ins);
						break;
					case 0x38:
						switch (decoded.unprefixed[2]) {
							case 0x17: { // ptest
								LOG("ptest");
								break;
							}
							case 0xf0: { // movbe r, r/m or crc32 r, r/m8
								x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[3]);
								int reg = x86_read_reg(modrm, decoded.prefixes);
								clear_register(&self.current_state.registers[reg]);
								self.current_state.sources[reg] = 0;
								clear_match(&analysis->loader, &self.current_state, reg, ins);
								break;
							}
							case 0xf1: {
								x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[3]);
								if (decoded.prefixes.has_repne) { // crc32 r, r/m
									int reg = x86_read_reg(modrm, decoded.prefixes);
									clear_register(&self.current_state.registers[reg]);
									self.current_state.sources[reg] = 0;
									clear_match(&analysis->loader, &self.current_state, reg, ins);
								} else { // movbe r/m, r
									ins_ptr remaining = &decoded.unprefixed[3];
									int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
									clear_register(&self.current_state.registers[rm]);
									self.current_state.sources[rm] = 0;
									clear_match(&analysis->loader, &self.current_state, rm, ins);
								}
								break;
							}
						}
						break;
					case 0x3a:
						switch (decoded.unprefixed[2]) {
							case 0x14: { // pextrb r/m8, xmm2, imm8
								ins_ptr remaining = &decoded.unprefixed[3];
								int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, sizeof(int8_t), &self.current_state, OPERATION_SIZE_8BIT, READ_RM_KEEP_MEM, NULL);
								if (rm != REGISTER_INVALID) {
									bool is_legacy = register_is_legacy_8bit_high(decoded.prefixes, &rm);
									clear_register(&self.current_state.registers[rm]);
									if (is_legacy) {
										truncate_to_16bit(&self.current_state.registers[rm]);
									} else {
										truncate_to_8bit(&self.current_state.registers[rm]);
									}
									self.current_state.sources[rm] = 0;
									clear_match(&analysis->loader, &self.current_state, rm, ins);
								}
								break;
							}
							case 0x16: { // pextrd/q r/m, xmm2, imm8
								ins_ptr remaining = &decoded.unprefixed[3];
								int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, sizeof(int8_t), &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
								if (rm != REGISTER_INVALID) {
									clear_register(&self.current_state.registers[rm]);
									truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
									self.current_state.sources[rm] = 0;
									clear_match(&analysis->loader, &self.current_state, rm, ins);
								}
								break;
							}
							case 0x17: { // extractps r/m32, xmm1, imm8
								ins_ptr remaining = &decoded.unprefixed[3];
								int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, sizeof(int8_t), &self.current_state, OPERATION_SIZE_32BIT, READ_RM_KEEP_MEM, NULL);
								if (rm != REGISTER_INVALID) {
									clear_register(&self.current_state.registers[rm]);
									truncate_to_32bit(&self.current_state.registers[rm]);
									self.current_state.sources[rm] = 0;
									clear_match(&analysis->loader, &self.current_state, rm, ins);
								}
								break;
							}
							case 0x60: { // pcmpestrm
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								break;
							}
							case 0x61: { // pcmpestri xmm1, xmm2/m128, imm8
								clear_register(&self.current_state.registers[REGISTER_RCX]);
								truncate_to_32bit(&self.current_state.registers[REGISTER_RCX]);
								self.current_state.sources[REGISTER_RCX] = 0;
								clear_match(&analysis->loader, &self.current_state, REGISTER_RCX, ins);
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								break;
							}
							case 0x62: { // pcmpistrm
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								break;
							}
							case 0x63: { // pcmpistri xmm1, xmm2/m128, imm8
								clear_register(&self.current_state.registers[REGISTER_RCX]);
								truncate_to_32bit(&self.current_state.registers[REGISTER_RCX]);
								self.current_state.sources[REGISTER_RCX] = 0;
								clear_match(&analysis->loader, &self.current_state, REGISTER_RCX, ins);
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								break;
							}
						}
						break;
					case 0x40: // cmovcc
					case 0x41:
					case 0x42:
					case 0x43:
					case 0x44:
					case 0x45:
					case 0x46:
					case 0x47:
					case 0x48:
					case 0x49:
					case 0x4a:
					case 0x4b:
					case 0x4c:
					case 0x4d:
					case 0x4e:
					case 0x4f: {
						LOG("found cmovcc");
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int dest = x86_read_reg(modrm, decoded.prefixes);
						ins_ptr remaining = &decoded.unprefixed[2];
						int source = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						LOG("from", name_for_register(source));
						LOG("to", name_for_register(dest));
						dump_registers(&analysis->loader, &self.current_state, ((register_mask)1 << dest) | ((register_mask)1 << source));
						switch (calculate_possible_conditions(x86_get_conditional_type(&decoded.unprefixed[1]), &self.current_state)) {
							case ALWAYS_MATCHES:
								LOG("conditional always matches");
								self.current_state.registers[dest] = self.current_state.registers[source];
								add_match_and_copy_sources(&analysis->loader, &self.current_state, dest, source, ins);
								self.current_state.sources[dest] |= self.current_state.compare_state.sources;
								break;
							case NEVER_MATCHES:
								LOG("conditional never matches");
								self.current_state.sources[dest] |= self.current_state.compare_state.sources;
								break;
							case POSSIBLY_MATCHES:
								LOG("conditional sometimes matches");
								if (register_is_partially_known(&self.current_state.registers[dest]) && register_is_partially_known(&self.current_state.registers[source])) {
									if (self.current_state.registers[source].value < self.current_state.registers[dest].value) {
										self.current_state.registers[dest].value = self.current_state.registers[source].value;
									}
									if (self.current_state.registers[source].max > self.current_state.registers[dest].max) {
										self.current_state.registers[dest].max = self.current_state.registers[source].max;
									}
									self.current_state.sources[dest] |= self.current_state.sources[source];
								} else {
									clear_register(&self.current_state.registers[dest]);
									self.current_state.sources[dest] = 0;
								}
								clear_match(&analysis->loader, &self.current_state, dest, ins);
								break;
						}
						break;
					}
					case 0x57: { // xorps xmm1, xmm2/m128
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						if (x86_modrm_is_direct(modrm) && reg == x86_read_rm(modrm, decoded.prefixes)) {
							LOG("found xor with self in SSE, zeroing idiom", reg);
							ins_ptr lookahead = next_ins(ins, &decoded);
							struct decoded_ins lookahead_decoded;
							if (decode_ins(lookahead, &lookahead_decoded)) {
								LOG("lookahead", temp_str(copy_address_description(&analysis->loader, lookahead)));
								LOG("length", lookahead_decoded.length);
								if (lookahead_decoded.unprefixed[0] == 0x0f && lookahead_decoded.unprefixed[1] == 0x11) { // movups xmm2/m128, xmm1
									x86_mod_rm_t lookahead_modrm = x86_read_modrm(&lookahead_decoded.unprefixed[2]);
									if (reg == x86_read_reg(lookahead_modrm, lookahead_decoded.prefixes)) {
										ins_ptr lookahead_temp = lookahead;
										int lookahead_rm = read_rm_ref(&analysis->loader, lookahead_decoded.prefixes, &lookahead_temp, 0, &self.current_state, OPERATION_SIZE_64BIT, READ_RM_REPLACE_MEM, NULL);
										LOG("found xorps+movps, zeroing idiom to register", name_for_register(lookahead_rm));
										set_register(&self.current_state.registers[lookahead_rm], 0);
										self.current_state.sources[lookahead_rm] = 0;
										clear_match(&analysis->loader, &self.current_state, lookahead_rm, ins);
										if (lookahead_rm >= REGISTER_STACK_0 && lookahead_rm < REGISTER_COUNT - 2) {
											LOG("zeroing idiom was to the stack, zeroing the next register as well", name_for_register(lookahead_rm+2));
											set_register(&self.current_state.registers[lookahead_rm+2], 0);
											self.current_state.sources[lookahead_rm+2] = 0;
											clear_match(&analysis->loader, &self.current_state, lookahead_rm+2, ins);
										}
										// skip the lookahead
										decoded = lookahead_decoded;
										ins = lookahead;
									}
								}
							}
						}
						break;
					}
					case 0x7e: { // movd/q r/m, mm
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
						if (rm != REGISTER_INVALID) {
							clear_register(&self.current_state.registers[rm]);
							if (!decoded.prefixes.has_w) {
								truncate_to_32bit(&self.current_state.registers[rm]);
							}
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
							pending_stack_clear &= ~((register_mask)1 << rm);
						}
						goto skip_stack_clear;
					}
					case 0x80: // conditional jumps
					case 0x81:
					case 0x82:
					case 0x83:
					case 0x84:
					case 0x85:
					case 0x86:
					case 0x87:
					case 0x88:
					case 0x89:
					case 0x8a:
					case 0x8b:
					case 0x8c:
					case 0x8d:
					case 0x8e:
					case 0x8f: {
						break;
					}
					case 0x90:
					case 0x91:
					case 0x92:
					case 0x93:
					case 0x94:
					case 0x95:
					case 0x96:
					case 0x97:
					case 0x98:
					case 0x99:
					case 0x9a:
					case 0x9b:
					case 0x9c:
					case 0x9d:
					case 0x9e:
					case 0x9f: {
						LOG("found setcc", temp_str(copy_address_description(&analysis->loader, ins)));
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						LOG("to", name_for_register(rm));
						switch (calculate_possible_conditions(x86_get_conditional_type(&decoded.unprefixed[1]), &self.current_state)) {
							case ALWAYS_MATCHES:
								LOG("conditional always matches");
								self.current_state.registers[rm].value = 1;
								self.current_state.registers[rm].max = 1;
								self.current_state.sources[rm] = self.current_state.compare_state.sources;
								break;
							case NEVER_MATCHES:
								LOG("conditional never matches");
								self.current_state.registers[rm].value = 0;
								self.current_state.registers[rm].max = 0;
								self.current_state.sources[rm] = self.current_state.compare_state.sources;
								break;
							case POSSIBLY_MATCHES:
								LOG("conditional sometimes matches");
								self.current_state.registers[rm].value = 0;
								self.current_state.registers[rm].max = 1;
								self.current_state.sources[rm] = 0;
								break;
						}
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						break;
					}
					case 0xa0: { // push fs
						push_stack(&self.current_state, 2);
						dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
						break;
					}
					case 0xa1: { // pop fs
						pop_stack(&self.current_state, 2);
						dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
						break;
					}
					case 0xa2: { // cpuid
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						truncate_to_32bit(&self.current_state.registers[REGISTER_RAX]);
						self.current_state.sources[REGISTER_RAX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						clear_register(&self.current_state.registers[REGISTER_RBX]);
						truncate_to_32bit(&self.current_state.registers[REGISTER_RBX]);
						self.current_state.sources[REGISTER_RBX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RBX, ins);
						clear_register(&self.current_state.registers[REGISTER_RCX]);
						truncate_to_32bit(&self.current_state.registers[REGISTER_RCX]);
						self.current_state.sources[REGISTER_RCX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RCX, ins);
						clear_register(&self.current_state.registers[REGISTER_RDX]);
						truncate_to_32bit(&self.current_state.registers[REGISTER_RDX]);
						self.current_state.sources[REGISTER_RDX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RDX, ins);
						break;
					}
					case 0xa3: { // bt r/m, r
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						break;
					}
					case 0xa4: { // shld r/m, r, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, sizeof(int8_t), &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
						if (rm != REGISTER_INVALID) {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
						}
						break;
					}
					case 0xa5: { // shld r/m, r, cl
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
						if (rm != REGISTER_INVALID) {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
						}
						break;
					}
					case 0xa8: { // push gs
						push_stack(&self.current_state, 2);
						dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
						break;
					}
					case 0xa9: { // pop gs
						pop_stack(&self.current_state, 2);
						dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
						break;
					}
					case 0xab: { // bts r/m, r
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
						if (rm != REGISTER_INVALID) {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
						}
						break;
					}
					case 0xac: { // shrd r/m, r, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, sizeof(int8_t), &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
						if (rm != REGISTER_INVALID) {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
						}
						break;
					}
					case 0xad: { // shrd r/m, r, cl
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
						if (rm != REGISTER_INVALID) {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
						}
						break;
					}
					case 0xaf: { // imul r, r/m
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						truncate_to_size_prefixes(&self.current_state.registers[reg], decoded.prefixes);
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xb0: { // cmpxchg r/m8, r8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						truncate_to_8bit(&self.current_state.registers[REGISTER_RAX]);
						self.current_state.sources[REGISTER_RAX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
						if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_16bit(&self.current_state.registers[rm]);
						} else {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_8bit(&self.current_state.registers[rm]);
						}
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						// TODO: check why this happens only in golang
						// if (self.current_state.stack_address_taken == STACK_ADDRESS_TAKEN_GOLANG) {
						// 	clear_stack(&self.current_state);
						// }
						break;
					}
					case 0xb1: { // cmpxchg r/m, r
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						truncate_to_size_prefixes(&self.current_state.registers[REGISTER_RAX], decoded.prefixes);
						self.current_state.sources[REGISTER_RAX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						// TODO: check why this happens only in golang
						// if (self.current_state.stack_address_taken == STACK_ADDRESS_TAKEN_GOLANG) {
						// 	clear_stack(&self.current_state);
						// }
						break;
					}
					case 0xb2: { // lss
						break;
					}
					case 0xb3: { // btr r/m, r
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						clear_register(&self.current_state.registers[rm]);
						truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						break;
					}
					case 0xb4: { // lfs
						break;
					}
					case 0xb5: { // lgs
						break;
					}
					case 0xb6: // movzx r, r/m8
					case 0xb7: { // movzx r, r/m16
						LOG("found movzx");
						int dest = x86_read_reg(x86_read_modrm(&decoded.unprefixed[2]), decoded.prefixes);
						LOG("to", name_for_register(dest));
						ins_ptr remaining = &decoded.unprefixed[2];
						int source_size = decoded.unprefixed[1] == 0xb6 ? OPERATION_SIZE_8BIT : OPERATION_SIZE_16BIT;
						struct register_state src;
						int source = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, source_size, READ_RM_KEEP_MEM, &src);
						LOG("from", name_for_register(source));
						uintptr_t mask = source_size == OPERATION_SIZE_8BIT ? 0xff : 0xffff;
						if (source == REGISTER_INVALID || (source_size == OPERATION_SIZE_8BIT ? register_is_legacy_8bit_high(decoded.prefixes, &source) : false)) {
							clear_register(&src);
						}
						if (source == REGISTER_MEM) {
							LOG("decoded mem r/m", temp_str(copy_decoded_rm_description(&analysis->loader, self.current_state.mem_rm)));
							if (self.current_state.mem_rm.rm == REGISTER_STACK_0 && self.current_state.mem_rm.index != REGISTER_SP) {
								int base = self.current_state.mem_rm.base;
								int index = self.current_state.mem_rm.index;
								uintptr_t base_addr = self.current_state.registers[base].value + self.current_state.mem_rm.addr;
								uintptr_t value = self.current_state.registers[index].value;
								uintptr_t max = self.current_state.registers[index].max;
								struct loaded_binary *mov_binary;
								if (protection_for_address(&analysis->loader, (const void *)(base_addr + value * sizeof(uint32_t)), &mov_binary, NULL) & PROT_READ) {
									if (max - value > MAX_LOOKUP_TABLE_SIZE) {
										LOG("unsigned lookup table rejected because range of index is too large", max - value);
										self.description = "rejected lookup table";
										LOG("trace", temp_str(copy_call_trace_description(&analysis->loader, &self)));
									} else {
										self.description = "lookup table";
										vary_effects_by_registers(&analysis->search, &analysis->loader, &self, ((register_mask)1 << base) | ((register_mask)1 << index), (register_mask)1 << base/* | ((register_mask)1 << index)*/, (register_mask)1 << base/* | ((register_mask)1 << index)*/, required_effects);
										LOG("unsigned lookup table from known base", temp_str(copy_address_description(&analysis->loader, (void *)base_addr)));
										dump_registers(&analysis->loader, &self.current_state, ((register_mask)1 << base) | ((register_mask)1 << index));
										struct registers copy = self.current_state;
										copy.sources[dest] = self.current_state.sources[base] | self.current_state.sources[index];
										clear_match(&analysis->loader, &copy, dest, ins);
										ins_ptr continue_target = next_ins(ins, &decoded);
										for (uintptr_t i = value; i != max + 1; i++) {
											LOG("processing table index", i);
											LOG("processing table value", (intptr_t)((ins_ptr)base_addr)[i]);
											LOG("processing table target (if jump table)", temp_str(copy_address_description(&analysis->loader, (void *)base_addr + ((ins_ptr)base_addr)[i])));
											if (index != dest) {
												set_register(&copy.registers[index], i);
												for_each_bit(copy.matches[index], bit, r) {
													set_register(&copy.registers[r], i);
												}
											}
											set_register(&copy.registers[dest], dest);
											effects |= analyze_instructions(analysis, required_effects, &copy, continue_target, &self, ALLOW_JUMPS_INTO_THE_ABYSS, false) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
											LOG("next table case for", temp_str(copy_address_description(&analysis->loader, self.address)));
										}
										LOG("completing from lookup table", temp_str(copy_address_description(&analysis->loader, self.entry)));
										goto update_and_return;
									}
								}
							}
						}
						self.current_state.registers[dest] = src;
						if (source != REGISTER_INVALID) {
							add_match_and_copy_sources(&analysis->loader, &self.current_state, dest, source, ins);
						} else {
							clear_match(&analysis->loader, &self.current_state, dest, ins);
							self.current_state.sources[dest] = 0;
						}
						if (register_is_exactly_known(&self.current_state.registers[dest]) || (register_is_partially_known(&self.current_state.registers[dest]) && self.current_state.registers[dest].max <= mask)) {
							// zero extension where we can provide a range
							self.current_state.registers[dest].value &= mask;
							self.current_state.registers[dest].max &= mask;
						} else {
							// zero extension of indeterminate value leaves only the mask
							self.current_state.registers[dest].value = 0;
							self.current_state.registers[dest].max = mask;
						}
						dump_registers(&analysis->loader, &self.current_state, (register_mask)1 << dest);
						break;
					}
					case 0xb8: { // popcnt r, r/m
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						self.current_state.registers[reg].value = 0;
						if (decoded.prefixes.has_w) {
							self.current_state.registers[reg].max = 64;
						} else if (decoded.prefixes.has_operand_size_override) {
							self.current_state.registers[reg].max = 16;
						} else {
							self.current_state.registers[reg].max = 32;
						}
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xb9:
						effects |= EFFECT_EXITS;
						LOG("completing from ud1", temp_str(copy_address_description(&analysis->loader, self.entry)));
						goto update_and_return;
					case 0xba: {
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						switch (modrm.reg) {
							case 4: // bt r/m, imm8
							case 5: // bts r/m, imm8
							case 6: // btr r/m, imm8
							case 7: { // btc r/m, imm8
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								ins_ptr remaining = &decoded.unprefixed[2];
								int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, sizeof(int8_t), &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
								if (rm != REGISTER_INVALID) {
									clear_register(&self.current_state.registers[rm]);
									truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
									self.current_state.sources[rm] = 0;
									clear_match(&analysis->loader, &self.current_state, rm, ins);
								}
								break;
							}
						}
						break;
					}
					case 0xbb: { // btc r/m, r
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
						if (rm != REGISTER_INVALID) {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
							self.current_state.sources[rm] = 0;
							clear_match(&analysis->loader, &self.current_state, rm, ins);
						}
						break;
					}
					case 0xbc: // bsf r, r/m or tzcnt r, r/m
					case 0xbd: { // bsr r, r/m
						if (decoded.unprefixed[1] == 0xbc) {
							if (decoded.prefixes.has_rep) {
								LOG("tzcnt");
							} else {
								LOG("bsf");
							}
						} else {
							LOG("bsr");
						}
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						self.current_state.registers[reg].value = 0;
						if (decoded.prefixes.has_w) {
							self.current_state.registers[reg].max = 63;
						} else if (decoded.prefixes.has_operand_size_override) {
							self.current_state.registers[reg].max = 15;
						} else {
							self.current_state.registers[reg].max = 31;
						}
						if (decoded.prefixes.has_rep) { // tzcnt
							self.current_state.registers[reg].max++;
						}
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xbe: { // movsx r, r/m8
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
						LOG("movsx r to", name_for_register(reg));
						LOG("from r/m8", name_for_register(rm));
						if (!register_is_legacy_8bit_high(decoded.prefixes, &rm) && self.current_state.registers[rm].max < 0x80 && register_is_partially_known_8bit(&self.current_state.registers[rm])) {
							self.current_state.registers[reg] = self.current_state.registers[rm];
							add_match_and_copy_sources(&analysis->loader, &self.current_state, reg, rm, ins);
							break;
						}
						clear_register(&self.current_state.registers[reg]);
						truncate_to_size_prefixes(&self.current_state.registers[reg], decoded.prefixes);
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xbf: { // movsx r, r/m
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						LOG("movsx r to", name_for_register(reg));
						LOG("from r/m", name_for_register(rm));
						if (self.current_state.registers[rm].max < 0x8000 && register_is_partially_known_16bit(&self.current_state.registers[rm])) {
							self.current_state.registers[reg] = self.current_state.registers[rm];
							add_match_and_copy_sources(&analysis->loader, &self.current_state, reg, rm, ins);
							break;
						}
						clear_register(&self.current_state.registers[reg]);
						truncate_to_size_prefixes(&self.current_state.registers[reg], decoded.prefixes);
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xc0: { // xadd r/m8, r8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						clear_register(&self.current_state.registers[rm]);
						if (!register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
							truncate_to_8bit(&self.current_state.registers[rm]);
						}
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						if (!register_is_legacy_8bit_high(decoded.prefixes, &reg)) {
							truncate_to_8bit(&self.current_state.registers[reg]);
						}
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xc1: { // xadd r/m, r
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[2];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						clear_register(&self.current_state.registers[rm]);
						truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						truncate_to_size_prefixes(&self.current_state.registers[reg], decoded.prefixes);
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xc5: { // pextrw reg, mm, imm8
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						truncate_to_size_prefixes(&self.current_state.registers[reg], decoded.prefixes);
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xc7: {
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						switch (modrm.reg) {
							case 1: // cmpxchg8/16b m64
								self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
								clear_register(&self.current_state.registers[REGISTER_RAX]);
								if (!decoded.prefixes.has_w) {
									truncate_to_32bit(&self.current_state.registers[REGISTER_RAX]);
								}
								self.current_state.sources[REGISTER_RAX] = 0;
								clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
								clear_register(&self.current_state.registers[REGISTER_RDX]);
								if (!decoded.prefixes.has_w) {
									truncate_to_32bit(&self.current_state.registers[REGISTER_RDX]);
								}
								self.current_state.sources[REGISTER_RDX] = 0;
								clear_match(&analysis->loader, &self.current_state, REGISTER_RDX, ins);
								break;
						}
						break;
					}
					case 0xc8: // bswap
					case 0xc9:
					case 0xca:
					case 0xcb:
					case 0xcc:
					case 0xcd:
					case 0xce:
					case 0xcf: {
						int reg = x86_read_opcode_register_index(decoded.unprefixed[1], 0xc8, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						if (!decoded.prefixes.has_w) {
							truncate_to_32bit(&self.current_state.registers[reg]);
						}
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xd7: { // pmovmskb reg, mm
						x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[2]);
						int reg = x86_read_reg(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[reg]);
						if (decoded.prefixes.has_operand_size_override) {
							truncate_to_16bit(&self.current_state.registers[reg]);
						} else {
							truncate_to_8bit(&self.current_state.registers[reg]);
						}
						self.current_state.sources[reg] = 0;
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						break;
					}
					case 0xff:
						effects |= EFFECT_EXITS;
						LOG("completing from ud0", temp_str(copy_address_description(&analysis->loader, self.entry)));
						goto update_and_return;
				}
				break;
			case 0x10: // adc r/m8, r8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_rm_r_8("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x11: // adc r/m, r
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_rm_r("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x12: // adc r8, r/m8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm_8("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x13: // adc r, r/m
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x14: // adc al, imm8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_al_imm8("adc", basic_op_adc, &analysis->loader, &self.current_state, &decoded.unprefixed[1]);
				break;
			case 0x15: // adc *ax, imm
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_imm("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, REGISTER_RAX, &decoded.unprefixed[1]);
				break;
			case 0x16:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x17:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x18: // sbb r/m8, r8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_rm_r_8("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x19: // sbb r/m, r
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_rm_r("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x1a: // sbb r8, r/m8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm_8("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x1b: // sbb r, r/m
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x1c: // sbb al, imm8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_al_imm8("sbb", basic_op_sbb, &analysis->loader, &self.current_state, &decoded.unprefixed[1]);
				break;
			case 0x1d: // sbb *ax, imm
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_imm("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, REGISTER_RAX, &decoded.unprefixed[1]);
				break;
			case 0x1e:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x1f:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x20: // and r/m8, r8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_rm_r_8("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x21: // and r/m, r
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_rm_r("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x22: // and r8, r/m8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm_8("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x23: // and r, r/m
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x24: // and al, imm8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_al_imm8("and", basic_op_and, &analysis->loader, &self.current_state, &decoded.unprefixed[1]);
				break;
			case 0x25: // and *ax, imm
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_imm("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, REGISTER_RAX, &decoded.unprefixed[1]);
				break;
			case 0x26:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x27:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x28: { // sub r/m8, r8
				int rm = perform_basic_op_rm_r_8("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
				set_compare_from_operation(&self.current_state, rm, 0xff);
				break;
			}
			case 0x29: { // sub r/m, r
				int rm = perform_basic_op_rm_r("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
				set_compare_from_operation(&self.current_state, rm, mask_for_size_prefixes(decoded.prefixes));
				break;
			}
			case 0x2a: { // sub r8, r/m8
				int reg = perform_basic_op_r_rm_8("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
				set_compare_from_operation(&self.current_state, reg, 0xff);
				break;
			}
			case 0x2b: { // sub r, r/m
				int reg = perform_basic_op_r_rm("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
				set_compare_from_operation(&self.current_state, reg, mask_for_size_prefixes(decoded.prefixes));
				break;
			}
			case 0x2c: { // sub al, imm8
				perform_basic_op_al_imm8("sub", basic_op_sub, &analysis->loader, &self.current_state, &decoded.unprefixed[1]);
				// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
				set_compare_from_operation(&self.current_state, REGISTER_RAX, 0xff);
				break;
			}
			case 0x2d: {// sub *ax, imm
				perform_basic_op_imm("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, REGISTER_RAX, &decoded.unprefixed[1]);
				// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
				set_compare_from_operation(&self.current_state, REGISTER_RAX, mask_for_size_prefixes(decoded.prefixes));
				break;
			}
			case 0x2e:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x2f:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x30: // xor r/m8, r8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_rm_r_8("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				break;
			case 0x31: { // xor r/m, r
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				if (x86_modrm_is_direct(modrm) && reg == x86_read_rm(modrm, decoded.prefixes)) {
					LOG("found xor with self, zeroing idiom", name_for_register(reg));
					set_register(&self.current_state.registers[reg], 0);
					self.current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self.current_state, reg, ins);
				} else {
					perform_basic_op_rm_r("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				}
				goto skip_stack_clear;
			}
			case 0x32: // xor r8, r/m8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm_8("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				goto skip_stack_clear;
			case 0x33: // xor r, r/m
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_r_rm("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
				goto skip_stack_clear;
			case 0x34: // xor al, imm8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_al_imm8("xor", basic_op_xor, &analysis->loader, &self.current_state, &decoded.unprefixed[1]);
				goto skip_stack_clear;
			case 0x35: // xor *ax, imm
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				perform_basic_op_imm("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, REGISTER_RAX, &decoded.unprefixed[1]);
				goto skip_stack_clear;
			case 0x36: // null prefix
				break;
			case 0x37:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x38: // cmp r/m8, r8
				break;
			case 0x39: // cmp r/m, r
				break;
			case 0x3a: // cmp r8, r/m8
				break;
			case 0x3b: // cmp r, r/m
				break;
			case 0x3c: // cmp al, imm8
				break;
			case 0x3d: // cmp r, imm
				break;
			case 0x3e: // null prefix
				break;
			case 0x3f:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x40: // rex
				break;
			case 0x41: // rex.b
				break;
			case 0x42: // rex.x
				break;
			case 0x43: // rex.xb
				break;
			case 0x44: // rex.r
				break;
			case 0x45: // rex.rb
				break;
			case 0x46: // rex.rx
				break;
			case 0x47: // rex.rxb
				break;
			case 0x48: // rex.w
				break;
			case 0x49: // rex.wb
				break;
			case 0x4a: // rex.wx
				break;
			case 0x4b: // rex.wxb
				break;
			case 0x4c: // rex.wr
				break;
			case 0x4d: // rex.wrb
				break;
			case 0x4e: // rex.wrx
				break;
			case 0x4f: // rex.wrxb
				break;
			case 0x50: // push
			case 0x51:
			case 0x52:
			case 0x53:
			case 0x54:
			case 0x55:
			case 0x56:
			case 0x57: {
				int reg = x86_read_opcode_register_index(*decoded.unprefixed, 0x50, decoded.prefixes);
				LOG("push", name_for_register(reg));
				if (decoded.prefixes.has_operand_size_override) {
					clear_match(&analysis->loader, &self.current_state, REGISTER_SP, ins);
				} else {
					push_stack(&self.current_state, 2);
				}
				self.current_state.registers[REGISTER_STACK_0] = self.current_state.registers[reg];
				self.current_state.sources[REGISTER_STACK_0] = self.current_state.sources[reg];
				if (decoded.prefixes.has_operand_size_override) {
					truncate_to_16bit(&self.current_state.registers[REGISTER_STACK_0]);
				}
				dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
				break;
			}
			case 0x58: // pop
			case 0x59:
			case 0x5a:
			case 0x5b:
			case 0x5c:
			case 0x5d:
			case 0x5e:
			case 0x5f: {
				int reg = x86_read_opcode_register_index(*decoded.unprefixed, 0x58, decoded.prefixes);
				LOG("pop", name_for_register(reg));
				jump_status = ALLOW_JUMPS_INTO_THE_ABYSS;
				self.current_state.registers[reg] = self.current_state.registers[REGISTER_STACK_0];
				self.current_state.sources[reg] = self.current_state.sources[REGISTER_STACK_0];
				if (decoded.prefixes.has_operand_size_override) {
					truncate_to_16bit(&self.current_state.registers[REGISTER_STACK_0]);
				}
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				if (decoded.prefixes.has_operand_size_override) {
					clear_match(&analysis->loader, &self.current_state, REGISTER_SP, ins);
				} else {
					pop_stack(&self.current_state, 2);
				}
				dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
				break;
			}
			case 0x60:
			case 0x61:
			case 0x62:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x63: {
				// found movsxd
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				LOG("movsxd", name_for_register(reg));
				if (modrm.mod != 0x3 && (modrm.rm == REGISTER_R12 || modrm.rm == REGISTER_SP)) {
					// read SIB
					x86_sib_t sib = x86_read_sib(&decoded.unprefixed[2]);
					int base = x86_read_base(sib, decoded.prefixes);
					int index = x86_read_index(sib, decoded.prefixes);
					LOG("movsxd dest", name_for_register(reg));
					LOG("movsxd base", name_for_register(base));
					LOG("movsxd index", name_for_register(index));
					LOG("movsxd scale", (int)1 << sib.scale);
					dump_registers(&analysis->loader, &self.current_state, (register_mask)1 << base | (register_mask)1 << index);
					if (sib.scale == 0x2) {
						int32_t displacement = 0;
						switch (modrm.mod) {
							case 0:
								// no displacement
								break;
							case 1:
								// 8 bit displacement
								displacement = *(int8_t *)&decoded.unprefixed[3];
								break;
							case 2:
								// 32 bit displacement
								displacement = *(x86_int32 *)&decoded.unprefixed[3];
								break;
						}
						struct registers copy = self.current_state;
						uintptr_t base_addr = 0;
						if (register_is_exactly_known(&self.current_state.registers[base])) {
							base_addr = self.current_state.registers[base].value + displacement;
							LOG("storing base address", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
							add_lookup_table_base_address(&analysis->search.lookup_base_addresses, ins, base_addr);
						}
						if (base_addr == 0) {
							base_addr = find_lookup_table_base_address(&analysis->search.lookup_base_addresses, ins);
							if (base_addr != 0) {
#if 0
								LOG("reusing previous base address", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
#else
								LOG("missing base address for lookup table that previously had a base address, skipping");
								effects = (effects | EFFECT_EXITS) & ~EFFECT_RETURNS;
								goto update_and_return;
#endif
							}
							set_register(&copy.registers[base], base_addr);
							clear_match(&analysis->loader, &copy, base, ins);
							copy.sources[base] = 0;
							clear_match(&analysis->loader, &self.current_state, base, ins);
							self.current_state.sources[base] = 0;
						}
						if (base_addr != 0) {
							uintptr_t value = self.current_state.registers[index].value;
							uintptr_t max = self.current_state.registers[index].max;
							// const void *first_entry_addr = (const void *)(base_addr + value * sizeof(uint32_t));
							struct loaded_binary *binary;
							LOG("looking up protection for base", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
							const ElfW(Shdr) *section;
							int prot = protection_for_address(&analysis->loader, (const void *)base_addr, &binary, &section);
							if ((prot & (PROT_READ | PROT_WRITE)) == PROT_READ) {
								// enforce max range from other lea instructions
								uintptr_t next_base_address = search_find_next_loaded_address(&analysis->search, base_addr);
								if ((next_base_address - base_addr) / sizeof(int32_t) <= max) {
									LOG("truncating to next base address", temp_str(copy_address_description(&analysis->loader, (const void *)next_base_address)));
									max = ((next_base_address - base_addr) / sizeof(int32_t)) - 1;
								}
								uintptr_t max_in_section = ((uintptr_t)apply_base_address(&binary->info, section->sh_addr) + section->sh_size - base_addr) / 4;
								if (max >= max_in_section) {
									max = max_in_section - 1;
									if (value >= max_in_section) {
										LOG("somehow in a jump table without a proper value, bailing");
										goto update_and_return;
									}
								}
								struct frame_details frame_details = { 0 };
								bool has_frame_details = binary->has_frame_info ? find_containing_frame_info(&binary->frame_info, ins, &frame_details) : false;
								const ElfW(Sym) *function_symbol = NULL;
								uintptr_t override_size = size_of_jump_table_from_metadata(&analysis->loader, binary, (const void *)base_addr, ins, (max - value > MAX_LOOKUP_TABLE_SIZE && !has_frame_details) ? DEBUG_SYMBOL_FORCING_LOAD : DEBUG_SYMBOL, &function_symbol);
								if (override_size != 0) {
									max = override_size - 1;
									LOG("overwrote maximum of signed lookup table to", max);
								}
								if ((max - value > MAX_LOOKUP_TABLE_SIZE) && !has_frame_details && (function_symbol == NULL)) {
									LOG("signed lookup table rejected because range of index is too large", max - value);
									dump_registers(&analysis->loader, &self.current_state, ((register_mask)1 << base) | ((register_mask)1 << index));
									self.description = "rejected lookup table";
									LOG("trace", temp_str(copy_call_trace_description(&analysis->loader, &self)));
									jump_status = binary && !binary->has_debuglink_symbols ? DISALLOW_AND_PROMPT_FOR_DEBUG_SYMBOLS : DISALLOW_JUMPS_INTO_THE_ABYSS;
								} else {
									self.description = "lookup table";
									vary_effects_by_registers(&analysis->search, &analysis->loader, &self, ((register_mask)1 << base) | ((register_mask)1 << index), (register_mask)1 << base | ((register_mask)1 << index), (register_mask)1 << base/* | ((register_mask)1 << index)*/, required_effects);
									LOG("signed lookup table from known base", temp_str(copy_address_description(&analysis->loader, (void *)base_addr)));
									dump_registers(&analysis->loader, &self.current_state, ((register_mask)1 << base) | ((register_mask)1 << index));
									copy.sources[reg] = self.current_state.sources[base] | self.current_state.sources[index];
									clear_match(&analysis->loader, &copy, reg, ins);
									ins_ptr continue_target = next_ins(ins, &decoded);
									for (uintptr_t i = value; i <= max; i++) {
										LOG("processing table index", (intptr_t)i);
										int32_t relative = ((const x86_int32 *)base_addr)[i];
										LOG("processing table value", (intptr_t)relative);
										ins_ptr jump_addr = (ins_ptr)base_addr + relative;
										LOG("processing table target (if jump table)", temp_str(copy_address_description(&analysis->loader, jump_addr)));
										if (!lookup_table_jump_is_valid(binary, has_frame_details ? &frame_details : NULL, function_symbol, jump_addr)) {
											LOG("detected jump table beyond bounds, truncating", i);
											break;
										}
										if (index != reg) {
											set_register(&copy.registers[index], i);
											for_each_bit(copy.matches[index], bit, r) {
												set_register(&copy.registers[r], i);
											}
										}
										set_register(&copy.registers[reg], relative);
										effects |= analyze_instructions(analysis, required_effects, &copy, continue_target, &self, DISALLOW_JUMPS_INTO_THE_ABYSS, false) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
										LOG("next table case for", temp_str(copy_address_description(&analysis->loader, self.address)));
										// re-enforce max range from other lea instructions that may have loaded addresses in the meantime
										next_base_address = search_find_next_loaded_address(&analysis->search, base_addr);
										if ((next_base_address - base_addr) / sizeof(int32_t) <= max) {
											max = ((next_base_address - base_addr) / sizeof(int32_t)) - 1;
										}
									}
									LOG("completing from lookup table", temp_str(copy_address_description(&analysis->loader, self.entry)));
									goto update_and_return;
								}
								// jump_status = DISALLOW_JUMPS_INTO_THE_ABYSS;
							} else {
								if ((prot & PROT_READ) == 0) {
									LOG("lookup table from unreadable base", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
								} else {
									LOG("lookup table from writable base", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
								}
							}
						} else {
							LOG("lookup table from unknown base");
							// jump_status = DISALLOW_JUMPS_INTO_THE_ABYSS;
						}
					} else {
						LOG("invalid scale for lookup table");
					}
				}
				ins_ptr remaining = &decoded.unprefixed[1];
				struct register_state source;
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, &source);
				if (register_is_exactly_known(&source)) {
					if (decoded.prefixes.has_operand_size_override) {
						int16_t truncated = (int16_t)source.value;
						set_register(&self.current_state.registers[reg], (uintptr_t)(intptr_t)truncated);
					} else {
						int32_t truncated = (int32_t)source.value;
						set_register(&self.current_state.registers[reg], (uintptr_t)(intptr_t)truncated);
					}
					// TODO: read sources for case where rm is REGISTER_INVALID
					self.current_state.sources[reg] = rm != REGISTER_INVALID ? self.current_state.sources[rm] : 0;
				} else {
					clear_register(&self.current_state.registers[reg]);
					self.current_state.sources[reg] = 0;
				}
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				break;
			}
			case 0x64: // FS segment override prefix
				break;
			case 0x65: // GS segment override prefix
				break;
			case 0x66: // operand size override prefix
				break;
			case 0x67: // address size override prefix
				break;
			case 0x68: // push imm
				break;
			case 0x69: { // imul r, r/m, imm
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				LOG("imul dest", name_for_register(reg));
				clear_register(&self.current_state.registers[reg]);
				self.current_state.sources[reg] = 0;
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				break;
			}
			case 0x6a: // push imm8
				break;
			case 0x6b: { // imul r, r/m, imm8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				LOG("imul dest", name_for_register(reg));
				clear_register(&self.current_state.registers[reg]);
				self.current_state.sources[reg] = 0;
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				break;
			}
			case 0x6c: // insb
			case 0x6d: // outs
				// TODO: handle the ins family of instructions
				break;
			case 0x6e: // outsb
			case 0x6f: // outs
				// TODO: handle the outs family of instructions
				break;
			case 0x70: // jo
				break;
			case 0x71: // jno
				break;
			case 0x72: // jb/jnae/jc
				break;
			case 0x73: // jnb/jae/jnc
				break;
			case 0x74: // jz/je
				break;
			case 0x75: // jnz/jne
				break;
			case 0x76: // jbe/jna
				break;
			case 0x77: // jbne/ja
				break;
			case 0x78: // js
				break;
			case 0x79: // jns
				break;
			case 0x7a: // jp/jpe
				break;
			case 0x7b: // jnp/jpo
				break;
			case 0x7c: // jl/jnge
				break;
			case 0x7d: // jnl/jge
				break;
			case 0x7e: // jle/jng
				break;
			case 0x7f: // jnle/jg
				break;
			case 0x80: {
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 0: // add r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm8_imm8("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 1: // or r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm8_imm8("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 2: // adc r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm8_imm8("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 3: // sbb r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm8_imm8("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 4: // and r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm8_imm8("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 5: { // sub r/m, imm8
						int rm = perform_basic_op_rm8_imm8("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						set_compare_from_operation(&self.current_state, rm, 0xff);
						break;
					}
					case 6: // xor r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm8_imm8("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 7: // cmp r/m, imm8
						// TODO: handle cmp
						break;
				}
				break;
			}
			case 0x81: {
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 0: // add r/m, imm
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 1: // or r/m, imm
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 2: // adc r/m, imm
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 3: // sbb r/m, imm
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 4: // and r/m, imm
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 5: { // sub r/m, imm
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						int rm = perform_basic_op_rm_imm("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						set_compare_from_operation(&self.current_state, rm, mask_for_size_prefixes(decoded.prefixes));
						break;
					}
					case 6: // xor r/m, imm
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 7: // cmp r/m, imm
						// TODO: handle cmp
						break;
				}
				break;
			}
			case 0x82:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x83: {
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 0: { // add r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						if (decoded.prefixes.has_w && modrm.mod == 0x3 && x86_read_rm(modrm, decoded.prefixes) == REGISTER_SP) {
							// handle stack operations
							int8_t imm = *(const int8_t *)&decoded.unprefixed[2];
							if ((imm & 0x3) == 0) {
								if (imm <= 0) {
									push_stack(&self.current_state, -(imm >> 2));
								} else {
									pop_stack(&self.current_state, imm >> 2);
								}
								struct register_state src;
								set_register(&src, imm);
								basic_op_add(&self.current_state.registers[REGISTER_SP], &src, REGISTER_SP, -1);
								canonicalize_register(&self.current_state.registers[REGISTER_SP]);
								dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
								break;
							}
						}
						perform_basic_op_rm_imm8("add", basic_op_add, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					}
					case 1: // or r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm8("or", basic_op_or, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 2: // adc r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm8("adc", basic_op_adc, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 3: // sbb r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm8("sbb", basic_op_sbb, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 4: // and r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm8("and", basic_op_and, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 5: { // sub r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						if (decoded.prefixes.has_w && modrm.mod == 0x3 && x86_read_rm(modrm, decoded.prefixes) == REGISTER_SP) {
							// handle stack operations
							int8_t imm = *(const int8_t *)&decoded.unprefixed[2];
							if ((imm & 0x3) == 0 && imm >= 0) {
								if (imm <= 0) {
									pop_stack(&self.current_state, -(imm >> 2));
								} else {
									push_stack(&self.current_state, imm >> 2);
								}
								struct register_state src;
								set_register(&src, imm);
								basic_op_sub(&self.current_state.registers[REGISTER_SP], &src, REGISTER_SP, -1);
								canonicalize_register(&self.current_state.registers[REGISTER_SP]);
								dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
								break;
							}
						}
						int rm = perform_basic_op_rm_imm8("sub", basic_op_sub, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						set_compare_from_operation(&self.current_state, rm, mask_for_size_prefixes(decoded.prefixes));
						break;
					}
					case 6: // xor r/m, imm8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						perform_basic_op_rm_imm8("xor", basic_op_xor, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 7: // cmp r/m, imm8
						// TODO: handle cmp
						break;
				}
				break;
			}
			case 0x84: // test r/m8, r8
				// TODO: handle test
				break;
			case 0x85: // test r/m, r
				// TODO: handle test
				break;
			case 0x86: { // xchg r8, r/m8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				bool reg_is_legacy = register_is_legacy_8bit_high(decoded.prefixes, &reg);
				struct register_state dest = self.current_state.registers[reg];
				if (reg_is_legacy) {
					clear_register(&dest);
				}
				truncate_to_8bit(&dest);
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
				bool rm_is_legacy = register_is_legacy_8bit_high(decoded.prefixes, &rm);
				struct register_state source = self.current_state.registers[rm];
				if (rm_is_legacy) {
					clear_register(&dest);
				}
				truncate_to_8bit(&source);
				self.current_state.registers[reg] = source;
				if (reg_is_legacy) {
					clear_register(&self.current_state.registers[reg]);
				}
				self.current_state.registers[rm] = dest;
				if (rm_is_legacy) {
					clear_register(&self.current_state.registers[rm]);
				}
				register_mask rm_sources = self.current_state.sources[rm];
				self.current_state.sources[rm] = self.current_state.sources[reg];
				self.current_state.sources[reg] = rm_sources;
				clear_match(&analysis->loader, &self.current_state, rm, ins);
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				pending_stack_clear &= ~((register_mask)1 << rm);
				break;
			}
			case 0x87: { // xchg r, r/m
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				struct register_state dest = self.current_state.registers[reg];
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
				truncate_to_size_prefixes(&dest, decoded.prefixes);
				struct register_state source = self.current_state.registers[rm];
				truncate_to_size_prefixes(&source, decoded.prefixes);
				self.current_state.registers[reg] = source;
				self.current_state.registers[rm] = dest;
				register_mask rm_sources = self.current_state.sources[rm];
				self.current_state.sources[rm] = self.current_state.sources[reg];
				self.current_state.sources[reg] = rm_sources;
				clear_match(&analysis->loader, &self.current_state, rm, ins);
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				pending_stack_clear &= ~((register_mask)1 << rm);
				break;
			}
			case 0x88: { // mov r/m8, r8
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				LOG("mov r/m8 to", name_for_register(rm));
				LOG("from r8", name_for_register(reg));
				if (reg == REGISTER_SP) {
					record_stack_address_taken(&analysis->loader, ins, &self.current_state);
				}
				struct register_state source = self.current_state.registers[reg];
				if (register_is_legacy_8bit_high(decoded.prefixes, &reg)) {
					clear_register(&source);
				}
				truncate_to_8bit(&source);
				if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
					clear_register(&source);
					clear_match(&analysis->loader, &self.current_state, rm, ins);
				} else {
					add_match_and_copy_sources(&analysis->loader, &self.current_state, rm, reg, ins);
				}
				self.current_state.registers[rm] = source;
				if (register_is_partially_known_8bit(&source)) {
					LOG("value is known", temp_str(copy_register_state_description(&analysis->loader, source)));
				} else {
					LOG("value is unknown", temp_str(copy_register_state_description(&analysis->loader, source)));
					self.current_state.sources[rm] = 0;
				}
				pending_stack_clear &= ~((register_mask)1 << rm);
				goto skip_stack_clear;
			}
			case 0x89: { // mov r/m, r
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				LOG("mov r/m to", name_for_register(rm));
				LOG("from r", name_for_register(reg));
				if (reg == REGISTER_SP) {
					record_stack_address_taken(&analysis->loader, ins, &self.current_state);
				}
				struct register_state source = self.current_state.registers[reg];
				if (register_is_exactly_known(&source) && source.value > mask_for_size_prefixes(decoded.prefixes) && binary_for_address(&analysis->loader, (const void *)source.value) != NULL) {
					clear_register(&source);
					clear_match(&analysis->loader, &self.current_state, rm, ins);
					self.current_state.sources[rm] = 0;
				} else {
					add_match_and_copy_sources(&analysis->loader, &self.current_state, rm, reg, ins);
				}
				truncate_to_size_prefixes(&source, decoded.prefixes);
				self.current_state.registers[rm] = source;
				if (register_is_partially_known_size_prefixes(&source, decoded.prefixes)) {
					LOG("value is known", temp_str(copy_register_state_description(&analysis->loader, source)));
				} else {
					LOG("value is unknown", temp_str(copy_register_state_description(&analysis->loader, source)));
					self.current_state.sources[rm] = 0;
				}
				pending_stack_clear &= ~((register_mask)1 << rm);
				goto skip_stack_clear;
			}
			case 0x8a: { // mov r8, r/m8
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				ins_ptr remaining = &decoded.unprefixed[1];
				struct register_state source;
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_KEEP_MEM, &source);
				LOG("mov r8 to", name_for_register(reg));
				LOG("from r/m8", name_for_register(rm));
				if (SHOULD_LOG) {
					if (UNLIKELY(pending_stack_clear) && rm >= REGISTER_STACK_0) {
						LOG("mov from stack after a call, assuming reload of stack spill");
					}
				}
				if (rm != REGISTER_INVALID) {
					pending_stack_clear &= ~((register_mask)1 << rm);
				}
				if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
					clear_register(&source);
				}
				truncate_to_8bit(&source);
				if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
					clear_register(&source);
					clear_match(&analysis->loader, &self.current_state, reg, ins);
					self.current_state.sources[reg] = 0;
				} else if (rm != REGISTER_INVALID) {
					add_match_and_copy_sources(&analysis->loader, &self.current_state, reg, rm, ins);
				} else {
					clear_match(&analysis->loader, &self.current_state, reg, ins);
					self.current_state.sources[reg] = 0;
				}
				self.current_state.registers[reg] = source;
				if (register_is_partially_known_8bit(&source)) {
					LOG("value is known", temp_str(copy_register_state_description(&analysis->loader, source)));
				} else {
					LOG("value is unknown", temp_str(copy_register_state_description(&analysis->loader, source)));
					self.current_state.sources[reg] = 0;
				}
				goto skip_stack_clear;
			}
			case 0x8b: { // mov r, r/m
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded.prefixes);
				LOG("mov r to", name_for_register(reg));
				ins_ptr remaining = &decoded.unprefixed[1];
				struct register_state source;
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, &source);
				LOG("from r/m", name_for_register(rm));
				if (SHOULD_LOG) {
					if (UNLIKELY(pending_stack_clear) && rm >= REGISTER_STACK_0) {
						LOG("mov from stack after a call, assuming reload of stack spill");
					}
				}
				if (rm != REGISTER_INVALID) {
					pending_stack_clear &= ~((register_mask)1 << rm);
					if (register_is_exactly_known(&source) && source.value > mask_for_size_prefixes(decoded.prefixes) && binary_for_address(&analysis->loader, (const void *)source.value) != NULL) {
						clear_register(&source);
						truncate_to_size_prefixes(&source, decoded.prefixes);
						clear_match(&analysis->loader, &self.current_state, reg, ins);
						self.current_state.sources[reg] = self.current_state.sources[rm];
					} else {
						add_match_and_copy_sources(&analysis->loader, &self.current_state, reg, rm, ins);
					}
				} else {
					clear_match(&analysis->loader, &self.current_state, reg, ins);
					self.current_state.sources[reg] = 0;
				}
				self.current_state.registers[reg] = source;
				if (register_is_partially_known_size_prefixes(&source, decoded.prefixes)) {
					LOG("value is known", temp_str(copy_register_state_description(&analysis->loader, source)));
				} else {
					LOG("value is unknown", temp_str(copy_register_state_description(&analysis->loader, source)));
					self.current_state.sources[reg] = 0;
				}
				goto skip_stack_clear;
			}
			case 0x8c: { // mov r/m, Sreg
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
				clear_register(&self.current_state.registers[rm]);
				truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
				self.current_state.sources[rm] = 0;
				clear_match(&analysis->loader, &self.current_state, rm, ins);
				pending_stack_clear &= ~((register_mask)1 << rm);
				break;
			}
			case 0x8d: { // lea r, r/m (only indirect!)
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				LOG("found lea");
				if (x86_modrm_is_direct(modrm)) {
					self.description = NULL;
					LOG("lea with direct addressing mode at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
					break;
				}
				int reg = x86_read_reg(modrm, decoded.prefixes);
				LOG("lea to", name_for_register(reg));
				struct register_state_and_source new_value = address_for_indirect(decoded, modrm, &self.current_state, &decoded.unprefixed[2], &analysis->loader, ins, NULL);
				// when an address is taken to the stack, clear all of the stack entries
				if (new_value.source & ((register_mask)1 << REGISTER_SP)) {
					// if (reg == REGISTER_RBP) {
					// 	LOG("ignoring address of stack (since it's to rbp)", temp_str(copy_address_description(&analysis->loader, self.address)));
					// } else
					record_stack_address_taken(&analysis->loader, self.address, &self.current_state);
				}
				self.current_state.registers[reg] = new_value.state;
				self.current_state.sources[reg] = new_value.source;
				dump_registers(&analysis->loader, &self.current_state, (register_mask)1 << reg);
				truncate_to_size_prefixes(&self.current_state.registers[reg], decoded.prefixes);
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				if (register_is_partially_known(&new_value.state)) {
					dump_register(&analysis->loader, new_value.state);
					self.description = "load address";
					vary_effects_by_registers(&analysis->search, &analysis->loader, &self, new_value.source, 0, 0, required_effects);
				}
				if (decoded.prefixes.has_w) {
					if (register_is_exactly_known(&self.current_state.registers[reg])) {
						ins_ptr address = (ins_ptr)self.current_state.registers[reg].value;
						struct loaded_binary *binary = binary_for_address(&analysis->loader, address);
						if (binary == NULL) {
							LOG("rip-relative lea is to unknown binary");
							break;
						}
						int prot = protection_for_address_in_binary(binary, (uintptr_t)address, NULL);
						if (prot & PROT_EXEC) {
							bool should_skip_lea = false;
							for (int i = 0; i < SKIPPED_LEA_AREA_COUNT; i++) {
								ins_ptr skipped_address = analysis->known_symbols.skipped_lea_areas[i].address;
								if (skipped_address == NULL) {
									break;
								}
								if (skipped_address <= address && skipped_address + analysis->known_symbols.skipped_lea_areas[i].size > address) {
									should_skip_lea = true;
									break;
								}
							}
							if (should_skip_lea) {
								LOG("discarding lea into skipped lea section");
								clear_register(&self.current_state.registers[reg]);
								self.current_state.sources[reg] = 0;
							} else if (address[0] == 0x98 && address[1] == 0x2f && address[2] == 0x8a && address[3] == 0x42 && address[4] == 0x91) {
								LOG("discarding lea into openssl's K256 table");
								clear_register(&self.current_state.registers[reg]);
								self.current_state.sources[reg] = 0;
							} else if (address[0] == 0x5b && address[1] == 0xc2 && address[2] == 0x56 && address[3] == 0x39 && address[4] == 0x5b) {
								// see: https://github.com/openssl/openssl/blob/master/crypto/sha/asm/sha256-mb-x86_64.pl#L291
								LOG("discarding lea into offset 128 of openssl's K256 table");
								clear_register(&self.current_state.registers[reg]);
								self.current_state.sources[reg] = 0;
							} else if (address[0] == 0x5b && address[1] == 0xc2 && address[2] == 0x56 && address[3] == 0x39 && address[4] == 0x5b) {
								// see: https://github.com/openssl/openssl/blob/master/crypto/sha/asm/sha256-mb-x86_64.pl#L291
								LOG("discarding lea into offset 128 of openssl's K256 table");
								clear_register(&self.current_state.registers[reg]);
								self.current_state.sources[reg] = 0;
							} else {
								self.description = "load address";
								if (required_effects & EFFECT_ENTRY_POINT) {
									if (reg == sysv_argument_abi_register_indexes[0]) {
										// main
										analysis->main = (uintptr_t)address;
										LOG("rip-relative lea is to executable address, assuming it is the main function");
										self.description = "load main address";
										analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, address, &self);
									} else if (reg == sysv_argument_abi_register_indexes[3]) {
										// init, will be called before main, can skip it
									} else if (reg == sysv_argument_abi_register_indexes[4] || reg == sysv_argument_abi_register_indexes[5]) {
										LOG("rip-relative lea is to executable address, assuming it is the finit function");
										analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, address, &self);
									} else {
										LOG("rip-relative lea is to executable address, assuming it could be called during startup");
										analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, address, &self);
									}
								} else {
									LOG("rip-relative lea is to executable address, assuming it could be called after startup");
									if (effects & EFFECT_ENTER_CALLS) {
										queue_instruction(&analysis->search.queue, address, ((binary->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_LIBC)) == BINARY_IS_INTERPRETER) ? required_effects : ((required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS), &empty_registers, self.address, "lea");
										//analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, address, &self);
									}
								}
							}
						} else if (prot & PROT_READ) {
							if ((effects & EFFECT_ENTER_CALLS) == 0) {
								if (analysis->address_loaded != NULL) {
									analysis->address_loaded(analysis, address, &self, analysis->address_loaded_data);
								}
							} else {
								add_loaded_address(&analysis->search, (uintptr_t)address);
								LOG("rip-relative lea is to readable address, assuming it is data");
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
										if (protection_for_address_in_binary(binary, data, NULL) & PROT_EXEC) {
											LOG("found reference to executable address at", temp_str(copy_address_description(&analysis->loader, &symbol_data[i])));
											LOG("value of address is, assuming callable", temp_str(copy_address_description(&analysis->loader, (ins_ptr)data)));
											self.description = "load address";
											struct analysis_frame new_caller = { .address = &symbol_data[i], .description = "skipped symbol in data section", .next = &self, .current_state = empty_registers, .entry = (void *)&symbol_data[i], .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
											analyze_function(analysis, effects, &empty_registers, (ins_ptr)data, &new_caller);
										}
									}
									if (binary->special_binary_flags & BINARY_IS_LIBCRYPTO) {
										analyze_libcrypto_dlopen(analysis);
										analysis->loader.searching_libcrypto_dlopen = false;
									}
								}
							}
						} else {
							LOG("rip-relative lea is to unreadable address, not sure what it is");
						}
					} else {
						LOG("rip-relative lea is to variable address, assuming it is data");
					}
				}
				break;
			}
			case 0x8e: // mov Sreg, r/m
				break;
			case 0x8f: { // pop r/m
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
				struct register_state empty;
				clear_register(&empty);
				truncate_to_size_prefixes(&empty, decoded.prefixes);
				self.current_state.registers[rm] = empty;
				self.current_state.sources[rm] = 0;
				clear_match(&analysis->loader, &self.current_state, rm, ins);
				break;
			}
			case 0x90: // xchg ax, ax
				// this is a nop!
				break;
			case 0x91: // xchg r, r
			case 0x92:
			case 0x93:
			case 0x94:
			case 0x95: 
			case 0x96:
			case 0x97: {
				int reg = x86_read_opcode_register_index(*decoded.unprefixed, 0x90, decoded.prefixes);
				struct register_state dest = self.current_state.registers[reg];
				struct register_state source = self.current_state.registers[REGISTER_RAX];
				truncate_to_size_prefixes(&dest, decoded.prefixes);
				truncate_to_size_prefixes(&source, decoded.prefixes);
				self.current_state.registers[reg] = source;
				self.current_state.registers[REGISTER_RAX] = dest;
				register_mask rax_sources = self.current_state.sources[REGISTER_RAX];
				self.current_state.sources[REGISTER_RAX] = self.current_state.sources[reg];
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				self.current_state.sources[reg] = rax_sources;
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				break;
			}
			case 0x98: { // cbw/cwde/cdqe
				if (decoded.prefixes.has_w) {
					if (self.current_state.registers[REGISTER_RAX].max >= 0x80000000) {
						truncate_to_32bit(&self.current_state.registers[REGISTER_RAX]);
						if (!register_is_partially_known_32bit(&self.current_state.registers[REGISTER_RAX])) {
							self.current_state.sources[REGISTER_RAX] = 0;
						}
						if (self.current_state.registers[REGISTER_RAX].max >= 0x80000000) {
							self.current_state.registers[REGISTER_RAX].max = (intptr_t)(int32_t)self.current_state.registers[REGISTER_RAX].max;
						}
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
					}
				} else {
					if (self.current_state.registers[REGISTER_RAX].max >= 0x80) {
						truncate_to_8bit(&self.current_state.registers[REGISTER_RAX]);
						if (!register_is_partially_known_8bit(&self.current_state.registers[REGISTER_RAX])) {
							self.current_state.sources[REGISTER_RAX] = 0;
						}
						if (self.current_state.registers[REGISTER_RAX].max >= 0x80) {
							self.current_state.registers[REGISTER_RAX].max = (intptr_t)(int8_t)self.current_state.registers[REGISTER_RAX].max;
							truncate_to_size_prefixes(&self.current_state.registers[REGISTER_RAX], decoded.prefixes);
						}
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
					}
				}
				break;
			}
			case 0x9a:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0x9b: // fwait/wait
				break;
			case 0x9c: // pushf
				break;
			case 0x9d: // popf
				break;
			case 0x9e: // sahf 
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0x9f: // lahf
				clear_register(&self.current_state.registers[REGISTER_RAX]);
				self.current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				break;
			case 0xa0: // mov al, moffs8
				clear_register(&self.current_state.registers[REGISTER_RAX]);
				truncate_to_8bit(&self.current_state.registers[REGISTER_RAX]);
				self.current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				break;
			case 0xa1: // mov *ax, moffs
				clear_register(&self.current_state.registers[REGISTER_RAX]);
				truncate_to_size_prefixes(&self.current_state.registers[REGISTER_RAX], decoded.prefixes);
				self.current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				break;
			case 0xa2: // mov moffs8, al
				break;
			case 0xa3: // mov moffs, *ax
				break;
			case 0xa4: // movs m8, m8
				break;
			case 0xa5: // movs m, m
				break;
			case 0xa6: // cmps m8, m8
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xa7: // cmps m, m
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xa8: // test al, imm8
				// TODO: implement test
				break;
			case 0xa9: // test *ax, imm
				// TODO: implement test
				break;
			case 0xaa: // stos m8, al
				break;
			case 0xab: // stos m, *ax
				break;
			case 0xac: // lods m, al
				clear_register(&self.current_state.registers[REGISTER_RAX]);
				truncate_to_8bit(&self.current_state.registers[REGISTER_RAX]);
				self.current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				break;
			case 0xad: // lods m, *ax
				clear_register(&self.current_state.registers[REGISTER_RAX]);
				truncate_to_size_prefixes(&self.current_state.registers[REGISTER_RAX], decoded.prefixes);
				self.current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				break;
			case 0xae: // scas m8, al
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xaf: // scas m, *ax
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xb0: // mov r8, imm8
			case 0xb1:
			case 0xb2:
			case 0xb3:
			case 0xb4: 
			case 0xb5:
			case 0xb6:
			case 0xb7: {
				int reg = x86_read_opcode_register_index(*decoded.unprefixed, 0xb0, decoded.prefixes);
				LOG("mov r8 to", name_for_register(reg));
				struct register_state dest;
				dest.value = (uint8_t)decoded.unprefixed[1];
				dest.max = dest.value;
				LOG("value is immediate", temp_str(copy_register_state_description(&analysis->loader, dest)));
				self.current_state.registers[reg] = dest;
				self.current_state.sources[reg] = 0;
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				goto skip_stack_clear;
			}
			case 0xb8: // mov r, imm
			case 0xb9:
			case 0xba:
			case 0xbb:
			case 0xbc: 
			case 0xbd:
			case 0xbe:
			case 0xbf: {
				int reg = x86_read_opcode_register_index(*decoded.unprefixed, 0xb8, decoded.prefixes);
				LOG("mov r to", name_for_register(reg));
				struct register_state dest;
				dest.value = decoded.prefixes.has_w ? *(const x86_uint64 *)&decoded.unprefixed[1] : read_imm(decoded.prefixes, &decoded.unprefixed[1]);
				dest.max = dest.value;
				LOG("value is immediate", temp_str(copy_register_state_description(&analysis->loader, dest)));
				self.current_state.registers[reg] = dest;
				self.current_state.sources[reg] = 0;
				clear_match(&analysis->loader, &self.current_state, reg, ins);
				void *address = (void *)dest.value;
				struct loaded_binary *binary;
				if (protection_for_address(&analysis->loader, address, &binary, NULL) & PROT_EXEC) {
					LOG("mov is to executable address, assuming it could be called after startup");
					queue_instruction(&analysis->search.queue, address, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, self.address, "mov");
					// self.description = "mov";
					// analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, (ins_ptr)address, &self);
				}
				goto skip_stack_clear;
			}
			case 0xc0: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m8, imm8
				// TODO: read reg to know which in the family to dispatch
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 4:
						perform_basic_op_rm8_imm8("shl", basic_op_shl, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 5:
						perform_basic_op_rm8_imm8("shr", basic_op_shr, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 7:
						perform_basic_op_rm8_imm8("sar", basic_op_shr, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					default:
						perform_basic_op_rm8_imm8("rotate/shift family", basic_op_unknown, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
				}
				break;
			}
			case 0xc1: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m, imm8
				// TODO: read reg to know which in the family to dispatch
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 4:
						perform_basic_op_rm_imm8("shl", basic_op_shl, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 5:
						perform_basic_op_rm_imm8("shr", basic_op_shr, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					case 7:
						perform_basic_op_rm_imm8("sar", basic_op_shr, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
					default:
						perform_basic_op_rm_imm8("rotate/shift family", basic_op_unknown, &analysis->loader, &self.current_state, decoded.prefixes, &decoded.unprefixed[1]);
						break;
				}
				break;
			}
			case 0xc2: // ret imm16
				break;
			case 0xc3: // ret
				break;
			case 0xc4: // three-byte vex prefix
				break;
			case 0xc5: // two-byte vex prefix
				break;
			case 0xc6: { // mov r/m8, imm8
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				if (modrm.reg == 0) {
					ins_ptr remaining = &decoded.unprefixed[1];
					int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, sizeof(int8_t), &self.current_state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
					LOG("mov r/m8 to", name_for_register(rm));
					struct register_state state;
					state.value = *remaining;
					state.max = state.value;
					LOG("value is immediate", temp_str(copy_register_state_description(&analysis->loader, state)));
					self.current_state.registers[rm] = state;
					self.current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self.current_state, rm, ins);
					pending_stack_clear &= ~((register_mask)1 << rm);
					goto skip_stack_clear;
				}
				break;
			}
			case 0xc7: { // mov r/m, imm
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				if (modrm.reg == 0) {
					ins_ptr remaining = &decoded.unprefixed[1];
					int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, imm_size_for_prefixes(decoded.prefixes), &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
					LOG("mov r/m to", name_for_register(rm));
					struct register_state state;
					state.value = read_imm(decoded.prefixes, remaining);
					state.max = state.value;
					LOG("value is immediate", temp_str(copy_register_state_description(&analysis->loader, state)));
					self.current_state.registers[rm] = state;
					self.current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self.current_state, rm, ins);
					dump_register(&analysis->loader, state);
					pending_stack_clear &= ~((register_mask)1 << rm);
					struct loaded_binary *binary;
					if (protection_for_address(&analysis->loader, (const void *)state.value, &binary, NULL) & PROT_EXEC) {
						self.description = "mov";
						if (required_effects & EFFECT_ENTRY_POINT) {
							if (rm == sysv_argument_abi_register_indexes[0]) {
								// main
								analysis->main = (uintptr_t)state.value;
								self.description = "mov main";
								LOG("mov is to executable address, assuming it is the main function");
								analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, (ins_ptr)state.value, &self);
							} else if (rm == sysv_argument_abi_register_indexes[3]) {
								// init, will be called before main, can skip it
							} else if (rm == sysv_argument_abi_register_indexes[4] || rm == sysv_argument_abi_register_indexes[5]) {
								LOG("mov is to executable address, assuming it is the finit function");
								analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, (ins_ptr)state.value, &self);
							} else {
								LOG("mov is to executable address, assuming it could be called during startup");
								analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT), &empty_registers, (ins_ptr)state.value, &self);
							}
						} else {
							LOG("mov is to executable address, assuming it could be called after startup");
							queue_instruction(&analysis->search.queue, (ins_ptr)state.value, required_effects | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, self.address, "mov");
						}
					} else {
						LOG("mov is to non-executable value, assuming it is data");
					}
					pending_stack_clear &= ~((register_mask)1 << rm);
					goto skip_stack_clear;
				}
				break;
			}
			case 0xc8: // enter
				break;
			case 0xc9: // leave
				break;
			case 0xca: // retf imm16
				break;
			case 0xcb: // retf
				break;
			case 0xcc: // int3
				break;
			case 0xcd: // int imm8
				break;
			case 0xce: // into
				break;
			case 0xcf: // iret
				break;
			case 0xd0: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m8, 1
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_KEEP_MEM, NULL);
				if (rm != REGISTER_INVALID) {
					if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
						clear_register(&self.current_state.registers[rm]);
						truncate_to_16bit(&self.current_state.registers[rm]);
					} else {
						clear_register(&self.current_state.registers[rm]);
					}
					self.current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self.current_state, rm, ins);
				}
				break;
			}
			case 0xd1: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m, 1
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
				if (rm != REGISTER_INVALID) {
					clear_register(&self.current_state.registers[rm]);
					truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
					self.current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self.current_state, rm, ins);
				}
				break;
			}
			case 0xd2: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m8, cl
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_KEEP_MEM, NULL);
				if (rm != REGISTER_INVALID) {
					if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
						clear_register(&self.current_state.registers[rm]);
						truncate_to_16bit(&self.current_state.registers[rm]);
					} else {
						clear_register(&self.current_state.registers[rm]);
					}
					self.current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self.current_state, rm, ins);
				}
				break;
			}
			case 0xd3: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m, cl
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				ins_ptr remaining = &decoded.unprefixed[1];
				int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM, NULL);
				if (rm != REGISTER_INVALID) {
					clear_register(&self.current_state.registers[rm]);
					truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
					self.current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self.current_state, rm, ins);
				}
				break;
			}
			case 0xd4:
			case 0xd5:
			case 0xd6:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0xd7:
				if (decoded.prefixes.has_vex) {
					// pmovmskb r, ymm
					x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
					int reg = x86_read_reg(modrm, decoded.prefixes);
					LOG("vpmovmskb to", name_for_register(reg));
					clear_register(&self.current_state.registers[reg]);
					truncate_to_32bit(&self.current_state.registers[reg]);
					self.current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self.current_state, reg, ins);
				} else {
					// xlat
					clear_register(&self.current_state.registers[REGISTER_RAX]);
					truncate_to_8bit(&self.current_state.registers[REGISTER_RAX]);
					self.current_state.sources[REGISTER_RAX] = 0;
					clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				}
				break;
			case 0xd8: // fadd/fmul/fcom/etc
				break;
			case 0xd9: // fld/fxch/fst/etc
				break;
			case 0xda: // fiadd/fcmovb/etc
				break;
			case 0xdb: // fild/etc
				break;
			case 0xdc: // fadd/fmul/fcom/etc
				break;
			case 0xdd: // legacy float garbage
				break;
			case 0xdf: // more legacy float garbage
				break;
			case 0xe0: // loopnz/loopne
				// TODO: handle loop
				break;
			case 0xe1: // loopz/loope
				// TODO: handle loop
				break;
			case 0xe2: // loop
				// TODO: handle loop
				break;
			case 0xe4: // in al, imm8
				break;
			case 0xe5: // in eax, imm8
				break;
			case 0xe6: // out al, imm8
				break;
			case 0xe7: // out eax, imm8
				break;
			case 0xe8: { // call
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				uintptr_t dest = (uintptr_t)next_ins(ins, &decoded) + *(const x86_int32 *)&decoded.unprefixed[1];
				LOG("found call", temp_str(copy_function_call_description(&analysis->loader, (void *)dest, self.current_state)));
				struct loaded_binary *binary = NULL;
				if (dest == 0) {
					LOG("found call to NULL, assuming all effects");
				} else if ((protection_for_address(&analysis->loader, (void *)dest, &binary, NULL) & PROT_EXEC) == 0) {
#if ABORT_AT_NON_EXECUTABLE_ADDRESS
					self.description = "call";
					ERROR("found call at", temp_str(copy_call_trace_description(&analysis->loader, &self)));
					DIE("to non-executable address", temp_str(copy_address_description(&analysis->loader, (void *)dest)));
#endif
					LOG("found call to non-executable address, assuming all effects");
					effects |= EFFECT_EXITS | EFFECT_RETURNS;
				} else if ((effects & EFFECT_ENTRY_POINT) && (ins_ptr)dest == next_ins(ins, &decoded)) {
					LOG("calling self pattern in entrypoint");
				} else if ((effects & EFFECT_ENTER_CALLS) == 0) {
					LOG("skipping call when searching for address loads");
					analysis->skipped_call = (ins_ptr)dest;
				} else {
					self.description = "call";
					function_effects more_effects = analyze_call(analysis, required_effects, ins, (ins_ptr)dest, &self);
					effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
					LOG("resuming", temp_str(copy_address_description(&analysis->loader, self.entry)));
					LOG("resuming from call", temp_str(copy_address_description(&analysis->loader, ins)));
					if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
						LOG("completing from call to exit-only function", temp_str(copy_address_description(&analysis->loader, self.entry)));
						push_unreachable_breakpoint(&analysis->unreachables, next_ins(ins, &decoded));
						goto update_and_return;
					}
					LOG("function may return, proceeding", name_for_effect(more_effects));
					struct loaded_binary *caller_binary = binary_for_address(&analysis->loader, ins);
					if (caller_binary != NULL) {
						struct frame_details frame;
						if (find_containing_frame_info(&caller_binary->frame_info, ins, &frame)) {
							if ((uintptr_t)frame.address + frame.size <= (uintptr_t)next_ins(ins, &decoded)) {
								LOG("found call to exit-only function not marked exit-only", temp_str(copy_address_description(&analysis->loader, ins)));
								goto update_and_return;
							}
						}
					}
				}
				clear_call_dirtied_registers(&analysis->loader, &self.current_state, binary, ins);
				pending_stack_clear = STACK_REGISTERS;
				if (is_stack_preserving_function(&analysis->loader, binary, (ins_ptr)dest)) {
					// we should be able to track dirtied slots, but for now assume golang preserves
					// the stack that's read immediately after the call
					LOG("target is stack-preserving function", temp_str(copy_address_description(&analysis->loader, ins)));
					self.current_state.stack_address_taken = NULL;
					goto skip_stack_clear;
				}
				break;
			}
			case 0xe9: // jmp rel
				break;
			case 0xea:
				LOG("invalid opcode", (uintptr_t)*decoded.unprefixed);
				break;
			case 0xeb: // jmp rel8
				break;
			case 0xec: // in al, dx
				clear_register(&self.current_state.registers[REGISTER_RAX]);
				truncate_to_8bit(&self.current_state.registers[REGISTER_RAX]);
				self.current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				break;
			case 0xed: // in *ax, *dx
				clear_register(&self.current_state.registers[REGISTER_RAX]);
				self.current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
				break;
			case 0xee: // out dx, al
				break;
			case 0xef: // out *dx, *ax
				break;
			case 0xf0: // lock prefix
				break;
			case 0xf1: // reserved
				break;
			case 0xf2: // repnz/repne/rep prefix
				break;
			case 0xf3: // repz/repe/rep prefix
				break;
			case 0xf4: // hlt
				effects |= EFFECT_EXITS;
				LOG("completing from hlt", temp_str(copy_address_description(&analysis->loader, self.entry)));
				goto update_and_return;
			case 0xf5: // cmc
				break;
			case 0xf6: {
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 0: 
					case 1: // test r/m8, imm8
						// TODO: implement test
						break;
					case 2: { // not r/m8, imm8
						// TODO: implement not
						int rm = x86_read_rm(modrm, decoded.prefixes);
						if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
							clear_register(&self.current_state.registers[rm]);
						} else {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_8bit(&self.current_state.registers[rm]);
						}
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						break;
					}
					case 3: { // neg r/m8, imm8
						// TODO: implement neg
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						int rm = x86_read_rm(modrm, decoded.prefixes);
						if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
							clear_register(&self.current_state.registers[rm]);
						} else {
							clear_register(&self.current_state.registers[rm]);
							truncate_to_8bit(&self.current_state.registers[rm]);
						}
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						break;
					}
					case 4: // mul ax, al, r/m8
					case 5: { // imul ax, al, r/m8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						truncate_to_16bit(&self.current_state.registers[REGISTER_RAX]);
						self.current_state.sources[REGISTER_RAX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						break;
					}
					case 6: // div al, ah, al, r/m8
					case 7: { // idiv al, ah, al, r/m8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						truncate_to_16bit(&self.current_state.registers[REGISTER_RAX]);
						self.current_state.sources[REGISTER_RAX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						break;
					}
				}
				break;
			}
			case 0xf7: {
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 0: 
					case 1: // test r/m, imm
						// TODO: implement test
						break;
					case 2: { // not r/m, imm
						// TODO: implement not
						int rm = x86_read_rm(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[rm]);
						truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						break;
					}
					case 3: { // neg r/m, imm
						// TODO: implement neg
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						int rm = x86_read_rm(modrm, decoded.prefixes);
						clear_register(&self.current_state.registers[rm]);
						truncate_to_size_prefixes(&self.current_state.registers[rm], decoded.prefixes);
						self.current_state.sources[rm] = 0;
						clear_match(&analysis->loader, &self.current_state, rm, ins);
						break;
					}
					case 4: // mul *dx, *ax, r/m
					case 5: { // imul *dx, *ax, r/m
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						clear_register(&self.current_state.registers[REGISTER_RDX]);
						self.current_state.sources[REGISTER_RAX] = 0;
						self.current_state.sources[REGISTER_RDX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						clear_match(&analysis->loader, &self.current_state, REGISTER_RDX, ins);
						break;
					}
					case 6: // div al, ah, al, r/m8
					case 7: { // idiv al, ah, al, r/m8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						clear_register(&self.current_state.registers[REGISTER_RAX]);
						clear_register(&self.current_state.registers[REGISTER_RDX]);
						self.current_state.sources[REGISTER_RAX] = 0;
						self.current_state.sources[REGISTER_RDX] = 0;
						clear_match(&analysis->loader, &self.current_state, REGISTER_RAX, ins);
						clear_match(&analysis->loader, &self.current_state, REGISTER_RDX, ins);
						break;
					}
				}
				break;
			}
			case 0xf8: // clc
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xf9: // stc
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xfa: // cli
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xfb: // sti
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xfc: // cld
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xfd: // std
				self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
				break;
			case 0xfe: {
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 0: { // inc r/m8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[1];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_8BIT, READ_RM_REPLACE_MEM, NULL);
						struct register_state state = self.current_state.registers[rm];
						if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
							clear_register(&self.current_state.registers[rm]);
						} else {
							truncate_to_8bit(&state);
							state.value++;
							state.max++;
							truncate_to_8bit(&state);
							self.current_state.registers[rm] = state;
						}
						break;
					}
					case 1: { // dec r/m8
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[1];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						if (register_is_legacy_8bit_high(decoded.prefixes, &rm)) {
							clear_register(&self.current_state.registers[rm]);
						} else {
							struct register_state state = self.current_state.registers[rm];
							truncate_to_8bit(&state);
							state.value--;
							state.max--;
							truncate_to_8bit(&state);
							self.current_state.registers[rm] = state;
						}
						break;
					}
					default:
						LOG("invalid opcode extension for 0xfe", (int)modrm.reg);
						break;
				}
				break;
			}
			case 0xff: {
				x86_mod_rm_t modrm = x86_read_modrm(&decoded.unprefixed[1]);
				switch (modrm.reg) {
					case 0: { // inc r/m
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[1];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						struct register_state state = self.current_state.registers[rm];
						truncate_to_size_prefixes(&state, decoded.prefixes);
						state.value++;
						state.max++;
						truncate_to_size_prefixes(&state, decoded.prefixes);
						self.current_state.registers[rm] = state;
						break;
					}
					case 1: { // dec r/m
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						ins_ptr remaining = &decoded.unprefixed[1];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						struct register_state state = self.current_state.registers[rm];
						truncate_to_size_prefixes(&state, decoded.prefixes);
						state.value--;
						state.max--;
						truncate_to_size_prefixes(&state, decoded.prefixes);
						self.current_state.registers[rm] = state;
						break;
					}
					case 2: // call
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						// TODO: implement call
						break;
					case 3: // callf
						self.current_state.compare_state.validity = COMPARISON_IS_INVALID;
						// TODO: implement callf
						break;
					case 4: // jmp
						// TODO: implement jmp
						break;
					case 5: // jmpf
						// TODO: implement jmpf
						break;
					case 6: { // push
						ins_ptr remaining = &decoded.unprefixed[1];
						int rm = read_rm_ref(&analysis->loader, decoded.prefixes, &remaining, 0, &self.current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM, NULL);
						struct register_state state = self.current_state.registers[rm];
						if (rm >= REGISTER_STACK_0) {
							if (rm == REGISTER_COUNT-1) {
								push_stack(&self.current_state, 2);
								break;
							}
							// stack positions shift, gaaah!
							rm += 2;
						}
						truncate_to_size_prefixes(&state, decoded.prefixes);
						push_stack(&self.current_state, 2);
						self.current_state.registers[REGISTER_STACK_0] = state;
						add_match_and_copy_sources(&analysis->loader, &self.current_state, REGISTER_STACK_0, rm, ins);
						dump_nonempty_registers(&analysis->loader, &self.current_state, STACK_REGISTERS);
						break;
					}
					default:
						LOG("invalid opcode extension for 0xff", (int)modrm.reg);
						break;
				}
				break;
			}
		}
		if (UNLIKELY(pending_stack_clear)) {
			LOG("clearing stack after call");
			for_each_bit(pending_stack_clear, bit, i) {
				if (SHOULD_LOG && register_is_partially_known(&self.current_state.registers[i])) {
					ERROR("clearing", name_for_register(i));
				}
				clear_register(&self.current_state.registers[i]);
				self.current_state.sources[i] = 0;
				self.current_state.matches[i] = 0;
			}
			for (int i = 0; i < REGISTER_STACK_0; i++) {
				self.current_state.matches[i] &= ~pending_stack_clear;
			}
			pending_stack_clear = 0;
		}
	skip_stack_clear:
		ins = next_ins(ins, &decoded);
		LOG("instruction", temp_str(copy_address_description(&analysis->loader, ins)));
		if (!decode_ins(ins, &decoded)) {
			LOG("invalid instruction, assuming all effects");
			effects |= EFFECT_RETURNS | EFFECT_EXITS;
			LOG("completing from invalid", temp_str(copy_address_description(&analysis->loader, self.entry)));
			decoded = (struct decoded_ins){ 0 };
			break;
		}
	}
update_and_return:
	effects &= ~EFFECT_PROCESSING;
	if ((effects & EFFECT_STICKY_EXITS) == 0) {
		if ((effects & (EFFECT_RETURNS | EFFECT_EXITS)) == 0) {
			effects |= EFFECT_RETURNS;
		}
		LOG("final effects", name_for_effect(effects));
		LOG("for", temp_str(copy_address_description(&analysis->loader, self.entry)));
		set_effects(&analysis->search, self.entry, &self.token, effects);
	} else {
		effects &= ~EFFECT_RETURNS;
		LOG("final effects (sticky exit)", name_for_effect(effects));
		LOG("for", temp_str(copy_address_description(&analysis->loader, self.entry)));
		set_effects(&analysis->search, self.entry, &self.token, effects);
		effects &= ~EFFECT_STICKY_EXITS;
	}
	if ((effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
		LOG("exit-only block", temp_str(copy_address_description(&analysis->loader, self.entry)));
	}
#if BREAK_ON_UNREACHABLES
	push_reachable_region(&analysis->loader, &analysis->unreachables, self.entry, next_ins(ins, &decoded));
#endif
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
		LOG("relocation address", temp_str(copy_address_description(context, (const void *)rel)));
		LOG("processing relocation of type", (int)type);
		uintptr_t relo_target = apply_base_address(&binary->info, offset);
		LOG("relocation is at", temp_str(copy_address_description(context, (const void *)relo_target)));
		LOG("symbol index", symbol_index);
		LOG("addend", addend);
		const char *textual_name;
		uintptr_t value;
		size_t size;
		if (binary->has_symbols) {
			const ElfW(Sym) *symbol = (const ElfW(Sym) *)(binary->symbols.symbols + symbol_index * binary->symbols.symbol_stride);
			textual_name = symbol_name(&binary->symbols, symbol);
			if (symbol->st_value != 0 && symbol->st_shndx != SHN_UNDEF) {
				value = apply_base_address(&binary->info, symbol->st_value);
#if defined(__x86_64__)
			} else if (type != R_X86_64_RELATIVE && type != R_X86_64_IRELATIVE && type != R_X86_64_DTPMOD64 && type != R_X86_64_DTPOFF64 && type != R_X86_64_TPOFF64 && type != R_X86_64_TPOFF32) {
				struct loaded_binary *other_binary = NULL;
				struct symbol_version_info version = binary->symbols.symbol_versions != NULL ? symbol_version_for_index(&binary->symbols, binary->symbols.symbol_versions[symbol_index] & 0x7fff) : (struct symbol_version_info){ 0 };
				value = (uintptr_t)resolve_loaded_symbol(context, textual_name, version.version_name, NORMAL_SYMBOL, &other_binary, NULL);
				if (value == 0) {
					if ((ELF64_ST_BIND(symbol->st_info) == STB_WEAK) || (type == R_X86_64_NONE)) {
						LOG("symbol value is NULL");
					} else {
						ERROR("symbol is in another castle", textual_name);
						if (version.version_name != NULL) {
							ERROR("version", version.version_name);
							if (version.library_name != NULL) {
								ERROR("in library", version.library_name);
							}
						}
						DIE("from", binary->path);
					}
				}
				LOG("resolving", textual_name);
				if (version.version_name != NULL) {
					LOG("version", version.version_name);
					if (version.library_name != NULL) {
						LOG("in library", version.library_name);
					}
				}
				LOG("from", binary->path);
				if (other_binary) {
					LOG("to", other_binary->path);
				}
#endif
#if defined(__aarch64__)
			} else if (type != R_AARCH64_RELATIVE && type != R_AARCH64_IRELATIVE && type != R_AARCH64_TLS_DTPREL && type != R_AARCH64_TLS_DTPMOD && type != R_AARCH64_TLS_TPREL) {
				struct loaded_binary *other_binary = NULL;
				struct symbol_version_info version = binary->symbols.symbol_versions != NULL ? symbol_version_for_index(&binary->symbols, binary->symbols.symbol_versions[symbol_index] & 0x7fff) : (struct symbol_version_info){ 0 };
				value = (uintptr_t)resolve_loaded_symbol(context, textual_name, version.version_name, NORMAL_SYMBOL, &other_binary, NULL);
				if (value == 0) {
					if ((ELF64_ST_BIND(symbol->st_info) == STB_WEAK) || (type == R_AARCH64_NONE)) {
						LOG("symbol value is NULL");
					} else {
						ERROR("symbol is in another castle", textual_name);
						if (version.version_name != NULL) {
							ERROR("version", version.version_name);
							if (version.library_name != NULL) {
								ERROR("in library", version.library_name);
							}
						}
						ERROR("relocation type", (intptr_t)type);
						ERROR("symbol index", rel_off / relaent);
						DIE("from", binary->path);
					}
				}
				LOG("resolving", textual_name);
				if (version.version_name != NULL) {
					LOG("version", version.version_name);
					if (version.library_name != NULL) {
						LOG("in library", version.library_name);
					}
				}
				LOG("from", binary->path);
				if (other_binary) {
					LOG("to", other_binary->path);
				}
#endif
			} else {
				value = 0;
			}
			size = symbol->st_size;
		} else {
			value = 0;
			size = 0;
			textual_name = "";
		}
		LOG("relocation is for value", value);
#ifdef __x86_64__
		switch (type) {
			case R_X86_64_NONE:
				// why does this exist?
				break;
			case R_X86_64_64:
				LOG("64 relocation for", textual_name);
				*(x86_uint64 *)relo_target = value + addend;
				break;
			case R_X86_64_PC32:
				LOG("pc32 relocation for", textual_name);
				*(x86_uint32 *)relo_target = value + addend - relo_target;
				break;
			case R_X86_64_GOT32:
				LOG("got32 relocation for, not supported", textual_name);
				// TODO
				break;
			case R_X86_64_PLT32:
				LOG("plt32 relocation for, not supported", textual_name);
				// TODO
				break;
			case R_X86_64_COPY:
				LOG("copy relocation for", textual_name);
				fs_memcpy((void *)relo_target, (const void *)value, size);
				break;
			case R_X86_64_GLOB_DAT:
				LOG("glob dat relocation for", textual_name);
				*(x86_uint64 *)relo_target = value;
				break;
			case R_X86_64_JUMP_SLOT:
				LOG("jump slot relocation for", textual_name);
				*(x86_uint64 *)relo_target = value;
				break;
			case R_X86_64_RELATIVE64:
			case R_X86_64_RELATIVE: {
				uintptr_t result = (uintptr_t)binary->info.base + addend;
				*(uintptr_t *)relo_target = result;
				LOG("relative relocation", temp_str(copy_address_description(context, (const void *)result)));
				break;
			}
			case R_X86_64_GOTPCREL:
				LOG("gotpcrel relocation for, not supported", textual_name);
				break;
			case R_X86_64_32:
				LOG("32 relocation for, not supported", textual_name);
				break;
			case R_X86_64_32S:
				LOG("32s relocation for, not supported", textual_name);
				break;
			case R_X86_64_16:
				LOG("16 relocation for, not supported", textual_name);
				break;
			case R_X86_64_PC16:
				LOG("pc16 relocation for, not supported", textual_name);
				break;
			case R_X86_64_8:
				LOG("8 relocation for, not supported", textual_name);
				break;
			case R_X86_64_PC8:
				LOG("pc8 relocation for, not supported", textual_name);
				break;
			case R_X86_64_PC64:
				LOG("pc64 relocation for, not supported", textual_name);
				break;
			case R_X86_64_SIZE32:
				LOG("size32 relocation for, not supported", textual_name);
				break;
			case R_X86_64_SIZE64:
				LOG("size64 relocation for, not supported", textual_name);
				break;
			case R_X86_64_TLSDESC:
				LOG("tlsdesc relocation for, not supported", textual_name);
				break;
			case R_X86_64_TLSDESC_CALL:
				LOG("tlsdesc call relocation for, not supported", textual_name);
				break;
			case R_X86_64_TLSGD:
				LOG("tlsgd relocation for, not supported", textual_name);
				break;
			case R_X86_64_TLSLD:
				LOG("tlsld relocation for, not supported", textual_name);
				break;
			case R_X86_64_DTPMOD64:
				LOG("dynamic thread vector entry relocation for, not supported", textual_name);
				break;
			case R_X86_64_DTPOFF64:
				LOG("dynamic dynamic pointer offset relocation for, not supported", textual_name);
				break;
			case R_X86_64_TPOFF32:
				LOG("thread pointer offset 32 relocation for, not supported", textual_name);
				break;
			case R_X86_64_TPOFF64:
				LOG("thread pointer offset 64 relocation for, not supported", textual_name);
				break;
			case R_X86_64_IRELATIVE:
				LOG("GNU magic to support STT_GNU_IFUNC/__attribute__((ifunc(\"...\"))), not supported", textual_name);
				// TODO: figure out how to trace these
				*(uintptr_t *)relo_target = value;
				break;
			default:
				ERROR("unknown relocation type for", textual_name);
				ERROR("type is", (intptr_t)type);
				ERROR("at", (intptr_t)(rel_off / relaent));
				DIE("from", binary->path);
				break;
		}
#else
#if defined(__aarch64__)
		switch (type) {
			case R_AARCH64_NONE:
				// why does this exist?
				break;
			case R_AARCH64_ABS64:
				LOG("abs64 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_ABS32:
				LOG("abs32 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_ABS16:
				LOG("abs16 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_PREL64:
				LOG("prel64 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_PREL32:
				LOG("prel32 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_PREL16:
				LOG("prel16 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_COPY:
				LOG("copy relocation for", textual_name);
				fs_memcpy((void *)relo_target, (const void *)value, size);
				break;
			case R_AARCH64_GLOB_DAT:
				LOG("glob dat relocation for", textual_name);
				*(uint64_t *)relo_target = value;
				break;
			case R_AARCH64_JUMP_SLOT:
				LOG("jump slot relocation for", textual_name);
				*(uint64_t *)relo_target = value;
				break;
			case R_AARCH64_RELATIVE: {
				uintptr_t result = (uintptr_t)binary->info.base + addend;
				*(uintptr_t *)relo_target = result;
				LOG("relative relocation", temp_str(copy_address_description(context, (const void *)result)));
				break;
			}
			case R_AARCH64_TLS_DTPREL:
				LOG("tls dtprel64 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_TLS_DTPMOD:
				LOG("tls dtpmod64 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_TLS_TPREL:
				LOG("tls tprel64 relocation for, not supported", textual_name);
				break;
			case R_AARCH64_TLSDESC:
				LOG("tls tlsdesc relocation for, not supported", textual_name);
				break;
			case R_AARCH64_IRELATIVE:
				LOG("GNU magic to support STT_GNU_IFUNC/__attribute__((ifunc(\"...\"))), not supported", textual_name);
				// TODO: figure out how to trace these
				*(uintptr_t *)relo_target = value;
				break;
			default:
				ERROR("unknown relocation type for", textual_name);
				ERROR("type is", (intptr_t)type);
				ERROR("at", (intptr_t)(rel_off / relaent));
				DIE("from", binary->path);
				break;
		}
#else
#error "Unknown architecture"
#endif
#endif
	}
	return 0;
}

static void *find_any_symbol_by_address(__attribute__((unused)) const struct loader_context *loader, struct loaded_binary *binary, const void *addr, int symbol_types, const struct symbol_info **out_used_symbols, const ElfW(Sym) **out_symbol)
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

static int special_binary_flags_for_path(const char *path)
{
	const char *slash = fs_strrchr(path, '/');
	if (slash) {
		path = slash+1;
	}
	int result = 0;
	if (path[0] == 'l' && path[1] == 'i' && path[2] == 'b') { // lib
		if (path[3] == 'c') {
			if (path[4] == '.') { // libc.
				result |= BINARY_IS_LIBC | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
			} else if (path[4] == 'r' && path[5] == 'y' && path[6] == 'p' && path[7] == 't' && path[8] == 'o' && path[9] == '.') { // libcrypto.
				// result |= BINARY_ASSUME_FUNCTION_CALLS_PRESERVE_STACK | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
				result |= BINARY_IS_LIBCRYPTO;
			} else if (path[4] == 'a' && path[5] == 'p' && path[6] == '.') {
				result |= BINARY_IS_LIBCAP;
			}
		} else if (path[3] == 'g') {
			if (path[4] == 'n' && path[5] == 'u' && path[6] == 't' && path[7] == 'l' && path[8] == 's' && path[9] == '.') { // libgnutls.
				// result |= BINARY_ASSUME_FUNCTION_CALLS_PRESERVE_STACK | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
			} else if (path[4] == 'c' && path[5] == 'r' && path[6] == 'y' && path[7] == 'p' && path[8] == 't' && path[9] == '.') { // libgcrypt.
				// result |= BINARY_ASSUME_FUNCTION_CALLS_PRESERVE_STACK | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
			} else if (path[4] == 'm' && path[5] == 'p' && path[6] == '.') { // libgmp.
				result |= BINARY_IGNORES_SIGNEDNESS;
			}
		} else if (path[3] == 'h') {
			if (path[4] == 'c' && path[5] == 'r' && path[6] == 'y' && path[7] == 'p' && path[8] == 't' && path[9] == 'o' && path[10] == '.') { // libhcrypto.
				// result |= BINARY_ASSUME_FUNCTION_CALLS_PRESERVE_STACK | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
			}
		} else if (path[3] == 'p') {
			if (path[4] == 't' && path[5] == 'h' && path[6] == 'r' && path[7] == 'e' && path[8] == 'a' && path[9] == 'd' && path[10] == '.') { // libpthread.
				result |= BINARY_IS_PTHREAD;
			}
		} else if (path[3] == 'r' && path[4] == 'e' && path[5] == 'a' && path[6] == 'd') {
			// result |= BINARY_IS_LIBREADLINE;
		} else if (path[3] == 's') {
			if (path[4] == 'e' && path[5] == 'c' && path[6] == 'c' && path[7] == 'o' && path[8] == 'm' && path[9] == 'p' && path[10] == '.') { // libseccomp.
				result |= BINARY_IS_SECCOMP;
			}
		} else if (path[3] == 'n') {
			if (path[4] == 's' && path[5] == 's' && path[6] == '_' && path[7] == 's' && path[8] == 'y' && path[9] == 's' && path[10] == 't' && path[11] == 'e' && path[12] == 'm' && path[13] == 'd' && path[14] == '.') { // libnss_systemd.
				result |= BINARY_IS_LIBNSS_SYSTEMD;
			}
		} else if (path[3] == 'k') {
			if (path[4] == 'r' && path[5] == 'b' && path[6] == '5' && path[7] == '.') { // libkrb5.
				// result |= BINARY_ASSUME_FUNCTION_CALLfS_PRESERVE_STACK | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
			}
		} else if (path[3] == 'r') {
			if (path[4] == 'u' && path[5] == 'b' && path[6] == 'y' && (path[7] == '.' || path[7] == '-' || path[7] == '2')) { // libruby. or libruby-
				// result |= BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
				result |= BINARY_IS_RUBY;
			}
		}
	} else if (fs_strcmp(path, "ubuntu-core-launcher") == 0) {
		result |= BINARY_IS_LIBCAP;
	} else if (fs_strncmp(path, "ruby", sizeof("ruby")-1) == 0) {
		result |= BINARY_IS_RUBY;
	}
	return result;
}

struct loaded_binary_stub {
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

int load_binary_into_analysis(struct program_state *analysis, const char *path, const char *full_path, int fd, const void *existing_base_address, struct loaded_binary **out_binary) {
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
		result = load_binary(fd, &info, /*(uintptr_t)hash * PAGE_SIZE*/0, false);
		if (result != 0) {
			return result;
		}
		relocate_binary(&info);
	}
	LOG("loading", path);
	if (full_path == NULL) {
		full_path = path;
	}
	size_t full_path_len = fs_strlen(full_path);
	struct loaded_binary *new_binary = malloc(sizeof(struct loaded_binary) + full_path_len + 1);
	*new_binary = (struct loaded_binary){ 0 };
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
		if (new_binary->has_sections) {
			new_binary->has_frame_info = load_frame_info(fd, &new_binary->info, &new_binary->sections, &new_binary->frame_info) == 0;
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
	} else {
		new_binary->device = 0;
		new_binary->inode = 0;
		new_binary->mode = 0;
		new_binary->uid = 0;
		new_binary->gid = 0;
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
						new_binary->special_binary_flags |= BINARY_IS_GOLANG | BINARY_ASSUME_FUNCTION_CALLS_PRESERVE_STACK;
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
		if (new_binary->special_binary_flags & (BINARY_IS_LIBC | BINARY_IS_LIBNSS_SYSTEMD | BINARY_IS_LIBREADLINE | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA)) {
			result = load_debuglink(&analysis->loader, new_binary, false);
			if (result < 0) {
				if (result == -ENOENT || result == -ENOEXEC) {
					print_debug_symbol_requirement(new_binary);
				} else {
					ERROR("failed to load debug symbols for", new_binary->path);
					ERROR("error was", fs_strerror(result));
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
	qsort_r(analysis->loader.sorted_binaries, analysis->loader.binary_count, sizeof(struct loaded_binary_stub), compare_loaded_binary_stubs, NULL);
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

static int load_debuglink(const struct loader_context *loader, struct loaded_binary *binary, bool force_loading) {
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
#define DEBUGLINK_ARCH_SEARCH_PATH "/usr/lib/debug/lib/"ARCH_NAME"-linux-gnu"
#define DEBUGLINK_BASE_SEARCH_PATH "/usr/lib/debug/lib:/lib/debug/usr/lib64:/usr/lib/debug/lib64"
#define DEBUGLINK_BUILD_ID_SEARCH_PATH "/usr/lib/debug/.build-id/XX"
	const char *debuglink_search_paths = DEBUGLINK_ARCH_SEARCH_PATH":"DEBUGLINK_BASE_SEARCH_PATH;
	char buf[sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH":"DEBUGLINK_ARCH_SEARCH_PATH":"DEBUGLINK_BASE_SEARCH_PATH)];
	const char *build_id = binary->build_id;
	if (build_id != NULL) {
		memcpy(buf, DEBUGLINK_BUILD_ID_SEARCH_PATH":"DEBUGLINK_ARCH_SEARCH_PATH":"DEBUGLINK_BASE_SEARCH_PATH, sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH":"DEBUGLINK_ARCH_SEARCH_PATH":"DEBUGLINK_BASE_SEARCH_PATH));
		buf[sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH)-3] = "0123456789abcdef"[(uint8_t)build_id[16] >> 4];
		buf[sizeof(DEBUGLINK_BUILD_ID_SEARCH_PATH)-2] = "0123456789abcdef"[(uint8_t)build_id[16] & 0xf];
		debuglink_search_paths = buf;
	}
	LOG("searching for debuglink", debuglink);
	LOG("debuglink search paths", debuglink_search_paths);
	int debuglink_fd = open_executable_in_paths(debuglink, debuglink_search_paths, false, loader->uid, loader->gid);
	if (debuglink_fd < 0) {
		LOG("failed to open debuglink", fs_strerror(debuglink_fd));
		return binary->debuglink_error = debuglink_fd;
	}
	int result = load_binary(debuglink_fd, &binary->debuglink_info, 0, true);
	if (result != 0) {
		LOG("failed to load debuglink", fs_strerror(result));
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
		LOG("failed to read sections from debuglink", fs_strerror(result));
		goto return_and_exit;
	}
	// try to load the linker symbol table
	result = load_section_symbols(debuglink_fd, &binary->debuglink_info, &debuglink_sections, false, &binary->debuglink_symbols);
	if (result != 0) {
		LOG("error loading debuglink section symbols", fs_strerror(result));
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

__attribute__((warn_unused_result))
static int load_needed_libraries(struct program_state *analysis, struct loaded_binary *new_binary)
{
	if (new_binary->has_loaded_needed_libraries) {
		return 0;
	}
	new_binary->has_loaded_needed_libraries = true;
	const ElfW(Dyn) *dynamic = new_binary->info.dynamic;
	size_t dynamic_size = new_binary->info.dynamic_size;
	if (new_binary->special_binary_flags & BINARY_IS_MAIN) {
		if (new_binary->info.interpreter) {
			int interpreter_fd = open_executable_in_paths(new_binary->info.interpreter, NULL, true, analysis->loader.uid, analysis->loader.gid);
			if (interpreter_fd < 0) {
				ERROR("failed to find interpreter", new_binary->info.interpreter);
				return interpreter_fd;
			}
			const char *interpreter_filename = fs_strrchr(new_binary->info.interpreter, '/');
			if (interpreter_filename) {
				interpreter_filename++;
			} else {
				interpreter_filename = new_binary->info.interpreter;
			}
			int result = load_binary_into_analysis(analysis, interpreter_filename, new_binary->info.interpreter, interpreter_fd, NULL, &analysis->loader.interpreter);
			fs_close(interpreter_fd);
			if (result < 0) {
				ERROR("failed to load interpreter", new_binary->info.interpreter);
				return result;
			}
			analysis->loader.interpreter->special_binary_flags |= BINARY_IS_INTERPRETER | BINARY_HAS_CUSTOM_JUMPTABLE_METADATA;
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
		const char *standard_run_path = "/lib64:/lib/"ARCH_NAME"-linux-gnu:/lib:/usr/lib:/usr/lib64:/usr/lib/perl5/core_perl/CORE";
		size_t standard_run_path_sizeof = sizeof("/lib64:/lib/"ARCH_NAME"-linux-gnu:/lib:/usr/lib:/usr/lib64:/usr/lib/perl5/core_perl/CORE");
		char *new_run_path = NULL;
		if (additional_run_path != NULL) {
			if (fs_strncmp(additional_run_path, "$ORIGIN", sizeof("$ORIGIN")-1) == 0) {
				const char *after_origin = &additional_run_path[sizeof("$ORIGIN")-1];
				size_t suffix_len = fs_strlen(after_origin);
				const char *pos = fs_strrchr(new_binary->path, '/');
				if (pos != NULL) {
					size_t prefix_len = pos - new_binary->path;
					new_run_path = malloc(prefix_len + suffix_len + (1 + standard_run_path_sizeof));
					fs_memcpy(new_run_path, new_binary->path, prefix_len);
					fs_memcpy(&new_run_path[prefix_len], after_origin, suffix_len);
					new_run_path[prefix_len+suffix_len] = ':';
					fs_memcpy(&new_run_path[prefix_len+suffix_len+1], standard_run_path, standard_run_path_sizeof);
				}
			} else {
				size_t prefix_len = fs_strlen(additional_run_path);
				new_run_path = malloc(prefix_len + (1 + standard_run_path_sizeof));
				fs_memcpy(new_run_path, additional_run_path, prefix_len);
				new_run_path[prefix_len] = ':';
				fs_memcpy(&new_run_path[prefix_len+1], standard_run_path, standard_run_path_sizeof);
			}
		}
		for (size_t i = 0; i < dynamic_size; i++) {
			switch (dynamic[i].d_tag) {
				case DT_NEEDED: {
					const char *needed_path = new_binary->symbols.strings + dynamic[i].d_un.d_val;
					LOG("needed", needed_path);
					if (find_loaded_binary(&analysis->loader, needed_path) == NULL) {
						char buf[PATH_MAX];
						const char *full_path;
						int needed_fd = find_executable_in_paths(needed_path, additional_run_path != NULL ? new_run_path : standard_run_path, false, analysis->loader.uid, analysis->loader.gid, buf, &full_path);
						if (needed_fd < 0) {
							ERROR("failed to find", needed_path);
							if (new_run_path != NULL) {
								free(new_run_path);
							}
							return needed_fd;
						}
						struct loaded_binary *additional_binary;
						int result = load_binary_into_analysis(analysis, needed_path, full_path, needed_fd, NULL, &additional_binary);
						fs_close(needed_fd);
						if (result < 0) {
							ERROR("failed to load", needed_path);
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

#ifndef SHT_RELR
#define SHT_RELR 19
#endif

// #ifndef ELF64_R_JUMP
// #define ELF64_R_JUMP(val) ((val) >> 56)
// #endif
// #ifndef ELF64_R_BITS
// #define ELF64_R_BITS(val) ((val) & 0xffffffffffffff)
// #endif

static void apply_relr_table(struct loaded_binary *new_binary, const uintptr_t *relative, size_t size)
{
	const uintptr_t *end = relative + size;
	// ElfW(Addr) offset = 0;
	uintptr_t base = (uintptr_t)new_binary->info.base;
	uintptr_t *where = (uintptr_t *)base;
	for (; relative < end; ++relative) {
		uintptr_t entry = *relative;
		if (entry & 1) {
			for (long i = 0; (entry >>= 1) != 0; i++) {
				if (entry & 1) {
					where[i] += base;
				}
			}
			where += CHAR_BIT * sizeof(uintptr_t) - 1;
		} else {
			where = (uintptr_t *)(base + entry);
			*where++ += base;
		}
	}
}

__attribute__((warn_unused_result))
static int relocate_loaded_library(struct program_state *analysis, struct loaded_binary *new_binary)
{
	if (new_binary->has_applied_relocation) {
		return 0;
	}
	new_binary->has_applied_relocation = true;
#if 0
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
#else
	if (new_binary->has_sections) {
		size_t relaent = sizeof(ElfW(Rela));
		const ElfW(Dyn) *dynamic = new_binary->info.dynamic;
		size_t dynamic_size = new_binary->info.dynamic_size;
		for (size_t i = 0; i < dynamic_size; i++) {
			switch (dynamic[i].d_tag) {
				case DT_RELAENT:
					relaent = dynamic[i].d_un.d_val;
					break;
			}
		}
		for (size_t i = 0; i < new_binary->info.section_entry_count; i++) {
			const ElfW(Shdr) *section = (const ElfW(Shdr) *)((char *)new_binary->sections.sections + i * new_binary->info.section_entry_size);
			switch (section->sh_type) {
				case SHT_RELA: {
					int result = apply_relocation_table(&analysis->loader, new_binary, section->sh_addr, relaent, section->sh_size);
					if (result < 0) {
						return result;
					}
					break;
				}
				case SHT_RELR: {
					apply_relr_table(new_binary, (const uintptr_t *)apply_base_address(&new_binary->info, section->sh_addr), section->sh_size / sizeof(uintptr_t));
					break;
				}
			}
		}
	}
#endif
	return 0;
}

static int load_all_needed_and_relocate(struct program_state *analysis)
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
	if ((binary->special_binary_flags & (BINARY_IS_MAIN | BINARY_IS_INTERPRETER | BINARY_IS_LIBC | BINARY_IS_PTHREAD | BINARY_IS_LIBNSS_SYSTEMD | BINARY_IS_LIBCRYPTO)) == 0) {
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
	} else {
		LOG("callable address in symbol", name);
		LOG("of binary", binary->path);
		return false;
	}
	*out_symbol = (struct address_and_size){
		.address = (ins_ptr)((uintptr_t)binary->info.base + symbol->st_value - (uintptr_t)binary->info.default_base),
		.size = symbol->st_size,
	};
	return true;
}

struct golang_init_task {
	uintptr_t state;
	uintptr_t ndeps;
	uintptr_t nfns;
	const void *data[0];
};

static void analyze_golang_init_task(struct program_state *analysis, function_effects effects, const struct golang_init_task *task)
{
	struct effect_token token;
	struct registers registers = empty_registers;
	function_effects *entry = get_or_populate_effects(analysis, (void *)task, &registers, EFFECT_NONE, &token);
	if ((*entry & effects) == effects) {
		return;
	}
	*entry |= effects & ~EFFECT_PROCESSING;
	LOG("analyzing golang task", temp_str(copy_address_description(&analysis->loader, task)));
	uintptr_t ndeps = task->ndeps;
	uintptr_t nfns = task->nfns;
	LOG("ndeps", (intptr_t)ndeps);
	LOG("nfns", (intptr_t)nfns);
	for (uintptr_t i = 0; i < ndeps; i++) {
		analyze_golang_init_task(analysis, effects, task->data[i]);
	}
	for (uintptr_t i = 0; i < nfns; i++) {
		LOG("found golang init function", temp_str(copy_address_description(&analysis->loader, task->data[ndeps+i])));
		struct analysis_frame new_caller = { .address = &task->data[ndeps+i], .description = "golang task init", .next = NULL, .current_state = registers, .entry = (const void *)task, .entry_state = &registers, .token = { 0 }, .is_entry = true };
		analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, task->data[ndeps+i], &new_caller);
	}
}

__attribute__((warn_unused_result))
int finish_loading_binary(struct program_state *analysis, struct loaded_binary *new_binary, function_effects effects, bool skip_analysis)
{
	if (new_binary->has_finished_loading) {
		return 0;
	}
	new_binary->has_finished_loading = true;
	int result = load_all_needed_and_relocate(analysis);
	if (result < 0) {
		return result;
	}
	LOG("finishing", new_binary->path);
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
					LOG("needed finishing", needed_path);
					struct loaded_binary *additional_binary = find_loaded_binary(&analysis->loader, needed_path);
					if (additional_binary) {
						result = finish_loading_binary(analysis, additional_binary, effects, skip_analysis);
						if (result != 0) {
							LOG("failed to finish loading", needed_path);
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
	LOG("resuming", new_binary->path);
	if (skip_analysis) {
		return 0;
	}
	if (init_array_ptr != 0) {
		const uintptr_t *inits = (const uintptr_t *)apply_base_address(&new_binary->info, init_array_ptr);
		for (size_t i = 0; i < init_array_count; i++) {
			LOG("analyzing initializer function", i);
			struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "init", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
			analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, (ins_ptr)(inits[i] < (uintptr_t)new_binary->info.base ? (uintptr_t)apply_base_address(&new_binary->info, inits[i]) : inits[i]), &new_caller);
		}
	}
	if (init != 0) {
		LOG("analyzing initializer function");
		ins_ptr init_function = (ins_ptr)apply_base_address(&new_binary->info, init);
		struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "init", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
		analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, init_function, &new_caller);
	}
	if (fini_array_ptr != 0) {
		const uintptr_t *finis = (const uintptr_t *)apply_base_address(&new_binary->info, fini_array_ptr);
		for (size_t i = 0; i < fini_array_count; i++) {
			LOG("analyzing finalizer function", i);
			struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "fini", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
			analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, (ins_ptr)(finis[i] < (uintptr_t)new_binary->info.base ? (uintptr_t)apply_base_address(&new_binary->info, finis[i]) : finis[i]), &new_caller);
		}
	}
	if (fini != 0) {
		LOG("analyzing finalizer function");
		ins_ptr fini_function = (ins_ptr)apply_base_address(&new_binary->info, fini);
		struct analysis_frame new_caller = { .address = new_binary->info.base, .description = "fini", .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
		analyze_function(analysis, EFFECT_PROCESSED | effects, &registers, fini_function, &new_caller);
	}
	void *golangInitTask = resolve_binary_loaded_symbol(&analysis->loader, new_binary, "main..inittask", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
	if (golangInitTask) {
		analyze_golang_init_task(analysis, effects | EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, golangInitTask);
	}
	// search for vtables that should go unsearched until they're referenced explicitly
	static const struct { const char *name; size_t size; bool inner_call; } function_pointer_ignore_sources[] = {
		// glibc
		{"authdes_pk_create", sizeof(uintptr_t) * 5, false}, // authdes_ops
		{"authunix_create", sizeof(uintptr_t) * 5, false}, // auth_unix_ops
		{"svctcp_create", sizeof(uintptr_t) * 5, false}, // svctcp_rendezvous_op
		{"svcunix_create", sizeof(uintptr_t) * 5, false}, // svcunix_rendezvous_op
		{"svcudp_bufcreate", sizeof(uintptr_t) * 5, false}, // svcudp_op
		{"svcunixfd_create", sizeof(uintptr_t) * 5, false}, // svcunix_op
		{"svcfd_create", sizeof(uintptr_t) * 5, false}, // svctcp_op
		{"clntudp_create", sizeof(uintptr_t) * 5, false}, // udp_ops
		{"__libc_clntudp_bufcreate", sizeof(uintptr_t) * 5, false}, // udp_ops
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
			LOG("found", function_pointer_ignore_sources[i].name);
			LOG("at", temp_str(copy_address_description(&analysis->loader, func)));
			struct analysis_frame new_caller = { .address = new_binary->info.base, .description = function_pointer_ignore_sources[i].name, .next = NULL, .current_state = empty_registers, .entry = new_binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = true };
			analyze_function_for_ignored_load(analysis, &new_caller.current_state, func, &new_caller, function_pointer_ignore_sources[i].size);
			if (function_pointer_ignore_sources[i].inner_call && analysis->skipped_call) {
				new_caller.current_state = empty_registers;
				analyze_function_for_ignored_load(analysis, &new_caller.current_state, analysis->skipped_call, &new_caller, function_pointer_ignore_sources[i].size);
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
					LOG("scanning section for addresses", name);
					const uintptr_t *section_data = (const uintptr_t *)apply_base_address(&new_binary->info, section->sh_addr);
					int size = section->sh_size / sizeof(uintptr_t);
					for (int j = 0; j < size; j++) {
						uintptr_t data = section_data[j];
						if (protection_for_address_in_binary(new_binary, data, NULL) & PROT_EXEC) {
							LOG("found reference to executable address at", temp_str(copy_address_description(&analysis->loader, &section_data[j])));
							LOG("value of address is, assuming callable", data);
							struct address_and_size symbol;
							if (!find_skipped_symbol_for_address(&analysis->loader, new_binary, &section_data[j], &symbol)) {
								struct analysis_frame new_caller = { .address = &section_data[j], .description = name, .next = NULL, .current_state = empty_registers, .entry = (void *)&section_data[j], .entry_state = &empty_registers, .token = { 0 }, .is_entry = true};
								analyze_function(analysis, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS | effects, &registers, (ins_ptr)data, &new_caller);
							}
						}
					}
				} else {
					LOG("skipping scanning section for addresses", name);
				}
			}
		}
	}
	return 0;
}

void free_loaded_binary(struct loaded_binary *binary) {
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
}

__attribute__((noinline))
static int protection_for_address_definitely_in_binary(const struct loaded_binary *binary, uintptr_t addr, const ElfW(Shdr) **out_section) {
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
						LOG("found address in section", section_name);
						LOG("of", binary->path);
						if (out_section != NULL) {
							*out_section = section;
						}
						for (int j = 0; j < OVERRIDE_ACCESS_SLOT_COUNT; j++) {
							if (UNLIKELY(addr >= (uintptr_t)binary->override_access_ranges[j].address && addr < (uintptr_t)binary->override_access_ranges[j].address + binary->override_access_ranges[j].size)) {
								LOG("using override", j);
								return binary->override_access_permissions[j];
							}
						}
						int result = PROT_READ;
						if (flags & SHF_EXECINSTR) {
							result |= PROT_EXEC;
						}
						if ((flags & SHF_WRITE) && (fs_strcmp(section_name, ".data.rel.ro") != 0) && (fs_strcmp(section_name, ".got") != 0)) {
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

__attribute__((always_inline))
static inline int protection_for_address_in_binary(const struct loaded_binary *binary, uintptr_t addr, const ElfW(Shdr) **out_section) {
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

__attribute__((nonnull(1, 3)))
static int protection_for_address(const struct loader_context *context, const void *address, struct loaded_binary **out_binary, const ElfW(Shdr) **out_section) {
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
	const ElfW(Sym) *symbol;
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
		uintptr_t ins_b = (uintptr_t)syscallb->ins;
		if (data != NULL) {
			struct loader_context *loader = data;
			struct loaded_binary *binary_a = binary_for_address(loader, syscalla->ins);
			if (binary_a != NULL) {
				ins_a += ((uintptr_t)binary_a->id << 48) - (uintptr_t)binary_a->info.base;
			}
			struct loaded_binary *binary_b = binary_for_address(loader, syscallb->ins);
			if (binary_b != NULL) {
				ins_b += ((uintptr_t)binary_b->id << 48) - (uintptr_t)binary_b->info.base;
			}
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
		const struct register_state *register_a = &syscalla->registers.registers[reg];
		const struct register_state *register_b = &syscallb->registers.registers[reg];
		// bool a_is_known = register_is_partially_known(register_a);
		// bool b_is_known = register_is_partially_known(register_b);
		// if (b_is_known && !a_is_known) {
		// 	return -1;
		// }
		// if (!b_is_known && a_is_known) {
		// 	return 1;
		// }
		if (register_a->value < register_b->value) {
			return -1;
		}
		if (register_a->value > register_b->value) {
			return 1;
		}
		if (register_a->max < register_b->max) {
			return -1;
		}
		if (register_a->max > register_b->max) {
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
	register_mask mismatched = ~matching_registers(source->registers.registers, target->registers.registers) & relevant_registers;
	if ((mismatched != 0) && ((mismatched & -mismatched) == mismatched)) {
		// source and target differ by only a single register
		int i = __builtin_ctzl(mismatched);
		return combine_register_states(&target->registers.registers[i], &source->registers.registers[i], i);
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
		merged:
			;
		}
		// keep trying until there are no possible merges
		if (new_count == count) {
			break;
		}
		list = out;
		count = new_count;
	}
	// sort the output so that it's stable
	qsort_r(out, count, sizeof(*out), compare_found_syscalls, loader);
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
				case __NR_setuid:
				case __NR_setgid:
				case __NR_setreuid:
				case __NR_setregid:
				case __NR_setgroups:
				case __NR_setresuid:
				case __NR_setresgid:
				case __NR_setfsuid:
				case __NR_setfsgid: {
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
	qsort_r(syscalls->list, count, sizeof(*syscalls->list), compare_found_syscalls, loader);
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
		if (log_arguments || i == 0 || list[i-1].nr != nr) {
			if (i != 0) {
				log_len++; // '\n'
			}
			if (log_arguments) {
				char *description = copy_syscall_description(context, nr, list[i].registers, include_symbol);
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
		if (log_arguments || i == 0 || list[i-1].nr != list[i].nr) {
			if (i != 0) {
				logbuf[logpos++] = '\n';
			}
			if (log_arguments) {
				char *description = copy_syscall_description(context, nr, list[i].registers, include_symbol);
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

static void push_bpf_insn(struct bpf_insn **array, size_t *cap, size_t *pos, struct bpf_insn value)
{
	size_t new_pos = *pos;
	size_t new_size = new_pos + 1;
	*pos = new_size;
	if (new_size > *cap) {
		*cap = new_size * 2;
		*array = realloc(*array, *cap * sizeof(value));
	}
	(*array)[new_pos] = value;
}

static void push_description(char ***descriptions, size_t *cap, size_t pos, char *description)
{
	if (pos > *cap) {
		*cap = pos * 2;
		*descriptions = realloc(*descriptions, *cap * sizeof(*descriptions));
	}
	(*descriptions)[pos-1] = description;
}

static inline bool special_arg_indexes_for_syscall(int nr, enum register_index *out_map_base_index, enum register_index *out_map_size_index)
{
	switch(nr) {
		case __NR_mmap:
		case __NR_munmap:
		case __NR_mremap:
		case __NR_mprotect:
		case __NR_pkey_mprotect:
		case __NR_remap_file_pages:
			*out_map_base_index = syscall_argument_abi_register_indexes[0];
			*out_map_size_index = syscall_argument_abi_register_indexes[1];
			return true;
		// case __NR_shmat:
		// 	break;
		default:
			return false;
	}
}

struct sock_fprog generate_seccomp_program(struct loader_context *loader, const struct recorded_syscalls *syscalls, const struct mapped_region_info *blocked_memory_regions, uint32_t syscall_range_low, uint32_t syscall_range_high)
{
	bool record_descriptions = SHOULD_LOG;
	struct recorded_syscall *list = syscalls->list;
	int count = syscalls->count;
	struct bpf_insn *filter = NULL;
	char **descriptions = NULL;
	size_t filter_cap = 0;
	size_t descriptions_cap = 0;
	size_t pos = 0;
	// validate architecture
	// can't exec, so don't bother -- architecture cannot change
	// push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)));
	// push_description(&descriptions, &descriptions_cap, pos, strdup("load arch"));
	// push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, CURRENT_AUDIT_ARCH, 1, 0));
	// push_description(&descriptions, &descriptions_cap, pos, strdup("compare CURRENT_AUDIT_ARCH"));
	// push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP));
	// push_description(&descriptions, &descriptions_cap, pos, strdup("return kill process"));
	// load syscall number
	push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)));
	if (record_descriptions) {
		push_description(&descriptions, &descriptions_cap, pos, strdup("load nr"));
	}
	if (syscall_range_low != 0) {
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, syscall_range_low, 1, 0));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("check syscall low"));
		}
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
		}
	}
	if (syscall_range_high != ~(uint32_t)0) {
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, syscall_range_high, 0, 1));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("check syscall high"));
		}
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
		}
	}
	for (int i = 0; i < count;) {
		uintptr_t nr = list[i].nr;
		if (nr < syscall_range_low || nr > syscall_range_high) {
			i++;
			continue;
		}
		size_t nr_pos = pos;
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, nr, 0, 0));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup(name_for_syscall(nr)));
		}
		if (blocked_memory_regions != NULL && blocked_memory_regions->count != 0) {
			enum register_index map_base_reg;
			enum register_index map_size_reg;
			if (special_arg_indexes_for_syscall(nr, &map_base_reg, &map_size_reg)) {
				// read the low part of size
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(map_size_reg)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of size"));
				}
				// shuffle to x register
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_MISC+BPF_TAX, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("shuffle to x register"));
				}
				// read the low part of base
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(map_base_reg)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of base"));
				}
				// add to form the new low bits of max of range
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("add low parts of size and base"));
				}
				// store low bits to the stack at slot 0
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ST, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("store low bits of max to the stack"));
				}
				// check for overflow
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 3, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("check for overflow"));
				}
				// read the high part of size
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(map_size_reg) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of size"));
				}
				// add 1 for overflow
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 1));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("add overflow"));
				}
				// jump to "shuffle to x register"
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_JMP+BPF_JA+BPF_K, 1));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("jump to \"shuffle to x register\""));
				}
				// read the high part of size
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(map_size_reg) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of size"));
				}
				// shuffle to x register
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_MISC+BPF_TAX, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("shuffle to x register"));
				}
				// read the high part of base
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(map_base_reg) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of base"));
				}
				// add to form the new high bits of max of range
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("add high parts of size and base"));
				}
				// store high bits to the stack at slot 1
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ST, 1));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("store high bits of max to the stack"));
				}
				for (int j = 0; j < blocked_memory_regions->count; j++) {
					// reload the high bits of the end of the requested range
					if (j != 0) {
						// not necessary on the first iteration since it was just calculated
						push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_MEM, 1));
						if (record_descriptions) {
							push_description(&descriptions, &descriptions_cap, pos, strdup("reload high bits of max from the stack"));
						}
					}
					// compare the high bits of the end of the requested range with the start of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, blocked_memory_regions->list[j].start >> 32, 0, 9 /* to next case */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of max"));
					}
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, blocked_memory_regions->list[j].start >> 32, 0, 2 /* to after low bits comparison */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of max equality"));
					}
					// load the low bits of the requested range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_MEM, 0));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("reload low bits of max from the stack"));
					}
					// compare the low bits of the end of the requested range with the start of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, blocked_memory_regions->list[j].start & ~(uint32_t)0, 0, 6 /* to next case */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare low bits of max"));
					}
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(map_base_reg) + sizeof(uint32_t)));
					// load the high bits of the start of the requested range
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of base"));
					}
					// compare the high bits of the start of the requested range with the end of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, blocked_memory_regions->list[j].end >> 32, 4 /* to next case */, 0));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of base"));
					}
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, blocked_memory_regions->list[j].end >> 32, 0, 2 /* to after low bits comparison */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of base equality"));
					}
					// load the low bits of the start of the requested range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(map_base_reg)));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of base"));
					}
					// compare the low bits of the start of the requested range with the end of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, blocked_memory_regions->list[j].end & ~(uint32_t)0, 1 /* to next case */, 0));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare low bits of base"));
					}
					// requested range overlaps with the blocked range, return EPERM
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("return EPERM"));
					}
				}
			}
		}
		int attributes = info_for_syscall(nr).attributes;
		if (list[i].ins != NULL && (attributes & SYSCALL_CAN_BE_FROM_ANYWHERE) == 0) {
			// compare instruction pointers
			do {
				// read high part of instruction pointer
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of instruction_pointer"));
				}
				uintptr_t addr = translate_analysis_address_to_child(loader, list[i].ins) + 2; // +2 for the syscall instruction
				// compare high part of instruction pointer
				size_t hi_pos = pos;
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, addr >> 32, 0, 0));
				if (record_descriptions) {
					char *desc = copy_address_description(loader, list[i].ins);
					char *compare_hi = malloc(30 + fs_strlen(desc));
					fs_utoah(addr >> 32, fs_strcpy(fs_strcpy(fs_strcpy(compare_hi, "compare "), desc), " hi part "));
					free(desc);
					push_description(&descriptions, &descriptions_cap, pos, compare_hi);
				}
				// load low part of instruction pointer
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of instruction_pointer"));
				}
				uintptr_t next_addr = addr;
				do {
					uintptr_t low_addr = next_addr;
					// compare low part of instruction pointer
					size_t low_pos = pos;
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uint32_t)low_addr, 0, 1));
					if (record_descriptions) {
						char *desc = copy_address_description(loader, list[i].ins);
						char *compare_low = malloc(30 + fs_strlen(desc));
						fs_utoah(low_addr & 0xffffffff, fs_strcpy(fs_strcpy(fs_strcpy(compare_low, "compare "), desc), " low part "));
						free(desc);
						push_description(&descriptions, &descriptions_cap, pos, compare_low);
					}
					// skip to next syscall + addr combination
					do {
						struct {
							size_t compare_hi;
							size_t compare_low_value;
							size_t compare_low_max;
						} arg_pos[6] = { 0 };
						for (int j = 0; j < (attributes & SYSCALL_ARGC_MASK); j++) {
							int arg_register = syscall_argument_abi_register_indexes[j];
							const struct register_state match_state = translate_register_state_to_child(loader, list[i].registers.registers[arg_register]);
							if (register_is_partially_known(&match_state) && (match_state.value >> 32) == (match_state.max >> 32)) {
								// read high part of argument
								push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(arg_register) + sizeof(uint32_t)));
								if (record_descriptions) {
									char *buf = malloc(50);
									fs_utoa(j, fs_strcpy(buf, "load high part of argument "));
									push_description(&descriptions, &descriptions_cap, pos, buf);
								}
								// compare high part of argument
								arg_pos[j].compare_hi = pos;
								push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, match_state.value >> 32, 0, 0));
								if (record_descriptions) {
									char *buf = malloc(50);
									fs_utoah(match_state.value >> 32, fs_strcpy(buf, "compare high part of argument "));
									push_description(&descriptions, &descriptions_cap, pos, buf);
								}
								// read low part of argument
								push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, seccomp_data_offset_for_register(arg_register)));
								if (record_descriptions) {
									push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of argument"));
								}
								// compare low part of argument
								uint32_t masked_value = match_state.value;
								uint32_t masked_max = match_state.max;
								if (masked_value == masked_max) {
									// compare == value
									arg_pos[j].compare_low_value = pos;
									push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, match_state.value, 0, 0));
									if (record_descriptions) {
										char *buf = malloc(50);
										fs_utoah(masked_value, fs_strcpy(buf, "compare low part of argument "));
										push_description(&descriptions, &descriptions_cap, pos, buf);
									}
								} else {
									// compare >= min
									if (masked_value != 0) {
										arg_pos[j].compare_low_value = pos;
										push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, masked_value, 0, 0));
										if (record_descriptions) {
											char *buf = malloc(50);
											fs_utoah(masked_value, fs_strcpy(buf, "compare low value of argument "));
											push_description(&descriptions, &descriptions_cap, pos, buf);
										}
									}
									// compare <= max
									if (masked_value != 0xffffffff) {
										arg_pos[j].compare_low_max = pos;
										push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, masked_max, 0, 0));
										if (record_descriptions) {
											char *buf = malloc(50);
											fs_utoah(masked_max, fs_strcpy(buf, "compare high value of argument "));
											push_description(&descriptions, &descriptions_cap, pos, buf);
										}
									}
								}
							}
						}
						// return allow
						push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW));
						if (record_descriptions) {
							push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
						}
						// else to next register comparison or the final return trap
						for (int j = 0; j < (attributes & SYSCALL_ARGC_MASK); j++) {
							size_t inner_hi_pos = arg_pos[j].compare_hi;
							if (inner_hi_pos != 0) {
								filter[hi_pos].jf = pos - inner_hi_pos - 1;
							}
							size_t low_value_pos = arg_pos[j].compare_low_value;
							if (low_value_pos != 0) {
								filter[low_value_pos].jf = pos - low_value_pos - 1;
							}
							size_t low_max_pos = arg_pos[j].compare_low_max;
							if (low_max_pos != 0) {
								filter[low_max_pos].jt = pos - low_max_pos - 1;
							}
						}
						i++;
						if (i == count) {
							break;
						}
						next_addr = translate_analysis_address_to_child(loader, list[i].ins) + 2;
					} while(low_addr == next_addr && list[i].nr == nr);
					// else to next address
					filter[low_pos].jf = pos - low_pos - 1;
				} while(i != count && (addr >> 32) == (next_addr >> 32) && list[i].nr == nr);
				// else to next address
				filter[hi_pos].jf = pos - hi_pos - 1;
			} while(i != count && list[i].nr == nr);
			push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP));
			if (record_descriptions) {
				push_description(&descriptions, &descriptions_cap, pos, strdup("return trap"));
			}
		} else {
			// allow all
			push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW));
			if (record_descriptions) {
				push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
			}
			// skip to next syscall
			do {
				i++;
			} while(i != count && list[i].nr == nr);
		}
		// else to next syscall or the final return trap
		filter[nr_pos].jf = pos - nr_pos - 1;
	}
	push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP));
	if (record_descriptions) {
		push_description(&descriptions, &descriptions_cap, pos, strdup("return trap"));
	}
	struct bpf_prog prog = {
		.len = pos,
		.filter = filter,
	};
	optimize_bpf_fprog(&prog, descriptions);
	expand_long_bpf_jumps(&prog, descriptions, pos);
	if (record_descriptions) {
		ERROR("program", temp_str(copy_bpf_prog_description(prog, (const char **)descriptions)));
	}
	if (descriptions != NULL) {
		for (size_t i = 0; i < prog.len; i++) {
			free(descriptions[i]);
		}
		free(descriptions);
	}
	struct sock_fprog result = convert_to_sock_fprog(prog);
	free(filter);
	return result;
}

struct loaded_binary *register_dlopen(struct program_state *analysis, const char *path, const struct analysis_frame *caller, bool skip_analysis, bool skip_analyzing_symbols, bool recursive)
{
	if (!recursive) {
		return register_dlopen_file(analysis, path, caller, skip_analysis, skip_analyzing_symbols);
	}
	int fd = fs_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	if (fd == -ENOTDIR) {
		struct loaded_binary *binary = register_dlopen_file(analysis, path, caller, skip_analysis, skip_analyzing_symbols);
		if (binary == NULL) {
			DIE("failed to load shared object specified via --dlopen", path);
		}
		return binary;
	} else if (fd < 0) {
		ERROR("failed to load shared object specified via --dlopen", path);
		DIE("error is", fs_strerror(fd));
	}
	size_t prefix_len = fs_strlen(path);
	if (path[prefix_len-1] == '/') {
		prefix_len--;
	}
	for (;;) {
		char buf[8192];
		int count = fs_getdents(fd, (struct fs_dirent *)&buf[0], sizeof(buf));
		if (count <= 0) {
			if (count < 0) {
				ERROR("failed to read directory specified via --dlopen", path);
				DIE("error is", fs_strerror(count));
			}
			break;
		}
		for (int offset = 0; offset < count; ) {
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
						register_dlopen(analysis, subpath, caller, skip_analysis, skip_analyzing_symbols, true);
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
		LOG("dequeuing", temp_str(copy_address_description(&analysis->loader, ins.ins)));
		dump_nonempty_registers(&analysis->loader, &ins.registers, ~(register_mask)0);
		struct analysis_frame queued_caller = { .address = ins.caller, .description = ins.description, .next = NULL, .current_state = empty_registers, .entry = ins.caller, .entry_state = &empty_registers, .token = { 0 }, .is_entry = false };
		// TODO: determine if this should always be considered a function entry point
		analyze_function(analysis, ins.effects, &ins.registers, ins.ins, &queued_caller);
	}

	sort_and_coalesce_syscalls(&analysis->syscalls, &analysis->loader);
}
