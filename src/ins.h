#ifndef INS_H
#define INS_H

#define MORE_STACK_SLOTS 1

#include "axon.h"

#include <stdbool.h>
#include <stdint.h>

#include <elf.h>

typedef int16_t ins_int16 __attribute__((aligned(1)));
typedef uint16_t ins_uint16 __attribute__((aligned(1)));
typedef int32_t ins_int32 __attribute__((aligned(1)));
typedef uint32_t ins_uint32 __attribute__((aligned(1)));
typedef int64_t ins_int64 __attribute__((aligned(1)));
typedef uint64_t ins_uint64 __attribute__((aligned(1)));

enum ins_jump_behavior
{
	INS_JUMPS_NEVER,
	INS_JUMPS_ALWAYS,
	INS_JUMPS_OR_CONTINUES,
	INS_JUMPS_ALWAYS_INDIRECT,
};

enum ins_operand_size
{
	OPERATION_SIZE_BYTE = 1,
	OPERATION_SIZE_HALF = 2,
	OPERATION_SIZE_WORD = 4,
	OPERATION_SIZE_DWORD = 8,
};

__attribute__((always_inline)) static inline uintptr_t mask_for_operand_size(enum ins_operand_size operand_size)
{
	switch (operand_size) {
		case OPERATION_SIZE_BYTE:
			return 0xff;
		case OPERATION_SIZE_HALF:
			return 0xffff;
		case OPERATION_SIZE_WORD:
			return 0xffffffff;
		default:
			return ~(uintptr_t)0;
	}
}

__attribute__((always_inline)) static inline intptr_t sign_extend(uintptr_t value, enum ins_operand_size operand_size)
{
	switch (operand_size) {
		case OPERATION_SIZE_BYTE:
			return (intptr_t)(int8_t)value;
		case OPERATION_SIZE_HALF:
			return (intptr_t)(int16_t)value;
		case OPERATION_SIZE_WORD:
			return (intptr_t)(int32_t)value;
		case OPERATION_SIZE_DWORD:
		default:
			return (intptr_t)(int64_t)value;
	}
}

struct register_state
{
	uintptr_t value;
	uintptr_t max;
};

__attribute__((nonnull(1))) static inline void clear_register(struct register_state *reg)
{
	reg->value = (uintptr_t)0;
	reg->max = ~(uintptr_t)0;
}

__attribute__((nonnull(1))) static inline void set_register(struct register_state *reg, uintptr_t value)
{
	reg->value = value;
	reg->max = value;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool register_is_exactly_known(const struct register_state *reg)
{
	return reg->value == reg->max;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool register_is_partially_known(const struct register_state *reg)
{
	return reg->value != (uintptr_t)0 || reg->max != ~(uintptr_t)0;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool truncate_to_8bit(struct register_state *reg)
{
	if ((reg->max >> 8) == (reg->value >> 8)) {
		if ((reg->max >> 8) == 0) {
			return false;
		}
		reg->value &= 0xff;
		reg->max &= 0xff;
		if (reg->value <= reg->max) {
			return true;
		}
	}
	reg->value = 0;
	reg->max = 0xff;
	return true;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool truncate_to_16bit(struct register_state *reg)
{
	if ((reg->max >> 16) == (reg->value >> 16)) {
		if ((reg->max >> 16) == 0) {
			return false;
		}
		reg->value &= 0xffff;
		reg->max &= 0xffff;
		if (reg->value <= reg->max) {
			return true;
		}
	}
	reg->value = 0;
	reg->max = 0xffff;
	return true;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool truncate_to_32bit(struct register_state *reg)
{
	if ((reg->max >> 32) == (reg->value >> 32)) {
		if ((reg->max >> 32) == 0) {
			return false;
		}
		reg->value &= 0xffffffff;
		reg->max &= 0xffffffff;
		if (reg->value <= reg->max) {
			return true;
		}
	}
	reg->value = 0;
	reg->max = 0xffffffff;
	return true;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool truncate_to_operand_size(struct register_state *reg, enum ins_operand_size operand_size)
{
	uintptr_t mask = mask_for_operand_size(operand_size);
	if ((reg->max & ~mask) == (reg->value & ~mask)) {
		if ((reg->max & ~mask) == 0) {
			return false;
		}
		reg->value &= mask;
		reg->max &= mask;
		if (reg->value <= reg->max) {
			return true;
		}
	}
	reg->value = 0;
	reg->max = mask;
	return true;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool sign_extend_from_operand_size(struct register_state *reg, enum ins_operand_size operand_size)
{
	if (reg->value & ((uintptr_t)1 << (operand_size * 8 - 1))) {
		reg->value |= ~(uintptr_t)0 << (operand_size * 8 - 1);
		reg->max |= ~(uintptr_t)0 << (operand_size * 8 - 1);
		return true;
	}
	if (reg->max & ((uintptr_t)1 << (operand_size * 8 - 1))) {
		reg->max |= ~(uintptr_t)0 << (operand_size * 8 - 1);
		return true;
	}
	return false;
}

#if MORE_STACK_SLOTS
#define STACK_SLOT_COUNT 63
#define GENERATE_PER_STACK_REGISTER() \
	PER_STACK_REGISTER_IMPL(0)        \
	PER_STACK_REGISTER_IMPL(4)        \
	PER_STACK_REGISTER_IMPL(8)        \
	PER_STACK_REGISTER_IMPL(12)       \
	PER_STACK_REGISTER_IMPL(16)       \
	PER_STACK_REGISTER_IMPL(20)       \
	PER_STACK_REGISTER_IMPL(24)       \
	PER_STACK_REGISTER_IMPL(28)       \
	PER_STACK_REGISTER_IMPL(32)       \
	PER_STACK_REGISTER_IMPL(36)       \
	PER_STACK_REGISTER_IMPL(40)       \
	PER_STACK_REGISTER_IMPL(44)       \
	PER_STACK_REGISTER_IMPL(48)       \
	PER_STACK_REGISTER_IMPL(52)       \
	PER_STACK_REGISTER_IMPL(56)       \
	PER_STACK_REGISTER_IMPL(60)       \
	PER_STACK_REGISTER_IMPL(64)       \
	PER_STACK_REGISTER_IMPL(68)       \
	PER_STACK_REGISTER_IMPL(72)       \
	PER_STACK_REGISTER_IMPL(76)       \
	PER_STACK_REGISTER_IMPL(80)       \
	PER_STACK_REGISTER_IMPL(84)       \
	PER_STACK_REGISTER_IMPL(88)       \
	PER_STACK_REGISTER_IMPL(92)       \
	PER_STACK_REGISTER_IMPL(96)       \
	PER_STACK_REGISTER_IMPL(100)      \
	PER_STACK_REGISTER_IMPL(104)      \
	PER_STACK_REGISTER_IMPL(108)      \
	PER_STACK_REGISTER_IMPL(112)      \
	PER_STACK_REGISTER_IMPL(116)      \
	PER_STACK_REGISTER_IMPL(120)      \
	PER_STACK_REGISTER_IMPL(124)      \
	PER_STACK_REGISTER_IMPL(128)      \
	PER_STACK_REGISTER_IMPL(132)      \
	PER_STACK_REGISTER_IMPL(136)      \
	PER_STACK_REGISTER_IMPL(140)      \
	PER_STACK_REGISTER_IMPL(144)      \
	PER_STACK_REGISTER_IMPL(148)      \
	PER_STACK_REGISTER_IMPL(152)      \
	PER_STACK_REGISTER_IMPL(156)      \
	PER_STACK_REGISTER_IMPL(160)      \
	PER_STACK_REGISTER_IMPL(164)      \
	PER_STACK_REGISTER_IMPL(168)      \
	PER_STACK_REGISTER_IMPL(172)      \
	PER_STACK_REGISTER_IMPL(176)      \
	PER_STACK_REGISTER_IMPL(180)      \
	PER_STACK_REGISTER_IMPL(184)      \
	PER_STACK_REGISTER_IMPL(188)      \
	PER_STACK_REGISTER_IMPL(192)      \
	PER_STACK_REGISTER_IMPL(196)      \
	PER_STACK_REGISTER_IMPL(200)      \
	PER_STACK_REGISTER_IMPL(204)      \
	PER_STACK_REGISTER_IMPL(208)      \
	PER_STACK_REGISTER_IMPL(212)      \
	PER_STACK_REGISTER_IMPL(216)      \
	PER_STACK_REGISTER_IMPL(220)      \
	PER_STACK_REGISTER_IMPL(224)      \
	PER_STACK_REGISTER_IMPL(228)      \
	PER_STACK_REGISTER_IMPL(232)      \
	PER_STACK_REGISTER_IMPL(236)      \
	PER_STACK_REGISTER_IMPL(240)      \
	PER_STACK_REGISTER_IMPL(244)      \
	PER_STACK_REGISTER_IMPL(248)
#else
#define STACK_SLOT_COUNT 30
#define GENERATE_PER_STACK_REGISTER() \
	PER_STACK_REGISTER_IMPL(0)        \
	PER_STACK_REGISTER_IMPL(4)        \
	PER_STACK_REGISTER_IMPL(8)        \
	PER_STACK_REGISTER_IMPL(12)       \
	PER_STACK_REGISTER_IMPL(16)       \
	PER_STACK_REGISTER_IMPL(20)       \
	PER_STACK_REGISTER_IMPL(24)       \
	PER_STACK_REGISTER_IMPL(28)       \
	PER_STACK_REGISTER_IMPL(32)       \
	PER_STACK_REGISTER_IMPL(36)       \
	PER_STACK_REGISTER_IMPL(40)       \
	PER_STACK_REGISTER_IMPL(44)       \
	PER_STACK_REGISTER_IMPL(48)       \
	PER_STACK_REGISTER_IMPL(52)       \
	PER_STACK_REGISTER_IMPL(56)       \
	PER_STACK_REGISTER_IMPL(60)       \
	PER_STACK_REGISTER_IMPL(64)       \
	PER_STACK_REGISTER_IMPL(68)       \
	PER_STACK_REGISTER_IMPL(72)       \
	PER_STACK_REGISTER_IMPL(76)       \
	PER_STACK_REGISTER_IMPL(80)       \
	PER_STACK_REGISTER_IMPL(84)       \
	PER_STACK_REGISTER_IMPL(88)       \
	PER_STACK_REGISTER_IMPL(92)       \
	PER_STACK_REGISTER_IMPL(96)       \
	PER_STACK_REGISTER_IMPL(100)      \
	PER_STACK_REGISTER_IMPL(104)      \
	PER_STACK_REGISTER_IMPL(108)      \
	PER_STACK_REGISTER_IMPL(112)      \
	PER_STACK_REGISTER_IMPL(116)
#endif

#ifdef __x86_64__

enum x86_register_index
{
	X86_REGISTER_AX,
	X86_REGISTER_CX,
	X86_REGISTER_DX,
	X86_REGISTER_BX,
	X86_REGISTER_SP,
	X86_REGISTER_BP,
	X86_REGISTER_SI,
	X86_REGISTER_DI,
	X86_REGISTER_8,
	X86_REGISTER_9,
	X86_REGISTER_10,
	X86_REGISTER_11,
	X86_REGISTER_12,
	X86_REGISTER_13,
	X86_REGISTER_14,
	X86_REGISTER_15,
};

enum register_index
{
#define BASE_REGISTER_COUNT 16
	REGISTER_RAX = X86_REGISTER_AX,
	REGISTER_RCX = X86_REGISTER_CX,
	REGISTER_RDX = X86_REGISTER_DX,
	REGISTER_RBX = X86_REGISTER_BX,
	REGISTER_SP = X86_REGISTER_SP,
	REGISTER_RBP = X86_REGISTER_BP,
	REGISTER_RSI = X86_REGISTER_SI,
	REGISTER_RDI = X86_REGISTER_DI,
	REGISTER_R8 = X86_REGISTER_8,
	REGISTER_R9 = X86_REGISTER_9,
	REGISTER_R10 = X86_REGISTER_10,
	REGISTER_R11 = X86_REGISTER_11,
	REGISTER_R12 = X86_REGISTER_12,
	REGISTER_R13 = X86_REGISTER_13,
	REGISTER_R14 = X86_REGISTER_14,
	REGISTER_R15 = X86_REGISTER_15,
	REGISTER_MEM,

#define PER_STACK_REGISTER_IMPL(offset) REGISTER_STACK_##offset,
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
};
#endif

#ifdef __aarch64__
enum aarch64_register_index
{
	AARCH64_REGISTER_INVALID = -1,
	AARCH64_REGISTER_X0 = 0,
	AARCH64_REGISTER_X1,
	AARCH64_REGISTER_X2,
	AARCH64_REGISTER_X3,
	AARCH64_REGISTER_X4,
	AARCH64_REGISTER_X5,
	AARCH64_REGISTER_X6,
	AARCH64_REGISTER_X7,
	AARCH64_REGISTER_X8,
	AARCH64_REGISTER_X9,
	AARCH64_REGISTER_X10,
	AARCH64_REGISTER_X11,
	AARCH64_REGISTER_X12,
	AARCH64_REGISTER_X13,
	AARCH64_REGISTER_X14,
	AARCH64_REGISTER_X15,
	AARCH64_REGISTER_X16,
	AARCH64_REGISTER_X17,
	AARCH64_REGISTER_X18,
	AARCH64_REGISTER_X19,
	AARCH64_REGISTER_X20,
	AARCH64_REGISTER_X21,
	AARCH64_REGISTER_X22,
	AARCH64_REGISTER_X23,
	AARCH64_REGISTER_X24,
	AARCH64_REGISTER_X25,
	AARCH64_REGISTER_X26,
	AARCH64_REGISTER_X27,
	AARCH64_REGISTER_X28,
	AARCH64_REGISTER_SP,
};

#define BASE_REGISTER_COUNT 30
enum register_index
{
	REGISTER_X0 = AARCH64_REGISTER_X0,
	REGISTER_X1 = AARCH64_REGISTER_X1,
	REGISTER_X2 = AARCH64_REGISTER_X2,
	REGISTER_X3 = AARCH64_REGISTER_X3,
	REGISTER_X4 = AARCH64_REGISTER_X4,
	REGISTER_X5 = AARCH64_REGISTER_X5,
	REGISTER_X6 = AARCH64_REGISTER_X6,
	REGISTER_X7 = AARCH64_REGISTER_X7,
	REGISTER_X8 = AARCH64_REGISTER_X8,
	REGISTER_X9 = AARCH64_REGISTER_X9,
	REGISTER_X10 = AARCH64_REGISTER_X10,
	REGISTER_X11 = AARCH64_REGISTER_X11,
	REGISTER_X12 = AARCH64_REGISTER_X12,
	REGISTER_X13 = AARCH64_REGISTER_X13,
	REGISTER_X14 = AARCH64_REGISTER_X14,
	REGISTER_X15 = AARCH64_REGISTER_X15,
	REGISTER_X16 = AARCH64_REGISTER_X16,
	REGISTER_X17 = AARCH64_REGISTER_X17,
	REGISTER_X18 = AARCH64_REGISTER_X18,
	REGISTER_X19 = AARCH64_REGISTER_X19,
	REGISTER_X20 = AARCH64_REGISTER_X20,
	REGISTER_X21 = AARCH64_REGISTER_X21,
	REGISTER_X22 = AARCH64_REGISTER_X22,
	REGISTER_X23 = AARCH64_REGISTER_X23,
	REGISTER_X24 = AARCH64_REGISTER_X24,
	REGISTER_X25 = AARCH64_REGISTER_X25,
	REGISTER_X26 = AARCH64_REGISTER_X26,
	REGISTER_X27 = AARCH64_REGISTER_X27,
	REGISTER_X28 = AARCH64_REGISTER_X28,
	REGISTER_SP = AARCH64_REGISTER_SP,

	REGISTER_MEM,

#define PER_STACK_REGISTER_IMPL(offset) REGISTER_STACK_##offset,
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
};

#endif

enum
{
	REGISTER_INVALID = -1,
	REGISTER_COUNT = BASE_REGISTER_COUNT + 1 + STACK_SLOT_COUNT,

#ifdef __x86_64__
	REGISTER_SYSCALL_NR = X86_REGISTER_AX,
	REGISTER_SYSCALL_ARG0 = X86_REGISTER_DI,
	REGISTER_SYSCALL_ARG1 = X86_REGISTER_SI,
	REGISTER_SYSCALL_ARG2 = X86_REGISTER_DX,
	REGISTER_SYSCALL_ARG3 = X86_REGISTER_10,
	REGISTER_SYSCALL_ARG4 = X86_REGISTER_8,
	REGISTER_SYSCALL_ARG5 = X86_REGISTER_9,
	REGISTER_SYSCALL_RESULT = X86_REGISTER_AX,

	SYSV_REGISTER_ARGUMENT_COUNT = 6,
#define CALL_PRESERVED_REGISTERS (mask_for_register(REGISTER_RBX) | mask_for_register(REGISTER_RBP) | mask_for_register(REGISTER_R12) | mask_for_register(REGISTER_R13) | mask_for_register(REGISTER_R14) | mask_for_register(REGISTER_R15))
#else
#ifdef __aarch64__
	REGISTER_SYSCALL_NR = AARCH64_REGISTER_X8,
	REGISTER_SYSCALL_ARG0 = AARCH64_REGISTER_X0,
	REGISTER_SYSCALL_ARG1 = AARCH64_REGISTER_X1,
	REGISTER_SYSCALL_ARG2 = AARCH64_REGISTER_X2,
	REGISTER_SYSCALL_ARG3 = AARCH64_REGISTER_X3,
	REGISTER_SYSCALL_ARG4 = AARCH64_REGISTER_X4,
	REGISTER_SYSCALL_ARG5 = AARCH64_REGISTER_X5,
	REGISTER_SYSCALL_RESULT = AARCH64_REGISTER_X0,

	SYSV_REGISTER_ARGUMENT_COUNT = 8,
#define CALL_PRESERVED_REGISTERS                                                                                                                                                                                 \
	(mask_for_register(REGISTER_X19) | mask_for_register(REGISTER_X20) | mask_for_register(REGISTER_X21) | mask_for_register(REGISTER_X22) | mask_for_register(REGISTER_X23) | mask_for_register(REGISTER_X24) | \
	 mask_for_register(REGISTER_X25) | mask_for_register(REGISTER_X26) | mask_for_register(REGISTER_X27) | mask_for_register(REGISTER_X28))
#else
#error "Unknown architecture"
#endif
#endif
};

#define REGISTER_COUNT (BASE_REGISTER_COUNT + 1 + STACK_SLOT_COUNT)

__attribute__((always_inline)) static inline int ctzuint128(__uint128_t value)
{
	union {
		__uint128_t value;
		struct
		{
			uint64_t low;
			uint64_t high;
		} parts;
	} temp;
	temp.value = value;
	return (temp.parts.low != 0) ? __builtin_ctzll(temp.parts.low) : (64 + __builtin_ctzll(temp.parts.high));
}

#if REGISTER_COUNT > 64
typedef __uint128_t register_mask;
__attribute__((always_inline)) static inline int first_set_register_in_mask(register_mask mask)
{
	return ctzuint128(mask);
}
#else
typedef uint64_t register_mask;
__attribute__((always_inline)) static inline int first_set_register_in_mask(register_mask mask)
{
	return __builtin_ctzll(mask);
}
#endif

__attribute__((always_inline)) static inline register_mask mask_for_conditional_register(bool conditional, enum register_index index)
{
#if REGISTER_COUNT > 64
	union {
		register_mask mask;
		struct
		{
			uint64_t low;
			uint64_t high;
		} parts;
	} temp;
	if (LIKELY(index < 64)) {
		temp.parts.low = (uint64_t)conditional << index;
		temp.parts.high = 0;
	} else {
		temp.parts.low = 0;
		temp.parts.high = (uint64_t)conditional << (index - 64);
	}
	return temp.mask;
#else
	return (register_mask)conditional << index;
#endif
}

__attribute__((always_inline)) static inline register_mask mask_for_register(enum register_index index)
{
	return mask_for_conditional_register(true, index);
}

#define ALL_REGISTERS ((~(register_mask)0) >> (sizeof(register_mask) * 8 - REGISTER_COUNT))
#define STACK_REGISTERS ((~(register_mask)0 << (BASE_REGISTER_COUNT + 1)) & ALL_REGISTERS)

struct __attribute__((packed)) decoded_rm
{
#if defined(__x86_64__)
	uintptr_t addr;
	uint16_t rm : 6;
	uint16_t base : 4;
	uint16_t index : 4;
	uint16_t scale : 2;
#endif
};

enum
{
	COMPARISON_IS_INVALID = 0,
	COMPARISON_SUPPORTS_EQUALITY = 1,
	COMPARISON_SUPPORTS_RANGE = 2,
	COMPARISON_SUPPORTS_ANY = COMPARISON_SUPPORTS_EQUALITY | COMPARISON_SUPPORTS_RANGE,
};

typedef uint8_t comparison_validity;

struct register_comparison
{
	struct register_state value;
	uintptr_t mask;
	struct decoded_rm mem_rm;
	register_mask sources;
	uint8_t target_register : 6;
	comparison_validity validity : 2;
};

#if defined(__x86_64__)

#include "x86.h"

#define ARCH_NAME "x86_64"
typedef const uint8_t *ins_ptr;
#define decoded_ins x86_instruction

#define decode_ins x86_decode_instruction
#define next_ins x86_next_instruction

#define is_return_ins x86_is_return_instruction

#define is_landing_pad_ins x86_is_endbr64_instruction

#define ins_interpret_jump_behavior x86_decode_jump_instruction

#define ins_conditional_type enum x86_conditional_type
#define INS_CONDITIONAL_TYPE_OVERFLOW X86_CONDITIONAL_TYPE_OVERFLOW
#define INS_CONDITIONAL_TYPE_NOT_OVERFLOW X86_CONDITIONAL_TYPE_NOT_OVERFLOW
#define INS_CONDITIONAL_TYPE_BELOW X86_CONDITIONAL_TYPE_BELOW
#define INS_CONDITIONAL_TYPE_ABOVE_OR_EQUAL X86_CONDITIONAL_TYPE_ABOVE_OR_EQUAL
#define INS_CONDITIONAL_TYPE_EQUAL X86_CONDITIONAL_TYPE_EQUAL
#define INS_CONDITIONAL_TYPE_NOT_EQUAL X86_CONDITIONAL_TYPE_NOT_EQUAL
#define INS_CONDITIONAL_TYPE_BELOW_OR_EQUAL X86_CONDITIONAL_TYPE_BELOW_OR_EQUAL
#define INS_CONDITIONAL_TYPE_ABOVE X86_CONDITIONAL_TYPE_ABOVE
#define INS_CONDITIONAL_TYPE_SIGN X86_CONDITIONAL_TYPE_SIGN
#define INS_CONDITIONAL_TYPE_NOT_SIGN X86_CONDITIONAL_TYPE_NOT_SIGN
#define INS_CONDITIONAL_TYPE_PARITY X86_CONDITIONAL_TYPE_PARITY
#define INS_CONDITIONAL_TYPE_PARITY_ODD X86_CONDITIONAL_TYPE_PARITY_ODD
#define INS_CONDITIONAL_TYPE_LOWER X86_CONDITIONAL_TYPE_LOWER
#define INS_CONDITIONAL_TYPE_GREATER_OR_EQUAL X86_CONDITIONAL_TYPE_GREATER_OR_EQUAL
#define INS_CONDITIONAL_TYPE_NOT_GREATER X86_CONDITIONAL_TYPE_NOT_GREATER
#define INS_CONDITIONAL_TYPE_GREATER X86_CONDITIONAL_TYPE_GREATER

static inline ins_conditional_type ins_get_conditional_type(const struct decoded_ins *decoded, __attribute__((unused)) struct register_comparison *out_compare_state)
{
	return x86_get_conditional_type(decoded->unprefixed);
}

static inline bool address_is_call_aligned(__attribute__((unused)) uintptr_t address)
{
	return true;
}

static inline long ins_syscall_poke_pattern(long original_bytes)
{
	return (original_bytes & ~(long)0xffffffff) | 0xfdeb050f;
}

static inline long ins_breakpoint_poke_pattern(long original_bytes)
{
	return (original_bytes & ~(long)0xff) | 0xcc;
}

#define INS_BREAKPOINT_LEN 1
#define INS_BREAKS_AFTER_BREAKPOINT 1

#define INS_R_NONE R_X86_64_NONE
#define INS_R_64 R_X86_64_64
#define INS_R_PC32 R_X86_64_PC32
#define INS_R_GOT32 R_X86_64_GOT32
#define INS_R_PLT32 R_X86_64_PLT32
#define INS_R_COPY R_X86_64_COPY
#define INS_R_GLOB_DAT R_X86_64_GLOB_DAT
#define INS_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define INS_R_RELATIVE64 R_X86_64_RELATIVE64
#define INS_R_RELATIVE R_X86_64_RELATIVE
#define INS_R_TLSDESC R_X86_64_TLSDESC
#define INS_R_TLS_DTPREL R_X86_64_DTPOFF64
#define INS_R_TLS_DTPMOD R_X86_64_DTPMOD64
#define INS_R_TLS_TPREL R_X86_64_TPOFF64
#define INS_R_IRELATIVE R_X86_64_IRELATIVE

#else
#if defined(__aarch64__)

#include "aarch64.h"

#define ARCH_NAME "aarch64"
typedef const uint32_t *ins_ptr;
#define decoded_ins aarch64_instruction

#define decode_ins aarch64_decode_instruction
#define next_ins(ins, unused) (&(ins)[1])

#define is_return_ins aarch64_is_return_instruction

#define is_landing_pad_ins aarch64_is_bti_instruction

#define ins_interpret_jump_behavior aarch64_decode_jump_instruction

#define ins_conditional_type enum aarch64_conditional_type
#define INS_CONDITIONAL_TYPE_OVERFLOW AARCH64_CONDITIONAL_TYPE_VS
#define INS_CONDITIONAL_TYPE_NOT_OVERFLOW AARCH64_CONDITIONAL_TYPE_VC
#define INS_CONDITIONAL_TYPE_BELOW AARCH64_CONDITIONAL_TYPE_CC
#define INS_CONDITIONAL_TYPE_ABOVE_OR_EQUAL AARCH64_CONDITIONAL_TYPE_CS
#define INS_CONDITIONAL_TYPE_EQUAL AARCH64_CONDITIONAL_TYPE_EQ
#define INS_CONDITIONAL_TYPE_NOT_EQUAL AARCH64_CONDITIONAL_TYPE_NE
#define INS_CONDITIONAL_TYPE_BELOW_OR_EQUAL AARCH64_CONDITIONAL_TYPE_LS
#define INS_CONDITIONAL_TYPE_ABOVE AARCH64_CONDITIONAL_TYPE_HI
#define INS_CONDITIONAL_TYPE_SIGN AARCH64_CONDITIONAL_TYPE_PL
#define INS_CONDITIONAL_TYPE_NOT_SIGN AARCH64_CONDITIONAL_TYPE_MI
#define INS_CONDITIONAL_TYPE_LOWER AARCH64_CONDITIONAL_TYPE_LT
#define INS_CONDITIONAL_TYPE_GREATER_OR_EQUAL AARCH64_CONDITIONAL_TYPE_GE
#define INS_CONDITIONAL_TYPE_NOT_GREATER AARCH64_CONDITIONAL_TYPE_LE
#define INS_CONDITIONAL_TYPE_GREATER AARCH64_CONDITIONAL_TYPE_GT
#define INS_CONDITIONAL_TYPE_BIT_CLEARED AARCH64_CONDITIONAL_TYPE_BC
#define INS_CONDITIONAL_TYPE_BIT_SET AARCH64_CONDITIONAL_TYPE_BS

#define ins_get_conditional_type aarch64_get_conditional_type

static inline bool address_is_call_aligned(uintptr_t address)
{
	return (address & 0x3) == 0;
}

static inline long ins_syscall_poke_pattern(long original_bytes)
{
	return (original_bytes & ~(long)0xffffffff) | 0xd4000001;
}

static inline long ins_breakpoint_poke_pattern(long original_bytes)
{
	return (original_bytes & ~(long)0xffffffff) | 0xd4200000;
}

#define INS_BREAKPOINT_LEN 4
#define INS_BREAKS_AFTER_BREAKPOINT 0

#define INS_R_NONE R_AARCH64_NONE
#define INS_R_64 R_AARCH64_ABS64
#define INS_R_COPY R_AARCH64_COPY
#define INS_R_GLOB_DAT R_AARCH64_GLOB_DAT
#define INS_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define INS_R_RELATIVE R_AARCH64_RELATIVE
#define INS_R_TLSDESC R_AARCH64_TLSDESC
#define INS_R_TLS_DTPREL R_AARCH64_TLS_DTPREL
#define INS_R_TLS_DTPMOD R_AARCH64_TLS_DTPMOD
#define INS_R_TLS_TPREL R_AARCH64_TLS_TPREL
#define INS_R_IRELATIVE R_AARCH64_IRELATIVE

#else
#error "Unsupported architecture"
#endif
#endif

static inline bool ins_relocation_type_requires_symbol(Elf64_Word type)
{
	switch (type) {
		case INS_R_NONE:
		case INS_R_RELATIVE:
		case INS_R_TLSDESC:
		case INS_R_TLS_DTPREL:
		case INS_R_TLS_DTPMOD:
		case INS_R_TLS_TPREL:
		case INS_R_IRELATIVE:
#if defined(__x86_64__)
		case R_X86_64_TPOFF32:
#endif
			return false;
		default:
			return true;
	}
}

#endif
