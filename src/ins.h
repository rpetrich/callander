#ifndef INS_H
#define INS_H

#include <stdint.h>

typedef int16_t ins_int16 __attribute__((aligned(1)));
typedef uint16_t ins_uint16 __attribute__((aligned(1)));
typedef int32_t ins_int32 __attribute__((aligned(1)));
typedef uint32_t ins_uint32 __attribute__((aligned(1)));
typedef int64_t ins_int64 __attribute__((aligned(1)));
typedef uint64_t ins_uint64 __attribute__((aligned(1)));

enum ins_jump_behavior {
	INS_JUMPS_NEVER,
	INS_JUMPS_ALWAYS,
	INS_JUMPS_OR_CONTINUES,
	INS_JUMPS_ALWAYS_INDIRECT,
};

enum ins_operand_size {
	OPERATION_SIZE_BYTE = 1,
	OPERATION_SIZE_HALF = 2,
	OPERATION_SIZE_WORD = 4,
	OPERATION_SIZE_DWORD = 8,
};

__attribute__((always_inline))
static inline uintptr_t mask_for_operand_size(enum ins_operand_size operand_size)
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

__attribute__((always_inline))
static inline intptr_t sign_extend(uintptr_t value, enum ins_operand_size operand_size)
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


struct register_state {
	uintptr_t value;
	uintptr_t max;
};

__attribute__((nonnull(1)))
static inline void clear_register(struct register_state *reg) {
	reg->value = (uintptr_t)0;
	reg->max = ~(uintptr_t)0;
}

__attribute__((nonnull(1)))
static inline void set_register(struct register_state *reg, uintptr_t value) {
	reg->value = value;
	reg->max = value;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline bool register_is_exactly_known(const struct register_state *reg) {
	return reg->value == reg->max;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline bool register_is_partially_known(const struct register_state *reg) {
	return reg->value != (uintptr_t)0 || reg->max != ~(uintptr_t)0;
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

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline void truncate_to_operand_size(struct register_state *reg, enum ins_operand_size operand_size) {
	uintptr_t mask = mask_for_operand_size(operand_size);
	if ((reg->max & ~mask) == (reg->value & ~mask)) {
		reg->value &= mask;
		reg->max &= mask;
		if (reg->value <= reg->max) {
			return;
		}
	}
	reg->value = 0;
	reg->max = mask;
}

#if defined(__x86_64__)

#include "x86.h"

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

static inline ins_conditional_type ins_get_conditional_type(const struct decoded_ins *decoded)
{
	return x86_get_conditional_type(decoded->unprefixed);
}

#else
#if defined(__aarch64__)

#include "aarch64.h"
typedef const uint32_t *ins_ptr;
#define decoded_ins aarch64_instruction

#define decode_ins aarch64_decode_instruction
#define next_ins(ins, unused) (&(ins)[1])

#define is_return_ins aarch64_is_return_instruction

#define is_landing_pad_ins aarch64_is_bti_instruction

#define ins_interpret_jump_behavior aarch64_decode_jump_instruction

#define ins_conditional_type enum Condition
#define INS_CONDITIONAL_TYPE_OVERFLOW COND_VS
#define INS_CONDITIONAL_TYPE_NOT_OVERFLOW COND_VC
#define INS_CONDITIONAL_TYPE_BELOW COND_CS
#define INS_CONDITIONAL_TYPE_ABOVE_OR_EQUAL COND_CC
#define INS_CONDITIONAL_TYPE_EQUAL COND_EQ
#define INS_CONDITIONAL_TYPE_NOT_EQUAL COND_NE
#define INS_CONDITIONAL_TYPE_BELOW_OR_EQUAL COND_LE
#define INS_CONDITIONAL_TYPE_ABOVE COND_GT
#define INS_CONDITIONAL_TYPE_SIGN COND_PL
#define INS_CONDITIONAL_TYPE_NOT_SIGN COND_MI
#define INS_CONDITIONAL_TYPE_PARITY /* not present */
#define INS_CONDITIONAL_TYPE_PARITY_ODD /* not present */
#define INS_CONDITIONAL_TYPE_LOWER COND_LT
#define INS_CONDITIONAL_TYPE_GREATER_OR_EQUAL COND_GE
#define INS_CONDITIONAL_TYPE_NOT_GREATER COND_LS
#define INS_CONDITIONAL_TYPE_GREATER COND_HI

#define ins_get_conditional_type aarch64_get_conditional_type

#else
#error "Unsupported architecture"
#endif
#endif

#endif
