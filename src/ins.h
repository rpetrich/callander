#ifndef INS_H
#define INS_H

enum ins_jump_behavior {
	INS_JUMPS_NEVER,
	INS_JUMPS_ALWAYS,
	INS_JUMPS_OR_CONTINUES,
	INS_JUMPS_ALWAYS_INDIRECT,
};

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
