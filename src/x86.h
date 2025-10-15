#ifndef X86_H
#define X86_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "axon.h"
#include "ins.h"
#include "x86_64_length_disassembler.h"

// x86_is_syscall_instruction checks if the instruction at address is a syscall
bool x86_is_syscall_instruction(const uint8_t *addr);

// x86_is_nop_instruction checks if the instruction at address is a nop
bool x86_is_nop_instruction(const uint8_t *addr);

struct x86_ins_prefixes
{
	bool has_lock : 1;
	bool has_repne : 1;
	bool has_rep : 1;
	bool has_w : 1;
	bool has_r : 1;
	bool has_x : 1;
	bool has_b : 1;
	bool has_any_rex : 1;
	bool has_segment_override : 1;
	bool has_notrack : 1;
	bool has_operand_size_override : 1;
	bool has_address_size_override : 1;
	// bool has_taken_hint:1;
	// bool has_not_taken_hint:1;
	// bool has_three_byte_vex:1;
	bool has_vex : 1;
	// bool has_xop:1;
};

__attribute__((always_inline)) __attribute__((nonnull(1))) static inline struct x86_ins_prefixes x86_decode_ins_prefixes(const uint8_t **ins)
{
	struct x86_ins_prefixes result = {0};
	if (**ins == 0x3e) {
		// notrack prefix for CET. not used
		result.has_notrack = true;
		++(*ins);
	}
#pragma GCC unroll 16
	for (int i = 0; i < 16; i++) {
		uint8_t value = **ins;
		if (value == 0xf0) {
			// lock prefix
			result.has_lock = true;
		} else if (value == 0xf2) {
			// repne prefix
			result.has_repne = true;
		} else if (value == 0xf3) {
			// rep prefix
			result.has_rep = true;
		} else if ((value & 0xf0) == 0x40) {
			// rex prefix
			result.has_w = (value & 0x8) != 0;
			result.has_r = (value & 0x4) != 0;
			result.has_x = (value & 0x2) != 0;
			result.has_b = (value & 0x1) != 0;
			result.has_any_rex = true;
		} else if (value == 0x66) {
			// operand size override
			result.has_operand_size_override = true;
		} else if (value == 0x67) {
			// address size override
			result.has_address_size_override = true;
		} else if (value == 0x2e) {
			// cs segment override
			result.has_segment_override = true;
		} else if (value == 0x36) {
			// ss segment override
			result.has_segment_override = true;
		} else if (value == 0x3e) {
			// ds segment override
			result.has_segment_override = true;
		} else if (value == 0x26) {
			// es segment override
			result.has_segment_override = true;
		} else if (value == 0x64) {
			// fs segment override
			result.has_segment_override = true;
		} else if (value == 0x65) {
			// gs segment override
			result.has_segment_override = true;
		} else if (value == 0x2e) {
			// not taken hint
			// result.has_not_taken_hint = true;
		} else if (value == 0x3e) {
			// taken hint
			// result.has_taken_hint = true;
		} else if (value == 0xc4) {
			// three byte vex
			result.has_vex = true;
			// skip two data bytes
			++(*ins);
			++(*ins);
		} else if (value == 0xc5) {
			// two byte vex
			result.has_vex = true;
			// skip one data bytes
			++(*ins);
		} else if (value == 0x8f) {
			// three-byte xop
			// result.has_xop = true;
			// skip two data bytes
			++(*ins);
			++(*ins);
		} else {
			break;
		}
		++(*ins);
	}
	return result;
}

struct x86_instruction
{
	const uint8_t *unprefixed;
	int length;
	struct x86_ins_prefixes prefixes;
};

__attribute__((always_inline)) static inline bool x86_decode_instruction(const uint8_t *addr, struct x86_instruction *out_ins)
{
	int length = InstructionSize_x86_64(addr, 0xf);
	out_ins->length = length;
	out_ins->unprefixed = addr;
	if (length == INSTRUCTION_INVALID) {
		out_ins->prefixes = (struct x86_ins_prefixes){0};
		return false;
	}
	out_ins->prefixes = x86_decode_ins_prefixes(&out_ins->unprefixed);
	return true;
}

static inline bool x86_is_endbr64_instruction(const struct x86_instruction *ins)
{
	return ins->prefixes.has_rep && ins->unprefixed[0] == 0x0f && ins->unprefixed[1] == 0x1e && ins->unprefixed[2] == 0xfa;
}

static inline const uint8_t *x86_next_instruction(const uint8_t *addr, const struct x86_instruction *ins)
{
	return addr + ins->length;
}

// x86_is_return_instruction checks if the instruction is a return
static inline bool x86_is_return_instruction(const struct x86_instruction *ins)
{
	switch (*ins->unprefixed) {
		case 0xc3: // ret
		case 0xc2: // ret imm16
		case 0xcb: // far ret
		case 0xca: // far ret imm16
			return true;
		default:
			return false;
	}
}

// x86_decode_jump_instruction determines if an instruction jumps, and
// fills the jump target
__attribute__((warn_unused_result)) __attribute__((nonnull(1, 2))) enum ins_jump_behavior x86_decode_jump_instruction(const struct x86_instruction *ins, const uint8_t **out_jump);

enum x86_conditional_type
{
	X86_CONDITIONAL_TYPE_OVERFLOW = 0x0,
	X86_CONDITIONAL_TYPE_NOT_OVERFLOW = 0x1,
	X86_CONDITIONAL_TYPE_BELOW = 0x2,
	X86_CONDITIONAL_TYPE_ABOVE_OR_EQUAL = 0x3,
	X86_CONDITIONAL_TYPE_EQUAL = 0x4,
	X86_CONDITIONAL_TYPE_NOT_EQUAL = 0x5,
	X86_CONDITIONAL_TYPE_BELOW_OR_EQUAL = 0x6,
	X86_CONDITIONAL_TYPE_ABOVE = 0x7,
	X86_CONDITIONAL_TYPE_SIGN = 0x8,
	X86_CONDITIONAL_TYPE_NOT_SIGN = 0x9,
	X86_CONDITIONAL_TYPE_PARITY = 0xa,
	X86_CONDITIONAL_TYPE_PARITY_ODD = 0xb,
	X86_CONDITIONAL_TYPE_LOWER = 0xc,
	X86_CONDITIONAL_TYPE_GREATER_OR_EQUAL = 0xd,
	X86_CONDITIONAL_TYPE_NOT_GREATER = 0xe,
	X86_CONDITIONAL_TYPE_GREATER = 0xf,
};

static inline int x86_get_conditional_type(const uint8_t *ins)
{
	return ins[*ins == 0x0f] & 0xf;
}

typedef struct
{
	uint8_t rm : 3;
	uint8_t reg : 3;
	uint8_t mod : 2;
} x86_mod_rm_t;

static inline x86_mod_rm_t x86_read_modrm(const uint8_t *byte)
{
	union {
		uint8_t byte;
		x86_mod_rm_t modrm;
	} pun;
	pun.byte = *byte;
	return pun.modrm;
}

enum
{
	SYSCALL_INSTRUCTION_SIZE = 2,
};

static inline int x86_read_reg(x86_mod_rm_t modrm, struct x86_ins_prefixes rex)
{
	return modrm.reg + (rex.has_r << 3);
}

static inline int x86_read_rm(x86_mod_rm_t modrm, struct x86_ins_prefixes rex)
{
	return modrm.rm + (rex.has_b << 3);
}

__attribute__((always_inline)) static inline bool x86_modrm_is_direct(x86_mod_rm_t modrm)
{
	return modrm.mod == 3;
}

typedef struct
{
	uint8_t base : 3;
	uint8_t index : 3;
	uint8_t scale : 2;
} x86_sib_t;

static inline x86_sib_t x86_read_sib(const uint8_t *byte)
{
	union {
		uint8_t byte;
		x86_sib_t sib;
	} pun;
	pun.byte = *byte;
	return pun.sib;
}

static inline int x86_read_base(x86_sib_t sib, struct x86_ins_prefixes rex)
{
	return sib.base + (rex.has_b << 3);
}

static inline int x86_read_index(x86_sib_t sib, struct x86_ins_prefixes rex)
{
	return sib.index + (rex.has_x << 3);
}

static inline int x86_read_opcode_register_index(uint8_t opcode_value, uint8_t opcode_start, struct x86_ins_prefixes rex)
{
	return opcode_value - opcode_start + ((int)rex.has_b << 3);
}

#endif
