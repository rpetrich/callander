#ifndef AARCH64_H
#define AARCH64_H

#include <stdbool.h>
#include <stdint.h>

#include "callander.h"

#define context context_
#include "arch-arm64/disassembler/decode.h"
#include "arch-arm64/disassembler/format.h"
#include "arch-arm64/disassembler/regs.h"
#undef context

enum aarch64_register_index {
	AARCH64_REGISTER_INVALID = -10000000,
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
	AARCH64_REGISTER_X29,
	AARCH64_REGISTER_X30,
	AARCH64_REGISTER_SP,
};

struct aarch64_instruction {
	Instruction decomposed;
};

static inline enum aarch64_register_index register_index_from_register(enum Register reg)
{
	switch (reg) {
		case REG_W0...REG_W30:
			return (enum aarch64_register_index)(reg - REG_W0);
		case REG_X0...REG_X30:
			return (enum aarch64_register_index)(reg - REG_X0);
		case REG_B0...REG_B30:
			return (enum aarch64_register_index)(reg - REG_B0);
		case REG_H0...REG_H30:
			return (enum aarch64_register_index)(reg - REG_H0);
		case REG_WSP:
		case REG_SP:
			return AARCH64_REGISTER_SP;
		default:
			return AARCH64_REGISTER_INVALID;
	}
}

static inline enum aarch64_register_index register_index_from_operand(const struct InstructionOperand *operand)
{
	switch (operand->operandClass) {
		case REG:
			return register_index_from_register(operand->reg[0]);
		default:
			return AARCH64_REGISTER_INVALID;
	}
}

static inline uintptr_t mask_for_operand_size(size_t operand_size)
{
	switch (operand_size) {
		case 1:
			return 0xff;
		case 2:
			return 0xffff;
		case 4:
			return 0xffffffff;
		default:
			return ~(uintptr_t)0;
	}
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline void truncate_to_mask(struct register_state *reg, uintptr_t mask) {
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

static inline bool apply_shift(const struct InstructionOperand *operand, struct register_state *reg)
{
	switch (operand->shiftType) {
		case ShiftType_NONE:
			return false;
		case ShiftType_LSL:
			if (reg->value == reg->max) {
				set_register(reg, reg->value << operand->shiftValueUsed);
			} else {
				clear_register(reg);
			}
			return true;
		case ShiftType_LSR:
			if (reg->value == reg->max) {
				set_register(reg, reg->value >> operand->shiftValueUsed);
			} else {
				clear_register(reg);
			}
			return true;
		case ShiftType_ASR:
			if (reg->value == reg->max) {
				set_register(reg, (uintptr_t)(((intptr_t)reg->value) >> operand->shiftValueUsed));
			} else {
				clear_register(reg);
			}
			return true;
		default:
			clear_register(reg);
			return true;
	}
}

static inline int read_operand(const struct InstructionOperand *operand, const struct register_state *regs, const uint32_t *ins, struct register_state *out_state, uintptr_t *out_mask)
{
	switch (operand->operandClass) {
		case REG: {
			int reg = register_index_from_register(operand->reg[0]);
			if (reg != AARCH64_REGISTER_INVALID) {
				*out_state = regs[reg];
			} else if (operand->reg[0] == REG_WZR || operand->reg[0] == REG_XZR) {
				clear_register(out_state);
			} else {
				break;
			}
			uintptr_t mask = mask_for_operand_size(get_register_size(operand->reg[0]));
			truncate_to_mask(out_state, mask);
			if (out_mask != NULL) {
				*out_mask = mask;
			}
			return reg;
		}
		case IMM32: {
			set_register(out_state, operand->immediate);
			truncate_to_mask(out_state, 0xffffffff);
			if (out_mask != NULL) {
				*out_mask = 0xffffffff;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case IMM64: {
			set_register(out_state, operand->immediate);
			if (out_mask != NULL) {
				*out_mask = ~(uintptr_t)0;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case LABEL: {
			set_register(out_state, (uintptr_t)ins + operand->immediate);
			if (out_mask != NULL) {
				*out_mask = ~(uintptr_t)0;
			}
			return AARCH64_REGISTER_INVALID;
		}
		default:
			break;
	}
	if (out_mask != NULL) {
		*out_mask = ~(uintptr_t)0;
	}
	clear_register(out_state);
	return AARCH64_REGISTER_INVALID;
}

__attribute__((always_inline))
static inline bool aarch64_decode_instruction(const uint32_t *ins, struct aarch64_instruction *out_decoded)
{
	return aarch64_decompose(*ins, &out_decoded->decomposed, (uintptr_t)ins) == 0;
}

__attribute__((always_inline))
static inline bool aarch64_is_conditional_branch(const struct aarch64_instruction *decoded)
{
	switch (decoded->decomposed.operation) {
		case ARM64_B_EQ:
		case ARM64_B_NE:
		case ARM64_B_CS:
		case ARM64_B_CC:
		case ARM64_B_MI:
		case ARM64_B_PL:
		case ARM64_B_VS:
		case ARM64_B_VC:
		case ARM64_B_HI:
		case ARM64_B_LS:
		case ARM64_B_GE:
		case ARM64_B_LT:
		case ARM64_B_GT:
		case ARM64_B_LE:
		case ARM64_TBZ:
		case ARM64_TBNZ:
		case ARM64_CBZ:
		case ARM64_CBNZ:
			return true;
		default:
			return false;
	}
}

__attribute__((always_inline))
static inline bool aarch64_is_return_instruction(const struct aarch64_instruction *decoded)
{
	switch (decoded->decomposed.operation) {
		case ARM64_ERET:
		case ARM64_ERETAA:
		case ARM64_ERETAB:
		case ARM64_RET:
		case ARM64_RETAA:
		case ARM64_RETAB:
			return true;
		default:
			return false;
	}
}

__attribute__((always_inline))
static inline bool aarch64_is_bti_instruction(const struct aarch64_instruction *decoded)
{
	switch (decoded->decomposed.operation) {
		case ARM64_BTI:
			return true;
		default:
			return false;
	}
}

__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
static inline enum ins_jump_behavior aarch64_decode_jump_instruction(const struct aarch64_instruction *ins, const uint32_t **out_jump)
{
	switch (ins->decomposed.operation) {
		case ARM64_B_EQ:
		case ARM64_B_NE:
		case ARM64_B_CS:
		case ARM64_B_CC:
		case ARM64_B_MI:
		case ARM64_B_PL:
		case ARM64_B_VS:
		case ARM64_B_VC:
		case ARM64_B_HI:
		case ARM64_B_LS:
		case ARM64_B_GE:
		case ARM64_B_LT:
		case ARM64_B_GT:
		case ARM64_B_LE:
		case ARM64_CBNZ:
		case ARM64_CBZ:
		case ARM64_TBNZ:
		case ARM64_TBZ:
			*out_jump = (const uint32_t *)ins->decomposed.operands[0].immediate;
			return INS_JUMPS_OR_CONTINUES;
		case ARM64_B_AL:
		case ARM64_B_NV:
		case ARM64_B:
			*out_jump = (const uint32_t *)ins->decomposed.operands[0].immediate;
			return INS_JUMPS_ALWAYS;
		default:
			return INS_JUMPS_NEVER;
	}
}

#define UNSUPPORTED_INSTRUCTION() do { \
	self.description = operation_to_str(decoded.decomposed.operation); \
	DIE("unsupported instruction", temp_str(copy_call_trace_description(&analysis->loader, &self))); \
} while(0)

#endif
