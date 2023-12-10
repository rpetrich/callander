#ifndef AARCH64_H
#define AARCH64_H

#include <stdbool.h>
#include <stdint.h>

#include "ins.h"
#include "axon.h"

#define context context_
#include "arch-arm64/disassembler/decode.h"
#include "arch-arm64/disassembler/format.h"
#include "arch-arm64/disassembler/regs.h"
#undef context

#include "callander.h"

enum aarch64_register_index {
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
	AARCH64_REGISTER_X29,
	// AARCH64_REGISTER_X30,
	AARCH64_REGISTER_SP,
};

enum {
	SYSCALL_INSTRUCTION_SIZE = 4,
};

struct aarch64_instruction {
	Instruction decomposed;
};

static inline enum aarch64_register_index register_index_from_register(enum Register reg)
{
	switch (reg) {
		case REG_W0...REG_W29:
			return (enum aarch64_register_index)(reg - REG_W0);
		case REG_X0...REG_X29:
			return (enum aarch64_register_index)(reg - REG_X0);
		case REG_B0...REG_B29:
			return (enum aarch64_register_index)(reg - REG_B0);
		case REG_H0...REG_H29:
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

static bool apply_operand_shift(struct register_state *reg, const struct InstructionOperand *operand)
{
	if (operand->shiftValue == 0) {
		return false;
	}
	switch (operand->shiftType) {
		case ShiftType_NONE:
			return false;
		case ShiftType_UXTX:
		case ShiftType_UXTW:
		case ShiftType_UXTB:
		case ShiftType_UXTH:
		case ShiftType_LSL: {
			if (register_is_exactly_known(reg)) {
				set_register(reg, reg->value << operand->shiftValue);
			} else if (__builtin_ffs(reg->max) + operand->shiftValue >= 64) {
				clear_register(reg);
			} else {
				reg->max <<= operand->shiftValue;
				reg->value <<= operand->shiftValue;
			}
			return true;
		}
		case ShiftType_LSR: {
			if (reg->value == reg->max) {
				set_register(reg, reg->value >> operand->shiftValueUsed);
			} else {
				clear_register(reg);
			}
			return true;
		}
		case ShiftType_ASR: {
			if (reg->value == reg->max) {
				set_register(reg, (uintptr_t)(((intptr_t)reg->value) >> operand->shiftValueUsed));
			} else {
				clear_register(reg);
			}
			return true;
		}
		case ShiftType_ROR: {
			if (register_is_exactly_known(reg)) {
				set_register(reg, (reg->value >> operand->shiftValue) | (reg->value << (64 - operand->shiftValue)));
			} else {
				clear_register(reg);
			}
			return true;
		}
		case ShiftType_SXTW: {
			if (register_is_exactly_known(reg) || operand->shiftValue <= 32) {
				set_register(reg, (uintptr_t)(intptr_t)(int32_t)reg->value << operand->shiftValue);
			} else {
				clear_register(reg);
			}
			return true;
		}
		case ShiftType_SXTH: {
			if (register_is_exactly_known(reg) || operand->shiftValue <= 48) {
				set_register(reg, (uintptr_t)(intptr_t)(int16_t)reg->value << operand->shiftValue);
			} else {
				clear_register(reg);
			}
			return true;
		}
		case ShiftType_SXTB: {
			if (register_is_exactly_known(reg) || operand->shiftValue <= 56) {
				set_register(reg, (uintptr_t)(intptr_t)(int8_t)reg->value << operand->shiftValue);
			} else {
				clear_register(reg);
			}
			return true;
		}
		default:
			clear_register(reg);
			return true;
	}
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
			*out_jump = (const uint32_t *)ins->decomposed.operands[0].immediate;
			return INS_JUMPS_OR_CONTINUES;
		case ARM64_CBNZ:
		case ARM64_CBZ:
		case ARM64_TBNZ:
		case ARM64_TBZ:
			*out_jump = (const uint32_t *)ins->decomposed.operands[1].immediate;
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

static inline enum Condition aarch64_get_conditional_type(const struct aarch64_instruction *ins)
{
	switch (ins->decomposed.operation) {
		case ARM64_B_EQ:
			return COND_EQ;
		case ARM64_B_NE:
			return COND_NE;
		case ARM64_B_CS:
			return COND_CS;
		case ARM64_B_CC:
			return COND_CC;
		case ARM64_B_MI:
			return COND_MI;
		case ARM64_B_PL:
			return COND_PL;
		case ARM64_B_VS:
			return COND_VS;
		case ARM64_B_VC:
			return COND_VC;
		case ARM64_B_HI:
			return COND_HI;
		case ARM64_B_LS:
			return COND_LS;
		case ARM64_B_GE:
			return COND_GE;
		case ARM64_B_LT:
			return COND_LT;
		case ARM64_B_GT:
			return COND_GT;
		case ARM64_B_LE:
			return COND_LE;
		default:
			return COND_AL;
	}
}

#define UNSUPPORTED_INSTRUCTION() do { \
	char *buf = malloc(4096); \
	if (aarch64_disassemble(&decoded.decomposed, buf, 4096) != DISASM_SUCCESS) { \
		self.description = operation_to_str(decoded.decomposed.operation); \
	} else { \
		self.description = buf; \
	} \
	DIE("unsupported instruction", temp_str(copy_call_trace_description(&analysis->loader, &self))); \
} while(0)

#endif
