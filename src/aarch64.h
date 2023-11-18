#ifndef AARCH64_H
#define AARCH64_H

#include <stdbool.h>
#include <stdint.h>

#define context context_
#include "arch-arm64/disassembler/decode.h"
#undef context

enum aarch64_register_index {
	AARCH64_REGISTER_X0,
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
};

static inline bool aarch64_decode_instruction(const uint32_t *ins, struct aarch64_instruction *out_decoded)
{
	(void)ins;
	*out_decoded = (struct aarch64_instruction){};
	return false;
}

static inline bool aarch64_is_conditional_branch(uint32_t ins)
{
	return (ins & 0xFF000010) == 0x54000000;
}

static inline uint32_t aarch64_read_cond(uint32_t ins)
{
	return ins & 0xf;
}

static inline bool aarch64_is_jbe_instruction(const uint32_t *ins)
{
	return aarch64_is_conditional_branch(*ins) && aarch64_read_cond(*ins) == 1;
}

__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
enum ins_jump_behavior aarch64_decode_jump_instruction(const struct aarch64_instruction *ins, const uint32_t **out_jump);

#endif
