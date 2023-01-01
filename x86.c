#include "x86.h"

#include "patch.h"

#define INS_SYSCALL_0 0x0f
#define INS_SYSCALL_1 0x05

#define INS_NOP 0x90

#define INS_OPERAND_SIZE_PREFIX 0x66

#define INS_REPNE 0xf2
#define INS_REPZ 0xf3

#define INS_RET 0xc3
#define INS_RET_IMM 0xc2
#define INS_RET_FAR 0xcb
#define INS_RET_FAR_IMM 0xca

#define INS_JMP_8_IMM 0xeb
#define INS_JMP_32_IMM 0xe9

#define INS_CONDITIONAL_JMP_8_IMM_START 0x70
#define INS_CONDITIONAL_JMP_8_IMM_END 0x7f
#define INS_CONDITIONAL_JMP_32_IMM_0 0x0f
#define INS_CONDITIONAL_JMP_32_IMM_1_START 0x80
#define INS_CONDITIONAL_JMP_32_IMM_1_END 0x8f

#define INS_JRCXZ 0xe3

__attribute__((used))
bool x86_is_syscall_instruction(const uint8_t *addr)
{
	return addr[0] == INS_SYSCALL_0 && addr[1] == INS_SYSCALL_1;
}

__attribute__((used))
bool x86_is_nop_instruction(const uint8_t *addr)
{
	if (addr[0] == INS_NOP) {
		// 1-byte nop
		return true;
	}
	if (addr[0] == INS_OPERAND_SIZE_PREFIX && addr[1] == INS_NOP) {
		// 2-byte nop
		return true;
	}
	if (addr[0] == 0x0f && addr[1] == 0x1f && addr[2] == 0) {
		// 3-byte nop
		return true;
	}
	if (addr[0] == 0x0f && addr[1] == 0x1f && addr[2] == 0x40 && addr[3] == 0) {
		// 4-byte nop
		return true;
	}
	if (addr[0] == 0x0f && addr[1] == 0x1f && addr[2] == 0x44 && addr[3] == 0 && addr[4] == 0) {
		// 5-byte nop
		return true;
	}
	if (addr[0] == INS_OPERAND_SIZE_PREFIX && addr[1] == 0x0f && addr[2] == 0x1f && addr[3] == 0x44 && addr[4] == 0 && addr[5] == 0) {
		// 6-byte nop
		return true;
	}
	if (addr[0] == 0x0f && addr[1] == 0x1f && addr[2] == 0x80 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0 && addr[6] == 0) {
		// 7-byte nop
		return true;
	}
	if (addr[0] == 0x0f && addr[1] == 0x1f && addr[2] == 0x84 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0) {
		// 8-byte nop
		return true;
	}
	if (addr[0] == INS_OPERAND_SIZE_PREFIX && addr[1] == 0x0f && addr[2] == 0x1f && addr[3] == 0x84 && addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 && addr[8] == 0) {
		// 9-byte nop
		return true;
	}
	if (addr[0] == INS_OPERAND_SIZE_PREFIX && addr[1] == 0x2e && addr[2] == 0x0f && addr[3] == 0x1f && addr[4] == 0x84 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 && addr[8] == 0 && addr[9] == 0) {
		// 10-byte nop
		return true;
	}
	if (addr[0] == INS_OPERAND_SIZE_PREFIX && addr[1] == INS_OPERAND_SIZE_PREFIX && addr[2] == 0x2e && addr[3] == 0x0f && addr[4] == 0x1f && addr[5] == 0x84 && addr[6] == 0 && addr[7] == 0 && addr[8] == 0 && addr[9] == 0 && addr[10] == 0) {
		// 11-byte nop
		return true;
	}
	return false;
}

__attribute__((used))
bool x86_is_return_instruction(const uint8_t *addr)
{
	if (*addr == INS_REPZ) {
		addr++;
	}
	switch (*addr) {
		case INS_RET:
		case INS_RET_IMM:
		case INS_RET_FAR:
		case INS_RET_FAR_IMM:
			return true;
		default:
			return false;
	}
}

__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
__attribute__((used))
enum x86_jumps x86_jump_addresses_at_instruction(const uint8_t *ins, const uint8_t **out_jump)
{
	while (*ins == INS_REPNE) {
		ins++;
	}
	if (ins[0] == INS_JMP_8_IMM) {
		PATCH_LOG("jmp", (uintptr_t)ins);
		*out_jump = ins + 2 + *(const int8_t *)&ins[1];
		return X86_JUMPS_ALWAYS;
	}
	if (ins[0] == INS_JMP_32_IMM) {
		PATCH_LOG("jmpq", (uintptr_t)ins);
		*out_jump = ins + 5 + *(const x86_int32 *)&ins[1];
		return X86_JUMPS_ALWAYS;
	}
	if (ins[0] == 0xff && ins[1] == 0x25) {
		PATCH_LOG("jmpq *", (uintptr_t)ins);
		const uint8_t **address = (const uint8_t **)(ins + 6 + *(const x86_int32 *)&ins[2]);
		*out_jump = *address;
		return X86_JUMPS_ALWAYS;
	}
	switch (ins[0]) {
		case 0xe0: // loopne
		case 0xe1: // loope
		case 0xe2: // loop
		case 0xe3: // jcxz
			*out_jump = ins + 1 + *(const int8_t*)&ins[1];
			return X86_JUMPS_OR_CONTINUES;
	}
	if ((ins[0] >= INS_CONDITIONAL_JMP_8_IMM_START && ins[0] <= INS_CONDITIONAL_JMP_8_IMM_END) || ins[0] == INS_JRCXZ) {
		PATCH_LOG("conditional jmp", (uintptr_t)ins);
		*out_jump = ins + 2 + *(const int8_t *)&ins[1];
		return X86_JUMPS_OR_CONTINUES;
	}
	if (ins[0] == INS_CONDITIONAL_JMP_32_IMM_0 && ins[1] >= INS_CONDITIONAL_JMP_32_IMM_1_START && ins[1] <= INS_CONDITIONAL_JMP_32_IMM_1_END) {
		PATCH_LOG("conditional jmpq", (uintptr_t)ins);
		*out_jump = ins + 6 + *(const x86_int32 *)&ins[2];
		return X86_JUMPS_OR_CONTINUES;
	}
	return X86_JUMPS_NEVER;
}

