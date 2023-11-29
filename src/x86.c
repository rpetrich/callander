#include "ins.h"
#include "x86.h"

#include "patch.h"

#define INS_SYSCALL_0 0x0f
#define INS_SYSCALL_1 0x05

#define INS_NOP 0x90

#define INS_OPERAND_SIZE_PREFIX 0x66

#define INS_REPNE 0xf2
#define INS_REPZ 0xf3

#define INS_JMP_8_IMM 0xeb
#define INS_JMP_32_IMM 0xe9

#define INS_CONDITIONAL_JMP_8_IMM_START 0x70
#define INS_CONDITIONAL_JMP_8_IMM_END 0x7f
#define INS_CONDITIONAL_JMP_32_IMM_0 0x0f
#define INS_CONDITIONAL_JMP_32_IMM_1_START 0x80
#define INS_CONDITIONAL_JMP_32_IMM_1_END 0x8f

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

__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
__attribute__((used))
enum ins_jump_behavior x86_decode_jump_instruction(const struct x86_instruction *ins, const uint8_t **out_jump)
{
	if (UNLIKELY(ins->prefixes.has_vex)) {
		return INS_JUMPS_NEVER;
	}
	const uint8_t *unprefixed = ins->unprefixed;
	switch (*unprefixed) {
		case INS_JMP_8_IMM:
			PATCH_LOG("jmp", (uintptr_t)unprefixed);
			*out_jump = unprefixed + 2 + *(const int8_t *)&unprefixed[1];
			return INS_JUMPS_ALWAYS;
		case INS_JMP_32_IMM:
			PATCH_LOG("jmpq", (uintptr_t)unprefixed);
			*out_jump = unprefixed + 5 + *(const ins_int32 *)&unprefixed[1];
			return INS_JUMPS_ALWAYS;
		case 0xff:
			if (unprefixed[1] == 0x25) {
				PATCH_LOG("jmpq *", (uintptr_t)unprefixed);
				const uint8_t **address = (const uint8_t **)(unprefixed + 6 + *(const ins_int32 *)&unprefixed[2]);
				*out_jump = *address;
				return INS_JUMPS_ALWAYS_INDIRECT;
			}
			break;
		case 0xe0: // loopne
		case 0xe1: // loope
		case 0xe2: // loop
		case 0xe3: // jcxz
			*out_jump = unprefixed + 2 + *(const int8_t*)&unprefixed[1];
			return INS_JUMPS_OR_CONTINUES;
		case INS_CONDITIONAL_JMP_8_IMM_START ... INS_CONDITIONAL_JMP_8_IMM_END:
			PATCH_LOG("conditional jmp", (uintptr_t)unprefixed);
			*out_jump = unprefixed + 2 + *(const int8_t *)&unprefixed[1];
			return INS_JUMPS_OR_CONTINUES;
		case INS_CONDITIONAL_JMP_32_IMM_0:
			switch (unprefixed[1]) {
				case INS_CONDITIONAL_JMP_32_IMM_1_START ... INS_CONDITIONAL_JMP_32_IMM_1_END:
					PATCH_LOG("conditional jmpq", (uintptr_t)unprefixed);
					*out_jump = unprefixed + 6 + *(const ins_int32 *)&unprefixed[2];
					return INS_JUMPS_OR_CONTINUES;
			}
			break;
	}
	return INS_JUMPS_NEVER;
}

