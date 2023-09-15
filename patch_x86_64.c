#if defined(__x86_64__)

#define PATCH_EXPOSE_INTERNALS
#include "patch_x86_64.h"

#include "attempt.h"
#include "debugger.h"
#include "freestanding.h"
#include "axon.h"
#include "handler.h"
#include "mapped.h"
#include "stack.h"
#include "ins.h"
#include "x86.h"
#include "x86_64_length_disassembler.h"

#include <stdatomic.h>
#include <string.h>
#include <errno.h>


__asm__(
".text\n"
".global trampoline_call_handler_start\n"
".hidden trampoline_call_handler_start\n"
".type trampoline_call_handler_start,@function\n" \
"trampoline_call_handler_start:\n"
"	mov %rax, %r11\n"
"	lahf\n"
"   seto %al\n"
"   sub $128, %rsp\n"
"	push %rax\n"
"	push %r9\n"
"	push %r8\n"
"	push %r10\n"
"	push %rdx\n"
"	push %rsi\n"
"	push %rdi\n"
"	push %r11\n"
"	mov %rsp, %rdi\n"
".global trampoline_call_handler_call\n"
".hidden trampoline_call_handler_call\n"
".type trampoline_call_handler_call,@function\n" \
"trampoline_call_handler_call:"
"	call *%rcx\n"
"	pop %rcx\n"
"	pop %rdi\n"
"	pop %rsi\n"
"	pop %rdx\n"
"	pop %r10\n"
"	pop %r8\n"
"	pop %r9\n"
"	pop %rax\n"
"	add $128, %rsp\n"
"	add $0xff, %al\n"
"	sahf\n"
"	mov %rcx, %rax\n"
".global trampoline_call_handler_end\n"
".hidden trampoline_call_handler_end\n"
".type trampoline_call_handler_end,@function\n" \
"trampoline_call_handler_end:"
);

void trampoline_call_handler_start();
void trampoline_call_handler_call();
void trampoline_call_handler_end();

__asm__(
".text\n"
".global breakpoint_call_handler_start\n"
".hidden breakpoint_call_handler_start\n"
".type breakpoint_call_handler_start,@function\n" \
"breakpoint_call_handler_start:\n"
"	lea -0x80(%rsp), %rsp\n"
"	push %rax\n"
"	lahf\n"
"   seto %al\n"
"	push %rax\n"
"	push %r11\n"
"	push %r10\n"
"	push %r9\n"
"	push %r8\n"
"	push %rcx\n"
"	push %rdx\n"
"	push %rsi\n"
"	push %rdi\n"
"	mov %rsp, %rdi\n"
".global breakpoint_call_handler_call\n"
".hidden breakpoint_call_handler_call\n"
".type breakpoint_call_handler_call,@function\n" \
"breakpoint_call_handler_call:"
"	call *%rcx\n"
"	pop %rdi\n"
"	pop %rsi\n"
"	pop %rdx\n"
"	pop %rcx\n"
"	pop %r8\n"
"	pop %r9\n"
"	pop %r10\n"
"	pop %r11\n"
"	pop %rax\n"
"	add $0xff, %al\n"
"	sahf\n"
"	pop %rax\n"
"	lea 0x80(%rsp), %rsp\n"
".global breakpoint_call_handler_end\n"
".hidden breakpoint_call_handler_end\n"
".type breakpoint_call_handler_end,@function\n" \
"breakpoint_call_handler_end:"
);

void breakpoint_call_handler_start();
void breakpoint_call_handler_call();
void breakpoint_call_handler_end();

__asm__(
".text\n"
".global function_call_handler_start\n"
".hidden function_call_handler_start\n"
".type function_call_handler_start,@function\n" \
"function_call_handler_start:\n"
"	push %r9\n"
"	push %r8\n"
"	push %rcx\n"
"	push %rdx\n"
"	push %rsi\n"
"	push %rdi\n"
"	mov %rsp, %rdi\n"
"	push %rax\n"
".global function_call_handler_call\n"
".hidden function_call_handler_call\n"
".type function_call_handler_call,@function\n" \
"function_call_handler_call:"
"	lea function_call_handler_end(%rip), %rsi\n"
"	call *%rcx\n"
"	lea 0x38(%rsp), %rsp\n"
"	ret\n"
".global function_call_handler_end\n"
".hidden function_call_handler_end\n"
".type function_call_handler_end,@function\n" \
"function_call_handler_end:"
);

void function_call_handler_start();
void function_call_handler_call();
void function_call_handler_end();

#define INS_OPERAND_SIZE_PREFIX 0x66
#define INS_REX_W_PREFIX 0x48
#define INS_CMP_32_IMM 0x3d
#define INS_CALL_32_IMM 0xe8
#define INS_JMP_8_IMM 0xeb
#define INS_CONDITIONAL_JMP_8_IMM_START 0x70
#define INS_CONDITIONAL_JMP_8_IMM_END 0x7f
#define INS_CONDITIONAL_JMP_32_IMM_0 0x0f
#define INS_CONDITIONAL_JMP_32_IMM_1_START 0x80
#define INS_CONDITIONAL_JMP_32_IMM_1_END 0x8f
#define INS_JRCXZ 0xe3
#define INS_MOV_REG 0x89
#define INS_NOP 0x90
#define INS_JMP_RCX_0 0xff
#define INS_JMP_RCX_1 0xe1
#define INS_REPZ 0xf3
#define INS_RET 0xc3
#define INS_RET_IMM 0xc2
#define INS_RET_FAR 0xcb
#define INS_RET_FAR_IMM 0xca
#define INS_ADD_SUB_RSP_8_IMM_0 0x48
#define INS_ADD_SUB_RSP_8_IMM_1 0x83
#define INS_ADD_SUB_RSP_32_IMM_1 0x81
#define INS_ADD_RSP_IMM_2 0xc4
#define INS_SUB_RSP_IMM_2 0xec
#define INS_PUSHQ_START 0x50
#define INS_PUSHQ_END 0x57
#define INS_POPQ_START 0x58
#define INS_POPQ_END 0x5f
#define INS_MOVL_START 0xb8
#define INS_MOVL_END 0xbf
#define INS_REXB_PREFIX 0x41
#define INS_ONE_BYTE_ILL 0x17
#define INS_LEA 0x8d

struct applied_patch {
	struct instruction_range range;
	uintptr_t target;
	struct applied_patch *next;
	bool is_ill_patch;
};

static struct fs_mutex patches_lock;
static struct applied_patch *patches;

static void trampoline_body(struct thread_storage *thread, intptr_t data[7])
{
	intptr_t syscall = data[0];
	data[0] = -EFAULT;
	data[0] = handle_syscall(thread, syscall, data[1], data[2], data[3], data[4], data[5], data[6], NULL);
}

// receive_trampoline is called by trampolines to handle the intercepted syscall
static void receive_trampoline(intptr_t data[7]) {
	intptr_t syscall = data[0];
	struct thread_storage *thread = get_thread_storage();
	attempt_with_sufficient_stack(thread, (attempt_body)&trampoline_body, data);
	if (data[0] == -ENOSYS) {
		data[0] = FS_SYSCALL(syscall, data[1], data[2], data[3], data[4], data[5], data[6]);
	}
}

// is_valid_pc_relative_offset verifies that an offset will fit in a 32-bit offset
static bool is_valid_pc_relative_offset(intptr_t offset)
{
	return (intptr_t)(int32_t)offset == offset;
}

// destination_of_pc_relative_addr returns the destination address of a pc-relative offset
__attribute__((unused))
static inline intptr_t destination_of_pc_relative_addr(const uint8_t *addr)
{
	int32_t relative = *(const int32_t *)addr;
	return (intptr_t)addr + 4 + relative;
}

// is_patchable_instruction returns true if the instruction can safely be relocated into a detour
static bool is_patchable_instruction(const struct x86_instruction *addr, patch_address_formatter formatter, void *formatter_data)
{
	(void)formatter;
	(void)formatter_data;
	const uint8_t *ins = addr->unprefixed;
	if (ins[0] >= INS_MOVL_START && ins[0] <= INS_MOVL_END) {
		PATCH_LOG("Patching address with movl $..., %...prefix", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] == 0xe9) {
		PATCH_LOG("Patching address with jump", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] == INS_MOV_REG) {
		PATCH_LOG("Patching address with mov prefix", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] == INS_CMP_32_IMM) {
		PATCH_LOG("Patching address with cmp prefix", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] == 0x85 || ins[1] == 0x86) {
		PATCH_LOG("Patching address with test", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] == 0x8b || ins[0] == 0x89) {
		if (ins[1] == 0x0d) {
			PATCH_LOG("Patching address with pc-relative mov prefix", temp_str(formatter(ins, formatter_data)));
			return true;
		}
		if (ins[1] == 0x44 || ins[1] == 0x54 || ins[1] == 0x74 || ins[1] == 0x7c) {
			PATCH_LOG("Patching address with sp-relative mov prefix", temp_str(formatter(ins, formatter_data)));
			return true;
		}
		PATCH_LOG("Patching address with mov", temp_str(formatter(ins, formatter_data)));
		return true;
	} else if (ins[0] == 0xc7) {
		PATCH_LOG("Patching address with mov $..., %...", temp_str(formatter(ins, formatter_data)));
		return true;
	} else if (ins[0] == 0x83) {
		PATCH_LOG("Patching address with sub $..., %...", temp_str(formatter(ins, formatter_data)));
		return true;
	} else if (ins[0] == INS_LEA) {
		if ((ins[1] & 0xc7) != 0x5) {
			PATCH_LOG("Patching address with lea", temp_str(formatter(ins, formatter_data)));
			return true;
		}
		x86_mod_rm_t modrm = x86_read_modrm(&ins[1]);
		if (!x86_modrm_is_direct(modrm)) {
			int rm = x86_read_rm(modrm, (struct x86_ins_prefixes){ 0 });
			switch (rm) {
				case X86_REGISTER_BP:
				case X86_REGISTER_13:
					PATCH_LOG("Patching address with rip-relative lea", temp_str(formatter(ins, formatter_data)));
					return true;
			}
		}
	}
	if (ins[0] == INS_CONDITIONAL_JMP_32_IMM_0 && ins[1] >= INS_CONDITIONAL_JMP_32_IMM_1_START && ins[1] <= INS_CONDITIONAL_JMP_32_IMM_1_END) {
		PATCH_LOG("Patching conditional jump", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] >= INS_MOVL_START && ins[0] <= INS_MOVL_END) {
		PATCH_LOG("Patching address with rex.b movl prefix", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] == 0x31) {
		PATCH_LOG("Patching address with xor reg to reg", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (ins[0] >= INS_PUSHQ_START && ins[0] <= INS_PUSHQ_END) {
		PATCH_LOG("Patching push", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	// WRITE_LITERAL(TELEMETRY_FD, "Failed to patch: not a known suffix instruction\n");
	if (x86_is_return_instruction(addr)) {
		PATCH_LOG("Patching address with ret", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (x86_is_syscall_instruction(ins)) {
		PATCH_LOG("Patching address with syscall", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	if (x86_is_nop_instruction(ins)) {
		PATCH_LOG("Patching address with nop", temp_str(formatter(ins, formatter_data)));
		return true;
	}
	PATCH_LOG("Address not patchable", temp_str(formatter(ins, formatter_data)));
	return false;
}

struct searched_instructions {
	const uint8_t *addresses[127];
	struct searched_instructions *next;
};

struct instruction_search {
	const uint8_t *addr;
	struct searched_instructions *searched;
};

// check_already_searched_instruction checks if an instruction was already searched
// if not, it is added to the search list
static bool check_already_searched_instruction(struct instruction_search search)
{
	struct searched_instructions *current_search = search.searched;
	int i = 0;
	for (;;) {
		for (; i < 127; i++) {
			if (current_search->addresses[i] == search.addr) {
				return true;
			}
			if (current_search->addresses[i] == NULL) {
				goto not_found;
			}
		}
		i = 0;
		struct searched_instructions *next = current_search->next;
		if (next == NULL) {
			next = malloc(sizeof(*current_search));
			next->addresses[0] = NULL;
			next->next = NULL;
			current_search->next = next;
			current_search = next;
			goto not_found;
		}
		current_search = next;
	}
not_found:
	current_search->addresses[i] = search.addr;
	current_search->addresses[i+1] = NULL;
	return false;
}

static void cleanup_searched_instructions(void *data)
{
	struct searched_instructions *searched = data;
	searched = searched->next;
	while (searched) {
		struct searched_instructions *next = searched->next;
		free(searched);
		searched = next;
	}
}

static void init_searched_instructions(struct thread_storage *thread, struct searched_instructions *searched, struct attempt_cleanup_state *cleanup)
{
	searched->addresses[0] = NULL;
	searched->next = NULL;
	cleanup->body = cleanup_searched_instructions;
	cleanup->data = searched;
	attempt_push_cleanup(thread, cleanup);
}

static void free_searched_instructions(struct searched_instructions *searched, struct attempt_cleanup_state *cleanup)
{
	attempt_pop_and_skip_cleanup(cleanup);
	cleanup_searched_instructions(searched);
}

// find_return_address_stack_offset returns the stack offset of the return address by inspecting stack manipulation
// instructions
__attribute__((warn_unused_result))
__attribute__((nonnull(3)))
static bool find_return_address(struct instruction_search search, intptr_t bp, patch_address_formatter formatter, void *formatter_data, intptr_t *out_return_address)
{
	if (check_already_searched_instruction(search)) {
		// avoid infinitely traversing loops
		return false;
	}
	const uint8_t *jump;
	const uint8_t *ins = search.addr;
	bool previous_ins_is_stack_check = false;
	for (;;) {
		struct x86_instruction decoded;
		if (!x86_decode_instruction(ins, &decoded)) {
			return false;
		}
		if (x86_is_return_instruction(&decoded)) {
			break;
		}
		// Examine jumps
		switch (x86_decode_jump_instruction(&decoded, &jump)) {
			case INS_JUMPS_NEVER:
				break;
			case INS_JUMPS_ALWAYS: {
				// jump instruction
				ins = jump;
				if (check_already_searched_instruction((struct instruction_search){
					.addr = ins,
					.searched = search.searched,
				})) {
					// avoid infinitely traversing loops
					return false;
				}
				continue;
			}
			case INS_JUMPS_OR_CONTINUES:
				if (!previous_ins_is_stack_check) {
					// conditional jump instruction
					intptr_t taken_return_address = *out_return_address;
					intptr_t not_return_address = *out_return_address;
					bool taken_result = find_return_address((struct instruction_search){
						.addr = jump,
						.searched = search.searched,
					}, bp, formatter, formatter_data, &taken_return_address);
					bool not_result = find_return_address((struct instruction_search){
						.addr = x86_next_instruction(ins, &decoded),
						.searched = search.searched,
					}, bp, formatter, formatter_data, &not_return_address);
					// succeed if both succeed and match, or if one succeeds
					if (taken_result) {
						*out_return_address = taken_return_address;
						return !not_result || (taken_return_address == not_return_address);
					}
					if (not_result) {
						*out_return_address = not_return_address;
						return true;
					}
					return false;
				}
				break;
		}
		previous_ins_is_stack_check = false;
		switch (decoded.length) {
			case 1:
				if (ins[0] >= INS_PUSHQ_START && ins[0] <= INS_PUSHQ_END) {
					// pushq %r...
					*out_return_address -= 8;
					PATCH_LOG("push", temp_str(formatter(ins, formatter_data)));
				} else if (ins[0] >= INS_POPQ_START && ins[0] <= INS_POPQ_END) {
					// popq %r...
					*out_return_address += 8;
					PATCH_LOG("pop", temp_str(formatter(ins, formatter_data)));
				}
				break;
			case 2:
				if (ins[0] == INS_REXB_PREFIX) {
					if (ins[1] >= INS_PUSHQ_START && ins[1] <= INS_PUSHQ_END) {
						// pushq %r...
						*out_return_address -= 8;
						PATCH_LOG("rexb push", temp_str(formatter(ins, formatter_data)));
					} else if (ins[1] >= INS_POPQ_START && ins[1] <= INS_POPQ_END) {
						// popq %r...
						*out_return_address += 8;
						PATCH_LOG("rexb pop", temp_str(formatter(ins, formatter_data)));
					}
				}
				break;
			case 4:
				if (ins[0] == INS_ADD_SUB_RSP_8_IMM_0 && ins[1] == INS_ADD_SUB_RSP_8_IMM_1) {
					if (ins[2] == INS_ADD_RSP_IMM_2) {
						// addq $..., %rsp (8-bit immediate)
						PATCH_LOG("add %rsp", temp_str(formatter(ins, formatter_data)));
						PATCH_LOG("add %rsp value", (int)ins[3]);
						*out_return_address += ins[3];
					} else if (ins[2] == INS_SUB_RSP_IMM_2) {
						// subq $..., %rsp (8-bit immediate)
						PATCH_LOG("sub %rsp", temp_str(formatter(ins, formatter_data)));
						PATCH_LOG("sub %rsp value", (int)ins[3]);
						*out_return_address -= ins[3];
					}
				}
				if (ins[0] == INS_REX_W_PREFIX && ins[1] == INS_LEA && ins[2] == 0x65) {
					// lea ...(%rbp), %rsp (8-bit immediate)
					PATCH_LOG("lea ...(%rbp), %rsp", temp_str(formatter(ins, formatter_data)));
					PATCH_LOG("lea %rbp value", (int)ins[3]);
					*out_return_address = bp + (int8_t)ins[3];
				}
				break;
			case 5:
				if (ins[0] == INS_REX_W_PREFIX && ins[1] == INS_LEA && ins[2] == 0x64 && ins[3] == 0x24) {
					// lea -...(%rsp), %rsp (8-bit immediate)
					PATCH_LOG("lea -...(%rsp), %rsp", (uintptr_t)ins);
					PATCH_LOG("lea %rsp value", (int)ins[4]);
					*out_return_address -= ins[4];
				}
				break;
			case 7:
				if (ins[0] == INS_REX_W_PREFIX && ins[1] == INS_ADD_SUB_RSP_32_IMM_1) {
					if (ins[2] == INS_ADD_RSP_IMM_2) {
						// addq $..., %rsp (32-bit immediate)
						PATCH_LOG("add %rsp", temp_str(formatter(ins, formatter_data)));
						PATCH_LOG("add %rsp value", (int)*(const uint32_t *)&ins[3]);
						*out_return_address += *(const uint32_t *)&ins[3];
					} else if (ins[2] == INS_SUB_RSP_IMM_2) {
						// subq $..., %rsp (32-bit immediate)
						PATCH_LOG("sub %rsp", temp_str(formatter(ins, formatter_data)));
						PATCH_LOG("sub %rsp value", (int)*(const uint32_t *)&ins[3]);
						*out_return_address -= *(const uint32_t *)&ins[3];
					}
				}
				break;
			case 8:
				if (ins[0] == INS_REX_W_PREFIX && ins[1] == INS_LEA && ins[2] == 0xa4 && ins[3] == 0x24) {
					// lea ...(%rsp), %rsp (32-bit immediate)
					PATCH_LOG("lea ...(%rsp), %rsp", temp_str(formatter(ins, formatter_data)));
					PATCH_LOG("lea %rsp value", (int)*(const uint32_t *)&ins[4]);
					*out_return_address -= *(const uint32_t *)&ins[4];
				}
				break;
			case 9:
				if (ins[0] == 0x64 && ins[1] == 0x48 && ins[2] == 0x33 && ins[4] == 0x25 && ins[5] == 0x28 && ins[6] == 0 && ins[7] == 0 && ins[8] == 0) {
					// xor %fs:0x28,%rcx
					// GCC's stack check. next conditional jump should be to __stack_chk_fail
					PATCH_LOG("found stack check", temp_str(formatter(ins, formatter_data)));
					previous_ins_is_stack_check = true;
				}
				break;
		}
		ins = x86_next_instruction(ins, &decoded);
	}
	// special case the imm16 form of the ret instruction
	if (*ins == INS_REPZ) {
		ins++;
	}
	if (*ins == INS_RET_IMM || *ins == INS_RET_FAR_IMM) {
		*out_return_address += *(const int16_t *)&ins[1];
	}
	return true;
}

// find_basic_block scans instructions to find the basic block containing an instruction
__attribute__((warn_unused_result))
__attribute__((nonnull(1, 3, 4)))
static bool find_basic_block(struct thread_storage *thread, struct instruction_search search, const uint8_t *instruction, struct instruction_range *out_block)
{
tail_call:
	if (check_already_searched_instruction(search)) {
		return true;
	}
	const uint8_t *jump;
	const uint8_t *ins = search.addr;
	bool has_instruction = instruction == ins;
	PATCH_LOG("searching for", (uintptr_t)instruction);
	struct x86_instruction decoded;
	for (;;) {
		PATCH_LOG("processing", (uintptr_t)ins);
		if (!x86_decode_instruction(ins, &decoded)) {
			return false;
		}
		PATCH_LOG("bytes", char_range((const char *)ins, decoded.length));
		if (x86_is_return_instruction(&decoded)) {
			break;
		}
		// Examine jumps
		switch (x86_decode_jump_instruction(&decoded, &jump)) {
			case INS_JUMPS_NEVER:
				break;
			case INS_JUMPS_ALWAYS:
				if (has_instruction) {
					if ((uintptr_t)search.addr > (uintptr_t)out_block->start) {
						out_block->start = search.addr;
					}
					out_block->end = x86_next_instruction(ins, &decoded);
				}
				search.addr = jump;
				goto tail_call;
			case INS_JUMPS_OR_CONTINUES: {
				bool jumped_result = find_basic_block(thread, (struct instruction_search){
					.addr = jump,
					.searched = search.searched,
				}, instruction, out_block);
				if (!jumped_result) {
					return false;
				}
				bool continued_result = find_basic_block(thread, (struct instruction_search){
					.addr = x86_next_instruction(ins, &decoded),
					.searched = search.searched,
				}, instruction, out_block);
				if (!continued_result) {
					return false;
				}
				break;
			}
		}
		ins = x86_next_instruction(ins, &decoded);
		if (ins == instruction) {
			has_instruction = true;
		}
	}
	ins = x86_next_instruction(ins, &decoded);
	// Search for trailing nops
	uintptr_t last_ins_page = ((uintptr_t)ins - 1) & -PAGE_SIZE;
	for (;;) {
		uintptr_t next_ins_page = ((uintptr_t)ins + 0xf) & -PAGE_SIZE;
		if (next_ins_page != last_ins_page) {
			if (!region_is_mapped(thread, (const void *)next_ins_page, 1)) {
				break;
			}
			last_ins_page = next_ins_page;
		}
		if (!x86_is_nop_instruction(ins)) {
			break;
		}
		if (!x86_decode_instruction(ins, &decoded)) {
			break;
		}
		ins = x86_next_instruction(ins, &decoded);
	}
	if (has_instruction) {
		if ((uintptr_t)search.addr > (uintptr_t)out_block->start) {
			out_block->start = search.addr;
		}
		out_block->end = ins;
	}
	return true;
}

// find_patch_target finds the longest possible span of patchable instructions
__attribute__((warn_unused_result))
__attribute__((nonnull(2, 5)))
bool find_patch_target(struct instruction_range basic_block, const uint8_t *target, size_t minimum_size, size_t ideal_size, patch_address_formatter formatter, void *formatter_data, struct instruction_range *out_result)
{
	// precheck on target
	struct x86_instruction ins;
	if (!x86_decode_instruction(target, &ins)) {
		return false;
	}
	if (!is_patchable_instruction(&ins, formatter, formatter_data)) {
		return false;
	}
	// find a candidate for the start of the patch, possibly the target itself
	const uint8_t *start = target;
	const uint8_t *end = x86_next_instruction(start, &ins);
	for (const uint8_t *current = basic_block.start; current < target; ) {
		if (!x86_decode_instruction(current, &ins)) {
			return false;
		}
		if (!is_patchable_instruction(&ins, formatter, formatter_data)) {
			start = target;
		} else if (start == target || end - current >= (ssize_t)minimum_size) {
			start = current;
		}
		current = x86_next_instruction(current, &ins);
	}
	// search past the target until the minimum patch size is found
	while (end < basic_block.end && end - start < (ssize_t)ideal_size) {
		if (!x86_decode_instruction(end, &ins)) {
			break;
		}
		if (!is_patchable_instruction(&ins, formatter, formatter_data)) {
			break;
		}
		end = x86_next_instruction(end, &ins);
	}
	// couldn't find enough patchable bytes
	if (end - start < (ssize_t)minimum_size) {
		return false;
	}
	out_result->start = start;
	out_result->end = end;
	return true;
}

__attribute__((warn_unused_result))
static inline bool patch_common(struct thread_storage *thread, uintptr_t instruction, struct instruction_range basic_block, void *start_template, void *call_template, void *end_template, void *handler, bool skip, int self_fd);

static char *naive_address_formatter(const uint8_t *address, void *unused)
{
	(void)unused;
	char *result = malloc(2 * sizeof(uintptr_t) + 3);
	fs_utoah((uintptr_t)address, result);
	return result;
}

// patch_body attempts to patch a syscall instruction already having taken the shard's lock
void patch_body(struct thread_storage *thread, struct patch_body_args *args)
{
	// Check if syscall has been rewritten
	const uint8_t *syscall_ins = (const uint8_t *)args->pc - 2;
	if (!x86_is_syscall_instruction(syscall_ins)) {
		return;
	}
	PATCH_LOG("pc", (uintptr_t)args->pc);
	PATCH_LOG("sp", (uintptr_t)args->sp);
	// Find the function entry point
	struct searched_instructions searched;
	struct attempt_cleanup_state searched_cleanup;
	init_searched_instructions(thread, &searched, &searched_cleanup);
	const struct instruction_search return_addr_search = {
		.addr = (uint8_t *)args->pc,
		.searched = &searched,
	};
	intptr_t return_address = args->sp;
	bool found_return_address = find_return_address(return_addr_search, args->bp, naive_address_formatter, NULL, &return_address);
	free_searched_instructions(&searched, &searched_cleanup);
	if (!found_return_address) {
		PATCH_LOG("could not find return address");
		return;
	}
	PATCH_LOG("ret slot", (uintptr_t)return_address);
	uintptr_t ret = *(const uintptr_t *)return_address;
	PATCH_LOG("ret addr", ret);
	if (ret == 0) {
		PATCH_LOG("invalid ret address");
		return;
	}
	uintptr_t entry;
	if (*(const uint8_t *)(ret - 5) == INS_CALL_32_IMM) {
		entry = ret + *(const int32_t *)(ret - 4);
	} else {
		PATCH_LOG("not a call", (uintptr_t)*(const uint8_t *)(ret - 5));
		const ElfW(Ehdr) *library_base = NULL;
		const char *library_path = NULL;
		if (!debug_find_library(syscall_ins, &library_base, &library_path)) {
			PATCH_LOG("unknown library");
			return;
		}
		PATCH_LOG("in library", library_path);
		PATCH_LOG("base", (uintptr_t)library_base);
		struct binary_info library_info;
		load_existing(&library_info, (uintptr_t)library_base);
		struct symbol_info symbols;
		int symbol_result = parse_dynamic_symbols(&library_info, (void *)library_base, &symbols);
		if (symbol_result < 0) {
			PATCH_LOG("error reading symbols", fs_strerror(symbol_result));
			return;
		}
		entry = (uintptr_t)find_symbol_by_address(&library_info, &symbols, syscall_ins, NULL);
		if (!entry) {
			PATCH_LOG("could not find symbol");
			return;
		}
	}
	PATCH_LOG("entry", entry);
	// Find the basic block containing the syscall instruction
	init_searched_instructions(thread, &searched, &searched_cleanup);
	const struct instruction_search basic_block_search = {
		.addr = (const uint8_t *)entry,
		.searched = &searched,
	};
	struct instruction_range basic_block = { 0 };
	bool found_basic_block = find_basic_block(thread, basic_block_search, (const uint8_t *)args->pc - 2, &basic_block) && basic_block.start != NULL;
	free_searched_instructions(&searched, &searched_cleanup);
	if (!found_basic_block) {
		PATCH_LOG("could not find basic block");
		return;
	}
	// Trim the basic block to not include the next instruction. Other threads
	// could be in the kernel's syscall handler and return to the next
	// instruction at any time!
	if (basic_block.end > (const uint8_t *)args->pc) {
		basic_block.end = (const uint8_t *)args->pc;
	}
	// Actually patch
	args->patched = patch_common(thread, args->pc - 2, basic_block, &trampoline_call_handler_start, &trampoline_call_handler_call, &trampoline_call_handler_end, &receive_trampoline, true, args->self_fd);
}

// migrate_instruction copies and relocates instructions
__attribute__((warn_unused_result))
bool migrate_instructions(uint8_t *dest, const uint8_t *src, ssize_t delta, size_t byte_count, patch_address_formatter formatter, void *formatter_data)
{
	(void)formatter;
	(void)formatter_data;
	const uint8_t *end_src = src + byte_count;
	while (src < end_src) {
		struct x86_instruction decoded;
		if (!x86_decode_instruction(src, &decoded)) {
			return false;
		}
		memcpy(dest, src, decoded.length);
		const uint8_t *ins = dest + (decoded.unprefixed - src);
		switch (*ins) {
			case 0xe9: {
				PATCH_LOG("fixing up rip-relative addressing", temp_str(formatter(src, formatter_data)));
				x86_int32 *disp = (x86_int32 *)&ins[1];
				PATCH_LOG("was", *disp);
				*disp += delta;
				PATCH_LOG("is now", *disp);
				break;
			}
			case INS_CONDITIONAL_JMP_32_IMM_0:
				if (ins[1] >= INS_CONDITIONAL_JMP_32_IMM_1_START && ins[1] <= INS_CONDITIONAL_JMP_32_IMM_1_END) {
					PATCH_LOG("fixing up rip-relative addressing", temp_str(formatter(src, formatter_data)));
					x86_int32 *disp = (x86_int32 *)&ins[2];
					PATCH_LOG("was", *disp);
					*disp += delta;
					PATCH_LOG("is now", *disp);
				}
				break;
			case 0x8b:
			case 0x89:
			case INS_LEA: {
				x86_mod_rm_t modrm = x86_read_modrm(&ins[1]);
				if (modrm.mod == 0) {
					int rm = x86_read_rm(modrm, decoded.prefixes);
					switch (rm) {
						case X86_REGISTER_BP:
						case X86_REGISTER_13: {
							PATCH_LOG("fixing up rip-relative addressing", temp_str(formatter(src, formatter_data)));
							x86_int32 *disp = (x86_int32 *)&ins[2];
							PATCH_LOG("was", *disp);
							*disp += delta;
							PATCH_LOG("is now", *disp);
							break;
						}
					}
				}
				break;
			}
		}
		dest = (uint8_t *)x86_next_instruction(dest, &decoded);
		src = x86_next_instruction(src, &decoded);
	}
	return true;
}

__attribute__((always_inline))
static inline bool patch_common(struct thread_storage *thread, uintptr_t instruction, struct instruction_range basic_block, void *start_template, void *call_template, void *end_template, void *handler, bool skip, int self_fd)
{
	PATCH_LOG("basic block start", (uintptr_t)basic_block.start);
	PATCH_LOG("basic block end", (uintptr_t)basic_block.end);
	// Find the patch target
	struct x86_instruction decoded;
	if (!x86_decode_instruction((const uint8_t *)instruction, &decoded)) {
		return false;
	}
	if (x86_is_endbr64_instruction(&decoded)) {
		instruction += decoded.length;
	}
	struct instruction_range patch_target;
	if (!find_patch_target(basic_block, (const uint8_t *)instruction, skip ? PCREL_JUMP_SIZE : 1, PCREL_JUMP_SIZE, naive_address_formatter, NULL, &patch_target)) {
		PATCH_LOG("unable to find patch target");
		ERROR_FLUSH();
		return false;
	}
	PATCH_LOG("patch start", (uintptr_t)patch_target.start);
	PATCH_LOG("patch end", (uintptr_t)patch_target.end);
	struct mapping target_mapping = { 0 };
	int mapping_error = lookup_mapping_for_address(patch_target.start, &target_mapping);
	if (mapping_error <= 0) {
		if (mapping_error < 0) {
			DIE("could not read memory mappings", fs_strerror(mapping_error));
		}
		DIE("could not find memory mapping");
	}
	if ((target_mapping.flags & (MAP_SHARED | MAP_PRIVATE)) == MAP_SHARED) {
		// Found that the mapping was shared, don't patch
		PATCH_LOG("found shared mapping", (uintptr_t)target_mapping.flags);
		ERROR_FLUSH();
		return false;
	}
	// Find an unused page to detour to
	uintptr_t start_page = (uintptr_t)patch_target.start & -PAGE_SIZE;
	uintptr_t stub_address;
	struct attempt_cleanup_state lock_cleanup;
	attempt_lock_and_push_mutex(thread, &lock_cleanup, &patches_lock);
	bool new_address;
	uintptr_t current_region = patches != NULL ? (uintptr_t)&patches[1] : 0;
	uintptr_t space_required = (10 + ((uintptr_t)end_template - (uintptr_t)start_template) + 12 + sizeof(struct applied_patch));
	if (current_region && trampoline_region_has_space((uint8_t *)current_region, space_required) && is_valid_pc_relative_offset(current_region - (uintptr_t)patch_target.end)) {
		// Have at least the space left in the trampoline page and the trampoline's address is compatible with a PC-relative jump
		stub_address = current_region;
		new_address = false;
	} else {
		void *new_mapping = fs_mmap((void *)start_page, TRAMPOLINE_REGION_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, self_fd == -1 ? MAP_ANONYMOUS|MAP_PRIVATE : MAP_PRIVATE, self_fd, self_fd == -1 ? 0 : PAGE_SIZE);
		if (UNLIKELY(fs_is_map_failed(new_mapping))) {
			attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
			PATCH_LOG("Failed to patch: mmap failed", -(intptr_t)new_mapping);
			return false;
		}
		if (is_valid_pc_relative_offset((uintptr_t)new_mapping - (uintptr_t)patch_target.end)) {
			// Address kernel gave us is compatible with a pc-relative jump, use it
			stub_address = (uintptr_t)new_mapping;
		} else {
			// search for a compatible address by searching the address space for a gap
			stub_address = find_unused_address(thread, start_page);
			if (!is_valid_pc_relative_offset((intptr_t)stub_address - (uintptr_t)patch_target.end)) {
				fs_munmap(new_mapping, TRAMPOLINE_REGION_SIZE);
				attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
				PATCH_LOG("Failed to patch: invalid pc-relative offset", (intptr_t)stub_address - (uintptr_t)patch_target.end);
				ERROR_FLUSH();
				return false;
			}
			void *remap_result = fs_mremap(new_mapping, TRAMPOLINE_REGION_SIZE, TRAMPOLINE_REGION_SIZE, MREMAP_FIXED|MREMAP_MAYMOVE, (void *)stub_address);
			if (fs_is_map_failed(remap_result)) {
				PATCH_LOG("Failed to patch: mremap failed", -(intptr_t)remap_result);
				fs_munmap(new_mapping, TRAMPOLINE_REGION_SIZE);
				attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
				ERROR_FLUSH();
				return false;
			}
		}
		new_address = true;
	}
	PATCH_LOG("trampoline", (uintptr_t)stub_address);
	// Construct the trampoline
	uint8_t *trampoline = (uint8_t *)stub_address;
	size_t head_size = instruction - (intptr_t)patch_target.start;
	if (!migrate_instructions(trampoline, patch_target.start, patch_target.start - trampoline, head_size, naive_address_formatter, NULL)) {
		attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
		PATCH_LOG("Failed to patch: migrating head failed");
		if (new_address) {
			fs_munmap((void *)stub_address, TRAMPOLINE_REGION_SIZE);
		}
	}
	trampoline += head_size;
	// Copy the prefix part of the trampoline
	size_t prefix_size = (uintptr_t)call_template - (uintptr_t)start_template;
	memcpy(trampoline, start_template, prefix_size);
	trampoline += prefix_size;
	// Move address of receive_trampoline into rcx
	*trampoline++ = INS_MOV_RCX_64_IMM_0;
	*trampoline++ = INS_MOV_RCX_64_IMM_1;
	*(uintptr_t *)trampoline = (uintptr_t)handler;
	trampoline += sizeof(uintptr_t);
	// Copy the suffix part of the trampoline
	size_t suffix_size = (uintptr_t)end_template - (uintptr_t)call_template;
	memcpy(trampoline, call_template, suffix_size);
	trampoline += suffix_size;
	// Copy the patched instructions from the original basic block
	uintptr_t tail_start = instruction;
	if (skip) {
		if (x86_decode_instruction((const uint8_t *)instruction, &decoded)) {
			tail_start += decoded.length;
		}
	}
	size_t tail_size = (uintptr_t)patch_target.end - tail_start;
	if (!migrate_instructions(trampoline, (const uint8_t *)tail_start, (uintptr_t)tail_start - (uintptr_t)trampoline, tail_size, naive_address_formatter, NULL)) {
		attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
		PATCH_LOG("Failed to patch: migrating tail failed");
		if (new_address) {
			fs_munmap((void *)stub_address, TRAMPOLINE_REGION_SIZE);
		}
	}
	trampoline += tail_size;
	// Construct a jump back to the original function
	intptr_t return_offset = (uintptr_t)patch_target.end - (intptr_t)&trampoline[PCREL_JUMP_SIZE];
	// PC-relative jump
	*trampoline++ = INS_JMP_32_IMM;
	*(int32_t *)trampoline = return_offset;
	trampoline += sizeof(int32_t);
	// Make the target function writable
	size_t protect_size = (((uintptr_t)patch_target.end + PAGE_SIZE - 1) & -PAGE_SIZE) - start_page;
	if (fs_mprotect((void *)start_page, protect_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
		PATCH_LOG("Failed to patch: mprotect failed");
		if (new_address) {
			fs_munmap((void *)stub_address, TRAMPOLINE_REGION_SIZE);
		}
		ERROR_FLUSH();
		return false;
	}
	// Patch in some illegal instructions
	for (const uint8_t *ill = patch_target.start; ill < patch_target.end; ) {
		struct x86_instruction ill_decoded;
		if (!x86_decode_instruction(ill, &ill_decoded)) {
			break;
		}
		*(uint8_t *)ill = INS_ONE_BYTE_ILL;
		ill = x86_next_instruction(ill, &ill_decoded);
	}
	// Wait for all cores to see these illegals
	if (membarrier_is_supported) {
		fs_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0);
	}
	// Patch the syscall and following instructions to jump to the trampoline
	uint8_t *ins = (uint8_t *)patch_target.start;
	bool patch_with_ill = (uintptr_t)patch_target.end - (uintptr_t)patch_target.start < PCREL_JUMP_SIZE;
	if (!patch_with_ill) {
		int32_t offset = stub_address - (intptr_t)&patch_target.start[5];
		*(int32_t *)&ins[1] = offset;
		atomic_store((_Atomic uint8_t *)ins, INS_JMP_32_IMM);
	}
	// Install nops in any trailing bytes, so that it's clean in the debugger
	for (ins += patch_with_ill ? 1 : PCREL_JUMP_SIZE; ins < patch_target.end; ++ins) {
		*ins = INS_NOP;
	}
	// Update the patches list
	struct applied_patch *patch = (struct applied_patch *)trampoline;
	patch->range = patch_target;
	patch->target = stub_address;
	patch->next = patches;
	patch->is_ill_patch = patch_with_ill;
	patches = patch;
	// Restore original protection
	if (mapping_error == 0) {
		int result = fs_mprotect((void *)start_page, protect_size, target_mapping.flags & (PROT_READ | PROT_WRITE | PROT_EXEC));
		if (result < 0) {
			PATCH_LOG("Failed to update protection", -result);
		}
	}
	attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
	PATCH_LOG("finished patch");
	ERROR_FLUSH();
	return true;
}

struct handle_illegal_args {
	ucontext_t *context;
	bool result;
};

static void patch_handle_illegal_instruction_body(struct thread_storage *thread, struct handle_illegal_args *args)
{
	struct attempt_cleanup_state lock_cleanup;
	attempt_lock_and_push_mutex(thread, &lock_cleanup, &patches_lock);
	const uint8_t *pc = (const uint8_t *)args->context->uc_mcontext.REG_PC;
	// Find a patch for the associated region, preferring newer patches
	struct applied_patch *patch = patches;
	while (patch) {
		if (patch->range.start <= pc && pc < patch->range.end && *patch->range.start == (patch->is_ill_patch ? INS_ONE_BYTE_ILL : INS_JMP_32_IMM)) {
			args->context->uc_mcontext.REG_PC = patch->target + (pc - patch->range.start);
			args->result = true;
			break;
		}
		patch = patch->next;
	}
	attempt_unlock_and_pop_mutex(&lock_cleanup, &patches_lock);
}

bool patch_handle_illegal_instruction(struct thread_storage *thread, ucontext_t *context)
{
	struct handle_illegal_args args = {
		.context = context,
		.result = false,
	};
	attempt(thread, (attempt_body)&patch_handle_illegal_instruction_body, &args);
	return args.result;
}

bool patch_breakpoint(struct thread_storage *thread, intptr_t address, intptr_t entry, void (*handler)(uintptr_t *), int self_fd)
{
	PATCH_LOG("patching breakpoint", (uintptr_t)address);
	// Construct the basic block that contains the address. Need to do a full
	// analysis of the procedure since it's possible for code to jump into the
	// middle of what looks like a basic block!
	struct searched_instructions searched;
	struct attempt_cleanup_state searched_cleanup;
	init_searched_instructions(thread, &searched, &searched_cleanup);
	const struct instruction_search basic_block_search = {
		.addr = (const uint8_t *)entry,
		.searched = &searched,
	};
	struct instruction_range basic_block = { 0 };
	bool found_basic_block = find_basic_block(thread, basic_block_search, (const uint8_t *)entry, &basic_block);
	free_searched_instructions(&searched, &searched_cleanup);
	if (!found_basic_block || basic_block.start == NULL) {
		PATCH_LOG("could not find basic block");
		return false;
	}
	return patch_common(thread, address, basic_block, &breakpoint_call_handler_start, &breakpoint_call_handler_call, &breakpoint_call_handler_end, handler, false, self_fd);
}

bool patch_function(struct thread_storage *thread, intptr_t function, intptr_t (*handler)(uintptr_t *arguments, intptr_t original), int self_fd)
{
	PATCH_LOG("patching function", (uintptr_t)function);
	// Construct the entry basic block. Need to do a full analysis of the
	// procedure since it's possible for code to jump back into the middle of
	// the patch point, if we're unlucky. In all but exceptional circumstances
	// the function prologue can be patched.
	struct searched_instructions searched;
	struct attempt_cleanup_state searched_cleanup;
	init_searched_instructions(thread, &searched, &searched_cleanup);
	const struct instruction_search basic_block_search = {
		.addr = (const uint8_t *)function,
		.searched = &searched,
	};
	struct instruction_range basic_block = { 0 };
	bool found_basic_block = find_basic_block(thread, basic_block_search, (const uint8_t *)function, &basic_block);
	free_searched_instructions(&searched, &searched_cleanup);
	if (!found_basic_block || basic_block.start == NULL) {
		PATCH_LOG("could not find basic block");
		return false;
	}
	return patch_common(thread, function, basic_block, &function_call_handler_start, &function_call_handler_call, &function_call_handler_end, handler, false, self_fd);
}

#endif
