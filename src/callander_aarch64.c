#include "callander.h"
#include "callander_internal.h"
#include "callander_print.h"

#include "ins.h"

#define UNSUPPORTED_INSTRUCTION()                                                                        \
	do {                                                                                                 \
		char *buf = malloc(4096);                                                                        \
		if (aarch64_disassemble(&decoded->decomposed, buf, 4096) != DISASM_SUCCESS) {                     \
			self->description = operation_to_str(decoded->decomposed.operation);                           \
		} else {                                                                                         \
			self->description = buf;                                                                      \
		}                                                                                                \
		DIE("unsupported instruction: ", temp_str(copy_call_trace_description(&analysis->loader, self))); \
	} while (0)

static inline void update_sources_for_basic_op_usage(struct registers *regs, int dest_reg, int left_reg, int right_reg, enum basic_op_usage usage)
{
	if (UNLIKELY(dest_reg == REGISTER_INVALID)) {
		return;
	}
	if (UNLIKELY(left_reg == REGISTER_INVALID)) {
		usage &= ~BASIC_OP_USED_LEFT;
	}
	if (right_reg == REGISTER_INVALID) {
		usage &= ~BASIC_OP_USED_RIGHT;
	}
	register_mask dest_mask = mask_for_register(dest_reg);
	switch (usage) {
		case BASIC_OP_USED_NEITHER:
			regs->sources[dest_reg] = 0;
			regs->requires_known_target &= ~dest_mask;
			break;
		case BASIC_OP_USED_RIGHT:
			regs->sources[dest_reg] = regs->sources[right_reg];
			regs->requires_known_target = (regs->requires_known_target & ~dest_mask) | ((regs->requires_known_target & mask_for_register(right_reg)) ? dest_mask : 0);
			break;
		case BASIC_OP_USED_LEFT:
			regs->sources[dest_reg] = regs->sources[left_reg];
			regs->requires_known_target = (regs->requires_known_target & ~dest_mask) | ((regs->requires_known_target & mask_for_register(left_reg)) ? dest_mask : 0);
			break;
		case BASIC_OP_USED_BOTH:
			regs->sources[dest_reg] = regs->sources[left_reg] | regs->sources[right_reg];
			regs->requires_known_target = (regs->requires_known_target & ~dest_mask) | ((regs->requires_known_target & (mask_for_register(left_reg) | mask_for_register(right_reg))) ? dest_mask : 0);
			break;
	}
}


static inline bool stack_offset_for_imm(int64_t imm, int64_t *out_offset)
{
	if (imm & 0x7) {
		return false;
	}
	*out_offset = imm >> 3;
	return true;
}

static bool add_to_stack(const struct loader_context *loader, struct registers *registers, int64_t amount, const ins_ptr ins)
{
	dump_nonempty_registers(loader, registers, STACK_REGISTERS);
	clear_register(&registers->registers[REGISTER_SP]);
	int64_t offset;
	if (!stack_offset_for_imm(amount, &offset)) {
		clear_match(loader, registers, REGISTER_SP, ins);
		return false;
	}
	clear_match_keep_stack(loader, registers, REGISTER_SP, ins);
	if (offset < 0) {
		push_stack(loader, registers, -offset, ins);
	} else if (amount > 0) {
		pop_stack(loader, registers, offset, ins);
	}
	dump_nonempty_registers(loader, registers, STACK_REGISTERS);
	return true;
}

static inline int read_operand(struct loader_context *loader, const struct InstructionOperand *operand, struct registers *regs, const ins_ptr ins, struct register_state out_state[static 1], enum ins_operand_size *out_size)
{
	switch (operand->operandClass) {
		case REG: {
			int reg = register_index_from_register(operand->reg[0]);
			if (reg != AARCH64_REGISTER_INVALID) {
				*out_state = regs->registers[reg];
			} else if (operand->reg[0] == REG_WZR || operand->reg[0] == REG_XZR) {
				set_register(out_state, 0);
			} else {
				break;
			}
			enum ins_operand_size size = get_register_size(operand->reg[0]);
			if (size != OPERATION_SIZE_DWORD && out_state->value > 0xffffffff) {
				// if truncating an address, consider the value unknown
				struct loaded_binary *binary = binary_for_address(loader, (const void *)out_state->value);
				if (binary != NULL) {
					clear_register(out_state);
					clear_match(loader, regs, reg, ins);
				}
			}
			truncate_to_operand_size(out_state, size);
			if (out_size != NULL) {
				*out_size = size;
			}
			return reg;
		}
		case IMM32: {
			set_register(out_state, operand->immediate);
			truncate_to_operand_size(out_state, OPERATION_SIZE_WORD);
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_WORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case IMM64: {
			set_register(out_state, operand->immediate);
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_DWORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case LABEL: {
			set_register(out_state, operand->immediate);
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_DWORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case MEM_REG: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				*out_state = regs->registers[REGISTER_STACK_0];
				if (out_size != NULL) {
					*out_size = OPERATION_SIZE_DWORD;
				}
				return REGISTER_STACK_0;
			}
			break;
		}
		case MEM_OFFSET: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				int64_t offset;
				if (stack_offset_for_imm(operand->immediate, &offset) && offset > 0) {
					uintptr_t reg = REGISTER_STACK_0 + offset;
					if (reg >= REGISTER_STACK_0 && reg < REGISTER_COUNT) {
						*out_state = regs->registers[reg];
						if (out_size != NULL) {
							*out_size = OPERATION_SIZE_DWORD;
						}
						return reg;
					}
				}
			}
			break;
		}
		case MEM_PRE_IDX: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				// adjust the stack
				add_to_stack(loader, regs, operand->immediate, ins);
				*out_state = regs->registers[REGISTER_STACK_0];
				if (out_size != NULL) {
					*out_size = OPERATION_SIZE_DWORD;
				}
				// and reference the data at the stack pointer
				return REGISTER_STACK_0;
			}
		}
		// fallthrough
		case MEM_POST_IDX: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				// adjust the stack
				add_to_stack(loader, regs, operand->immediate, ins);
			} else {
				int reg = register_index_from_register(operand->reg[0]);
				if (reg != REGISTER_INVALID) {
					struct register_state imm;
					set_register(&imm, operand->immediate);
					add_registers(&regs->registers[reg], &imm);
					clear_match(loader, regs, reg, ins);
				}
			}
			clear_register(out_state);
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_DWORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		default:
			break;
	}
	clear_register(out_state);
	if (out_size != NULL) {
		*out_size = OPERATION_SIZE_DWORD;
	}
	return AARCH64_REGISTER_INVALID;
}

static inline int get_operand(struct loader_context *loader, const struct InstructionOperand *operand, struct registers *regs, const ins_ptr ins, enum ins_operand_size *out_size)
{
	switch (operand->operandClass) {
		case REG: {
			int reg = register_index_from_register(operand->reg[0]);
			if (reg == AARCH64_REGISTER_INVALID) {
				break;
			}
			enum ins_operand_size size = get_register_size(operand->reg[0]);
			if (size != OPERATION_SIZE_DWORD && regs->registers[reg].value > 0xffffffff) {
				// if truncating an address, consider the value unknown
				struct loaded_binary *binary = binary_for_address(loader, (const void *)regs->registers[reg].value);
				if (binary != NULL) {
					clear_match(loader, regs, reg, ins);
				}
			}
			if (out_size != NULL) {
				*out_size = size;
			}
			return reg;
		}
		case IMM32: {
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_WORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case IMM64: {
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_DWORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case LABEL: {
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_DWORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		case MEM_REG: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				if (out_size != NULL) {
					*out_size = OPERATION_SIZE_DWORD;
				}
				return REGISTER_STACK_0;
			}
			break;
		}
		case MEM_OFFSET: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				int64_t offset;
				if (stack_offset_for_imm(operand->immediate, &offset) && offset > 0) {
					uintptr_t reg = REGISTER_STACK_0 + offset;
					if (reg >= REGISTER_STACK_0 && reg < REGISTER_COUNT) {
						if (out_size != NULL) {
							*out_size = OPERATION_SIZE_DWORD;
						}
						return reg;
					}
				}
			}
			break;
		}
		case MEM_PRE_IDX: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				// adjust the stack
				add_to_stack(loader, regs, operand->immediate, ins);
				if (out_size != NULL) {
					*out_size = OPERATION_SIZE_DWORD;
				}
				// and reference the data at the stack pointer
				return REGISTER_STACK_0;
			}
		}
		// fallthrough
		case MEM_POST_IDX: {
			if (register_index_from_register(operand->reg[0]) == AARCH64_REGISTER_SP) {
				// adjust the stack
				add_to_stack(loader, regs, operand->immediate, ins);
			} else {
				int reg = register_index_from_register(operand->reg[0]);
				if (reg != REGISTER_INVALID) {
					struct register_state imm;
					set_register(&imm, operand->immediate);
					add_registers(&regs->registers[reg], &imm);
					clear_match(loader, regs, reg, ins);
				}
			}
			if (out_size != NULL) {
				*out_size = OPERATION_SIZE_DWORD;
			}
			return AARCH64_REGISTER_INVALID;
		}
		default:
			break;
	}
	if (out_size != NULL) {
		*out_size = OPERATION_SIZE_DWORD;
	}
	return AARCH64_REGISTER_INVALID;
}

#define UNARY_OP_ARGS                                                                                                                                                               \
	struct register_state dest[static 1], __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg, __attribute__((unused)) enum ins_operand_size operand_size, \
		__attribute__((unused)) struct additional_result additional[static 1]
typedef __attribute__((warn_unused_result)) bool (*unary_op)(UNARY_OP_ARGS);

static bool unary_op_cls(UNARY_OP_ARGS)
{
	if (register_is_exactly_known(dest)) {
		switch (operand_size) {
			case OPERATION_SIZE_DWORD:
				set_register(dest, __builtin_clzll(~(uint64_t)dest->value));
				break;
			case OPERATION_SIZE_WORD:
				set_register(dest, __builtin_clz(~(uint32_t)dest->value));
				break;
			case OPERATION_SIZE_HALF:
				set_register(dest, __builtin_clz(~(uint16_t)dest->value) - 16);
				break;
			case OPERATION_SIZE_BYTE:
				set_register(dest, __builtin_clz(~(uint8_t)dest->value) - 24);
				break;
		}
		return true;
	} else {
		clear_register(dest);
		return false;
	}
}

static bool unary_op_clz(UNARY_OP_ARGS)
{
	if (register_is_exactly_known(dest)) {
		switch (operand_size) {
			case OPERATION_SIZE_DWORD:
				set_register(dest, __builtin_clzll((uint64_t)dest->value));
				break;
			case OPERATION_SIZE_WORD:
				set_register(dest, __builtin_clz((uint32_t)dest->value));
				break;
			case OPERATION_SIZE_HALF:
				set_register(dest, __builtin_clz((uint16_t)dest->value) - 16);
				break;
			case OPERATION_SIZE_BYTE:
				set_register(dest, __builtin_clz((uint8_t)dest->value) - 24);
				break;
		}
		return true;
	} else {
		clear_register(dest);
		return false;
	}
}

static bool unary_op_neg(UNARY_OP_ARGS)
{
	if (register_is_exactly_known(dest)) {
		switch (operand_size) {
			case OPERATION_SIZE_DWORD:
				set_register(dest, -(int64_t)dest->value);
				break;
			case OPERATION_SIZE_WORD:
				set_register(dest, -(int32_t)dest->value);
				break;
			case OPERATION_SIZE_HALF:
				set_register(dest, -(int16_t)dest->value);
				break;
			case OPERATION_SIZE_BYTE:
				set_register(dest, -(int8_t)dest->value);
				break;
		}
		return true;
	} else {
		clear_register(dest);
		return false;
	}
}

static bool unary_op_mvn(UNARY_OP_ARGS)
{
	if (register_is_exactly_known(dest)) {
		switch (operand_size) {
			case OPERATION_SIZE_DWORD:
				set_register(dest, ~dest->value);
				break;
			case OPERATION_SIZE_WORD:
				set_register(dest, ~(uint32_t)dest->value);
				break;
			case OPERATION_SIZE_HALF:
				set_register(dest, ~(uint16_t)dest->value);
				break;
			case OPERATION_SIZE_BYTE:
				set_register(dest, ~(uint8_t)dest->value);
				break;
		}
		return true;
	} else {
		clear_register(dest);
		return false;
	}
}

static bool unary_op_rev(UNARY_OP_ARGS)
{
	if (register_is_exactly_known(dest)) {
		switch (operand_size) {
			case OPERATION_SIZE_DWORD:
				set_register(dest, __builtin_bswap64(dest->value));
				break;
			case OPERATION_SIZE_WORD:
				set_register(dest, __builtin_bswap32(dest->value));
				break;
			case OPERATION_SIZE_HALF:
				set_register(dest, __builtin_bswap16(dest->value));
				break;
			case OPERATION_SIZE_BYTE:
				break;
		}
		return true;
	} else {
		clear_register(dest);
		return false;
	}
}

static bool unary_op_rbit(UNARY_OP_ARGS)
{
	if (register_is_exactly_known(dest)) {
		uintptr_t result = 0;
		for (int i = 0; i < (int)operand_size * 8; i++) {
			if (dest->value & ((uint64_t)1 << i)) {
				result |= (uint64_t)1 << (operand_size * 8 - i);
			}
		}
		set_register(dest, result);
		return true;
	} else {
		clear_register(dest);
		return false;
	}
}

__attribute__((warn_unused_result)) static int perform_unary_op(__attribute__((unused)) const char *name, unary_op op, struct loader_context *loader, struct registers *regs, ins_ptr ins, struct aarch64_instruction *decoded,
                                                                enum ins_operand_size *out_size, struct additional_result *additional)
{
	enum ins_operand_size size;
	int dest = get_operand(loader, &decoded->decomposed.operands[0], regs, ins, &size);
	if (dest == REGISTER_INVALID) {
		if (out_size != NULL) {
			*out_size = OPERATION_SIZE_DWORD;
		}
		return REGISTER_INVALID;
	}
	LOG("unary ", name, " operation on ", name_for_register(dest));
	struct register_state state;
	int source = read_operand(loader, &decoded->decomposed.operands[1], regs, ins, &state, NULL);
	if (source != REGISTER_INVALID) {
		LOG("", name_for_register(source), " is source");
	}
	bool applied_shift = apply_operand_shift(&state, &decoded->decomposed.operands[1]);
	LOG("", temp_str(copy_register_state_description(loader, state)), " is value");
	additional->used = false;
	uintptr_t orig_value = state.value;
	bool usage = op(&state, dest, applied_shift ? REGISTER_INVALID : source, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &state, additional, orig_value);
	} else {
		truncate_to_operand_size(&state, size);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_operand_size(&additional->state, size);
		merge_and_log_additional_result(loader, &state, additional, dest);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, state)));
	}
	regs->registers[dest] = state;
	if (register_is_partially_known(&state)) {
		update_sources_for_basic_op_usage(regs, dest, source, source, usage);
	} else {
		regs->sources[dest] = 0;
	}
	clear_match(loader, regs, dest, ins);
	if (out_size != NULL) {
		*out_size = size;
	}
	return dest;
}

__attribute__((warn_unused_result)) static int perform_basic_op(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, ins_ptr ins, const struct aarch64_instruction *decoded,
                                                                enum ins_operand_size *out_size, struct additional_result *additional)
{
	enum ins_operand_size size;
	int dest = get_operand(loader, &decoded->decomposed.operands[0], regs, ins, &size);
	if (dest == REGISTER_INVALID) {
		if (out_size != NULL) {
			*out_size = OPERATION_SIZE_DWORD;
		}
		return REGISTER_INVALID;
	}
	LOG("basic ", name, " operation dest: ", name_for_register(dest));
	struct register_state left_state;
	int left = read_operand(loader, &decoded->decomposed.operands[1], regs, ins, &left_state, NULL);
	if (left != REGISTER_INVALID) {
		LOG("", name_for_register(left), " is left source");
	}
	LOG("", temp_str(copy_register_state_description(loader, left_state)), " is left value");
	struct register_state right_state;
	int right = read_operand(loader, &decoded->decomposed.operands[2], regs, ins, &right_state, NULL);
	if (right != REGISTER_INVALID) {
		LOG("", name_for_register(right), " is right source");
	}
	bool applied_shift = apply_operand_shift(&right_state, &decoded->decomposed.operands[2]);
	LOG("", temp_str(copy_register_state_description(loader, right_state)), " is right value");
	additional->used = false;
	uintptr_t orig_value = left_state.value;
	enum basic_op_usage usage = op(&left_state, &right_state, left, applied_shift ? REGISTER_INVALID : right, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &left_state, additional, orig_value);
		widen_cross_binary_bound_operation(loader, &left_state, additional, right_state.value);
	} else {
		truncate_to_operand_size(&left_state, size);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_operand_size(&additional->state, size);
		merge_and_log_additional_result(loader, &left_state, additional, left);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, left_state)));
	}
	regs->registers[dest] = left_state;
	if (register_is_partially_known(&left_state)) {
		update_sources_for_basic_op_usage(regs, dest, left, right, usage);
	} else {
		regs->sources[dest] = 0;
	}
	clear_match(loader, regs, dest, ins);
	if (out_size != NULL) {
		*out_size = size;
	}
	return dest;
}

static void clear_arg(struct loader_context *loader, struct registers *regs, int index, ins_ptr ins, const struct aarch64_instruction *decoded)
{
	enum ins_operand_size size;
	int dest = get_operand(loader, &decoded->decomposed.operands[index], regs, ins, &size);
	if (dest == REGISTER_INVALID) {
		return;
	}
	LOG("clearing ", name_for_register(dest));
	clear_register(&regs->registers[dest]);
	truncate_to_operand_size(&regs->registers[dest], size);
	regs->sources[dest] = 0;
	clear_match(loader, regs, dest, ins);
	dump_registers(loader, regs, mask_for_register(dest));
}

static void perform_unknown_op(struct loader_context *loader, struct registers *regs, ins_ptr ins, const struct aarch64_instruction *decoded)
{
	LOG("unsupported ", get_operation(&decoded->decomposed), " operation at ", temp_str(copy_address_description(loader, ins)));
	clear_arg(loader, regs, 0, ins, decoded);
}

bool analyze_instructions_arch(struct program_state *analysis, function_effects required_effects, function_effects *effects, ins_ptr ins, const struct analysis_frame *caller, trace_flags trace_flags, struct analysis_frame *self, struct aarch64_instruction *decoded)
{
	struct additional_result additional;
	int additional_reg;
	switch (decoded->decomposed.operation) {
		case ARM64_ERROR:
			DIE("error decoding instruction: ", temp_str(copy_address_description(&analysis->loader, ins)));
			break;
		case ARM64_ABS:
		case ARM64_ADCLB:
		case ARM64_ADCLT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ADC: {
			int dest = perform_basic_op("adc", basic_op_adc, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ADCS: {
			int dest = perform_basic_op("adcs", basic_op_adc, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			clear_comparison_state(&self->current_state);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ADD: {
			if (register_index_from_register(decoded->decomposed.operands[0].reg[0]) == AARCH64_REGISTER_SP && register_index_from_register(decoded->decomposed.operands[1].reg[0]) == AARCH64_REGISTER_SP) {
				if (decoded->decomposed.operands[2].operandClass == IMM32 || decoded->decomposed.operands[2].operandClass == IMM64) {
					if (decoded->decomposed.operands[1].reg[0] == decoded->decomposed.operands[0].reg[0]) {
						int64_t imm = (int64_t)decoded->decomposed.operands[2].immediate;
						add_to_stack(&analysis->loader, &self->current_state, imm, ins);
					}
					goto skip_stack_clear;
				}
			}
			int dest = perform_basic_op("add", basic_op_add, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			// check for address-forming idiom
			if (register_is_exactly_known(&self->current_state.registers[dest])) {
				const void *address = (const void *)self->current_state.registers[dest].value;
				struct loaded_binary *binary;
				int prot = protection_for_address(&analysis->loader, address, &binary, NULL);
				if ((prot & PROT_EXEC) && address_is_call_aligned(self->current_state.registers[dest].value)) {
					LOG("formed executable address, assuming it could be called after startup");
					if (*effects & EFFECT_ENTER_CALLS) {
						if (!in_plt_section(binary, ins) && (decoded->decomposed.operands[2].operandClass == IMM32 || decoded->decomposed.operands[2].operandClass == IMM64)) {
							if (!check_for_searched_function(&analysis->loader, address)) {
								queue_instruction(&analysis->search.queue,
								                  address,
								                  ((binary->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_LIBC)) == BINARY_IS_INTERPRETER)
								                      ? required_effects
								                      : ((required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS),
								                  &empty_registers,
								                  self->address,
								                  "adrp+add");
							}
						} else {
							int left = get_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, NULL);
							int right = get_operand(&analysis->loader, &decoded->decomposed.operands[2], &self->current_state, ins, NULL);
							if (left != REGISTER_INVALID && right != REGISTER_INVALID) {
								vary_effects_by_registers(&analysis->search, &analysis->loader, self, mask_for_register(dest), mask_for_register(dest), mask_for_register(dest), 0);
							}
						}
					}
				} else if (prot & PROT_READ) {
					analyze_memory_read(analysis, self, ins, *effects, binary, address);
				}
			}
			goto skip_stack_clear;
		}
		case ARM64_ADDG:
		case ARM64_ADDPT:
			// TODO: determine how to handle checked pointer adds
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ADDHA:
		case ARM64_ADDHN:
		case ARM64_ADDHN2:
		case ARM64_ADDHNB:
		case ARM64_ADDHNT:
		case ARM64_ADDP:
		case ARM64_ADDPL:
		case ARM64_ADDQP:
		case ARM64_ADDQV:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ADDS: {
			int dest = perform_basic_op("adds", basic_op_add, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			clear_comparison_state(&self->current_state);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ADDSPL:
		case ARM64_ADDSUBP:
		case ARM64_ADDSVL:
		case ARM64_ADDV:
		case ARM64_ADDVA:
		case ARM64_ADDVL:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ADR: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			struct register_state source_state;
			read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			LOG("adr ", name_for_register(dest));
			self->current_state.registers[dest] = source_state;
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_ADRP: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			struct register_state source_state;
			read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			LOG("adrp ", name_for_register(dest));
			set_register(&self->current_state.registers[dest], source_state.value & ~(uintptr_t)0xFFF);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_AESD:
		case ARM64_AESDIMC:
		case ARM64_AESE:
		case ARM64_AESEMC:
		case ARM64_AESIMC:
		case ARM64_AESMC:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_AND: {
			int dest = perform_basic_op("and", basic_op_and, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			// hack to represent matches in lower parts of registers
			if (!additional.used) {
				if (decoded->decomposed.operands[2].operandClass == IMM32 || decoded->decomposed.operands[2].operandClass == IMM64) {
					if (decoded->decomposed.operands[2].immediate == 0xff || decoded->decomposed.operands[2].immediate == 0xffff) {
						struct register_state source_state;
						int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
						if (source != REGISTER_INVALID) {
							add_match_and_sources(&analysis->loader, &self->current_state, dest, source, self->current_state.sources[source], ins);
						}
					}
				}
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ANDS: {
			int dest = perform_basic_op("ands", basic_op_and, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			clear_comparison_state(&self->current_state);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ANDQV:
		case ARM64_ANDV:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ASR:
		case ARM64_ASRD:
		case ARM64_ASRR:
		case ARM64_ASRV: {
			int dest = perform_basic_op("asr", basic_op_sar, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_APAS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_AT: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("AT ", name_for_register(dest));
			clear_register(&self->current_state.registers[dest]);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			break;
		}
		case ARM64_AUTIA171615:
		case ARM64_AUTIASPPC:
		case ARM64_AUTIASPPCR:
		case ARM64_AUTIB171615:
		case ARM64_AUTIBSPPC:
		case ARM64_AUTIBSPPCR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_AUTDA:
		case ARM64_AUTDB:
		case ARM64_AUTIA:
		case ARM64_AUTIB: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			if (source == dest) {
				break;
			}
			LOG("autda/autdb to ", name_for_register(dest), " from: ", name_for_register(source));
			add_match_and_sources(&analysis->loader, &self->current_state, dest, source, source == REGISTER_INVALID ? 0 : self->current_state.sources[source], ins);
			self->current_state.registers[dest] = source_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				self->current_state.sources[dest] = 0;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_AUTDZA:
		case ARM64_AUTDZB:
		case ARM64_AUTIZA:
		case ARM64_AUTIZB: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("autz ", name_for_register(dest));
			set_register(&self->current_state.registers[dest], 0);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			break;
		}
		case ARM64_AUTIA1716:
		case ARM64_AUTIB1716:
		case ARM64_AUTIASP:
		case ARM64_AUTIBSP:
		case ARM64_AUTIAZ:
		case ARM64_AUTIBZ: {
			LOG("aut preserve");
			break;
		}
		case ARM64_AXFLAG:
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_B:
		case ARM64_BC:
			// handled in aarch64_decode_jump_instruction
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_BCAX:
		case ARM64_BDEP:
		case ARM64_BEXT:
		case ARM64_BF1CVT:
		case ARM64_BF1CVTL:
		case ARM64_BF1CVTL2:
		case ARM64_BF1CVTLT:
		case ARM64_BF2CVT:
		case ARM64_BF2CVTL:
		case ARM64_BF2CVTL2:
		case ARM64_BF2CVTLT:
		case ARM64_BFADD:
		case ARM64_BFC:
		case ARM64_BFCLAMP:
		case ARM64_BFCVT:
		case ARM64_BFCVTN:
		case ARM64_BFCVTN2:
		case ARM64_BFCVTNT:
		case ARM64_BFDOT:
		case ARM64_BFI:
		case ARM64_BFM:
		case ARM64_BFMAX:
		case ARM64_BFMAXNM:
		case ARM64_BFMIN:
		case ARM64_BFMINNM:
		case ARM64_BFMLA:
		case ARM64_BFMLS:
		case ARM64_BFMLSL:
		case ARM64_BFMLSLB:
		case ARM64_BFMLSLT:
		case ARM64_BFMOP4A:
		case ARM64_BFMOP4S:
		case ARM64_BFMUL:
		case ARM64_BFSCALE:
		case ARM64_BFSUB:
		case ARM64_BFTMOPA:
		case ARM64_BFVDOT:
		case ARM64_BMOPA:
		case ARM64_BMOPS:
			// TODO: implement BFM
		case ARM64_BRB:
		case ARM64_BFMLAL:
		case ARM64_BFMLALB:
		case ARM64_BFMLALT:
		case ARM64_BFMMLA:
		case ARM64_BFMOPA:
		case ARM64_BFMOPS:
		case ARM64_BFXIL:
		case ARM64_BGRP:
		case ARM64_BRKA:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_BRKAS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_BRKB:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_BRKBS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_BRKN:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_BRKNS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_BRKPA:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_BRKPAS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_BRKPB:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_BRKPBS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_BIC: {
			int dest = perform_basic_op("bic", basic_op_unknown, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_BICS: {
			int dest = perform_basic_op("bics", basic_op_unknown, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			clear_comparison_state(&self->current_state);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_BIF:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_BIT: {
			LOG("bit");
			break;
		}
		case ARM64_BL: {
			struct register_state target_state;
			enum ins_operand_size size;
			read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &target_state, &size);
			clear_comparison_state(&self->current_state);
			if (!register_is_exactly_known(&target_state)) {
				UNSUPPORTED_INSTRUCTION();
			}
			ins_ptr dest = (ins_ptr)target_state.value;
			LOG("found bl ", temp_str(copy_function_call_description(&analysis->loader, dest, &self->current_state)));
			if (required_effects & EFFECT_ENTRY_POINT) {
				int main_reg = sysv_argument_abi_register_indexes[0];
				if (register_is_exactly_known(&self->current_state.registers[main_reg]) && binary_for_address(&analysis->loader, (ins_ptr)self->current_state.registers[main_reg].value) != NULL) {
					analysis->main = self->current_state.registers[main_reg].value;
					LOG("bl in init, assuming arg 0 is the main function: ", temp_str(copy_address_description(&analysis->loader, (ins_ptr)analysis->main)));
					self->description = "main";
					struct registers registers = empty_registers;
					analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, (ins_ptr)self->current_state.registers[main_reg].value, self);
				}
				int fini_reg = sysv_argument_abi_register_indexes[4];
				if (register_is_exactly_known(&self->current_state.registers[fini_reg]) && binary_for_address(&analysis->loader, (ins_ptr)self->current_state.registers[fini_reg].value) != NULL) {
					LOG("bl in init, assuming arg 4 is the fini function");
					self->description = "fini";
					struct registers registers = empty_registers;
					analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, (ins_ptr)self->current_state.registers[fini_reg].value, self);
				}
				int rtld_fini_reg = sysv_argument_abi_register_indexes[4];
				if (register_is_exactly_known(&self->current_state.registers[rtld_fini_reg]) && binary_for_address(&analysis->loader, (ins_ptr)self->current_state.registers[rtld_fini_reg].value) != NULL) {
					LOG("bl in init, assuming arg 4 is the rtld_fini function");
					self->description = "rtld_fini";
					struct registers registers = empty_registers;
					analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, (ins_ptr)self->current_state.registers[rtld_fini_reg].value, self);
				}
				// this is __libc_start_main or equivalent
				*effects = (*effects | EFFECT_AFTER_STARTUP) & ~EFFECT_ENTRY_POINT;
				required_effects = (required_effects | EFFECT_AFTER_STARTUP) & ~EFFECT_ENTRY_POINT;
			}
			struct loaded_binary *binary = NULL;
			function_effects more_effects = DEFAULT_EFFECTS;
			if (dest == 0) {
				LOG("found call to NULL, assuming all effects");
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else if ((protection_for_address(&analysis->loader, (void *)dest, &binary, NULL) & PROT_EXEC) == 0) {
				encountered_non_executable_address(&analysis->loader, "call", self, (ins_ptr)dest);
				LOG("found call to non-executable address, assuming all effects");
				*effects |= DEFAULT_EFFECTS;
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else if ((*effects & EFFECT_ENTER_CALLS) == 0) {
				LOG("skipping call when searching for address loads");
				analysis->skipped_call = (ins_ptr)dest;
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else {
				// TODO: see if this works in general
				check_for_searched_function(&analysis->loader, dest);
				self->description = "bl";
				more_effects = analyze_call(analysis, required_effects, binary, ins, dest, self);
				*effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
				LOG("resuming ", temp_str(copy_address_description(&analysis->loader, self->entry)), " from bl ", temp_str(copy_address_description(&analysis->loader, ins)));
				if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
					LOG("completing from call to exit-only function: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					goto update_and_return;
				}
				LOG("function may return, proceeding with effects: ", effects_description(more_effects));
				struct loaded_binary *caller_binary = binary_for_address(&analysis->loader, ins);
				if (caller_binary != NULL) {
					struct frame_details frame;
					if (find_containing_frame_info(&caller_binary->frame_info, ins, &frame)) {
						if ((uintptr_t)frame.address + frame.size <= (uintptr_t)next_ins(ins, &decoded)) {
							LOG("found call to exit-only function not marked exit-only: ", temp_str(copy_address_description(&analysis->loader, ins)));
							goto update_and_return;
						}
					}
				}
			}
			if (more_effects & EFFECT_MODIFIES_STACK) {
				if (is_stack_preserving_function(&analysis->loader, binary, (ins_ptr)dest)) {
					// we should be able to track dirtied slots, but for now assume golang preserves
					// the stack that's read immediately after the call
					LOG("target is stack-preserving function: ", temp_str(copy_address_description(&analysis->loader, ins)));
					self->current_state.stack_address_taken = NULL;
					goto skip_stack_clear;
				} else {
					self->pending_stack_clear = STACK_REGISTERS;
				}
			}
			break;
		}
		case ARM64_BLR:
		case ARM64_BLRAA:
		case ARM64_BLRAAZ:
		case ARM64_BLRAB:
		case ARM64_BLRABZ: {
			enum ins_operand_size size;
			struct register_state target_state;
			clear_comparison_state(&self->current_state);
			int target = read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &target_state, &size);
			self->description = "blr";
			LOG("blr to address in ", name_for_register(target));
			if (target != REGISTER_INVALID) {
#if STORE_LAST_MODIFIED
				if (self->current_state.last_modify_ins[target] != NULL) {
					LOG("last modified at ", temp_str(copy_address_description(&analysis->loader, self->current_state.last_modify_ins[target])));
				}
#endif
				vary_effects_by_registers(&analysis->search, &analysis->loader, self, 0, 0, 0, required_effects);
			}
			struct loaded_binary *binary = NULL;
			function_effects more_effects = DEFAULT_EFFECTS;
			if (!register_is_exactly_known(&target_state)) {
				LOG("address isn't exactly known, assuming all effects");
				// could have any effect
				// effects |= DEFAULT_EFFECTS;
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else if ((*effects & EFFECT_ENTER_CALLS) == 0) {
				LOG("skipping call when searching for address loads");
				analysis->skipped_call = (ins_ptr)target_state.value;
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else {
				ins_ptr dest = (ins_ptr)target_state.value;
				LOG("found blr ", temp_str(copy_function_call_description(&analysis->loader, dest, &self->current_state)));
				if (dest == NULL) {
					LOG("found call to NULL, assuming all effects");
					clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
				} else if ((protection_for_address(&analysis->loader, (void *)dest, &binary, NULL) & PROT_EXEC) == 0) {
					encountered_non_executable_address(&analysis->loader, "call", self, (ins_ptr)dest);
					LOG("found call to non-executable address, assuming all effects");
					*effects |= DEFAULT_EFFECTS;
					clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, (uintptr_t)dest == TLSDESC_ADDR ? mask_for_register(REGISTER_X0) : ALL_REGISTERS);
				} else {
					self->description = "blr";
#if STORE_LAST_MODIFIED
					if (target != REGISTER_INVALID && self->current_state.last_modify_ins[target] != NULL) {
						if (analysis->search.queue.count != 0) {
							// if we are calling an address we just loaded, skip processing it later with no arguments
							uint32_t new_count = analysis->search.queue.count - 1;
							struct queued_instruction *peek = &analysis->search.queue.queue[new_count];
							if (peek->ins == dest && peek->caller == self->current_state.last_modify_ins[target]) {
								analysis->search.queue.count = new_count;
							}
						}
					}
#endif
					more_effects = analyze_call(analysis, required_effects, binary, ins, dest, self);
					*effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
					LOG("resuming ", temp_str(copy_address_description(&analysis->loader, self->entry)), " from blr", temp_str(copy_address_description(&analysis->loader, ins)));
					if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
						LOG("completing from call to exit-only function: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
						goto update_and_return;
					}
					LOG("function may return, proceeding with ", effects_description(more_effects), " effects");
					struct loaded_binary *caller_binary = binary_for_address(&analysis->loader, ins);
					if (caller_binary != NULL) {
						struct frame_details frame;
						if (find_containing_frame_info(&caller_binary->frame_info, ins, &frame)) {
							if ((uintptr_t)frame.address + frame.size <= (uintptr_t)next_ins(ins, &decoded)) {
								LOG("found call to exit-only function not marked exit-only: ", temp_str(copy_address_description(&analysis->loader, ins)));
								goto update_and_return;
							}
						}
					}
				}
			}
			if (more_effects & EFFECT_MODIFIES_STACK) {
				self->pending_stack_clear = STACK_REGISTERS;
			}
			break;
		}
		case ARM64_BR:
		case ARM64_BRAA:
		case ARM64_BRAAZ:
		case ARM64_BRAB:
		case ARM64_BRABZ: {
			struct register_state target_state;
			int target = read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &target_state, NULL);
			self->description = get_operation(&decoded->decomposed);
			LOG("br to address in ", name_for_register(target));
			if (target != REGISTER_INVALID) {
				vary_effects_by_registers(&analysis->search, &analysis->loader, self, mask_for_register(target), self->current_state.requires_known_target & mask_for_register(target), 0, required_effects);
			}
			struct frame_details caller_frame;
			bool allow_jumps_into_the_abyss = (target == REGISTER_INVALID) || ((self->current_state.requires_known_target & mask_for_register(target)) == 0);
			if (!register_is_exactly_known(&target_state)) {
				if (allow_jumps_into_the_abyss) {
					LOG("br to unknown address: ", temp_str(copy_address_description(&analysis->loader, self->address)));
					dump_nonempty_registers(&analysis->loader, &self->current_state, ALL_REGISTERS);
				} else {
					struct loaded_binary *caller_binary = binary_for_address(&analysis->loader, ins);
					if (caller_binary != NULL && caller_binary->has_frame_info && find_containing_frame_info(&caller_binary->frame_info, ins, &caller_frame)) {
						if ((uintptr_t)caller_frame.address + caller_frame.size == (uintptr_t)next_ins(ins, &decoded)) {
							// if last instruction in function, ignore br to unknown address on the assumption that it's a tail call
							*effects |= DEFAULT_EFFECTS;
							goto update_and_return;
						}
					}
					ERROR("br to unknown address: ", temp_str(copy_address_description(&analysis->loader, self->address)));
					self->description = get_operation(&decoded->decomposed);
					DIE("trace: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
				}
				// could have any effect
				*effects |= DEFAULT_EFFECTS;
				LOG("completing from br ", temp_str(copy_address_description(&analysis->loader, self->entry)));
				goto update_and_return;
			}
			ins_ptr new_ins = (ins_ptr)target_state.value;
			struct loaded_binary *call_binary;
			if (new_ins == NULL) {
				LOG("address is known, but only filled at runtime, assuming all effects");
				*effects |= DEFAULT_EFFECTS;
				LOG("completing from br to known, but unfilled address: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			} else if ((protection_for_address(&analysis->loader, new_ins, &call_binary, NULL) & PROT_EXEC) == 0) {
				dump_nonempty_registers(&analysis->loader, &self->current_state, ALL_REGISTERS);
				*effects |= DEFAULT_EFFECTS;
				encountered_non_executable_address(&analysis->loader, get_operation(&decoded->decomposed), self, new_ins);
				LOG("completing from br to non-executable address: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			} else {
				if (!allow_jumps_into_the_abyss && call_binary->has_frame_info) {
					struct loaded_binary *caller_binary = binary_for_address(&analysis->loader, ins);
					if (caller_binary != NULL && caller_binary->has_frame_info) {
						struct frame_details call_frame;
						if (find_containing_frame_info(&call_binary->frame_info, new_ins, &call_frame) && find_containing_frame_info(&caller_binary->frame_info, ins, &caller_frame)) {
							struct searched_instruction_data *data = table_entry_for_token(&analysis->search, self->entry, &self->token)->data;
							if (call_frame.address != caller_frame.address) {
								LOG("jump into a different function from a function that already is jumping into self, ignoring");
								if (data->sticky_effects & EFFECT_STICKY_JUMPS_TO_SELF) {
									// block previously jumped into itself, but now doesn't
									// assume we've read off the end of a jump table and ignore
									*effects |= DEFAULT_EFFECTS;
									goto update_and_return;
								}
							} else {
								// jumping into the same frame, mark block as jumping into itself
								data->sticky_effects |= EFFECT_STICKY_JUMPS_TO_SELF;
							}
						}
					}
				}
				self->description = get_operation(&decoded->decomposed);
				*effects |= analyze_instructions(analysis, required_effects, &self->current_state, new_ins, self, trace_flags) & ~(EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS | EFFECT_PROCESSING);
				LOG("completing from br: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			}
			goto update_and_return;
		}
		case ARM64_BRK: {
			*effects |= EFFECT_EXITS;
			LOG("completing from brk: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			goto update_and_return;
		}
		case ARM64_BSL:
		case ARM64_BSL1N:
		case ARM64_BSL2N:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_BTI: {
			LOG("bti");
			break;
		}
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
		case ARM64_B_AL:
		case ARM64_B_NV:
			// handled in aarch64_decode_jump_instruction
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_CADD:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CBNZ:
			// handled in aarch64_decode_jump_instruction
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_CBZ:
			// handled in aarch64_decode_jump_instruction
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_CDOT:
		case ARM64_CAS:
		case ARM64_CASA:
		case ARM64_CASAL:
		case ARM64_CASALT:
		case ARM64_CASAT:
		case ARM64_CASLT:
		case ARM64_CASL:
		case ARM64_CASB:
		case ARM64_CASAB:
		case ARM64_CASALB:
		case ARM64_CASLB:
		case ARM64_CASH:
		case ARM64_CASAH:
		case ARM64_CASALH:
		case ARM64_CASLH:
		case ARM64_CASPALT:
		case ARM64_CASPAT:
		case ARM64_CASPT:
		case ARM64_CAST:
		case ARM64_CBBEQ:
		case ARM64_CBBGE:
		case ARM64_CBBGT:
		case ARM64_CBBHI:
		case ARM64_CBBHS:
		case ARM64_CBBLE:
		case ARM64_CBBLO:
		case ARM64_CBBLS:
		case ARM64_CBBLT:
		case ARM64_CBBNE:
		case ARM64_CBEQ:
		case ARM64_CBGE:
		case ARM64_CBGT:
		case ARM64_CBHEQ:
		case ARM64_CBHGE:
		case ARM64_CBHGT:
		case ARM64_CBHHI:
		case ARM64_CBHHS:
		case ARM64_CBHI:
		case ARM64_CBHLE:
		case ARM64_CBHLO:
		case ARM64_CBHLS:
		case ARM64_CBHLT:
		case ARM64_CBHNE:
		case ARM64_CBHS:
		case ARM64_CBLE:
		case ARM64_CBLO:
		case ARM64_CBLS:
		case ARM64_CBLT:
		case ARM64_CBNE:
			// compare and store unprivileged
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CASP:
		case ARM64_CASPA:
		case ARM64_CASPAL:
		case ARM64_CASPL:
		case ARM64_CASPLT:
			// TODO: invalidate pair
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CCMN: {
			// TODO
			LOG("ccmn");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CCMP: {
			// TODO
			LOG("ccmp");
			switch (calculate_possible_conditions(&analysis->loader, (enum aarch64_conditional_type)decoded->decomposed.operands[3].cond, &self->current_state)) {
				case ALWAYS_MATCHES: {
					LOG("conditional always matches");
					enum ins_operand_size size;
					struct register_state right_state;
					int left = read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &right_state, &size);
					if (left == REGISTER_INVALID) {
						LOG("ccmp with unsupported operand");
						clear_comparison_state(&self->current_state);
						break;
					}
					int right = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &right_state, NULL);
					truncate_to_operand_size(&right_state, size);
					bool applied_shift = apply_operand_shift(&right_state, &decoded->decomposed.operands[1]);
					LOG("ccmp ", name_for_register(left), " with ", name_for_register(right), " value: ", temp_str(copy_register_state_description(&analysis->loader, right_state)));
					if (applied_shift) {
						clear_comparison_state(&self->current_state);
					} else {
						set_comparison_state(&analysis->loader,
						                     &self->current_state,
						                     (struct register_comparison){
												 .target_register = left,
												 .value = right_state,
												 .mask = mask_for_operand_size(size),
												 .mem_ref = self->current_state.mem_ref,
												 .sources = (right == REGISTER_INVALID ? 0 : self->current_state.sources[right]) | self->current_state.compare_state.sources,
												 .validity = COMPARISON_SUPPORTS_ANY,
											 });
					}
					break;
				}
				case NEVER_MATCHES:
					LOG("conditional never matches");
					clear_comparison_state(&self->current_state);
					break;
				case POSSIBLY_MATCHES:
					LOG("conditional sometimes matches");
					clear_comparison_state(&self->current_state);
					break;
			}
			break;
		}
		case ARM64_CFINV:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CFP:
			// no speculation!
			break;
		case ARM64_CHKFEAT:
			LOG("chkfeat");
			clear_register(&self->current_state.registers[REGISTER_X16]);
			self->current_state.sources[REGISTER_X16] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_X16, ins);
			break;
		case ARM64_CINC:
		case ARM64_CINV:
		case ARM64_CNEG: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			switch (decoded->decomposed.operation) {
				case ARM64_CINC:
					LOG("cinc ", name_for_register(dest));
					break;
				case ARM64_CINV:
					LOG("cinv ", name_for_register(dest));
					break;
				case ARM64_CNEG:
					LOG("cneg ", name_for_register(dest));
					break;
				default:
					break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			if (source != REGISTER_INVALID) {
				LOG("source: ", name_for_register(source));
			}
			truncate_to_operand_size(&source_state, size);
			struct register_state match_state = source_state;
			LOG("value: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			switch (decoded->decomposed.operation) {
				case ARM64_CINC: {
					struct register_state one;
					set_register(&one, 1);
					add_registers(&match_state, &one);
					break;
				}
				case ARM64_CINV: {
					if (register_is_exactly_known(&match_state)) {
						set_register(&match_state, ~(uintptr_t)0 ^ match_state.value);
					} else {
						clear_register(&match_state);
					}
					break;
				}
				case ARM64_CNEG: {
					if (register_is_exactly_known(&match_state)) {
						set_register(&match_state, 0 - match_state.value);
					} else {
						clear_register(&match_state);
					}
					break;
				}
				default:
					break;
			}
			truncate_to_operand_size(&match_state, size);
			LOG("match_state: ", temp_str(copy_register_state_description(&analysis->loader, match_state)));
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			switch (calculate_possible_conditions(&analysis->loader, (enum aarch64_conditional_type)decoded->decomposed.operands[2].cond, &self->current_state)) {
				case ALWAYS_MATCHES:
					LOG("conditional always matches");
					self->current_state.registers[dest] = match_state;
					if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&match_state) : register_is_partially_known_32bit(&match_state)) {
						update_sources_for_basic_op_usage(&self->current_state, dest, source, source, BASIC_OP_USED_LEFT);
						self->current_state.sources[dest] |= self->current_state.compare_state.sources;
					} else {
						self->current_state.sources[dest] = 0;
					}
					break;
				case NEVER_MATCHES:
					LOG("conditional never matches");
					self->current_state.registers[dest] = source_state;
					if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&source_state) : register_is_partially_known_32bit(&source_state)) {
						update_sources_for_basic_op_usage(&self->current_state, dest, source, source, BASIC_OP_USED_RIGHT);
						self->current_state.sources[dest] |= self->current_state.compare_state.sources;
					} else {
						self->current_state.sources[dest] = 0;
					}
					break;
				case POSSIBLY_MATCHES:
					LOG("conditional sometimes matches");
					bool combined = combine_register_states(&match_state, &source_state, dest);
					self->current_state.registers[dest] = match_state;
					dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
					if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&match_state) : register_is_partially_known_32bit(&match_state)) {
						update_sources_for_basic_op_usage(&self->current_state, dest, source, source, combined ? BASIC_OP_USED_BOTH : BASIC_OP_USED_LEFT);
					} else {
						self->current_state.sources[dest] = 0;
					}
					if (!combined) {
						ins = next_ins(ins, decoded);
						ANALYZE_PRIMARY_RESULT();
						self->current_state.registers[dest] = source_state;
						dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
						if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&source_state) : register_is_partially_known_32bit(&source_state)) {
							update_sources_for_basic_op_usage(&self->current_state, dest, source, source, BASIC_OP_USED_RIGHT);
						} else {
							self->current_state.sources[dest] = 0;
						}
						goto use_alternate_result;
					}
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_CLASTA:
		case ARM64_CLASTB:
		case ARM64_CLRBHB:
		case ARM64_COSP:
		case ARM64_CMLA:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CMPP:
			// todo: implement compare discarding tag
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_CNOT:
		case ARM64_CNTP:
		case ARM64_COMPACT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CLREX: {
			LOG("clrex");
			break;
		}
		case ARM64_CLS: {
			int dest = perform_unary_op("cls", unary_op_cls, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_CLZ: {
			int dest = perform_unary_op("clz", unary_op_clz, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_CMEQ: {
			LOG("cmgt");
			break;
		}
		case ARM64_CMGE: {
			LOG("cmge");
			break;
		}
		case ARM64_CMGT: {
			LOG("cmgt");
			break;
		}
		case ARM64_CMHI: {
			LOG("cmhi");
			break;
		}
		case ARM64_CMHS: {
			LOG("cmhs");
			break;
		}
		case ARM64_CMLE: {
			LOG("cmle");
			break;
		}
		case ARM64_CMLT: {
			LOG("cmlt");
			break;
		}
		case ARM64_CMTST: {
			LOG("cmtst");
			break;
		}
		case ARM64_CMN: {
			enum ins_operand_size size;
			int left = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (left == REGISTER_INVALID) {
				LOG("cmn with unsupported operand");
				clear_comparison_state(&self->current_state);
				break;
			}
			struct register_state right_state;
			int right = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &right_state, NULL);
			if (!register_is_exactly_known(&right_state)) {
				LOG("cmn with ranged comparison");
				clear_comparison_state(&self->current_state);
				break;
			}
			set_register(&right_state, -right_state.value);
			truncate_to_operand_size(&right_state, size);
			apply_operand_shift(&right_state, &decoded->decomposed.operands[1]);
			LOG("cmn ", name_for_register(left));
			if (right != REGISTER_INVALID) {
				LOG("with ", name_for_register(right));
			}
			LOG("value is ", temp_str(copy_register_state_description(&analysis->loader, right_state)));
			set_comparison_state(&analysis->loader,
			                     &self->current_state,
			                     (struct register_comparison){
									 .target_register = left,
									 .value = right_state,
									 .mask = mask_for_operand_size(size),
									 .mem_ref = self->current_state.mem_ref,
									 .sources = right == REGISTER_INVALID ? 0 : self->current_state.sources[right],
									 .validity = COMPARISON_SUPPORTS_ANY,
								 });
			break;
		}
		case ARM64_CMP: {
			enum ins_operand_size size;
			struct register_state right_state;
			int left = read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &right_state, &size);
			if (left == REGISTER_INVALID) {
				LOG("cmp with unsupported operand");
				clear_comparison_state(&self->current_state);
				break;
			}
			int right = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &right_state, NULL);
			truncate_to_operand_size(&right_state, size);
			bool applied_shift = apply_operand_shift(&right_state, &decoded->decomposed.operands[1]);
			LOG("cmp ", name_for_register(left));
			if (right != REGISTER_INVALID) {
				LOG("with ", name_for_register(right));
			}
			LOG("value is ", temp_str(copy_register_state_description(&analysis->loader, right_state)));
			if (applied_shift && !register_is_exactly_known(&right_state)) {
				clear_comparison_state(&self->current_state);
			} else {
				set_comparison_state(&analysis->loader,
				                     &self->current_state,
				                     (struct register_comparison){
										 .target_register = left,
										 .value = right_state,
										 .mask = mask_for_operand_size(size),
										 .mem_ref = self->current_state.mem_ref,
										 .sources = right == REGISTER_INVALID ? 0 : self->current_state.sources[right],
										 .validity = COMPARISON_SUPPORTS_ANY,
									 });
			}
			break;
		}
		case ARM64_CMPEQ: {
			// TODO
			LOG("cmpeq");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPGT: {
			// TODO
			LOG("cmpgt");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPGE: {
			// TODO
			LOG("cmpge");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPHI: {
			// TODO
			LOG("cmphi");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPHS: {
			// TODO
			LOG("cmphs");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPLO: {
			// TODO
			LOG("cmplo");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPLS: {
			// TODO
			LOG("cmpls");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPLT: {
			// TODO
			LOG("cmplt");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPLE: {
			// TODO
			LOG("cmple");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CMPNE: {
			// TODO
			LOG("cmpne");
			clear_comparison_state(&self->current_state);
			break;
		}
		case ARM64_CNT: {
			LOG("cnt");
			break;
		}
		case ARM64_CNTB:
		case ARM64_CNTD:
		case ARM64_CNTH:
		case ARM64_CNTW:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CPP:
			// no speculation!
			break;
		case ARM64_CPY:
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_CRC32B:
		case ARM64_CRC32H:
		case ARM64_CRC32W:
		case ARM64_CRC32X:
		case ARM64_CRC32CB:
		case ARM64_CRC32CH:
		case ARM64_CRC32CW:
		case ARM64_CRC32CX:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_CPYE:
		case ARM64_CPYEN:
		case ARM64_CPYERN:
		case ARM64_CPYERT:
		case ARM64_CPYERTN:
		case ARM64_CPYERTRN:
		case ARM64_CPYERTWN:
		case ARM64_CPYET:
		case ARM64_CPYETN:
		case ARM64_CPYETRN:
		case ARM64_CPYETWN:
		case ARM64_CPYEWN:
		case ARM64_CPYEWT:
		case ARM64_CPYEWTN:
		case ARM64_CPYEWTRN:
		case ARM64_CPYEWTWN:
		case ARM64_CPYFE:
		case ARM64_CPYFEN:
		case ARM64_CPYFERN:
		case ARM64_CPYFERT:
		case ARM64_CPYFERTN:
		case ARM64_CPYFERTRN:
		case ARM64_CPYFERTWN:
		case ARM64_CPYFET:
		case ARM64_CPYFETN:
		case ARM64_CPYFETRN:
		case ARM64_CPYFETWN:
		case ARM64_CPYFEWN:
		case ARM64_CPYFEWT:
		case ARM64_CPYFEWTN:
		case ARM64_CPYFEWTRN:
		case ARM64_CPYFEWTWN:
		case ARM64_CPYFM:
		case ARM64_CPYFMN:
		case ARM64_CPYFMRN:
		case ARM64_CPYFMRT:
		case ARM64_CPYFMRTN:
		case ARM64_CPYFMRTRN:
		case ARM64_CPYFMRTWN:
		case ARM64_CPYFMT:
		case ARM64_CPYFMTN:
		case ARM64_CPYFMTRN:
		case ARM64_CPYFMTWN:
		case ARM64_CPYFMWN:
		case ARM64_CPYFMWT:
		case ARM64_CPYFMWTN:
		case ARM64_CPYFMWTRN:
		case ARM64_CPYFMWTWN:
		case ARM64_CPYFP:
		case ARM64_CPYFPN:
		case ARM64_CPYFPRN:
		case ARM64_CPYFPRT:
		case ARM64_CPYFPRTN:
		case ARM64_CPYFPRTRN:
		case ARM64_CPYFPRTWN:
		case ARM64_CPYFPT:
		case ARM64_CPYFPTN:
		case ARM64_CPYFPTRN:
		case ARM64_CPYFPTWN:
		case ARM64_CPYFPWN:
		case ARM64_CPYFPWT:
		case ARM64_CPYFPWTN:
		case ARM64_CPYFPWTRN:
		case ARM64_CPYFPWTWN:
		case ARM64_CPYM:
		case ARM64_CPYMN:
		case ARM64_CPYMRN:
		case ARM64_CPYMRT:
		case ARM64_CPYMRTN:
		case ARM64_CPYMRTRN:
		case ARM64_CPYMRTWN:
		case ARM64_CPYMT:
		case ARM64_CPYMTN:
		case ARM64_CPYMTRN:
		case ARM64_CPYMTWN:
		case ARM64_CPYMWN:
		case ARM64_CPYMWT:
		case ARM64_CPYMWTN:
		case ARM64_CPYMWTRN:
		case ARM64_CPYMWTWN:
		case ARM64_CPYP:
		case ARM64_CPYPN:
		case ARM64_CPYPRN:
		case ARM64_CPYPRT:
		case ARM64_CPYPRTN:
		case ARM64_CPYPRTRN:
		case ARM64_CPYPRTWN:
		case ARM64_CPYPT:
		case ARM64_CPYPTN:
		case ARM64_CPYPTRN:
		case ARM64_CPYPTWN:
		case ARM64_CPYPWN:
		case ARM64_CPYPWT:
		case ARM64_CPYPWTN:
		case ARM64_CPYPWTRN:
		case ARM64_CPYPWTWN:
			// TODO: handle memcpy instructions
		case ARM64_CSDB:
			// no speculation!
			break;
		case ARM64_CSEL:
		case ARM64_CSINC:
		case ARM64_CSINV:
		case ARM64_CSNEG: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			switch (decoded->decomposed.operation) {
				case ARM64_CSEL:
					LOG("csel ", name_for_register(dest));
					break;
				case ARM64_CSINC:
					LOG("csinc ", name_for_register(dest));
					break;
				case ARM64_CSINV:
					LOG("csinv ", name_for_register(dest));
					break;
				case ARM64_CSNEG:
					LOG("csneg ", name_for_register(dest));
					break;
				default:
					break;
			}
			struct register_state left_state;
			int left = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &left_state, NULL);
			if (left != REGISTER_INVALID) {
				LOG("", name_for_register(left), " is left source");
			}
			truncate_to_operand_size(&left_state, size);
			LOG("", temp_str(copy_register_state_description(&analysis->loader, left_state)), " is left value");
			struct register_state right_state;
			int right = read_operand(&analysis->loader, &decoded->decomposed.operands[2], &self->current_state, ins, &right_state, NULL);
			if (right != REGISTER_INVALID) {
				LOG("", name_for_register(right), " is right source");
			}
			switch (decoded->decomposed.operation) {
				case ARM64_CSINC: {
					struct register_state one;
					set_register(&one, 1);
					add_registers(&right_state, &one);
					break;
				}
				case ARM64_CSINV: {
					if (register_is_exactly_known(&right_state)) {
						set_register(&right_state, ~right_state.value);
					} else {
						clear_register(&right_state);
					}
					break;
				}
				case ARM64_CSNEG: {
					if (register_is_exactly_known(&right_state)) {
						set_register(&right_state, -right_state.value);
					} else {
						clear_register(&right_state);
					}
					break;
				}
				default:
					break;
			}
			truncate_to_operand_size(&right_state, size);
			LOG("", temp_str(copy_register_state_description(&analysis->loader, right_state)), " is right");
			enum possible_conditions possibilities = calculate_possible_conditions(&analysis->loader, (enum aarch64_conditional_type)decoded->decomposed.operands[3].cond, &self->current_state);
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			switch (possibilities) {
				case ALWAYS_MATCHES:
					LOG("conditional always matches");
					self->current_state.registers[dest] = left_state;
					if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&left_state) : register_is_partially_known_32bit(&left_state)) {
						update_sources_for_basic_op_usage(&self->current_state, dest, left, right, BASIC_OP_USED_LEFT);
						self->current_state.sources[dest] |= self->current_state.compare_state.sources;
					} else {
						self->current_state.sources[dest] = 0;
					}
					break;
				case NEVER_MATCHES:
					LOG("conditional never matches");
					self->current_state.registers[dest] = right_state;
					if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&right_state) : register_is_partially_known_32bit(&right_state)) {
						update_sources_for_basic_op_usage(&self->current_state, dest, left, right, BASIC_OP_USED_RIGHT);
						self->current_state.sources[dest] |= self->current_state.compare_state.sources;
					} else {
						self->current_state.sources[dest] = 0;
					}
					break;
				case POSSIBLY_MATCHES:
					LOG("conditional sometimes matches");
					bool combined = combine_register_states(&left_state, &right_state, dest);
					self->current_state.registers[dest] = left_state;
					dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
					if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&left_state) : register_is_partially_known_32bit(&left_state)) {
						update_sources_for_basic_op_usage(&self->current_state, dest, left, right, combined ? BASIC_OP_USED_BOTH : BASIC_OP_USED_LEFT);
					} else {
						self->current_state.sources[dest] = 0;
					}
					if (!combined) {
						ins = next_ins(ins, decoded);
						ANALYZE_PRIMARY_RESULT();
						self->current_state.registers[dest] = right_state;
						dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
						if (size == OPERATION_SIZE_DWORD ? register_is_partially_known(&right_state) : register_is_partially_known_32bit(&right_state)) {
							update_sources_for_basic_op_usage(&self->current_state, dest, left, right, BASIC_OP_USED_RIGHT);
						} else {
							self->current_state.sources[dest] = 0;
						}
						goto use_alternate_result;
					}
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_CSET: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("cset ", name_for_register(dest));
			switch (calculate_possible_conditions(&analysis->loader, (enum aarch64_conditional_type)decoded->decomposed.operands[1].cond, &self->current_state)) {
				case ALWAYS_MATCHES:
					LOG("conditional always matches");
					self->current_state.registers[dest].value = 1;
					self->current_state.registers[dest].max = 1;
					self->current_state.sources[dest] = self->current_state.compare_state.sources;
					break;
				case NEVER_MATCHES:
					LOG("conditional never matches");
					self->current_state.registers[dest].value = 0;
					self->current_state.registers[dest].max = 0;
					self->current_state.sources[dest] = self->current_state.compare_state.sources;
					break;
				case POSSIBLY_MATCHES:
					LOG("conditional sometimes matches");
					self->current_state.registers[dest].value = 0;
					self->current_state.registers[dest].max = 1;
					self->current_state.sources[dest] = 0;
					break;
			}
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_CSETM: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("csetm ", name_for_register(dest));
			enum possible_conditions possibilities = calculate_possible_conditions(&analysis->loader, (enum aarch64_conditional_type)decoded->decomposed.operands[1].cond, &self->current_state);
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			switch (possibilities) {
				case ALWAYS_MATCHES:
					LOG("conditional always matches");
					set_register(&self->current_state.registers[dest], mask_for_operand_size(size));
					self->current_state.sources[dest] = self->current_state.compare_state.sources;
					break;
				case NEVER_MATCHES:
					LOG("conditional never matches");
					set_register(&self->current_state.registers[dest], 0);
					self->current_state.sources[dest] = self->current_state.compare_state.sources;
					break;
				case POSSIBLY_MATCHES:
					LOG("conditional sometimes matches");
					self->current_state.sources[dest] = 0;
					set_register(&self->current_state.registers[dest], mask_for_operand_size(size));
					ins = next_ins(ins, decoded);
					ANALYZE_PRIMARY_RESULT();
					set_register(&self->current_state.registers[dest], 0);
					goto use_alternate_result;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_CTERMEQ:
		case ARM64_CTERMNE:
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_CTZ:
			LOG("ctz");
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_DC:
			LOG("dc");
			break;
		case ARM64_DCPS1:
			LOG("dcps1");
			break;
		case ARM64_DCPS2:
			LOG("dcps2");
			break;
		case ARM64_DCPS3:
			LOG("dcps3");
			break;
		case ARM64_DECB:
		case ARM64_DECD:
		case ARM64_DECH:
		case ARM64_DECP:
		case ARM64_DECW:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_DGH:
			// no speculation!
			break;
		case ARM64_DMB:
			LOG("dmb");
			break;
		case ARM64_DRPS:
			LOG("drps");
			break;
		case ARM64_DSB:
			// no speculation!
			break;
		case ARM64_DUP:
		case ARM64_DUPM:
		case ARM64_DUPQ:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_DVP:
			// no speculation!
			break;
		case ARM64_EON:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_EOR: {
			int dest = perform_basic_op("eor", basic_op_xor, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_EORS: {
			int dest = perform_basic_op("eor", basic_op_xor, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			clear_comparison_state(&self->current_state);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_EOR3:
		case ARM64_EORBT:
		case ARM64_EORQV:
		case ARM64_EORTB:
		case ARM64_EORV:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ERET:
		case ARM64_ERETAA:
		case ARM64_ERETAB:
			// handled in aarch64_decode_jump_instruction
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_ESB:
			// no speculation!
			break;
		case ARM64_EXPAND:
		case ARM64_EXT:
		case ARM64_EXTQ:
		case ARM64_EXTR:
		case ARM64_F1CVT:
		case ARM64_F1CVTL:
		case ARM64_F1CVTL2:
		case ARM64_F1CVTLT:
		case ARM64_F2CVT:
		case ARM64_F2CVTL:
		case ARM64_F2CVTL2:
		case ARM64_F2CVTLT:
		case ARM64_FABD:
		case ARM64_FABS:
		case ARM64_FACGE:
		case ARM64_FACGT:
		case ARM64_FACLE:
		case ARM64_FACLT:
		case ARM64_FADD:
		case ARM64_FADDA:
		case ARM64_FADDQV:
		case ARM64_FADDP:
		case ARM64_FADDV:
		case ARM64_FAMAX:
		case ARM64_FAMIN:
		case ARM64_FCADD:
		case ARM64_FCLAMP:
		case ARM64_FCMLA:
		case ARM64_FCMNE:
		case ARM64_FCMUO:
		case ARM64_FCPY:
		case ARM64_FCVTL:
		case ARM64_FCVTL2:
		case ARM64_FCVTLT:
		case ARM64_FCVTN:
		case ARM64_FCVTN2:
		case ARM64_FCVTNS:
		case ARM64_FCVTNT:
		case ARM64_FCVTNU:
		case ARM64_FCVTX:
		case ARM64_FCVTXN:
		case ARM64_FCVTXN2:
		case ARM64_FCVTXNT:
		case ARM64_FCVTNB:
		case ARM64_FCVTZSN:
		case ARM64_FCVTZUN:
		case ARM64_FDOT:
		case ARM64_FIRSTP:
		case ARM64_FMAXNMQV:
		case ARM64_FMAXQV:
		case ARM64_FMINNMQV:
		case ARM64_FMINQV:
		case ARM64_FMLALL:
		case ARM64_FMLALLBB:
		case ARM64_FMLALLBT:
		case ARM64_FMLALLTB:
		case ARM64_FMLALLTT:
		case ARM64_FMOP4A:
		case ARM64_FMOP4S:
		case ARM64_FTMOPA:
		case ARM64_FVDOT:
		case ARM64_FVDOTB:
		case ARM64_FVDOTT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_FCCMP:
			LOG("fccmp");
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_FCCMPE:
			LOG("fccmpe");
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_FCMEQ:
		case ARM64_FCMGE:
		case ARM64_FCMGT:
		case ARM64_FCMLE:
		case ARM64_FCMLT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_FCMP:
			LOG("fcmp");
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_FCMPE:
			LOG("fcmpe");
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_FCSEL:
			LOG("fcsel");
			break;
		case ARM64_FCVT:
		case ARM64_FCVTAS:
		case ARM64_FCVTAU:
		case ARM64_FCVTMS:
		case ARM64_FCVTMU:
		case ARM64_FCVTPS:
		case ARM64_FCVTPU:
		case ARM64_FCVTZS:
		case ARM64_FCVTZU:
		case ARM64_FDIV:
		case ARM64_FDIVR:
		case ARM64_FDUP:
		case ARM64_FEXPA:
		case ARM64_FJCVTZS:
		case ARM64_FLOGB:
		case ARM64_FMAD:
		case ARM64_FMADD:
		case ARM64_FMAX:
		case ARM64_FMAXNM:
		case ARM64_FMAXNMP:
		case ARM64_FMAXNMV:
		case ARM64_FMAXP:
		case ARM64_FMAXV:
		case ARM64_FMIN:
		case ARM64_FMINNM:
		case ARM64_FMINNMP:
		case ARM64_FMINNMV:
		case ARM64_FMINP:
		case ARM64_FMINV:
		case ARM64_FMLA:
		case ARM64_FMLAL:
		case ARM64_FMLAL2:
		case ARM64_FMLALB:
		case ARM64_FMLALT:
		case ARM64_FMLS:
		case ARM64_FMLSL:
		case ARM64_FMLSL2:
		case ARM64_FMLSLB:
		case ARM64_FMLSLT:
		case ARM64_FMMLA:
		case ARM64_FMOPA:
		case ARM64_FMOPS:
		case ARM64_FMSB:
		case ARM64_FMOV:
		case ARM64_FMUL:
		case ARM64_FMULX:
		case ARM64_FMSUB:
		case ARM64_FNEG:
		case ARM64_FNMAD:
		case ARM64_FNMADD:
		case ARM64_FNMLA:
		case ARM64_FNMLS:
		case ARM64_FNMSB:
		case ARM64_FNMSUB:
		case ARM64_FNMUL:
		case ARM64_FRECPE:
		case ARM64_FRECPS:
		case ARM64_FRECPX:
		case ARM64_FRINT32X:
		case ARM64_FRINT32Z:
		case ARM64_FRINT64X:
		case ARM64_FRINT64Z:
		case ARM64_FRINTA:
		case ARM64_FRINTI:
		case ARM64_FRINTN:
		case ARM64_FRINTM:
		case ARM64_FRINTP:
		case ARM64_FRINTX:
		case ARM64_FRINTZ:
		case ARM64_FRSQRTE:
		case ARM64_FRSQRTS:
		case ARM64_FSCALE:
		case ARM64_FSUB:
		case ARM64_FSUBR:
		case ARM64_FSQRT:
		case ARM64_FTMAD:
		case ARM64_FTSMUL:
		case ARM64_FTSSEL:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_GIC:
		case ARM64_GICR:
		case ARM64_GSB:
			// generic interrupt controller
			break;
		case ARM64_GCSB:
		case ARM64_GCSPUSHM:
		case ARM64_GCSPUSHX:
			// guarded control stack
			break;
		case ARM64_GCSPOPCX:
		case ARM64_GCSPOPX:
		case ARM64_GCSPOPM:
			// guarded control stack pop
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_GCSSS1:
		case ARM64_GCSSS2:
		case ARM64_GCSSTR:
		case ARM64_GCSSTTR:
			// guarded control stack
			break;
		case ARM64_HISTCNT:
		case ARM64_HISTSEG:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_HVC:
			// invalid in userland
			*effects |= EFFECT_EXITS;
			LOG("completing from hvc: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			goto update_and_return;
		case ARM64_INCP:
		case ARM64_INSR:
		case ARM64_GMI:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_HINT: {
			LOG("hint");
			break;
		}
		case ARM64_HLT: {
			*effects |= EFFECT_EXITS;
			LOG("completing from hlt: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			goto update_and_return;
		}
		case ARM64_IC:
		case ARM64_INCB:
		case ARM64_INCD:
		case ARM64_INCH:
		case ARM64_INCW:
		case ARM64_INDEX:
		case ARM64_INS:
		case ARM64_IRG:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ISB: {
			LOG("isb");
			break;
		}
		case ARM64_LASTA:
		case ARM64_LASTB:
		case ARM64_LASTP:
		case ARM64_LD1:
		case ARM64_LD1B:
		case ARM64_LD1D:
		case ARM64_LD1H:
		case ARM64_LD1Q:
		case ARM64_LD1R:
		case ARM64_LD1RB:
		case ARM64_LD1RD:
		case ARM64_LD1RH:
		case ARM64_LD1ROB:
		case ARM64_LD1ROD:
		case ARM64_LD1ROH:
		case ARM64_LD1ROW:
		case ARM64_LD1RQB:
		case ARM64_LD1RQD:
		case ARM64_LD1RQH:
		case ARM64_LD1RQW:
		case ARM64_LD1RSB:
		case ARM64_LD1RSH:
		case ARM64_LD1RSW:
		case ARM64_LD1RW:
		case ARM64_LD1SB:
		case ARM64_LD1SH:
		case ARM64_LD1SW:
		case ARM64_LD1W:
		case ARM64_LD2:
		case ARM64_LD2B:
		case ARM64_LD2D:
		case ARM64_LD2H:
		case ARM64_LD2Q:
		case ARM64_LD2R:
		case ARM64_LD2W:
		case ARM64_LD3:
		case ARM64_LD3B:
		case ARM64_LD3D:
		case ARM64_LD3H:
		case ARM64_LD3Q:
		case ARM64_LD3R:
		case ARM64_LD3W:
		case ARM64_LD4:
		case ARM64_LD4B:
		case ARM64_LD4D:
		case ARM64_LD4H:
		case ARM64_LD4Q:
		case ARM64_LD4R:
		case ARM64_LD4W:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_LDBFADD:
		case ARM64_LDBFADDA:
		case ARM64_LDBFADDAL:
		case ARM64_LDBFADDL:
		case ARM64_LDBFMAX:
		case ARM64_LDBFMAXA:
		case ARM64_LDBFMAXAL:
		case ARM64_LDBFMAXL:
		case ARM64_LDBFMAXNM:
		case ARM64_LDBFMAXNMA:
		case ARM64_LDBFMAXNMAL:
		case ARM64_LDBFMAXNML:
		case ARM64_LDBFMIN:
		case ARM64_LDBFMINA:
		case ARM64_LDBFMINAL:
		case ARM64_LDBFMINL:
		case ARM64_LDBFMINNM:
		case ARM64_LDBFMINNMA:
		case ARM64_LDBFMINNMAL:
		case ARM64_LDBFMINNML:
		case ARM64_LDFADD:
		case ARM64_LDFADDA:
		case ARM64_LDFADDAL:
		case ARM64_LDFADDL:
		case ARM64_LDFMAX:
		case ARM64_LDFMAXA:
		case ARM64_LDFMAXAL:
		case ARM64_LDFMAXL:
		case ARM64_LDFMAXNM:
		case ARM64_LDFMAXNMA:
		case ARM64_LDFMAXNMAL:
		case ARM64_LDFMAXNML:
		case ARM64_LDFMIN:
		case ARM64_LDFMINA:
		case ARM64_LDFMINAL:
		case ARM64_LDFMINL:
		case ARM64_LDFMINNM:
		case ARM64_LDFMINNMA:
		case ARM64_LDFMINNMAL:
		case ARM64_LDFMINNML:
			// atomic float/bfloat loads
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_LD64B:
			DIE("ld64b instruction is not supported: ", temp_str(copy_address_description(&analysis->loader, ins)));
			break;
		case ARM64_LDFF1B:
		case ARM64_LDFF1D:
		case ARM64_LDFF1H:
		case ARM64_LDFF1SB:
		case ARM64_LDFF1SH:
		case ARM64_LDFF1SW:
		case ARM64_LDFF1W:
		case ARM64_LDGM:
		case ARM64_LDNF1B:
		case ARM64_LDNF1D:
		case ARM64_LDNF1H:
		case ARM64_LDNF1SB:
		case ARM64_LDNF1SH:
		case ARM64_LDNF1SW:
		case ARM64_LDNF1W:
		case ARM64_LDNT1B:
		case ARM64_LDNT1D:
		case ARM64_LDNT1H:
		case ARM64_LDNT1SB:
		case ARM64_LDNT1SH:
		case ARM64_LDNT1SW:
		case ARM64_LDNT1W:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_LDAXP: {
			// TODO: handle LDAXP correctly
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		}
		case ARM64_LDAP1:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_LDIAPP:
		case ARM64_LDAPP:
		case ARM64_LDAP:
		case ARM64_LDPSW:
		case ARM64_LDNP:
		case ARM64_LDP:
		case ARM64_LDTP:
		case ARM64_LDTNP:
		case ARM64_LDXP: {
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[2], &self->current_state, ins, &source_state, NULL);
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			int dest2 = get_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &size);
			if (decoded->decomposed.operation == ARM64_LDPSW) {
				truncate_to_operand_size(&source_state, OPERATION_SIZE_WORD);
				sign_extend_from_operand_size(&source_state, OPERATION_SIZE_WORD);
			} else {
				truncate_to_operand_size(&source_state, size);
			}
			LOG("ldp to ", name_for_register(dest), " and ", name_for_register(dest2), " from ", name_for_register(source));
			if (dest != REGISTER_INVALID) {
				if (source != REGISTER_INVALID) {
					add_match_and_sources(&analysis->loader, &self->current_state, dest, source, self->current_state.sources[source], ins);
					self->current_state.registers[dest] = source_state;
					if (register_is_partially_known(&source_state)) {
						LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
					} else {
						LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
						self->current_state.sources[dest] = 0;
					}
				} else {
					LOG("not on the stack");
					clear_register(&self->current_state.registers[dest]);
					truncate_to_operand_size(&self->current_state.registers[dest], size);
					self->current_state.sources[dest] = 0;
					clear_match(&analysis->loader, &self->current_state, dest, ins);
					dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
				}
			}
			if (dest2 != REGISTER_INVALID) {
				if (source != REGISTER_INVALID && (mask_for_register(source) & (STACK_REGISTERS & (STACK_REGISTERS >> 1))) && decoded->decomposed.operation == ARM64_LDP && size == OPERATION_SIZE_DWORD) {
					int source2 = source + 1;
					LOG("loading second value from stack: ", name_for_register(source2));
					source_state = self->current_state.registers[source2];
					add_match_and_sources(&analysis->loader, &self->current_state, dest2, source2, self->current_state.sources[source2], ins);
					self->current_state.registers[dest2] = source_state;
					if (register_is_partially_known(&source_state)) {
						LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
					} else {
						LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
						self->current_state.sources[dest2] = 0;
					}
				} else {
					LOG("second source not on the stack");
					clear_register(&self->current_state.registers[dest2]);
					truncate_to_operand_size(&self->current_state.registers[dest2], size);
					self->current_state.sources[dest2] = 0;
					clear_match(&analysis->loader, &self->current_state, dest2, ins);
					dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest2));
				}
			}
			break;
		}
		case ARM64_LDADD:
		case ARM64_LDADDA:
		case ARM64_LDADDAL:
		case ARM64_LDADDL:
		case ARM64_LDADDB:
		case ARM64_LDADDAB:
		case ARM64_LDADDALB:
		case ARM64_LDADDLB:
		case ARM64_LDADDH:
		case ARM64_LDADDAH:
		case ARM64_LDADDALH:
		case ARM64_LDADDLH:
		case ARM64_LDTADD:
		case ARM64_LDTADDA:
		case ARM64_LDTADDAL:
		case ARM64_LDTADDL: {
			LOG("ldadd*");
			enum ins_operand_size size;
			int loaded = get_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &size);
			if (loaded == REGISTER_INVALID) {
				break;
			}
			self->current_state.registers[loaded].value = 0;
			self->current_state.registers[loaded].max = mask_for_operand_size(size);
			self->current_state.sources[loaded] = 0;
			clear_match(&analysis->loader, &self->current_state, loaded, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(loaded));
			goto skip_stack_clear;
		}
		case ARM64_LDAPR:
		case ARM64_LDAPRB:
		case ARM64_LDAPRH:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_LDAPUR:
		case ARM64_LDAPURB:
		case ARM64_LDAPURH:
		case ARM64_LDAPURSB:
		case ARM64_LDAPURSH:
		case ARM64_LDAPURSW:
		case ARM64_LDAR:
		case ARM64_LDARB:
		case ARM64_LDARH:
		case ARM64_LDAXR:
		case ARM64_LDAXRB:
		case ARM64_LDAXRH:
		case ARM64_LDLAR:
		case ARM64_LDLARB:
		case ARM64_LDLARH:
		case ARM64_LDR:
		case ARM64_LDRAA:
		case ARM64_LDRAB:
		case ARM64_LDRB:
		case ARM64_LDRH:
		case ARM64_LDRSB:
		case ARM64_LDRSH:
		case ARM64_LDRSW:
		case ARM64_LDATXR:
		case ARM64_LDTXR:
		case ARM64_LDXR:
		case ARM64_LDXRB:
		case ARM64_LDXRH: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			enum ins_operand_size mem_size;
			bool is_signed = false;
			switch (decoded->decomposed.operation) {
				case ARM64_LDAPURB:
				case ARM64_LDAPURSB:
				case ARM64_LDRSB:
					is_signed = true;
					// fallthrough
				case ARM64_LDARB:
				case ARM64_LDAXRB:
				case ARM64_LDLARB:
				case ARM64_LDRB:
				case ARM64_LDXRB:
					mem_size = OPERATION_SIZE_BYTE;
					break;
				case ARM64_LDAPURH:
				case ARM64_LDAPURSH:
				case ARM64_LDRSH:
					is_signed = true;
					// fallthrough
				case ARM64_LDARH:
				case ARM64_LDAXRH:
				case ARM64_LDLARH:
				case ARM64_LDRH:
				case ARM64_LDXRH:
					mem_size = OPERATION_SIZE_HALF;
					break;
				case ARM64_LDAPURSW:
				case ARM64_LDRSW:
					is_signed = true;
					mem_size = OPERATION_SIZE_WORD;
					break;
				default:
					mem_size = size;
					break;
			}
			LOG("ldr ", name_for_register(dest));
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, &size);
			if (source != REGISTER_INVALID) {
				LOG("from ", name_for_register(source));
				add_match_and_sources(&analysis->loader, &self->current_state, dest, source, self->current_state.sources[source], ins);
				truncate_to_operand_size(&source_state, mem_size);
				if (is_signed) {
					sign_extend_from_operand_size(&source_state, mem_size);
				}
				truncate_to_operand_size(&source_state, size);
				self->current_state.registers[dest] = source_state;
				if (register_is_partially_known(&source_state)) {
					LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				} else {
					LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
					self->current_state.sources[dest] = 0;
				}
				dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest) | mask_for_register(source));
				self->pending_stack_clear &= ~mask_for_register(dest);
				goto skip_stack_clear;
			}
			int reg = register_index_from_register(decoded->decomposed.operands[1].reg[0]);
			if (reg == REGISTER_INVALID) {
				LOG("invalid source, clearing register");
				goto clear_ldr;
			}
			LOG("base of ", name_for_register(reg));
			register_mask dump_mask = mask_for_register(dest) | mask_for_register(reg);
			if (SHOULD_LOG) {
				for_each_bit (self->current_state.matches[reg], bit, i) {
					ERROR_NOPREFIX("matching", name_for_register(i));
				}
			}
			source_state = self->current_state.registers[reg];
			register_mask used_registers = self->current_state.sources[reg];
			bool requires_known_target = false;
			switch (decoded->decomposed.operands[1].operandClass) {
				case MEM_REG: {
					LOG("no offset");
					break;
				}
				case MEM_OFFSET: {
					struct register_state imm;
					set_register(&imm, decoded->decomposed.operands[1].immediate);
					add_registers(&source_state, &imm);
					LOG("offset of ", imm.value);
					break;
				}
				case MEM_PRE_IDX: {
					LOG("preindex of ", (uintptr_t)decoded->decomposed.operands[1].immediate);
					// indexing already made in read_operand
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case MEM_POST_IDX: {
					LOG("postindex of ", (uintptr_t)decoded->decomposed.operands[1].immediate);
					// subtract the indexing made in read_operand out for the base value
					struct register_state imm;
					set_register(&imm, -decoded->decomposed.operands[1].immediate);
					add_registers(&source_state, &imm);
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case MEM_EXTENDED: {
					int index = register_index_from_register(decoded->decomposed.operands[1].reg[1]);
					if (index == REGISTER_INVALID) {
						LOG("invalid extended index, clearing register");
						goto clear_ldr;
					}
					dump_mask |= mask_for_register(index);
					LOG("extended ", name_for_register(index));
					if (SHOULD_LOG) {
						for_each_bit (self->current_state.matches[index], bit, i) {
							ERROR_NOPREFIX("matching", name_for_register(i));
						}
					}
					used_registers |= self->current_state.sources[index];
					struct register_state index_state = self->current_state.registers[index];
					struct loaded_binary *binary;
					const ElfW(Shdr) * section;
					uintptr_t base_addr = 0;
					if (register_is_exactly_known(&source_state)) {
						base_addr = source_state.value;
						LOG("storing base address: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
						add_lookup_table_base_address(&analysis->search.lookup_base_addresses, ins, base_addr);
					}
					struct registers copy = self->current_state;
					if (base_addr == 0) {
						base_addr = find_lookup_table_base_address(&analysis->search.lookup_base_addresses, ins);
						if (base_addr != 0) {
							if (false) {
								LOG("reusing previous base address: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
							} else {
								LOG("missing base address for lookup table that previously had a base address, skipping");
								goto update_and_return;
							}
						}
						set_register(&copy.registers[reg], base_addr);
						clear_match(&analysis->loader, &copy, reg, ins);
						copy.sources[reg] = 0;
						clear_match(&analysis->loader, &self->current_state, reg, ins);
						self->current_state.sources[reg] = 0;
					}
					if (trace_flags < TRACE_MEMORY_LOAD_RECURSION_LIMIT && base_addr != 0) {
						ins_ptr lookahead = next_ins(ins, &decoded);
						struct decoded_ins lookahead_decoded;
						if (decode_ins(lookahead, &lookahead_decoded) && lookahead_decoded.decomposed.operation == decoded->decomposed.operation) {
							trace_flags |= TRACE_MEMORY_LOAD_RECURSION_LIMIT;
							goto cancel_lookup_table;
						}
						dump_registers(&analysis->loader, &self->current_state, dump_mask);
						LOG("looking up protection for base: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
						int prot = protection_for_address(&analysis->loader, (const void *)base_addr, &binary, &section);
						if ((prot & (PROT_READ | PROT_WRITE)) == PROT_READ) {
							if (index_state.max - index_state.value > MAX_LOOKUP_TABLE_SIZE) {
								LOG("lookup table rejected because range of index is too large: ", index_state.max - index_state.value);
								dump_registers(&analysis->loader, &self->current_state, mask_for_register(reg) | mask_for_register(index));
								self->description = "rejected lookup table";
								LOG("trace: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
								if (decoded->decomposed.operation != ARM64_LDR) {
									requires_known_target = true;
								}
								*effects |= EFFECT_RETURNS;
							} else {
								self->description = "lookup table";
								vary_effects_by_registers(&analysis->search,
								                          &analysis->loader,
								                          self,
								                          mask_for_register(reg) | mask_for_register(index),
								                          mask_for_register(reg) | mask_for_register(index),
								                          mask_for_register(reg) /* | mask_for_register(index)*/,
								                          required_effects);
								LOG("lookup table from known base: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
								dump_registers(&analysis->loader, &self->current_state, mask_for_register(reg) | mask_for_register(index));
								// enforce max range from other ldr instructions
								uintptr_t next_base_address = search_find_next_address(&analysis->search.loaded_addresses, base_addr);
								uintptr_t last_base_index = ((next_base_address - base_addr) >> decoded->decomposed.operands[1].shiftValue) - 1;
								if (last_base_index < index_state.max) {
									LOG("truncating to next base address of ", temp_str(copy_address_description(&analysis->loader, (const void *)next_base_address)), " for range ", temp_str(copy_register_state_description(&analysis->loader, index_state)));
									index_state.max = last_base_index;
									LOG("new range is ", temp_str(copy_register_state_description(&analysis->loader, index_state)));
								}
								uintptr_t last_in_section = (((uintptr_t)apply_base_address(&binary->info, section->sh_addr) + section->sh_size - base_addr) >> decoded->decomposed.operands[1].shiftValue) - 1;
								if (index_state.max > last_in_section) {
									index_state.max = last_in_section;
									LOG("truncating to new maximum of ", temp_str(copy_register_state_description(&analysis->loader, index_state)));
									if (index_state.value > last_in_section) {
										LOG("somehow in a jump table without a proper value, bailing");
										goto update_and_return;
									}
								}
								copy.sources[dest] = used_registers;
								clear_match(&analysis->loader, &copy, dest, ins);
								if (decoded->decomposed.operation != ARM64_LDR) {
									copy.requires_known_target |= mask_for_register(dest);
								}
								ins_ptr continue_target = next_ins(ins, &decoded);
								for (uintptr_t i = index_state.value; i <= index_state.max; i++) {
									LOG("processing table index of ", (intptr_t)i);
									struct register_state index_single_state;
									set_register(&index_single_state, i);
									apply_operand_shift(&index_single_state, &decoded->decomposed.operands[1]);
									struct register_state source_single_state;
									set_register(&source_single_state, base_addr);
									add_registers(&source_single_state, &index_single_state);
									if (!register_is_exactly_known(&source_single_state)) {
										DIE("expected table entry address to be exactly known: ", (intptr_t)i);
									}
									if (index != dest) {
										set_register(&copy.registers[index], i);
										for_each_bit (copy.matches[index], bit, r) {
											set_register(&copy.registers[r], i);
										}
									}
									uintptr_t value = is_signed ? (uintptr_t)read_memory_signed((const void *)source_single_state.value, mem_size) : read_memory((const void *)source_single_state.value, mem_size);
									set_register(&copy.registers[dest], value);
									if (is_signed) {
										LOG("processing table value: ", (intptr_t)value);
									} else {
										LOG("processing table value: ", value);
									}
									truncate_to_operand_size(&copy.registers[dest], size);
									if (mem_size == OPERATION_SIZE_DWORD && (protection_for_address(&analysis->loader, (ins_ptr)value, &binary, NULL) & PROT_EXEC) == 0) {
										LOG("discovered non-executable address, cancelling lookup table: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
										goto cancel_lookup_table;
									}
									*effects |=
										analyze_instructions(analysis, required_effects, &copy, continue_target, self, trace_flags + TRACE_MEMORY_LOAD_RECURSION_STEP) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
									LOG("next table case for ", temp_str(copy_address_description(&analysis->loader, self->address)));
									// re-enforce max range from other lea instructions that may have loaded addresses in the meantime
									next_base_address = search_find_next_address(&analysis->search.loaded_addresses, base_addr);
									last_base_index = ((next_base_address - base_addr) >> decoded->decomposed.operands[1].shiftValue) - 1;
									if (last_base_index < index_state.max) {
										LOG("truncating to next base address of ", temp_str(copy_address_description(&analysis->loader, (const void *)next_base_address)), " for range ", temp_str(copy_register_state_description(&analysis->loader, index_state)));
										index_state.max = last_base_index;
										LOG("new range is ", temp_str(copy_register_state_description(&analysis->loader, index_state)));
									}
								}
								LOG("completing from lookup table: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
								goto update_and_return;
							}
						}
					}
				cancel_lookup_table:
					apply_operand_shift(&index_state, &decoded->decomposed.operands[1]);
					add_registers(&source_state, &index_state);
					break;
				}
				default:
					LOG("invalid operand class ", (intptr_t)decoded->decomposed.operands[1].operandClass, ", clearing register");
					goto clear_ldr;
			}
			if (register_is_exactly_known(&source_state)) {
				uintptr_t addr = source_state.value;
				if (addr < 4096) {
					LOG("exiting because memory read from NULL");
					vary_effects_by_registers(&analysis->search, &analysis->loader, self, used_registers, 0, 0, required_effects);
					*effects = (*effects | EFFECT_EXITS) & ~EFFECT_RETURNS;
					goto update_and_return;
				}
				struct loaded_binary *binary;
				int prot = protection_for_address(&analysis->loader, (const void *)addr, &binary, NULL);
				if (prot & PROT_READ) {
					uintptr_t value = is_signed ? (uintptr_t)read_memory_signed((const void *)addr, mem_size) : read_memory((const void *)addr, mem_size);
					if ((prot & PROT_WRITE) == 0 || (value == SYS_fcntl && (binary->special_binary_flags & BINARY_IS_GOLANG))) { // workaround for golang's syscall.fcntl64Syscall
						dump_registers(&analysis->loader, &self->current_state, dump_mask);
						set_register(&self->current_state.registers[dest], value);
						truncate_to_operand_size(&self->current_state.registers[dest], size);
						self->current_state.sources[dest] = used_registers;
						LOG("loaded memory constant ", temp_str(copy_register_state_description(&analysis->loader, self->current_state.registers[dest])), " from ", temp_str(copy_address_description(&analysis->loader, (const void *)addr)));
						clear_match(&analysis->loader, &self->current_state, dest, ins);
						dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
						if (mem_size == OPERATION_SIZE_DWORD && !is_signed && address_is_call_aligned(value) && !in_plt_section(binary, ins)) {
							prot = protection_for_address(&analysis->loader, (const void *)value, &binary, NULL);
							if ((prot & PROT_EXEC) && (*effects & EFFECT_ENTER_CALLS)) {
								LOG("found reference to executable address: ", temp_str(copy_address_description(&analysis->loader, (ins_ptr)value)), ", assuming callable");
								queue_instruction(&analysis->search.queue, (ins_ptr)value, (*effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, ins, "ld");
							}
						}
						break;
					}
				}
			}
			LOG("value is unknown, clearing register");
		clear_ldr:
			dump_registers(&analysis->loader, &self->current_state, dump_mask);
			clear_register(&source_state);
			truncate_to_operand_size(&source_state, mem_size);
			if (is_signed) {
				sign_extend_from_operand_size(&source_state, mem_size);
			}
			truncate_to_operand_size(&source_state, size);
			self->current_state.registers[dest] = source_state;
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			if (requires_known_target) {
				self->current_state.requires_known_target |= mask_for_register(dest);
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_LDCLR:
		case ARM64_LDCLRA:
		case ARM64_LDCLRAL:
		case ARM64_LDCLRL:
		case ARM64_LDCLRB:
		case ARM64_LDCLRAB:
		case ARM64_LDCLRALB:
		case ARM64_LDCLRLB:
		case ARM64_LDCLRH:
		case ARM64_LDCLRAH:
		case ARM64_LDCLRALH:
		case ARM64_LDCLRLH:
		case ARM64_LDTCLR:
		case ARM64_LDTCLRA:
		case ARM64_LDTCLRAL:
		case ARM64_LDTCLRL: {
			LOG("ldclr*");
			enum ins_operand_size size;
			int loaded = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (loaded == REGISTER_INVALID) {
				break;
			}
			self->current_state.registers[loaded].value = 0;
			self->current_state.registers[loaded].max = mask_for_operand_size(size);
			self->current_state.sources[loaded] = 0;
			clear_match(&analysis->loader, &self->current_state, loaded, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(loaded));
			goto skip_stack_clear;
		}
		case ARM64_LDCLRP:
		case ARM64_LDCLRPA:
		case ARM64_LDCLRPAL:
		case ARM64_LDCLRPL: {
			LOG("ldclrp*");
			for (int i = 0; i < 2; i++) {
				enum ins_operand_size size;
				int loaded = get_operand(&analysis->loader, &decoded->decomposed.operands[i], &self->current_state, ins, &size);
				if (loaded != REGISTER_INVALID) {
					self->current_state.registers[loaded].value = 0;
					self->current_state.registers[loaded].max = mask_for_operand_size(size);
					self->current_state.sources[loaded] = 0;
					clear_match(&analysis->loader, &self->current_state, loaded, ins);
					dump_registers(&analysis->loader, &self->current_state, mask_for_register(loaded));
				}
			}
			goto skip_stack_clear;
		}
		case ARM64_LDEOR:
		case ARM64_LDEORA:
		case ARM64_LDEORAL:
		case ARM64_LDEORL:
		case ARM64_LDEORB:
		case ARM64_LDEORAB:
		case ARM64_LDEORALB:
		case ARM64_LDEORLB:
		case ARM64_LDEORH:
		case ARM64_LDEORAH:
		case ARM64_LDEORALH:
		case ARM64_LDEORLH: {
			LOG("ldeor*");
			enum ins_operand_size size;
			int loaded = get_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &size);
			if (loaded == REGISTER_INVALID) {
				break;
			}
			self->current_state.registers[loaded].value = 0;
			self->current_state.registers[loaded].max = mask_for_operand_size(size);
			self->current_state.sources[loaded] = 0;
			clear_match(&analysis->loader, &self->current_state, loaded, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(loaded));
			goto skip_stack_clear;
		}
		case ARM64_LDG:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_LDSET:
		case ARM64_LDSETA:
		case ARM64_LDSETAL:
		case ARM64_LDSETL:
		case ARM64_LDSETB:
		case ARM64_LDSETAB:
		case ARM64_LDSETALB:
		case ARM64_LDSETLB:
		case ARM64_LDSETH:
		case ARM64_LDSETAH:
		case ARM64_LDSETALH:
		case ARM64_LDSETLH:
		case ARM64_LDSETP:
		case ARM64_LDSETPA:
		case ARM64_LDSETPAL:
		case ARM64_LDSETPL:
		case ARM64_LDTSET:
		case ARM64_LDTSETA:
		case ARM64_LDTSETAL:
		case ARM64_LDTSETL: {
			LOG("ldset*");
			enum ins_operand_size size;
			int loaded = get_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &size);
			if (loaded == REGISTER_INVALID) {
				break;
			}
			self->current_state.registers[loaded].value = 0;
			self->current_state.registers[loaded].max = mask_for_operand_size(size);
			self->current_state.sources[loaded] = 0;
			clear_match(&analysis->loader, &self->current_state, loaded, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(loaded));
			goto skip_stack_clear;
		}
		case ARM64_LDSMAX:
		case ARM64_LDSMAXA:
		case ARM64_LDSMAXAB:
		case ARM64_LDSMAXAH:
		case ARM64_LDSMAXAL:
		case ARM64_LDSMAXALB:
		case ARM64_LDSMAXALH:
		case ARM64_LDSMAXB:
		case ARM64_LDSMAXH:
		case ARM64_LDSMAXL:
		case ARM64_LDSMAXLB:
		case ARM64_LDSMAXLH:
			DIE("ldsmax* instruction is not supported: ", temp_str(copy_address_description(&analysis->loader, ins)));
			break;
		case ARM64_LDSMIN:
		case ARM64_LDSMINA:
		case ARM64_LDSMINAB:
		case ARM64_LDSMINAH:
		case ARM64_LDSMINAL:
		case ARM64_LDSMINALB:
		case ARM64_LDSMINALH:
		case ARM64_LDSMINB:
		case ARM64_LDSMINH:
		case ARM64_LDSMINL:
		case ARM64_LDSMINLB:
		case ARM64_LDSMINLH:
			DIE("ldsmin* instruction is not supported: ", temp_str(copy_address_description(&analysis->loader, ins)));
			break;
		case ARM64_LDTR:
		case ARM64_LDTRB:
		case ARM64_LDTRH:
		case ARM64_LDTRSB:
		case ARM64_LDTRSH:
		case ARM64_LDTRSW:
			DIE("ldtr* instruction is not supported: ", temp_str(copy_address_description(&analysis->loader, ins)));
			break;
		case ARM64_LDUMAX:
		case ARM64_LDUMAXA:
		case ARM64_LDUMAXAB:
		case ARM64_LDUMAXAH:
		case ARM64_LDUMAXAL:
		case ARM64_LDUMAXALB:
		case ARM64_LDUMAXALH:
		case ARM64_LDUMAXB:
		case ARM64_LDUMAXH:
		case ARM64_LDUMAXL:
		case ARM64_LDUMAXLB:
		case ARM64_LDUMAXLH:
			DIE("ldumax* instruction is not supported: ", temp_str(copy_address_description(&analysis->loader, ins)));
			break;
		case ARM64_LDUMIN:
		case ARM64_LDUMINA:
		case ARM64_LDUMINAB:
		case ARM64_LDUMINAH:
		case ARM64_LDUMINAL:
		case ARM64_LDUMINALB:
		case ARM64_LDUMINALH:
		case ARM64_LDUMINB:
		case ARM64_LDUMINH:
		case ARM64_LDUMINL:
		case ARM64_LDUMINLB:
		case ARM64_LDUMINLH:
			DIE("ldumin* instruction is not supported: ", temp_str(copy_address_description(&analysis->loader, ins)));
			break;
		case ARM64_LDUR: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ldur ", name_for_register(dest));
			clear_register(&self->current_state.registers[dest]);
			truncate_to_operand_size(&self->current_state.registers[dest], size);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_LDURB: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ldurb ", name_for_register(dest));
			clear_register(&self->current_state.registers[dest]);
			truncate_to_operand_size(&self->current_state.registers[dest], OPERATION_SIZE_BYTE);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_LDURH: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ldurh ", name_for_register(dest));
			clear_register(&self->current_state.registers[dest]);
			truncate_to_operand_size(&self->current_state.registers[dest], OPERATION_SIZE_HALF);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_LDURSB: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ldursb ", name_for_register(dest));
			clear_register(&self->current_state.registers[dest]);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_LDURSH: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ldursh ", name_for_register(dest));
			clear_register(&self->current_state.registers[dest]);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_LDURSW: {
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ldursw ", name_for_register(dest));
			clear_register(&self->current_state.registers[dest]);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_LSL:
		case ARM64_LSLV: {
			int dest = perform_basic_op("lsl", basic_op_shl, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_LSLR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_LSR:
		case ARM64_LSRV: {
			int dest = perform_basic_op("lsr", basic_op_shr, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_LSRR:
		case ARM64_LUTI2:
		case ARM64_LUTI4:
		case ARM64_LUTI6:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_MAD:
		case ARM64_MADPT:
		case ARM64_MADD:
		case ARM64_MADDPT:
		case ARM64_MATCH:
		case ARM64_MLA:
		case ARM64_MLAPT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_MLBI:
			// MPAM lookaside buffer invalidate
			break;
		case ARM64_MLS:
		case ARM64_MNEG:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_MOV: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID || (dest == REGISTER_SP && decoded->decomposed.operands[0].reg[0] == REG_X29)) {
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			LOG("mov to ", name_for_register(dest), " from ", name_for_register(source));
			add_match_and_sources(&analysis->loader, &self->current_state, dest, source, source == REGISTER_INVALID ? 0 : self->current_state.sources[source], ins);
			self->current_state.registers[dest] = source_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				self->current_state.sources[dest] = 0;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_MOVA:
		case ARM64_MOVAZ:
		case ARM64_MOVI:
		case ARM64_MOVT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_MOVK: {
			// TODO: support movk properly overriding only the appropriate bits
			struct register_state dest_state;
			enum ins_operand_size size;
			int dest = read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &dest_state, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			LOG("movk to ", name_for_register(dest), " from ", name_for_register(source));
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			if (register_is_exactly_known(&dest_state) && register_is_exactly_known(&source_state)) {
				uint32_t shift = decoded->decomposed.operands[1].shiftValue;
				set_register(&dest_state, (dest_state.value & ~((uintptr_t)0xffff << shift)) | (source_state.value << shift));
				if (source != REGISTER_INVALID) {
					self->current_state.sources[dest] |= self->current_state.sources[source];
				}
			} else {
				clear_register(&dest_state);
			}
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			self->current_state.registers[dest] = dest_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, dest_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, dest_state)));
				self->current_state.sources[dest] = 0;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_MOVPRFX:
			// prefixes!? in my riscy ISA?
			break;
		case ARM64_MOVN:
		case ARM64_MOVS:
		case ARM64_MOVZ:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_MRS: {
			// move system register clears output reg
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			add_address_to_list(&analysis->search.tls_addresses, (uintptr_t)ins);
			break;
		}
		case ARM64_MRRS: {
			// move system register pair clears output regs
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_arg(&analysis->loader, &self->current_state, 1, ins, decoded);
			add_address_to_list(&analysis->search.tls_addresses, (uintptr_t)ins);
			break;
		}
		case ARM64_MSB:
		case ARM64_MSUB:
		case ARM64_MSUBPT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_MSR:
		case ARM64_MSRR: {
			LOG("msr ", temp_str(copy_address_description(&analysis->loader, ins)));
			add_address_to_list(&analysis->search.tls_addresses, (uintptr_t)ins);
			break;
		}
		case ARM64_MUL: {
			int dest = perform_basic_op("mul", basic_op_mul, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_MVN: {
			int dest = perform_unary_op("mvn", unary_op_mvn, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_MVNI:
		case ARM64_NAND:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_NANDS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_NBSL:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_NEG: {
			int dest = perform_unary_op("neg", unary_op_neg, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_NEGS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_NGC:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_NGCS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_NMATCH:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_NOP: {
			LOG("nop");
			break;
		}
		case ARM64_NOR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_NORS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_NOT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_NOTS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_ORR: {
			int dest = perform_basic_op("orr", basic_op_or, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ORRS: {
			int dest = perform_basic_op("orrs", basic_op_or, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			clear_comparison_state(&self->current_state);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ORN: {
			int dest = perform_basic_op("orn", basic_op_unknown, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ORNS: {
			int dest = perform_basic_op("orn", basic_op_unknown, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			clear_comparison_state(&self->current_state);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_ORQV:
		case ARM64_ORV:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_PACGA:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_PACDA:
		case ARM64_PACDB:
		case ARM64_PACDZA:
		case ARM64_PACDZB:
		case ARM64_PACIA:
		case ARM64_PACIA1716:
		case ARM64_PACIA171615:
		case ARM64_PACIASP:
		case ARM64_PACIASPPC:
		case ARM64_PACIAZ:
		case ARM64_PACIB:
		case ARM64_PACIB1716:
		case ARM64_PACIB171615:
		case ARM64_PACIBSP:
		case ARM64_PACIBSPPC:
		case ARM64_PACIBZ:
		case ARM64_PACIZA:
		case ARM64_PACIZB:
		case ARM64_PACM:
		case ARM64_PACNBIASPPC:
		case ARM64_PACNBIBSPPC: {
			LOG("pointer authentication instruction");
			break;
		}
		case ARM64_PEXT:
		case ARM64_PFALSE:
		case ARM64_PFIRST:
		case ARM64_PMLAL:
		case ARM64_PMUL:
		case ARM64_PMULL:
		case ARM64_PMULL2:
		case ARM64_PMULLB:
		case ARM64_PMULLT:
		case ARM64_PNEXT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_PMOV:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_PRFB:
			LOG("prfb");
			break;
		case ARM64_PRFD:
			LOG("prfd");
			break;
		case ARM64_PRFH:
			LOG("prfh");
			break;
		case ARM64_PRFM:
			LOG("prfm");
			break;
		case ARM64_PRFUM:
			LOG("prfum");
			break;
		case ARM64_PRFW:
			LOG("prfw");
			break;
		case ARM64_PSB:
			LOG("psb");
			break;
		case ARM64_PSEL:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_PSSBB:
			LOG("pssbb");
			break;
		case ARM64_PTEST:
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_PTRUE:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_PTRUES:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_PUNPKHI:
		case ARM64_PUNPKLO:
		case ARM64_RADDHN:
		case ARM64_RADDHN2:
		case ARM64_RADDHNB:
		case ARM64_RADDHNT:
		case ARM64_RAX1:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_RCWCAS:
		case ARM64_RCWCASA:
		case ARM64_RCWCASAL:
		case ARM64_RCWCASL:
		case ARM64_RCWCASP:
		case ARM64_RCWCASPA:
		case ARM64_RCWCASPAL:
		case ARM64_RCWCASPL:
		case ARM64_RCWCLR:
		case ARM64_RCWCLRA:
		case ARM64_RCWCLRAL:
		case ARM64_RCWCLRL:
		case ARM64_RCWCLRP:
		case ARM64_RCWCLRPA:
		case ARM64_RCWCLRPAL:
		case ARM64_RCWCLRPL:
		case ARM64_RCWSCAS:
		case ARM64_RCWSCASA:
		case ARM64_RCWSCASAL:
		case ARM64_RCWSCASL:
		case ARM64_RCWSCASP:
		case ARM64_RCWSCASPA:
		case ARM64_RCWSCASPAL:
		case ARM64_RCWSCASPL:
		case ARM64_RCWSCLR:
		case ARM64_RCWSCLRA:
		case ARM64_RCWSCLRAL:
		case ARM64_RCWSCLRL:
		case ARM64_RCWSCLRP:
		case ARM64_RCWSCLRPA:
		case ARM64_RCWSCLRPAL:
		case ARM64_RCWSCLRPL:
		case ARM64_RCWSET:
		case ARM64_RCWSETA:
		case ARM64_RCWSETAL:
		case ARM64_RCWSETL:
		case ARM64_RCWSETP:
		case ARM64_RCWSETPA:
		case ARM64_RCWSETPAL:
		case ARM64_RCWSETPL:
		case ARM64_RCWSSET:
		case ARM64_RCWSSETA:
		case ARM64_RCWSSETAL:
		case ARM64_RCWSSETL:
		case ARM64_RCWSSETP:
		case ARM64_RCWSSETPA:
		case ARM64_RCWSSETPAL:
		case ARM64_RCWSSETPL:
		case ARM64_RCWSSWP:
		case ARM64_RCWSSWPA:
		case ARM64_RCWSSWPAL:
		case ARM64_RCWSSWPL:
		case ARM64_RCWSWP:
		case ARM64_RCWSWPA:
		case ARM64_RCWSWPAL:
		case ARM64_RCWSWPL:
		case ARM64_RCWSWPP:
		case ARM64_RCWSWPPA:
		case ARM64_RCWSWPPAL:
		case ARM64_RCWSWPPL:
		case ARM64_RCWSSWPP:
		case ARM64_RCWSSWPPA:
		case ARM64_RCWSSWPPL:
		case ARM64_RCWSSWPPAL:
			// read check write
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_RDFFR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_RBIT: {
			int dest = perform_unary_op("rbit", unary_op_rbit, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_RDFFRS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_RDVL:
		case ARM64_RDSVL:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_RET:
		case ARM64_RETAA:
		case ARM64_RETAB:
		case ARM64_RETAASPPC:
		case ARM64_RETAASPPCR:
		case ARM64_RETABSPPC:
		case ARM64_RETABSPPCR:
			// handled earlier in is_return_ins check
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_REV: {
			int dest = perform_unary_op("rev", unary_op_rev, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_REV16:
		case ARM64_REV32:
		case ARM64_REV64:
		case ARM64_REVB:
		case ARM64_REVD:
		case ARM64_REVH:
		case ARM64_REVW:
		case ARM64_RMIF:
		case ARM64_RSHRN:
		case ARM64_RSHRN2:
		case ARM64_RSHRNB:
		case ARM64_RSHRNT:
		case ARM64_RSUBHN:
		case ARM64_RSUBHN2:
		case ARM64_RSUBHNB:
		case ARM64_RSUBHNT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ROR:
		case ARM64_RORV: {
			int dest = perform_basic_op("ror", basic_op_ror, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			goto skip_stack_clear;
		}
		case ARM64_RPRFM:
			// prefetch
			break;
		case ARM64_SABA:
		case ARM64_SABAL:
		case ARM64_SABAL2:
		case ARM64_SABALB:
		case ARM64_SABALT:
		case ARM64_SABD:
		case ARM64_SABDL:
		case ARM64_SABDL2:
		case ARM64_SABDLB:
		case ARM64_SABDLT:
		case ARM64_SADALP:
		case ARM64_SADDL:
		case ARM64_SADDL2:
		case ARM64_SADDLB:
		case ARM64_SADDLBT:
		case ARM64_SADDLP:
		case ARM64_SADDLT:
		case ARM64_SADDLV:
		case ARM64_SADDW:
		case ARM64_SADDWB:
		case ARM64_SADDWT:
		case ARM64_SADDW2:
		case ARM64_SADDV:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SB:
			LOG("sb");
			break;
		case ARM64_SBC: {
			int dest = perform_basic_op("sbc", basic_op_sbb, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_SBCLB:
		case ARM64_SBCLT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SBCS: {
			int dest = perform_basic_op("sbc", basic_op_sbb, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_SBFIZ:
		case ARM64_SBFM:
		case ARM64_SBFX:
		case ARM64_SCLAMP:
		case ARM64_SDIV:
		case ARM64_SDIVR:
		case ARM64_SDOT:
		case ARM64_SEL:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SETP:
		case ARM64_SETM:
		case ARM64_SETE:
		case ARM64_SETPN:
		case ARM64_SETMN:
		case ARM64_SETEN:
		case ARM64_SETPT:
		case ARM64_SETMT:
		case ARM64_SETET:
		case ARM64_SETPTN:
		case ARM64_SETMTN:
		case ARM64_SETETN:
		case ARM64_SETGP:
		case ARM64_SETGM:
		case ARM64_SETGE:
		case ARM64_SETGPN:
		case ARM64_SETGMN:
		case ARM64_SETGEN:
		case ARM64_SETGPT:
		case ARM64_SETGMT:
		case ARM64_SETGET:
		case ARM64_SETGPTN:
		case ARM64_SETGMTN:
		case ARM64_SETGETN:
			// memset
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_arg(&analysis->loader, &self->current_state, 1, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_SETF16:
		case ARM64_SETF8:
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_SETFFR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SEV:
			LOG("sev");
			break;
		case ARM64_SEVL:
			LOG("sevl");
			break;
		case ARM64_SHA1C:
		case ARM64_SHA1H:
		case ARM64_SHA1M:
		case ARM64_SHA1P:
		case ARM64_SHA1SU0:
		case ARM64_SHA1SU1:
		case ARM64_SHA256SU0:
		case ARM64_SHA256SU1:
		case ARM64_SHA256H:
		case ARM64_SHA256H2:
		case ARM64_SHA512SU0:
		case ARM64_SHA512SU1:
		case ARM64_SHA512H:
		case ARM64_SHA512H2:
		case ARM64_SHADD:
		case ARM64_SHL:
		case ARM64_SHLL:
		case ARM64_SHLL2:
		case ARM64_SHRN:
		case ARM64_SHRN2:
		case ARM64_SHRNB:
		case ARM64_SHRNT:
		case ARM64_SHSUB:
		case ARM64_SHSUBR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SHUH:
			LOG("shared update hint");
			break;
		case ARM64_SLI:
		case ARM64_SM3PARTW1:
		case ARM64_SM3PARTW2:
		case ARM64_SM3SS1:
		case ARM64_SM3TT1A:
		case ARM64_SM3TT1B:
		case ARM64_SM3TT2A:
		case ARM64_SM3TT2B:
		case ARM64_SM4E:
		case ARM64_SM4EKEY:
		case ARM64_SMAX:
		case ARM64_SMAXQV:
		case ARM64_SMAXP:
		case ARM64_SMAXV:
		case ARM64_SMADDL:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SMC:
			// invalid in userland
			*effects |= EFFECT_EXITS;
			LOG("completing from hvc: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			goto update_and_return;
		case ARM64_SMIN:
		case ARM64_SMINQV:
		case ARM64_SMINP:
		case ARM64_SMINV:
		case ARM64_SMLAL:
		case ARM64_SMLAL2:
		case ARM64_SMLALB:
		case ARM64_SMLALL:
		case ARM64_SMLALT:
		case ARM64_SMLSL:
		case ARM64_SMLSL2:
		case ARM64_SMLSLB:
		case ARM64_SMLSLL:
		case ARM64_SMLSLT:
		case ARM64_SMMLA:
		case ARM64_SMNEGL:
		case ARM64_SMOPA:
		case ARM64_SMOPS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SMSTART:
			LOG("smstart");
			break;
		case ARM64_SMSTOP:
			LOG("smstop");
			break;
		case ARM64_SMOV:
		case ARM64_SMSUBL:
		case ARM64_SMULH:
		case ARM64_SMULL:
		case ARM64_SMULL2:
		case ARM64_SMULLB:
		case ARM64_SMULLT:
		case ARM64_SPLICE:
		case ARM64_SQABS:
		case ARM64_SQADD:
		case ARM64_SQCADD:
		case ARM64_SQDECB:
		case ARM64_SQDECD:
		case ARM64_SQDECH:
		case ARM64_SQDECP:
		case ARM64_SQDECW:
		case ARM64_SQDMLAL:
		case ARM64_SQDMLAL2:
		case ARM64_SQDMLALB:
		case ARM64_SQDMLALBT:
		case ARM64_SQDMLALT:
		case ARM64_SQDMLSL:
		case ARM64_SQDMLSL2:
		case ARM64_SQDMLSLB:
		case ARM64_SQDMLSLBT:
		case ARM64_SQDMLSLT:
		case ARM64_SQDMULH:
		case ARM64_SQDMULL:
		case ARM64_SQDMULL2:
		case ARM64_SQDMULLB:
		case ARM64_SQDMULLT:
		case ARM64_SQINCB:
		case ARM64_SQINCD:
		case ARM64_SQINCH:
		case ARM64_SQINCP:
		case ARM64_SQINCW:
		case ARM64_SQNEG:
		case ARM64_SQRDCMLAH:
		case ARM64_SQRDMLAH:
		case ARM64_SQRDMLSH:
		case ARM64_SQRDMULH:
		case ARM64_SQRSHL:
		case ARM64_SQRSHLR:
		case ARM64_SQRSHRN:
		case ARM64_SQRSHRN2:
		case ARM64_SQRSHRNB:
		case ARM64_SQRSHRNT:
		case ARM64_SQRSHRUN:
		case ARM64_SQRSHRUN2:
		case ARM64_SQRSHRUNB:
		case ARM64_SQRSHRUNT:
		case ARM64_SQSHL:
		case ARM64_SQSHLR:
		case ARM64_SQSHLU:
		case ARM64_SQSHRN:
		case ARM64_SQSHRN2:
		case ARM64_SQSHRNB:
		case ARM64_SQSHRNT:
		case ARM64_SQSHRUN:
		case ARM64_SQSHRUN2:
		case ARM64_SQSHRUNB:
		case ARM64_SQSHRUNT:
		case ARM64_SQSUB:
		case ARM64_SQSUBR:
		case ARM64_SQXTN:
		case ARM64_SQXTN2:
		case ARM64_SQXTNB:
		case ARM64_SQXTNT:
		case ARM64_SQXTUN:
		case ARM64_SQXTUN2:
		case ARM64_SQXTUNB:
		case ARM64_SQXTUNT:
		case ARM64_SRHADD:
		case ARM64_SRI:
		case ARM64_SRSHL:
		case ARM64_SRSHLR:
		case ARM64_SRSHR:
		case ARM64_SRSRA:
		case ARM64_SSBB:
		case ARM64_SSHL:
		case ARM64_SSHLL:
		case ARM64_SSHLL2:
		case ARM64_SSHLLB:
		case ARM64_SSHLLT:
		case ARM64_SSHR:
		case ARM64_SSRA:
		case ARM64_SSUBL:
		case ARM64_SSUBL2:
		case ARM64_SSUBLB:
		case ARM64_SSUBLBT:
		case ARM64_SSUBLT:
		case ARM64_SSUBLTB:
		case ARM64_SSUBW:
		case ARM64_SSUBW2:
		case ARM64_SSUBWB:
		case ARM64_SSUBWT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_ST1:
		case ARM64_ST1B:
		case ARM64_ST1D:
		case ARM64_ST1H:
		case ARM64_ST1Q:
		case ARM64_ST1W:
			LOG("st1, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_ST2:
		case ARM64_ST2B:
		case ARM64_ST2D:
		case ARM64_ST2H:
		case ARM64_ST2W:
		case ARM64_ST2G:
			LOG("st2, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_ST3:
		case ARM64_ST3B:
		case ARM64_ST3D:
		case ARM64_ST3H:
		case ARM64_ST3W:
			LOG("st3, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_ST4:
		case ARM64_ST4B:
		case ARM64_ST4D:
		case ARM64_ST4H:
		case ARM64_ST4W:
			LOG("st2, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_ST64B:
		case ARM64_ST64BV:
		case ARM64_ST64BV0:
			LOG("st64b*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STADD:
		case ARM64_STADDB:
		case ARM64_STADDH:
		case ARM64_STADDL:
		case ARM64_STADDLB:
		case ARM64_STADDLH:
			LOG("stadd*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STCLR:
		case ARM64_STCLRB:
		case ARM64_STCLRH:
		case ARM64_STCLRL:
		case ARM64_STCLRLB:
		case ARM64_STCLRLH:
			LOG("stclr*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STEOR:
		case ARM64_STEORB:
		case ARM64_STEORH:
		case ARM64_STEORL:
		case ARM64_STEORLB:
		case ARM64_STEORLH:
			LOG("steor*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STG: {
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		}
		case ARM64_STGM: {
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		}
		case ARM64_STGP: {
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		}
		case ARM64_STLLR:
		case ARM64_STLLRB:
		case ARM64_STLLRH:
		case ARM64_STLUR:
		case ARM64_STLURB:
		case ARM64_STLURH:
			LOG("stl*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STP: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[2], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				LOG("stp");
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &source_state, NULL);
			struct register_state source2_state;
			int source2 = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source2_state, NULL);
			LOG("stp to ", name_for_register(dest), " from ", name_for_register(source), " and ", name_for_register(source2));
			add_match_and_sources(&analysis->loader, &self->current_state, dest, source, source == REGISTER_INVALID ? 0 : self->current_state.sources[source], ins);
			self->current_state.registers[dest] = source_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				self->current_state.sources[dest] = 0;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			if (mask_for_register(dest) & (STACK_REGISTERS & (STACK_REGISTERS >> 1))) {
				int dest2 = dest + 1;
				LOG("storing second value to stack: ", name_for_register(dest2));
				add_match_and_sources(&analysis->loader, &self->current_state, dest2, source2, source2 == REGISTER_INVALID ? 0 : self->current_state.sources[source2], ins);
				self->current_state.registers[dest2] = source2_state;
				if (register_is_partially_known(&source2_state)) {
					LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source2_state)));
				} else {
					LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source2_state)));
					self->current_state.sources[dest2] = 0;
				}
				dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest2));
			} else {
				LOG("second dest not on the stack");
			}
			// TODO: support other types of stores
			*effects |= EFFECT_MODIFIES_STACK;
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_STLR:
		case ARM64_STLRB:
		case ARM64_STLRH:
			LOG("stlr, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STNP:
			LOG("stnp, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STNT1B:
		case ARM64_STNT1D:
		case ARM64_STNT1H:
		case ARM64_STNT1W:
			LOG("stnt1*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STR:
		case ARM64_STRB:
		case ARM64_STRH:
		case ARM64_STUR:
		case ARM64_STURB:
		case ARM64_STURH: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				if (decoded->decomposed.operands[1].operandClass == MEM_REG || decoded->decomposed.operands[1].operandClass == MEM_OFFSET) {
					dest = register_index_from_register(decoded->decomposed.operands[1].reg[0]);
					if (dest != REGISTER_INVALID && register_is_exactly_known(&self->current_state.registers[dest]) && self->current_state.registers[dest].value < 4096) {
						LOG("exiting because memory write to NULL");
						vary_effects_by_registers(&analysis->search, &analysis->loader, self, mask_for_register(dest), 0, 0, required_effects);
						*effects = (*effects | EFFECT_EXITS) & ~EFFECT_RETURNS;
						goto update_and_return;
					}
				}
				LOG("str");
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &source_state, NULL);
			LOG("str to ", name_for_register(dest), " from ", name_for_register(source));
			add_match_and_sources(&analysis->loader, &self->current_state, dest, source, source == REGISTER_INVALID ? 0 : self->current_state.sources[source], ins);
			self->current_state.registers[dest] = source_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				self->current_state.sources[dest] = 0;
			}
			// TODO: support other types of stores
			*effects |= EFFECT_MODIFIES_STACK;
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_STSET:
		case ARM64_STSETB:
		case ARM64_STSETH:
		case ARM64_STSETL:
		case ARM64_STSETLB:
		case ARM64_STSETLH:
			LOG("stset*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STSMAX:
		case ARM64_STSMAXB:
		case ARM64_STSMAXH:
		case ARM64_STSMAXL:
		case ARM64_STSMAXLB:
		case ARM64_STSMAXLH:
			LOG("stsmax*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STSMIN:
		case ARM64_STSMINB:
		case ARM64_STSMINH:
		case ARM64_STSMINL:
		case ARM64_STSMINLB:
		case ARM64_STSMINLH:
			LOG("stsmin*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STTR:
		case ARM64_STTRB:
		case ARM64_STTRH:
			LOG("sttr*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STUMAX:
		case ARM64_STUMAXB:
		case ARM64_STUMAXH:
		case ARM64_STUMAXL:
		case ARM64_STUMAXLB:
		case ARM64_STUMAXLH:
			LOG("stumax*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STUMIN:
		case ARM64_STUMINB:
		case ARM64_STUMINH:
		case ARM64_STUMINL:
		case ARM64_STUMINLB:
		case ARM64_STUMINLH:
			LOG("stumin*, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		case ARM64_STXR:
		case ARM64_STXRB:
		case ARM64_STXRH:
		case ARM64_STXP:
		case ARM64_STLXR:
		case ARM64_STLXRB:
		case ARM64_STLXRH:
		case ARM64_STLXP: {
			LOG("stlxr, memory not supported yet");
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			clear_register(&self->current_state.registers[REGISTER_MEM]);
			clear_match(&analysis->loader, &self->current_state, REGISTER_MEM, ins);
			// TODO
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, NULL);
			if (dest == REGISTER_INVALID) {
				break;
			}
			self->current_state.registers[dest].value = 0;
			self->current_state.registers[dest].max = 1;
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			break;
		}
		case ARM64_STZ2G: {
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		}
		case ARM64_STZG: {
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		}
		case ARM64_STZGM: {
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			break;
		}
		case ARM64_SCVTFLT:
		case ARM64_SCVTF: {
			LOG("scvtf");
			break;
		}
		case ARM64_SMOP4A:
		case ARM64_SMOP4S:
		case ARM64_SQCVT:
		case ARM64_SQCVTN:
		case ARM64_SQCVTU:
		case ARM64_SQCVTUN:
		case ARM64_SQRSHR:
		case ARM64_SQRSHRU:
		case ARM64_ST2Q:
		case ARM64_ST3Q:
		case ARM64_ST4Q:
		case ARM64_STBFADD:
		case ARM64_STBFADDL:
		case ARM64_STBFMAX:
		case ARM64_STBFMAXL:
		case ARM64_STBFMAXNM:
		case ARM64_STBFMAXNML:
		case ARM64_STBFMIN:
		case ARM64_STBFMINL:
		case ARM64_STBFMINNM:
		case ARM64_STBFMINNML:
		case ARM64_STCPH:
		case ARM64_STFADD:
		case ARM64_STFADDL:
		case ARM64_STFMAX:
		case ARM64_STFMAXL:
		case ARM64_STFMAXNM:
		case ARM64_STFMAXNML:
		case ARM64_STFMIN:
		case ARM64_STFMINL:
		case ARM64_STFMINNM:
		case ARM64_STFMINNML:
		case ARM64_STILP:
		case ARM64_STL1:
		case ARM64_STLP:
		case ARM64_STLTXR:
		case ARM64_STMOPA:
		case ARM64_STSHH:
		case ARM64_STTADD:
		case ARM64_STTADDL:
		case ARM64_STTCLR:
		case ARM64_STTCLRL:
		case ARM64_STTNP:
		case ARM64_STTP:
		case ARM64_STTSET:
		case ARM64_STTSETL:
		case ARM64_STTXR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SUB: {
			if (register_index_from_register(decoded->decomposed.operands[0].reg[0]) == AARCH64_REGISTER_SP && register_index_from_register(decoded->decomposed.operands[1].reg[0]) == AARCH64_REGISTER_SP) {
				if (decoded->decomposed.operands[2].operandClass == IMM32 || decoded->decomposed.operands[2].operandClass == IMM64) {
					if (decoded->decomposed.operands[1].reg[0] == decoded->decomposed.operands[0].reg[0]) {
						int64_t imm = (int64_t)decoded->decomposed.operands[2].immediate;
						add_to_stack(&analysis->loader, &self->current_state, -imm, ins);
					}
					goto skip_stack_clear;
				}
			}
			int dest = perform_basic_op("sub", basic_op_sub, &analysis->loader, &self->current_state, ins, decoded, NULL, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_SUBG:
		case ARM64_SUBHN:
		case ARM64_SUBHN2:
		case ARM64_SUBHNB:
		case ARM64_SUBHNT:
		case ARM64_SUBP:
		case ARM64_SUBPT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SUBPS:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_SUBR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SUBS: {
			enum ins_operand_size size;
			int dest = perform_basic_op("subs", basic_op_sub, &analysis->loader, &self->current_state, ins, decoded, &size, &additional);
			if (UNLIKELY(dest == REGISTER_INVALID)) {
				break;
			}
			set_compare_from_operation(&self->current_state, dest, mask_for_operand_size(size));
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(dest);
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_SUDOT:
		case ARM64_SUMOPA:
		case ARM64_SUMOPS:
		case ARM64_SUNPKHI:
		case ARM64_SUNPKLO:
		case ARM64_SUQADD:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SVC: {
			switch (analyze_syscall_instruction(analysis, self, &additional, caller, ins, required_effects, effects)) {
				case SYSCALL_ANALYSIS_CONTINUE:
					break;
				case SYSCALL_ANALYSIS_UPDATE_AND_RETURN:
					goto update_and_return;
				case SYSCALL_ANALYSIS_EXIT:
					*effects = (*effects | EFFECT_EXITS) & ~EFFECT_RETURNS;
					goto update_and_return;
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_SYSCALL_RESULT);
			break;
		}
		case ARM64_SUMLALL:
		case ARM64_SUMOP4A:
		case ARM64_SUMOP4S:
		case ARM64_SUNPK:
		case ARM64_SUTMOPA:
		case ARM64_SUVDOT:
		case ARM64_SVDOT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SWP:
		case ARM64_SWPA:
		case ARM64_SWPAL:
		case ARM64_SWPL:
		case ARM64_SWPB:
		case ARM64_SWPAB:
		case ARM64_SWPALB:
		case ARM64_SWPLB:
		case ARM64_SWPH:
		case ARM64_SWPAH:
		case ARM64_SWPALH:
		case ARM64_SWPLH:
		case ARM64_SWPP:
		case ARM64_SWPPA:
		case ARM64_SWPPAL:
		case ARM64_SWPPL:
		case ARM64_SWPT:
		case ARM64_SWPTA:
		case ARM64_SWPTAL:
		case ARM64_SWPTL: {
			LOG("swp*");
			enum ins_operand_size size;
			int loaded = get_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &size);
			if (loaded == REGISTER_INVALID) {
				break;
			}
			self->current_state.registers[loaded].value = 0;
			self->current_state.registers[loaded].max = mask_for_operand_size(size);
			self->current_state.sources[loaded] = 0;
			clear_match(&analysis->loader, &self->current_state, loaded, ins);
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(loaded));
			goto skip_stack_clear;
		}
		case ARM64_SXTB: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			LOG("sxtb to ", name_for_register(dest), " from ", name_for_register(source));
			if (sign_extend_from_operand_size(&source_state, OPERATION_SIZE_BYTE)) {
				self->current_state.sources[dest] = source != REGISTER_INVALID ? self->current_state.sources[source] : 0;
				clear_match(&analysis->loader, &self->current_state, dest, ins);
			} else {
				add_match_and_sources(&analysis->loader, &self->current_state, dest, source, source == REGISTER_INVALID ? 0 : self->current_state.sources[source], ins);
			}
			self->current_state.registers[dest] = source_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				self->current_state.sources[dest] = 0;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_SXTH: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			LOG("sxth to ", name_for_register(dest), " from ", name_for_register(source));
			if (sign_extend_from_operand_size(&source_state, OPERATION_SIZE_HALF)) {
				self->current_state.sources[dest] = source != REGISTER_INVALID ? self->current_state.sources[source] : 0;
				clear_match(&analysis->loader, &self->current_state, dest, ins);
			} else {
				add_match_and_sources(&analysis->loader, &self->current_state, dest, source, source == REGISTER_INVALID ? 0 : self->current_state.sources[source], ins);
			}
			self->current_state.registers[dest] = source_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				self->current_state.sources[dest] = 0;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_SXTW: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			struct register_state source_state;
			int source = read_operand(&analysis->loader, &decoded->decomposed.operands[1], &self->current_state, ins, &source_state, NULL);
			LOG("sxtw to ", name_for_register(dest), " from ", name_for_register(source));
			if (sign_extend_from_operand_size(&source_state, OPERATION_SIZE_WORD)) {
				self->current_state.sources[dest] = source != REGISTER_INVALID ? self->current_state.sources[source] : 0;
				clear_match(&analysis->loader, &self->current_state, dest, ins);
			} else {
				add_match_and_sources(&analysis->loader, &self->current_state, dest, source, source == REGISTER_INVALID ? 0 : self->current_state.sources[source], ins);
			}
			self->current_state.registers[dest] = source_state;
			if (register_is_partially_known(&source_state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source_state)));
				self->current_state.sources[dest] = 0;
			}
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
			self->pending_stack_clear &= ~mask_for_register(dest);
			goto skip_stack_clear;
		}
		case ARM64_SXTL:
		case ARM64_SXTL2:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SYS:
			LOG("sys system instruction");
			break;
		case ARM64_SYSL:
			LOG("sysp system instruction with result");
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_SYSP:
			LOG("sysp system pair instruction");
			break;
		case ARM64_TBNZ:
		case ARM64_TBZ:
			// handled in aarch64_decode_jump_instruction
			UNSUPPORTED_INSTRUCTION();
			break;
		case ARM64_TBL:
		case ARM64_TBLQ:
		case ARM64_TBX:
		case ARM64_TBXQ:
#if 0
		case ARM64_TCANCEL:
		case ARM64_TCOMMIT:
		case ARM64_TSTART:
		case ARM64_TTEST:
#endif
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_TLBI:
			LOG("tlbi tlb invalidate");
			break;
		case ARM64_TLBIP:
			LOG("tlbip tlb invalidate pair");
			break;
		case ARM64_TRCIT:
			LOG("trcit trace instruction");
			break;
		case ARM64_TRN1:
		case ARM64_TRN2:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_TSB:
			LOG("tsb");
			break;
		case ARM64_TST:
			// TODO
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_UABA:
		case ARM64_UABAL:
		case ARM64_UABAL2:
		case ARM64_UABALB:
		case ARM64_UABALT:
		case ARM64_UABD:
		case ARM64_UABDL:
		case ARM64_UABDL2:
		case ARM64_UABDLB:
		case ARM64_UABDLT:
		case ARM64_UADALP:
		case ARM64_UADDL:
		case ARM64_UADDL2:
		case ARM64_UADDLB:
		case ARM64_UADDLT:
		case ARM64_UADDLP:
		case ARM64_UADDLV:
		case ARM64_UADDV:
		case ARM64_UADDW:
		case ARM64_UADDW2:
		case ARM64_UADDWB:
		case ARM64_UADDWT:
		case ARM64_UBFM:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_UBFIZ: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ubfiz to ", name_for_register(dest));
			struct register_state lsb_state;
			read_operand(&analysis->loader, &decoded->decomposed.operands[2], &self->current_state, ins, &lsb_state, NULL);
			struct register_state w_state;
			read_operand(&analysis->loader, &decoded->decomposed.operands[3], &self->current_state, ins, &w_state, NULL);
			self->current_state.registers[dest].value = 0;
			if (w_state.max == 1) {
				// shifting a single bit into position
				self->current_state.registers[dest].max = 0;
				ins = next_ins(ins, decoded);
				ANALYZE_PRIMARY_RESULT();
				set_register(&self->current_state.registers[dest], (uint64_t)1 << lsb_state.max);
				goto use_alternate_result;
			} else {
				// shifting multiple bits
				self->current_state.registers[dest].max = ~(uint64_t)0 >> (64 - (w_state.max + lsb_state.max));
				truncate_to_operand_size(&self->current_state.registers[dest], size);
				self->current_state.sources[dest] = 0;
				clear_match(&analysis->loader, &self->current_state, dest, ins);
			}
			break;
		}
		case ARM64_UBFX: {
			enum ins_operand_size size;
			int dest = get_operand(&analysis->loader, &decoded->decomposed.operands[0], &self->current_state, ins, &size);
			if (dest == REGISTER_INVALID) {
				break;
			}
			LOG("ubfx to ", name_for_register(dest));
			struct register_state w_state;
			read_operand(&analysis->loader, &decoded->decomposed.operands[3], &self->current_state, ins, &w_state, NULL);
			self->current_state.registers[dest].value = 0;
			self->current_state.registers[dest].max = ~(uint64_t)0 >> (64 - w_state.max);
			truncate_to_operand_size(&self->current_state.registers[dest], size);
			self->current_state.sources[dest] = 0;
			clear_match(&analysis->loader, &self->current_state, dest, ins);
			break;
		}
		case ARM64_UCLAMP:
		case ARM64_UCVTF:
		case ARM64_UCVTFLT:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_UDF:
			LOG("udf");
			break;
		case ARM64_UDIV:
		case ARM64_UDIVR:
		case ARM64_UDOT:
		case ARM64_UHADD:
		case ARM64_UHSUB:
		case ARM64_UHSUBR:
		case ARM64_UMADDL:
		case ARM64_UMAXQV:
		case ARM64_UMINQV:
		case ARM64_UMLALB:
		case ARM64_UMLALL:
		case ARM64_UMLALT:
		case ARM64_UMLSL:
		case ARM64_UMLSL2:
		case ARM64_UMLSLB:
		case ARM64_UMLSLL:
		case ARM64_UMLSLT:
		case ARM64_UMAX:
		case ARM64_UMAXP:
		case ARM64_UMAXV:
		case ARM64_UMIN:
		case ARM64_UMINP:
		case ARM64_UMINV:
		case ARM64_UMMLA:
		case ARM64_UMOPA:
		case ARM64_UMOPS:
		case ARM64_UMOV:
		case ARM64_UMLAL:
		case ARM64_UMLAL2:
		case ARM64_UMNEGL:
		case ARM64_UMOP4A:
		case ARM64_UMOP4S:
		case ARM64_UMSUBL:
		case ARM64_UMULH:
		case ARM64_UMULL:
		case ARM64_UMULL2:
		case ARM64_UMULLB:
		case ARM64_UMULLT:
		case ARM64_UQADD:
		case ARM64_UQCVT:
		case ARM64_UQCVTN:
		case ARM64_UQDECB:
		case ARM64_UQDECD:
		case ARM64_UQDECH:
		case ARM64_UQDECP:
		case ARM64_UQDECW:
		case ARM64_UQINCB:
		case ARM64_UQINCD:
		case ARM64_UQINCH:
		case ARM64_UQINCP:
		case ARM64_UQINCW:
		case ARM64_UQRSHL:
		case ARM64_UQRSHLR:
		case ARM64_UQRSHR:
		case ARM64_UQRSHRN:
		case ARM64_UQRSHRN2:
		case ARM64_UQRSHRNB:
		case ARM64_UQRSHRNT:
		case ARM64_UQSHL:
		case ARM64_UQSHLR:
		case ARM64_UQSHRN:
		case ARM64_UQSHRN2:
		case ARM64_UQSHRNB:
		case ARM64_UQSHRNT:
		case ARM64_UQSUB:
		case ARM64_UQSUBR:
		case ARM64_UQXTN:
		case ARM64_UQXTN2:
		case ARM64_UQXTNB:
		case ARM64_UQXTNT:
		case ARM64_URECPE:
		case ARM64_URHADD:
		case ARM64_URSHL:
		case ARM64_URSHLR:
		case ARM64_URSHR:
		case ARM64_URSQRTE:
		case ARM64_URSRA:
		case ARM64_USDOT:
		case ARM64_USHL:
		case ARM64_USHLL:
		case ARM64_USHLL2:
		case ARM64_USHLLB:
		case ARM64_USHLLT:
		case ARM64_USHR:
		case ARM64_USMLALL:
		case ARM64_USMMLA:
		case ARM64_USMOPA:
		case ARM64_USMOPS:
		case ARM64_USMOP4A:
		case ARM64_USMOP4S:
		case ARM64_USQADD:
		case ARM64_USUBL:
		case ARM64_USUBL2:
		case ARM64_USUBLB:
		case ARM64_USUBLT:
		case ARM64_USUBWB:
		case ARM64_USUBWT:
		case ARM64_USRA:
		case ARM64_USUBW:
		case ARM64_USUBW2:
		case ARM64_USVDOT:
		case ARM64_USTMOPA:
		case ARM64_UTMOPA:
		case ARM64_UUNPK:
		case ARM64_UUNPKHI:
		case ARM64_UUNPKLO:
		case ARM64_UVDOT:
		case ARM64_UXTB:
		case ARM64_UXTH:
		case ARM64_UXTL:
		case ARM64_UXTL2:
		case ARM64_UXTW:
		case ARM64_UZP:
		case ARM64_UZP1:
		case ARM64_UZPQ1:
		case ARM64_UZP2:
		case ARM64_UZPQ2:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_WFE:
		case ARM64_WFET:
			LOG("wfe");
			break;
		case ARM64_WFI:
		case ARM64_WFIT:
			LOG("wfi");
			break;
		case ARM64_WHILEGE:
		case ARM64_WHILEGT:
		case ARM64_WHILEHI:
		case ARM64_WHILEHS:
		case ARM64_WHILELE:
		case ARM64_WHILELO:
		case ARM64_WHILELS:
		case ARM64_WHILELT:
		case ARM64_WHILERW:
		case ARM64_WHILEWR:
		case ARM64_WRFFR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_XAFLAG:
			clear_comparison_state(&self->current_state);
			break;
		case ARM64_XAR:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_XPACD:
			LOG("xpacd");
			break;
		case ARM64_XPACI:
			LOG("xpaci");
			break;
		case ARM64_XPACLRI:
			LOG("xpaclri");
			break;
		case ARM64_XTN:
		case ARM64_XTN2:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
		case ARM64_YIELD:
			LOG("yield");
			break;
		case ARM64_ZERO:
		case ARM64_ZIP:
		case ARM64_ZIP1:
		case ARM64_ZIP2:
		case ARM64_ZIPQ1:
		case ARM64_ZIPQ2:
			perform_unknown_op(&analysis->loader, &self->current_state, ins, decoded);
			break;
	}
	apply_pending_stack_clear(self);
skip_stack_clear:
	return false;
process_split_results:
    ins = next_ins(ins, decoded);
	ANALYZE_PRIMARY_RESULT();
	self->current_state.registers[additional_reg] = additional.state;
use_alternate_result:
	self->description = "alternate result";
	*effects |= analyze_instructions(analysis, required_effects, &self->current_state, ins, self, trace_flags) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
update_and_return:
	return true;
}
