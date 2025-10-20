#include "callander.h"
#include "callander_internal.h"
#include "callander_print.h"

#include "ins.h"

struct register_state_and_source
{
	struct register_state state;
	register_mask source;
};

static inline void dump_x86_ins_prefixes(__attribute__((unused)) struct x86_ins_prefixes prefixes)
{
	LOG("decoded ", prefixes.has_w ? "w:true" : "w:false", prefixes.has_r ? " r:true" : " r:false", prefixes.has_x ? " x:true" : " x:false", prefixes.has_b ? " b:true" : " b:false");
	// LOG("notrack:", prefixes.has_notrack ? "true" : "false");
}

__attribute__((always_inline)) __attribute__((nonnull(2))) static inline bool register_is_legacy_8bit_high(struct x86_ins_prefixes prefixes, int *register_index)
{
	if (UNLIKELY(*register_index >= REGISTER_SP && *register_index < REGISTER_R8 && !prefixes.has_any_rex)) {
		*register_index -= 4;
		LOG("found legacy 8bit register: ", name_for_register(*register_index));
		return true;
	}
	return false;
}

static inline enum ins_operand_size operand_size_from_prefixes(struct x86_ins_prefixes prefixes)
{
	if (prefixes.has_w) {
		return OPERATION_SIZE_DWORD;
	} else if (prefixes.has_operand_size_override) {
		return OPERATION_SIZE_HALF;
	} else {
		return OPERATION_SIZE_WORD;
	}
}

__attribute__((nonnull(1))) static inline bool truncate_to_size_prefixes(struct register_state *reg, struct x86_ins_prefixes prefixes)
{
	if (prefixes.has_w) {
		return canonicalize_register(reg);
	} else if (prefixes.has_operand_size_override) {
		return truncate_to_16bit(reg);
	} else {
		return truncate_to_32bit(reg);
	}
}

__attribute__((nonnull(1))) static inline bool register_is_partially_known_size_prefixes(struct register_state *reg, struct x86_ins_prefixes prefixes)
{
	if (prefixes.has_w) {
		return register_is_partially_known(reg);
	} else if (prefixes.has_operand_size_override) {
		return register_is_partially_known_16bit(reg);
	} else {
		return register_is_partially_known_32bit(reg);
	}
}

static inline struct register_state_and_source address_for_indirect(struct x86_instruction decoded, x86_mod_rm_t modrm, struct registers *state, const uint8_t *data, const struct loader_context *loader, ins_ptr ins, bool *out_base_is_null)
{
	struct register_state_and_source result;
	result.source = 0;
	clear_register(&result.state);
	int rm = x86_read_rm(modrm, decoded.prefixes);
	switch (rm) {
		case REGISTER_SP:
		case REGISTER_R12: {
			// decode SIB
			x86_sib_t sib = x86_read_sib(data++);
			int base_reg = x86_read_base(sib, decoded.prefixes);
			struct register_state base;
			if (modrm.mod == 0 && (base_reg == REGISTER_RBP || base_reg == REGISTER_R13)) {
				LOG("processing SIB without base");
				base.value = 0;
				base.max = 0;
				// force disp32
				modrm.mod = 2;
			} else {
				base = state->registers[base_reg];
				LOG("processing SIB from base of ", name_for_register(base_reg), ": ", temp_str(copy_register_state_description(loader, base)));
				result.source |= state->sources[base_reg];
			}
			if (out_base_is_null) {
				*out_base_is_null = register_is_exactly_known(&base) && base.value == 0;
			}
			int index_reg = x86_read_index(sib, decoded.prefixes);
			if (index_reg == REGISTER_SP) {
				LOG("without index");
				result.state = base;
				break;
			}
			result.source |= state->sources[index_reg];
			struct register_state index = state->registers[index_reg];
			LOG("and index of ", name_for_register(index_reg), ": ", temp_str(copy_register_state_description(loader, index)), "; scale: ", 1 << sib.scale);
			struct register_state scaled;
			scaled.value = index.value << sib.scale;
			scaled.max = index.max << sib.scale;
			if (((scaled.value >> sib.scale) == index.value) && ((scaled.max >> sib.scale) == index.max)) {
				struct register_state proposed;
				proposed.value = base.value + index.value;
				proposed.max = base.max + index.max;
				if (scaled.value >= base.value && scaled.max >= base.max) {
					result.state = proposed;
					break;
				}
			}
			result.source = 0;
			LOG("overflow when calculating SIB");
			break;
		}
		case REGISTER_RBP:
		case REGISTER_R13:
			if (modrm.mod == 0) {
				// decode RIP+disp32
				set_register(&result.state, (uintptr_t)data + 4 + *(const ins_int32 *)data);
				LOG("decoded rip-relative");
				if (out_base_is_null) {
					*out_base_is_null = false;
				}
				break;
			}
			// fallthrough
		default:
			// use register
			result.state = state->registers[rm];
			result.source = state->sources[rm];
			LOG("taking address in ", name_for_register(rm), ": ", temp_str(copy_register_state_description(loader, result.state)));
			if (out_base_is_null) {
				*out_base_is_null = register_is_exactly_known(&result.state) && result.state.value == 0;
			}
			break;
	}
	switch (modrm.mod) {
		case 1:
			if (register_is_partially_known(&result.state)) {
				// add 8-bit displacement
				int8_t disp = *(const int8_t *)data;
				result.state.value += disp;
				result.state.max += disp;
				LOG("adding 8-bit displacement of ", (intptr_t)disp);
			}
			break;
		case 2:
			if (register_is_partially_known(&result.state)) {
				// add 32-bit displacement
				int32_t disp = *(const ins_int32 *)data;
				result.state.value += disp;
				result.state.max += disp;
				LOG("adding 32-bit displacement of ", (intptr_t)disp);
			}
			break;
		case 3:
			DIE("modrm is not indirect at: ", temp_str(copy_address_description(loader, ins)));
			break;
	}
	canonicalize_register(&result.state);
	return result;
}

struct ins_memory_reference decode_rm(const uint8_t **ins_modrm, struct x86_ins_prefixes prefixes, uint8_t imm_size, bool uses_frame_pointer)
{
	x86_mod_rm_t modrm = x86_read_modrm(*ins_modrm);
	*ins_modrm += sizeof(x86_mod_rm_t);
	struct ins_memory_reference result = (struct ins_memory_reference){0};
	if (prefixes.has_segment_override) {
		result.rm = REGISTER_STACK_4;
		result.base = 0;
		result.index = 0;
		result.scale = 0;
		result.addr = 0;
	} else {
		switch ((result.rm = x86_read_rm(modrm, prefixes))) {
			case REGISTER_SP:
				if (uses_frame_pointer) {
					result.rm = REGISTER_STACK_4;
					result.base = 0;
					result.index = 0;
					result.scale = 0;
					result.addr = 0;
					break;
				}
				// fallthrough
			case REGISTER_R12: {
				// decode SIB
				x86_sib_t sib = x86_read_sib(*ins_modrm);
				*ins_modrm += sizeof(x86_sib_t);
				result.base = x86_read_base(sib, prefixes);
				result.index = x86_read_index(sib, prefixes);
				result.scale = sib.scale;
				result.addr = 0;
				result.rm = REGISTER_STACK_0;
				break;
			}
			case REGISTER_RBP:
			case REGISTER_R13:
				if (modrm.mod == 0) {
					// decode RIP+disp32
					result.base = 0;
					result.index = 0;
					result.scale = 0;
					result.addr = (uintptr_t)*ins_modrm + sizeof(int32_t) + *(const ins_int32 *)*ins_modrm + imm_size;
					result.rm = REGISTER_MEM;
					*ins_modrm += sizeof(int32_t);
					break;
				}
				// frame pointer offset
				if (result.rm == REGISTER_RBP && uses_frame_pointer) {
					result.base = REGISTER_SP;
					result.index = REGISTER_SP;
					result.scale = 0;
					result.addr = 0;
					result.rm = REGISTER_STACK_0;
					break;
				}
				// fallthrough
			default:
				result.base = 0;
				result.index = 0;
				result.scale = 0;
				result.addr = 0;
				break;
		}
	}
	switch (modrm.mod) {
		case 1: {
			int8_t disp = *(const int8_t *)*ins_modrm;
			result.addr += disp;
			*ins_modrm += sizeof(int8_t);
			break;
		}
		case 2: {
			int32_t disp = *(const ins_int32 *)*ins_modrm;
			result.addr += disp;
			*ins_modrm += sizeof(int32_t);
			break;
		}
	}
	return result;
}

static uintptr_t read_imm(struct x86_ins_prefixes prefixes, ins_ptr imm)
{
	if (prefixes.has_w) { // imm32 sign-extended
		return *(const ins_int32 *)imm;
	} else if (prefixes.has_operand_size_override) { // imm16
		return *(const ins_uint16 *)imm;
	} else { // imm32
		return *(const ins_uint32 *)imm;
	}
}


enum
{
	OPERATION_SIZE_DEFAULT = 0,
};

enum read_rm_flags
{
	READ_RM_REPLACE_MEM = 0,
	READ_RM_KEEP_MEM = 2,
	READ_RM_USES_FRAME_POINTER = 1,
};

static inline enum read_rm_flags read_rm_flags_from_trace_flags(trace_flags flags)
{
	return (flags & TRACE_USES_FRAME_POINTER) ? READ_RM_USES_FRAME_POINTER : 0;
}

struct rm_result
{
	struct register_state state;
	register_mask sources;
	int reg;
	bool faults;
};

__attribute__((always_inline)) static inline void truncate_to_operation_size(struct register_state *value, int operation_size, struct x86_ins_prefixes prefixes)
{
	switch (operation_size) {
		case OPERATION_SIZE_DEFAULT:
			truncate_to_size_prefixes(value, prefixes);
			break;
		case OPERATION_SIZE_BYTE:
			truncate_to_8bit(value);
			break;
		case OPERATION_SIZE_HALF:
			truncate_to_16bit(value);
			break;
		case OPERATION_SIZE_WORD:
			truncate_to_32bit(value);
			break;
		case OPERATION_SIZE_DWORD:
			break;
	}
}

static inline struct rm_result read_rm_ref(const struct loader_context *loader, struct x86_ins_prefixes prefixes, ins_ptr *ins_modrm, size_t imm_size, struct registers *regs, int operation_size, enum read_rm_flags flags)
{
	struct rm_result result = {
		.reg = REGISTER_INVALID,
		.sources = 0,
		.faults = false,
	};
	if (UNLIKELY(prefixes.has_segment_override) && (flags & READ_RM_KEEP_MEM)) {
	return_invalid:
		clear_register(&result.state);
		goto return_result;
	}
	x86_mod_rm_t modrm = x86_read_modrm(*ins_modrm);
	register_mask sources = 0;
	if (x86_modrm_is_direct(modrm)) {
		*ins_modrm += sizeof(x86_mod_rm_t);
		result.reg = x86_read_rm(modrm, prefixes);
	return_for_reg:
		result.state = regs->registers[result.reg];
		result.sources = regs->sources[result.reg];
		goto return_result;
	}
	struct ins_memory_reference decoded = decode_rm(ins_modrm, prefixes, imm_size, (flags & READ_RM_USES_FRAME_POINTER) == READ_RM_USES_FRAME_POINTER);
	if (decoded.rm == REGISTER_STACK_0 && decoded.base == REGISTER_SP && decoded.index == REGISTER_SP) {
		switch (decoded.addr) {
#define PER_STACK_REGISTER_IMPL(offset)                                   \
	case offset:                                                          \
		LOG("stack slot of ", name_for_register(REGISTER_STACK_##offset)); \
		result.reg = REGISTER_STACK_##offset;                             \
		goto return_for_reg;
			GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
		}
		LOG("stack offset of ", (intptr_t)decoded.addr);
	}
	if (memory_ref_equal(&decoded, &regs->mem_ref)) {
		result.reg = REGISTER_MEM;
		goto return_for_reg;
	}
	uintptr_t addr = decoded.addr;
	bool valid = false;
	switch (decoded.rm) {
		case REGISTER_STACK_0:
			if (decoded.index == REGISTER_SP) {
				if (register_is_exactly_known(&regs->registers[decoded.base])) {
					addr += regs->registers[decoded.base].value;
					result.sources = regs->sources[decoded.base];
					valid = true;
				}
			} else {
				if (decoded.base == REGISTER_SP) {
					record_stack_address_taken(loader, *ins_modrm, regs);
				}
				if (register_is_exactly_known(&regs->registers[decoded.base]) && register_is_exactly_known(&regs->registers[decoded.index])) {
					addr += regs->registers[decoded.base].value + (regs->registers[decoded.index].value << decoded.scale);
					result.sources = regs->sources[decoded.base] | regs->sources[decoded.index];
					valid = true;
				}
			}
			break;
		case REGISTER_MEM:
			valid = true;
			break;
		default:
			if (decoded.rm == REGISTER_SP) {
				record_stack_address_taken(loader, *ins_modrm, regs);
			}
			if (register_is_exactly_known(&regs->registers[decoded.rm])) {
				result.sources = regs->sources[decoded.rm];
				addr += regs->registers[decoded.rm].value;
				valid = true;
			}
			break;
	}
	clear_register(&result.state);
	if (valid) {
		struct loaded_binary *binary;
		if (addr < 4096) {
			LOG("faults because null address");
			result.faults = true;
		}
		int prot = protection_for_address(loader, (const void *)addr, &binary, NULL);
		if (prot & PROT_READ) {
			uintptr_t value = read_memory((const void *)addr, operation_size == OPERATION_SIZE_DEFAULT ? operand_size_from_prefixes(prefixes) : (enum ins_operand_size)operation_size);
			LOG("read value: ", value);
			if ((prot & PROT_WRITE) == 0 || (value == SYS_fcntl && (binary->special_binary_flags & BINARY_IS_GOLANG))) { // workaround for golang's syscall.fcntl64Syscall
				if (flags & READ_RM_KEEP_MEM && !register_is_partially_known(&regs->registers[REGISTER_MEM])) {
					set_register(&result.state, value);
					LOG("loaded memory constant: ", temp_str(copy_register_state_description(loader, (struct register_state){.value = value, .max = value})), " from ", temp_str(copy_address_description(loader, (const void *)addr)));
					return result;
				}
				LOG("replacing old mem r/m ", temp_str(copy_memory_ref_description(loader, regs->mem_ref)), " with ", temp_str(copy_memory_ref_description(loader, decoded)));
				regs->mem_ref = decoded;
				result.reg = REGISTER_MEM;
				set_register(&regs->registers[REGISTER_MEM], value);
				regs->sources[REGISTER_MEM] = sources;
				LOG("loaded memory constant ", temp_str(copy_register_state_description(loader, regs->registers[REGISTER_MEM])), " from ", temp_str(copy_address_description(loader, (const void *)addr)));
				clear_match(loader, regs, REGISTER_MEM, *ins_modrm);
				goto return_for_reg;
			}
			LOG("region is writable, assuming it might not be constant: ", value);
		}
	}
	if (flags & READ_RM_KEEP_MEM && !register_is_partially_known(&regs->registers[REGISTER_MEM])) {
		result.reg = REGISTER_INVALID;
		result.sources = 0;
		goto return_invalid;
	}
	LOG("replacing old mem r/m of ", temp_str(copy_memory_ref_description(loader, regs->mem_ref)), " with ", temp_str(copy_memory_ref_description(loader, decoded)));
	regs->mem_ref = decoded;
	clear_match(loader, regs, REGISTER_MEM, *ins_modrm);
	result.reg = REGISTER_MEM;
	clear_register(&regs->registers[REGISTER_MEM]);
	truncate_to_operation_size(&regs->registers[REGISTER_MEM], operation_size, prefixes);
	regs->sources[REGISTER_MEM] = 0;
	if (valid) {
		LOG("unknown memory value: ", temp_str(copy_register_state_description(loader, regs->registers[REGISTER_MEM])));
	} else {
		LOG("unknown memory address: ", temp_str(copy_register_state_description(loader, regs->registers[REGISTER_MEM])));
	}
return_result:
	truncate_to_operation_size(&result.state, operation_size, prefixes);
	return result;
}

__attribute__((nonnull(1))) __attribute__((unused)) static inline void clear_stack(struct registers *regs, __attribute__((unused)) ins_ptr ins)
{
	for (int i = REGISTER_STACK_0; i < REGISTER_COUNT; i++) {
		clear_register(&regs->registers[i]);
		regs->sources[i] = 0;
		regs->matches[i] = 0;
#if STORE_LAST_MODIFIED
		regs->last_modify_ins[i] = ins;
#endif
	}
	for (int i = 0; i < REGISTER_STACK_0; i++) {
		regs->matches[i] &= ~STACK_REGISTERS;
	}
	regs->modified |= STACK_REGISTERS;
	regs->requires_known_target &= ~STACK_REGISTERS;
}

__attribute__((always_inline)) static inline uintptr_t mask_for_size_prefixes(struct x86_ins_prefixes prefixes)
{
	return prefixes.has_w ? (uintptr_t)0xffffffffffffffff : (prefixes.has_operand_size_override ? (uintptr_t)0xffff : (uintptr_t)0xffffffff);
}

static uint8_t imm_size_for_prefixes(struct x86_ins_prefixes prefixes)
{
	if (prefixes.has_w) { // imm32 sign-extended
		return sizeof(int32_t);
	} else if (prefixes.has_operand_size_override) { // imm16
		return sizeof(uint16_t);
	} else { // imm32
		return sizeof(uint32_t);
	}
}

static inline void update_sources_for_basic_op_usage(struct registers *regs, int dest_reg, int source_reg, enum basic_op_usage usage)
{
	if (source_reg == REGISTER_INVALID) {
		usage &= ~BASIC_OP_USED_RIGHT;
	}
	switch (usage) {
		case BASIC_OP_USED_NEITHER:
			regs->sources[dest_reg] = 0;
			regs->requires_known_target &= ~mask_for_register(dest_reg);
			break;
		case BASIC_OP_USED_RIGHT:
			regs->sources[dest_reg] = regs->sources[source_reg];
			regs->requires_known_target = (regs->requires_known_target & ~mask_for_register(dest_reg)) | ((regs->requires_known_target & mask_for_register(source_reg)) ? mask_for_register(dest_reg) : 0);
			break;
		case BASIC_OP_USED_LEFT:
			break;
		case BASIC_OP_USED_BOTH:
			regs->sources[dest_reg] |= regs->sources[source_reg];
			regs->requires_known_target |= (regs->requires_known_target & mask_for_register(source_reg)) ? mask_for_register(dest_reg) : 0;
			break;
	}
}

struct basic_op_result
{
	register_mask fault_sources;
	int reg;
	bool faults;
};

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_rm_r_8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                          ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(rm.reg), " operand: ", name_for_register(reg));
	dump_registers(loader, regs, mask_for_register(reg) | mask_for_register(rm.reg));
	additional->used = false;
	enum basic_op_usage usage;
	if (register_is_legacy_8bit_high(prefixes, &rm.reg) || register_is_legacy_8bit_high(prefixes, &reg)) {
		usage = BASIC_OP_USED_NEITHER;
		clear_register(&rm.state);
		truncate_to_16bit(&rm.state);
	} else {
		struct register_state src = regs->registers[reg];
		truncate_to_8bit(&src);
		truncate_to_8bit(&rm.state);
		usage = op(&rm.state, &src, rm.reg, reg, OPERATION_SIZE_BYTE, additional);
		truncate_to_8bit(&rm.state);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_8bit(&additional->state);
		merge_and_log_additional_result(loader, &rm.state, additional, rm.reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, rm.state)));
	}
	regs->registers[rm.reg] = rm.state;
	update_sources_for_basic_op_usage(regs, rm.reg, reg, register_is_partially_known_8bit(&rm.state) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, rm.reg, ins_modrm);
	return (struct basic_op_result){
		.reg = rm.reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_rm_r(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                        ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(rm.reg), " operand: ", name_for_register(reg));
	dump_registers(loader, regs, mask_for_register(reg) | mask_for_register(rm.reg));
	struct register_state src = regs->registers[reg];
	truncate_to_size_prefixes(&src, prefixes);
	truncate_to_size_prefixes(&rm.state, prefixes);
	additional->used = false;
	uintptr_t orig_value = rm.state.value;
	enum ins_operand_size size = operand_size_from_prefixes(prefixes);
	enum basic_op_usage usage = op(&rm.state, &src, rm.reg, reg, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &rm.state, additional, orig_value);
		widen_cross_binary_bound_operation(loader, &rm.state, additional, src.value);
	} else {
		truncate_to_size_prefixes(&rm.state, prefixes);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_size_prefixes(&additional->state, prefixes);
		merge_and_log_additional_result(loader, &rm.state, additional, rm.reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, rm.state)));
	}
	regs->registers[rm.reg] = rm.state;
	update_sources_for_basic_op_usage(regs, rm.reg, reg, register_is_partially_known_size_prefixes(&rm.state, prefixes) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, rm.reg, ins_modrm);
	return (struct basic_op_result){
		.reg = rm.reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_r_rm_8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                          ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(reg), " operand: ", name_for_register(rm.reg));
	struct register_state dest = regs->registers[reg];
	additional->used = false;
	enum basic_op_usage usage;
	if (register_is_legacy_8bit_high(prefixes, &rm.reg) || register_is_legacy_8bit_high(prefixes, &reg)) {
		usage = BASIC_OP_USED_NEITHER;
		clear_register(&dest);
		truncate_to_16bit(&dest);
	} else {
		truncate_to_8bit(&rm.state);
		truncate_to_8bit(&dest);
		usage = op(&dest, &rm.state, reg, rm.reg, OPERATION_SIZE_BYTE, additional);
		truncate_to_8bit(&dest);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_8bit(&additional->state);
		merge_and_log_additional_result(loader, &dest, additional, reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, dest)));
	}
	regs->registers[reg] = dest;
	update_sources_for_basic_op_usage(regs, reg, rm.reg, register_is_partially_known_8bit(&dest) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, reg, ins_modrm);
	return (struct basic_op_result){
		.reg = reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_r_rm(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                        ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, 0, regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(reg), " operand: ", name_for_register(rm.reg));
	struct register_state dest = regs->registers[reg];
	dump_registers(loader, regs, mask_for_register(reg) | mask_for_register(rm.reg));
	truncate_to_size_prefixes(&rm.state, prefixes);
	truncate_to_size_prefixes(&dest, prefixes);
	additional->used = false;
	uintptr_t orig_value = dest.value;
	enum ins_operand_size size = operand_size_from_prefixes(prefixes);
	enum basic_op_usage usage = op(&dest, &rm.state, reg, rm.reg, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &rm.state, additional, orig_value);
		widen_cross_binary_bound_operation(loader, &rm.state, additional, rm.state.value);
	} else {
		truncate_to_size_prefixes(&rm.state, prefixes);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_size_prefixes(&additional->state, prefixes);
		merge_and_log_additional_result(loader, &dest, additional, reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, dest)));
	}
	regs->registers[reg] = dest;
	update_sources_for_basic_op_usage(regs, reg, rm.reg, register_is_partially_known_size_prefixes(&dest, prefixes) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, reg, ins_modrm);
	return (struct basic_op_result){
		.reg = reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_rm8_imm8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                            ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, sizeof(uint8_t), regs, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(rm.reg));
	dump_registers(loader, regs, mask_for_register(rm.reg));
	additional->used = false;
	enum basic_op_usage usage;
	if (register_is_legacy_8bit_high(prefixes, &rm.reg)) {
		usage = BASIC_OP_USED_NEITHER;
		LOG("legacy 8 bit high");
		clear_register(&rm.state);
		truncate_to_16bit(&rm.state);
	} else {
		truncate_to_8bit(&rm.state);
		struct register_state src;
		set_register(&src, *ins_modrm);
		LOG("basic immediate of ", src.value);
		usage = op(&rm.state, &src, rm.reg, -1, OPERATION_SIZE_BYTE, additional);
		truncate_to_8bit(&rm.state);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_8bit(&additional->state);
		merge_and_log_additional_result(loader, &rm.state, additional, rm.reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, rm.state)));
	}
	regs->registers[rm.reg] = rm.state;
	update_sources_for_basic_op_usage(regs, rm.reg, REGISTER_INVALID, register_is_partially_known_8bit(&rm.state) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, rm.reg, ins_modrm);
	return (struct basic_op_result){
		.reg = rm.reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

static void perform_basic_op_al_imm8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, ins_ptr imm, struct additional_result *additional)
{
	int reg = REGISTER_RAX;
	LOG("basic ", name, " operation dest: ", name_for_register(reg));
	dump_registers(loader, regs, mask_for_register(reg));
	struct register_state dest = regs->registers[reg];
	truncate_to_8bit(&dest);
	struct register_state src;
	set_register(&src, *imm);
	LOG("immediate of ", src.value);
	additional->used = false;
	enum basic_op_usage usage = op(&dest, &src, reg, -1, OPERATION_SIZE_BYTE, additional);
	truncate_to_8bit(&dest);
	if (UNLIKELY(additional->used)) {
		truncate_to_8bit(&additional->state);
		merge_and_log_additional_result(loader, &dest, additional, REGISTER_RAX);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, dest)));
	}
	regs->registers[reg] = dest;
	update_sources_for_basic_op_usage(regs, reg, REGISTER_INVALID, register_is_partially_known_8bit(&dest) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, reg, imm);
}

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_rm_imm(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                          ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, imm_size_for_prefixes(prefixes), regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(rm.reg));
	dump_registers(loader, regs, mask_for_register(rm.reg));
	truncate_to_size_prefixes(&rm.state, prefixes);
	struct register_state src;
	set_register(&src, read_imm(prefixes, ins_modrm));
	LOG("immediate of ", src.value);
	additional->used = false;
	uintptr_t orig_value = rm.state.value;
	enum ins_operand_size size = operand_size_from_prefixes(prefixes);
	enum basic_op_usage usage = op(&rm.state, &src, rm.reg, -1, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &rm.state, additional, orig_value);
	} else {
		truncate_to_size_prefixes(&rm.state, prefixes);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_size_prefixes(&additional->state, prefixes);
		merge_and_log_additional_result(loader, &rm.state, additional, rm.reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, rm.state)));
	}
	regs->registers[rm.reg] = rm.state;
	update_sources_for_basic_op_usage(regs, rm.reg, rm.reg, register_is_partially_known_size_prefixes(&rm.state, prefixes) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, rm.reg, ins_modrm);
	return (struct basic_op_result){
		.reg = rm.reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_r_rm_imm(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                            ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	int reg = x86_read_reg(x86_read_modrm(ins_modrm), prefixes);
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, imm_size_for_prefixes(prefixes), regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(reg), " operand: ", name_for_register(rm.reg));
	dump_registers(loader, regs, mask_for_register(rm.reg));
	truncate_to_size_prefixes(&rm.state, prefixes);
	struct register_state src;
	set_register(&src, read_imm(prefixes, ins_modrm));
	LOG("immediate of ", src.value);
	additional->used = false;
	uintptr_t orig_value = rm.state.value;
	enum ins_operand_size size = operand_size_from_prefixes(prefixes);
	enum basic_op_usage usage = op(&rm.state, &src, rm.reg, -1, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &rm.state, additional, orig_value);
	} else {
		truncate_to_size_prefixes(&rm.state, prefixes);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_size_prefixes(&additional->state, prefixes);
		merge_and_log_additional_result(loader, &rm.state, additional, reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, rm.state)));
	}
	regs->registers[reg] = rm.state;
	update_sources_for_basic_op_usage(regs, reg, rm.reg, register_is_partially_known_size_prefixes(&rm.state, prefixes) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, reg, ins_modrm);
	return (struct basic_op_result){
		.reg = reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

static void perform_basic_op_imm(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes, int reg, ins_ptr imm, struct additional_result *additional)
{
	LOG("basic ", name, " operation dest: ", name_for_register(reg));
	dump_registers(loader, regs, mask_for_register(reg));
	struct register_state dest = regs->registers[reg];
	truncate_to_size_prefixes(&dest, prefixes);
	struct register_state src;
	set_register(&src, read_imm(prefixes, imm));
	LOG("immediate of ", src.value);
	additional->used = false;
	uintptr_t orig_value = dest.value;
	enum ins_operand_size size = operand_size_from_prefixes(prefixes);
	enum basic_op_usage usage = op(&dest, &src, reg, -1, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &dest, additional, orig_value);
	} else {
		truncate_to_size_prefixes(&dest, prefixes);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_size_prefixes(&additional->state, prefixes);
		merge_and_log_additional_result(loader, &dest, additional, reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, dest)));
	}
	regs->registers[reg] = dest;
	update_sources_for_basic_op_usage(regs, reg, REGISTER_INVALID, register_is_partially_known_size_prefixes(&dest, prefixes) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, reg, imm);
}

__attribute__((warn_unused_result)) static struct basic_op_result perform_basic_op_rm_imm8(__attribute__((unused)) const char *name, basic_op op, struct loader_context *loader, struct registers *regs, struct x86_ins_prefixes prefixes,
                                                                                           ins_ptr ins_modrm, trace_flags trace_flags, struct additional_result *additional)
{
	struct rm_result rm = read_rm_ref(loader, prefixes, &ins_modrm, sizeof(int8_t), regs, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
	LOG("basic ", name, " operation dest: ", name_for_register(rm.reg));
	dump_registers(loader, regs, mask_for_register(rm.reg));
	truncate_to_size_prefixes(&rm.state, prefixes);
	struct register_state src;
	int8_t imm = *(const int8_t *)ins_modrm;
	if (prefixes.has_w) { // sign extend to 64-bits
		set_register(&src, (int64_t)imm);
	} else if (prefixes.has_operand_size_override) { // sign extend to 16-bits
		set_register(&src, (int16_t)imm);
	} else { // sign extend to 32-bits
		set_register(&src, (int32_t)imm);
	}
	LOG("immediate of ", src.value);
	additional->used = false;
	uintptr_t orig_value = rm.state.value;
	enum ins_operand_size size = operand_size_from_prefixes(prefixes);
	enum basic_op_usage usage = op(&rm.state, &src, rm.reg, -1, size, additional);
	if (size == OPERATION_SIZE_DWORD) {
		widen_cross_binary_bound_operation(loader, &rm.state, additional, orig_value);
	} else {
		truncate_to_size_prefixes(&rm.state, prefixes);
	}
	if (UNLIKELY(additional->used)) {
		truncate_to_size_prefixes(&additional->state, prefixes);
		merge_and_log_additional_result(loader, &rm.state, additional, rm.reg);
	} else {
		LOG("result: ", temp_str(copy_register_state_description(loader, rm.state)));
	}
	regs->registers[rm.reg] = rm.state;
	update_sources_for_basic_op_usage(regs, rm.reg, REGISTER_INVALID, register_is_partially_known_size_prefixes(&rm.state, prefixes) ? usage : BASIC_OP_USED_NEITHER);
	clear_match(loader, regs, rm.reg, ins_modrm);
	return (struct basic_op_result){
		.reg = rm.reg,
		.faults = rm.faults,
		.fault_sources = rm.faults ? rm.sources : 0,
	};
}

static bool lookup_table_jump_is_valid(const struct loaded_binary *binary, const struct frame_details *frame_details, const ElfW(Sym) * function_symbol, ins_ptr jump)
{
	if (frame_details != NULL) {
		return (frame_details->address <= (const void *)jump) && ((const void *)jump < frame_details->address + frame_details->size);
	} else if (function_symbol != NULL) {
		return (binary->info.base + function_symbol->st_value <= (const void *)jump) && ((const void *)jump < binary->info.base + function_symbol->st_value + function_symbol->st_size);
	} else {
		return (binary->info.base <= (const void *)jump) && ((const void *)jump < binary->info.base + binary->info.size);
	}
}

bool analyze_instructions_arch(struct program_state *analysis, function_effects required_effects, function_effects *effects, ins_ptr ins, const struct analysis_frame *caller, trace_flags trace_flags, struct analysis_frame *self, struct x86_instruction *decoded)
{
	struct additional_result additional;
	int additional_reg;
#define CHECK_FAULT(fault, sources)                                                                                  \
	do {                                                                                                             \
		if (UNLIKELY(fault)) {                                                                                       \
			LOG("exiting because memory access was certain to fail");                                                \
			vary_effects_by_registers(&analysis->search, &analysis->loader, self, sources, 0, 0, required_effects); \
			*effects = (*effects | EFFECT_EXITS) & ~EFFECT_RETURNS;                                                    \
			goto update_and_return;                                                                                  \
		}                                                                                                            \
	} while (0)
#define CHECK_BASIC_OP_FAULT(expression)                                \
	({                                                                  \
		struct basic_op_result _fault_result = expression;              \
		CHECK_FAULT(_fault_result.faults, _fault_result.fault_sources); \
		_fault_result.reg;                                              \
	})
#define CHECK_RM_FAULT(rm) CHECK_FAULT(rm.faults, rm.sources)
	switch (*decoded->unprefixed) {
		case 0x00: { // add r/m8, r8
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r_8("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x01: { // add r/m, r
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x02: { // add r8, r/m8
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_8("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x03: { // add r, r/m
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x04: { // add al, imm8
			perform_basic_op_al_imm8("add", basic_op_add, &analysis->loader, &self->current_state, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x05: { // add *ax, imm
			perform_basic_op_imm("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, REGISTER_RAX, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x06:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x07:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x08: { // or r/m8, r8
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r_8("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x09: { // or r/m, r
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x0a: { // or r8, r/m8
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_8("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x0b: { // or r, r/m
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x0c: { // or al, imm8
			perform_basic_op_al_imm8("or", basic_op_or, &analysis->loader, &self->current_state, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x0d: { // or *ax, imm
			perform_basic_op_imm("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, REGISTER_RAX, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x0e:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x0f:
			switch (decoded->unprefixed[1]) {
				case 0x00: {
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					switch (modrm.reg) {
						case 0: // sldt r/m16
						case 1: { // str r/m16
							ins_ptr remaining = &decoded->unprefixed[2];
							struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_HALF, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
							CHECK_RM_FAULT(rm);
							struct register_state state;
							clear_register(&state);
							truncate_to_16bit(&state);
							self->current_state.registers[rm.reg] = state;
							self->current_state.sources[rm.reg] = 0;
							clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
							break;
						}
						case 2: // lldt r/m16
							break;
						case 3: // ltr r/m16
							break;
						case 4: // verr r/m16
							clear_comparison_state(&self->current_state);
							break;
						case 5: // verw r/m16
							clear_comparison_state(&self->current_state);
							break;
						default:
							LOG("invalid opcode extension for 0x0f00: ", (int)modrm.reg);
							break;
					}
					break;
				}
				case 0x01: {
					switch (decoded->unprefixed[2]) {
						case 0xf9: // rdtscp
							clear_register(&self->current_state.registers[REGISTER_RAX]);
							truncate_to_32bit(&self->current_state.registers[REGISTER_RAX]);
							clear_register(&self->current_state.registers[REGISTER_RDX]);
							truncate_to_32bit(&self->current_state.registers[REGISTER_RDX]);
							clear_register(&self->current_state.registers[REGISTER_RCX]);
							truncate_to_32bit(&self->current_state.registers[REGISTER_RCX]);
							self->current_state.sources[REGISTER_RAX] = 0;
							self->current_state.sources[REGISTER_RDX] = 0;
							self->current_state.sources[REGISTER_RCX] = 0;
							clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
							clear_match(&analysis->loader, &self->current_state, REGISTER_RDX, ins);
							clear_match(&analysis->loader, &self->current_state, REGISTER_RCX, ins);
							break;
					}
					break;
				}
				case 0x05: { // syscall
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
				case 0x0b: // ud2
					*effects |= EFFECT_EXITS;
					LOG("completing from ud2: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					goto update_and_return;
				case 0x0d: // noop
					break;
				case 0x11: { // movups xmm/m, xmm
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DWORD, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg >= REGISTER_MEM) {
						LOG("movups to mem: ", name_for_register(rm.reg));
						struct register_state value;
						x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
						if (x86_read_reg(modrm, decoded->prefixes) == REGISTER_R15 && binary_has_flags(binary_for_address(&analysis->loader, ins), BINARY_IS_GOLANG)) {
							set_register(&value, 0);
							LOG("found golang 0 register");
						} else {
							clear_register(&value);
							LOG("assuming any value");
						}
						self->current_state.registers[rm.reg] = value;
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
						self->pending_stack_clear &= ~mask_for_register(rm.reg);
						if (rm.reg >= REGISTER_STACK_0 && rm.reg < REGISTER_COUNT - 2) {
							self->current_state.registers[rm.reg + 2] = value;
							self->current_state.sources[rm.reg + 2] = 0;
							clear_match(&analysis->loader, &self->current_state, rm.reg + 2, ins);
							self->pending_stack_clear &= ~mask_for_register(rm.reg + 2);
						}
					}
					goto skip_stack_clear;
				}
				case 0x2c: { // cvttss2si r, xmm
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0x2d: { // cvttsd2si r, xmm
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0x2e: { // ucomiss xmm, xmm/m
					clear_comparison_state(&self->current_state);
					break;
				}
				case 0x2f: { // comiss xmm, xmm/m
					clear_comparison_state(&self->current_state);
					break;
				}
				case 0x31: // rdtsc
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					truncate_to_32bit(&self->current_state.registers[REGISTER_RAX]);
					self->current_state.sources[REGISTER_RAX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					clear_register(&self->current_state.registers[REGISTER_RDX]);
					truncate_to_32bit(&self->current_state.registers[REGISTER_RDX]);
					self->current_state.sources[REGISTER_RDX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RDX, ins);
					break;
				case 0x38:
					switch (decoded->unprefixed[2]) {
						case 0x17: { // ptest
							clear_comparison_state(&self->current_state);
							break;
						}
						case 0xf0: { // movbe r, r/m or crc32 r, r/m8
							x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[3]);
							int reg = x86_read_reg(modrm, decoded->prefixes);
							clear_register(&self->current_state.registers[reg]);
							self->current_state.sources[reg] = 0;
							clear_match(&analysis->loader, &self->current_state, reg, ins);
							break;
						}
						case 0xf1: {
							x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[3]);
							if (decoded->prefixes.has_repne) { // crc32 r, r/m
								int reg = x86_read_reg(modrm, decoded->prefixes);
								clear_register(&self->current_state.registers[reg]);
								self->current_state.sources[reg] = 0;
								clear_match(&analysis->loader, &self->current_state, reg, ins);
							} else { // movbe r/m, r
								ins_ptr remaining = &decoded->unprefixed[3];
								struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
								CHECK_RM_FAULT(rm);
								clear_register(&self->current_state.registers[rm.reg]);
								self->current_state.sources[rm.reg] = 0;
								clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
							}
							break;
						}
					}
					break;
				case 0x3a:
					switch (decoded->unprefixed[2]) {
						case 0x14: { // pextrb r/m8, xmm2, imm8
							ins_ptr remaining = &decoded->unprefixed[3];
							struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_BYTE, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
							CHECK_RM_FAULT(rm);
							if (rm.reg != REGISTER_INVALID) {
								bool is_legacy = register_is_legacy_8bit_high(decoded->prefixes, &rm.reg);
								clear_register(&self->current_state.registers[rm.reg]);
								if (is_legacy) {
									truncate_to_16bit(&self->current_state.registers[rm.reg]);
								} else {
									truncate_to_8bit(&self->current_state.registers[rm.reg]);
								}
								self->current_state.sources[rm.reg] = 0;
								clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
							}
							break;
						}
						case 0x16: { // pextrd/q r/m, xmm2, imm8
							ins_ptr remaining = &decoded->unprefixed[3];
							struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
							CHECK_RM_FAULT(rm);
							if (rm.reg != REGISTER_INVALID) {
								clear_register(&self->current_state.registers[rm.reg]);
								truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
								self->current_state.sources[rm.reg] = 0;
								clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
							}
							break;
						}
						case 0x17: { // extractps r/m32, xmm1, imm8
							ins_ptr remaining = &decoded->unprefixed[3];
							struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_WORD, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
							CHECK_RM_FAULT(rm);
							if (rm.reg != REGISTER_INVALID) {
								clear_register(&self->current_state.registers[rm.reg]);
								truncate_to_32bit(&self->current_state.registers[rm.reg]);
								self->current_state.sources[rm.reg] = 0;
								clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
							}
							break;
						}
						case 0x60: { // pcmpestrm
							clear_comparison_state(&self->current_state);
							break;
						}
						case 0x61: { // pcmpestri xmm1, xmm2/m128, imm8
							clear_register(&self->current_state.registers[REGISTER_RCX]);
							truncate_to_32bit(&self->current_state.registers[REGISTER_RCX]);
							self->current_state.sources[REGISTER_RCX] = 0;
							clear_match(&analysis->loader, &self->current_state, REGISTER_RCX, ins);
							clear_comparison_state(&self->current_state);
							break;
						}
						case 0x62: { // pcmpistrm
							clear_comparison_state(&self->current_state);
							break;
						}
						case 0x63: { // pcmpistri xmm1, xmm2/m128, imm8
							clear_register(&self->current_state.registers[REGISTER_RCX]);
							truncate_to_32bit(&self->current_state.registers[REGISTER_RCX]);
							self->current_state.sources[REGISTER_RCX] = 0;
							clear_match(&analysis->loader, &self->current_state, REGISTER_RCX, ins);
							clear_comparison_state(&self->current_state);
							break;
						}
					}
					break;
				case 0x40: // cmovcc
				case 0x41:
				case 0x42:
				case 0x43:
				case 0x44:
				case 0x45:
				case 0x46:
				case 0x47:
				case 0x48:
				case 0x49:
				case 0x4a:
				case 0x4b:
				case 0x4c:
				case 0x4d:
				case 0x4e:
				case 0x4f: {
					LOG("found cmovcc");
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int dest = x86_read_reg(modrm, decoded->prefixes);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					LOG("from ", name_for_register(rm.reg), " to ", name_for_register(dest));
					dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest) | mask_for_register(rm.reg));
					switch (calculate_possible_conditions(&analysis->loader, x86_get_conditional_type(&decoded->unprefixed[1]), &self->current_state)) {
						case ALWAYS_MATCHES:
							LOG("conditional always matches");
							self->current_state.registers[dest] = rm.state;
							add_match_and_sources(&analysis->loader, &self->current_state, dest, rm.reg, rm.sources, ins);
							self->current_state.sources[dest] |= self->current_state.compare_state.sources;
							break;
						case NEVER_MATCHES:
							LOG("conditional never matches");
							self->current_state.sources[dest] |= self->current_state.compare_state.sources;
							break;
						case POSSIBLY_MATCHES:
							LOG("conditional sometimes matches");
							if (combine_register_states(&self->current_state.registers[dest], &rm.state, dest)) {
								self->current_state.sources[dest] |= rm.sources;
								clear_match(&analysis->loader, &self->current_state, dest, ins);
							} else {
								ins = next_ins(ins, decoded);
								ANALYZE_PRIMARY_RESULT();
								self->current_state.registers[dest] = rm.state;
								add_match_and_sources(&analysis->loader, &self->current_state, dest, rm.reg, rm.sources, ins);
								goto use_alternate_result;
							}
							break;
					}
					break;
				}
				case 0x57: { // xorps xmm1, xmm2/m128
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					if (x86_modrm_is_direct(modrm) && reg == x86_read_rm(modrm, decoded->prefixes)) {
						LOG("found xor of ", name_for_register(reg), " with self in SSE, zeroing idiom");
						ins_ptr lookahead = next_ins(ins, decoded);
						struct decoded_ins lookahead_decoded;
						if (decode_ins(lookahead, &lookahead_decoded)) {
							LOG("lookahead: ", temp_str(copy_address_description(&analysis->loader, lookahead)), " of length ", lookahead_decoded.length);
							if (lookahead_decoded.unprefixed[0] == 0x0f && lookahead_decoded.unprefixed[1] == 0x11) { // movups xmm2/m128, xmm1
								x86_mod_rm_t lookahead_modrm = x86_read_modrm(&lookahead_decoded.unprefixed[2]);
								if (reg == x86_read_reg(lookahead_modrm, lookahead_decoded.prefixes)) {
									ins_ptr lookahead_temp = lookahead;
									struct rm_result lookahead_rm =
										read_rm_ref(&analysis->loader, lookahead_decoded.prefixes, &lookahead_temp, 0, &self->current_state, OPERATION_SIZE_DWORD, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
									CHECK_RM_FAULT(lookahead_rm);
									LOG("found xorps+movps, zeroing idiom to ", name_for_register(lookahead_rm.reg));
									set_register(&self->current_state.registers[lookahead_rm.reg], 0);
									self->current_state.sources[lookahead_rm.reg] = 0;
									clear_match(&analysis->loader, &self->current_state, lookahead_rm.reg, ins);
									if (lookahead_rm.reg >= REGISTER_STACK_0 && lookahead_rm.reg < REGISTER_COUNT - 2) {
										LOG("zeroing idiom was to the stack, zeroing the next register ", name_for_register(lookahead_rm.reg + 2), " as well");
										set_register(&self->current_state.registers[lookahead_rm.reg + 2], 0);
										self->current_state.sources[lookahead_rm.reg + 2] = 0;
										clear_match(&analysis->loader, &self->current_state, lookahead_rm.reg + 2, ins);
									}
									// skip the lookahead
									self->description = "zeroing idiom";
									*effects |= analyze_instructions(analysis, required_effects, &self->current_state, lookahead, self, trace_flags) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
									return true;
								}
							}
						}
					}
					break;
				}
				case 0x7e: { // movd/q r/m, mm
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg != REGISTER_INVALID) {
						clear_register(&self->current_state.registers[rm.reg]);
						if (!decoded->prefixes.has_w) {
							truncate_to_32bit(&self->current_state.registers[rm.reg]);
						}
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
						self->pending_stack_clear &= ~mask_for_register(rm.reg);
					}
					goto skip_stack_clear;
				}
				case 0x80: // conditional jumps
				case 0x81:
				case 0x82:
				case 0x83:
				case 0x84:
				case 0x85:
				case 0x86:
				case 0x87:
				case 0x88:
				case 0x89:
				case 0x8a:
				case 0x8b:
				case 0x8c:
				case 0x8d:
				case 0x8e:
				case 0x8f: {
					break;
				}
				case 0x90:
				case 0x91:
				case 0x92:
				case 0x93:
				case 0x94:
				case 0x95:
				case 0x96:
				case 0x97:
				case 0x98:
				case 0x99:
				case 0x9a:
				case 0x9b:
				case 0x9c:
				case 0x9d:
				case 0x9e:
				case 0x9f: {
					LOG("found setcc at ", temp_str(copy_address_description(&analysis->loader, ins)));
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					LOG("to ", name_for_register(rm.reg));
					switch (calculate_possible_conditions(&analysis->loader, x86_get_conditional_type(&decoded->unprefixed[1]), &self->current_state)) {
						case ALWAYS_MATCHES:
							LOG("conditional always matches");
							self->current_state.registers[rm.reg].value = 1;
							self->current_state.registers[rm.reg].max = 1;
							self->current_state.sources[rm.reg] = self->current_state.compare_state.sources;
							break;
						case NEVER_MATCHES:
							LOG("conditional never matches");
							self->current_state.registers[rm.reg].value = 0;
							self->current_state.registers[rm.reg].max = 0;
							self->current_state.sources[rm.reg] = self->current_state.compare_state.sources;
							break;
						case POSSIBLY_MATCHES:
							LOG("conditional sometimes matches");
							self->current_state.registers[rm.reg].value = 0;
							self->current_state.registers[rm.reg].max = 1;
							self->current_state.sources[rm.reg] = 0;
							break;
					}
					clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					break;
				}
				case 0xa0: { // push fs
					push_stack(&analysis->loader, &self->current_state, 2, ins);
					dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
					break;
				}
				case 0xa1: { // pop fs
					pop_stack(&analysis->loader, &self->current_state, 2, ins);
					dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
					break;
				}
				case 0xa2: { // cpuid
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					truncate_to_32bit(&self->current_state.registers[REGISTER_RAX]);
					self->current_state.sources[REGISTER_RAX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					clear_register(&self->current_state.registers[REGISTER_RBX]);
					truncate_to_32bit(&self->current_state.registers[REGISTER_RBX]);
					self->current_state.sources[REGISTER_RBX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RBX, ins);
					clear_register(&self->current_state.registers[REGISTER_RCX]);
					truncate_to_32bit(&self->current_state.registers[REGISTER_RCX]);
					self->current_state.sources[REGISTER_RCX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RCX, ins);
					clear_register(&self->current_state.registers[REGISTER_RDX]);
					truncate_to_32bit(&self->current_state.registers[REGISTER_RDX]);
					self->current_state.sources[REGISTER_RDX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RDX, ins);
					break;
				}
				case 0xa3: { // bt r/m, r
					clear_comparison_state(&self->current_state);
					break;
				}
				case 0xa4: { // shld r/m, r, imm8
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg != REGISTER_INVALID) {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					}
					break;
				}
				case 0xa5: { // shld r/m, r, cl
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg != REGISTER_INVALID) {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					}
					break;
				}
				case 0xa8: { // push gs
					push_stack(&analysis->loader, &self->current_state, 2, ins);
					dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
					break;
				}
				case 0xa9: { // pop gs
					pop_stack(&analysis->loader, &self->current_state, 2, ins);
					dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
					break;
				}
				case 0xab: { // bts r/m, r
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg != REGISTER_INVALID) {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					}
					break;
				}
				case 0xac: { // shrd r/m, r, imm8
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg != REGISTER_INVALID) {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					}
					break;
				}
				case 0xad: { // shrd r/m, r, cl
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg != REGISTER_INVALID) {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					}
					break;
				}
				case 0xaf: { // imul r, r/m
					clear_comparison_state(&self->current_state);
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					truncate_to_size_prefixes(&self->current_state.registers[reg], decoded->prefixes);
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xb0: { // cmpxchg r/m8, r8
					clear_comparison_state(&self->current_state);
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					truncate_to_8bit(&self->current_state.registers[REGISTER_RAX]);
					self->current_state.sources[REGISTER_RAX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_16bit(&self->current_state.registers[rm.reg]);
					} else {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_8bit(&self->current_state.registers[rm.reg]);
					}
					self->current_state.sources[rm.reg] = 0;
					clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					// TODO: check why this happens only in golang
					// if (self->current_state.stack_address_taken == STACK_ADDRESS_TAKEN_GOLANG) {
					// 	clear_stack(&self->current_state, ins);
					// }
					break;
				}
				case 0xb1: { // cmpxchg r/m, r
					clear_comparison_state(&self->current_state);
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					truncate_to_size_prefixes(&self->current_state.registers[REGISTER_RAX], decoded->prefixes);
					self->current_state.sources[REGISTER_RAX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
					self->current_state.sources[rm.reg] = 0;
					clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					// TODO: check why this happens only in golang
					// if (self->current_state.stack_address_taken == STACK_ADDRESS_TAKEN_GOLANG) {
					// 	clear_stack(&self->current_state, ins);
					// }
					break;
				}
				case 0xb2: { // lss
					LOG("found lss");
					int dest = x86_read_reg(x86_read_modrm(&decoded->unprefixed[2]), decoded->prefixes);
					LOG("to ", name_for_register(dest));
					clear_register(&self->current_state.registers[dest]);
					truncate_to_size_prefixes(&self->current_state.registers[dest], decoded->prefixes);
					self->current_state.sources[dest] = 0;
					clear_match(&analysis->loader, &self->current_state, dest, ins);
					break;
				}
				case 0xb3: { // btr r/m, r
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					clear_register(&self->current_state.registers[rm.reg]);
					truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
					self->current_state.sources[rm.reg] = 0;
					clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					break;
				}
				case 0xb4: { // lfs
					LOG("found lfs");
					int dest = x86_read_reg(x86_read_modrm(&decoded->unprefixed[2]), decoded->prefixes);
					LOG("to ", name_for_register(dest));
					clear_register(&self->current_state.registers[dest]);
					truncate_to_size_prefixes(&self->current_state.registers[dest], decoded->prefixes);
					self->current_state.sources[dest] = 0;
					clear_match(&analysis->loader, &self->current_state, dest, ins);
					break;
				}
				case 0xb5: { // lgs
					LOG("found lgs");
					int dest = x86_read_reg(x86_read_modrm(&decoded->unprefixed[2]), decoded->prefixes);
					LOG("to ", name_for_register(dest));
					clear_register(&self->current_state.registers[dest]);
					truncate_to_size_prefixes(&self->current_state.registers[dest], decoded->prefixes);
					self->current_state.sources[dest] = 0;
					clear_match(&analysis->loader, &self->current_state, dest, ins);
					break;
				}
				case 0xb6: // movzx r, r/m8
				case 0xb7: { // movzx r, r/m16
					LOG("found movzx");
					int dest = x86_read_reg(x86_read_modrm(&decoded->unprefixed[2]), decoded->prefixes);
					LOG("to ", name_for_register(dest));
					ins_ptr remaining = &decoded->unprefixed[2];
					int source_size = decoded->unprefixed[1] == 0xb6 ? OPERATION_SIZE_BYTE : OPERATION_SIZE_HALF;
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, source_size, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					LOG("from ", name_for_register(rm.reg));
					uintptr_t mask = source_size == OPERATION_SIZE_BYTE ? 0xff : 0xffff;
					if (rm.reg == REGISTER_INVALID || (source_size == OPERATION_SIZE_BYTE ? register_is_legacy_8bit_high(decoded->prefixes, &rm.reg) : false)) {
						clear_register(&rm.state);
					}
					if (rm.reg == REGISTER_MEM) {
						LOG("decoded mem r/m: ", temp_str(copy_memory_ref_description(&analysis->loader, self->current_state.mem_ref)));
						if (self->current_state.mem_ref.rm == REGISTER_STACK_0 && self->current_state.mem_ref.index != REGISTER_SP) {
							int base = self->current_state.mem_ref.base;
							int index = self->current_state.mem_ref.index;
							uintptr_t base_addr = self->current_state.registers[base].value + self->current_state.mem_ref.addr;
							uintptr_t value = self->current_state.registers[index].value;
							uintptr_t max = self->current_state.registers[index].max;
							struct loaded_binary *mov_binary;
							if (protection_for_address(&analysis->loader, (const void *)(base_addr + value * sizeof(uint32_t)), &mov_binary, NULL) & PROT_READ) {
								if (max - value > MAX_LOOKUP_TABLE_SIZE) {
									LOG("unsigned lookup table rejected because range of index is too large: ", max - value);
									self->description = "rejected lookup table";
									LOG("trace: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
									*effects |= EFFECT_RETURNS;
								} else {
									self->description = "lookup table";
									vary_effects_by_registers(&analysis->search,
									                          &analysis->loader,
									                          self,
									                          mask_for_register(base) | mask_for_register(index),
									                          mask_for_register(base) /* | mask_for_register(index)*/,
									                          mask_for_register(base) /* | mask_for_register(index)*/,
									                          required_effects);
									LOG("unsigned lookup table from known base: ", temp_str(copy_address_description(&analysis->loader, (void *)base_addr)));
									dump_registers(&analysis->loader, &self->current_state, mask_for_register(base) | mask_for_register(index));
									struct registers copy = self->current_state;
									copy.sources[dest] = self->current_state.sources[base] | self->current_state.sources[index];
									clear_match(&analysis->loader, &copy, dest, ins);
									ins_ptr continue_target = next_ins(ins, decoded);
									for (uintptr_t i = value; i != max + 1; i++) {
										LOG("processing table index ", i, " with value ", (intptr_t)((ins_ptr)base_addr)[i], " and target: ", temp_str(copy_address_description(&analysis->loader, (void *)base_addr + ((ins_ptr)base_addr)[i])), " (if jump table)");
										if (index != dest) {
											set_register(&copy.registers[index], i);
											for_each_bit (copy.matches[index], bit, r) {
												set_register(&copy.registers[r], i);
											}
										}
										set_register(&copy.registers[dest], dest);
										*effects |= analyze_instructions(analysis, required_effects, &copy, continue_target, self, 0) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
										LOG("next table case for ", temp_str(copy_address_description(&analysis->loader, self->address)));
									}
									LOG("completing from lookup table: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
									goto update_and_return;
								}
							}
						}
					}
					self->current_state.registers[dest] = rm.state;
					add_match_and_sources(&analysis->loader, &self->current_state, dest, rm.reg, rm.sources, ins);
					if (register_is_exactly_known(&self->current_state.registers[dest]) || (register_is_partially_known(&self->current_state.registers[dest]) && self->current_state.registers[dest].max <= mask)) {
						// zero extension where we can provide a range
						self->current_state.registers[dest].value &= mask;
						self->current_state.registers[dest].max &= mask;
					} else {
						// zero extension of indeterminate value leaves only the mask
						self->current_state.registers[dest].value = 0;
						self->current_state.registers[dest].max = mask;
					}
					dump_registers(&analysis->loader, &self->current_state, mask_for_register(dest));
					break;
				}
				case 0xb8: { // popcnt r, r/m
					clear_comparison_state(&self->current_state);
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					self->current_state.registers[reg].value = 0;
					if (decoded->prefixes.has_w) {
						self->current_state.registers[reg].max = 64;
					} else if (decoded->prefixes.has_operand_size_override) {
						self->current_state.registers[reg].max = 16;
					} else {
						self->current_state.registers[reg].max = 32;
					}
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xb9:
					*effects |= EFFECT_EXITS;
					LOG("completing from ud1: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					goto update_and_return;
				case 0xba: {
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					switch (modrm.reg) {
						case 4: // bt r/m, imm8
						case 5: // bts r/m, imm8
						case 6: // btr r/m, imm8
						case 7: { // btc r/m, imm8
							clear_comparison_state(&self->current_state);
							ins_ptr remaining = &decoded->unprefixed[2];
							struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
							CHECK_RM_FAULT(rm);
							if (rm.reg != REGISTER_INVALID) {
								clear_register(&self->current_state.registers[rm.reg]);
								truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
								self->current_state.sources[rm.reg] = 0;
								clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
							}
							break;
						}
					}
					break;
				}
				case 0xbb: { // btc r/m, r
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg != REGISTER_INVALID) {
						clear_register(&self->current_state.registers[rm.reg]);
						truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
						self->current_state.sources[rm.reg] = 0;
						clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					}
					break;
				}
				case 0xbc: // bsf r, r/m or tzcnt r, r/m
				case 0xbd: { // bsr r, r/m
					if (decoded->unprefixed[1] == 0xbc) {
						if (decoded->prefixes.has_rep) {
							LOG("tzcnt");
						} else {
							LOG("bsf");
						}
					} else {
						LOG("bsr");
					}
					clear_comparison_state(&self->current_state);
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					self->current_state.registers[reg].value = 0;
					if (decoded->prefixes.has_w) {
						self->current_state.registers[reg].max = 63;
					} else if (decoded->prefixes.has_operand_size_override) {
						self->current_state.registers[reg].max = 15;
					} else {
						self->current_state.registers[reg].max = 31;
					}
					if (decoded->prefixes.has_rep) { // tzcnt
						self->current_state.registers[reg].max++;
					}
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xbe: { // movsx r, r/m8
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					LOG("movsx r to ", name_for_register(reg), " from r/m8: ", name_for_register(rm.reg));
					if (!register_is_legacy_8bit_high(decoded->prefixes, &rm.reg) && self->current_state.registers[rm.reg].max < 0x80 && register_is_partially_known_8bit(&self->current_state.registers[rm.reg])) {
						self->current_state.registers[reg] = self->current_state.registers[rm.reg];
						add_match_and_sources(&analysis->loader, &self->current_state, reg, rm.reg, rm.sources, ins);
						break;
					}
					clear_register(&self->current_state.registers[reg]);
					truncate_to_size_prefixes(&self->current_state.registers[reg], decoded->prefixes);
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xbf: { // movsx r, r/m
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					LOG("movsx r to ", name_for_register(reg), " from r/m: ", name_for_register(rm.reg));
					if (self->current_state.registers[rm.reg].max < 0x8000 && register_is_partially_known_16bit(&self->current_state.registers[rm.reg])) {
						self->current_state.registers[reg] = self->current_state.registers[rm.reg];
						add_match_and_sources(&analysis->loader, &self->current_state, reg, rm.reg, rm.sources, ins);
						break;
					}
					clear_register(&self->current_state.registers[reg]);
					truncate_to_size_prefixes(&self->current_state.registers[reg], decoded->prefixes);
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xc0: { // xadd r/m8, r8
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					clear_register(&self->current_state.registers[rm.reg]);
					if (!register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
						truncate_to_8bit(&self->current_state.registers[rm.reg]);
					}
					self->current_state.sources[rm.reg] = 0;
					clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					if (!register_is_legacy_8bit_high(decoded->prefixes, &reg)) {
						truncate_to_8bit(&self->current_state.registers[reg]);
					}
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xc1: { // xadd r/m, r
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[2];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					clear_register(&self->current_state.registers[rm.reg]);
					truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
					self->current_state.sources[rm.reg] = 0;
					clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					truncate_to_size_prefixes(&self->current_state.registers[reg], decoded->prefixes);
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xc5: { // pextrw reg, mm, imm8
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					truncate_to_size_prefixes(&self->current_state.registers[reg], decoded->prefixes);
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xc7: {
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					switch (modrm.reg) {
						case 1: // cmpxchg8/16b m64
							clear_comparison_state(&self->current_state);
							clear_register(&self->current_state.registers[REGISTER_RAX]);
							if (!decoded->prefixes.has_w) {
								truncate_to_32bit(&self->current_state.registers[REGISTER_RAX]);
							}
							self->current_state.sources[REGISTER_RAX] = 0;
							clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
							clear_register(&self->current_state.registers[REGISTER_RDX]);
							if (!decoded->prefixes.has_w) {
								truncate_to_32bit(&self->current_state.registers[REGISTER_RDX]);
							}
							self->current_state.sources[REGISTER_RDX] = 0;
							clear_match(&analysis->loader, &self->current_state, REGISTER_RDX, ins);
							break;
					}
					break;
				}
				case 0xc8: // bswap
				case 0xc9:
				case 0xca:
				case 0xcb:
				case 0xcc:
				case 0xcd:
				case 0xce:
				case 0xcf: {
					int reg = x86_read_opcode_register_index(decoded->unprefixed[1], 0xc8, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					if (!decoded->prefixes.has_w) {
						truncate_to_32bit(&self->current_state.registers[reg]);
					}
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xd7: { // pmovmskb reg, mm
					x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[2]);
					int reg = x86_read_reg(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[reg]);
					if (decoded->prefixes.has_operand_size_override) {
						truncate_to_16bit(&self->current_state.registers[reg]);
					} else {
						truncate_to_8bit(&self->current_state.registers[reg]);
					}
					self->current_state.sources[reg] = 0;
					clear_match(&analysis->loader, &self->current_state, reg, ins);
					break;
				}
				case 0xff:
					*effects |= EFFECT_EXITS;
					LOG("completing from ud0: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					goto update_and_return;
			}
			break;
		case 0x10: { // adc r/m8, r8
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r_8("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x11: { // adc r/m, r
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x12: { // adc r8, r/m8
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_8("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x13: { // adc r, r/m
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x14: { // adc al, imm8
			perform_basic_op_al_imm8("adc", basic_op_adc, &analysis->loader, &self->current_state, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x15: { // adc *ax, imm
			perform_basic_op_imm("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, REGISTER_RAX, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x16:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x17:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x18: { // sbb r/m8, r8
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r_8("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x19: { // sbb r/m, r
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x1a: { // sbb r8, r/m8
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_8("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x1b: { // sbb r, r/m
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x1c: { // sbb al, imm8
			perform_basic_op_al_imm8("sbb", basic_op_sbb, &analysis->loader, &self->current_state, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x1d: { // sbb *ax, imm
			perform_basic_op_imm("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, REGISTER_RAX, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x1e:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x1f:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x20: { // and r/m8, r8
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r_8("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x21: { // and r/m, r
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x22: { // and r8, r/m8
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_8("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x23: { // and r, r/m
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x24: { // and al, imm8
			perform_basic_op_al_imm8("and", basic_op_and, &analysis->loader, &self->current_state, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x25: { // and *ax, imm
			perform_basic_op_imm("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, REGISTER_RAX, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x26:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x27:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x28: { // sub r/m8, r8
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r_8("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
			set_compare_from_operation(&self->current_state, rm, 0xff);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x29: { // sub r/m, r
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
			set_compare_from_operation(&self->current_state, rm, mask_for_size_prefixes(decoded->prefixes));
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x2a: { // sub r8, r/m8
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_8("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
			set_compare_from_operation(&self->current_state, reg, 0xff);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x2b: { // sub r, r/m
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
			set_compare_from_operation(&self->current_state, reg, mask_for_size_prefixes(decoded->prefixes));
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x2c: { // sub al, imm8
			perform_basic_op_al_imm8("sub", basic_op_sub, &analysis->loader, &self->current_state, &decoded->unprefixed[1], &additional);
			// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
			set_compare_from_operation(&self->current_state, REGISTER_RAX, 0xff);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x2d: { // sub *ax, imm
			perform_basic_op_imm("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, REGISTER_RAX, &decoded->unprefixed[1], &additional);
			// sub is equivalent to a comparison with 0, since it refers to the value after the subtraction
			set_compare_from_operation(&self->current_state, REGISTER_RAX, mask_for_size_prefixes(decoded->prefixes));
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			break;
		}
		case 0x2e:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x2f:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x30: { // xor r/m8, r8
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r_8("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x31: { // xor r/m, r
			int rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_r("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			goto skip_stack_clear;
		}
		case 0x32: { // xor r8, r/m8
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_8("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			goto skip_stack_clear;
		}
		case 0x33: { // xor r, r/m
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			goto skip_stack_clear;
		}
		case 0x34: { // xor al, imm8
			perform_basic_op_al_imm8("xor", basic_op_xor, &analysis->loader, &self->current_state, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			goto skip_stack_clear;
		}
		case 0x35: { // xor *ax, imm
			perform_basic_op_imm("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, REGISTER_RAX, &decoded->unprefixed[1], &additional);
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(REGISTER_RAX);
			goto skip_stack_clear;
		}
		case 0x36: // null prefix
			break;
		case 0x37:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x38: { // cmp r/m8, r8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			struct register_state comparator = self->current_state.registers[reg];
			truncate_to_size_prefixes(&comparator, decoded->prefixes);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			uintptr_t mask = mask_for_size_prefixes(decoded->prefixes);
			set_comparison_state(&analysis->loader,
			                     &self->current_state,
			                     (struct register_comparison){
									 .target_register = rm.reg,
									 .value = comparator,
									 .mask = mask,
									 .mem_ref = self->current_state.mem_ref,
									 .sources = self->current_state.sources[reg],
									 .validity = COMPARISON_SUPPORTS_ANY,
								 });
			break;
		}
		case 0x39: { // cmp r/m, r
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			struct register_state comparator = self->current_state.registers[reg];
			truncate_to_size_prefixes(&comparator, decoded->prefixes);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			uintptr_t mask = mask_for_size_prefixes(decoded->prefixes);
			set_comparison_state(&analysis->loader,
			                     &self->current_state,
			                     (struct register_comparison){
									 .target_register = rm.reg,
									 .value = comparator,
									 .mask = mask,
									 .mem_ref = self->current_state.mem_ref,
									 .sources = self->current_state.sources[reg],
									 .validity = COMPARISON_SUPPORTS_ANY,
								 });
			break;
		}
		case 0x3a: { // cmp r8, r/m8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
				clear_comparison_state(&self->current_state);
				break;
			}
			truncate_to_8bit(&rm.state);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			if (register_is_legacy_8bit_high(decoded->prefixes, &reg)) {
				clear_comparison_state(&self->current_state);
				break;
			}
			set_comparison_state(&analysis->loader,
			                     &self->current_state,
			                     (struct register_comparison){
									 .target_register = reg,
									 .value = rm.state,
									 .mask = 0xff,
									 .mem_ref = self->current_state.mem_ref,
									 .sources = rm.sources,
									 .validity = COMPARISON_SUPPORTS_ANY,
								 });
			break;
		}
		case 0x3b: { // cmp r, r/m
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			truncate_to_size_prefixes(&rm.state, decoded->prefixes);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			uintptr_t mask = mask_for_size_prefixes(decoded->prefixes);
			set_comparison_state(&analysis->loader,
			                     &self->current_state,
			                     (struct register_comparison){
									 .target_register = reg,
									 .value = rm.state,
									 .mask = mask,
									 .mem_ref = self->current_state.mem_ref,
									 .sources = rm.sources,
									 .validity = COMPARISON_SUPPORTS_ANY,
								 });
			break;
		}
		case 0x3c: { // cmp al, imm8
			struct register_state comparator;
			comparator.value = comparator.max = (uintptr_t)*(const int8_t *)&decoded->unprefixed[1] & 0xff;
			set_comparison_state(&analysis->loader,
			                     &self->current_state,
			                     (struct register_comparison){
									 .target_register = REGISTER_RAX,
									 .value = comparator,
									 .mask = 0xff,
									 .mem_ref = self->current_state.mem_ref,
									 .sources = 0,
									 .validity = COMPARISON_SUPPORTS_ANY,
								 });
			break;
		}
		case 0x3d: { // cmp r, imm
			uintptr_t mask = mask_for_size_prefixes(decoded->prefixes);
			struct register_state comparator;
			if (decoded->prefixes.has_operand_size_override) {
				comparator.value = (*(const ins_uint16 *)&decoded->unprefixed[1]) & mask;
			} else {
				comparator.value = (decoded->prefixes.has_w ? (uintptr_t)*(const ins_int32 *)&decoded->unprefixed[1] : (uintptr_t)*(const ins_uint32 *)&decoded->unprefixed[1]) & mask;
			}
			comparator.max = comparator.value;
			set_comparison_state(&analysis->loader,
			                     &self->current_state,
			                     (struct register_comparison){
									 .target_register = REGISTER_RAX,
									 .value = comparator,
									 .mask = mask,
									 .mem_ref = self->current_state.mem_ref,
									 .sources = 0,
									 .validity = COMPARISON_SUPPORTS_ANY,
								 });
			break;
		}
		case 0x3e: // null prefix
			break;
		case 0x3f:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x40: // rex
			break;
		case 0x41: // rex.b
			break;
		case 0x42: // rex.x
			break;
		case 0x43: // rex.xb
			break;
		case 0x44: // rex.r
			break;
		case 0x45: // rex.rb
			break;
		case 0x46: // rex.rx
			break;
		case 0x47: // rex.rxb
			break;
		case 0x48: // rex.w
			break;
		case 0x49: // rex.wb
			break;
		case 0x4a: // rex.wx
			break;
		case 0x4b: // rex.wxb
			break;
		case 0x4c: // rex.wr
			break;
		case 0x4d: // rex.wrb
			break;
		case 0x4e: // rex.wrx
			break;
		case 0x4f: // rex.wrxb
			break;
		case 0x50: // push
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57: {
			int reg = x86_read_opcode_register_index(*decoded->unprefixed, 0x50, decoded->prefixes);
			LOG("push of ", name_for_register(reg));
			if (trace_flags & TRACE_USES_FRAME_POINTER) {
				if (self->current_state.matches[REGISTER_SP] & mask_for_register(REGISTER_RBP)) {
					LOG("detaching stack frame pointer link");
					clear_match_keep_stack(&analysis->loader, &self->current_state, REGISTER_SP, ins);
				} else {
					LOG("clearing stack because this function was using the frame pointer");
					clear_stack(&self->current_state, ins);
					trace_flags &= ~TRACE_USES_FRAME_POINTER;
				}
			}
			if (decoded->prefixes.has_operand_size_override) {
				clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			} else {
				push_stack(&analysis->loader, &self->current_state, 2, ins);
			}
			self->current_state.registers[REGISTER_STACK_0] = self->current_state.registers[reg];
			self->current_state.sources[REGISTER_STACK_0] = self->current_state.sources[reg];
			if (decoded->prefixes.has_operand_size_override) {
				truncate_to_16bit(&self->current_state.registers[REGISTER_STACK_0]);
			}
			dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
			break;
		}
		case 0x58: // pop
		case 0x59:
		case 0x5a:
		case 0x5b:
		case 0x5c:
		case 0x5d:
		case 0x5e:
		case 0x5f: {
			int reg = x86_read_opcode_register_index(*decoded->unprefixed, 0x58, decoded->prefixes);
			LOG("pop to ", name_for_register(reg));
			self->current_state.registers[reg] = self->current_state.registers[REGISTER_STACK_0];
			self->current_state.sources[reg] = self->current_state.sources[REGISTER_STACK_0];
			if (decoded->prefixes.has_operand_size_override) {
				truncate_to_16bit(&self->current_state.registers[REGISTER_STACK_0]);
			}
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			if (decoded->prefixes.has_operand_size_override) {
				clear_match(&analysis->loader, &self->current_state, REGISTER_SP, ins);
			} else {
				pop_stack(&analysis->loader, &self->current_state, 2, ins);
			}
			dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
			break;
		}
		case 0x60:
		case 0x61:
		case 0x62:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x63: {
			// found movsxd
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			LOG("movsxd to ", name_for_register(reg));
			bool requires_known_target = false;
			if (modrm.mod != 0x3 && (modrm.rm == REGISTER_R12 || modrm.rm == REGISTER_SP)) {
				// read SIB
				x86_sib_t sib = x86_read_sib(&decoded->unprefixed[2]);
				int base = x86_read_base(sib, decoded->prefixes);
				int index = x86_read_index(sib, decoded->prefixes);
				LOG("movsxd dest:", name_for_register(reg), " base: ", name_for_register(base), " index: ", name_for_register(index), " scale: ", (int)1 << sib.scale);
				dump_registers(&analysis->loader, &self->current_state, mask_for_register(base) | mask_for_register(index));
				if (sib.scale == 0x2) {
					int32_t displacement = 0;
					switch (modrm.mod) {
						case 0:
							// no displacement
							break;
						case 1:
							// 8 bit displacement
							displacement = *(int8_t *)&decoded->unprefixed[3];
							break;
						case 2:
							// 32 bit displacement
							displacement = *(ins_int32 *)&decoded->unprefixed[3];
							break;
					}
					struct registers copy = self->current_state;
					uintptr_t base_addr = 0;
					if (register_is_exactly_known(&self->current_state.registers[base])) {
						base_addr = self->current_state.registers[base].value + displacement;
						LOG("storing base address: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
						add_lookup_table_base_address(&analysis->search.lookup_base_addresses, ins, base_addr);
					}
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
						set_register(&copy.registers[base], base_addr);
						clear_match(&analysis->loader, &copy, base, ins);
						copy.sources[base] = 0;
						clear_match(&analysis->loader, &self->current_state, base, ins);
						self->current_state.sources[base] = 0;
					}
					if (base_addr != 0) {
						uintptr_t value = self->current_state.registers[index].value;
						uintptr_t max = self->current_state.registers[index].max;
						// const void *first_entry_addr = (const void *)(base_addr + value * sizeof(uint32_t));
						struct loaded_binary *binary;
						LOG("looking up protection for base: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
						const ElfW(Shdr) * section;
						int prot = protection_for_address(&analysis->loader, (const void *)base_addr, &binary, &section);
						if ((prot & (PROT_READ | PROT_WRITE)) == PROT_READ) {
							// enforce max range from other lea instructions
							uintptr_t next_base_address = search_find_next_address(&analysis->search.loaded_addresses, base_addr);
							uintptr_t last_base_index = (next_base_address - base_addr) / sizeof(int32_t) - 1;
							if (last_base_index < max) {
								LOG("truncating to next base address of ", temp_str(copy_address_description(&analysis->loader, (const void *)next_base_address)), "; new max is ", last_base_index);
								max = last_base_index;
							}
							uintptr_t max_in_section = ((uintptr_t)apply_base_address(&binary->info, section->sh_addr) + section->sh_size - base_addr) / 4;
							if (max >= max_in_section) {
								max = max_in_section - 1;
								if (value >= max_in_section) {
									LOG("somehow in a jump table without a proper value, bailing");
									goto update_and_return;
								}
							}
							struct frame_details frame_details = {0};
							bool has_frame_details = binary->has_frame_info ? find_containing_frame_info(&binary->frame_info, ins, &frame_details) : false;
							if ((max - value > MAX_LOOKUP_TABLE_SIZE) && !has_frame_details) {
								LOG("signed lookup table rejected because range of index is too large: ", max - value);
								dump_registers(&analysis->loader, &self->current_state, mask_for_register(base) | mask_for_register(index));
								self->description = "rejected lookup table";
								LOG("trace: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
								requires_known_target = true;
								*effects |= EFFECT_RETURNS;
							} else {
								self->description = "lookup table";
								vary_effects_by_registers(&analysis->search,
								                          &analysis->loader,
								                          self,
								                          mask_for_register(base) | mask_for_register(index),
								                          mask_for_register(base) | mask_for_register(index),
								                          mask_for_register(base) /* | mask_for_register(index)*/,
								                          required_effects);
								LOG("signed lookup table from known base: ", temp_str(copy_address_description(&analysis->loader, (void *)base_addr)));
								dump_registers(&analysis->loader, &self->current_state, mask_for_register(base) | mask_for_register(index));
								copy.sources[reg] = self->current_state.sources[base] | self->current_state.sources[index];
								clear_match(&analysis->loader, &copy, reg, ins);
								copy.requires_known_target |= mask_for_register(reg);
								ins_ptr continue_target = next_ins(ins, decoded);
								const ElfW(Sym) *function_symbol = NULL;
								find_any_symbol_by_address(&analysis->loader, binary, ins, NORMAL_SYMBOL | LINKER_SYMBOL, NULL, &function_symbol);
								for (uintptr_t i = value; i <= max; i++) {
									LOG("processing table index: ", (intptr_t)i);
									int32_t relative = ((const ins_int32 *)base_addr)[i];
									LOG("processing table value: ", (intptr_t)relative);
									ins_ptr jump_addr = (ins_ptr)base_addr + relative;
									LOG("processing table target (if jump table): ", temp_str(copy_address_description(&analysis->loader, jump_addr)));
									if (!lookup_table_jump_is_valid(binary, has_frame_details ? &frame_details : NULL, function_symbol, jump_addr)) {
										LOG("detected jump table index ", i, " beyond bounds, truncating");
										break;
									}
									if (index != reg) {
										set_register(&copy.registers[index], i);
										for_each_bit (copy.matches[index], bit, r) {
											set_register(&copy.registers[r], i);
										}
									}
									set_register(&copy.registers[reg], relative);
									*effects |= analyze_instructions(analysis, required_effects, &copy, continue_target, self, trace_flags) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS);
									LOG("next table case for: ", temp_str(copy_address_description(&analysis->loader, self->address)));
									// re-enforce max range from other lea instructions that may have loaded addresses in the meantime
									next_base_address = search_find_next_address(&analysis->search.loaded_addresses, base_addr);
									last_base_index = (next_base_address - base_addr) / sizeof(int32_t) - 1;
									if (last_base_index < max) {
										max = last_base_index;
									}
								}
								LOG("completing from lookup table: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
								goto update_and_return;
							}
						} else {
							if ((prot & PROT_READ) == 0) {
								LOG("lookup table from unreadable base: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
							} else {
								LOG("lookup table from writable base: ", temp_str(copy_address_description(&analysis->loader, (const void *)base_addr)));
							}
						}
					} else {
						LOG("lookup table from unknown base");
					}
				} else {
					LOG("invalid scale for lookup table");
				}
			}
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			truncate_to_32bit(&rm.state);
			if (register_is_exactly_known(&rm.state)) {
				set_register(&self->current_state.registers[reg], sign_extend(rm.state.value, OPERATION_SIZE_WORD));
				// TODO: read sources for case where rm is REGISTER_INVALID
				self->current_state.sources[reg] = rm.sources;
			} else if (rm.state.max < 0x80000000) {
				self->current_state.registers[reg] = rm.state;
				self->current_state.sources[reg] = rm.sources;
			} else if (rm.state.value & rm.state.max & 0x80000000) {
				self->current_state.registers[reg].value = sign_extend(rm.state.value, OPERATION_SIZE_WORD);
				self->current_state.registers[reg].max = sign_extend(rm.state.max, OPERATION_SIZE_WORD);
				self->current_state.sources[reg] = rm.sources;
			} else {
				clear_register(&self->current_state.registers[reg]);
				self->current_state.sources[reg] = 0;
			}
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			if (requires_known_target) {
				self->current_state.requires_known_target |= mask_for_register(reg);
			}
			break;
		}
		case 0x64: // FS segment override prefix
			break;
		case 0x65: // GS segment override prefix
			break;
		case 0x66: // operand size override prefix
			break;
		case 0x67: // address size override prefix
			break;
		case 0x68: { // push imm
			uint64_t imm = read_imm(decoded->prefixes, &decoded->unprefixed[1]);
			LOG("push ", imm);
			if (trace_flags & TRACE_USES_FRAME_POINTER) {
				LOG("clearing stack because this function was using the frame pointer");
				clear_stack(&self->current_state, ins);
				trace_flags &= ~TRACE_USES_FRAME_POINTER;
			}
			push_stack(&analysis->loader, &self->current_state, 2, ins);
			set_register(&self->current_state.registers[REGISTER_STACK_0], imm);
			break;
		}
		case 0x69: { // imul r, r/m, imm
			int reg = CHECK_BASIC_OP_FAULT(perform_basic_op_r_rm_imm("imul", basic_op_mul, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg);
			break;
		}
		case 0x6a: { // push imm8
			uint8_t imm = *(const uint8_t *)&decoded->unprefixed[1];
			LOG("push ", (uintptr_t)imm);
			if (trace_flags & TRACE_USES_FRAME_POINTER) {
				LOG("clearing stack because this function was using the frame pointer");
				clear_stack(&self->current_state, ins);
				trace_flags &= ~TRACE_USES_FRAME_POINTER;
			}
			push_stack(&analysis->loader, &self->current_state, 2, ins);
			set_register(&self->current_state.registers[REGISTER_STACK_0], imm);
			break;
		}
		case 0x6b: { // imul r, r/m, imm8
			clear_comparison_state(&self->current_state);
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			LOG("imul to ", name_for_register(reg));
			clear_register(&self->current_state.registers[reg]);
			self->current_state.sources[reg] = 0;
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			break;
		}
		case 0x6c: // insb
		case 0x6d: // outs
			// TODO: handle the ins family of instructions
			break;
		case 0x6e: // outsb
		case 0x6f: // outs
			// TODO: handle the outs family of instructions
			break;
		case 0x70: // jo
			break;
		case 0x71: // jno
			break;
		case 0x72: // jb/jnae/jc
			break;
		case 0x73: // jnb/jae/jnc
			break;
		case 0x74: // jz/je
			break;
		case 0x75: // jnz/jne
			break;
		case 0x76: // jbe/jna
			break;
		case 0x77: // jbne/ja
			break;
		case 0x78: // js
			break;
		case 0x79: // jns
			break;
		case 0x7a: // jp/jpe
			break;
		case 0x7b: // jnp/jpo
			break;
		case 0x7c: // jl/jnge
			break;
		case 0x7d: // jnl/jge
			break;
		case 0x7e: // jle/jng
			break;
		case 0x7f: // jnle/jg
			break;
		case 0x80: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int rm;
			switch (modrm.reg) {
				case 0: // add r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 1: // or r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 2: // adc r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 3: // sbb r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 4: // and r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 5: // sub r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					set_compare_from_operation(&self->current_state, rm, 0xff);
					break;
				case 6: // xor r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 7: { // cmp r/m, imm8
					ins_ptr remaining = &decoded->unprefixed[1];
					struct rm_result rm_res = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(uint8_t), &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm_res);
					if (register_is_legacy_8bit_high(decoded->prefixes, &rm_res.reg)) {
						clear_comparison_state(&self->current_state);
					} else {
						struct register_state comparator;
						comparator.value = comparator.max = *(ins_ptr)remaining;
						set_comparison_state(&analysis->loader,
						                     &self->current_state,
						                     (struct register_comparison){
												 .target_register = rm_res.reg,
												 .value = comparator,
												 .mask = 0xff,
												 .mem_ref = self->current_state.mem_ref,
												 .sources = 0,
												 .validity = COMPARISON_SUPPORTS_ANY,
											 });
					}
					additional.used = false;
					rm = REGISTER_INVALID;
					break;
				}
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x81: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int rm;
			switch (modrm.reg) {
				case 0: // add r/m, imm
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 1: // or r/m, imm
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 2: // adc r/m, imm
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 3: // sbb r/m, imm
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 4: // and r/m, imm
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 5: // sub r/m, imm
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					set_compare_from_operation(&self->current_state, rm, mask_for_size_prefixes(decoded->prefixes));
					break;
				case 6: // xor r/m, imm
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 7: { // cmp r/m, imm
					ins_ptr remaining = &decoded->unprefixed[1];
					uintptr_t mask = mask_for_size_prefixes(decoded->prefixes);
					struct register_state comparator;
					struct rm_result rm_res;
					if (decoded->prefixes.has_operand_size_override) {
						rm_res = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int16_t), &self->current_state, OPERATION_SIZE_HALF, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
						comparator.value = comparator.max = (uintptr_t)*(const ins_uint16 *)remaining & mask;
					} else {
						rm_res = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int32_t), &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
						comparator.value = comparator.max = (decoded->prefixes.has_w ? (uintptr_t)*(const ins_int32 *)remaining : (uintptr_t)*(const ins_uint32 *)remaining) & mask;
					}
					CHECK_RM_FAULT(rm_res);
					set_comparison_state(&analysis->loader,
					                     &self->current_state,
					                     (struct register_comparison){
											 .target_register = rm_res.reg,
											 .value = comparator,
											 .mask = mask,
											 .mem_ref = self->current_state.mem_ref,
											 .sources = 0,
											 .validity = COMPARISON_SUPPORTS_ANY,
										 });
					additional.used = false;
					rm = REGISTER_INVALID;
					break;
				}
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x82:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x83: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int rm;
			switch (modrm.reg) {
				case 0: { // add r/m, imm8
					if (decoded->prefixes.has_w && modrm.mod == 0x3 && x86_read_rm(modrm, decoded->prefixes) == REGISTER_SP) {
						// handle stack operations
						int8_t imm = *(const int8_t *)&decoded->unprefixed[2];
						if ((imm & 0x3) == 0) {
							if (trace_flags & TRACE_USES_FRAME_POINTER) {
								LOG("skipping stack increment because this function is using the frame pointer");
								rm = REGISTER_INVALID;
								break;
							}
							if (imm <= 0) {
								push_stack(&analysis->loader, &self->current_state, -(imm >> 2), ins);
							} else {
								pop_stack(&analysis->loader, &self->current_state, imm >> 2, ins);
							}
							struct register_state src;
							set_register(&src, imm);
							additional.used = false;
							(void)basic_op_add(&self->current_state.registers[REGISTER_SP], &src, REGISTER_SP, -1, OPERATION_SIZE_DWORD, &additional);
							if (additional.used) {
								clear_register(&self->current_state.registers[REGISTER_SP]);
							}
							canonicalize_register(&self->current_state.registers[REGISTER_SP]);
							dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
							clear_comparison_state(&self->current_state);
							additional.used = false;
							rm = REGISTER_INVALID;
							break;
						}
					}
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("add", basic_op_add, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				}
				case 1: // or r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("or", basic_op_or, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 2: // adc r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("adc", basic_op_adc, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 3: // sbb r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("sbb", basic_op_sbb, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 4: // and r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("and", basic_op_and, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 5: { // sub r/m, imm8
					if (decoded->prefixes.has_w && modrm.mod == 0x3 && x86_read_rm(modrm, decoded->prefixes) == REGISTER_SP) {
						// handle stack operations
						int8_t imm = *(const int8_t *)&decoded->unprefixed[2];
						if ((imm & 0x3) == 0) {
							if (trace_flags & TRACE_USES_FRAME_POINTER) {
								LOG("skipping stack decrement because this function is using the frame pointer");
								rm = REGISTER_INVALID;
								break;
							}
							if (imm <= 0) {
								pop_stack(&analysis->loader, &self->current_state, -(imm >> 2), ins);
							} else {
								push_stack(&analysis->loader, &self->current_state, imm >> 2, ins);
							}
							struct register_state src;
							set_register(&src, imm);
							additional.used = false;
							(void)basic_op_sub(&self->current_state.registers[REGISTER_SP], &src, REGISTER_SP, -1, OPERATION_SIZE_DWORD, &additional);
							if (additional.used) {
								clear_register(&self->current_state.registers[REGISTER_SP]);
							}
							canonicalize_register(&self->current_state.registers[REGISTER_SP]);
							dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
							self->current_state.compare_state.validity = COMPARISON_IS_INVALID;
							additional.used = false;
							rm = REGISTER_INVALID;
							break;
						}
					}
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("sub", basic_op_sub, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					set_compare_from_operation(&self->current_state, rm, mask_for_size_prefixes(decoded->prefixes));
					break;
				}
				case 6: // xor r/m, imm8
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("xor", basic_op_xor, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					clear_comparison_state(&self->current_state);
					break;
				case 7: { // cmp r/m, imm8
					ins_ptr remaining = &decoded->unprefixed[1];
					struct rm_result rm_res = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm_res);
					uintptr_t mask = mask_for_size_prefixes(decoded->prefixes);
					struct register_state comparator;
					comparator.value = comparator.max = (uintptr_t)*(const int8_t *)remaining & mask;
					set_comparison_state(&analysis->loader,
					                     &self->current_state,
					                     (struct register_comparison){
											 .target_register = rm_res.reg,
											 .value = comparator,
											 .mask = mask,
											 .mem_ref = self->current_state.mem_ref,
											 .sources = 0,
											 .validity = COMPARISON_SUPPORTS_ANY,
										 });
					additional.used = false;
					rm = REGISTER_INVALID;
					break;
				}
			}
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0x84: { // test r/m8, r8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			if (x86_modrm_is_direct(modrm) && reg == x86_read_rm(modrm, decoded->prefixes)) {
				if (register_is_legacy_8bit_high(decoded->prefixes, &reg)) {
					clear_comparison_state(&self->current_state);
				} else {
					LOG("found test ", name_for_register(reg));
					struct register_state comparator;
					comparator.value = comparator.max = 0;
					set_comparison_state(&analysis->loader,
					                     &self->current_state,
					                     (struct register_comparison){
											 .target_register = reg,
											 .value = comparator,
											 .mask = 0xff,
											 .mem_ref = self->current_state.mem_ref,
											 .sources = 0,
											 .validity = COMPARISON_SUPPORTS_EQUALITY,
										 });
				}
			} else {
				clear_comparison_state(&self->current_state);
			}
			break;
		}
		case 0x85: { // test r/m, r
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			if (x86_modrm_is_direct(modrm) && reg == x86_read_rm(modrm, decoded->prefixes)) {
				LOG("found test ", name_for_register(reg));
				struct register_state comparator;
				comparator.value = comparator.max = 0;
				set_comparison_state(&analysis->loader,
				                     &self->current_state,
				                     (struct register_comparison){
										 .target_register = reg,
										 .value = comparator,
										 .mask = mask_for_size_prefixes(decoded->prefixes),
										 .mem_ref = self->current_state.mem_ref,
										 .sources = 0,
										 .validity = COMPARISON_SUPPORTS_EQUALITY,
									 });
			} else {
				clear_comparison_state(&self->current_state);
			}
			break;
		}
		case 0x86: { // xchg r8, r/m8
			clear_comparison_state(&self->current_state);
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			bool reg_is_legacy = register_is_legacy_8bit_high(decoded->prefixes, &reg);
			struct register_state dest = self->current_state.registers[reg];
			if (reg_is_legacy) {
				clear_register(&dest);
			}
			truncate_to_8bit(&dest);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			bool rm_is_legacy = register_is_legacy_8bit_high(decoded->prefixes, &rm.reg);
			if (rm_is_legacy) {
				clear_register(&dest);
			}
			truncate_to_8bit(&rm.state);
			self->current_state.registers[reg] = rm.state;
			if (reg_is_legacy) {
				clear_register(&self->current_state.registers[reg]);
			}
			self->current_state.registers[rm.reg] = dest;
			if (rm_is_legacy) {
				clear_register(&self->current_state.registers[rm.reg]);
			}
			self->current_state.sources[rm.reg] = self->current_state.sources[reg];
			self->current_state.sources[reg] = rm.sources;
			clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			self->pending_stack_clear &= ~mask_for_register(rm.reg);
			break;
		}
		case 0x87: { // xchg r, r/m
			clear_comparison_state(&self->current_state);
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			struct register_state dest = self->current_state.registers[reg];
			truncate_to_size_prefixes(&dest, decoded->prefixes);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			truncate_to_size_prefixes(&rm.state, decoded->prefixes);
			self->current_state.registers[reg] = rm.state;
			self->current_state.registers[rm.reg] = dest;
			self->current_state.sources[rm.reg] = self->current_state.sources[reg];
			self->current_state.sources[reg] = rm.sources;
			clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			self->pending_stack_clear &= ~mask_for_register(rm.reg);
			break;
		}
		case 0x88: { // mov r/m8, r8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			LOG("mov r/m8 to ", name_for_register(rm.reg), " from r8: ", name_for_register(reg));
			if (reg == REGISTER_SP) {
				record_stack_address_taken(&analysis->loader, ins, &self->current_state);
			}
			struct register_state source = self->current_state.registers[reg];
			if (register_is_legacy_8bit_high(decoded->prefixes, &reg)) {
				clear_register(&source);
			}
			truncate_to_8bit(&source);
			if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
				clear_register(&source);
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			} else {
				add_match_and_sources(&analysis->loader, &self->current_state, rm.reg, reg, self->current_state.sources[reg], ins);
			}
			self->current_state.registers[rm.reg] = source;
			if (register_is_partially_known_8bit(&source)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source)));
				self->current_state.sources[rm.reg] = 0;
			}
			self->pending_stack_clear &= ~mask_for_register(rm.reg);
			goto skip_stack_clear;
		}
		case 0x89: { // mov r/m, r
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			LOG("mov r/m to ", name_for_register(rm.reg), " from r: ", name_for_register(reg));
			if (reg == REGISTER_SP) {
				if (rm.reg == REGISTER_RBP) {
					trace_flags |= TRACE_USES_FRAME_POINTER;
					LOG("function is using the frame pointer");
				} else {
					record_stack_address_taken(&analysis->loader, ins, &self->current_state);
				}
			}
			struct register_state source = self->current_state.registers[reg];
			if (register_is_exactly_known(&source) && source.value > mask_for_size_prefixes(decoded->prefixes) && binary_for_address(&analysis->loader, (const void *)source.value) != NULL) {
				clear_register(&source);
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
				self->current_state.sources[rm.reg] = 0;
			} else {
				add_match_and_sources(&analysis->loader, &self->current_state, rm.reg, reg, self->current_state.sources[reg], ins);
			}
			truncate_to_size_prefixes(&source, decoded->prefixes);
			self->current_state.registers[rm.reg] = source;
			if (register_is_partially_known_size_prefixes(&source, decoded->prefixes)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, source)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, source)));
				self->current_state.sources[rm.reg] = 0;
			}
			self->pending_stack_clear &= ~mask_for_register(rm.reg);
			goto skip_stack_clear;
		}
		case 0x8a: { // mov r8, r/m8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			LOG("mov r8 to: ", name_for_register(reg), " from r/m8: ", name_for_register(rm.reg));
			if (SHOULD_LOG) {
				if (UNLIKELY(self->pending_stack_clear) && rm.reg >= REGISTER_STACK_0) {
					LOG("mov from stack after a call, assuming reload of stack spill");
				}
			}
			if (rm.reg != REGISTER_INVALID) {
				self->pending_stack_clear &= ~mask_for_register(rm.reg);
			}
			if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
				clear_register(&rm.state);
			}
			truncate_to_8bit(&rm.state);
			if (register_is_legacy_8bit_high(decoded->prefixes, &reg)) {
				clear_register(&rm.state);
				truncate_to_16bit(&rm.state);
				clear_match(&analysis->loader, &self->current_state, reg, ins);
				self->current_state.sources[reg] = 0;
			} else {
				add_match_and_sources(&analysis->loader, &self->current_state, reg, rm.reg, rm.sources, ins);
			}
			self->current_state.registers[reg] = rm.state;
			if (register_is_partially_known_8bit(&rm.state)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, rm.state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, rm.state)));
				self->current_state.sources[reg] = 0;
			}
			goto skip_stack_clear;
		}
		case 0x8b: { // mov r, r/m
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int reg = x86_read_reg(modrm, decoded->prefixes);
			LOG("mov r to ", name_for_register(reg));
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			LOG("from r/m ", name_for_register(rm.reg));
			if (SHOULD_LOG) {
				if (UNLIKELY(self->pending_stack_clear) && rm.reg >= REGISTER_STACK_0) {
					LOG("mov from stack after a call, assuming reload of stack spill");
				}
			}
			self->pending_stack_clear &= ~mask_for_register(rm.reg);
			if (register_is_exactly_known(&rm.state) && rm.state.value > mask_for_size_prefixes(decoded->prefixes) && binary_for_address(&analysis->loader, (const void *)rm.state.value) != NULL) {
				clear_register(&rm.state);
				truncate_to_size_prefixes(&rm.state, decoded->prefixes);
				clear_match(&analysis->loader, &self->current_state, reg, ins);
				self->current_state.sources[reg] = self->current_state.sources[rm.reg];
			} else {
				add_match_and_sources(&analysis->loader, &self->current_state, reg, rm.reg, rm.sources, ins);
			}
			self->current_state.registers[reg] = rm.state;
			if (register_is_partially_known_size_prefixes(&rm.state, decoded->prefixes)) {
				LOG("value is known: ", temp_str(copy_register_state_description(&analysis->loader, rm.state)));
			} else {
				LOG("value is unknown: ", temp_str(copy_register_state_description(&analysis->loader, rm.state)));
				self->current_state.sources[reg] = 0;
			}
			goto skip_stack_clear;
		}
		case 0x8c: { // mov r/m, Sreg
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			clear_register(&self->current_state.registers[rm.reg]);
			truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
			self->current_state.sources[rm.reg] = 0;
			clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			self->pending_stack_clear &= ~mask_for_register(rm.reg);
			break;
		}
		case 0x8d: { // lea r, r/m (only indirect!)
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			LOG("found lea");
			if (x86_modrm_is_direct(modrm)) {
				self->description = NULL;
				LOG("lea with direct addressing mode at ", temp_str(copy_call_trace_description(&analysis->loader, self)));
				break;
			}
			int reg = x86_read_reg(modrm, decoded->prefixes);
			LOG("lea to ", name_for_register(reg));
			struct register_state_and_source new_value = address_for_indirect(*decoded, modrm, &self->current_state, &decoded->unprefixed[2], &analysis->loader, ins, NULL);
			// when an address is taken to the stack, clear all of the stack entries
			if (new_value.source & mask_for_register(REGISTER_SP)) {
				// if (reg == REGISTER_RBP) {
				// 	LOG("ignoring address of stack (since it's to rbp): ", temp_str(copy_address_description(&analysis->loader, self->address)));
				// } else
				record_stack_address_taken(&analysis->loader, self->address, &self->current_state);
				*effects |= EFFECT_MODIFIES_STACK;
			}
			self->current_state.registers[reg] = new_value.state;
			self->current_state.sources[reg] = new_value.source;
			dump_registers(&analysis->loader, &self->current_state, mask_for_register(reg));
			truncate_to_size_prefixes(&self->current_state.registers[reg], decoded->prefixes);
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			if (register_is_partially_known(&new_value.state)) {
				LOG("loaded address: ", temp_str(copy_register_state_description(&analysis->loader, new_value.state)));
				self->description = "load address";
				vary_effects_by_registers(&analysis->search, &analysis->loader, self, new_value.source, 0, 0, required_effects);
			}
			if (decoded->prefixes.has_w) {
				if (register_is_exactly_known(&self->current_state.registers[reg])) {
					ins_ptr address = (ins_ptr)self->current_state.registers[reg].value;
					struct loaded_binary *binary = binary_for_address(&analysis->loader, address);
					if (binary == NULL) {
						LOG("rip-relative lea is to unknown binary");
						break;
					}
					int prot = protection_for_address_in_binary(binary, (uintptr_t)address, NULL);
					if (prot & PROT_EXEC) {
						if (address[0] == 0x98 && address[1] == 0x2f && address[2] == 0x8a && address[3] == 0x42 && address[4] == 0x91) {
							LOG("discarding lea into openssl's K256 table");
							clear_register(&self->current_state.registers[reg]);
							self->current_state.sources[reg] = 0;
						} else if (address[0] == 0x5b && address[1] == 0xc2 && address[2] == 0x56 && address[3] == 0x39 && address[4] == 0x5b) {
							// see: https://github.com/openssl/openssl/blob/master/crypto/sha/asm/sha256-mb-x86_64.pl#L291
							LOG("discarding lea into offset 128 of openssl's K256 table");
							clear_register(&self->current_state.registers[reg]);
							self->current_state.sources[reg] = 0;
						} else if (address[0] == 0x5b && address[1] == 0xc2 && address[2] == 0x56 && address[3] == 0x39 && address[4] == 0x5b) {
							// see: https://github.com/openssl/openssl/blob/master/crypto/sha/asm/sha256-mb-x86_64.pl#L291
							LOG("discarding lea into offset 128 of openssl's K256 table");
							clear_register(&self->current_state.registers[reg]);
							self->current_state.sources[reg] = 0;
						} else {
							self->description = "load address";
							if (required_effects & EFFECT_ENTRY_POINT) {
								if (reg == sysv_argument_abi_register_indexes[0]) {
									// main
									analysis->main = (uintptr_t)address;
									LOG("rip-relative lea is to executable address, assuming it is the main function");
									self->description = "load main address";
									struct registers registers = empty_registers;
									analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, address, self);
								} else if (reg == sysv_argument_abi_register_indexes[3]) {
									// init, will be called before main, can skip it
								} else if (reg == sysv_argument_abi_register_indexes[4] || reg == sysv_argument_abi_register_indexes[5]) {
									LOG("rip-relative lea is to executable address, assuming it is the finit function");
									struct registers registers = empty_registers;
									analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, address, self);
								} else {
									LOG("rip-relative lea is to executable address, assuming it could be called during startup");
									struct registers registers = empty_registers;
									analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, address, self);
								}
							} else {
								LOG("rip-relative lea is to executable address, assuming it could be called after startup");
								if (*effects & EFFECT_ENTER_CALLS) {
									if (!check_for_searched_function(&analysis->loader, address)) {
										queue_instruction(&analysis->search.queue,
										                  address,
										                  ((binary->special_binary_flags & (BINARY_IS_INTERPRETER | BINARY_IS_LIBC)) == BINARY_IS_INTERPRETER)
										                      ? required_effects
										                      : ((required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS),
										                  &empty_registers,
										                  self->address,
										                  "lea");
									}
								}
							}
						}
					} else if (prot & PROT_READ) {
						analyze_memory_read(analysis, self, ins, *effects, binary, address);
					} else {
						LOG("rip-relative lea is to unreadable address, not sure what it is");
					}
				} else {
					LOG("rip-relative lea is to variable address, assuming it is data");
				}
			}
			break;
		}
		case 0x8e: // mov Sreg, r/m
			break;
		case 0x8f: { // pop r/m
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			struct register_state empty;
			clear_register(&empty);
			truncate_to_size_prefixes(&empty, decoded->prefixes);
			self->current_state.registers[rm.reg] = empty;
			self->current_state.sources[rm.reg] = 0;
			clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			break;
		}
		case 0x90: // xchg ax, ax
			// this is a nop!
			break;
		case 0x91: // xchg r, r
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x96:
		case 0x97: {
			int reg = x86_read_opcode_register_index(*decoded->unprefixed, 0x90, decoded->prefixes);
			struct register_state dest = self->current_state.registers[reg];
			struct register_state source = self->current_state.registers[REGISTER_RAX];
			truncate_to_size_prefixes(&dest, decoded->prefixes);
			truncate_to_size_prefixes(&source, decoded->prefixes);
			self->current_state.registers[reg] = source;
			self->current_state.registers[REGISTER_RAX] = dest;
			register_mask rax_sources = self->current_state.sources[REGISTER_RAX];
			self->current_state.sources[REGISTER_RAX] = self->current_state.sources[reg];
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			self->current_state.sources[reg] = rax_sources;
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			break;
		}
		case 0x98: { // cbw/cwde/cdqe
			if (decoded->prefixes.has_w) {
				if (self->current_state.registers[REGISTER_RAX].max >= 0x80000000) {
					truncate_to_32bit(&self->current_state.registers[REGISTER_RAX]);
					if (!register_is_partially_known_32bit(&self->current_state.registers[REGISTER_RAX])) {
						self->current_state.sources[REGISTER_RAX] = 0;
					}
					if (self->current_state.registers[REGISTER_RAX].max >= 0x80000000) {
						self->current_state.registers[REGISTER_RAX].max = sign_extend(self->current_state.registers[REGISTER_RAX].max, OPERATION_SIZE_WORD);
					}
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
				}
			} else {
				if (self->current_state.registers[REGISTER_RAX].max >= 0x80) {
					truncate_to_8bit(&self->current_state.registers[REGISTER_RAX]);
					if (!register_is_partially_known_8bit(&self->current_state.registers[REGISTER_RAX])) {
						self->current_state.sources[REGISTER_RAX] = 0;
					}
					if (self->current_state.registers[REGISTER_RAX].max >= 0x80) {
						self->current_state.registers[REGISTER_RAX].max = sign_extend(self->current_state.registers[REGISTER_RAX].max, OPERATION_SIZE_BYTE);
						truncate_to_size_prefixes(&self->current_state.registers[REGISTER_RAX], decoded->prefixes);
					}
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
				}
			}
			break;
		}
		case 0x9a:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0x9b: // fwait/wait
			break;
		case 0x9c: // pushf
			break;
		case 0x9d: // popf
			break;
		case 0x9e: // sahf
			clear_comparison_state(&self->current_state);
			break;
		case 0x9f: // lahf
			clear_register(&self->current_state.registers[REGISTER_RAX]);
			self->current_state.sources[REGISTER_RAX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			break;
		case 0xa0: // mov al, moffs8
			clear_register(&self->current_state.registers[REGISTER_RAX]);
			truncate_to_8bit(&self->current_state.registers[REGISTER_RAX]);
			self->current_state.sources[REGISTER_RAX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			break;
		case 0xa1: // mov *ax, moffs
			clear_register(&self->current_state.registers[REGISTER_RAX]);
			truncate_to_size_prefixes(&self->current_state.registers[REGISTER_RAX], decoded->prefixes);
			self->current_state.sources[REGISTER_RAX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			break;
		case 0xa2: // mov moffs8, al
			break;
		case 0xa3: // mov moffs, *ax
			break;
		case 0xa4: // movs m8, m8
			break;
		case 0xa5: // movs m, m
			break;
		case 0xa6: // cmps m8, m8
			clear_comparison_state(&self->current_state);
			break;
		case 0xa7: // cmps m, m
			clear_comparison_state(&self->current_state);
			break;
		case 0xa8: // test al, imm8
			clear_comparison_state(&self->current_state);
			break;
		case 0xa9: // test *ax, imm
			clear_comparison_state(&self->current_state);
			break;
		case 0xaa: // stos m8, al
			if (decoded->prefixes.has_rep) {
				set_register(&self->current_state.registers[REGISTER_RCX], 0);
			} else {
				clear_register(&self->current_state.registers[REGISTER_RCX]);
			}
			self->current_state.sources[REGISTER_RCX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RCX, ins);
			break;
		case 0xab: // stos m, *ax
			if (decoded->prefixes.has_rep) {
				set_register(&self->current_state.registers[REGISTER_RCX], 0);
			} else {
				clear_register(&self->current_state.registers[REGISTER_RCX]);
			}
			self->current_state.sources[REGISTER_RCX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RCX, ins);
			break;
		case 0xac: // lods m, al
			clear_register(&self->current_state.registers[REGISTER_RAX]);
			truncate_to_8bit(&self->current_state.registers[REGISTER_RAX]);
			self->current_state.sources[REGISTER_RAX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			break;
		case 0xad: // lods m, *ax
			clear_register(&self->current_state.registers[REGISTER_RAX]);
			truncate_to_size_prefixes(&self->current_state.registers[REGISTER_RAX], decoded->prefixes);
			self->current_state.sources[REGISTER_RAX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			break;
		case 0xae: // scas m8, al
			clear_comparison_state(&self->current_state);
			break;
		case 0xaf: // scas m, *ax
			clear_comparison_state(&self->current_state);
			break;
		case 0xb0: // mov r8, imm8
		case 0xb1:
		case 0xb2:
		case 0xb3:
		case 0xb4:
		case 0xb5:
		case 0xb6:
		case 0xb7: {
			int reg = x86_read_opcode_register_index(*decoded->unprefixed, 0xb0, decoded->prefixes);
			LOG("mov r8 to ", name_for_register(reg));
			struct register_state dest;
			dest.value = (uint8_t)decoded->unprefixed[1];
			dest.max = dest.value;
			LOG("value is immediate: ", temp_str(copy_register_state_description(&analysis->loader, dest)));
			self->current_state.registers[reg] = dest;
			self->current_state.sources[reg] = 0;
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			goto skip_stack_clear;
		}
		case 0xb8: // mov r, imm
		case 0xb9:
		case 0xba:
		case 0xbb:
		case 0xbc:
		case 0xbd:
		case 0xbe:
		case 0xbf: {
			int reg = x86_read_opcode_register_index(*decoded->unprefixed, 0xb8, decoded->prefixes);
			LOG("mov r to ", name_for_register(reg));
			struct register_state dest;
			dest.value = decoded->prefixes.has_w ? *(const ins_uint64 *)&decoded->unprefixed[1] : read_imm(decoded->prefixes, &decoded->unprefixed[1]);
			dest.max = dest.value;
			LOG("value is immediate: ", temp_str(copy_register_state_description(&analysis->loader, dest)));
			self->current_state.registers[reg] = dest;
			self->current_state.sources[reg] = 0;
			clear_match(&analysis->loader, &self->current_state, reg, ins);
			void *address = (void *)dest.value;
			struct loaded_binary *binary;
			if (protection_for_address(&analysis->loader, address, &binary, NULL) & PROT_EXEC) {
				LOG("mov is to executable address, assuming it could be called after startup");
				if (*effects & EFFECT_ENTER_CALLS) {
					queue_instruction(&analysis->search.queue, address, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, self->address, "mov");
					// self->description = "mov";
					// analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, (ins_ptr)address, self);
				}
			}
			goto skip_stack_clear;
		}
		case 0xc0: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m8, imm8
			// TODO: read reg to know which in the family to dispatch
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			int rm;
			switch (modrm.reg) {
				case 4:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("shl", basic_op_shl, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
				case 5:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("shr", basic_op_shr, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
				case 7:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("sar", basic_op_sar, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
				default:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm8_imm8("rotate/shift family", basic_op_unknown, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
			}
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0xc1: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m, imm8
			// TODO: read reg to know which in the family to dispatch
			int rm;
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			switch (modrm.reg) {
				case 4:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("shl", basic_op_shl, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
				case 5:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("shr", basic_op_shr, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
				case 7:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("sar", basic_op_sar, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
				default:
					rm = CHECK_BASIC_OP_FAULT(perform_basic_op_rm_imm8("rotate/shift family", basic_op_unknown, &analysis->loader, &self->current_state, decoded->prefixes, &decoded->unprefixed[1], trace_flags, &additional));
					break;
			}
			clear_comparison_state(&self->current_state);
			CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(rm);
			break;
		}
		case 0xc2: // ret imm16
			break;
		case 0xc3: // ret
			break;
		case 0xc4: // three-byte vex prefix
			break;
		case 0xc5: // two-byte vex prefix
			break;
		case 0xc6: { // mov r/m8, imm8
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			if (modrm.reg == 0) {
				ins_ptr remaining = &decoded->unprefixed[1];
				struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, sizeof(int8_t), &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
				CHECK_RM_FAULT(rm);
				LOG("mov r/m8 to ", name_for_register(rm.reg));
				struct register_state state;
				state.value = *remaining;
				state.max = state.value;
				LOG("value is immediate: ", temp_str(copy_register_state_description(&analysis->loader, state)));
				self->current_state.registers[rm.reg] = state;
				self->current_state.sources[rm.reg] = 0;
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
				self->pending_stack_clear &= ~mask_for_register(rm.reg);
				goto skip_stack_clear;
			}
			break;
		}
		case 0xc7: { // mov r/m, imm
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			if (modrm.reg == 0) {
				ins_ptr remaining = &decoded->unprefixed[1];
				struct rm_result rm =
					read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, imm_size_for_prefixes(decoded->prefixes), &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
				CHECK_RM_FAULT(rm);
				LOG("mov r/m to ", name_for_register(rm.reg));
				struct register_state state;
				state.value = read_imm(decoded->prefixes, remaining);
				state.max = state.value;
				LOG("value is immediate: ", temp_str(copy_register_state_description(&analysis->loader, state)));
				self->current_state.registers[rm.reg] = state;
				self->current_state.sources[rm.reg] = 0;
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
				self->pending_stack_clear &= ~mask_for_register(rm.reg);
				struct loaded_binary *binary;
				if (protection_for_address(&analysis->loader, (const void *)state.value, &binary, NULL) & PROT_EXEC) {
					self->description = "mov";
					if (required_effects & EFFECT_ENTRY_POINT) {
						if (rm.reg == sysv_argument_abi_register_indexes[0]) {
							// main
							analysis->main = (uintptr_t)state.value;
							self->description = "mov main";
							LOG("mov is to executable address, assuming it is the main function");
							struct registers registers = empty_registers;
							analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, (ins_ptr)state.value, self);
						} else if (rm.reg == sysv_argument_abi_register_indexes[3]) {
							// init, will be called before main, can skip it
						} else if (rm.reg == sysv_argument_abi_register_indexes[4] || rm.reg == sysv_argument_abi_register_indexes[5]) {
							LOG("mov is to executable address, assuming it is the finit function");
							struct registers registers = empty_registers;
							analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT) | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &registers, (ins_ptr)state.value, self);
						} else {
							LOG("mov is to executable address, assuming it could be called during startup");
							struct registers registers = empty_registers;
							analyze_function(analysis, (required_effects & ~EFFECT_ENTRY_POINT), &registers, (ins_ptr)state.value, self);
						}
					} else {
						if (*effects & EFFECT_ENTER_CALLS) {
							LOG("mov is to executable address, assuming it could be called after startup");
							queue_instruction(&analysis->search.queue, (ins_ptr)state.value, required_effects | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, self->address, "mov");
						}
					}
				} else {
					LOG("mov is to non-executable value, assuming it is data");
				}
				self->pending_stack_clear &= ~mask_for_register(rm.reg);
				goto skip_stack_clear;
			}
			break;
		}
		case 0xc8: // enter
			break;
		case 0xc9: // leave
			break;
		case 0xca: // retf imm16
			break;
		case 0xcb: // retf
			break;
		case 0xcc: // int3
			break;
		case 0xcd: // int imm8
			break;
		case 0xce: // into
			break;
		case 0xcf: // iret
			break;
		case 0xd0: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m8, 1
			clear_comparison_state(&self->current_state);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			if (rm.reg != REGISTER_INVALID) {
				if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
					clear_register(&self->current_state.registers[rm.reg]);
					truncate_to_16bit(&self->current_state.registers[rm.reg]);
				} else {
					clear_register(&self->current_state.registers[rm.reg]);
				}
				self->current_state.sources[rm.reg] = 0;
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			}
			break;
		}
		case 0xd1: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m, 1
			clear_comparison_state(&self->current_state);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			if (rm.reg != REGISTER_INVALID) {
				clear_register(&self->current_state.registers[rm.reg]);
				truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
				self->current_state.sources[rm.reg] = 0;
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			}
			break;
		}
		case 0xd2: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m8, cl
			clear_comparison_state(&self->current_state);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			if (rm.reg != REGISTER_INVALID) {
				if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
					clear_register(&self->current_state.registers[rm.reg]);
					truncate_to_16bit(&self->current_state.registers[rm.reg]);
				} else {
					clear_register(&self->current_state.registers[rm.reg]);
				}
				self->current_state.sources[rm.reg] = 0;
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			}
			break;
		}
		case 0xd3: { // rol/ror/rcl/rcr/shl/sal/shr/sar r/m, cl
			clear_comparison_state(&self->current_state);
			ins_ptr remaining = &decoded->unprefixed[1];
			struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_KEEP_MEM | read_rm_flags_from_trace_flags(trace_flags));
			CHECK_RM_FAULT(rm);
			if (rm.reg != REGISTER_INVALID) {
				clear_register(&self->current_state.registers[rm.reg]);
				truncate_to_size_prefixes(&self->current_state.registers[rm.reg], decoded->prefixes);
				self->current_state.sources[rm.reg] = 0;
				clear_match(&analysis->loader, &self->current_state, rm.reg, ins);
			}
			break;
		}
		case 0xd4:
		case 0xd5:
		case 0xd6:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0xd7:
			if (decoded->prefixes.has_vex) {
				// pmovmskb r, ymm
				x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
				int reg = x86_read_reg(modrm, decoded->prefixes);
				LOG("vpmovmskb to ", name_for_register(reg));
				clear_register(&self->current_state.registers[reg]);
				truncate_to_32bit(&self->current_state.registers[reg]);
				self->current_state.sources[reg] = 0;
				clear_match(&analysis->loader, &self->current_state, reg, ins);
			} else {
				// xlat
				clear_register(&self->current_state.registers[REGISTER_RAX]);
				truncate_to_8bit(&self->current_state.registers[REGISTER_RAX]);
				self->current_state.sources[REGISTER_RAX] = 0;
				clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			}
			break;
		case 0xd8: // fadd/fmul/fcom/etc
			break;
		case 0xd9: // fld/fxch/fst/etc
			break;
		case 0xda: // fiadd/fcmovb/etc
			break;
		case 0xdb: // fild/etc
			break;
		case 0xdc: // fadd/fmul/fcom/etc
			break;
		case 0xdd: // legacy float garbage
			break;
		case 0xdf: // more legacy float garbage
			break;
		case 0xe0: // loopnz/loopne
			// TODO: handle loop
			break;
		case 0xe1: // loopz/loope
			// TODO: handle loop
			break;
		case 0xe2: // loop
			// TODO: handle loop
			break;
		case 0xe4: // in al, imm8
			break;
		case 0xe5: // in eax, imm8
			break;
		case 0xe6: // out al, imm8
			break;
		case 0xe7: // out eax, imm8
			break;
		case 0xe8: { // call
			clear_comparison_state(&self->current_state);
			uintptr_t dest = (uintptr_t)next_ins(ins, decoded) + *(const ins_int32 *)&decoded->unprefixed[1];
			LOG("found call ", temp_str(copy_function_call_description(&analysis->loader, (void *)dest, &self->current_state)));
			struct loaded_binary *binary = NULL;
			function_effects more_effects = EFFECT_NONE;
			if (dest == 0) {
				LOG("found call to NULL, assuming all effects");
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else if ((protection_for_address(&analysis->loader, (void *)dest, &binary, NULL) & PROT_EXEC) == 0) {
				encountered_non_executable_address(&analysis->loader, "call", self, (ins_ptr)dest);
				LOG("found call to non-executable address, assuming all effects");
				*effects |= DEFAULT_EFFECTS;
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else if ((*effects & EFFECT_ENTRY_POINT) && (ins_ptr)dest == next_ins(ins, decoded)) {
				LOG("calling self pattern in entrypoint");
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else if ((*effects & EFFECT_ENTER_CALLS) == 0) {
				LOG("skipping call when searching for address loads");
				analysis->skipped_call = (ins_ptr)dest;
				clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary, ins, ALL_REGISTERS);
			} else {
				self->description = "call";
				check_for_searched_function(&analysis->loader, (ins_ptr)dest);
				more_effects = analyze_call(analysis, required_effects, binary, ins, (ins_ptr)dest, self);
				*effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
				LOG("resuming ", temp_str(copy_address_description(&analysis->loader, self->entry)), " from call ", temp_str(copy_address_description(&analysis->loader, ins)));
				if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
					LOG("completing from call to exit-only function: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					goto update_and_return;
				}
				LOG("function may return, proceeding with ", effects_description(more_effects), " effects");
				struct loaded_binary *caller_binary = binary_for_address(&analysis->loader, ins);
				if (caller_binary != NULL) {
					struct frame_details frame;
					if (find_containing_frame_info(&caller_binary->frame_info, ins, &frame)) {
						if ((uintptr_t)frame.address + frame.size <= (uintptr_t)next_ins(ins, decoded)) {
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
		case 0xe9: // jmp rel
			break;
		case 0xea:
			LOG("invalid opcode: ", (uintptr_t)*decoded->unprefixed);
			break;
		case 0xeb: // jmp rel8
			break;
		case 0xec: // in al, dx
			clear_register(&self->current_state.registers[REGISTER_RAX]);
			truncate_to_8bit(&self->current_state.registers[REGISTER_RAX]);
			self->current_state.sources[REGISTER_RAX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			break;
		case 0xed: // in *ax, *dx
			clear_register(&self->current_state.registers[REGISTER_RAX]);
			self->current_state.sources[REGISTER_RAX] = 0;
			clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
			break;
		case 0xee: // out dx, al
			break;
		case 0xef: // out *dx, *ax
			break;
		case 0xf0: // lock prefix
			break;
		case 0xf1: // reserved
			break;
		case 0xf2: // repnz/repne/rep prefix
			break;
		case 0xf3: // repz/repe/rep prefix
			break;
		case 0xf4: // hlt
			*effects |= EFFECT_EXITS;
			LOG("completing from hlt: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
			goto update_and_return;
		case 0xf5: // cmc
			break;
		case 0xf6: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			switch (modrm.reg) {
				case 0:
				case 1: // test r/m8, imm8
					clear_comparison_state(&self->current_state);
					break;
				case 2: { // not r/m8, imm8
					// TODO: implement not
					int rm = x86_read_rm(modrm, decoded->prefixes);
					if (register_is_legacy_8bit_high(decoded->prefixes, &rm)) {
						clear_register(&self->current_state.registers[rm]);
					} else {
						clear_register(&self->current_state.registers[rm]);
						truncate_to_8bit(&self->current_state.registers[rm]);
					}
					self->current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self->current_state, rm, ins);
					break;
				}
				case 3: { // neg r/m8, imm8
					// TODO: implement neg
					clear_comparison_state(&self->current_state);
					int rm = x86_read_rm(modrm, decoded->prefixes);
					if (register_is_legacy_8bit_high(decoded->prefixes, &rm)) {
						clear_register(&self->current_state.registers[rm]);
					} else {
						clear_register(&self->current_state.registers[rm]);
						truncate_to_8bit(&self->current_state.registers[rm]);
					}
					self->current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self->current_state, rm, ins);
					break;
				}
				case 4: // mul ax, al, r/m8
				case 5: { // imul ax, al, r/m8
					clear_comparison_state(&self->current_state);
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					truncate_to_16bit(&self->current_state.registers[REGISTER_RAX]);
					self->current_state.sources[REGISTER_RAX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					break;
				}
				case 6: // div al, ah, al, r/m8
				case 7: { // idiv al, ah, al, r/m8
					clear_comparison_state(&self->current_state);
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					truncate_to_16bit(&self->current_state.registers[REGISTER_RAX]);
					self->current_state.sources[REGISTER_RAX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					break;
				}
			}
			break;
		}
		case 0xf7: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			switch (modrm.reg) {
				case 0:
				case 1: // test r/m, imm
					clear_comparison_state(&self->current_state);
					break;
				case 2: { // not r/m, imm
					// TODO: implement not
					int rm = x86_read_rm(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[rm]);
					truncate_to_size_prefixes(&self->current_state.registers[rm], decoded->prefixes);
					self->current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self->current_state, rm, ins);
					break;
				}
				case 3: { // neg r/m, imm
					// TODO: implement neg
					clear_comparison_state(&self->current_state);
					int rm = x86_read_rm(modrm, decoded->prefixes);
					clear_register(&self->current_state.registers[rm]);
					truncate_to_size_prefixes(&self->current_state.registers[rm], decoded->prefixes);
					self->current_state.sources[rm] = 0;
					clear_match(&analysis->loader, &self->current_state, rm, ins);
					break;
				}
				case 4: // mul *dx, *ax, r/m
				case 5: { // imul *dx, *ax, r/m
					clear_comparison_state(&self->current_state);
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					clear_register(&self->current_state.registers[REGISTER_RDX]);
					self->current_state.sources[REGISTER_RAX] = 0;
					self->current_state.sources[REGISTER_RDX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					clear_match(&analysis->loader, &self->current_state, REGISTER_RDX, ins);
					break;
				}
				case 6: // div al, ah, al, r/m8
				case 7: { // idiv al, ah, al, r/m8
					clear_comparison_state(&self->current_state);
					clear_register(&self->current_state.registers[REGISTER_RAX]);
					clear_register(&self->current_state.registers[REGISTER_RDX]);
					self->current_state.sources[REGISTER_RAX] = 0;
					self->current_state.sources[REGISTER_RDX] = 0;
					clear_match(&analysis->loader, &self->current_state, REGISTER_RAX, ins);
					clear_match(&analysis->loader, &self->current_state, REGISTER_RDX, ins);
					break;
				}
			}
			break;
		}
		case 0xf8: // clc
			clear_comparison_state(&self->current_state);
			break;
		case 0xf9: // stc
			clear_comparison_state(&self->current_state);
			break;
		case 0xfa: // cli
			clear_comparison_state(&self->current_state);
			break;
		case 0xfb: // sti
			clear_comparison_state(&self->current_state);
			break;
		case 0xfc: // cld
			clear_comparison_state(&self->current_state);
			break;
		case 0xfd: // std
			clear_comparison_state(&self->current_state);
			break;
		case 0xfe: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			switch (modrm.reg) {
				case 0: { // inc r/m8
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[1];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_BYTE, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					struct register_state state = self->current_state.registers[rm.reg];
					if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
						clear_register(&self->current_state.registers[rm.reg]);
					} else {
						truncate_to_8bit(&state);
						state.value++;
						state.max++;
						truncate_to_8bit(&state);
						self->current_state.registers[rm.reg] = state;
					}
					break;
				}
				case 1: { // dec r/m8
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[1];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (register_is_legacy_8bit_high(decoded->prefixes, &rm.reg)) {
						clear_register(&self->current_state.registers[rm.reg]);
					} else {
						struct register_state state = self->current_state.registers[rm.reg];
						truncate_to_8bit(&state);
						state.value--;
						state.max--;
						truncate_to_8bit(&state);
						self->current_state.registers[rm.reg] = state;
					}
					break;
				}
				default:
					LOG("invalid opcode extension for 0xfe: ", (int)modrm.reg);
					break;
			}
			break;
		}
		case 0xff: {
			x86_mod_rm_t modrm = x86_read_modrm(&decoded->unprefixed[1]);
			switch (modrm.reg) {
				case 0: { // inc r/m
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[1];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					struct register_state state = self->current_state.registers[rm.reg];
					truncate_to_size_prefixes(&state, decoded->prefixes);
					state.value++;
					state.max++;
					truncate_to_size_prefixes(&state, decoded->prefixes);
					self->current_state.registers[rm.reg] = state;
					break;
				}
				case 1: { // dec r/m
					clear_comparison_state(&self->current_state);
					ins_ptr remaining = &decoded->unprefixed[1];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					struct register_state state = self->current_state.registers[rm.reg];
					truncate_to_size_prefixes(&state, decoded->prefixes);
					state.value--;
					state.max--;
					truncate_to_size_prefixes(&state, decoded->prefixes);
					self->current_state.registers[rm.reg] = state;
					break;
				}
				case 2: // call
					clear_comparison_state(&self->current_state);
					LOG("found call*");
					if (x86_modrm_is_direct(modrm)) {
						int reg = x86_read_rm(modrm, decoded->prefixes);
						LOG("call to address in ", name_for_register(reg));
						struct register_state address = self->current_state.registers[reg];
						self->description = "call*";
						vary_effects_by_registers(&analysis->search, &analysis->loader, self, mask_for_register(reg), 0, 0, required_effects);
						struct loaded_binary *call_binary;
						if (!register_is_exactly_known(&address)) {
							LOG("address isn't exactly known, assuming all effects");
							// could have any effect
							// *effects |= DEFAULT_EFFECTS;
							clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
						} else if ((protection_for_address(&analysis->loader, (const void *)address.value, &call_binary, NULL) & PROT_EXEC) == 0) {
							encountered_non_executable_address(&analysis->loader, "call*", self, (ins_ptr)address.value);
							LOG("call* to non-executable address ", address.value, ", assuming all effects");
							clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
						} else if ((*effects & EFFECT_ENTER_CALLS) == 0) {
							LOG("skipping call when searching for address loads");
							analysis->skipped_call = (ins_ptr)address.value;
							clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
						} else {
							self->description = "indirect call";
							function_effects more_effects = analyze_call(analysis, required_effects, call_binary, ins, (ins_ptr)address.value, self);
							*effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
							LOG("resuming ", temp_str(copy_address_description(&analysis->loader, self->entry)), " from call* ", temp_str(copy_address_description(&analysis->loader, ins)));
							if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
								LOG("completing from call to exit-only function: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
								goto update_and_return;
							}
							LOG("function may return, proceeding with ", effects_description(more_effects), " effects");
						}
					} else {
						bool is_null;
						struct register_state_and_source address = address_for_indirect(*decoded, modrm, &self->current_state, &decoded->unprefixed[2], &analysis->loader, ins, &is_null);
						self->description = "call*";
						vary_effects_by_registers(&analysis->search, &analysis->loader, self, address.source, 0, 0, required_effects);
						struct loaded_binary *call_address_binary;
						if (!register_is_exactly_known(&address.state)) {
							LOG("address isn't exactly known, assuming all effects");
							// could have any effect
							// *effects |= DEFAULT_EFFECTS;
							clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
						} else if (is_null) {
							LOG("indirecting through null, assuming read of data that is populated at runtime");
							clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
						} else if ((protection_for_address(&analysis->loader, (const void *)address.state.value, &call_address_binary, NULL) & PROT_READ) == 0) {
							LOG("call* indirect to known, but unreadable address: ", address.state.value);
							clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
						} else {
							ins_ptr dest = (ins_ptr)(uintptr_t)*(const ins_uint64 *)address.state.value;
							LOG("dest is ", (uintptr_t)dest);
							if (dest == NULL) {
								clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
							} else {
								struct loaded_binary *call_binary;
								if ((protection_for_address(&analysis->loader, dest, &call_binary, NULL) & PROT_EXEC) == 0) {
									dump_nonempty_registers(&analysis->loader, &self->current_state, ALL_REGISTERS);
									encountered_non_executable_address(&analysis->loader, "call*", self, dest);
									LOG("call* to non-executable address, assuming all *effects: ", temp_str(copy_address_description(&analysis->loader, ins)));
									*effects |= DEFAULT_EFFECTS;
									clear_call_dirtied_registers(
										&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, (uintptr_t)dest == TLSDESC_ADDR ? mask_for_register(REGISTER_RAX) : ALL_REGISTERS);
								} else if ((*effects & EFFECT_ENTER_CALLS) == 0) {
									LOG("skipping call when searching for address loads");
									analysis->skipped_call = dest;
									clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
								} else {
									self->description = "indirect call";
									function_effects more_effects = analyze_call(analysis, required_effects, call_binary, ins, dest, self);
									*effects |= more_effects & ~(EFFECT_RETURNS | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
									LOG("resuming ", temp_str(copy_address_description(&analysis->loader, self->entry)), " from call* ", temp_str(copy_address_description(&analysis->loader, ins)));
									if ((more_effects & (EFFECT_RETURNS | EFFECT_EXITS)) == EFFECT_EXITS) {
										LOG("completing from call to exit-only function: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
										goto update_and_return;
									}
									LOG("function may return, proceeding with ", effects_description(more_effects), " effects");
								}
							}
						}
					}
					// set_effects(&analysis->search, self->entry, &self->token, *effects | EFFECT_PROCESSING, 0);
					clear_stack(&self->current_state, ins);
					break;
				case 3: // callf
					clear_comparison_state(&self->current_state);
					LOG("found unsupported call*");
					clear_call_dirtied_registers(&analysis->loader, &self->current_state, binary_for_address(&analysis->loader, ins), ins, ALL_REGISTERS);
					clear_stack(&self->current_state, ins);
					break;
				case 4: { // jmp
					// found jmp*
					int reg = x86_read_rm(modrm, decoded->prefixes);
					LOG("jmpq* ", name_for_register(reg));
					dump_nonempty_registers(&analysis->loader, &self->current_state, mask_for_register(reg));
					self->description = "indirect jump";
					vary_effects_by_registers(&analysis->search, &analysis->loader, self, mask_for_register(reg), self->current_state.requires_known_target & mask_for_register(reg), 0, required_effects);
					ins_ptr new_ins;
					if (x86_modrm_is_direct(modrm)) {
						if (!register_is_exactly_known(&self->current_state.registers[reg])) {
							bool allow_jumps_into_the_abyss = (self->current_state.requires_known_target & mask_for_register(reg)) == 0;
							if (allow_jumps_into_the_abyss) {
								LOG("jmp* to unknown address: ", temp_str(copy_address_description(&analysis->loader, self->address)));
								dump_nonempty_registers(&analysis->loader, &self->current_state, ALL_REGISTERS);
							} else {
								ERROR("jmp* to unknown address: ", temp_str(copy_address_description(&analysis->loader, self->address)));
								self->description = "jmp*";
								DIE("trace: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
							}
							// could have any effect
							*effects |= DEFAULT_EFFECTS;
							LOG("completing from jmpq*: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
							goto update_and_return;
						}
						new_ins = (ins_ptr)self->current_state.registers[reg].value;
					} else {
						bool is_null;
						struct register_state_and_source address = address_for_indirect(*decoded, modrm, &self->current_state, &decoded->unprefixed[2], &analysis->loader, ins, &is_null);
						if (is_null) {
							LOG("indirecting through null, assuming read of data that is populated at runtime");
							// could have any effect
							*effects |= DEFAULT_EFFECTS;
							LOG("completing from jmpq*: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
							goto update_and_return;
						}
						if (!register_is_exactly_known(&address.state)) {
							LOG("address isn't exactly known, assuming all effects");
							// could have any effect
							*effects |= DEFAULT_EFFECTS;
							LOG("completing from jmpq*: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
							goto update_and_return;
						}
						bool allow_jumps_into_the_abyss = (self->current_state.requires_known_target & address.source) == 0;
						struct loaded_binary *call_address_binary;
						if ((protection_for_address(&analysis->loader, (const void *)address.state.value, &call_address_binary, NULL) & PROT_READ) == 0) {
							if (allow_jumps_into_the_abyss) {
								LOG("jmp* indirect to known, but unreadable address: ", temp_str(copy_address_description(&analysis->loader, (const void *)address.state.value)));
								self->description = NULL;
								LOG("at: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
							} else {
								ERROR("jmp* indirect to known, but unreadable address: ", temp_str(copy_address_description(&analysis->loader, (const void *)address.state.value)));
								self->description = "jmp*";
								DIE("at: ", temp_str(copy_call_trace_description(&analysis->loader, self)));
							}
							// could have any effect
							*effects |= DEFAULT_EFFECTS;
							LOG("completing from jmpq*: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
							goto update_and_return;
						}
						new_ins = *(ins_ptr *)address.state.value;
					}
					struct loaded_binary *call_binary;
					if (new_ins == NULL) {
						LOG("address is known, but only filled at runtime, assuming all effects");
						*effects |= DEFAULT_EFFECTS;
						LOG("completing from jmpq* to known, but unfilled address: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					} else if ((protection_for_address(&analysis->loader, new_ins, &call_binary, NULL) & PROT_EXEC) == 0) {
						dump_nonempty_registers(&analysis->loader, &self->current_state, ALL_REGISTERS);
						*effects |= DEFAULT_EFFECTS;
						encountered_non_executable_address(&analysis->loader, "jump*", self, new_ins);
						LOG("completing from jmpq* to non-executable address: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					} else {
						*effects |= analyze_instructions(analysis, required_effects, &self->current_state, new_ins, caller, 0) & ~(EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS | EFFECT_PROCESSING);
						LOG("completing from jmpq*: ", temp_str(copy_address_description(&analysis->loader, self->entry)));
					}
					goto update_and_return;
				}
				case 5: // jmpf
					LOG("found unsupported jump*");
					goto update_and_return;
				case 6: { // push
					ins_ptr remaining = &decoded->unprefixed[1];
					struct rm_result rm = read_rm_ref(&analysis->loader, decoded->prefixes, &remaining, 0, &self->current_state, OPERATION_SIZE_DEFAULT, READ_RM_REPLACE_MEM | read_rm_flags_from_trace_flags(trace_flags));
					CHECK_RM_FAULT(rm);
					if (rm.reg >= REGISTER_STACK_0) {
						if (rm.reg >= REGISTER_COUNT - 2) {
							// check for cases like push QWORD PTR [rsp+0x70] where source stack register will be pushed out of existence
							push_stack(&analysis->loader, &self->current_state, 2, ins);
							break;
						}
						// stack positions shift, gaaah!
						rm.reg += 2;
					}
					truncate_to_size_prefixes(&rm.state, decoded->prefixes);
					push_stack(&analysis->loader, &self->current_state, 2, ins);
					self->current_state.registers[REGISTER_STACK_0] = rm.state;
					add_match_and_sources(&analysis->loader, &self->current_state, REGISTER_STACK_0, rm.reg, rm.sources, ins);
					dump_nonempty_registers(&analysis->loader, &self->current_state, STACK_REGISTERS);
					break;
				}
				default:
					LOG("invalid opcode extension for 0xff: ", (int)modrm.reg);
					break;
			}
			break;
		}
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
