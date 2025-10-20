#ifndef CALLANDER_INTERNAL_H
#define CALLANDER_INTERNAL_H

#include "callander.h"
#include "callander_print.h"

struct additional_result
{
	struct register_state state;
	bool used;
};

void merge_and_log_additional_result(__attribute__((unused)) struct loader_context *loader, struct register_state *dest, struct additional_result *additional, int reg);
void widen_cross_binary_bound_operation(struct loader_context *loader, struct register_state *state, struct additional_result *additional, uintptr_t orig_value);

bool analyze_instructions_arch(struct program_state *analysis, function_effects required_effects, function_effects *effects, ins_ptr ins, const struct analysis_frame *caller, trace_flags trace_flags, struct analysis_frame *self, struct decoded_ins *decoded);

enum syscall_analysis_result
{
	SYSCALL_ANALYSIS_CONTINUE,
	SYSCALL_ANALYSIS_UPDATE_AND_RETURN,
	SYSCALL_ANALYSIS_EXIT,
};

uint8_t analyze_syscall_instruction(struct program_state *analysis, struct analysis_frame *self, struct additional_result *additional, const struct analysis_frame *caller, ins_ptr ins,
                                    function_effects required_effects, function_effects *effects);
function_effects analyze_call(struct program_state *analysis, function_effects required_effects, struct loaded_binary *binary, ins_ptr ins, ins_ptr call_target, struct analysis_frame *self);
__attribute__((nonnull(1, 2, 4))) void clear_call_dirtied_registers(const struct loader_context *loader, struct registers *regs, struct loaded_binary *binary, ins_ptr ins, register_mask modified);
__attribute__((nonnull(1, 2, 3))) void vary_effects_by_registers(struct searched_instructions *search, const struct loader_context *loader, const struct analysis_frame *self, register_mask relevant_registers,
                                                                 register_mask preserved_registers, register_mask preserved_and_kept_registers, function_effects required_effects);

void encountered_non_executable_address(__attribute__((unused)) struct loader_context *loader, __attribute__((unused)) const char *description, __attribute__((unused)) struct analysis_frame *frame,
                                               __attribute__((unused)) ins_ptr target);

struct queued_instruction
{
	ins_ptr ins;
	struct registers registers;
	ins_ptr caller;
	const char *description;
	function_effects effects;
};

__attribute__((nonnull(1, 2, 4))) void queue_instruction(struct queued_instructions *queue, ins_ptr ins, function_effects effects, const struct registers *registers, ins_ptr caller, const char *description);

__attribute__((nonnull(1, 2))) void add_lookup_table_base_address(struct lookup_base_addresses *addresses, ins_ptr ins, uintptr_t base);
__attribute__((nonnull(1, 2))) uintptr_t find_lookup_table_base_address(const struct lookup_base_addresses *addresses, ins_ptr ins);

__attribute__((unused)) void record_stack_address_taken(__attribute__((unused)) const struct loader_context *loader, __attribute__((unused)) ins_ptr addr, struct registers *regs);

__attribute__((nonnull(1, 3))) int protection_for_address(const struct loader_context *context, const void *address, struct loaded_binary **out_binary, const ElfW(Shdr) * *out_section);
int protection_for_address_in_binary(const struct loaded_binary *binary, uintptr_t addr, const ElfW(Shdr) * *out_section);
bool in_plt_section(const struct loaded_binary *binary, ins_ptr ins);
bool is_stack_preserving_function(struct loader_context *loader, struct loaded_binary *binary, ins_ptr addr);

__attribute__((nonnull(1, 2))) char *copy_function_call_description(const struct loader_context *context, ins_ptr target, const struct registers *registers);
__attribute__((nonnull(1))) char *copy_memory_ref_description(const struct loader_context *loader, struct ins_memory_reference rm);
char *effects_description(function_effects effects);

bool binary_has_flags(const struct loaded_binary *binary, binary_flags flags);

void *find_any_symbol_by_address(const struct loader_context *loader, struct loaded_binary *binary, const void *addr, int symbol_types, const struct symbol_info **out_used_symbols, const ElfW(Sym) * *out_symbol);


void analyze_memory_read(struct program_state *analysis, struct analysis_frame *self, ins_ptr ins, function_effects effects, struct loaded_binary *binary, const void *address);
uintptr_t read_memory(const void *addr, enum ins_operand_size size);
intptr_t read_memory_signed(const void *addr, enum ins_operand_size size);
__attribute__((nonnull(1, 2))) bool memory_ref_equal(const struct ins_memory_reference *l, const struct ins_memory_reference *r);

void set_comparison_state(struct loader_context *loader, struct registers *state, struct register_comparison comparison);
void clear_comparison_state(struct registers *state);
void set_compare_from_operation(struct registers *regs, int reg, uintptr_t mask);

uintptr_t search_find_next_address(struct address_list *list, uintptr_t address);
void add_address_to_list(struct address_list *list, uintptr_t address);
bool check_for_searched_function(struct loader_context *loader, ins_ptr address);

__attribute__((nonnull(1, 2, 6))) void add_match_and_sources(const struct loader_context *loader, struct registers *regs, int dest_reg, int source_reg, register_mask sources, __attribute__((unused)) ins_ptr ins);
__attribute__((nonnull(1, 2, 4))) void clear_match(const struct loader_context *loader, struct registers *regs, int register_index, __attribute__((unused)) ins_ptr ins);
__attribute__((nonnull(1, 2, 4))) void clear_match_keep_stack(__attribute__((unused)) const struct loader_context *loader, struct registers *regs, int register_index, __attribute__((unused)) ins_ptr ins);

__attribute__((nonnull(1))) void push_stack(const struct loader_context *loader, struct registers *regs, int push_count, ins_ptr ins);
__attribute__((nonnull(1))) void pop_stack(const struct loader_context *loader, struct registers *regs, int pop_count, ins_ptr ins);

__attribute__((nonnull(1, 2))) void dump_registers(const struct loader_context *loader, const struct registers *state, register_mask registers);
__attribute__((nonnull(1, 2))) void dump_nonempty_registers(const struct loader_context *loader, const struct registers *state, register_mask registers);

void add_registers(struct register_state *dest, const struct register_state *source);

bool combine_register_states(struct register_state *out_state, const struct register_state *combine_state, __attribute__((unused)) int register_index);

enum possible_conditions
{
	ALWAYS_MATCHES = 0x1,
	NEVER_MATCHES = 0x2,
	POSSIBLY_MATCHES = 0x3,
};

enum possible_conditions calculate_possible_conditions(__attribute__((unused)) const struct loader_context *loader, ins_conditional_type cond, struct registers *current_state);


enum basic_op_usage
{
	BASIC_OP_USED_NEITHER = 0,
	BASIC_OP_USED_RIGHT = 1,
	BASIC_OP_USED_LEFT = 2,
	BASIC_OP_USED_BOTH = 3,
};

#define BASIC_OP_ARGS                                                                                                                                                                                                             \
	struct register_state dest[static 1], const struct register_state source[static 1], __attribute__((unused)) int dest_reg, __attribute__((unused)) int source_reg, __attribute__((unused)) enum ins_operand_size operand_size, \
		__attribute__((unused)) struct additional_result additional[static 1]
typedef __attribute__((warn_unused_result)) enum basic_op_usage (*basic_op)(BASIC_OP_ARGS);

enum basic_op_usage basic_op_unknown(BASIC_OP_ARGS);
enum basic_op_usage basic_op_add(BASIC_OP_ARGS);
enum basic_op_usage basic_op_or(BASIC_OP_ARGS);
enum basic_op_usage basic_op_adc(BASIC_OP_ARGS);
enum basic_op_usage basic_op_and(BASIC_OP_ARGS);
enum basic_op_usage basic_op_sbb(BASIC_OP_ARGS);
enum basic_op_usage basic_op_sub(BASIC_OP_ARGS);
enum basic_op_usage basic_op_xor(BASIC_OP_ARGS);
enum basic_op_usage basic_op_shr(BASIC_OP_ARGS);
enum basic_op_usage basic_op_shl(BASIC_OP_ARGS);
enum basic_op_usage basic_op_sar(BASIC_OP_ARGS);
enum basic_op_usage basic_op_ror(BASIC_OP_ARGS);
enum basic_op_usage basic_op_mul(BASIC_OP_ARGS);

enum
{
	TRACE_USES_FRAME_POINTER = 1,
#ifdef __aarch64__
	TRACE_MEMORY_LOAD_RECURSION_STEP = 2,
	TRACE_MEMORY_LOAD_RECURSION_LIMIT = 6,
#endif
};

#define ANALYZE_PRIMARY_RESULT() \
	do { \
		self->description = "primary result"; \
		*effects |= analyze_instructions(analysis, required_effects, &self->current_state, ins, self, trace_flags) & ~(EFFECT_AFTER_STARTUP | EFFECT_PROCESSING | EFFECT_ENTER_CALLS); \
	} while (0)
#define CHECK_AND_SPLIT_ON_ADDITIONAL_STATE(reg) \
	do {                                         \
		if (UNLIKELY(additional.used)) {         \
			additional_reg = reg;                \
			goto process_split_results;          \
		}                                        \
	} while (0)

static inline void apply_pending_stack_clear(struct analysis_frame *self)
{
	if (UNLIKELY(self->pending_stack_clear)) {
		LOG("clearing stack after call");
		{
			for_each_bit (self->pending_stack_clear, bit, i) {
				if (SHOULD_LOG && register_is_partially_known(&self->current_state.registers[i])) {
					ERROR_NOPREFIX("clearing", name_for_register(i));
				}
#if STORE_LAST_MODIFIED
				if (register_is_partially_known(&self->current_state.registers[i])) {
					self->current_state.last_modify_ins[i] = self->address;
				}
#endif
				clear_register(&self->current_state.registers[i]);
				self->current_state.sources[i] = 0;
				self->current_state.matches[i] = 0;
			}
		}
		for (int i = 0; i < REGISTER_STACK_0; i++) {
			self->current_state.matches[i] &= ~self->pending_stack_clear;
		}
		self->pending_stack_clear = 0;
	}
}

enum
{
	MAX_LOOKUP_TABLE_SIZE = 0x408,
};


__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool canonicalize_register(struct register_state *reg)
{
	if (reg->value > reg->max) {
		clear_register(reg);
		return true;
	}
	return false;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) __attribute__((unused)) static inline bool register_is_partially_known_8bit(const struct register_state *reg)
{
	return reg->value != (uintptr_t)0 || reg->max < 0xff;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) __attribute__((unused)) static inline bool register_is_partially_known_16bit(const struct register_state *reg)
{
	return reg->value != (uintptr_t)0 || reg->max < 0xffff;
}

__attribute__((nonnull(1))) __attribute__((always_inline)) static inline bool register_is_partially_known_32bit(const struct register_state *reg)
{
	return reg->value != (uintptr_t)0 || reg->max < 0xffffffff;
}

__attribute__((nonnull(1, 2))) __attribute__((always_inline)) static inline bool register_is_subset_of_register(const struct register_state *potential_subset, const struct register_state *potential_superset)
{
	return potential_subset->value >= potential_superset->value && potential_subset->max <= potential_superset->max;
}

__attribute__((always_inline)) static inline struct register_state union_of_register_states(struct register_state a, struct register_state b)
{
	return (struct register_state){
		.value = a.value < b.value ? a.value : b.value,
		.max = a.max > b.max ? a.max : b.max,
	};
}

struct searched_instruction_data_entry
{
	register_mask used_registers;
	register_mask modified;
	register_mask requires_known_target;
	function_effects effects;
	uint8_t widen_count[REGISTER_COUNT];
	uint8_t used_count;
	uint16_t generation;
	struct register_state registers[];
};

struct searched_instruction_data
{
	register_mask relevant_registers;
	register_mask preserved_registers;
	register_mask preserved_and_kept_registers;
	uint32_t end_offset;
	function_effects sticky_effects;
	uint16_t callback_index;
	ins_ptr next_ins;
	struct searched_instruction_data_entry entries[];
};

struct searched_instruction_entry
{
	ins_ptr address;
	struct searched_instruction_data *data;
};

struct searched_instruction_entry *table_entry_for_token(struct searched_instructions *search, ins_ptr addr, struct effect_token *token);

#define TLSDESC_ADDR (uintptr_t)0x43534544534C54

#endif
