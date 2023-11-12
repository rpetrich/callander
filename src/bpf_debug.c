#include "bpf_debug.h"

#include <stdlib.h>

#include "freestanding.h"
#include "axon.h"

static const char *bpf_class_description(uint16_t class)
{
	switch (class) {
		case BPF_LD:
			return "BPF_LD";
		case BPF_LDX:
			return "BPF_LDX";
		case BPF_ST:
			return "BPF_ST";
		case BPF_ALU:
			return "BPF_ALU";
		case BPF_JMP:
			return "BPF_JMP";
		case BPF_RET:
			return "BPF_RET";
		case BPF_MISC:
			return "BPF_MISC";
		default:
			return "BPF_INVALID_CLASS";
	}
}

static const char *bpf_size_description(uint16_t size)
{
	switch (size) {
		case BPF_W:
			return "BPF_W";
		case BPF_H:
			return "BPF_H";
		case BPF_B:
			return "BPF_B";
		case 0x18: // BPF_DW:
			return "BPF_DW";
		default:
			return "BPF_INVALID_SIZE";
	}
}

static const char *bpf_mode_description(uint16_t mode)
{
	switch (mode) {
		case BPF_IMM:
			return "BPF_IMM";
		case BPF_ABS:
			return "BPF_ABS";
		case BPF_IND:
			return "BPF_IND";
		case BPF_MEM:
			return "BPF_MEM";
		case BPF_LEN:
			return "BPF_LEN";
		case BPF_MSH:
			return "BPF_MSH";
		default:
			return "BPF_INVALID_MODE";
	}
}

static const char *bpf_alu_op_description(uint16_t alu_op)
{
	switch (alu_op) {
		case BPF_ADD:
			return "BPF_ADD";
		case BPF_SUB:
			return "BPF_SUB";
		case BPF_MUL:
			return "BPF_MUL";
		case BPF_OR:
			return "BPF_OR";
		case BPF_AND:
			return "BPF_AND";
		case BPF_LSH:
			return "BPF_LSH";
		case BPF_RSH:
			return "BPF_RSH";
		case BPF_NEG:
			return "BPF_NEG";
		case BPF_MOD:
			return "BPF_MOD";
		case BPF_XOR:
			return "BPF_XOR";
		default:
			return "BPF_INVALID_ALU_OP";
	}
}

static const char *bpf_jmp_op_description(uint16_t jmp_op)
{
	switch (jmp_op) {
		case BPF_JA:
			return "BPF_JA";
		case BPF_JEQ:
			return "BPF_JEQ";
		case BPF_JGT:
			return "BPF_JGT";
		case BPF_JGE:
			return "BPF_JGE";
		case BPF_JSET:
			return "BPF_JSET";
		default:
			return "BPF_INVALID_JMP_OP";
	}
}

static const char *bpf_src_description(uint16_t src)
{
	switch (src) {
		case BPF_K:
			return "BPF_K";
		case BPF_X:
			return "BPF_X";
		case BPF_A:
			return "BPF_A";
		default:
			return "BPF_INVALID_SRC";
	}
}

__attribute__((used))
char *copy_bpf_insn_description(struct bpf_insn insn)
{
	const char *prefix = "{ .code = ";
	const char *class = bpf_class_description(BPF_CLASS(insn.code));
	const char *size = bpf_size_description(BPF_SIZE(insn.code));
	const char *mode = bpf_mode_description(BPF_MODE(insn.code));
	const char *src = bpf_src_description(BPF_SRC(insn.code));
	const char *op;
	switch (BPF_CLASS(insn.code)) {
		case BPF_ALU:
			op = bpf_alu_op_description(BPF_OP(insn.code));
			break;
		case BPF_JMP:
			op = bpf_jmp_op_description(BPF_OP(insn.code));
			break;
		default:
			op = NULL;
			break;
	}
	const char *jt_prefix = ", .jt = ";
	char jt[16];
	int jt_len = fs_utoa(insn.jt, jt);
	const char *jf_prefix = ", .jf = ";
	char jf[16];
	int jf_len = fs_utoa(insn.jf, jf);
	const char *k_prefix = ", .k = ";
	char k[16];
	int k_len = BPF_CLASS(insn.code) == BPF_RET || insn.k > 4096 ? fs_utoah(insn.k, k) : fs_utoa(insn.k, k);
	const char *suffix = " }";
	char *result = malloc(fs_strlen(prefix) + fs_strlen(class) + 1 + fs_strlen(size) + 1 + fs_strlen(mode) + 1 + fs_strlen(src) + (op != NULL ? fs_strlen(op) + 1 : 0) + (BPF_CLASS(insn.code) == BPF_JMP ? fs_strlen(jt_prefix) + jt_len + fs_strlen(jf_prefix) + jf_len : 0) + fs_strlen(k_prefix) + k_len + fs_strlen(suffix) + 1);
	char *buf = fs_strcpy(result, prefix);
	buf = fs_strcpy(buf, class);
	*buf++ = '|';
	buf = fs_strcpy(buf, size);
	*buf++ = '|';
	buf = fs_strcpy(buf, mode);
	*buf++ = '|';
	buf = fs_strcpy(buf, src);
	if (op != NULL) {
		*buf++ = '|';
		buf = fs_strcpy(buf, op);
	}
	if (BPF_CLASS(insn.code) == BPF_JMP) {
		buf = fs_strcpy(buf, jt_prefix);
		buf = fs_strcpy(buf, jt);
		buf = fs_strcpy(buf, jf_prefix);
		buf = fs_strcpy(buf, jf);
	}
	buf = fs_strcpy(buf, k_prefix);
	buf = fs_strcpy(buf, k);
	buf = fs_strcpy(buf, suffix);
	return result;
}

__attribute__((used))
char *copy_bpf_prog_description(struct bpf_prog prog, const char **descriptions)
{
	char **bufs = malloc(prog.len * sizeof(char *));
	size_t total_len = 1;
	for (unsigned long i = 0; i < prog.len; i++) {
		if (i != 0) {
			int class = BPF_CLASS(prog.filter[i-1].code);
			if (class == BPF_JMP || class == BPF_RET) {
				total_len++; // '\n'
			}
			total_len++; // '\n'
		}
		char buf[10];
		total_len += fs_utoa(i, buf);
		total_len += 2; // ': '
		bufs[i] = copy_bpf_insn_description(prog.filter[i]);
		total_len += fs_strlen(bufs[i]);
		if (BPF_CLASS(prog.filter[i].code) == BPF_JMP) {
			if (prog.filter[i].jt != 0) {
				total_len += 4; // " jt="
				uint32_t jt = prog.filter[i].jt + i + 1;
				total_len += fs_utoa(jt, buf);
				if (jt < prog.len && descriptions && descriptions[jt]) {
					total_len += 2; // '(' ')'
					total_len += fs_strlen(descriptions[jt]);
				}
			}
			if (prog.filter[i].jf != 0) {
				total_len += 4; // " jf="
				uint32_t jf = prog.filter[i].jf + i + 1;
				total_len += fs_utoa(jf, buf);
				if (jf < prog.len && descriptions && descriptions[jf]) {
					total_len += 2; // '(' ')'
					total_len += fs_strlen(descriptions[jf]);
				}
			}
		}
		if (descriptions && descriptions[i]) {
			total_len++; // ' '
			total_len += fs_strlen(descriptions[i]);
		}
	}
	char *result = malloc(total_len);
	char *cur = result;
	for (uint32_t i = 0; i < prog.len; i++) {
		if (i != 0) {
			int class = BPF_CLASS(prog.filter[i-1].code);
			if (class == BPF_JMP || class == BPF_RET) {
				*cur++ = '\n';
			}
			*cur++ = '\n';
		}
		cur += fs_utoa(i, cur);
		*cur++ = ':';
		*cur++ = ' ';
		cur = fs_strcpy(cur, bufs[i]);
		if (BPF_CLASS(prog.filter[i].code) == BPF_JMP) {
			if (prog.filter[i].jt != 0) {
				cur = fs_strcpy(cur, " jt=");
				uint32_t jt = prog.filter[i].jt + i + 1;
				cur += fs_utoa(jt, cur);
				if (jt < prog.len && descriptions && descriptions[jt]) {
					*cur++ = '(';
					cur = fs_strcpy(cur, descriptions[jt]);
					*cur++ = ')';
				}
			}
			if (prog.filter[i].jf != 0) {
				cur = fs_strcpy(cur, " jf=");
				uint32_t jf = prog.filter[i].jf + i + 1;
				cur += fs_utoa(jf, cur);
				if (jf < prog.len && descriptions && descriptions[jf]) {
					*cur++ = '(';
					cur = fs_strcpy(cur, descriptions[jf]);
					*cur++ = ')';
				}
			}
		}
		if (descriptions && descriptions[i]) {
			*cur++ = ' ';
			cur = fs_strcpy(cur, descriptions[i]);
		}
	}
	*cur = '\0';
	free(bufs);
	return result;
}

__attribute__((used))
const char *bpf_interpret(struct sock_fprog prog, const char *buffer, size_t length, bool print_debug_messages, uint32_t *out_result)
{
	size_t pc = 0;
	uint32_t acc = 0;
	uint32_t index = 0;
	uint32_t scratch[BPF_MEMWORDS] = { 0 };
	for (; pc <= prog.len; pc++) {
		if (print_debug_messages) {
			ERROR("pc", (intptr_t)pc);
			ERROR("insn", temp_str(copy_bpf_insn_description((struct bpf_insn){
				.code = prog.filter[pc].code,
				.jt = prog.filter[pc].jt,
				.jf = prog.filter[pc].jf,
				.k = prog.filter[pc].k,
			})));
		}
		uint16_t code = prog.filter[pc].code;
		switch (BPF_CLASS(code)) {
			case BPF_LD: {
				size_t offset = 0;
				switch (BPF_MODE(code)) {
					case BPF_IMM:
						acc = prog.filter[pc].k;
						if (print_debug_messages) {
							ERROR("acc", acc);
						}
						goto next;
					case BPF_ABS:
						offset = prog.filter[pc].k;
						break;
					case BPF_IND:
						offset = index;
						break;
					case BPF_MEM:
						offset = prog.filter[pc].k;
						if (offset >= BPF_MEMWORDS) {
							return "invalid BPF_MEM index!";
						}
						acc = scratch[offset];
						if (print_debug_messages) {
							ERROR("acc", acc);
						}
						goto next;
					case BPF_LEN:
						acc = length;
						if (print_debug_messages) {
							ERROR("acc", acc);
						}
						goto next;
					case BPF_MSH:
						return "BPF_MSH invalid in this context!";
				}
				switch (BPF_SIZE(code)) {
					case BPF_W:
						if (offset + sizeof(uint32_t) > length) {
							return "BPF_W load beyond packet bounds";
						}
						acc = *(const uint32_t *)&buffer[offset];
						break;
					case BPF_H:
						if (offset + sizeof(uint16_t) > length) {
							return "BPF_H load beyond packet bounds";
						}
						acc = *(const uint16_t *)&buffer[offset];
						break;
					case BPF_B:
						if (offset + sizeof(uint8_t) > length) {
							return "BPF_B load beyond packet bounds";
						}
						acc = *(const uint8_t *)&buffer[offset];
						break;
					case 0x18:
						return "BPF_DW is only valid for eBPF!";
					default:
						return "invalid size for BPF_LD!";
				}
				if (print_debug_messages) {
					ERROR("acc", acc);
				}
				break;
			}
			case BPF_LDX: {
				switch (BPF_MODE(code)) {
					case BPF_MEM: {
						size_t offset = prog.filter[pc].k;
						if (offset >= BPF_MEMWORDS) {
							return "invalid BPF_MEM index!";
						}
						index = scratch[offset];
						break;
					}
					default:
						return "invalid mode for BPF_LDX!";
				}
				if (print_debug_messages) {
					ERROR("index", index);
				}
				break;
			}
			case BPF_ST: {
				size_t offset = prog.filter[pc].k;
				if (offset >= BPF_MEMWORDS) {
					return "invalid BPF_MEM index!";
				}
				scratch[offset] = acc;
				break;
			}
			case BPF_STX: {
				size_t offset = prog.filter[pc].k;
				if (offset >= BPF_MEMWORDS) {
					return "invalid BPF_MEM index!";
				}
				scratch[offset] = index;
				break;
			}
			case BPF_ALU: {
				uint32_t operand;
				switch (BPF_SRC(code)) {
					case BPF_K:
						operand = prog.filter[pc].k;
						break;
					case BPF_X:
						operand = index;
						break;
					default:
						if (BPF_OP(code) != BPF_NEG) {
							return "unsupported source in BPF_ALU!";
						}
				}
				switch (BPF_OP(code)) {
					case BPF_ADD:
						acc += operand;
						break;
					case BPF_SUB:
						acc -= operand;
						break;
					case BPF_MUL:
						acc *= operand;
						break;
					case BPF_DIV:
						acc /= operand;
						break;
					case BPF_AND:
						acc &= operand;
						break;
					case BPF_OR:
						acc |= operand;
						break;
					case BPF_LSH:
						acc <<= operand;
						break;
					case BPF_RSH:
						acc >>= operand;
						break;
					case BPF_NEG:
						acc = -acc;
						break;
					default:
						return "BPF_ALU operation not supported!";
				}
				if (print_debug_messages) {
					ERROR("acc", acc);
				}
				break;
			}
			case BPF_JMP: {
				uint32_t operand;
				switch (BPF_SRC(code)) {
					case BPF_K:
						operand = prog.filter[pc].k;
						break;
					case BPF_X:
						operand = index;
						break;
					default:
						return "unsupported source in BPF_JMP!";
				}
				switch (BPF_OP(code)) {
					case BPF_JA:
						pc += prog.filter[pc].k;
						break;
					case BPF_JGT:
						pc += (acc > operand) ? prog.filter[pc].jt : prog.filter[pc].jf;
						break;
					case BPF_JGE:
						pc += (acc >= operand) ? prog.filter[pc].jt : prog.filter[pc].jf;
						break;
					case BPF_JEQ:
						pc += (acc == operand) ? prog.filter[pc].jt : prog.filter[pc].jf;
						break;
					case BPF_JSET:
						pc += (acc & operand) ? prog.filter[pc].jt : prog.filter[pc].jf;
						break;
				}
				break;
			}
			case BPF_RET:
				switch (BPF_SRC(code)) {
					case BPF_K:
						*out_result = prog.filter[pc].k;
						return NULL;
					case BPF_A:
						*out_result = acc;
						return NULL;
					default:
						return "invalid source for BPF_RET!";
				}
			case BPF_MISC:
				switch (code) {
					case BPF_MISC|BPF_TAX:
						index = acc;
						if (print_debug_messages) {
							ERROR("index", index);
						}
						break;
					case BPF_MISC|BPF_TXA:
						acc = index;
						if (print_debug_messages) {
							ERROR("acc", acc);
						}
						break;
					default:
						return "BPF_MISC not supported!";
				}
				break;
			default:
				return "invalid class!";
		}
	next:
		;
	}
	return "program counter advanced outside the program";
}

__attribute__((always_inline))
static inline void saturating_increment(uint8_t *target) {
	if (*target < 0xff) {
		(*target)++;
	}
}

static void calculate_usage_counts(struct bpf_prog prog, uint8_t *counts)
{
	counts[0] = 1;
	for (uint32_t i = 1; i < prog.len; i++) {
		counts[i] = 0;
	}
	for (uint32_t i = 0; i < prog.len - 1; i++) {
		if (counts[i]) {
			switch (BPF_CLASS(prog.filter[i].code)) {
				case BPF_RET:
					// exits, so doesn't update any other usage bitmaps
					break;
				case BPF_JMP:
					// mark jump targets as used
					if (BPF_OP(prog.filter[i].code) == BPF_JA) {
						saturating_increment(&counts[i+prog.filter[i].k+1]);
					} else {
						saturating_increment(&counts[i+prog.filter[i].jt+1]);
						saturating_increment(&counts[i+prog.filter[i].jf+1]);
					}
					break;
				default:
					// all other instructions proceed normally
					saturating_increment(&counts[i+1]);
					break;
			}
		}
	}
}

static void fixup_jumps(struct bpf_insn *filter, size_t len, int offset)
{
	for (uint32_t i = 0; i < len; i++) {
		if (BPF_CLASS(filter[i].code) == BPF_JMP) {
			if (BPF_OP(filter[i].code) == BPF_JA) {
				if (i + 1 + filter[i].k >= (uint32_t)len) {
					filter[i].k += offset;
				}
			} else {
				if (i + 1 + filter[i].jt > len) {
					filter[i].jt += offset;
				}
				if (i + 1 + filter[i].jf > len) {
					filter[i].jf += offset;
				}
			}
		}
	}
}

__attribute__((used))
void optimize_bpf_fprog(struct bpf_prog *prog, char **descriptions)
{
	uint8_t *counts = malloc(sizeof(uint8_t) * prog->len);
	for (;;) {
		calculate_usage_counts(*prog, counts);
		bool optimized = false;
		// find later, but still valid jump targets
		for (uint32_t i = 0; i < prog->len; i++) {
			if (BPF_CLASS(prog->filter[i].code) == BPF_JMP) {
				if (BPF_OP(prog->filter[i].code) != BPF_JA) {
					uint32_t max = i + 1 + 0xff;
					if (max >= prog->len) {
						max = prog->len - 1;
					}
					uint32_t jt = i + 1 + prog->filter[i].jt;
					if (BPF_CLASS(prog->filter[jt].code) == BPF_RET) {
						uint32_t candidate = 0;
						uint32_t k = prog->filter[jt].k;
						for (uint32_t j = max; j > i + 1; j--) {
							if (BPF_CLASS(prog->filter[j].code) == BPF_RET && prog->filter[j].k == k) {
								if ((candidate == 0 || counts[candidate] < counts[j]) && j != jt) {
									candidate = j;
								}
							}
						}
						if (candidate) {
							saturating_increment(&counts[candidate]);
							prog->filter[i].jt = candidate - i - 1;
							optimized = true;
						}
					}
					uint32_t jf = i + 1 + prog->filter[i].jf;
					if (BPF_CLASS(prog->filter[jf].code) == BPF_RET) {
						uint32_t candidate = 0;
						uint32_t k = prog->filter[jf].k;
						for (uint32_t j = max; j > i + 1; j--) {
							if (BPF_CLASS(prog->filter[j].code) == BPF_RET && prog->filter[j].k == k) {
								if ((candidate == 0 || counts[candidate] < counts[j]) && j != jf) {
									candidate = j;
								}
							}
						}
						if (candidate) {
							saturating_increment(&counts[candidate]);
							prog->filter[i].jf = candidate - i - 1;
							optimized = true;
						}
					}
				}
			}
		}
		if (!optimized) {
			break;
		}
		// mark parts of the code that are used
		calculate_usage_counts(*prog, counts);
		// now delete any instructions that are unused, fixing up any jumps that pass over them
		// for (int i = 0; i < prog->len; i++) {
		unsigned long original_len = prog->len;
		for (uint32_t i = original_len - 1; i > 0; i--) {
			if (counts[i] == 0) {
				// fix up jumps
				fixup_jumps(prog->filter, i, -1);
				// remove the unused instruction
				fs_memmove(&prog->filter[i], &prog->filter[i+1], (prog->len - i - 1) * sizeof(prog->filter[0]));
				if (descriptions != NULL) {
					free(descriptions[i]);
					fs_memmove(&descriptions[i], &descriptions[i+1], (prog->len - i - 1) * sizeof(*descriptions));
				}
				prog->len--;
			}
		}
		if (original_len == prog->len) {
			break;
		}
	}
	free(counts);
}

__attribute__((used))
void expand_long_bpf_jumps(struct bpf_prog *prog, char **descriptions, size_t capacity)
{
	for (intptr_t i = prog->len - 1; i >= 0; i--) {
		if (BPF_CLASS(prog->filter[i].code) == BPF_JMP && BPF_OP(prog->filter[i].code) != BPF_JA) {
			if (UNLIKELY(!bpf_jump_offset_is_valid(prog->filter[i].jt + 1))) {
				if (UNLIKELY(prog->len >= capacity)) {
					capacity++;
					prog->filter = realloc(prog->filter, capacity * sizeof(prog->filter[0]));
				}
				fs_memmove(&prog->filter[i+2], &prog->filter[i+1], (prog->len - i - 1) * sizeof(prog->filter[0]));
				if (descriptions != NULL) {
					fs_memmove(&descriptions[i+2], &descriptions[i+1], (prog->len - i - 1) * sizeof(*descriptions));
					descriptions[i+1] = strdup("inserted absolute jump for jt");
				}
				prog->filter[i+1] = (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JA+BPF_K, prog->filter[i].jt, 0, 0);
				prog->filter[i].jt = 0;
				prog->filter[i].jf++;
				prog->len++;
				fixup_jumps(prog->filter, i, 1);
			}
			if (UNLIKELY(!bpf_jump_offset_is_valid(prog->filter[i].jf))) {
				if (UNLIKELY(prog->len >= capacity)) {
					capacity++;
					prog->filter = realloc(prog->filter, capacity * sizeof(prog->filter[0]));
				}
				fs_memmove(&prog->filter[i+2], &prog->filter[i+1], (prog->len - i - 1) * sizeof(prog->filter[0]));
				if (descriptions != NULL) {
					fs_memmove(&descriptions[i+2], &descriptions[i+1], (prog->len - i - 1) * sizeof(*descriptions));
					descriptions[i+1] = strdup("inserted absolute jump for jf");
				}
				prog->filter[i+1] = (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JA+BPF_K, prog->filter[i].jf, 0, 0);
				prog->filter[i].jf = 0;
				prog->filter[i].jt++;
				prog->len++;
				fixup_jumps(prog->filter, i, 1);
			}
		}
	}
}

__attribute__((used))
struct sock_fprog convert_to_sock_fprog(struct bpf_prog prog)
{
	struct sock_filter *filter = malloc(prog.len * sizeof(struct sock_filter));
	for (unsigned long i = 0; i < prog.len; i++) {
		if (UNLIKELY(!bpf_code_is_valid(prog.filter[i].code))) {
			ERROR("invalid code", temp_str(copy_bpf_insn_description(prog.filter[i])));
			DIE("for instruction at index", (intptr_t)i);
		}
		if (UNLIKELY(!bpf_jump_offset_is_valid(prog.filter[i].jt))) {
			ERROR("invalid jt", temp_str(copy_bpf_insn_description(prog.filter[i])));
			DIE("for instruction at index", (intptr_t)i);
		}
		if (UNLIKELY(!bpf_jump_offset_is_valid(prog.filter[i].jf))) {
			ERROR("invalid jf", temp_str(copy_bpf_insn_description(prog.filter[i])));
			DIE("for instruction at index", (intptr_t)i);
		}
		filter[i] = (struct sock_filter){
			.code = prog.filter[i].code,
			.jt = prog.filter[i].jt,
			.jf = prog.filter[i].jf,
			.k = prog.filter[i].k,
		};
	}
	return (struct sock_fprog){
		.filter = filter,
		.len = prog.len,
	};
}
