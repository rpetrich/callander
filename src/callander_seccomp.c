#include "callander.h"

#ifdef __linux__

#include "bpf_debug.h"
#include "callander_print.h"
#include "linux.h"

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdlib.h>

static inline ssize_t seccomp_data_offset_for_register(enum register_index reg)
{
	switch (reg) {
		case REGISTER_SYSCALL_NR:
			return offsetof(struct seccomp_data, nr);
		case REGISTER_SYSCALL_ARG0:
			return offsetof(struct seccomp_data, args);
		case REGISTER_SYSCALL_ARG1:
			return offsetof(struct seccomp_data, args) + sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG2:
			return offsetof(struct seccomp_data, args) + 2 * sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG3:
			return offsetof(struct seccomp_data, args) + 3 * sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG4:
			return offsetof(struct seccomp_data, args) + 4 * sizeof(uint64_t);
		case REGISTER_SYSCALL_ARG5:
			return offsetof(struct seccomp_data, args) + 5 * sizeof(uint64_t);
		default:
			return -1;
	}
}

static inline bool special_arg_indexes_for_syscall(int nr, enum register_index *out_map_base_index, enum register_index *out_map_size_index)
{
	switch (nr) {
		case LINUX_SYS_mmap:
		case LINUX_SYS_munmap:
		case LINUX_SYS_mremap:
		case LINUX_SYS_mprotect:
		case LINUX_SYS_pkey_mprotect:
		case LINUX_SYS_remap_file_pages:
			*out_map_base_index = syscall_argument_abi_register_indexes[0];
			*out_map_size_index = syscall_argument_abi_register_indexes[1];
			return true;
		// case LINUX_SYS_shmat:
		// 	break;
		default:
			return false;
	}
}

static void push_bpf_insn(struct bpf_insn **array, size_t *cap, size_t *pos, struct bpf_insn value)
{
	size_t new_pos = *pos;
	size_t new_size = new_pos + 1;
	*pos = new_size;
	if (new_size > *cap) {
		*cap = new_size * 2;
		*array = realloc(*array, *cap * sizeof(value));
	}
	(*array)[new_pos] = value;
}

static void push_description(char ***descriptions, size_t *cap, size_t pos, char *description)
{
	if (pos > *cap) {
		*cap = pos * 2;
		*descriptions = realloc(*descriptions, *cap * sizeof(*descriptions));
	}
	(*descriptions)[pos - 1] = description;
}

struct sock_fprog generate_seccomp_program(struct loader_context *loader, const struct recorded_syscalls *syscalls, const struct mapped_region_info *blocked_memory_regions, uint32_t syscall_range_low, uint32_t syscall_range_high)
{
	bool record_descriptions = SHOULD_LOG;
	struct recorded_syscall *list = syscalls->list;
	int count = syscalls->count;
	struct bpf_insn *filter = NULL;
	char **descriptions = NULL;
	size_t filter_cap = 0;
	size_t descriptions_cap = 0;
	size_t pos = 0;
	// validate architecture
	// can't exec, so don't bother -- architecture cannot change
	// push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)));
	// push_description(&descriptions, &descriptions_cap, pos, strdup("load arch"));
	// push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, CURRENT_AUDIT_ARCH, 1, 0));
	// push_description(&descriptions, &descriptions_cap, pos, strdup("compare CURRENT_AUDIT_ARCH"));
	// push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP));
	// push_description(&descriptions, &descriptions_cap, pos, strdup("return kill process"));
	// load syscall number
	push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)));
	if (record_descriptions) {
		push_description(&descriptions, &descriptions_cap, pos, strdup("load nr"));
	}
	if (syscall_range_low != 0) {
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, syscall_range_low, 1, 0));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("check syscall low"));
		}
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
		}
	}
	if (syscall_range_high != ~(uint32_t)0) {
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, syscall_range_high, 0, 1));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("check syscall high"));
		}
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
		}
	}
	for (int i = 0; i < count;) {
		uintptr_t nr = list[i].nr;
		if (nr < syscall_range_low || nr > syscall_range_high) {
			i++;
			continue;
		}
		size_t nr_pos = pos;
		push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 0));
		if (record_descriptions) {
			push_description(&descriptions, &descriptions_cap, pos, strdup(name_for_syscall(nr)));
		}
		if (blocked_memory_regions != NULL && blocked_memory_regions->count != 0) {
			enum register_index map_base_reg;
			enum register_index map_size_reg;
			if (special_arg_indexes_for_syscall(nr, &map_base_reg, &map_size_reg)) {
				// read the low part of size
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(map_size_reg)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of size"));
				}
				// shuffle to x register
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_MISC + BPF_TAX, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("shuffle to x register"));
				}
				// read the low part of base
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(map_base_reg)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of base"));
				}
				// add to form the new low bits of max of range
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("add low parts of size and base"));
				}
				// store low bits to the stack at slot 0
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ST, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("store low bits of max to the stack"));
				}
				// check for overflow
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGE + BPF_X, 0, 3, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("check for overflow"));
				}
				// read the high part of size
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(map_size_reg) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of size"));
				}
				// add 1 for overflow
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ALU + BPF_ADD + BPF_K, 1));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("add overflow"));
				}
				// jump to "shuffle to x register"
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_JMP + BPF_JA + BPF_K, 1));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("jump to \"shuffle to x register\""));
				}
				// read the high part of size
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(map_size_reg) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of size"));
				}
				// shuffle to x register
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_MISC + BPF_TAX, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("shuffle to x register"));
				}
				// read the high part of base
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(map_base_reg) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of base"));
				}
				// add to form the new high bits of max of range
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("add high parts of size and base"));
				}
				// store high bits to the stack at slot 1
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_ST, 1));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("store high bits of max to the stack"));
				}
				for (int j = 0; j < blocked_memory_regions->count; j++) {
					// reload the high bits of the end of the requested range
					if (j != 0) {
						// not necessary on the first iteration since it was just calculated
						push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_MEM, 1));
						if (record_descriptions) {
							push_description(&descriptions, &descriptions_cap, pos, strdup("reload high bits of max from the stack"));
						}
					}
					// compare the high bits of the end of the requested range with the start of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, blocked_memory_regions->list[j].start >> 32, 0, 9 /* to next case */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of max"));
					}
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, blocked_memory_regions->list[j].start >> 32, 0, 2 /* to after low bits comparison */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of max equality"));
					}
					// load the low bits of the requested range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_MEM, 0));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("reload low bits of max from the stack"));
					}
					// compare the low bits of the end of the requested range with the start of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, blocked_memory_regions->list[j].start & ~(uint32_t)0, 0, 6 /* to next case */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare low bits of max"));
					}
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(map_base_reg) + sizeof(uint32_t)));
					// load the high bits of the start of the requested range
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of base"));
					}
					// compare the high bits of the start of the requested range with the end of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, blocked_memory_regions->list[j].end >> 32, 4 /* to next case */, 0));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of base"));
					}
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, blocked_memory_regions->list[j].end >> 32, 0, 2 /* to after low bits comparison */));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare high bits of base equality"));
					}
					// load the low bits of the start of the requested range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(map_base_reg)));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of base"));
					}
					// compare the low bits of the start of the requested range with the end of the blocked range
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, blocked_memory_regions->list[j].end & ~(uint32_t)0, 1 /* to next case */, 0));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("compare low bits of base"));
					}
					// requested range overlaps with the blocked range, return EPERM
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM));
					if (record_descriptions) {
						push_description(&descriptions, &descriptions_cap, pos, strdup("return EPERM"));
					}
				}
			}
		}
		int attributes = info_for_syscall(nr).attributes;
		if (list[i].ins != NULL && (attributes & SYSCALL_CAN_BE_FROM_ANYWHERE) == 0) {
			// compare instruction pointers
			do {
				// read high part of instruction pointer
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + sizeof(uint32_t)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load high part of instruction_pointer"));
				}
				uintptr_t addr = translate_analysis_address_to_child(loader, list[i].ins) + SYSCALL_INSTRUCTION_SIZE;
				// compare high part of instruction pointer
				size_t hi_pos = pos;
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, addr >> 32, 0, 0));
				if (record_descriptions) {
					char *desc = copy_address_description(loader, list[i].ins);
					char *compare_hi = malloc(30 + fs_strlen(desc));
					fs_utoah(addr >> 32, fs_strcpy(fs_strcpy(fs_strcpy(compare_hi, "compare "), desc), " hi part "));
					free(desc);
					push_description(&descriptions, &descriptions_cap, pos, compare_hi);
				}
				// load low part of instruction pointer
				push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)));
				if (record_descriptions) {
					push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of instruction_pointer"));
				}
				uintptr_t next_addr = addr;
				do {
					uintptr_t low_addr = next_addr;
					// compare low part of instruction pointer
					size_t low_pos = pos;
					push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (uint32_t)low_addr, 0, 1));
					if (record_descriptions) {
						char *desc = copy_address_description(loader, list[i].ins);
						char *compare_low = malloc(30 + fs_strlen(desc));
						fs_utoah(low_addr & 0xffffffff, fs_strcpy(fs_strcpy(fs_strcpy(compare_low, "compare "), desc), " low part "));
						free(desc);
						push_description(&descriptions, &descriptions_cap, pos, compare_low);
					}
					// skip to next syscall + addr combination
					do {
						struct
						{
							size_t compare_hi;
							size_t compare_low_value;
							size_t compare_low_max;
						} arg_pos[6] = {0};
						for (int j = 0; j < (attributes & SYSCALL_ARGC_MASK); j++) {
							int arg_register = syscall_argument_abi_register_indexes[j];
							const struct register_state match_state = translate_register_state_to_child(loader, list[i].registers.registers[arg_register]);
							if (register_is_partially_known(&match_state) && (match_state.value >> 32) == (match_state.max >> 32)) {
								// read high part of argument
								push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(arg_register) + sizeof(uint32_t)));
								if (record_descriptions) {
									char *buf = malloc(50);
									fs_utoa(j, fs_strcpy(buf, "load high part of argument "));
									push_description(&descriptions, &descriptions_cap, pos, buf);
								}
								// compare high part of argument
								arg_pos[j].compare_hi = pos;
								push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, match_state.value >> 32, 0, 0));
								if (record_descriptions) {
									char *buf = malloc(50);
									fs_utoah(match_state.value >> 32, fs_strcpy(buf, "compare high part of argument "));
									push_description(&descriptions, &descriptions_cap, pos, buf);
								}
								// read low part of argument
								push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_LD + BPF_W + BPF_ABS, seccomp_data_offset_for_register(arg_register)));
								if (record_descriptions) {
									push_description(&descriptions, &descriptions_cap, pos, strdup("load low part of argument"));
								}
								// compare low part of argument
								uint32_t masked_value = match_state.value;
								uint32_t masked_max = match_state.max;
								if (masked_value == masked_max) {
									// compare == value
									arg_pos[j].compare_low_value = pos;
									push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, match_state.value, 0, 0));
									if (record_descriptions) {
										char *buf = malloc(50);
										fs_utoah(masked_value, fs_strcpy(buf, "compare low part of argument "));
										push_description(&descriptions, &descriptions_cap, pos, buf);
									}
								} else {
									// compare >= min
									if (masked_value != 0) {
										arg_pos[j].compare_low_value = pos;
										push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, masked_value, 0, 0));
										if (record_descriptions) {
											char *buf = malloc(50);
											fs_utoah(masked_value, fs_strcpy(buf, "compare low value of argument "));
											push_description(&descriptions, &descriptions_cap, pos, buf);
										}
									}
									// compare <= max
									if (masked_value != 0xffffffff) {
										arg_pos[j].compare_low_max = pos;
										push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, masked_max, 0, 0));
										if (record_descriptions) {
											char *buf = malloc(50);
											fs_utoah(masked_max, fs_strcpy(buf, "compare high value of argument "));
											push_description(&descriptions, &descriptions_cap, pos, buf);
										}
									}
								}
							}
						}
						// return allow
						push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
						if (record_descriptions) {
							push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
						}
						// else to next register comparison or the final return trap
						for (int j = 0; j < (attributes & SYSCALL_ARGC_MASK); j++) {
							size_t inner_hi_pos = arg_pos[j].compare_hi;
							if (inner_hi_pos != 0) {
								filter[hi_pos].jf = pos - inner_hi_pos - 1;
							}
							size_t low_value_pos = arg_pos[j].compare_low_value;
							if (low_value_pos != 0) {
								filter[low_value_pos].jf = pos - low_value_pos - 1;
							}
							size_t low_max_pos = arg_pos[j].compare_low_max;
							if (low_max_pos != 0) {
								filter[low_max_pos].jt = pos - low_max_pos - 1;
							}
						}
						i++;
						if (i == count) {
							break;
						}
						next_addr = translate_analysis_address_to_child(loader, list[i].ins) + SYSCALL_INSTRUCTION_SIZE;
					} while (low_addr == next_addr && list[i].nr == nr);
					// else to next address
					filter[low_pos].jf = pos - low_pos - 1;
				} while (i != count && (addr >> 32) == (next_addr >> 32) && list[i].nr == nr);
				// else to next address
				filter[hi_pos].jf = pos - hi_pos - 1;
			} while (i != count && list[i].nr == nr);
			push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP));
			if (record_descriptions) {
				push_description(&descriptions, &descriptions_cap, pos, strdup("return trap"));
			}
		} else {
			// allow all
			push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
			if (record_descriptions) {
				push_description(&descriptions, &descriptions_cap, pos, strdup("return allow"));
			}
			// skip to next syscall
			do {
				i++;
			} while (i != count && list[i].nr == nr);
		}
		// else to next syscall or the final return trap
		filter[nr_pos].jf = pos - nr_pos - 1;
	}
	push_bpf_insn(&filter, &filter_cap, &pos, (struct bpf_insn)BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP));
	if (record_descriptions) {
		push_description(&descriptions, &descriptions_cap, pos, strdup("return trap"));
	}
	struct bpf_prog prog = {
		.len = pos,
		.filter = filter,
	};
	optimize_bpf_fprog(&prog, descriptions);
	expand_long_bpf_jumps(&prog, descriptions, pos);
	if (record_descriptions) {
		ERROR("program: ", temp_str(copy_bpf_prog_description(prog, (const char **)descriptions)));
	}
	if (descriptions != NULL) {
		for (size_t i = 0; i < prog.len; i++) {
			free(descriptions[i]);
		}
		free(descriptions);
	}
	struct sock_fprog result = convert_to_sock_fprog(prog);
	free(filter);
	return result;
}

#endif
