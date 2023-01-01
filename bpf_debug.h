#ifndef BPF_DEBUG_H
#define BPF_DEBUG_H

#include <linux/filter.h>
#include <stddef.h>
#include <stdint.h>

#include "axon.h"

struct bpf_insn {
	uint32_t code;
	uint32_t jt;
	uint32_t jf;
	uint32_t k;
};

struct bpf_prog {
	unsigned long len;
	struct bpf_insn *filter;
};

char *copy_bpf_insn_description(struct bpf_insn insn);
char *copy_bpf_prog_description(struct bpf_prog prog, const char **descriptions);

const char *bpf_interpret(struct sock_fprog prog, const char *buffer, size_t length, uint32_t *out_result);

__attribute__((always_inline))
static inline bool bpf_code_is_valid(uint32_t code) {
	return code < (1 << sizeof(uint16_t) * 8);
}

__attribute__((always_inline))
static inline uint16_t validate_bpf_code(uint32_t code) {
	if (UNLIKELY(!bpf_code_is_valid(code))) {
		ERROR("invalid bpf code", (intptr_t)code);
		abort();
	}
	return (uint16_t)code;
}

__attribute__((always_inline))
static inline bool bpf_jump_offset_is_valid(uint32_t offset) {
	return offset < (1 << sizeof(uint8_t) * 8);
}

__attribute__((always_inline))
static inline uint8_t validate_bpf_jump_offset(uint32_t offset) {
	if (UNLIKELY(!bpf_jump_offset_is_valid(offset))) {
		ERROR("invalid bpf jump offset", (intptr_t)offset);
		abort();
	}
	return (uint8_t)offset;
}

void optimize_bpf_fprog(struct bpf_prog *prog, char **descriptions);

void expand_long_bpf_jumps(struct bpf_prog *prog, char **descriptions, size_t capacity);

struct sock_fprog convert_to_sock_fprog(struct bpf_prog prog);

#endif
