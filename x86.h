#ifndef X86_H
#define X86_H

#include <stdbool.h>
#include <stdint.h>

typedef int16_t x86_int16 __attribute__((aligned(1)));
typedef uint16_t x86_uint16 __attribute__((aligned(1)));
typedef int32_t x86_int32 __attribute__((aligned(1)));
typedef uint32_t x86_uint32 __attribute__((aligned(1)));
typedef int64_t x86_int64 __attribute__((aligned(1)));
typedef uint64_t x86_uint64 __attribute__((aligned(1)));

// x86_is_syscall_instruction checks if the instruction at address is a syscall
bool x86_is_syscall_instruction(const uint8_t *addr);

// x86_is_nop_instruction checks if the instruction at address is a nop
bool x86_is_nop_instruction(const uint8_t *addr);

// x86_is_return_instruction checks if the instruction is a return
bool x86_is_return_instruction(const uint8_t *addr);

static inline bool x86_is_endbr64_instruction(const uint8_t *addr)
{
	return addr[0] == 0xf3 && addr[1] == 0x0f && addr[2] == 0x1e && addr[3] == 0xfa;
}

enum x86_jumps {
	X86_JUMPS_NEVER,
	X86_JUMPS_ALWAYS,
	X86_JUMPS_OR_CONTINUES,
};

// x86_jump_addresses_at_instruction determines when an instruction jumps, and
// fills the jump target
__attribute__((warn_unused_result))
__attribute__((nonnull(1, 2)))
enum x86_jumps x86_jump_addresses_at_instruction(const uint8_t *ins, const uint8_t **out_jump);

static inline bool x86_is_jo_instruction(const uint8_t *ins)
{
	return *ins == 0x70 || (*ins == 0x0f && ins[1] == 0x80);
}

static inline bool x86_is_jno_instruction(const uint8_t *ins)
{
	return *ins == 0x71 || (*ins == 0x0f && ins[1] == 0x81);
}

static inline bool x86_is_jb_instruction(const uint8_t *ins)
{
	return *ins == 0x72 || (*ins == 0x0f && ins[1] == 0x82);
}

static inline bool x86_is_jae_instruction(const uint8_t *ins)
{
	return *ins == 0x73 || (*ins == 0x0f && ins[1] == 0x83);
}

static inline bool x86_is_je_instruction(const uint8_t *ins)
{
	return *ins == 0x74 || (*ins == 0x0f && ins[1] == 0x84);
}

static inline bool x86_is_jne_instruction(const uint8_t *ins)
{
	return *ins == 0x75 || (*ins == 0x0f && ins[1] == 0x85);
}

static inline bool x86_is_jbe_instruction(const uint8_t *ins)
{
	return *ins == 0x76 || (*ins == 0x0f && ins[1] == 0x86);
}

static inline bool x86_is_ja_instruction(const uint8_t *ins)
{
	return *ins == 0x77 || (*ins == 0x0f && ins[1] == 0x87);
}

static inline bool x86_is_js_instruction(const uint8_t *ins)
{
	return *ins == 0x78 || (*ins == 0x0f && ins[1] == 0x88);
}

static inline bool x86_is_jns_instruction(const uint8_t *ins)
{
	return *ins == 0x79 || (*ins == 0x0f && ins[1] == 0x89);
}

static inline bool x86_is_jp_instruction(const uint8_t *ins)
{
	return *ins == 0x7a || (*ins == 0x0f && ins[1] == 0x8a);
}

static inline bool x86_is_jpo_instruction(const uint8_t *ins)
{
	return *ins == 0x7b || (*ins == 0x0f && ins[1] == 0x8b);
}

static inline bool x86_is_jl_instruction(const uint8_t *ins)
{
	return *ins == 0x7c || (*ins == 0x0f && ins[1] == 0x8c);
}

static inline bool x86_is_jge_instruction(const uint8_t *ins)
{
	return *ins == 0x7d || (*ins == 0x0f && ins[1] == 0x8d);
}

static inline bool x86_is_jng_instruction(const uint8_t *ins)
{
	return *ins == 0x7e || (*ins == 0x0f && ins[1] == 0x8e);
}

static inline bool x86_is_jg_instruction(const uint8_t *ins)
{
	return *ins == 0x7f || (*ins == 0x0f && ins[1] == 0x8f);
}

#endif
