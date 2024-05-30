#ifndef CALLANDER_PRINT_H
#define CALLANDER_PRINT_H

#include "callander.h"

extern struct syscall_decl const syscall_list[SYSCALL_DEFINED_COUNT];
const char *name_for_syscall(uintptr_t nr);
struct syscall_info info_for_syscall(uintptr_t nr);

__attribute__((unused))
__attribute__((nonnull(1, 2, 4)))
extern char *copy_call_description(const struct loader_context *context, const char *name, const struct registers *registers, const int *register_indexes, struct syscall_info info, bool include_symbol);

__attribute__((nonnull(1)))
extern char *copy_register_state_description(const struct loader_context *context, struct register_state reg);

#define for_each_bit(value, bit_name, index) int index; \
	for (__typeof__(value) bit_name, temp = value; temp != 0;) \
		if ((bit_name = temp & -temp), (index = _Generic(temp, register_mask: first_set_register_in_mask(temp), default: _Generic(temp, unsigned int: __builtin_ctz(temp), unsigned long: __builtin_ctzl(temp), unsigned long long: __builtin_ctzll(temp), __uint128_t: ctzuint128(temp)))), (temp ^= bit_name), true)

extern char *copy_raw_syscall_description(intptr_t syscall, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6);

#endif
