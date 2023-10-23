#ifndef CALLANDER_PRINT_H
#define CALLANDER_PRINT_H

#include "callander.h"

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline bool register_is_exactly_known(const struct register_state *reg) {
	return reg->value == reg->max;
}

__attribute__((nonnull(1))) __attribute__((always_inline))
static inline bool register_is_partially_known(const struct register_state *reg) {
	return reg->value != (uintptr_t)0 || reg->max != ~(uintptr_t)0;
}

__attribute__((unused))
__attribute__((nonnull(1, 2, 4)))
char *copy_call_description(const struct loader_context *context, const char *name, struct registers registers, const int *register_indexes, struct syscall_info info, bool include_symbol);

__attribute__((nonnull(1)))
char *copy_register_state_description(const struct loader_context *context, struct register_state reg);

#define for_each_bit(value, bit_name, index) for (__typeof__(value) bit_name, index, temp = value; temp != 0;) if ((bit_name = temp & -temp), (index = __builtin_ctzl(temp)), (temp ^= bit_name), true)

#endif
