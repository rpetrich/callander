#ifndef CALLANDER_PRINT_H
#define CALLANDER_PRINT_H

#include "callander.h"

__attribute__((unused))
__attribute__((nonnull(1, 2, 4)))
extern char *copy_call_description(const struct loader_context *context, const char *name, struct registers registers, const int *register_indexes, struct syscall_info info, bool include_symbol);

__attribute__((nonnull(1)))
extern char *copy_register_state_description(const struct loader_context *context, struct register_state reg);

#define for_each_bit(value, bit_name, index) int index; for (__typeof__(value) bit_name, temp = value; temp != 0;) if ((bit_name = temp & -temp), (index = first_set_register_in_mask(temp)), (temp ^= bit_name), true)

#endif
