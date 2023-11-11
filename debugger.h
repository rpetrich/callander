#ifndef DEBUGGER_H
#define DEBUGGER_H

#include "loader.h"

#include <link.h>

__attribute__((visibility("default")))
extern struct r_debug _r_debug;

// _dl_debug_state is a function that is called whenever the link map changes.
// Debuggers know this function by name and will set a breakpoint on it to
// detect when the link map changes
__attribute__((visibility("default")))
void _dl_debug_state(void);

// debug_field_for_self returns the address of the DT_DEBUG field
__attribute__((warn_unused_result))
uintptr_t *debug_field_for_self(const struct binary_info *self_info);

// debug_init initializes debugger support
void debug_init(struct r_debug *main_debug, void (*update_callback)(void));

// debug_register_relocated_self add the relocated copy of self to the link
// map so that debuggers see both copies
void debug_register_relocated_self(void *base_address);

// debug_register registers a binary with any attached debuggers
void debug_register(const struct binary_info *info, const char *path);

// debug_intercept_system_loader will intercept the system loader and import
// any link maps that it creates
void debug_intercept_system_loader(int fd, const struct binary_info *info);

// debug_find_library finds the library containing a specific address. May
// spuriously return a library when the specified address is not within a
// shared object
bool debug_find_library(const void *addr, const ElfW(Ehdr) **out_base_address, const char **out_path);

#endif
