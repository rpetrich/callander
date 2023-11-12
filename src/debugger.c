#include "debugger.h"

#include "attempt.h"
#include "freestanding.h"
#include "axon.h"
#include "libraries.h"
#include "patch.h"
#include "tls.h"

struct debug {
	int version;
	struct link_map *map;
	void (*update)();
	int state;
	void *base;
};

static struct link_map maps[4];
static size_t next_map;
static struct fs_mutex link_lock;

__attribute__((visibility("default")))
struct r_debug _r_debug;
static struct r_debug *debug;

__attribute__((visibility("default")))
__attribute__((noinline))
void _dl_debug_state(void)
{
	__asm__ __volatile__("" : : : "memory");
}

static void add_link_map(void *base, const char *name, const void *dynamic) {
	debug->r_state = RT_ADD;
	((void (*)(void))debug->r_brk)();
	maps[next_map].l_addr = (ElfW(Addr))base;
	maps[next_map].l_name = (char *)name;
	maps[next_map].l_ld = (void *)dynamic;
	struct link_map **field;
	if (next_map == 0) {
		field = &debug->r_map;
		maps[next_map].l_prev = NULL;
	} else {
		field = &maps[next_map-1].l_next;
		maps[next_map].l_prev = &maps[next_map-1];
	}
	if (*field) {
		(*field)->l_prev = &maps[next_map];
	}
	maps[next_map].l_next = *field;
	*field = &maps[next_map];
	++next_map;
	debug->r_state = RT_CONSISTENT;
	((void (*)(void))debug->r_brk)();
}

static struct debug *inferior_debug;

static void inferior_debug_state_hit(__attribute__((unused)) uintptr_t *args)
{
	if (inferior_debug) {
		debug->r_state = RT_ADD;
		((void (*)(void))debug->r_brk)();
		struct link_map *ours = &maps[next_map - 1];
		fs_mutex_lock(&link_lock);
		struct link_map *theirs = inferior_debug->map;
		ours->l_next = theirs;
		if (theirs) {
			theirs->l_prev = ours;
		}
		if (inferior_debug->state == RT_CONSISTENT) {
			update_libraries(theirs);
		}
		fs_mutex_unlock(&link_lock);
		debug->r_state = RT_CONSISTENT;
		((void (*)(void))debug->r_brk)();
	}
}

uintptr_t *debug_field_for_self(const struct binary_info *self_info)
{
	for (int i = 0; i < (int)self_info->dynamic_size; i++) {
		switch (_DYNAMIC[i].d_tag) {
			case DT_DEBUG:
				return (uintptr_t *)&_DYNAMIC[i].d_un.d_ptr;
		}
	}
	return NULL;
}

void debug_init(struct r_debug *main_debug, void (*update_callback)(void))
{
	debug = main_debug;
	debug->r_version = 1;
	// debug->r_base = (void *)data.base_address;
	debug->r_brk = (ElfW(Addr))update_callback;

	add_link_map(NULL, "", NULL);
}

void debug_register_relocated_self(void *base_address)
{
	add_link_map(base_address, "axon", &_DYNAMIC);
}

void debug_register(const struct binary_info *info, const char *path)
{
	add_link_map((void *)((intptr_t)info->base - (intptr_t)info->default_base), path, info->dynamic);
}

void debug_intercept_system_loader(int fd, const struct binary_info *info)
{
	struct symbol_info symbols;
	int symbol_error = load_dynamic_symbols(fd, info, &symbols);
	if (symbol_error == 0) {
		void *main_dl_debug_state = find_symbol(info, &symbols, "_dl_debug_state", NULL, NULL);
		if (main_dl_debug_state) {
			if (!patch_breakpoint(get_thread_storage(), (intptr_t)main_dl_debug_state, (intptr_t)main_dl_debug_state, &inferior_debug_state_hit, SELF_FD)) {
#if 0
				ERROR("failed to patch _dl_debug_state");
#endif
			}
		}
		inferior_debug = find_symbol(info, &symbols, "_r_debug", NULL, NULL);
		free_symbols(&symbols);
	}
}

bool debug_find_library(const void *addr, const ElfW(Ehdr) **out_base_address, const char **out_path)
{
	if (!debug) {
		return false;
	}
	const ElfW(Ehdr) *base_address = NULL;
	const char *path = NULL;
	struct link_map *map = debug->r_map;
	while (map != NULL) {
		if (map->l_addr && ((uintptr_t)map->l_addr <= (uintptr_t)addr) && ((uintptr_t)map->l_addr >= (uintptr_t)base_address)) {
			base_address = (const ElfW(Ehdr) *)map->l_addr;
			path = map->l_name;
		}
		map = map->l_next;
	}
	if (base_address) {
		if (out_base_address) {
			*out_base_address = base_address;
		}
		if (out_path) {
			*out_path = path;
		}
		return true;
	}
	return false;
}
