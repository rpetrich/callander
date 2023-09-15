#include "axon.h"

#include "freestanding.h"
#include "loader.h"
#include "mapped.h"
#include "patch.h"

#include <link.h>

FS_DEFINE_SYSCALL

struct full_binary_info {
	int fd;
	struct fs_stat stat;
	struct binary_info info;
};

static intptr_t load_full_binary_info(int dirfd, const char *pathname, struct full_binary_info *out_info)
{
	int fd = fs_openat(dirfd, pathname, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		return fd;
	}
	intptr_t result = fs_fstat(fd, &out_info->stat);
	if (result < 0) {
		fs_close(fd);
		return result;
	}
	result = load_binary(fd, &out_info->info, 0, false);
	if (result < 0) {
		fs_close(fd);
	} else {
		out_info->fd = fd;
	}
	return result;
}

static void free_full_binary_info(struct full_binary_info *info)
{
	unload_binary(&info->info);
	fs_close(info->fd);
}

static bool mapping_is_copy_of_full_binary_info(const struct mapping *mapping, const struct full_binary_info *info)
{
	return mapping->inode == info->stat.st_ino && mapping->device == info->stat.st_dev && (mapping->start < info->info.base || mapping->start >= info->info.base + info->info.size);
}

struct debug {
	int version;
	struct link_map *map;
	void (*update)();
	int state;
	void *base;
};

struct r_debug *global_r_debug;

static void inferior_debug_state_hit(__attribute__((unused)) uintptr_t *args)
{
	if (global_r_debug->r_state == RT_CONSISTENT) {
		ERROR("link map updated");
		ERROR_FLUSH();
	}
}

static intptr_t inferior_inflateInit2_(__attribute__((unused)) uintptr_t *args, __attribute((unused)) intptr_t original)
{
	ERROR("inflateInit2_ called");
	int (*orig_inflateInit2_)(void *strm, int windowBits, const char *version, int stream_size) = (void *)original;
	return orig_inflateInit2_((void *)args[0], args[1], (const char *)args[2], args[3]);
}

static intptr_t inferior_inflate(__attribute__((unused)) uintptr_t *args, __attribute((unused)) intptr_t original)
{
	ERROR("inflate called");
	int (*orig_inflate)(void *strm, int flush) = (void *)original;
	return orig_inflate((void *)args[0], args[1]);
}

static intptr_t inferior_inflateEnd(__attribute__((unused)) uintptr_t *args, __attribute((unused)) intptr_t original)
{
	ERROR("inflateEnd called");
	ERROR_FLUSH();
	int (*orig_inflateEnd)(void *strm) = (void *)original;
	return orig_inflateEnd((void *)args[0]);
}

__attribute__((constructor))
static void constructor(void)
{
	struct full_binary_info main;
	intptr_t result = load_full_binary_info(AT_FDCWD, "/proc/self/exe", &main);
	if (result < 0) {
		DIE("failed to load main binary", fs_strerror(result));
	}

	struct full_binary_info interpreter;

	if (main.info.interpreter) {
		result = load_full_binary_info(AT_FDCWD, main.info.interpreter, &interpreter);
		if (result < 0) {
			DIE("failed to load interpreter binary", fs_strerror(result));
		}
	}

	// struct symbol_info symbols;
	// result = load_dynamic_symbols(fd, info, &symbols);
	// if (result < 0) {
	// 	DIE("failed to load dynamic symbols for self", fs_strerror(result));
	// }

	// free_symbols(&symbols);

	int fd = fs_open("/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		DIE("unable to open self maps", fs_strerror(fd));
	}

	void *main_base = NULL;
	struct binary_info loaded_main;
	void *interpreter_base = NULL;
	struct binary_info loaded_interpreter;

	struct maps_file_state file;
	init_maps_file_state(&file);
	for (;;) {
		struct mapping mapping;
		result = read_next_mapping_from_file(fd, &file, &mapping);
		if (result != 1) {
			if (result == 0) {
				break;
			}
			DIE("error reading mapping", fs_strerror(fd));
		}
		if ((mapping.device != 0 || mapping.inode != 0) && (mapping.prot & PROT_EXEC) && mapping.path[0] != '\0') {
			ERROR("found library", mapping.path);
			uintptr_t base = (uintptr_t)mapping.start - mapping.offset;
			ERROR("at", (uintptr_t)base);
			if (main_base == NULL) {
				if (mapping_is_copy_of_full_binary_info(&mapping, &main)) {
					ERROR("is main");
					load_existing(&loaded_main, base);
					main_base = (void *)base;
				}
			}
			if (main.info.interpreter && interpreter_base == NULL) {
				if (mapping_is_copy_of_full_binary_info(&mapping, &interpreter)) {
					ERROR("is interpreter");
					load_existing(&loaded_interpreter, base);
					interpreter_base = (void *)base;
				}
			}
		}
	}
	fs_close(fd);

	if (main_base == NULL) {
		DIE("could not find main binary mapped");
	}
	if (main.info.interpreter && interpreter_base == NULL) {
		DIE("could not find interpreter binary mapped");
	}

	const struct full_binary_info *debug_info;
	const struct binary_info *loaded_debug;
	if (interpreter_base != NULL) {
		debug_info = &interpreter;
		loaded_debug = &loaded_interpreter;
	} else {
		debug_info = &main;
		loaded_debug = &loaded_main;
	}

	struct symbol_info symbols;
	result = load_dynamic_symbols(debug_info->fd, loaded_debug, &symbols);
	if (result < 0) {
		DIE("failed to load symbols", fs_strerror(result));
	}

	global_r_debug = find_symbol(loaded_debug, &symbols, "_r_debug", NULL, NULL);
	if (global_r_debug == NULL) {
		DIE("could not find _r_debug symbol");
	}

	if (global_r_debug->r_version != 1) {
		DIE("invalid r_debug version", global_r_debug->r_version);
	}

	struct thread_storage *thread = get_thread_storage();

	if (!patch_breakpoint(thread, (intptr_t)global_r_debug->r_brk, (intptr_t)global_r_debug->r_brk, &inferior_debug_state_hit, -1)) {
		DIE("failed to patch r_debug patch_breakpoint");
	}

	free_symbols(&symbols);

	for (const struct link_map *entry = global_r_debug->r_map; entry != NULL; entry = entry->l_next) {
		ERROR("found in link map", entry->l_name);
		ERROR("at", (uintptr_t)entry->l_addr);
		if (fs_strcmp(entry->l_name, "/lib/x86_64-linux-gnu/libz.so.1") == 0) {
			ERROR("found libz!");
			struct full_binary_info libz;
			result = load_full_binary_info(AT_FDCWD, entry->l_name, &libz);
			if (result < 0) {
				DIE("error loading libz", fs_strerror(result));
			}
			struct binary_info loaded_libz;
			load_existing(&loaded_libz, entry->l_addr);
			struct symbol_info libz_symbols;
			result = load_dynamic_symbols(libz.fd, &libz.info, &libz_symbols);
			if (result < 0) {
				DIE("error loading libz symbols", fs_strerror(result));
			}
			void *inflateInit2_ = find_symbol(&loaded_libz, &libz_symbols, "inflateInit2_", NULL, NULL);
			void *inflate = find_symbol(&loaded_libz, &libz_symbols, "inflate", NULL, NULL);
			void *inflateEnd = find_symbol(&loaded_libz, &libz_symbols, "inflateEnd", NULL, NULL);
			if (!inflateInit2_ || !inflate || !inflateEnd) {
				DIE("missing an inflate symbol");
			}
			if (!patch_function(thread, (intptr_t)inflateInit2_, &inferior_inflateInit2_, -1)) {
				DIE("failed to patch inflateInit2_");
			}
			if (!patch_function(thread, (intptr_t)inflate, &inferior_inflate, -1)) {
				DIE("failed to patch inflate");
			}
			if (!patch_function(thread, (intptr_t)inflateEnd, &inferior_inflateEnd, -1)) {
				DIE("failed to patch inflateEnd");
			}
			free_symbols(&libz_symbols);
			free_full_binary_info(&libz);
		}
	}

	// if (interpreter_base) {
	// 	unload_binary(&loaded_interpreter);
	// }
	// unload_binary(&loaded_main);

	if (main.info.interpreter) {
		free_full_binary_info(&interpreter);
	}
	free_full_binary_info(&main);

	ERROR_FLUSH();
}
