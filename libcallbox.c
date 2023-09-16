#define _GNU_SOURCE
#include "axon.h"

#include "freestanding.h"
#include "loader.h"
#include "mapped.h"
#include "patch.h"

#include <link.h>
#include <sched.h>
#include <sys/prctl.h>

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

static int worker_fd;


static void spawn_worker(void)
{
	if (worker_fd != 0) {
		return;
	}
	int sockets[2];
	intptr_t result = fs_socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets);
	if (result < 0) {
		DIE("failed to create sockets", fs_strerror(result));
	}
	pid_t child_pid = (pid_t)FS_SYSCALL(SYS_clone, SIGCHLD | CLONE_FILES | CLONE_FS, 0);
	if (child_pid < 0) {
		DIE("failed to fork child", fs_strerror(child_pid));
	}
	char buf = '\0';
	if (child_pid != 0) {
		// fs_close(sockets[1]);
		do {
			result = fs_read(sockets[0], &buf, sizeof(buf));
		} while(result == -EINTR);
		if (result < 1) {
			DIE("failed to read hello packet", fs_strerror(result));
		}
		worker_fd = sockets[0];
		return;
	}
	// fs_close(sockets[0]);
	result = fs_prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (result < 0) {
		DIE("failed to set death signal", fs_strerror(result));
	}
	do {
		result = fs_write(sockets[1], &buf, sizeof(buf));
	} while(result == -EINTR);
	if (result < 1) {
		DIE("failed to write hello packet", fs_strerror(result));
	}
	for (;;) {
		do {
			result = fs_read(sockets[1], &buf, sizeof(buf));
		} while(result == -EINTR);
		if (result < 1) {
			DIE("failed to read command packet", fs_strerror(result));
		}
		do {
			result = fs_write(sockets[1], &buf, sizeof(buf));
		} while(result == -EINTR);
		if (result < 1) {
			DIE("failed to write response packet", fs_strerror(result));
		}
	}
}

static void ping_worker(void)
{
	char buf = '\0';
	intptr_t result;
	do {
		result = fs_write(worker_fd, &buf, sizeof(buf));
	} while(result == -EINTR);
	if (result < 0) {
		DIE("failed to write ping command", fs_strerror(result));
	}
	do {
		result = fs_read(worker_fd, &buf, sizeof(buf));
	} while(result == -EINTR);
	if (result < 0) {
		DIE("failed to read ping response", fs_strerror(result));
	}
}

static intptr_t inferior_inflateInit_(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateInit_ called");
	ping_worker();
	int (*orig_inflateInit_)(void *strm, const char *version, int stream_size) = (void *)original;
	return orig_inflateInit_((void *)args[0], (const char *)args[1], args[2]);
}

static intptr_t inferior_inflateInit2_(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateInit2_ called");
	ping_worker();
	int (*orig_inflateInit2_)(void *strm, int windowBits, const char *version, int stream_size) = (void *)original;
	return orig_inflateInit2_((void *)args[0], args[1], (const char *)args[2], args[3]);
}

static intptr_t inferior_inflate(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflate called");
	ping_worker();
	int (*orig_inflate)(void *strm, int flush) = (void *)original;
	return orig_inflate((void *)args[0], args[1]);
}

static intptr_t inferior_inflateEnd(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateEnd called");
	ERROR_FLUSH();
	ping_worker();
	int (*orig_inflateEnd)(void *strm) = (void *)original;
	return orig_inflateEnd((void *)args[0]);
}

static intptr_t inferior_inflateSetDictionary(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateSetDictionary called");
	int (*orig_inflateSetDictionary)(void *strm, const void *dictionary, size_t dictLength) = (void *)original;
	return orig_inflateSetDictionary((void *)args[0], (const void *)args[1], args[2]);
}

static intptr_t inferior_inflateGetDictionary(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateGetDictionary called");
	int (*orig_inflateGetDictionary)(void *strm, void *dictionary, size_t *dictLength) = (void *)original;
	return orig_inflateGetDictionary((void *)args[0], (void *)args[1], (size_t *)args[2]);
}

static intptr_t inferior_inflateSync(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateSync called");
	int (*orig_inflateSync)(void *strm) = (void *)original;
	return orig_inflateSync((void *)args[0]);
}

static intptr_t inferior_inflateCopy(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateCopy called");
	int (*orig_inflateCopy)(void *dest, void *source) = (void *)original;
	return orig_inflateCopy((void *)args[0], (void *)args[1]);
}

static intptr_t inferior_inflateReset(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateReset called");
	ping_worker();
	int (*orig_inflateReset)(void *strm) = (void *)original;
	return orig_inflateReset((void *)args[0]);
}

static intptr_t inferior_inflateReset2(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateReset2 called");
	ping_worker();
	int (*orig_inflateReset2)(void *strm, int windowBits) = (void *)original;
	return orig_inflateReset2((void *)args[0], args[1]);
}

static intptr_t inferior_inflatePrime(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflatePrime called");
	int (*orig_inflatePrime)(void *strm, int bits, int value) = (void *)original;
	return orig_inflatePrime((void *)args[0], args[1], args[2]);
}

static intptr_t inferior_inflateMark(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateMark called");
	int (*orig_inflateMark)(void *strm) = (void *)original;
	return orig_inflateMark((void *)args[0]);
}

static intptr_t inferior_inflateGetHeader(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateGetHeader called");
	int (*orig_inflateGetHeader)(void *strm, void *header) = (void *)original;
	return orig_inflateGetHeader((void *)args[0], (void *)args[1]);
}

static intptr_t inferior_inflateBackInit_(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateBackInit_ called");
	int (*orig_inflateBackInit_)(void *strm, int windowBits, unsigned char *window, const char *version, int stream_size) = (void *)original;
	return orig_inflateBackInit_((void *)args[0], args[1], (unsigned char *)args[2], (const char *)args[3], args[4]);
}

static intptr_t inferior_inflateBack(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateBack called");
	int (*orig_inflateBack)(void *strm, void *in, void *in_desc, void *out, void *out_desc) = (void *)original;
	return orig_inflateBack((void *)args[0], (char *)args[1], (char *)args[2], (char *)args[3], (char *)args[4]);
}

static intptr_t inferior_inflateBackEnd(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateBackEnd called");
	ERROR_FLUSH();
	int (*orig_inflateBackEnd)(void *strm) = (void *)original;
	return orig_inflateBackEnd((void *)args[0]);
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
			spawn_worker();
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
			static const struct { const char *name; intptr_t (*handler)(uintptr_t *arguments, intptr_t original); } zlib_symbols[] = {
				{"inflateInit_", &inferior_inflateInit_},
				{"inflateInit2_", &inferior_inflateInit2_},
				{"inflate", &inferior_inflate},
				{"inflateEnd", &inferior_inflateEnd},
				{"inflateSetDictionary", &inferior_inflateSetDictionary},
				{"inflateGetDictionary", &inferior_inflateGetDictionary},
				{"inflateSync", &inferior_inflateSync},
				{"inflateCopy", &inferior_inflateCopy},
				{"inflateReset", &inferior_inflateReset},
				{"inflateReset2", &inferior_inflateReset2},
				{"inflatePrime", &inferior_inflatePrime},
				{"inflateMark", &inferior_inflateMark},
				{"inflateGetHeader", &inferior_inflateGetHeader},
				{"inflateBackInit_", &inferior_inflateBackInit_},
				{"inflateBack", &inferior_inflateBack},
				{"inflateBackEnd", &inferior_inflateBackEnd},
			};
			for (size_t i = 0; i < sizeof(zlib_symbols) / sizeof(zlib_symbols[0]); i++) {
				void *value = find_symbol(&loaded_libz, &libz_symbols, zlib_symbols[i].name, NULL, NULL);
				if (!value) {
					DIE("missing zlib symbol", zlib_symbols[i].name);
				}
				enum patch_status status = patch_function(thread, (intptr_t)value, zlib_symbols[i].handler, -1);
				if (status != PATCH_STATUS_INSTALLED_TRAMPOLINE) {
					if (status == PATCH_STATUS_INSTALLED_ILLEGAL) {
						DIE("failed to install trampoline", zlib_symbols[i].name);
					}
					DIE("failed to patch", zlib_symbols[i].name);
				}
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
