#define _GNU_SOURCE
#include "axon.h"

#include "freestanding.h"
#include "loader.h"
#include "mapped.h"
#include "patch.h"
#include "proxy.h"
#include "target.h"

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

static target_state state;

#define EXIT_FROM_ERRNO(message, errno) DIE(message, fs_strerror(errno))

noreturn static void process_data(void)
{
	char buf[512 * 1024];
	int sockfd_local = state.sockfd;
	for (;;) {
		// read header
		union {
			char buf[sizeof(request_message)];
			request_message message;
		} request;
		uint32_t bytes_read = 0;
#ifdef SYS_futex
		fs_mutex_lock(&state.read_mutex);
#endif
		do {
			int result = fs_read(sockfd_local, &request.buf[bytes_read], sizeof(request.buf) - bytes_read);
			if (result <= 0) {
				if (result == -EINTR) {
					continue;
				}
				if (result == 0) {
					fs_exit(0);
				}
				EXIT_FROM_ERRNO("Failed to read from socket", result);
			}
			bytes_read += result;
		} while(bytes_read != sizeof(request));
		// interpret request
		response_message response;
		struct iovec vec[7];
		vec[0].iov_base = &response;
		vec[0].iov_len = sizeof(response);
		size_t io_count = 1;
		switch (request.message.template.nr) {
			case TARGET_NR_PEEK:
				// peek at local memory, writing the current data to the socket
#ifdef SYS_futex
				fs_mutex_unlock(&state.read_mutex);
#endif
				vec[io_count].iov_base = (void *)request.message.values[0];
				vec[io_count].iov_len = request.message.values[1];
				io_count++;
				response.result = 0;
				break;
			case TARGET_NR_POKE: {
				// poke at local memory, reading the new data from the socket
				bytes_read = 0;
				char *addr = (char *)request.message.values[0];
				size_t trailer_bytes = request.message.values[1];
				while (trailer_bytes != bytes_read) {
					int result = fs_read(sockfd_local, addr + bytes_read, trailer_bytes - bytes_read);
					if (result <= 0) {
						if (result == -EINTR) {
							continue;
						}
						if (result == 0) {
							fs_exit(0);
						}
						EXIT_FROM_ERRNO("Failed to read from socket", result);
					}
					bytes_read += result;
				}
#ifdef SYS_futex
				fs_mutex_unlock(&state.read_mutex);
#endif
				break;
			}
			default: {
				size_t trailer_bytes = 0;
				intptr_t index = 0;
				uint64_t values[PROXY_ARGUMENT_COUNT];
				for (int i = 0; i < PROXY_ARGUMENT_COUNT; i++) {
					if (request.message.template.is_in & (1 << i)) {
						trailer_bytes += request.message.values[i];
						if (request.message.template.is_out & (1 << i)) {
							vec[io_count].iov_base = &buf[index];
							vec[io_count].iov_len = request.message.values[i];
							io_count++;
						}
						values[i] = (intptr_t)&buf[index];
						index += request.message.values[i];
					} else if (request.message.template.is_out & (1 << i)) {
					} else {
						values[i] = request.message.values[i];
					}
				}
				for (int i = 0; i < PROXY_ARGUMENT_COUNT; i++) {
					if (request.message.template.is_in & (1 << i)) {
						if (request.message.template.is_out & (1 << i)) {
						}
					} else if (request.message.template.is_out & (1 << i)) {
						vec[io_count].iov_base = &buf[index];
						vec[io_count].iov_len = request.message.values[i];
						io_count++;
						values[i] = (intptr_t)&buf[index];
						index += request.message.values[i];
					}
				}
				// read trailer
				bytes_read = 0;
				while (trailer_bytes != bytes_read) {
					int result = fs_read(sockfd_local, &buf[bytes_read], sizeof(buf) - bytes_read);
					if (result <= 0) {
						if (result == -EINTR) {
							continue;
						}
						if (result == 0) {
							fs_exit(0);
						}
						EXIT_FROM_ERRNO("Failed to read from socket", result);
					}
					bytes_read += result;
				}
#ifdef SYS_futex
				fs_mutex_unlock(&state.read_mutex);
#endif
				// perform syscall
				int syscall = request.message.template.nr & ~TARGET_NO_RESPONSE;
				if (syscall == TARGET_NR_CALL) {
					intptr_t (*target)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t) = (void *)values[0];
					response.result = target(values[1], values[2], values[3], values[4], values[5]);
#ifdef __NR_clone
				} else if (syscall == __NR_clone) {
					response.result = fs_clone(values[0], (void *)values[1], (void *)values[2], (void *)values[3], (void *)values[4], (void *)values[5]);
#endif
				} else {
					response.result = FS_SYSCALL(syscall, values[0], values[1], values[2], values[3], values[4], values[5]);
				}
				break;
			}
		}
		if ((request.message.template.nr & TARGET_NO_RESPONSE) == 0) {
			// write result
			response.id = request.message.id;
			size_t io_start = 0;
#ifdef SYS_futex
			fs_mutex_lock(&state.write_mutex);
#endif
			for (;;) {
				intptr_t result = fs_writev(sockfd_local, &vec[io_start], io_count-io_start);
				if (result <= 0) {
					if (result == -EINTR) {
						continue;
					}
					if (result == 0) {
						fs_exit(0);
					}
					EXIT_FROM_ERRNO("Failed to write to socket", result);
				}
				while ((uintptr_t)result >= vec[io_start].iov_len) {
					result -= vec[io_start].iov_len;
					if (++io_start == io_count) {
						goto unlock;
					}
				}
				vec[io_start].iov_base += result;
				vec[io_start].iov_len -= result;
			}
	unlock:
#ifdef SYS_futex
			fs_mutex_unlock(&state.write_mutex);
#else
			;
#endif
		}
	}
	__builtin_unreachable();
}


static int (*worker_pthread_create)(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void *), void *restrict arg);

void remote_spawn_worker(void)
{
	// TODO: support thread pinning, which zlib requires. in the meantime, don't spawn a worker
	// intptr_t buf = proxy_alloc(PAGE_SIZE);
	// intptr_t result = PROXY_CALL(TARGET_NR_CALL | PROXY_NO_WORKER, proxy_value((intptr_t)worker_pthread_create), proxy_value(buf), proxy_value(0), proxy_value((intptr_t)&process_data), proxy_value(0));
	// proxy_free(buf, PAGE_SIZE);
	// if (result != 0) {
	// 	DIE("unable to call pthread_create in worker", fs_strerror(result));
	// }
}

static void spawn_worker(void)
{
	int sockets[2];
	intptr_t result = fs_socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets);
	if (result < 0) {
		DIE("failed to create sockets", fs_strerror(result));
	}
	ERROR_FLUSH();
#if 1
	pid_t child_pid = (pid_t)FS_SYSCALL(SYS_clone, SIGCHLD | CLONE_FILES | CLONE_FS, 0);
#else
	pid_t child_pid = fs_fork();
#endif
	if (child_pid < 0) {
		DIE("failed to fork child", fs_strerror(child_pid));
	}
	if (child_pid != 0) {
		// fs_close(sockets[1]);
		install_proxy(sockets[0]);
		return;
	}
	// fs_close(sockets[0]);
	result = fs_prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (result < 0) {
		DIE("failed to set death signal", fs_strerror(result));
	}
	hello_message hello;
#ifdef __linux__
	hello.target_platform = TARGET_PLATFORM_LINUX;
#else
	hello.target_platform = TARGET_PLATFORM_DARWIN;
#endif
	hello.process_data = process_data;
	state.sockfd = sockets[1];
	hello.state = &state;
	result = fs_write_all(sockets[1], (const char *)&hello, sizeof(hello));
	if (result < (intptr_t)sizeof(hello)) {
		DIE("failed to write startup message", fs_strerror(result));
	}
	process_data();
}

typedef struct z_stream_s {
    const unsigned char *next_in;     /* next input byte */
    unsigned int     avail_in;  /* number of bytes available at next_in */
    unsigned long    total_in;  /* total number of input bytes read so far */

    unsigned char    *next_out; /* next output byte will go here */
    unsigned int     avail_out; /* remaining free space at next_out */
    unsigned long    total_out; /* total number of bytes output so far */

    const char *msg;  /* last error message, NULL if no error */
    void *state; /* not visible by applications */

    void *zalloc;  /* used to allocate the internal state */
    void *zfree;   /* used to free the internal state */
    void *opaque;  /* private data object passed to zalloc and zfree */

    int     data_type;  /* best guess about the data type: binary or text
                           for deflate, or the decoding state for inflate */
    unsigned long   adler;      /* Adler-32 or CRC-32 value of the uncompressed data */
    unsigned long   reserved;   /* reserved for future use */
} z_stream;

static intptr_t inferior_inflateInit_(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateInit_ called");
	int (*orig_inflateInit_)(void *strm, const char *version, int stream_size) = (void *)original;
	return orig_inflateInit_((void *)args[0], (const char *)args[1], args[2]);
}

static void *worker_inflateInit2_;

static intptr_t inferior_inflateInit2_(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	ERROR("inflateInit2_ called");
	ERROR_FLUSH();
#if 1
	return PROXY_CALL(TARGET_NR_CALL, proxy_value((intptr_t)worker_inflateInit2_), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_value(args[1]), proxy_string((const char *)args[2]), proxy_value(args[3]));
#else
	int (*orig_inflateInit2_)(void *strm, int windowBits, const char *version, int stream_size) = (void *)original;
	return orig_inflateInit2_((void *)args[0], args[1], (const char *)args[2], args[3]);
#endif
}

static void *worker_inflate;

static intptr_t inferior_inflate(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	ERROR("inflate called");
	ERROR_FLUSH();
#if 1
	struct z_stream_s *stream = (void *)args[0];
	struct z_stream_s copy = *stream;
	size_t avail_in = stream->avail_in;
	size_t avail_out = stream->avail_out;
	const unsigned char *orig_next_in = stream->next_in;
	unsigned char *orig_next_out = stream->next_out;
	intptr_t next_in = proxy_alloc(avail_in);
	intptr_t next_out = proxy_alloc(avail_out);
	copy.next_in = (void *)next_in;
	copy.next_out = (void *)next_out;
	intptr_t result = proxy_poke(next_in, avail_in, stream->next_in);
	if (result < 0) {
		DIE("failed to poke", fs_strerror(result));
	}
	intptr_t inflate_return = PROXY_CALL(TARGET_NR_CALL, proxy_value((intptr_t)worker_inflate), proxy_inout(&copy, sizeof(struct z_stream_s)), proxy_value(args[1]));
	result = proxy_peek(next_out, avail_out - copy.avail_out, orig_next_out);
	if (result < 0) {
		DIE("failed to peek", fs_strerror(result));
	}
	*stream = copy;
	stream->next_in = &orig_next_in[(intptr_t)copy.next_in - (intptr_t)next_in]; 
	stream->next_out = &orig_next_out[(intptr_t)copy.next_out - (intptr_t)next_out];
	return inflate_return;
#else
	int (*orig_inflate)(void *strm, int flush) = (void *)original;
	return orig_inflate((void *)args[0], args[1]);
#endif
}

static void *worker_inflateEnd;

static intptr_t inferior_inflateEnd(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	ERROR("inflateEnd called");
	ERROR_FLUSH();
#if 1
	return PROXY_CALL(TARGET_NR_CALL, proxy_value((intptr_t)worker_inflateEnd), proxy_inout((void *)args[0], sizeof(struct z_stream_s)));
#else
	int (*orig_inflateEnd)(void *strm) = (void *)original;
	return orig_inflateEnd((void *)args[0]);
#endif
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
	int (*orig_inflateReset)(void *strm) = (void *)original;
	return orig_inflateReset((void *)args[0]);
}

static intptr_t inferior_inflateReset2(__attribute__((unused)) uintptr_t *args, intptr_t original)
{
	ERROR("inflateReset2 called");
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

static void entrypoint_hit(__attribute__((unused)) uintptr_t *registers)
{
	const struct link_map *libz_entry = NULL;
	const struct link_map *libpthread_entry = NULL;
	for (const struct link_map *entry = global_r_debug->r_map; entry != NULL; entry = entry->l_next) {
		ERROR("found in link map", entry->l_name);
		ERROR("at", (uintptr_t)entry->l_addr);
		if (fs_strcmp(entry->l_name, "/lib/x86_64-linux-gnu/libz.so.1") == 0) {
			libz_entry = entry;
		} else if (fs_strcmp(entry->l_name, "/lib/x86_64-linux-gnu/libpthread.so.0") == 0) {
			libpthread_entry = entry;
		}
	}

	if (libpthread_entry != NULL) {
		struct full_binary_info libpthread;
		intptr_t result = load_full_binary_info(AT_FDCWD, libpthread_entry->l_name, &libpthread);
		if (result < 0) {
			DIE("error loading libpthread", fs_strerror(result));
		}
		struct binary_info loaded_libpthread;
		load_existing(&loaded_libpthread, libpthread_entry->l_addr);
		struct symbol_info libpthread_symbols;
		result = load_dynamic_symbols(libpthread.fd, &libpthread.info, &libpthread_symbols);
		if (result < 0) {
			DIE("error loading libpthread symbols", fs_strerror(result));
		}
		worker_pthread_create = find_symbol(&loaded_libpthread, &libpthread_symbols, "pthread_create", NULL, NULL);
		if (!worker_pthread_create) {
			DIE("could not find symbol pthread_create");
		}
		free_symbols(&libpthread_symbols);
		free_full_binary_info(&libpthread);
	} else {
		DIE("could not find libpthread");
	}

	if (libz_entry != NULL) {
		ERROR("found libz!");
		spawn_worker();
		struct full_binary_info libz;
		intptr_t result = load_full_binary_info(AT_FDCWD, libz_entry->l_name, &libz);
		if (result < 0) {
			DIE("error loading libz", fs_strerror(result));
		}
		struct binary_info loaded_libz;
		load_existing(&loaded_libz, libz_entry->l_addr);
		struct symbol_info libz_symbols;
		result = load_dynamic_symbols(libz.fd, &libz.info, &libz_symbols);
		if (result < 0) {
			DIE("error loading libz symbols", fs_strerror(result));
		}
		static const struct { const char *name; intptr_t (*handler)(uintptr_t *arguments, intptr_t original); void **original; } zlib_symbols[] = {
			{"inflateInit_", &inferior_inflateInit_, NULL},
			{"inflateInit2_", &inferior_inflateInit2_, &worker_inflateInit2_},
			{"inflate", &inferior_inflate, &worker_inflate},
			{"inflateEnd", &inferior_inflateEnd, &worker_inflateEnd},
			{"inflateSetDictionary", &inferior_inflateSetDictionary, NULL},
			{"inflateGetDictionary", &inferior_inflateGetDictionary, NULL},
			{"inflateSync", &inferior_inflateSync, NULL},
			{"inflateCopy", &inferior_inflateCopy, NULL},
			{"inflateReset", &inferior_inflateReset, NULL},
			{"inflateReset2", &inferior_inflateReset2, NULL},
			{"inflatePrime", &inferior_inflatePrime, NULL},
			{"inflateMark", &inferior_inflateMark, NULL},
			{"inflateGetHeader", &inferior_inflateGetHeader, NULL},
			{"inflateBackInit_", &inferior_inflateBackInit_, NULL},
			{"inflateBack", &inferior_inflateBack, NULL},
			{"inflateBackEnd", &inferior_inflateBackEnd, NULL},
		};
		struct thread_storage *thread = get_thread_storage();
		for (size_t i = 0; i < sizeof(zlib_symbols) / sizeof(zlib_symbols[0]); i++) {
			void *value = find_symbol(&loaded_libz, &libz_symbols, zlib_symbols[i].name, NULL, NULL);
			if (!value) {
				DIE("missing zlib symbol", zlib_symbols[i].name);
			}
			if (zlib_symbols[i].original != NULL) {
				*zlib_symbols[i].original = value;
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

	ERROR_FLUSH();
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
		DIE("failed to attach breakpoint to r_debug");
	}

	free_symbols(&symbols);

	if (loaded_main.entrypoint == NULL) {
		DIE("could not find entrypoint");
	}

	if (!patch_breakpoint(thread, (intptr_t)loaded_main.entrypoint, (intptr_t)loaded_main.entrypoint, entrypoint_hit, -1)) {
		DIE("failed to attach breakpoint to entrypoint");
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
