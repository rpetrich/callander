#define _GNU_SOURCE
#include "axon.h"

#include "callander.h"
#include "freestanding.h"
#include "loader.h"
#include "mapped.h"
#include "patch.h"
#include "proxy.h"
#include "target.h"

#include <link.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/prctl.h>

FS_DEFINE_SYSCALL

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

typedef struct gz_header_s {
    int     text;       /* true if compressed data believed to be text */
    unsigned long   time;       /* modification time */
    int     xflags;     /* extra flags (not used when writing a gzip file) */
    int     os;         /* operating system */
    unsigned char   *extra;     /* pointer to extra field or Z_NULL if none */
    unsigned int    extra_len;  /* extra field length (valid if extra != Z_NULL) */
    unsigned int    extra_max;  /* space at extra (only when reading header) */
    unsigned char   *name;      /* pointer to zero-terminated file name or Z_NULL */
    unsigned int    name_max;   /* space at name (only when reading header) */
    unsigned char   *comment;   /* pointer to zero-terminated comment or Z_NULL */
    unsigned int    comm_max;   /* space at comment (only when reading header) */
    int     hcrc;       /* true if there was or will be a header crc */
    int     done;       /* true when done reading gzip header (not used
                           when writing a gzip file) */
} gz_header;

static intptr_t worker_inflateInit_;
static intptr_t inferior_inflateInit_(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateInit_), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_string((const char *)args[1]), proxy_value(args[2]));
}

static intptr_t worker_inflateInit2_;
static intptr_t inferior_inflateInit2_(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateInit2_), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_value(args[1]), proxy_string((const char *)args[2]), proxy_value(args[3]));
}

static intptr_t worker_inflate;
static intptr_t inferior_inflate(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
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
	intptr_t inflate_return = PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflate), proxy_inout(&copy, sizeof(struct z_stream_s)), proxy_value(args[1]));
	result = proxy_peek(next_out, avail_out - copy.avail_out, orig_next_out);
	if (result < 0) {
		DIE("failed to peek", fs_strerror(result));
	}
	*stream = copy;
	stream->next_in = &orig_next_in[(intptr_t)copy.next_in - (intptr_t)next_in]; 
	stream->next_out = &orig_next_out[(intptr_t)copy.next_out - (intptr_t)next_out];
	return inflate_return;
}

static intptr_t worker_inflateEnd;
static intptr_t inferior_inflateEnd(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateEnd), proxy_inout((void *)args[0], sizeof(struct z_stream_s)));
}

static intptr_t worker_inflateSetDictionary;
static intptr_t inferior_inflateSetDictionary(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateSetDictionary), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_in((void *)args[1], args[2]), proxy_value(args[2]));
}

static intptr_t worker_inflateGetDictionary;
static intptr_t inferior_inflateGetDictionary(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	void *dictionary = (void *)args[1];
	unsigned int size = 0;
	if (dictionary != NULL) {
		// need to do this weirdness because we don't actually know how large of a buffer dictionary is
		intptr_t result = PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateGetDictionary), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_value(0), proxy_out(&size, sizeof(size)));
		if (result != 0) {
			return result;
		}
	}
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateGetDictionary), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_out(dictionary, size), proxy_out((void *)args[2], sizeof(unsigned int)));
}

static intptr_t worker_inflateSync;
static intptr_t inferior_inflateSync(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	struct z_stream_s *stream = (void *)args[0];
	struct z_stream_s copy = *stream;
	size_t avail_in = stream->avail_in;
	const unsigned char *orig_next_in = stream->next_in;
	intptr_t next_in = proxy_alloc(avail_in);
	copy.next_in = (void *)next_in;
	intptr_t result = proxy_poke(next_in, avail_in, stream->next_in);
	if (result < 0) {
		DIE("failed to poke", fs_strerror(result));
	}
	intptr_t inflate_return = PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateSync), proxy_inout(&copy, sizeof(struct z_stream_s)), proxy_value(args[1]));
	*stream = copy;
	stream->next_in = &orig_next_in[(intptr_t)copy.next_in - (intptr_t)next_in]; 
	return inflate_return;
}

static intptr_t inferior_inflateCopy(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	// TODO: Support copying. This has the same problem where inflateStateCheck cares if a stream has been moved
	return -4;
}

static intptr_t worker_inflateReset;
static intptr_t inferior_inflateReset(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateReset), proxy_inout((void *)args[0], sizeof(struct z_stream_s)));
}

static intptr_t worker_inflateReset2;
static intptr_t inferior_inflateReset2(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateReset2), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_value(args[1]));
}

static intptr_t worker_inflatePrime;
static intptr_t inferior_inflatePrime(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflatePrime), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_value(args[1]), proxy_value(args[2]));
}

static intptr_t worker_inflateMark;
static intptr_t inferior_inflateMark(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateMark), proxy_inout((void *)args[0], sizeof(struct z_stream_s)));
}

static intptr_t worker_inflateGetHeader;
static intptr_t inferior_inflateGetHeader(__attribute__((unused)) uintptr_t *args, __attribute__((unused)) intptr_t original)
{
	return PROXY_CALL(TARGET_NR_CALL, proxy_value(worker_inflateGetHeader), proxy_inout((void *)args[0], sizeof(struct z_stream_s)), proxy_out((void *)args[1], sizeof(struct gz_header_s)));
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

static const struct { const char *name; intptr_t (*handler)(uintptr_t *arguments, intptr_t original); intptr_t *original; } zlib_symbols[] = {
	{"inflateInit_", &inferior_inflateInit_, &worker_inflateInit_},
	{"inflateInit2_", &inferior_inflateInit2_, &worker_inflateInit2_},
	{"inflate", &inferior_inflate, &worker_inflate},
	{"inflateEnd", &inferior_inflateEnd, &worker_inflateEnd},
	{"inflateSetDictionary", &inferior_inflateSetDictionary, &worker_inflateSetDictionary},
	{"inflateGetDictionary", &inferior_inflateGetDictionary, &worker_inflateGetDictionary},
	{"inflateSync", &inferior_inflateSync, &worker_inflateSync},
	{"inflateCopy", &inferior_inflateCopy, NULL},
	{"inflateReset", &inferior_inflateReset, &worker_inflateReset},
	{"inflateReset2", &inferior_inflateReset2, &worker_inflateReset2},
	{"inflatePrime", &inferior_inflatePrime, &worker_inflatePrime},
	{"inflateMark", &inferior_inflateMark, &worker_inflateMark},
	{"inflateGetHeader", &inferior_inflateGetHeader, &worker_inflateGetHeader},
	{"inflateBackInit_", &inferior_inflateBackInit_, NULL},
	{"inflateBack", &inferior_inflateBack, NULL},
	{"inflateBackEnd", &inferior_inflateBackEnd, NULL},
};

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
		// ERROR("link map updated");
		// ERROR_FLUSH();
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

__attribute__((used)) __attribute__((visibility("hidden")))
void callander_perform_analysis(struct program_state *analysis, const struct link_map *libz_entry, __attribute__((unused)) void *data)
{
	int ld = fs_open("/lib64/ld-linux-x86-64.so.2", O_RDONLY | O_CLOEXEC, 0);
	struct loaded_binary *ld_binary;
	load_binary_into_analysis(analysis, "ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", ld, NULL, &ld_binary);
	ld_binary->special_binary_flags |= BINARY_IS_INTERPRETER;
	fs_close(ld);

	int libc = fs_open("/usr/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY | O_CLOEXEC, 0);
	struct loaded_binary *libc_binary;
	load_binary_into_analysis(analysis, "libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", libc, NULL, &libc_binary);
	libc_binary->special_binary_flags |= BINARY_IS_LIBC;
	fs_close(libc);

	record_syscall(analysis, SYS_clock_gettime, (struct analysis_frame){
		.next = NULL,
		.address = NULL,
		.description = "vDSO",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);

	record_syscall(analysis, SYS_futex, (struct analysis_frame){
		.next = NULL,
		.address = &fs_syscall,
		.description = "libcallbox",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
	record_syscall(analysis, SYS_read, (struct analysis_frame){
		.next = NULL,
		.address = &fs_syscall,
		.description = "libcallbox",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
	record_syscall(analysis, SYS_write, (struct analysis_frame){
		.next = NULL,
		.address = &fs_syscall,
		.description = "libcallbox",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
	record_syscall(analysis, SYS_writev, (struct analysis_frame){
		.next = NULL,
		.address = &fs_syscall,
		.description = "libcallbox",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
	record_syscall(analysis, SYS_exit_group, (struct analysis_frame){
		.next = NULL,
		.address = &fs_syscall,
		.description = "libcallbox",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
	record_syscall(analysis, SYS_mmap, (struct analysis_frame){
		.next = NULL,
		.address = &fs_syscall,
		.description = "libcallbox",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
	record_syscall(analysis, SYS_munmap, (struct analysis_frame){
		.next = NULL,
		.address = &fs_syscall,
		.description = "libcallbox",
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
		.is_entry = true,
	}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);

	struct loaded_binary *binary = register_dlopen(analysis, libz_entry->l_name, NULL, false, true, false);
	if (binary == NULL) {
		DIE("could not load libz for analysis");
	}
	binary->child_base = libz_entry->l_addr;
	binary->special_binary_flags |= BINARY_HAS_FUNCTION_SYMBOLS_ANALYZED;
	for (size_t i = 0; i < sizeof(zlib_symbols) / sizeof(zlib_symbols[0]); i++) {
		void *addr = resolve_binary_loaded_symbol(&analysis->loader, binary, zlib_symbols[i].name, NULL, NORMAL_SYMBOL, NULL);
		if (addr == NULL) {
			DIE("could not analyze", zlib_symbols[i].name);
		}
		struct analysis_frame new_caller = { .address = addr, .description = zlib_symbols[i].name, .next = NULL, .current_state = empty_registers, .entry = binary->info.base, .entry_state = &empty_registers, .token = { 0 }, .is_entry = false, };
		analyze_function(analysis, EFFECT_PROCESSED | EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, &empty_registers, addr, &new_caller);
	}

	sort_and_coalesce_syscalls(&analysis->syscalls, &analysis->loader);
}

static const struct link_map *find_link_map(const char *path)
{
	for (const struct link_map *entry = global_r_debug->r_map; entry != NULL; entry = entry->l_next) {
		if (fs_strcmp(entry->l_name, path) == 0) {
			return entry;
		}
	}
	return NULL;
}

static void *(*worker_dlopen)(const char *filename, int flags);

#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
__attribute__((noinline))
static void apply_sandbox(const struct link_map *libz_entry)
{
	struct program_state analysis = { 0 };
	analysis.pid = fs_getpid();
	analysis.loader.loaded_gconv_libraries = true;
	analysis.loader.ignore_dlopen = true;
	// analysis.syscalls.config[__NR_openat] |= SYSCALL_CONFIG_DEBUG;
	init_searched_instructions(&analysis.search);

	// revoke permissions
	intptr_t result = fs_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (result != 0) {
		DIE("failed to set no new privileges", fs_strerror(result));
	}

	// allocate a temporary stack
	void *stack = fs_mmap(NULL, ALT_STACK_SIZE + STACK_GUARD_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
	if (fs_is_map_failed(stack)) {
		DIE("failed to allocate stack", fs_strerror((intptr_t)stack));
	}
	// apply the guard page
	result = fs_mprotect(stack, STACK_GUARD_SIZE, PROT_NONE);
	if (result != 0) {
		DIE("failed to protect stack guard", fs_strerror(result));
	}
	CALL_ON_ALTERNATE_STACK_WITH_ARG(callander_perform_analysis, &analysis, libz_entry, NULL, (char *)stack + ALT_STACK_SIZE + STACK_GUARD_SIZE);
	// unmap the temporary stack
	fs_munmap(stack, ALT_STACK_SIZE + STACK_GUARD_SIZE);

	cleanup_searched_instructions(&analysis.search);
	// patch in child base addresses, which doesn't really apply since there is no child
	for (struct loaded_binary *binary = analysis.loader.last; binary != NULL; binary = binary->previous) {
		if (binary->child_base == 0) {
			const struct link_map *entry = find_link_map(binary->loaded_path);
			if (entry == NULL) {
				worker_dlopen(binary->loaded_path, RTLD_NOW);
				entry = find_link_map(binary->loaded_path);
				if (entry == NULL) {
					for (const struct link_map *other = global_r_debug->r_map; other != NULL; other = other->l_next) {
						ERROR("found in link map", other->l_name);
					}
					DIE("missing base for", binary->loaded_path);
				}
			}
			binary->child_base = (uintptr_t)entry->l_addr;
		}
	}
	struct sock_fprog prog = generate_seccomp_program(&analysis.loader, &analysis.syscalls, NULL, 0, ~(uint32_t)0);
	// ERROR("permitted syscalls", temp_str(copy_used_syscalls(&analysis.loader, &analysis.syscalls, true, true, true)));
	free_loaded_binary(analysis.loader.binaries);
	ERROR_FLUSH();
	result = FS_SYSCALL(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, (intptr_t)&prog);
	if (result < 0) {
		DIE("failed to apply program", fs_strerror(result));
	}
	free(prog.filter);
}
#pragma GCC pop_options

static void spawn_worker(const struct link_map *libz_entry)
{
	int sockets[2];
	intptr_t result = fs_socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets);
	if (result < 0) {
		DIE("failed to create sockets", fs_strerror(result));
	}
	ERROR_FLUSH();
#if 0
	pid_t child_pid = (pid_t)FS_SYSCALL(SYS_clone, SIGCHLD | CLONE_FILES | CLONE_FS, 0);
#else
	pid_t child_pid = fs_fork();
#endif
	if (child_pid < 0) {
		DIE("failed to fork child", fs_strerror(child_pid));
	}
	if (child_pid != 0) {
		fs_close(sockets[1]);
		install_proxy(sockets[0]);
		return;
	}
	fs_close(sockets[0]);
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
	apply_sandbox(libz_entry);
	process_data();
}

static void *find_loaded_symbol(const struct link_map *entry, const char *symbol_name)
{
	struct full_binary_info binary;
	intptr_t result = load_full_binary_info(AT_FDCWD, entry->l_name, &binary);
	if (result < 0) {
		DIE("error loading binary", fs_strerror(result));
	}
	struct binary_info loaded;
	load_existing(&loaded, entry->l_addr);
	struct symbol_info symbols;
	result = load_dynamic_symbols(binary.fd, &binary.info, &symbols);
	if (result < 0) {
		DIE("error loading symbols", fs_strerror(result));
	}
	void *symbol = find_symbol(&loaded, &symbols, symbol_name, NULL, NULL);
	free_symbols(&symbols);
	free_full_binary_info(&binary);
	return symbol;
}

static void entrypoint_hit(__attribute__((unused)) uintptr_t *registers)
{
	const struct link_map *libz_entry = NULL;
	const struct link_map *libpthread_entry = NULL;
	const struct link_map *libc_entry = NULL;
	const struct link_map *libdl_entry = NULL;
	for (const struct link_map *entry = global_r_debug->r_map; entry != NULL; entry = entry->l_next) {
		// ERROR("found in link map", entry->l_name);
		// ERROR("at", (uintptr_t)entry->l_addr);
		if (fs_strcmp(entry->l_name, "/lib/x86_64-linux-gnu/libz.so.1") == 0) {
			libz_entry = entry;
		} else if (fs_strcmp(entry->l_name, "/lib/x86_64-linux-gnu/libpthread.so.0") == 0) {
			libpthread_entry = entry;
		} else if (fs_strcmp(entry->l_name, "/lib/x86_64-linux-gnu/libc.so.6") == 0) {
			libc_entry = entry;
		} else if (fs_strcmp(entry->l_name, "/lib/x86_64-linux-gnu/libdl.so.2") == 0) {
			libdl_entry = entry;
		}
	}

	if (libpthread_entry != NULL) {
		worker_pthread_create = find_loaded_symbol(libpthread_entry, "pthread_create");
		if (worker_pthread_create == NULL) {
			DIE("could not find symbol pthread_create");
		}
	} else {
		DIE("could not find libpthread");
	}

	if (libdl_entry != NULL) {
		worker_dlopen = find_loaded_symbol(libdl_entry, "dlopen");
		if (worker_dlopen == NULL) {
			DIE("failed to find dlopen");
		}
	} else {
		DIE("could not find libdl");
	}

	if (libc_entry != NULL) {
		void *(*iconv_open)(const char *to, const char *from) = find_loaded_symbol(libc_entry, "iconv_open");
		if (iconv_open == NULL) {
			DIE("failed to find iconv_open");
		}
		iconv_open("UTF8", "UTF8");
	} else {
		DIE("could not find libc");
	}

	if (libz_entry != NULL) {
		// ERROR("found libz!");
		spawn_worker(libz_entry);
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
		struct thread_storage *thread = get_thread_storage();
		for (size_t i = 0; i < sizeof(zlib_symbols) / sizeof(zlib_symbols[0]); i++) {
			void *value = find_symbol(&loaded_libz, &libz_symbols, zlib_symbols[i].name, NULL, NULL);
			if (!value) {
				DIE("missing zlib symbol", zlib_symbols[i].name);
			}
			if (zlib_symbols[i].original != NULL) {
				*zlib_symbols[i].original = (intptr_t)value;
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
			// ERROR("found library", mapping.path);
			uintptr_t base = (uintptr_t)mapping.start - mapping.offset;
			// ERROR("at", (uintptr_t)base);
			if (main_base == NULL) {
				if (mapping_is_copy_of_full_binary_info(&mapping, &main)) {
					// ERROR("is main");
					load_existing(&loaded_main, base);
					main_base = (void *)base;
				}
			}
			if (main.info.interpreter && interpreter_base == NULL) {
				if (mapping_is_copy_of_full_binary_info(&mapping, &interpreter)) {
					// ERROR("is interpreter");
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
