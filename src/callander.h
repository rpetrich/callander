#ifndef CALLANDER_H
#define CALLANDER_H

#ifdef __linux__
#include <linux/filter.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "loader.h"

#define STORE_LAST_MODIFIED 1
#define RECORD_WHERE_STACK_ADDRESS_TAKEN 0

// #define LOGGING
// #define STATS

#ifdef LOGGING
extern bool should_log;
#define SHOULD_LOG UNLIKELY(should_log)
#define LOG(...) do { if (UNLIKELY(should_log)) { ERROR_NOPREFIX(__VA_ARGS__); } } while(0)
#else
#define SHOULD_LOG false
#define LOG(...) do { } while(0)
#endif

enum {
	ALT_STACK_SIZE = 200 * 1024 * 1024,
	SIGNAL_STACK_SIZE = 512 * 1024,
	STACK_GUARD_SIZE = 1024 * 1024,
};


enum {
	SYSCALL_ARGC_MASK = 0xf,
	SYSCALL_IS_RESTARTABLE = 0x10,
	SYSCALL_CAN_BE_FROM_ANYWHERE = 0x20,

	SYSCALL_RETURN_MASK = 0x700,

	SYSCALL_RETURNS_SIZE = 0x100,
	SYSCALL_RETURNS_COUNT = SYSCALL_RETURNS_SIZE,
	SYSCALL_RETURNS_OFFSET = SYSCALL_RETURNS_SIZE,
	SYSCALL_RETURNS_FD = 0x200,
	SYSCALL_RETURNS_ERROR = 0x300,
	SYSCALL_RETURNS_ADDRESS = 0x400,
	SYSCALL_RETURNS_NEVER = 0x500,
	SYSCALL_RETURNS_SELF_PID = 0x600,

	SYSCALL_ARG_IS_INTEGER = 0x0,
	SYSCALL_ARG_IS_OFFSET = SYSCALL_ARG_IS_INTEGER,
	SYSCALL_ARG_IS_FLAGS = SYSCALL_ARG_IS_INTEGER,
	SYSCALL_ARG_IS_ADDRESS = 0x1,
	SYSCALL_ARG_IS_PATH = SYSCALL_ARG_IS_ADDRESS,
	SYSCALL_ARG_IS_STRING = SYSCALL_ARG_IS_ADDRESS,
	SYSCALL_ARG_IS_FD = 0x2,
	SYSCALL_ARG_IS_SIZE = 0x3,
	SYSCALL_ARG_IS_COUNT = SYSCALL_ARG_IS_SIZE,
	SYSCALL_ARG_IS_MODEFLAGS = 0x4,
	SYSCALL_ARG_IS_PROT = 0x5,
	SYSCALL_ARG_IS_MAP_FLAGS = 0x6,
	SYSCALL_ARG_IS_REMAP_FLAGS = 0x7,
	SYSCALL_ARG_IS_OPEN_FLAGS = 0x8,
	SYSCALL_ARG_IS_SIGNUM = 0x9,
	SYSCALL_ARG_IS_IOCTL = 0xa,
	SYSCALL_ARG_IS_PID = 0xb,
	SYSCALL_ARG_IS_SIGHOW = 0xc,
	SYSCALL_ARG_IS_MADVISE = 0xd,
	SYSCALL_ARG_IS_FCNTL = 0xe,
	SYSCALL_ARG_IS_RLIMIT = 0xf,
	SYSCALL_ARG_IS_SOCKET_DOMAIN = 0x10,
	SYSCALL_ARG_IS_SOCKET_TYPE = 0x11,
	SYSCALL_ARG_IS_CLOCK_ID = 0x12,
	SYSCALL_ARG_IS_SOCKET_LEVEL = 0x13,
	SYSCALL_ARG_IS_SOCKET_OPTION = 0x14,
	SYSCALL_ARG_IS_ACCESS_MODE = 0x15,
	SYSCALL_ARG_IS_ACCESSAT_FLAGS = 0x16,
	SYSCALL_ARG_IS_REMOVEAT_FLAGS = 0x17,
	SYSCALL_ARG_IS_MSYNC_FLAGS = 0x18,
	SYSCALL_ARG_IS_OFLAGS = 0x19,
	SYSCALL_ARG_IS_MSG_FLAGS = 0x1a,
	SYSCALL_ARG_IS_SHUTDOWN_HOW = 0x1b,
	SYSCALL_ARG_IS_MODE = 0x1c,
	SYSCALL_ARG_IS_FUTEX_OP = 0x1d,
	SYSCALL_ARG_IS_SIGNALFD_FLAGS = 0x1e,
	SYSCALL_ARG_IS_TIMERFD_FLAGS = 0x1f,
	SYSCALL_ARG_IS_SOCKET_FLAGS = 0x20,
	SYSCALL_ARG_IS_PRCTL = 0x21,
	SYSCALL_ARG_IS_CLONEFLAGS = 0x22,
	SYSCALL_ARG_IS_SHM_FLAGS = 0x23,
	SYSCALL_ARG_IS_SOCKET_PROTOCOL = 0x24,
	SYSCALL_ARG_IS_EVENTFD_FLAGS = 0x25,
	SYSCALL_ARG_IS_EPOLL_FLAGS = 0x26,
	SYSCALL_ARG_IS_XATTR_FLAGS = 0x27,
	SYSCALL_ARG_IS_TIMER_FLAGS = 0x28,
	SYSCALL_ARG_IS_WAIT_FLAGS = 0x29,
	SYSCALL_ARG_IS_WAITIDTYPE = 0x2a,
	SYSCALL_ARG_IS_INOTIFY_EVENT_MASK = 0x2b,
	SYSCALL_ARG_IS_INOTIFY_INIT_FLAGS = 0x2c,
	SYSCALL_ARG_IS_SECCOMP_OPERATION = 0x2d,
	SYSCALL_ARG_IS_MEMFD_FLAGS = 0x2e,
	SYSCALL_ARG_IS_BPF_COMMAND = 0x2f,
	SYSCALL_ARG_IS_USERFAULTFD_FLAGS = 0x30,
	SYSCALL_ARG_IS_MLOCKALL_FLAGS = 0x31,
	SYSCALL_ARG_IS_UMOUNT_FLAGS = 0x32,
	SYSCALL_ARG_IS_SWAP_FLAGS = 0x33,
	SYSCALL_ARG_IS_SPLICE_FLAGS = 0x34,
	SYSCALL_ARG_IS_SYNC_FILE_RANGE_FLAGS = 0x35,
	SYSCALL_ARG_IS_TIMERFD_SETTIME_FLAGS = 0x36,
	SYSCALL_ARG_IS_PERF_EVENT_OPEN_FLAGS = 0x37,
	SYSCALL_ARG_IS_MODULE_INIT_FLAGS = 0x38,
	SYSCALL_ARG_IS_GETRANDOM_FLAGS = 0x3a,
	SYSCALL_ARG_IS_MEMBARRIER_COMMAND = 0x3b,
	SYSCALL_ARG_IS_STATX_MASK = 0x3c,
	SYSCALL_ARG_IS_FLOCK_OPERATION = 0x3d,
	SYSCALL_ARG_IS_ITIMER_WHICH = 0x3e,
	SYSCALL_ARG_IS_SEEK_WHENCE = 0x3f,
	SYSCALL_ARG_IS_SHMCTL_COMMAND = 0x40,
	SYSCALL_ARG_IS_SEMCTL_COMMAND = 0x41,
	SYSCALL_ARG_IS_PTRACE_REQUEST = 0x42,
	SYSCALL_ARG_IS_SEM_FLAGS = 0x43,
	SYSCALL_ARG_IS_UNSHARE_FLAGS = 0x44,
	SYSCALL_ARG_IS_SOCKET_OPTION_IP = 0x45,
	SYSCALL_ARG_IS_SOCKET_OPTION_IPV6 = 0x46,
	SYSCALL_ARG_IS_SOCKET_OPTION_TCP = 0x47,
	SYSCALL_ARG_IS_SOCKET_OPTION_TLS = 0x48,
	SYSCALL_ARG_IS_SOCKET_OPTION_ALG = 0x49,
	SYSCALL_ARG_IS_SOCKET_OPTION_NETLINK = 0x4a,
	SYSCALL_ARG_IS_SOCKET_OPTION_ICMPV6 = 0x4b,
	SYSCALL_ARG_IS_SOCKET_OPTION_RAW = 0x4c,
	SYSCALL_ARG_TYPE_MASK = 0x7f,
	SYSCALL_ARG_IS_PRESERVED = 0x80,
	SYSCALL_ARG_RELATED_ARGUMENT_BASE = 0x100,
};

#define SYSCALL_RETURNS(arg) (0x20 * (arg))

struct syscall_info {
	uint16_t attributes;
	uint16_t arguments[6];
};

struct syscall_decl {
	const char *name;
	struct syscall_info info;
};

#define SYSCALL_DEF(...) 1+
#define SYSCALL_DEF_EMPTY() 1+
enum {
	SYSCALL_COUNT = 512,
	SYSCALL_DEFINED_COUNT = 
#include "syscall_defs.h"
	0,
};
#undef SYSCALL_DEF
#undef SYSCALL_DEF_EMPTY

enum {
	BINARY_IS_MAIN = 1 << 0,
	BINARY_IS_INTERPRETER = 1 << 1,
	BINARY_IS_LIBC = 1 << 2,
	BINARY_IS_PTHREAD = 1 << 2,
	BINARY_IS_LIBCRYPTO = 1 << 4,
	BINARY_IS_SECCOMP = 1 << 5,
	BINARY_IS_LIBCAP = 1 << 6,
	BINARY_IS_LIBNSS_SYSTEMD = 1 << 7,
	BINARY_IS_LIBREADLINE = 1 << 8,
	BINARY_IS_RUBY = 1 << 9,
	BINARY_IS_LOADED_VIA_DLOPEN = 1 << 10,
	BINARY_IS_GOLANG = 1 << 11,
	BINARY_ASSUME_FUNCTION_CALLS_PRESERVE_STACK = 1 << 12,
	BINARY_HAS_CUSTOM_JUMPTABLE_METADATA = 1 << 13,
	BINARY_HAS_FUNCTION_SYMBOLS_ANALYZED = 1 << 14,
	BINARY_IS_LIBPYTHON = 1 << 15,
	BINARY_IS_PERL = 1 << 16,
	BINARY_IS_LIBP11KIT = 1 << 17,
	BINARY_IS_LIBKRB5 = 1 << 18,
	BINARY_IS_LIBSASL2 = 1 << 19,
};

enum {
	OVERRIDE_ACCESS_SLOT_COUNT = 3,
};

#include "ins.h"

struct address_and_size {
	ins_ptr address;
	size_t size;
};

struct loaded_binary {
	struct binary_info info;
	const char *path;
	unsigned long path_hash;
	bool has_symbols:1;
	bool has_sections:1;
	bool has_linker_symbols:1;
	bool has_debuglink_info:1;
	bool has_forced_debuglink_info:1;
	bool has_debuglink_symbols:1;
	bool has_loaded_needed_libraries:1;
	bool has_applied_relocation:1;
	bool has_finished_loading:1;
	bool has_frame_info:1;
	bool owns_binary_info:1;
	bool owns_path:1;
	struct symbol_info symbols;
	struct symbol_info linker_symbols;
	struct section_info sections;
	struct frame_info frame_info;
	struct loaded_binary *next;
	struct loaded_binary *previous;
	int id;
	int special_binary_flags;
	dev_t device;
	ino_t inode;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	int debuglink_error;
	uintptr_t child_base;
	struct binary_info debuglink_info;
	struct symbol_info debuglink_symbols;
	char *debuglink;
	char *build_id;
	size_t build_id_size;
	struct address_and_size override_access_ranges[OVERRIDE_ACCESS_SLOT_COUNT];
	int override_access_permissions[OVERRIDE_ACCESS_SLOT_COUNT];
	struct address_and_size *skipped_symbols;
	size_t skipped_symbol_count;
	char loaded_path[];
};

struct loader_stub;

struct loader_context {
	struct loaded_binary *binaries;
	struct loaded_binary *last;
	struct loaded_binary *main;
	struct loaded_binary *interpreter;
	struct loader_stub *stubs;
	pid_t pid;
	uid_t uid;
	gid_t gid;
	uintptr_t vdso;
	bool loaded_nss_libraries:1;
	bool loaded_gconv_libraries:1;
	bool ignore_dlopen:1;
	bool searching_gconv_dlopen:1;
	bool searching_libcrypto_dlopen:1;
	bool searching_setxid:1;
	bool searching_setxid_sighandler:1;
	bool searching_do_setxid:1;
	ins_ptr gconv_dlopen;
	ins_ptr libcrypto_dlopen;
	ins_ptr setxid_syscall;
	ins_ptr setxid_syscall_entry;
	ins_ptr setxid_sighandler_syscall;
	ins_ptr setxid_sighandler_syscall_entry;
	ins_ptr do_setxid;
	struct loaded_binary_stub *sorted_binaries;
	int binary_count;
	const char *sysroot;
};

__attribute__((nonnull(1)))
char *copy_used_binaries(const struct loader_context *loader);
__attribute__((nonnull(1)))
char *copy_address_details(const struct loader_context *loader, const void *addr, bool include_symbol);
__attribute__((nonnull(1)))
char *copy_address_description(const struct loader_context *context, const void *address);
struct analysis_frame;
__attribute__((nonnull(1, 2)))
char *copy_call_trace_description(const struct loader_context *context, const struct analysis_frame *head);
typedef char *(*additional_print_callback)(const struct loader_context *loader, const struct analysis_frame *frame, void *callback_data);
__attribute__((nonnull(1, 2)))
char *copy_call_trace_description_with_additional(const struct loader_context *context, const struct analysis_frame *head, additional_print_callback callback, void *callback_data);
__attribute__((nonnull(1, 2)))
struct loaded_binary *find_loaded_binary(const struct loader_context *context, const char *path);
__attribute__((nonnull(1)))
void free_loader_context(struct loader_context *loader_context);
__attribute__((nonnull(1, 1)))
void *resolve_loaded_symbol(const struct loader_context *context, const char *name, const char *version_name, int symbol_types, struct loaded_binary **out_binary, const ElfW(Sym) **out_symbol);
__attribute__((nonnull(1, 2, 3)))
void *resolve_binary_loaded_symbol(const struct loader_context *loader, struct loaded_binary *binary, const char *name, const char *version_name, int symbol_types, const ElfW(Sym) **out_symbol);

__attribute__((nonnull(1)))
uintptr_t translate_analysis_address_to_child(struct loader_context *loader, ins_ptr addr);
__attribute__((nonnull(1)))
struct register_state translate_register_state_to_child(struct loader_context *loader, struct register_state state);

struct queued_instruction;

struct queued_instructions {
	struct queued_instruction *queue;
	uint32_t count;
	uint32_t capacity;
};

struct searched_instruction_entry;

struct lookup_base_address;

struct lookup_base_addresses {
	struct lookup_base_address *addresses;
	size_t count;
};

struct effect_token {
	uint16_t generation;
	uint16_t entry_generation;
	uint32_t index;
	uint32_t entry_offset;
};

extern const int syscall_argument_abi_register_indexes[6];
extern const int sysv_argument_abi_register_indexes[SYSV_REGISTER_ARGUMENT_COUNT];

struct registers {
	struct register_state registers[REGISTER_COUNT];
	register_mask sources[REGISTER_COUNT];
	register_mask matches[REGISTER_COUNT];
	register_mask modified;
	register_mask requires_known_target;
#if STORE_LAST_MODIFIED
	ins_ptr last_modify_ins[REGISTER_COUNT];
#endif
	struct decoded_rm mem_rm;
	struct register_comparison compare_state;
#if RECORD_WHERE_STACK_ADDRESS_TAKEN
	ins_ptr stack_address_taken;
#else
	bool stack_address_taken:1;
#endif
};

extern const struct registers empty_registers;

struct analysis_frame {
	const struct analysis_frame *next;
	const void *address;
	const char *description;
	struct registers current_state;
	ins_ptr entry;
	const struct registers *entry_state;
	struct effect_token token;
};

enum effects {
	EFFECT_NONE          = 0,
	EFFECT_RETURNS       = 1 << 0, // set if the function could potentially return to its caller
	EFFECT_EXITS         = 1 << 1, // set if the function could potentially exit the program/thread
	EFFECT_STICKY_EXITS  = 1 << 2, // set if the function always exits by predefined policy
	EFFECT_PROCESSED     = 1 << 3, // set if the address has been processed
	EFFECT_PROCESSING    = 1 << 4, // set if the function is currently in the middle of being processed
	EFFECT_AFTER_STARTUP = 1 << 5, // set if the function could run after startup
	EFFECT_ENTRY_POINT   = 1 << 6, // set if the function is run as the program entrypoint
	EFFECT_ENTER_CALLS   = 1 << 7, // set if should traverse calls instead of recording loads
	EFFECT_MODIFIES_STACK = 1 << 8, // set if the function could potentially modify the stack
	EFFECT_STICKY_JUMPS_TO_SELF = 1 << 8, // set if the block jumps into itself to ignore reading off the end of jump tables
	EFFECT_TEMPORARY_IN_VARY_EFFECTS = 1 << 9, // set temporarily while varying effects
	VALID_EFFECTS        = (EFFECT_MODIFIES_STACK << 1) - 1,
	DEFAULT_EFFECTS = EFFECT_EXITS | EFFECT_RETURNS | EFFECT_MODIFIES_STACK,
};
typedef uint16_t function_effects;

struct program_state;

typedef void (*instruction_reached_callback)(struct program_state *, ins_ptr, struct registers *, function_effects, const struct analysis_frame *, struct effect_token *, void *callback_data);

struct searched_instruction_callback {
	instruction_reached_callback callback;
	void *data;
};

struct address_list {
	uintptr_t *addresses;
	size_t count;
};

struct searched_instructions {
	struct searched_instruction_entry *table;
	uint32_t mask;
	uint32_t remaining_slots;
	struct queued_instructions queue;
	struct lookup_base_addresses lookup_base_addresses;
	struct searched_instruction_callback *callbacks;
	uint32_t callback_count;
	uint16_t generation;
	struct address_list loaded_addresses;
	struct address_list tls_addresses;
	struct register_state *fopen_modes;
	size_t fopen_mode_count;
};

__attribute__((nonnull(1)))
void init_searched_instructions(struct searched_instructions *search);
__attribute__((nonnull(1)))
void cleanup_searched_instructions(struct searched_instructions *search);

struct recorded_syscall {
	uintptr_t nr;
	ins_ptr ins;
	ins_ptr entry;
	struct registers registers;
};

enum {
	SYSCALL_CONFIG_BLOCK = 1,
	SYSCALL_CONFIG_DEBUG = 2,
};

struct recorded_syscalls {
	struct recorded_syscall *list;
	int count;
	int capacity;
	bool unknown;
	uint8_t config[SYSCALL_COUNT];
};

__attribute__((nonnull(1, 2)))
char *copy_used_syscalls(const struct loader_context *context, const struct recorded_syscalls *syscalls, bool log_arguments, bool log_caller, bool include_symbol);
__attribute__((nonnull(1)))
char *copy_syscall_description(const struct loader_context *context, uintptr_t nr, const struct registers *registers, bool include_symbol);
__attribute__((nonnull(1, 2)))
void sort_and_coalesce_syscalls(struct recorded_syscalls *syscalls, struct loader_context *loader);
__attribute__((nonnull(1)))
const struct recorded_syscall *find_recorded_syscall(const struct recorded_syscalls *syscalls, uintptr_t nr);

struct mapped_region {
	uintptr_t start;
	uintptr_t end;
};
struct mapped_region_info {
	struct mapped_region *list;
	int count;
};
__attribute__((nonnull(1, 2)))
struct sock_fprog generate_seccomp_program(struct loader_context *loader, const struct recorded_syscalls *syscalls, const struct mapped_region_info *blocked_memory_regions, uint32_t syscall_range_low, uint32_t syscall_range_high);

enum {
	SKIPPED_LEA_AREA_COUNT = 32,
};

struct blocked_symbol {
	const char *name;
	ins_ptr value;
	int symbol_types;
	bool is_dlopen:1;
	bool is_required:1;
};

struct known_symbols {
	struct blocked_symbol *blocked_symbols;
	uint32_t blocked_symbol_count;
};

enum {
	NORMAL_SYMBOL = 1 << 0,
	LINKER_SYMBOL = 1 << 1,
	DEBUG_SYMBOL = 1 << 2,
	DEBUG_SYMBOL_FORCING_LOAD = DEBUG_SYMBOL | (1 << 3),
#if 0
	INTERNAL_COMMON_SYMBOL = NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL_FORCING_LOAD,
#else
	INTERNAL_COMMON_SYMBOL = NORMAL_SYMBOL | LINKER_SYMBOL,
#endif
};

__attribute__((nonnull(1, 2)))
struct blocked_symbol *add_blocked_symbol(struct known_symbols *known_symbols, const char *name, int symbol_types, bool required);

struct dlopen_path {
	struct dlopen_path *next;
	const char *path;
};

struct reachable_region {
	ins_ptr entry;
	ins_ptr exit;
};

struct reachable_instructions {
	struct reachable_region *regions;
	size_t count;
	size_t buffer_size;
};

typedef void (*address_loaded_callback)(struct program_state *, ins_ptr, const struct analysis_frame *, void *callback_data);

struct program_state {
	struct loader_context loader;
	struct searched_instructions search;
	struct recorded_syscalls syscalls;
	struct known_symbols known_symbols;
	uintptr_t main;
	const char *ld_preload;
	const char *ld_profile;
	struct dlopen_path *dlopen;
	const char *main_function_name;
	struct reachable_instructions reachable;
	ins_ptr skipped_call;
	address_loaded_callback address_loaded;
	void *address_loaded_data;
	const struct analysis_frame *current_frame;
};

__attribute__((nonnull(1, 2, 6)))
int load_binary_into_analysis(struct program_state *analysis, const char *path, const char *full_path, int fd, const void *existing_base_address, struct loaded_binary **out_binary);
__attribute__((nonnull(1, 2)))
int finish_loading_binary(struct program_state *analysis, struct loaded_binary *new_binary, function_effects effects, bool skip_analysis);
__attribute__((nonnull(1, 2, 3, 4)))
void analyze_function_symbols(struct program_state *analysis, const struct loaded_binary *binary, const struct symbol_info *symbols, struct analysis_frame *caller);

enum dlopen_options {
	DLOPEN_OPTION_ANALYZE_CODE = 1 << 0,
	DLOPEN_OPTION_ANALYZE_SYMBOLS = 1 << 1,
	DLOPEN_OPTION_RECURSE_INTO_FOLDERS = 1 << 2,
	DLOPEN_OPTION_IGNORE_ENOENT = 1 << 3,

	DLOPEN_OPTION_ANALYZE = DLOPEN_OPTION_ANALYZE_CODE | DLOPEN_OPTION_ANALYZE_SYMBOLS,
};
__attribute__((nonnull(1, 2)))
struct loaded_binary *register_dlopen(struct program_state *analysis, const char *path, const struct analysis_frame *caller, enum dlopen_options options);
__attribute__((nonnull(1)))
void finish_analysis(struct program_state *analysis);

void log_basic_blocks(const struct program_state *analysis, function_effects required_effects);

void populate_reachable_regions(struct program_state *analysis);

__attribute__((nonnull(1, 3, 4, 5)))
function_effects analyze_instructions(struct program_state *analysis, function_effects required_effects, struct registers *entry_state, ins_ptr ins, const struct analysis_frame *caller, int flags);

__attribute__((always_inline))
__attribute__((nonnull(1, 3, 4, 5)))
static inline function_effects analyze_function(struct program_state *analysis, function_effects required_effects, struct registers *entry_state, ins_ptr ins, const struct analysis_frame *caller)
{
	return analyze_instructions(analysis, required_effects, entry_state, ins, caller, 0);
}

__attribute__((nonnull(1)))
void record_syscall(struct program_state *analysis, uintptr_t nr, struct analysis_frame self, function_effects effects);

#ifdef STATS
extern intptr_t analyzed_instruction_count;
#endif

#endif
