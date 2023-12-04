#ifndef CALLANDER_H
#define CALLANDER_H

#include <linux/filter.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "loader.h"

#define MORE_STACK_SLOTS 0
#define STORE_LAST_MODIFIED 0
#define BREAK_ON_UNREACHABLES 0
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
	SYSCALL_ARG_IS_ITIMER_WHICH = 0x3f,
	SYSCALL_ARG_IS_SEEK_WHENCE = 0x40,
	SYSCALL_ARG_IS_SHMCTL_COMMAND = 0x41,
	SYSCALL_ARG_IS_SEMCTL_COMMAND = 0x42,
	SYSCALL_ARG_IS_PTRACE_REQUEST = 0x43,
	SYSCALL_ARG_IS_SEM_FLAGS = 0x44,
	SYSCALL_ARG_IS_UNSHARE_FLAGS = 0x45,
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

extern struct syscall_decl const syscall_list[SYSCALL_DEFINED_COUNT];
const char *name_for_syscall(uintptr_t nr);
struct syscall_info info_for_syscall(uintptr_t nr);

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
	BINARY_IGNORES_SIGNEDNESS = 1 << 12,
	BINARY_ASSUME_FUNCTION_CALLS_PRESERVE_STACK = 1 << 13,
	BINARY_HAS_CUSTOM_JUMPTABLE_METADATA = 1 << 14,
	BINARY_HAS_FUNCTION_SYMBOLS_ANALYZED = 1 << 15,
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
	ins_ptr gconv_dlopen;
	ins_ptr libcrypto_dlopen;
	ins_ptr setxid_syscall;
	ins_ptr setxid_syscall_entry;
	ins_ptr setxid_sighandler_syscall;
	ins_ptr setxid_sighandler_syscall_entry;
	struct loaded_binary_stub *sorted_binaries;
	int binary_count;
};

__attribute__((nonnull(1)))
char *copy_used_binaries(const struct loader_context *loader);
__attribute__((nonnull(1)))
char *copy_address_details(const struct loader_context *loader, const void *addr, bool include_symbol);
__attribute__((nonnull(1)))
char *copy_address_description(const struct loader_context *context, const void *address);
__attribute__((nonnull(1, 2)))
struct loaded_binary *find_loaded_binary(const struct loader_context *context, const char *path);
__attribute__((nonnull(1)))
void free_loaded_binary(struct loaded_binary *binary);
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

#if MORE_STACK_SLOTS
#define STACK_SLOT_COUNT 64
#define GENERATE_PER_STACK_REGISTER() \
	PER_STACK_REGISTER_IMPL(0) \
	PER_STACK_REGISTER_IMPL(4) \
	PER_STACK_REGISTER_IMPL(8) \
	PER_STACK_REGISTER_IMPL(12) \
	PER_STACK_REGISTER_IMPL(16) \
	PER_STACK_REGISTER_IMPL(20) \
	PER_STACK_REGISTER_IMPL(24) \
	PER_STACK_REGISTER_IMPL(28) \
	PER_STACK_REGISTER_IMPL(32) \
	PER_STACK_REGISTER_IMPL(36) \
	PER_STACK_REGISTER_IMPL(40) \
	PER_STACK_REGISTER_IMPL(44) \
	PER_STACK_REGISTER_IMPL(48) \
	PER_STACK_REGISTER_IMPL(52) \
	PER_STACK_REGISTER_IMPL(56) \
	PER_STACK_REGISTER_IMPL(60) \
	PER_STACK_REGISTER_IMPL(64) \
	PER_STACK_REGISTER_IMPL(68) \
	PER_STACK_REGISTER_IMPL(72) \
	PER_STACK_REGISTER_IMPL(76) \
	PER_STACK_REGISTER_IMPL(80) \
	PER_STACK_REGISTER_IMPL(84) \
	PER_STACK_REGISTER_IMPL(88) \
	PER_STACK_REGISTER_IMPL(92) \
	PER_STACK_REGISTER_IMPL(96) \
	PER_STACK_REGISTER_IMPL(100) \
	PER_STACK_REGISTER_IMPL(104) \
	PER_STACK_REGISTER_IMPL(108) \
	PER_STACK_REGISTER_IMPL(112) \
	PER_STACK_REGISTER_IMPL(116) \
	PER_STACK_REGISTER_IMPL(120) \
	PER_STACK_REGISTER_IMPL(124) \
	PER_STACK_REGISTER_IMPL(128) \
	PER_STACK_REGISTER_IMPL(132) \
	PER_STACK_REGISTER_IMPL(136) \
	PER_STACK_REGISTER_IMPL(140) \
	PER_STACK_REGISTER_IMPL(144) \
	PER_STACK_REGISTER_IMPL(148) \
	PER_STACK_REGISTER_IMPL(152) \
	PER_STACK_REGISTER_IMPL(156) \
	PER_STACK_REGISTER_IMPL(160) \
	PER_STACK_REGISTER_IMPL(164) \
	PER_STACK_REGISTER_IMPL(168) \
	PER_STACK_REGISTER_IMPL(172) \
	PER_STACK_REGISTER_IMPL(176) \
	PER_STACK_REGISTER_IMPL(180) \
	PER_STACK_REGISTER_IMPL(184) \
	PER_STACK_REGISTER_IMPL(188) \
	PER_STACK_REGISTER_IMPL(192) \
	PER_STACK_REGISTER_IMPL(196) \
	PER_STACK_REGISTER_IMPL(200) \
	PER_STACK_REGISTER_IMPL(204) \
	PER_STACK_REGISTER_IMPL(208) \
	PER_STACK_REGISTER_IMPL(212) \
	PER_STACK_REGISTER_IMPL(216) \
	PER_STACK_REGISTER_IMPL(220) \
	PER_STACK_REGISTER_IMPL(224) \
	PER_STACK_REGISTER_IMPL(228) \
	PER_STACK_REGISTER_IMPL(232) \
	PER_STACK_REGISTER_IMPL(236) \
	PER_STACK_REGISTER_IMPL(240) \
	PER_STACK_REGISTER_IMPL(244) \
	PER_STACK_REGISTER_IMPL(248) \
	PER_STACK_REGISTER_IMPL(252)
#else
#define STACK_SLOT_COUNT 30
#define GENERATE_PER_STACK_REGISTER() \
	PER_STACK_REGISTER_IMPL(0) \
	PER_STACK_REGISTER_IMPL(4) \
	PER_STACK_REGISTER_IMPL(8) \
	PER_STACK_REGISTER_IMPL(12) \
	PER_STACK_REGISTER_IMPL(16) \
	PER_STACK_REGISTER_IMPL(20) \
	PER_STACK_REGISTER_IMPL(24) \
	PER_STACK_REGISTER_IMPL(28) \
	PER_STACK_REGISTER_IMPL(32) \
	PER_STACK_REGISTER_IMPL(36) \
	PER_STACK_REGISTER_IMPL(40) \
	PER_STACK_REGISTER_IMPL(44) \
	PER_STACK_REGISTER_IMPL(48) \
	PER_STACK_REGISTER_IMPL(52) \
	PER_STACK_REGISTER_IMPL(56) \
	PER_STACK_REGISTER_IMPL(60) \
	PER_STACK_REGISTER_IMPL(64) \
	PER_STACK_REGISTER_IMPL(68) \
	PER_STACK_REGISTER_IMPL(72) \
	PER_STACK_REGISTER_IMPL(76) \
	PER_STACK_REGISTER_IMPL(80) \
	PER_STACK_REGISTER_IMPL(84) \
	PER_STACK_REGISTER_IMPL(88) \
	PER_STACK_REGISTER_IMPL(92) \
	PER_STACK_REGISTER_IMPL(96) \
	PER_STACK_REGISTER_IMPL(100) \
	PER_STACK_REGISTER_IMPL(104) \
	PER_STACK_REGISTER_IMPL(108) \
	PER_STACK_REGISTER_IMPL(112) \
	PER_STACK_REGISTER_IMPL(116)
#endif

enum register_index {
#ifdef __x86_64__
#define BASE_REGISTER_COUNT 16
	REGISTER_RAX = X86_REGISTER_AX,
	REGISTER_RCX = X86_REGISTER_CX,
	REGISTER_RDX = X86_REGISTER_DX,
	REGISTER_RBX = X86_REGISTER_BX,
	REGISTER_SP = X86_REGISTER_SP,
	REGISTER_RBP = X86_REGISTER_BP,
	REGISTER_RSI = X86_REGISTER_SI,
	REGISTER_RDI = X86_REGISTER_DI,
	REGISTER_R8 = X86_REGISTER_8,
	REGISTER_R9 = X86_REGISTER_9,
	REGISTER_R10 = X86_REGISTER_10,
	REGISTER_R11 = X86_REGISTER_11,
	REGISTER_R12 = X86_REGISTER_12,
	REGISTER_R13 = X86_REGISTER_13,
	REGISTER_R14 = X86_REGISTER_14,
	REGISTER_R15 = X86_REGISTER_15,
#else
#ifdef __aarch64__
#define BASE_REGISTER_COUNT 31
	REGISTER_X0 = AARCH64_REGISTER_X0,
	REGISTER_X1 = AARCH64_REGISTER_X1,
	REGISTER_X2 = AARCH64_REGISTER_X2,
	REGISTER_X3 = AARCH64_REGISTER_X3,
	REGISTER_X4 = AARCH64_REGISTER_X4,
	REGISTER_X5 = AARCH64_REGISTER_X5,
	REGISTER_X6 = AARCH64_REGISTER_X6,
	REGISTER_X7 = AARCH64_REGISTER_X7,
	REGISTER_X8 = AARCH64_REGISTER_X8,
	REGISTER_X9 = AARCH64_REGISTER_X9,
	REGISTER_X10 = AARCH64_REGISTER_X10,
	REGISTER_X11 = AARCH64_REGISTER_X11,
	REGISTER_X12 = AARCH64_REGISTER_X12,
	REGISTER_X13 = AARCH64_REGISTER_X13,
	REGISTER_X14 = AARCH64_REGISTER_X14,
	REGISTER_X15 = AARCH64_REGISTER_X15,
	REGISTER_X16 = AARCH64_REGISTER_X16,
	REGISTER_X17 = AARCH64_REGISTER_X17,
	REGISTER_X18 = AARCH64_REGISTER_X18,
	REGISTER_X19 = AARCH64_REGISTER_X19,
	REGISTER_X20 = AARCH64_REGISTER_X20,
	REGISTER_X21 = AARCH64_REGISTER_X21,
	REGISTER_X22 = AARCH64_REGISTER_X22,
	REGISTER_X23 = AARCH64_REGISTER_X23,
	REGISTER_X24 = AARCH64_REGISTER_X24,
	REGISTER_X25 = AARCH64_REGISTER_X25,
	REGISTER_X26 = AARCH64_REGISTER_X26,
	REGISTER_X27 = AARCH64_REGISTER_X27,
	REGISTER_X28 = AARCH64_REGISTER_X28,
	REGISTER_X29 = AARCH64_REGISTER_X29,
	// REGISTER_X30 = AARCH64_REGISTER_X30,
	REGISTER_SP = AARCH64_REGISTER_SP,
#else
#error "Unknown architecture"
#endif
#endif

	REGISTER_MEM,

#define PER_STACK_REGISTER_IMPL(offset) REGISTER_STACK_##offset,
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
};

enum {
	REGISTER_INVALID = -1,
	REGISTER_COUNT = BASE_REGISTER_COUNT + 1 + STACK_SLOT_COUNT,

#ifdef __x86_64__
	REGISTER_SYSCALL_NR = X86_REGISTER_AX,
	REGISTER_SYSCALL_ARG0 = X86_REGISTER_DI,
	REGISTER_SYSCALL_ARG1 = X86_REGISTER_SI,
	REGISTER_SYSCALL_ARG2 = X86_REGISTER_DX,
	REGISTER_SYSCALL_ARG3 = X86_REGISTER_10,
	REGISTER_SYSCALL_ARG4 = X86_REGISTER_8,
	REGISTER_SYSCALL_ARG5 = X86_REGISTER_9,
	REGISTER_SYSCALL_RESULT = X86_REGISTER_AX,

	SYSV_REGISTER_ARGUMENT_COUNT = 6,
#else
#ifdef __aarch64__
	REGISTER_SYSCALL_NR = AARCH64_REGISTER_X8,
	REGISTER_SYSCALL_ARG0 = AARCH64_REGISTER_X0,
	REGISTER_SYSCALL_ARG1 = AARCH64_REGISTER_X1,
	REGISTER_SYSCALL_ARG2 = AARCH64_REGISTER_X2,
	REGISTER_SYSCALL_ARG3 = AARCH64_REGISTER_X3,
	REGISTER_SYSCALL_ARG4 = AARCH64_REGISTER_X4,
	REGISTER_SYSCALL_ARG5 = AARCH64_REGISTER_X5,
	REGISTER_SYSCALL_RESULT = AARCH64_REGISTER_X0,

	SYSV_REGISTER_ARGUMENT_COUNT = 8,
#else
#error "Unknown architecture"
#endif
#endif
};

extern const int syscall_argument_abi_register_indexes[6];
extern const int sysv_argument_abi_register_indexes[SYSV_REGISTER_ARGUMENT_COUNT];

#define REGISTER_COUNT (BASE_REGISTER_COUNT + 1 + STACK_SLOT_COUNT)

#if REGISTER_COUNT > 64
typedef __uint128_t register_mask;
#else
typedef uint64_t register_mask;
#endif

#define ALL_REGISTERS ((~(register_mask)0) >> (sizeof(register_mask) * 8 - REGISTER_COUNT))
#define STACK_REGISTERS ((~(register_mask)0 << (BASE_REGISTER_COUNT + 1)) & ALL_REGISTERS)

__attribute__((packed))
struct decoded_rm {
#if defined(__x86_64__)
	uintptr_t addr;
	uint8_t rm:6;
	uint8_t base:4;
	uint8_t index:4;
	uint8_t scale:2;
#endif
};

enum {
	COMPARISON_IS_INVALID = 0,
	COMPARISON_SUPPORTS_EQUALITY = 1,
	COMPARISON_SUPPORTS_RANGE = 2,
	COMPARISON_SUPPORTS_ANY = COMPARISON_SUPPORTS_EQUALITY | COMPARISON_SUPPORTS_RANGE,
};

typedef uint8_t comparison_validity;

struct register_comparison {
	struct register_state value;
	uintptr_t mask;
	struct decoded_rm mem_rm;
	register_mask sources;
	uint8_t target_register:6;
	comparison_validity validity:2;
};

struct registers {
	struct register_state registers[REGISTER_COUNT];
	register_mask sources[REGISTER_COUNT];
	register_mask matches[REGISTER_COUNT];
#if STORE_LAST_MODIFIED
	ins_ptr last_modify_ins[REGISTER_COUNT];
#define last_modify_syscall_register last_modify_ins[REGISTER_SYSCALL_NR]
#else
	ins_ptr last_modify_syscall_register;
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
	VALID_EFFECTS        = (EFFECT_ENTER_CALLS << 1) - 1,
};
typedef uint8_t function_effects;

struct program_state;

typedef void (*instruction_reached_callback)(struct program_state *, ins_ptr, struct registers *, function_effects, const struct analysis_frame *, struct effect_token *, void *callback_data);

struct searched_instruction_callback {
	instruction_reached_callback callback;
	void *data;
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
	uintptr_t *loaded_addresses;
	int loaded_address_count;
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
char *copy_syscall_description(const struct loader_context *context, uintptr_t nr, struct registers registers, bool include_symbol);
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
	struct address_and_size skipped_lea_areas[SKIPPED_LEA_AREA_COUNT];
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

struct unreachable_instructions {
#if BREAK_ON_UNREACHABLES
	ins_ptr *breakpoints;
	size_t breakpoint_count;
	size_t breakpoint_buffer_size;
	struct reachable_region *reachable_regions;
	size_t reachable_region_count;
	size_t reachable_region_buffer_size;
#endif
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
	struct unreachable_instructions unreachables;
	ins_ptr skipped_call;
	address_loaded_callback address_loaded;
	void *address_loaded_data;
};

__attribute__((nonnull(1, 2, 6)))
int load_binary_into_analysis(struct program_state *analysis, const char *path, const char *full_path, int fd, const void *existing_base_address, struct loaded_binary **out_binary);
__attribute__((nonnull(1, 2)))
int finish_loading_binary(struct program_state *analysis, struct loaded_binary *new_binary, function_effects effects, bool skip_analysis);
__attribute__((nonnull(1, 2, 3, 4)))
void analyze_function_symbols(struct program_state *analysis, const struct loaded_binary *binary, const struct symbol_info *symbols, struct analysis_frame *caller);
__attribute__((nonnull(1, 2)))
struct loaded_binary *register_dlopen(struct program_state *analysis, const char *path, const struct analysis_frame *caller, bool skip_analysis, bool skip_analyzing_symbols, bool recursive);
__attribute__((nonnull(1)))
void finish_analysis(struct program_state *analysis);

enum {
	ALLOW_JUMPS_INTO_THE_ABYSS = 1,
};

__attribute__((nonnull(1, 3, 4, 5)))
function_effects analyze_instructions(struct program_state *analysis, function_effects required_effects, const struct registers *entry_state, ins_ptr ins, const struct analysis_frame *caller, int flags);

__attribute__((always_inline))
__attribute__((nonnull(1, 3, 4, 5)))
static inline function_effects analyze_function(struct program_state *analysis, function_effects required_effects, const struct registers *entry_state, ins_ptr ins, const struct analysis_frame *caller)
{
	return analyze_instructions(analysis, required_effects, entry_state, ins, caller, ALLOW_JUMPS_INTO_THE_ABYSS);
}

__attribute__((nonnull(1)))
void record_syscall(struct program_state *analysis, uintptr_t nr, struct analysis_frame self, function_effects effects);

#ifdef STATS
extern intptr_t analyzed_instruction_count;
#endif

#endif
