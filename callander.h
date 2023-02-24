#ifndef CALLANDER_H
#define CALLANDER_H

#include <linux/filter.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "loader.h"

#define MORE_STACK_SLOTS 1
#define STORE_LAST_MODIFIED 0
#define BREAK_ON_UNREACHABLES 0
#define RECORD_WHERE_STACK_ADDRESS_TAKEN 0

#define LOGGING

#ifdef LOGGING
extern bool should_log;
#define SHOULD_LOG UNLIKELY(should_log)
#define LOG(...) do { if (UNLIKELY(should_log)) { ERROR(__VA_ARGS__); } } while(0)
#else
#define SHOULD_LOG false
#define LOG(...) do { } while(0)
#endif

enum {
	ALT_STACK_SIZE = 160 * 1024 * 1024,
	SIGNAL_STACK_SIZE = 512 * 1024,
	STACK_GUARD_SIZE = 1024 * 1024,
};


enum {
	SYSCALL_ARGC_MASK = 0x7,
	SYSCALL_ARG_IS_ADDRESS_BASE = 0x8,
	SYSCALL_CAN_BE_FROM_ANYWHERE = SYSCALL_ARG_IS_ADDRESS_BASE << 6,
	SYSCALL_IS_RESTARTABLE = SYSCALL_ARG_IS_ADDRESS_BASE << 7,
	SYSCALL_ARG_IS_PRESERVED_BASE = SYSCALL_ARG_IS_ADDRESS_BASE << 8,
	SYSCALL_ARG_IS_MODEFLAGS_BASE = SYSCALL_ARG_IS_PRESERVED_BASE << 6,
};

struct syscall_decl {
	const char *name;
	uint32_t valid_args;
};

#define SYSCALL_DEF(name, argc, flags) 1+
#define SYSCALL_DEF_EMPTY() 1+
enum {
	SYSCALL_COUNT = 512,
	SYSCALL_DEFINED_COUNT = 
#include "syscall_defs_x86_64.h"
	0,
};
#undef SYSCALL_DEF
#undef SYSCALL_DEF_EMPTY

extern struct syscall_decl const syscall_list[SYSCALL_DEFINED_COUNT];
const char *name_for_syscall(uintptr_t nr);
uint32_t argc_for_syscall(uintptr_t nr);

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

struct loaded_binary {
	const char *path;
	unsigned long path_hash;
	struct binary_info info;
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
	uintptr_t override_access_starts[OVERRIDE_ACCESS_SLOT_COUNT];
	uintptr_t override_access_ends[OVERRIDE_ACCESS_SLOT_COUNT];
	int override_access_permissions[OVERRIDE_ACCESS_SLOT_COUNT];
	ElfW(Sym) libcrypto_dso_meth_dl;
	char loaded_path[];
};

struct loader_stub;

struct loader_context {
	struct loaded_binary *binaries;
	struct loaded_binary *last;
	struct loaded_binary *main;
	struct loaded_binary *interpreter;
	struct loader_stub *stubs;
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
	const uint8_t *gconv_dlopen;
	const uint8_t *libcrypto_dlopen;
	const uint8_t *setxid_syscall;
	const uint8_t *setxid_sighandler_syscall;
	struct loaded_binary *last_used;
	int binary_count;
};

char *copy_used_binaries(const struct loader_context *loader);
char *copy_address_details(const struct loader_context *loader, const void *addr, bool include_symbol);
char *copy_address_description(const struct loader_context *context, const void *address);
struct loaded_binary *find_loaded_binary(const struct loader_context *context, const char *path);
void free_loaded_binary(struct loaded_binary *binary);
void *resolve_loaded_symbol(const struct loader_context *context, const char *name, const char *version_name, int symbol_types, struct loaded_binary **out_binary, const ElfW(Sym) **out_symbol);

uintptr_t translate_analysis_address_to_child(struct loader_context *loader, const uint8_t *addr);
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
	PER_STACK_REGISTER_IMPL(120)
#else
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
	PER_STACK_REGISTER_IMPL(60)
#endif

enum register_index {
	REGISTER_RAX,
	REGISTER_RCX,
	REGISTER_RDX,
	REGISTER_RBX,
	REGISTER_RSP,
	REGISTER_RBP,
	REGISTER_RSI,
	REGISTER_RDI,
	REGISTER_R8,
	REGISTER_R9,
	REGISTER_R10,
	REGISTER_R11,
	REGISTER_R12,
	REGISTER_R13,
	REGISTER_R14,
	REGISTER_R15,

	REGISTER_MEM,

#define PER_STACK_REGISTER_IMPL(offset) REGISTER_STACK_##offset,
	GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
};

enum {
	REGISTER_INVALID = -10000000,
#if MORE_STACK_SLOTS
	REGISTER_COUNT = REGISTER_STACK_120 + 1,
#else
	REGISTER_COUNT = REGISTER_STACK_60 + 1,
#endif
};

const int syscall_argument_abi_register_indexes[6];
const int sysv_argument_abi_register_indexes[6];

typedef uint64_t register_mask;

enum {
	ALL_REGISTERS = (((register_mask)1 << (REGISTER_COUNT - 1)) - 1) << 1 | 1,
	STACK_REGISTERS = (register_mask)0
#define PER_STACK_REGISTER_IMPL(offset) | ((register_mask)1 << REGISTER_STACK_##offset)
	GENERATE_PER_STACK_REGISTER(),
#undef PER_STACK_REGISTER_IMPL
};

struct register_state { 
	uintptr_t value;
	uintptr_t max;
};

static inline void clear_register(struct register_state *reg) {
	reg->value = (uintptr_t)0;
	reg->max = ~(uintptr_t)0;
}

static inline void set_register(struct register_state *reg, uintptr_t value) {
	reg->value = value;
	reg->max = value;
}

__attribute__((packed))
struct decoded_rm {
	uintptr_t addr;
	uint8_t rm:6;
	uint8_t base:4;
	uint8_t index:4;
	uint8_t scale:2;
};

enum {
	COMPARISON_IS_INVALID = 0,
	COMPARISON_SUPPORTS_EQUALITY = 1,
	COMPARISON_SUPPORTS_RANGE = 2,
	COMPARISON_SUPPORTS_ANY = COMPARISON_SUPPORTS_EQUALITY | COMPARISON_SUPPORTS_RANGE,
};

typedef uint8_t comparison_validity;

struct x86_comparison {
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
	const uint8_t *last_modify_ins[REGISTER_COUNT];
#endif
#if RECORD_WHERE_STACK_ADDRESS_TAKEN
	const uint8_t *stack_address_taken;
#else
	bool stack_address_taken:1;
#endif
	struct decoded_rm mem_rm;
	struct x86_comparison compare_state;
};

const struct registers empty_registers;

struct analysis_frame {
	const struct analysis_frame *next;
	const void *address;
	const char *description;
	struct registers current_state;
	const uint8_t *entry;
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
	VALID_EFFECTS        = (EFFECT_ENTRY_POINT << 1) - 1,
};
typedef uint8_t function_effects;

struct program_state;

typedef void (*instruction_reached_callback)(struct program_state *, const uint8_t *, struct registers *, function_effects, struct analysis_frame *, struct effect_token *, void *callback_data);

struct searched_instruction_callback {
	instruction_reached_callback callback;
	void *data;
};

struct searched_instructions {
	struct searched_instruction_entry *table;
	uint32_t mask;
	uint32_t remaining_slots;
	uint16_t generation;
	struct queued_instructions queue;
	struct lookup_base_addresses lookup_base_addresses;
	struct searched_instruction_callback *callbacks;
	uint32_t callback_count;
	uintptr_t *loaded_addresses;
	size_t loaded_address_count;
	bool loaded_addresses_are_sorted:1;
};

void init_searched_instructions(struct searched_instructions *search);
void cleanup_searched_instructions(struct searched_instructions *search);

struct recorded_syscall {
	uintptr_t nr;
	const uint8_t *ins;
	const uint8_t *entry;
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

char *copy_used_syscalls(const struct loader_context *context, const struct recorded_syscalls *syscalls, bool log_arguments, bool log_caller, bool include_symbol);
void sort_and_coalesce_syscalls(struct recorded_syscalls *syscalls, struct loader_context *loader);
const struct recorded_syscall *find_recorded_syscall(const struct recorded_syscalls *syscalls, uintptr_t nr);

enum seccomp_validation_mode {
	VALIDATE_SYSCALL_ONLY = 0,
	VALIDATE_SYSCALL_AND_CALL_SITE = 1,
	VALIDATE_ALL = 2,
};
struct sock_fprog generate_seccomp_program(struct loader_context *loader, struct recorded_syscalls *syscalls, enum seccomp_validation_mode validation_mode, uint32_t syscall_range_low, uint32_t syscall_range_high);

struct address_and_size {
	const uint8_t *address;
	size_t size;
};

enum {
	SKIPPED_LEA_AREA_COUNT = 32,
};

struct blocked_symbol {
	const char *name;
	const uint8_t *value;
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
};

struct blocked_symbol *add_blocked_symbol(struct known_symbols *known_symbols, const char *name, int symbol_types, bool required);

struct dlopen_path {
	struct dlopen_path *next;
	const char *path;
};

struct reachable_region {
	const uint8_t *entry;
	const uint8_t *exit;
};

struct unreachable_instructions {
#if BREAK_ON_UNREACHABLES
	const uint8_t **breakpoints;
	size_t breakpoint_count;
	size_t breakpoint_buffer_size;
	struct reachable_region *reachable_regions;
	size_t reachable_region_count;
	size_t reachable_region_buffer_size;
#endif
};

struct program_state {
	struct loader_context loader;
	struct searched_instructions search;
	struct recorded_syscalls syscalls;
	struct known_symbols known_symbols;
	uintptr_t main;
	pid_t pid;
	const char *ld_preload;
	const char *ld_profile;
	struct dlopen_path *dlopen;
	const char *main_function_name;
	struct unreachable_instructions unreachables;
};

int load_binary_into_analysis(struct program_state *analysis, const char *path, int fd, const void *existing_base_address, struct loaded_binary **out_binary);
int finish_loading_binary(struct program_state *analysis, struct loaded_binary *new_binary, function_effects effects, bool skip_analysis);
void analyze_function_symbols(struct program_state *analysis, const struct loaded_binary *binary, const struct symbol_info *symbols, struct analysis_frame *caller);
const struct loaded_binary *register_dlopen(struct program_state *analysis, const char *path, struct analysis_frame *caller, bool skip_analysis, bool recursive);
void finish_analysis(struct program_state *analysis);

enum jump_table_status {
	DISALLOW_JUMPS_INTO_THE_ABYSS = 0,
	ALLOW_JUMPS_INTO_THE_ABYSS = 1,
	DISALLOW_AND_PROMPT_FOR_DEBUG_SYMBOLS = 2,
};

function_effects analyze_instructions(struct program_state *analysis, function_effects required_effects, const struct registers *entry_state, const uint8_t *ins, struct analysis_frame *caller, enum jump_table_status jump_status);

void record_syscall(struct program_state *analysis, uintptr_t nr, struct analysis_frame self, function_effects effects);

#endif
