#include "callander.h"

#include <dirent.h>
#include <linux/audit.h>
#include <linux/binfmts.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "bpf_debug.h"
#include "exec.h"
#include "dlmalloc.h"
#include "freestanding.h"
#include "axon.h"
#include "loader.h"
#include "mapped.h"
#include "qsort.h"
#include "search.h"

#if defined(__x86_64__)
#define BREAKPOINT_LEN 1
#else
#if defined(__aarch64__)
#define BREAKPOINT_LEN 4
#else
#error "Unknown architecture"
#endif
#endif


#ifdef STANDALONE
AXON_BOOTSTRAP_ASM
#else
__asm__(
".text\n"
".global __restore\n"
".hidden __restore\n"
".type __restore,@function\n"
"__restore:\n"
"	mov $15, %rax\n"
); \
FS_DEFINE_SYSCALL
#endif

#ifndef SA_RESTORER
#define SA_RESTORER	0x04000000
#endif

enum attach_behavior {
	DETACH_AT_START,
	STAY_ATTACHED,
	ATTACH_GDB,
	ATTACH_STRACE,
};

#define PROFILE_HEADER_LINE "callander profile 0.0.1"

static void write_profile(const struct loader_context *loader, const struct recorded_syscalls *syscalls, ins_ptr main, const char *path)
{
	int fd = fs_open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		DIE("error opening profile", fs_strerror(fd));
	}
	// headers
	intptr_t result = fs_write_all(fd, PROFILE_HEADER_LINE"\n\n", sizeof(PROFILE_HEADER_LINE"\n\n")-1);
	if (result < 0) {
		goto error_write;
	}
	// binaries
	char *binaries_text = copy_used_binaries(loader);
	result = fs_write_all(fd, binaries_text, fs_strlen(binaries_text));
	free(binaries_text);
	if (result < 0) {
		goto error_write;
	}
	// separator
	result = fs_write_all(fd, "\n\n", 2);
	if (result < 0) {
		goto error_write;
	}
	// main
	char *main_str = copy_address_details(loader, main, false);
	result = fs_write_all(fd, main_str, fs_strlen(main_str));
	free(main_str);
	if (result < 0) {
		goto error_write;
	}
	// separator
	result = fs_write_all(fd, "\n", 1);
	if (result < 0) {
		goto error_write;
	}
	// syscalls
	char *syscalls_text = copy_used_syscalls(loader, syscalls, true, true, false);
	result = fs_write_all(fd, syscalls_text, fs_strlen(syscalls_text));
	free(syscalls_text);
	if (result < 0) {
		goto error_write;
	}
	fs_close(fd);
	return;
error_write:
	fs_close(fd);
	DIE("error writing profile", fs_strerror(result));
}

struct line_buf {
	char buf[4096];
	size_t consumed;
	size_t remaining;
};

static ssize_t read_line(int fd, struct line_buf *lines)
{
	if (lines->consumed != 0) {
		for (size_t i = 0; i < lines->remaining; i++) {
			lines->buf[i] = lines->buf[lines->consumed + i];
		}
	}
	size_t original_remaining = lines->remaining;
	for (size_t i = 0; i < original_remaining; i++) {
		if (lines->buf[i] == '\n' || lines->buf[i] == '\0') {
			lines->consumed = i + 1;
			lines->remaining -= lines->consumed;
			return i;
		}
	}
	while (lines->remaining < sizeof(lines->buf)) {
		intptr_t result = fs_read(fd, &lines->buf[lines->remaining], sizeof(lines->buf) - lines->remaining);
		if (result <= 0) {
			if (result == 0) {
				break;
			}
			return result;
		}
		lines->remaining += result;
	}
	for (size_t i = original_remaining; i < lines->remaining; i++) {
		if (lines->buf[i] == '\n' || lines->buf[i] == '\0') {
			lines->consumed = i + 1;
			lines->remaining -= lines->consumed;
			return i;
		}
	}
	lines->consumed = lines->remaining;
	lines->remaining = 0;
	return lines->consumed;
}

static struct loaded_binary *parse_and_load_library_line(struct program_state *analysis, char *buf, size_t len)
{
	// parse path part
	size_t name_end = len;
	size_t path_start = len;
	int special_binary_flags = 0;
	for (size_t i = 0; i < len; i++) {
		if (buf[i] == '*' && buf[i + 1] == ' ') {
			special_binary_flags = BINARY_IS_LOADED_VIA_DLOPEN;
			name_end = i;
			path_start = i + 2;
			break;
		}
		if (buf[i] == ' ') {
			name_end = i;
			path_start = i + 1;
			break;
		}
	}
	size_t path_end = len;
	for (size_t i = path_start; i < len; i++) {
		if (buf[i] == ' ') {
			path_end = i;
			break;
		}
	}
	char *name = malloc(name_end + 1 + (path_end - path_start) + 1);
	fs_memcpy(name, buf, name_end);
	name[name_end] = '\0';
	char *path = &name[name_end] + 1;
	fs_memcpy(path, &buf[path_start], path_end - path_start);
	path[path_end - path_start] = '\0';
	// should not have duplicates
	struct loaded_binary *binary = find_loaded_binary(&analysis->loader, name);
	if (binary != NULL) {
		free(name);
		return NULL;
	}
	// open the executable
	char path_buf[PATH_MAX];
	const char *full_path;
	int library_fd = find_executable_in_paths(path, NULL, false, analysis->loader.uid, analysis->loader.gid, path_buf, &full_path);
	if (library_fd < 0) {
		free(name);
		return NULL;
	}
	int result = load_binary_into_analysis(analysis, name, full_path, library_fd, NULL, &binary);
	fs_close(library_fd);
	if (result < 0) {
		free(name);
		return NULL;
	}
	binary->special_binary_flags |= special_binary_flags;
	// TODO: check hash!
	return binary;
}

static bool read_hex_numeric_offset(const struct loader_context *loader, char *buf, size_t len, uintptr_t *out_value)
{
	size_t num_pos = 0;
	for (size_t i = 0; i < len; i++) {
		if (buf[i] == '+' && buf[i+1] == '0' && buf[i+2] == 'x') {
			num_pos = i + 1;
			break;
		}
	}
	if (buf[num_pos] != '0' || buf[num_pos + 1] != 'x') {
		return false;
	}
	uintptr_t offset = 0;
	for (size_t i = num_pos + 2; i < len; i++) {
		int hex = fs_hexval(buf[i]);
		if (hex < 0) {
			return false;
		}
		offset = offset << 4 | hex;
	}
	// constant without a binary base
	if (num_pos == 0) {
		*out_value = offset;
		return true;
	}
	// offset from a binary base, find it
	for (struct loaded_binary *binary = loader->binaries; binary != NULL; binary = binary->next) {
		if (fs_strncmp(binary->path, buf, num_pos - 1) == 0 && binary->path[num_pos - 1] == '\0') {
			*out_value = (uintptr_t)binary->info.base + offset;
			return true;
		}
	}
	// binary not found
	return false;
}

static bool parse_and_load_syscall_line(struct program_state *analysis, char *buf, size_t len)
{
	// find opening paren
	size_t name_len = 0;
	for (; name_len < len; name_len++) {
		if (buf[name_len] == '(') {
			goto found_paren;
		}
	}
	return false;
found_paren:
	;
	// find syscall number
	uintptr_t nr = 0;
	for (; nr < sizeof(syscall_list) / sizeof(syscall_list[0]); nr++) {
		const char *candidate = name_for_syscall(nr);
		if (fs_strncmp(candidate, buf, name_len) == 0 && candidate[name_len] == '\0') {
			goto found_number;
		}
	}
	buf[name_len] = '\0';
	if (fs_scanu(buf, &nr) != &buf[name_len]) {
		return false;
	}
found_number:
	;
	struct recorded_syscalls *syscalls = &analysis->syscalls;
	int index = syscalls->count++;
	if (syscalls->list == NULL) {
		syscalls->capacity = 8;
		syscalls->list = malloc(syscalls->capacity * sizeof(struct recorded_syscall));
	} else if (index >= syscalls->capacity) {
		syscalls->capacity = syscalls->capacity << 1;
		syscalls->list = realloc(syscalls->list, syscalls->capacity * sizeof(struct recorded_syscall));
	}
	struct registers regs = empty_registers;
	set_register(&regs.registers[REGISTER_SYSCALL_NR], nr);
	// int argc = argc_for_syscall(nr) & SYSCALL_ARGC_MASK;
	size_t arg_start = name_len + 1;
	for (int i = 0; i < 6; i++) {
		if (buf[arg_start] == ')') {
			arg_start++;
			break;
		}
		while (buf[arg_start] == ' ') {
			arg_start++;
		}
		size_t dash_pos = len;
		size_t arg_end = arg_start;
		size_t plus_pos = len;
		for (size_t j = arg_start; j < len; j++) {
			if (buf[j] == '+') {
				plus_pos = j;
			} else if (buf[j] == '-') {
				if (plus_pos != len || dash_pos == len) {
					dash_pos = j;
					plus_pos = len;
				}
			} else if (buf[j] == ',' || buf[j] == ')') {
				arg_end = j;
				break;
			}
		}
		struct register_state state;
		if (dash_pos < arg_end && read_hex_numeric_offset(&analysis->loader, &buf[arg_start], dash_pos - arg_start, &state.value)) {
			if (!read_hex_numeric_offset(&analysis->loader, &buf[dash_pos + 1], arg_end - (dash_pos + 1), &state.max)) {
				return false;
			}
		} else {
			if (!read_hex_numeric_offset(&analysis->loader, &buf[arg_start], arg_end - arg_start, &state.value)) {
				return false;
			}
			state.max = state.value;
		}
		regs.registers[syscall_argument_abi_register_indexes[i]] = state;
		arg_start = arg_end + 1;
		if (len == arg_end || buf[arg_end] == ')') {
			break;
		}
	}
	uintptr_t ins = 0;
	if (arg_start + 3 < len && buf[arg_start] == ' ' && buf[arg_start + 1] == '@' && buf[arg_start + 2] == ' ') {
		read_hex_numeric_offset(&analysis->loader, &buf[arg_start + 3], len - (arg_start + 3), &ins);
	}
	syscalls->list[index] = (struct recorded_syscall){
		.nr = nr,
		.ins = (ins_ptr)ins,
		.registers = regs,
	};
	return true;
}

static bool read_profile(struct program_state *analysis, const char *path)
{
	int fd = fs_open(path, O_RDONLY, 0);
	if (fd < 0) {
		return false;
	}
	bool valid = false;
	struct line_buf lines;
	lines.consumed = 0;
	lines.remaining = 0;
	// validate header
	ssize_t char_count = read_line(fd, &lines);
	if (char_count != sizeof(PROFILE_HEADER_LINE)-1 || fs_strncmp(&lines.buf[0], PROFILE_HEADER_LINE, sizeof(PROFILE_HEADER_LINE)-1) != 0) {
		goto finish_profile;
	}
	// validate empty line
	if (read_line(fd, &lines) != 0) {
		goto finish_profile;
	}
	// read libraries
	for (;;) {
		char_count = read_line(fd, &lines);
		if (char_count <= 0) {
			if (char_count < 0) {
				goto finish_profile;
			}
			break;
		}
		const struct loaded_binary *binary = parse_and_load_library_line(analysis, lines.buf, char_count);
		if (binary == NULL) {
			lines.buf[char_count] = '\0';
			goto finish_profile;
		}
	}
	// read main function
	char_count = read_line(fd, &lines);
	if (char_count <= 0) {
		if (char_count < 0) {
			goto finish_profile;
		}
		goto finish_profile;
	}
	if (!read_hex_numeric_offset(&analysis->loader, lines.buf, char_count, &analysis->main)) {
		goto finish_profile;
	}
	// validate empty line
	if (read_line(fd, &lines) != 0) {
		goto finish_profile;
	}
	// read syscalls
	for (;;) {
		char_count = read_line(fd, &lines);
		if (char_count <= 0) {
			if (char_count < 0) {
				goto finish_profile;
			}
			break;
		}
		if (!parse_and_load_syscall_line(analysis, lines.buf, char_count)) {
			lines.buf[char_count] = '\0';
			goto finish_profile;
		}
	}
	valid = true;
finish_profile:
	fs_close(fd);
	return valid;
}

static void log_used_syscalls(const struct loader_context *loader, const struct recorded_syscalls *syscalls, bool log_arguments, bool log_caller, bool include_symbol)
{
	ERROR("permitted syscalls", temp_str(copy_used_syscalls(loader, syscalls, log_arguments, log_caller, include_symbol)));
}

static void log_used_binaries(const struct loader_context *loader)
{
	ERROR("loaded binaries", temp_str(copy_used_binaries(loader)));
}

__attribute__((used)) __attribute__((visibility("hidden")))
void perform_analysis(struct program_state *analysis, const char *executable_path, int fd)
{
	// load the main executable path
	struct loaded_binary *loaded;
	int result = load_binary_into_analysis(analysis, executable_path, executable_path, fd, NULL, &loaded);
	if (result != 0) {
		DIE("failed to load main binary", fs_strerror(result));
	}
	if (UNLIKELY(loaded->mode & S_ISUID) && loaded->uid != analysis->loader.uid) {
		DIE("executable is setuid and not currently running as uid", loaded->uid);
	}
	if (UNLIKELY(loaded->mode & S_ISGID) && loaded->gid != analysis->loader.gid) {
		DIE("executable is setgid and not currently running as gid", loaded->gid);
	}

	// load LD_PRELOAD libraries
	const char *ld_preload = analysis->ld_preload;
	if (ld_preload) {
		int cur = 0;
		for (int i = 0; ; i++) {
			if (ld_preload[i] == ':' || ld_preload[i] == ' ' || ld_preload[i] == '\0') {
				char *preload_path = malloc(i - cur + 1);
				fs_memcpy(preload_path, &ld_preload[cur], i - cur);
				preload_path[i - cur] = '\0';
				struct loaded_binary *binary = register_dlopen(analysis, preload_path, NULL, false, false, false);
				if (binary == NULL) {
					DIE("failed to load shared object specified via LD_PRELOAD", preload_path);
					free(preload_path);
				} else if (binary->path != preload_path) {
					free(preload_path);
				} else {
					binary->owns_path = true;
				}
				if (ld_preload[i] == '\0') {
					break;
				}
				cur = i+1;
			}
		}
	}

	for (struct dlopen_path *dlopen = analysis->dlopen; dlopen != NULL; dlopen = dlopen->next) {
		register_dlopen(analysis, dlopen->path, NULL, false, false, true);
	}

	// finish loading the main binary
	result = finish_loading_binary(analysis, loaded, EFFECT_NONE, false);
	if (result != 0) {
		if (result == -ENOENT) {
			ERROR_FLUSH();
			fs_exit(1);
		}
		DIE("failed to finish loading", fs_strerror(result));
	}
	analysis->main = (uintptr_t)loaded->info.entrypoint;

	fs_close(fd);

	// analyze the program
	if (analysis->loader.vdso != 0) {
		struct loaded_binary *vdso;
		result = load_binary_into_analysis(analysis, "[vdso]", "[vdso]", -1, (const void *)analysis->loader.vdso, &vdso);
		if (result != 0) {
			DIE("failed to load vDSO", fs_strerror(result));
		}
		result = finish_loading_binary(analysis, vdso, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, false);
		if (result != 0) {
			DIE("failed to finish loading vDSO", fs_strerror(result));
		}
		if (vdso->has_symbols) {
			LOG("analyzing symbols for", vdso->path);
			struct analysis_frame vdso_caller = { .address = vdso->info.base, .description = "vdso", .next = NULL, .current_state = empty_registers, .entry = vdso->info.base, .entry_state = &empty_registers, .token = { 0 } };
			analyze_function_symbols(analysis, vdso, &vdso->symbols, &vdso_caller);
		} else {
			DIE("expected vDSO to have symbols");
		}
	}

	LOG("base", (uintptr_t)loaded->info.base);
	LOG("entrypoint", temp_str(copy_address_description(&analysis->loader, loaded->info.entrypoint)));
	LOG("size", (uintptr_t)loaded->info.size);
	if (analysis->main_function_name != NULL) {
		void *main = resolve_loaded_symbol(&analysis->loader, analysis->main_function_name, NULL, NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL, NULL, NULL);
		if (main == NULL) {
			DIE("could not resolve main function", analysis->main_function_name);
		}
		analysis->main = (uintptr_t)main;
		struct analysis_frame new_caller = { .address = loaded->info.base, .description = "main", .next = NULL, .current_state = empty_registers, .entry = loaded->info.base, .entry_state = &empty_registers, .token = { 0 } };
		analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &empty_registers, main, &new_caller);
	} else {
		struct analysis_frame new_caller = { .address = loaded->info.base, .description = "entrypoint", .next = NULL, .current_state = empty_registers, .entry = loaded->info.base, .entry_state = &empty_registers, .token = { 0 } };
		analyze_function(analysis, EFFECT_ENTRY_POINT | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &empty_registers, loaded->info.entrypoint, &new_caller);
		if (analysis->main == (uintptr_t)loaded->info.entrypoint) {
			// reanalyze, since we didn't find a main
			analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &empty_registers, loaded->info.entrypoint, &new_caller);
		}
	}
	// interpreter entrypoint
	struct loaded_binary *interpreter = analysis->loader.interpreter;
	if (interpreter != NULL) {
		// LOG("assuming interpreter can run after startup");
		struct analysis_frame new_caller = { .address = interpreter->info.base, .description = "interpreter", .next = NULL, .current_state = empty_registers, .entry = loaded->info.base, .entry_state = &empty_registers, .token = { 0 } };
		analyze_function(analysis, EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &empty_registers, interpreter->info.entrypoint, &new_caller);
	} else {
		LOG("no interpreter for this binary");
	}

	LOG("finished initial pass, dequeuing instructions");
	ERROR_FLUSH();
	finish_analysis(analysis);
}

static void kill_or_die(pid_t pid)
{
	intptr_t result = fs_kill(pid, 9);
	if (result < 0) {
		DIE("failed to kill", fs_strerror(result));
	}
}

static intptr_t waitpid_uninterrupted(pid_t pid, int *status, int options)
{
	intptr_t result;
	do {
		result = FS_SYSCALL(__NR_wait4, pid, (intptr_t)status, options, 0);
	} while(result == -EINTR);
	return result;
}

static int populate_child_addresses(pid_t pid, struct loader_context *loader, bool allow_unexpected)
{
	char procbuf[64];
	fs_memcpy(procbuf, "/proc/", sizeof("/proc/")-1);
	int offset = fs_itoa(pid, &procbuf[sizeof("/proc/") - 1]);
	fs_memcpy(&procbuf[sizeof("/proc/") - 1 + offset], "/maps", sizeof("/maps"));
	int fd = fs_open(procbuf, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		return fd;
	}
	struct maps_file_state file;
	init_maps_file_state(&file);
	intptr_t result;
	for (;;) {
		struct mapping mapping;
		result = read_next_mapping_from_file(fd, &file, &mapping);
		if (result != 1) {
			break;
		}
		result = 0;
		if ((mapping.device != 0 || mapping.inode != 0 || fs_strcmp(mapping.path, "[vdso]") == 0) && (mapping.prot & PROT_EXEC)) {
			for (struct loaded_binary *binary = loader->binaries; binary != NULL; binary = binary->next) {
				if (binary->inode == mapping.inode && binary->device == mapping.device) {
					if (binary->child_base == 0) {
						LOG("populated child address", &mapping.path[0]);
						binary->child_base = (uintptr_t)mapping.start - mapping.offset;
					}
					goto next_mapping;
				}
			}
			// fallback that ignores device
			// workaround for lack of overlayfs virtualization of mount id in /proc/.../maps: https://github.com/moby/moby/issues/43512
			for (struct loaded_binary *binary = loader->binaries; binary != NULL; binary = binary->next) {
				if (binary->inode == mapping.inode) {
					if (binary->child_base == 0) {
						LOG("populated child address", &mapping.path[0]);
						binary->child_base = (uintptr_t)mapping.start - mapping.offset;
					}
					goto next_mapping;
				}
			}
			if (!allow_unexpected) {
				DIE("found unexpected binary", &mapping.path[0]);
			}
		}
	next_mapping:
		;
	}
	fs_close(fd);
	return result;
}

static struct loaded_binary *binary_for_child_address(const struct loader_context *context, uintptr_t addr, ins_ptr *out_analysis_address)
{
	if ((uintptr_t)addr < PAGE_SIZE) {
		return NULL;
	}
	struct loaded_binary *binary = context->binaries;
	for (; binary != NULL; binary = binary->next) {
		if (addr >= binary->child_base && addr < binary->child_base + binary->info.size) {
			if (out_analysis_address) {
				*out_analysis_address = (ins_ptr)(addr - binary->child_base + (uintptr_t)binary->info.base);
			}
			break;
		}
	}
	return binary;
}

static int compare_regions(const void *l, const void *r, void *unused)
{
	(void)unused;
	const struct mapped_region *l_region = l;
	const struct mapped_region *r_region = r;
	if (l_region->start < r_region->start) {
		return -1;
	}
	if (l_region->start > r_region->start) {
		return 1;
	}
	if (l_region->end < r_region->end) {
		return -1;
	}
	if (l_region->end > r_region->end) {
		return 1;
	}
	return 0;
}

static struct mapped_region_info copy_sorted_mapped_regions(const struct loader_context *loader)
{
	struct mapped_region *regions = malloc(loader->binary_count * sizeof(struct mapped_region));
	// convert to a list of regions
	int count = 0;
	for (struct loaded_binary *binary = loader->binaries; binary != NULL; binary = binary->next) {
		if (binary->child_base != 0) {
			regions[count++] = (struct mapped_region){
				.start = binary->child_base,
				.end = (binary->child_base + binary->info.size + (PAGE_SIZE - 1) /*+ (PAGE_SIZE * 2)*/) & -PAGE_SIZE,
			};
		}
	}
	// sort by address
	qsort_r(regions, count, sizeof(struct mapped_region), compare_regions, NULL);
	// merge overlapping addresses
	for (int i = count - 1; i > 0; i--) {
		if (regions[i].start <= regions[i-1].end) {
			regions[i-1].end = regions[i].end;
			count--;
			for (int j = i; j < count; j++) {
				regions[j] = regions[j+1];
			}
		}
	}
	return (struct mapped_region_info) {
		.list = regions,
		.count = count,
	};
}

static void wait_for_ptrace_event(enum __ptrace_request request, pid_t pid)
{
	// identify that we're looking for syscall entries
	intptr_t result = fs_ptrace(request, pid, 0, 0);
	if (result < 0) {
		DIE("failed to wait for syscall entry", fs_strerror(result));
	}
	// wait for syscall
	int status;
	waitpid_uninterrupted(pid, &status, 0);
}

__attribute__((warn_unused_result))
static intptr_t ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
#ifdef PTRACE_GETREGS
	return fs_ptrace(PTRACE_GETREGS, pid, 0, &regs);
#else
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof(*regs),
	};
	return fs_ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
#endif
}

__attribute__((warn_unused_result))
static intptr_t ptrace_setregs(pid_t pid, const struct user_regs_struct *regs)
{
#ifdef PTRACE_SETREGS
	return fs_ptrace(PTRACE_SETREGS, pid, 0, &regs);
#else
	struct iovec iov = {
		.iov_base = (void *)regs,
		.iov_len = sizeof(*regs),
	};
	return fs_ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
#endif
}

static intptr_t remote_perform_syscall(pid_t pid, struct user_regs_struct valid_regs, intptr_t id, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6)
{
	struct user_regs_struct regs = valid_regs;
	regs.USER_REG_SYSCALL = id;
	regs.USER_REG_ARG1 = arg1;
	regs.USER_REG_ARG2 = arg2;
	regs.USER_REG_ARG3 = arg3;
	regs.USER_REG_ARG4 = arg4;
	regs.USER_REG_ARG5 = arg5;
	regs.USER_REG_ARG6 = arg6;
	intptr_t result = ptrace_setregs(pid, &regs);
	if (result < 0) {
		DIE("failed to set registers", fs_strerror(result));
	}
	long original_bytes;
	result = fs_ptrace(PTRACE_PEEKTEXT, pid, (void *)valid_regs.USER_REG_PC, &original_bytes);
	if (result < 0) {
		DIE("failed to peek under program counter", fs_strerror(result));
	}
#if defined(__x86_64__)
	long new_bytes = 0xfdeb050f;
#else
#if defined(__aarch64__)
	long new_bytes = 0xd4000001;
#else
#error "Unsupported architecture"
#endif
#endif
	result = fs_ptrace(PTRACE_POKETEXT, pid, (void *)valid_regs.USER_REG_PC, (void *)new_bytes);
	if (result < 0) {
		DIE("failed to poke a syscall", fs_strerror(result));
	}
	// wait for syscall entry
	wait_for_ptrace_event(PTRACE_SYSCALL, pid);
	// wait for syscall exit
	wait_for_ptrace_event(PTRACE_SYSCALL, pid);
	// single step
	wait_for_ptrace_event(PTRACE_SINGLESTEP, pid);
	result = fs_ptrace(PTRACE_POKETEXT, pid, (void *)valid_regs.USER_REG_PC, (void *)original_bytes);
	if (result < 0) {
		DIE("failed to poke the original data back", fs_strerror(result));
	}
	result = ptrace_getregs(pid, &regs);
	if (result < 0) {
		DIE("failed to read registers back", fs_strerror(result));
	}
	return regs.USER_REG_RESULT;
}

static char *remote_read_string(pid_t pid, uintptr_t address)
{
	if (address == 0) {
		return NULL;
	}
	char buf[PAGE_SIZE * 2];
	size_t remaining_in_page = PAGE_SIZE - (address & PAGE_SIZE);
	intptr_t result = fs_process_vm_read(pid, buf, remaining_in_page, address);
	if (result < 0) {
		return NULL;
	}
	for (size_t i = 0; i < remaining_in_page; i++) {
		if (buf[i] == '\0') {
			char *str = malloc(i+1);
			memcpy(str, buf, i+1);
			return str;
		}
	}
	result = fs_process_vm_read(pid, &buf[remaining_in_page], PAGE_SIZE, address + remaining_in_page);
	if (result < 0) {
		return NULL;
	}
	for (size_t i = remaining_in_page; i < remaining_in_page + PAGE_SIZE; i++) {
		if (buf[i] == '\0') {
			char *str = malloc(i+1);
			memcpy(str, buf, i+1);
			return str;
		}
	}
	return NULL;
}

static void remote_apply_seccomp_filter(int tracee, struct user_regs_struct regs, intptr_t remote_address, struct sock_fprog *prog)
{
	struct sock_fprog child_prog = {
		.filter = (void *)(remote_address + sizeof(struct sock_fprog)),
		.len = prog->len,
	};
	intptr_t result = fs_process_vm_write(tracee, &child_prog, sizeof(struct sock_fprog), remote_address);
	if (result < 0) {
		DIE("failed to send program header to child", fs_strerror(result));
	}
	result = fs_process_vm_write(tracee, prog->filter, sizeof(struct sock_filter) * prog->len, remote_address + sizeof(struct sock_fprog));
	if (result < 0) {
		DIE("failed to send program filter to child", fs_strerror(result));
	}
	result = remote_perform_syscall(tracee, regs, __NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, remote_address, 0, 0, 0);
	if (result < 0) {
		DIE("failed to set seccomp policy in child", fs_strerror(result));
	}
}

static void remote_apply_seccomp_filter_or_split(int tracee, struct user_regs_struct regs, intptr_t remote_address, struct loader_context *loader, struct recorded_syscalls *syscalls, const struct mapped_region_info *regions, uint32_t syscall_range_low, uint32_t syscall_range_high, struct sock_fprog *out_prog)
{
	struct sock_fprog prog = generate_seccomp_program(loader, syscalls, regions, syscall_range_low, syscall_range_high);
	if (prog.len <= BPF_MAXINSNS) {
		remote_apply_seccomp_filter(tracee, regs, remote_address, &prog);
		if (out_prog != NULL) {
			*out_prog = prog;
		} else {
			free(prog.filter);
		}
		return;
	}
	if (out_prog != NULL) {
		*out_prog = prog;
	} else {
		free(prog.filter);
	}
	if (syscall_range_low == syscall_range_high) {
		DIE("syscall has too many call sites to generate a seccomp program", name_for_syscall(syscall_range_low));
	}
	// split, so half the syscalls are in one program and half in another
	uint32_t mid = syscall_range_low + ((syscall_range_high == ~(uint32_t)0 ? syscalls->list[syscalls->count-1].nr : syscall_range_high) - syscall_range_low) / 2;
	// apply both programs, being sure to load the program containing __NR_seccomp later since it will block additional program loads
	if (__NR_seccomp > mid) {
		remote_apply_seccomp_filter_or_split(tracee, regs, remote_address, loader, syscalls, regions, syscall_range_low, mid, NULL);
		remote_apply_seccomp_filter_or_split(tracee, regs, remote_address, loader, syscalls, regions, mid+1, syscall_range_high, NULL);
	} else {
		remote_apply_seccomp_filter_or_split(tracee, regs, remote_address, loader, syscalls, regions, mid+1, syscall_range_high, NULL);
		remote_apply_seccomp_filter_or_split(tracee, regs, remote_address, loader, syscalls, regions, syscall_range_low, mid, NULL);
	}
}

#if BREAK_ON_UNREACHABLES
static int compare_addresses(const void *left, const void *right, __attribute__((unused)) void *data)
{
	ins_ptr const *left_address = left;
	ins_ptr const *right_address = right;
	if ((uintptr_t)*left_address < (uintptr_t)*right_address) {
		return -1;
	}
	if ((uintptr_t)*left_address > (uintptr_t)*right_address) {
		return 1;
	}
	return 0;
}

static int compare_reachable_regions(const void *left, const void *right, __attribute__((unused)) void *data)
{
	const struct reachable_region *left_region = left;
	const struct reachable_region *right_region = right;
	if ((uintptr_t)left_region->exit < (uintptr_t)right_region->exit) {
		return -1;
	}
	if ((uintptr_t)left_region->exit > (uintptr_t)right_region->exit) {
		return 1;
	}
	if ((uintptr_t)left_region->entry < (uintptr_t)right_region->entry) {
		return -1;
	}
	if ((uintptr_t)left_region->entry > (uintptr_t)right_region->entry) {
		return 1;
	}
	return 0;
}

static void prune_unreachable_instructions(__attribute__((unused)) struct unreachable_instructions *unreachables, __attribute__((unused)) struct loader_context *loader)
{
	size_t breakpoint_count = unreachables->breakpoint_count;
	qsort_r(unreachables->breakpoints, breakpoint_count, sizeof(*unreachables->breakpoints), compare_addresses, NULL);
	for (size_t i = 1; i < breakpoint_count; i++) {
		if (unreachables->breakpoints[i] < unreachables->breakpoints[i-1]) {
			DIE("sorting breakpoints failed");
		}
	}
	size_t reachable_region_count = unreachables->reachable_region_count;
	if (UNLIKELY(reachable_region_count == 0)) {
		return;
	}
	qsort_r(unreachables->reachable_regions, reachable_region_count, sizeof(*unreachables->reachable_regions), compare_reachable_regions, NULL);
	for (size_t i = 1; i < reachable_region_count; i++) {
		if (unreachables->reachable_regions[i].exit < unreachables->reachable_regions[i-1].exit) {
			DIE("sorting reachable regions failed");
		}
		if (unreachables->reachable_regions[i].exit == unreachables->reachable_regions[i-1].exit) {
			if (unreachables->reachable_regions[i].entry < unreachables->reachable_regions[i-1].entry) {
				DIE("sorting reachable regions failed");
			}
		}
	}
	size_t j = 0;
	ins_ptr last_breakpoint = NULL;
	for (size_t i = 0; i < breakpoint_count; i++) {
		ins_ptr breakpoint = unreachables->breakpoints[i];
		if (breakpoint == last_breakpoint) {
			// prune duplicates
			unreachables->breakpoints[i] = NULL;
		} else {
			last_breakpoint = breakpoint;
			// prune breakpoints that were marked as reachable
			while ((uintptr_t)breakpoint >= (uintptr_t)unreachables->reachable_regions[j].exit) {
				j++;
				if (UNLIKELY(j == reachable_region_count)) {
					return;
				}
				LOG("advancing to entry", temp_str(copy_address_description(loader, unreachables->reachable_regions[j].entry)));
				LOG("advancing to exit", temp_str(copy_address_description(loader, unreachables->reachable_regions[j].exit)));
			}
			if ((uintptr_t)unreachables->reachable_regions[j].entry <= (uintptr_t)breakpoint) {
				unreachables->breakpoints[i] = NULL;
				LOG("pruning unreachable instruction that was later discovered to be reachable", temp_str(copy_address_description(loader, breakpoint)));
			} else {
				LOG("keeping unreachable instruction", temp_str(copy_address_description(loader, breakpoint)));
			}
		}
	}
}
#endif

static void add_dlopen_path(struct program_state *analysis, const char *path)
{
	struct dlopen_path *dlopen = malloc(sizeof(struct dlopen_path));
	dlopen->path = path;
	dlopen->next = analysis->dlopen;
	analysis->dlopen = dlopen;
}

static char *copy_path_with_subpath(const char *path, size_t path_len, const char *subpath, size_t subpath_len)
{
	char *result = malloc(path_len + 1 + subpath_len + 1);
	fs_memcpy(result, path, path_len);
	result[path_len] = '/';
	fs_memcpy(&result[path_len+1], subpath, subpath_len);
	result[path_len+1+subpath_len] = '\0';
	return result;
}

static int add_dlopen_paths_recursively(struct program_state *analysis, const char *path, const char *required_suffixes)
{
	size_t prefix_len = strlen(path);
	int fd = fs_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	if (fd < 0) {
		if (fd == -ENOENT) {
			return 0;
		}
		return fd;
	}
	for (;;) {
		char buf[8192];
		int count = fs_getdents(fd, (struct fs_dirent *)&buf[0], sizeof(buf));
		if (count <= 0) {
			if (count < 0) {
				return count;
			}
			break;
		}
		for (const char *current_required_suffix = required_suffixes; ;) {
			for (int offset = 0; offset < count; ) {
				const struct fs_dirent *ent = (const struct fs_dirent *)&buf[offset];
				const char *name = ent->d_name;
				const char *needle = current_required_suffix;
				for (const char *haystack = name;;) {
					if (*haystack == *needle || *needle == ':') {
						if (*needle == '\0' || *needle == ':') {
							add_dlopen_path(analysis, copy_path_with_subpath(path, prefix_len, name, haystack - name));
						}
						needle++;
					} else {
						needle = current_required_suffix;
					}
					if (*haystack == '\0') {
						break;
					}
					haystack++;
				}
				if (ent->d_type == DT_DIR && name[0] != '.' && current_required_suffix == required_suffixes) {
					char *child_path = copy_path_with_subpath(path, prefix_len, name, fs_strlen(name));
					int result = add_dlopen_paths_recursively(analysis, child_path, required_suffixes);
					free(child_path);
					if (result < 0){
						fs_close(fd);
						return result;
					}
				}
				offset += ent->d_reclen;
			}
			current_required_suffix = fs_strchr(current_required_suffix, ':');
			if (*current_required_suffix == '\0') {
				break;
			}
			current_required_suffix++;
		}
	}
	fs_close(fd);
	return 0;
}

static int query_program_version(const char *program_path, char *const envp[], char **out_response, size_t *out_size)
{
	int pipes[2];
	int result = fs_pipe(pipes);
	if (result < 0) {
		return result;
	}
	pid_t child_pid = fs_fork();
	if (child_pid < 0) {
		return child_pid;
	}
	if (child_pid == 0) {
		fs_close(pipes[0]);
		fs_close(0);
		result = fs_dup2(pipes[1], 1);
		if (result >= 0) {
			result = fs_dup2(pipes[1], 2);
			fs_close(pipes[1]);
			if (result >= 0) {
				const char *args[3];
				args[0] = program_path;
				args[1] = "--version";
				args[2] = NULL;
				result = fs_execve(program_path, (char * const*)args, envp);
			}
		}
		fs_exit(-result);
	}
	fs_close(pipes[1]);
	char *buf = malloc(PAGE_SIZE);
	size_t size = PAGE_SIZE;
	size_t offset = 0;
	for (;;) {
		result = fs_read(pipes[0], &buf[offset], size-offset);
		if (result <= 0) {
			if (result == -EINTR) {
				continue;
			}
			if (result < 0) {
				fs_close(pipes[0]);
				int status;
				waitpid_uninterrupted(child_pid, &status, 0);
				free(buf);
				return result;
			}
			break;
		}
		offset += result;
		if (offset == size) {
			size *= 2;
			buf = realloc(buf, size);
		}
	}
	fs_close(pipes[0]);
	int status;
	result = waitpid_uninterrupted(child_pid, &status, 0);
	if (result < 0) {
		free(buf);
		return result;
	}
	*out_response = buf;
	*out_size = size - offset;
	return status;
}

static bool parse_version_components(char *version_output, const char **out_major, const char **out_minor, const char **out_patch)
{
	char *cur = (char *)fs_strchr(version_output, ' ');
	if (*cur == '\0') {
		return false;
	}
	cur++;
	*out_major = cur;
	cur = (char *)fs_strchr(cur, '.');
	if (*cur == '\0') {
		return false;
	}
	cur++;
	*out_minor = cur;
	for (;; cur++) {
		if (*cur < '0' || *cur > '9') {
			break;
		}
	}
	if (*cur != '.') {
		*cur = '\0';
		*out_patch = "0";
	} else {
		*cur = '\0';
		cur++;
		*out_patch = cur;
		for (;; cur++) {
			if (*cur < '0' || *cur > '9') {
				*cur = '\0';
				break;
			}
		}
	}
	return true;
}

#define MAKE_VERSION_BUF(name, prefix, separator, suffix) \
	char name[sizeof(prefix "xxxxx" separator "xxxxx" suffix)]; \
	do { \
		size_t major_len = fs_strlen(version_major); \
		size_t minor_len = fs_strlen(version_minor); \
		if (major_len + minor_len > 10) { \
			DIE("invalid version"); \
		} \
		char *buf = name; \
		fs_memcpy(buf, prefix, sizeof(prefix)-1); \
		buf += sizeof(prefix)-1; \
		fs_memcpy(buf, version_major, major_len); \
		buf += major_len; \
		fs_memcpy(buf, separator, sizeof(separator)-1); \
		buf += sizeof(separator)-1; \
		fs_memcpy(buf, version_minor, minor_len); \
		buf += minor_len; \
		fs_memcpy(buf, suffix, sizeof(suffix)); \
	} while(0)

#define MAKE_FULL_VERSION_BUF(name, prefix, separator, separator2, suffix) \
	char name[sizeof(prefix "xxxxx" separator "xxxxx" separator2 "xxxxx" suffix)]; \
	do { \
		size_t major_len = fs_strlen(version_major); \
		size_t minor_len = fs_strlen(version_minor); \
		size_t patch_len = fs_strlen(version_patch); \
		if (major_len + minor_len + patch_len > 15) { \
			DIE("invalid version"); \
		} \
		char *buf = name; \
		fs_memcpy(buf, prefix, sizeof(prefix)-1); \
		buf += sizeof(prefix)-1; \
		fs_memcpy(buf, version_major, major_len); \
		buf += major_len; \
		fs_memcpy(buf, separator, sizeof(separator)-1); \
		buf += sizeof(separator)-1; \
		fs_memcpy(buf, version_minor, minor_len); \
		buf += minor_len; \
		fs_memcpy(buf, separator, sizeof(separator2)-1); \
		buf += sizeof(separator2)-1; \
		fs_memcpy(buf, version_patch, patch_len); \
		buf += patch_len; \
		fs_memcpy(buf, suffix, sizeof(suffix)); \
	} while(0)

static int apply_program_special_cases(struct program_state *analysis, const char *program_path, char *const envp[])
{
	const char *slash = fs_strrchr(program_path, '/');
	const char *program_name = *slash != '\0' ? &slash[1] : program_path;
	if (fs_strncmp(program_name, "python", sizeof("python")-1) == 0) {
		// found a python!
		analysis->loader.ignore_dlopen = true;
		char *version_string;
		size_t version_string_size;
		int result = query_program_version(program_path, envp, &version_string, &version_string_size);
		if (result < 0) {
			DIE("failed reading python version", fs_strerror(result));
		}
		version_string[version_string_size-1] = '\0';
		const char *version_major;
		const char *version_minor;
		const char *version_patch;
		if (!parse_version_components(version_string, &version_major, &version_minor, &version_patch)) {
			DIE("failed parsing python version", version_string);
		}
		MAKE_VERSION_BUF(dynload_buf, "/usr/lib/python", ".", "/lib-dynload");
		MAKE_VERSION_BUF(dynload64_buf, "/usr/lib64/python", ".", "/lib-dynload");
		MAKE_VERSION_BUF(site_packages_buf, "/usr/lib/python", ".", "/site-packages");
		MAKE_VERSION_BUF(site_packages64_buf, "/usr/lib64/python", ".", "/site-packages");
		MAKE_VERSION_BUF(suffix_buf, ".cpython-", "", "-x86_64-linux-gnu.so:.abi3.so");
		free(version_string);
		result = add_dlopen_paths_recursively(analysis, dynload_buf, suffix_buf);
		if (result < 0) {
			return result;
		}
		result = add_dlopen_paths_recursively(analysis, dynload64_buf, suffix_buf);
		if (result < 0) {
			return result;
		}
		result = add_dlopen_paths_recursively(analysis, "/usr/lib/python3/dist-packages", suffix_buf);
		if (result < 0) {
			return result;
		}
		result = add_dlopen_paths_recursively(analysis, site_packages_buf, suffix_buf);
		if (result < 0) {
			return result;
		}
		result = add_dlopen_paths_recursively(analysis, site_packages64_buf, suffix_buf);
		if (result < 0) {
			return result;
		}
	} else if (fs_strncmp(program_name, "ruby", sizeof("ruby")-1) == 0) {
		analysis->loader.ignore_dlopen = true;
		char *version_string;
		size_t version_string_size;
		int result = query_program_version(program_path, envp, &version_string, &version_string_size);
		if (result < 0) {
			DIE("failed reading ruby version", fs_strerror(result));
		}
		version_string[version_string_size-1] = '\0';
		const char *version_major;
		const char *version_minor;
		const char *version_patch;
		if (!parse_version_components(version_string, &version_major, &version_minor, &version_patch)) {
			DIE("failed parsing ruby version", version_string);
		}
		// add_blocked_symbol(&analysis->known_symbols, "rb_f_syscall", NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL_FORCING_LOAD, false);
		// add_blocked_symbol(&analysis->known_symbols, "rb_f_syscall.lto_priv.0", NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL_FORCING_LOAD, false);
		result = add_dlopen_paths_recursively(analysis, "/usr/lib64/ruby", ".so");
		if (result < 0) {
			return result;
		}
		result = add_dlopen_paths_recursively(analysis, "/usr/lib/ruby", ".so");
		if (result < 0) {
			return result;
		}
		MAKE_FULL_VERSION_BUF(usr_lib_buf, "/usr/lib/x86_64-linux-gnu/ruby/", ".", ".", "");
		result = add_dlopen_paths_recursively(analysis, usr_lib_buf, ".so");
		if (result < 0) {
			return result;
		}
	} else if (fs_strncmp(program_name, "perl", sizeof("perl")-1) == 0) {
		add_blocked_symbol(&analysis->known_symbols, "Perl_pp_syscall", NORMAL_SYMBOL | LINKER_SYMBOL, false);
	}
	return 0;
}

static char **copy_argv_with_prefixes(char **argv, char *arg0, char *arg1)
{
	size_t existing_argc = count_args(argv);
	size_t starting_offset = 1 + (arg1 != NULL ? 1 : 0);
	char **result = malloc((existing_argc + (starting_offset + 1)) * sizeof(char *));
	result[0] = arg0;
	if (arg1 != NULL) {
		result[1] = arg1;
	}
	for (size_t i = 0; i <= existing_argc; i++) {
		result[starting_offset+i] = argv[i];
	}
	return result;
}

__attribute__((unused))
static void test_mprotect(struct sock_fprog prog, uintptr_t base, size_t size, int prot, uint32_t expected_bpf_result)
{
	struct seccomp_data data = {
		.nr = __NR_mprotect,
		.arch = CURRENT_AUDIT_ARCH,
		.instruction_pointer = 0,
		.args = {
			base,
			size,
			prot,
			0,
			0,
			0,
		},
	};
	uint32_t bpf_result;
	ERROR("test_mprotect base", base);
	ERROR("test_mprotect size", size);
	const char *bpf_message = bpf_interpret(prog, (const char *)&data, sizeof(data), false, &bpf_result);
	if (bpf_message != NULL) {
		ERROR("test_mprotect returned error", bpf_message);
		return;
	}
	switch (bpf_result) {
		case SECCOMP_RET_ALLOW:
			ERROR("test_mprotect determined call would be allowed");
			break;
		case SECCOMP_RET_TRAP:
			ERROR("test_mprotect determined call would be trapped");
			break;
		case SECCOMP_RET_KILL_PROCESS:
			ERROR("test_mprotect determined call would kill process");
			break;
		default:
			ERROR("test_mprotect determined decision code", (uintptr_t)bpf_result);
			break;
	}
	if (bpf_result != expected_bpf_result) {
		switch (expected_bpf_result) {
			case SECCOMP_RET_ALLOW:
				ERROR("test_mprotect expected call would be allowed");
				break;
			case SECCOMP_RET_TRAP:
				ERROR("test_mprotect expected call would be trapped");
				break;
			case SECCOMP_RET_KILL_PROCESS:
				ERROR("test_mprotect expected call would kill process");
				break;
			default:
				ERROR("test_mprotect expected decision code", (uintptr_t)bpf_result);
				break;
		}
	}
}

static void cleanup_syscalls(struct recorded_syscalls *syscalls)
{
	free(syscalls->list);
	syscalls->list = NULL;
}

void __restore();

static void *stack;

static void segfault_handler(__attribute__((unused)) int nr, __attribute__((unused)) siginfo_t *info, __attribute__((unused)) void *void_context)
{
	if (info->si_code == SEGV_ACCERR && stack != NULL && info->si_addr >= stack && info->si_addr < (stack + STACK_GUARD_SIZE)) {
		DIE("binary requires more stack to analyze than was configured at build time");
	}
	struct fs_sigaction sa = {
		.handler = SIG_DFL,
		.flags = SA_RESTORER,
		.restorer = (void *)&__restore,
		.mask = { 0 },
	};
	int sa_result = fs_rt_sigaction(SIGSEGV, &sa, NULL, sizeof(struct fs_sigset_t));
	if (sa_result < 0) {
		DIE("failed to reset sigaction", fs_strerror(sa_result));
	}
}

#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
#ifdef STANDALONE
__attribute__((noinline))
int main(char *argv[], char *envp[], const ElfW(auxv_t) *aux)
#else
extern char **environ;
__attribute__((noinline, visibility("hidden")))
int main(__attribute__((unused)) int argc_, char *argv[])
#endif
{
#ifndef STANDALONE
	char **envp = (char **)environ;
#endif
	// Find PATH and LD_PRELOAD
	int envp_count = 0;
	const char *path = "/bin:/usr/bin";
	struct program_state analysis = { 0 };
	for (char **s = envp; *s != NULL; s++) {
		if (fs_strncmp(*s, "LD_PRELOAD=", sizeof("LD_PRELOAD=")-1) == 0) {
			analysis.ld_preload = *s + sizeof("LD_PRELOAD=")-1;
		} else {
			if (fs_strncmp(*s, "PATH=", sizeof("PATH=")-1) == 0) {
				const char *new_path = &(*s)[sizeof("PATH=")-1];
				if (*new_path != '\0') {
					path = new_path;
				}
			} else if (fs_strncmp(*s, "LD_PROFILE=", sizeof("LD_PROFILE=")-1) == 0) {
				const char *new_path = &(*s)[sizeof("LD_PROFILE=")-1];
				if (*new_path != '\0') {
					analysis.ld_profile = new_path;
				}
			}
			envp_count++;
		}
	}
#ifndef STANDALONE
	analysis.loader.uid = getauxval(AT_EUID);
	analysis.loader.gid = getauxval(AT_EGID);
	analysis.loader.vdso = getauxval(AT_SYSINFO_EHDR);
#else
	while (aux->a_type != AT_NULL) {
		switch (aux->a_type) {
			case AT_EUID:
				analysis.loader.uid = aux->a_un.a_val;
				break;
			case AT_EGID:
				analysis.loader.gid = aux->a_un.a_val;
				break;
			case AT_SYSINFO_EHDR:
				analysis.loader.vdso = aux->a_un.a_val;
				break;
		}
		aux++;
	}
#endif
	int executable_index = 1;
	bool show_permitted = false;
	bool show_binaries = false;
	bool allow_unexpected = false;
	bool mutable_binary_mappings = false;
	const char *profile_path = NULL;
	enum attach_behavior attach = DETACH_AT_START;
	bool skip_running = false;
	while (argv[executable_index] && *argv[executable_index] == '-') {
		const char *arg = argv[executable_index];
		bool is_permit = fs_strcmp(arg, "--permit-syscall") == 0;
		bool is_block = fs_strcmp(arg, "--block-syscall") == 0;
		if (is_permit || is_block || fs_strcmp(arg, "--debug-syscall") == 0) {
			const char *syscall_name = argv[executable_index+1];
			if (syscall_name == NULL) {
				if (is_permit) {
					ERROR("--permit-syscall requires an argument");
				} else if (is_block) {
					ERROR("--block-syscall requires an argument");
				} else {
					ERROR("--debug-syscall requires an argument");
				}
				ERROR_FLUSH();
				return 1;
			}
			bool found = false;
			for (size_t i = 0; i < sizeof(syscall_list) / sizeof(syscall_list[0]); i++) {
				if (syscall_list[i].name && fs_strcmp(syscall_list[i].name, syscall_name) == 0) {
					if (is_permit) {
						record_syscall(&analysis, i, (struct analysis_frame){
							.address = NULL, .description = "permit", .next = NULL,
							.current_state = empty_registers,
							.entry = NULL,
							.entry_state = &empty_registers,
							.token = { 0 },
						}, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS);
					} else if (is_block) {
						analysis.syscalls.config[i] |= SYSCALL_CONFIG_BLOCK;
					} else {
						analysis.syscalls.config[i] |= SYSCALL_CONFIG_DEBUG;
					}
					found = true;
					break;
				}
			}
			if (!found) {
				ERROR("invalid or unknown syscall", syscall_name);
				ERROR_FLUSH();
				return 1;
			}
			executable_index++;
		} else if (fs_strcmp(arg, "--block-exec") == 0) {
			analysis.syscalls.config[__NR_execve] |= SYSCALL_CONFIG_BLOCK;
			analysis.syscalls.config[__NR_execveat] |= SYSCALL_CONFIG_BLOCK;
		} else if (fs_strcmp(arg, "--block-function") == 0) {
			const char *function_name = argv[executable_index+1];
			if (function_name == NULL) {
				ERROR("--block-function requires an argument");
				ERROR_FLUSH();
				return 1;
			}
			add_blocked_symbol(&analysis.known_symbols, function_name, NORMAL_SYMBOL | LINKER_SYMBOL, true);
			executable_index++;
			if (!attach) {
				attach = STAY_ATTACHED;
			}
		} else if (fs_strcmp(arg, "--block-debug-function") == 0) {
			const char *function_name = argv[executable_index+1];
			if (function_name == NULL) {
				ERROR("--block-debug-function requires an argument");
				ERROR_FLUSH();
				return 1;
			}
			add_blocked_symbol(&analysis.known_symbols, function_name, NORMAL_SYMBOL | LINKER_SYMBOL | DEBUG_SYMBOL_FORCING_LOAD, true);
			executable_index++;
			if (!attach) {
				attach = STAY_ATTACHED;
			}
		} else if (fs_strcmp(arg, "--ignore-gconv-libraries") == 0) {
			analysis.loader.loaded_gconv_libraries = true;
		} else if (fs_strcmp(arg, "--ignore-dlopen") == 0) {
			analysis.loader.ignore_dlopen = true;
		} else if (fs_strcmp(arg, "--dlopen") == 0) {
			const char *dlopen_path = argv[executable_index+1];
			if (dlopen_path == NULL) {
				ERROR("--dlopen requires an argument");
				ERROR_FLUSH();
				return 1;
			}
			add_dlopen_path(&analysis, dlopen_path);
			executable_index++;
		} else if (fs_strcmp(arg, "--main-function") == 0) {
			if (analysis.main_function_name != NULL) {
				ERROR("--main-function can only be specified once");
				ERROR_FLUSH();
				return 1;
			}
			analysis.main_function_name = argv[executable_index+1];
			if (analysis.main_function_name == NULL) {
				ERROR("--main-function requires an argument");
				ERROR_FLUSH();
				return 1;
			}
			executable_index++;
		} else if (fs_strcmp(arg, "--show-permitted") == 0) {
			show_permitted = true;
		} else if (fs_strcmp(arg, "--show-binaries") == 0) {
			show_binaries = true;
		} else if (fs_strcmp(arg, "--allow-unexpected-binaries") == 0) {
			allow_unexpected = true;
		} else if (fs_strcmp(arg, "--mutable-binary-mappings") == 0) {
			mutable_binary_mappings = true;
		} else if (fs_strcmp(arg, "--profile") == 0) {
			profile_path = argv[executable_index+1];
			if (profile_path == NULL) {
				ERROR("--profile requires an argument");
				ERROR_FLUSH();
				return 1;
			}
			executable_index++;
		} else if (fs_strcmp(arg, "--attach-gdb") == 0) {
			if (attach) {
				ERROR("--attach-gdb overrides previous attachment behavior");
			}
			attach = ATTACH_GDB;
		} else if (fs_strcmp(arg, "--attach-strace") == 0) {
			if (attach) {
				ERROR("--attach-strace overrides previous attachment behavior");
			}
			attach = ATTACH_STRACE;
		} else if (fs_strcmp(arg, "--stay-attached") == 0) {
			if (attach) {
				ERROR("--stay-attached overrides previous attachment behavior");
				ERROR_FLUSH();
				return 1;
			}
			attach = STAY_ATTACHED;
#ifdef LOGGING
		} else if (fs_strcmp(arg, "--log") == 0) {
			should_log = true;
#endif
		} else if (fs_strcmp(arg, "--version") == 0) {
#define VERSION "callander 0.1\n"
			fs_write(1, VERSION, sizeof(VERSION)-1);
			return 0;
		} else if (fs_strcmp(arg, "--skip-running") == 0) {
			if (skip_running) {
				ERROR("--skip-running can only be specified once");
				ERROR_FLUSH();
				return 1;
			}
			skip_running = true;
		} else if (fs_strcmp(arg, "--") == 0) {
			executable_index++;
			break;
		} else {
			ERROR("unknown command line option", arg);
			ERROR_FLUSH();
			return 1;
		}
		executable_index++;
	}
	const char *executable_path = argv[executable_index];

	if (!executable_path) {
		ERROR_FLUSH();
#define USAGE "usage: callander [command]\n"\
		"Runs programs in an automatically generated seccomp sandbox\n"\
		"Copyright (C) 2020-2023 Ryan Petrich\n"\
		"\n"\
		"  --block-exec                 blocks calls to execute new programs\n"\
		"  --permit-syscall NAME        permits a specific system call by NAME (may be specified multiple times)\n"\
		"  --block-syscall NAME         blocks a specific system call by NAME (may be specified multiple times)\n"\
		"  --block-function NAME        blocks a specific function by symbol NAME (may be specified multiple times)\n"\
		"  --block-debug-function NAME  blocks a specific function by debug symbol NAME (may be specified multiple times)\n"\
		"  --main-function NAME         wait until the specified function is called before applying sandbox\n"\
		"  --dlopen LIBRARY_PATH        load a specific library at startup, assuming it will be dynamically dlopened after startup\n"\
		"  --ignore-dlopen              ignore calls to dlopen, assuming libraries will already be preloaded\n"\
		"  --show-permitted             shows permitted syscalls before launching program\n"\
		"  --attach-gdb                 attaches gdb to the program at startup\n"\
		"  --                           stop processing command line arguments\n"
		fs_write(2, USAGE, sizeof(USAGE)-1);
		return 1;
	}

	// open the main executable
	int fd = open_executable_in_paths(executable_path, path, true, analysis.loader.uid, analysis.loader.gid);
	if (UNLIKELY(fd < 0)) {
		ERROR("could not find main executable", executable_path);
		ERROR_FLUSH();
		return 1;
	}

	// find path so we can exec it
	char path_buf[PATH_MAX+1];
	intptr_t result = fs_readlink_fd(fd, path_buf, sizeof(path_buf)-1);
	if (result < 0) {
		DIE("failed to read path", fs_strerror(result));
	}
	path_buf[result] = '\0';
	LOG("will exec", &path_buf[0]);

	char **new_argv = &argv[executable_index];

	// parse #! lines
	char *loaded_executable_path = NULL;
	do {
	next_interpreter:
		;
		char header[BINPRM_BUF_SIZE + 1];
		size_t header_size = fs_pread_all(fd, header, BINPRM_BUF_SIZE, 0);
		if (header_size <= 0) {
			if (header_size == 0) {
				DIE("could not read executable header");
			}
			DIE("could not read executable header", fs_strerror(header_size));
		}
		header[header_size] = '\0';
		if (header[0] == '#' && header[1] == '!') {
			if (fs_strstr(header, "[_mri_]=/usr/bin/ruby-mri") != NULL) {
				// TODO: Support JRuby in RubyPick
				int new_fd = open_executable_in_paths("/usr/bin/ruby-mri", path, true, analysis.loader.uid, analysis.loader.gid);
				if (new_fd < 0) {
					DIE("could not load #! interpreter", fs_strerror(new_fd));
				}
				fs_close(fd);
				fd = new_fd;
				loaded_executable_path = "/usr/bin/ruby-mri";
				new_argv = copy_argv_with_prefixes(&new_argv[1], "/usr/bin/ruby-mri", NULL);
				goto next_interpreter;
			}
			char *arg0 = &header[2];
			while (*arg0 == ' ' || *arg0 == '\t') {
				arg0++;
			}
			if (*arg0 != '\n' && *arg0 != '\0') {
				char *arg1 = arg0;
				size_t arg0_len;
				size_t arg1_len = 0;
				for (;; arg1++) {
					if (*arg1 == ' ' || *arg1 == '\t') {
						*arg1 = '\0';
						arg0_len = arg1 - arg0;
						arg1++;
						for (char *end = arg1;; end++) {
							if (*end == ' ' || *end == '\t' || *end == '\n') {
								*end = '\0';
								arg1_len = end - arg1;
								break;
							}
							if (*end == '\0') {
								arg1_len = end - arg1;
								break;
							}
						}
						break;
					}
					if (*arg1 == '\n') {
						*arg1 = '\0';
						arg0_len = arg1 - arg0;
						arg1 = NULL;
						break;
					}
					if (*arg1 == '\0') {
						arg0_len = arg1 - arg0;
						arg1 = NULL;
						break;
					}
				}
				int new_fd = open_executable_in_paths(arg0, path, true, analysis.loader.uid, analysis.loader.gid);
				if (new_fd < 0) {
					DIE("could not load #! interpreter", fs_strerror(new_fd));
				}
				fs_close(fd);
				fd = new_fd;
				char *new_path = malloc(arg0_len + 1);
				fs_memcpy(new_path, arg0, arg0_len + 1);
				char *new_arg1 = NULL;
				if (arg1 != NULL) {
					new_arg1 = malloc(arg1_len + 1);
					fs_memcpy(new_arg1, arg1, arg1_len + 1);
				}
				new_argv = copy_argv_with_prefixes(new_argv, new_path, new_arg1);
				loaded_executable_path = new_path;
				goto next_interpreter;
			}
		}
	} while (0);
	result = apply_program_special_cases(&analysis, loaded_executable_path != NULL ? loaded_executable_path : &path_buf[0], (char *const *)envp);
	if (result < 0) {
		DIE("failed to apply program special cases", fs_strerror(result));
	}

	char *new_ld_preload = NULL;
	// create child so we can get the pid
	pid_t tracee = 0;
	int wakeup_child_fd = 0;
	if (!skip_running) {
		new_ld_preload = fs_mmap(NULL, PAGE_SIZE * 128, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (fs_is_map_failed(new_ld_preload)) {
			DIE("failed to allocate a shared page for LD_PRELOAD", fs_strerror((intptr_t)new_ld_preload));
		}
		int pipe_fds[2];
		result = FS_SYSCALL(SYS_pipe2, (intptr_t)&pipe_fds, O_CLOEXEC);
		if (result < 0) {
			DIE("failed to create pipe", fs_strerror(result));
		}
		pid_t tracer = fs_getpid();
		ERROR_FLUSH();
		result = fs_fork();
		if (result < 0) {
			DIE("failed to fork", fs_strerror(result));
		}
		if (result == 0) {
			char **new_envp = malloc((envp_count + 3) * sizeof(*envp));
			char **d = new_envp;
			for (char **s = envp; *s != NULL; s++) {
				if (fs_strncmp(*s, "LD_PRELOAD=", sizeof("LD_PRELOAD=")-1) != 0 && fs_strncmp(*s, "LD_BIND_NOW=1", sizeof("LD_BIND_NOW=")-1) != 0) {
					*d++ = *s;
				}
			}
			*d++ = "LD_BIND_NOW=1";

			// child does not need any new privs, so revoke them preemptively
			result = fs_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
			if (result != 0) {
				DIE("failed to set no new privileges", fs_strerror(result));
			}

			// set the tracer so Yama doesn't block ptrace in the parent
			result = fs_prctl(PR_SET_PTRACER, tracer, 0, 0, 0);
			if (result < 0) {
				LOG("failed to set tracer", fs_strerror(result));
			}

			// wait to be woken up on the pipe
			fs_close(pipe_fds[1]);
			char buf;
			result = fs_read(pipe_fds[0], &buf, 1);
			if (result != 1) {
				if (result == 0) {
					return 0;
				}
				DIE("error reading from pipe", fs_strerror(result));
			}
			if (*new_ld_preload != '\0') {
				*d++ = new_ld_preload;
			}
			*d = NULL;
			ERROR_FLUSH();

			result = fs_ptrace(PTRACE_TRACEME, 0, 0, 0);
			if (result < 0) {
				DIE("failed to be traced", fs_strerror(result));
			}

			// ask to be traced
			// exec the new program
			result = fs_execve(loaded_executable_path ?: &path_buf[0], new_argv, (char *const *)new_envp);
			if (result < 0) {
				DIE("failed to exec", fs_strerror(result));
			}
			ERROR_FLUSH();
			return 0;
		}
		tracee = result;
		analysis.loader.pid = tracee;
		wakeup_child_fd = pipe_fds[1];
		fs_close(pipe_fds[0]);
	}

	// load the main executable path
	init_searched_instructions(&analysis.search);

	bool has_read_profile = false;
	if (profile_path != NULL) {
		struct program_state profile_analysis = { 0 };
		if (read_profile(&profile_analysis, profile_path)) {
			analysis.loader = profile_analysis.loader;
			analysis.syscalls = profile_analysis.syscalls;
			analysis.main = profile_analysis.main;
			has_read_profile = true;
			goto skip_analysis;
		}
	}

	// allocate a signal stack
	void *signal_stack = fs_mmap(NULL, SIGNAL_STACK_SIZE + STACK_GUARD_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
	if (fs_is_map_failed(signal_stack)) {
		DIE("failed to allocate signal stack", fs_strerror((intptr_t)signal_stack));
	}
	// apply the guard page
	result = fs_mprotect(signal_stack, STACK_GUARD_SIZE, PROT_NONE);
	if (result != 0) {
		DIE("failed to protect stack guard", fs_strerror(result));
	}
	// assign the signal stack
	stack_t sigstack = {
		.ss_sp = signal_stack + STACK_GUARD_SIZE,
		.ss_size = SIGNAL_STACK_SIZE,
		.ss_flags = 0,
	};
	result = fs_sigaltstack(&sigstack, NULL);
	if (result < 0) {
		DIE("failed to assign signal stack", fs_strerror(result));
	}
	// look for segfaults
	struct fs_sigaction action = {
		.handler = (void *)&segfault_handler,
		.flags = SA_RESTORER|SA_SIGINFO|SA_NODEFER|SA_ONSTACK,
		.restorer = (void *)&__restore,
		.mask = { ~0l },
	};
	fs_sigdelset(&action.mask, SIGSEGV);
	result = fs_rt_sigaction(SIGSEGV, &action, NULL, sizeof(struct fs_sigset_t));
	if (result < 0) {
		DIE("failed to register for SIGSEGV", fs_strerror(result));
	}

	// allocate a temporary stack
	stack = fs_mmap(NULL, ALT_STACK_SIZE + STACK_GUARD_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
	if (fs_is_map_failed(stack)) {
		DIE("failed to allocate stack", fs_strerror((intptr_t)stack));
	}
	// apply the guard page
	result = fs_mprotect(stack, STACK_GUARD_SIZE, PROT_NONE);
	if (result != 0) {
		DIE("failed to protect stack guard", fs_strerror(result));
	}
	CALL_ON_ALTERNATE_STACK_WITH_ARG(perform_analysis, &analysis, loaded_executable_path ?: path_buf, fd, (char *)stack + ALT_STACK_SIZE + STACK_GUARD_SIZE);
#if 0
	{
		const intptr_t *stack_start = stack + STACK_GUARD_SIZE;
		bool found = false;
		intptr_t i = 0;
		for (; i < ALT_STACK_SIZE / PAGE_SIZE; i++) {
			const intptr_t *page_start = &stack_start[i * PAGE_SIZE / sizeof(intptr_t)];
#pragma GCC unroll 64
			for (size_t j = 0; j < PAGE_SIZE / sizeof(intptr_t); j++) {
				if (page_start[j] != 0) {
					found = true;
				}
			}
			if (found) {
				break;
			}
		}
		ERROR("bytes of stack used", ((ALT_STACK_SIZE / PAGE_SIZE) - i) * PAGE_SIZE);
	}
#endif
	// unmap the temporary stack
	fs_munmap(stack, ALT_STACK_SIZE + STACK_GUARD_SIZE);
	stack = NULL;
skip_analysis:

	if (analysis.syscalls.unknown) {
		if (!skip_running) {
			kill_or_die(tracee);
		}
		ERROR("not all syscalls could be determined");
		ERROR_FLUSH();
		return 1;
	} else {
		const struct recorded_syscall *discovered_execve = find_recorded_syscall(&analysis.syscalls, __NR_execve);
		const struct recorded_syscall *discovered_execveat = find_recorded_syscall(&analysis.syscalls, __NR_execveat);
		if (discovered_execve || discovered_execveat) {
			if (!skip_running) {
				kill_or_die(tracee);
			}
			if (discovered_execve && discovered_execveat) {
				ERROR("program calls execve and execveat. unable to analyze through execs. if you know your use of this program doesn't result in new programs being executed specify --block-exec");
			} else if (discovered_execve) {
				ERROR("program calls execve. unable to analyze through execs. if you know your use of this program doesn't result in new programs being executed specify --block-exec");
			} else {
				ERROR("program calls execveat. unable to analyze through execs. if you know your use of this program doesn't result in new programs being executed specify --block-exec");
			}
			ERROR_FLUSH();
			return 1;
		}
	}

	if (skip_running) {
		if (show_permitted) {
			log_used_syscalls(&analysis.loader, &analysis.syscalls, true, true, true);
		}
		if (show_binaries) {
			log_used_binaries(&analysis.loader);
		}
		if (profile_path != NULL && !has_read_profile) {
			write_profile(&analysis.loader, &analysis.syscalls, (ins_ptr)analysis.main, profile_path);
		}
		cleanup_searched_instructions(&analysis.search);
		free_loaded_binary(analysis.loader.binaries);
		cleanup_syscalls(&analysis.syscalls);
		free(analysis.known_symbols.blocked_symbols);
		ERROR_FLUSH();
		return 0;
	}

	// populate the shared LD_PRELOAD mapping
	if (new_ld_preload != NULL) {
		char *ld_preload_buf = new_ld_preload;
		for (const struct loaded_binary *binary = analysis.loader.last; binary != NULL; binary = binary->previous) {
			if (binary->special_binary_flags & BINARY_IS_LOADED_VIA_DLOPEN) {
				if (ld_preload_buf == new_ld_preload) {
					fs_memcpy(ld_preload_buf, "LD_PRELOAD=", sizeof("LD_PRELOAD=")-1);
					ld_preload_buf += sizeof("LD_PRELOAD=")-1;
				} else {
					*ld_preload_buf++ = ':';
				}
				ld_preload_buf = fs_strcpy(ld_preload_buf, binary->path);
			}
		}

		// wake the child
		char buf = 1;
		result = fs_write(wakeup_child_fd, &buf, 1);
		if (result != 1) {
			if (result == 0) {
				DIE("failed to write to pipe");
			}
			DIE("failed to write to pipe", fs_strerror(result));
		}

		// cleanup the shared LD_PRELOAD mapping
		fs_munmap(new_ld_preload, PAGE_SIZE * 128);
	}

	// set the child to exit if we ever do
	int status;
	waitpid_uninterrupted(tracee, &status, 0);
	result = fs_ptrace(PTRACE_SETOPTIONS, tracee, NULL, (void *)PTRACE_O_EXITKILL);
	if (result < 0) {
		kill_or_die(tracee);
		DIE("failed to set PTRACE_O_EXITKILL", fs_strerror(result));
	}

	// no longer need the wakeup fd
	fs_close(wakeup_child_fd);

	// find the mapped addresses so we can determine where main landed
	result = populate_child_addresses(tracee, &analysis.loader, allow_unexpected);
	if (result < 0) {
		DIE("failed to read child process map", fs_strerror(result));
	}
	if (analysis.loader.main->child_base == 0) {
		DIE("failed to find main base address");
	}
	LOG("runtime base", analysis.loader.main->child_base);
	uintptr_t child_main = translate_analysis_address_to_child(&analysis.loader, (void *)analysis.main);
	// overwrite the main function with a breakpoint instruction
	long original_bytes;
	result = fs_ptrace(PTRACE_PEEKTEXT, tracee, (void *)child_main, &original_bytes);
	if (result < 0) {
		DIE("failed to peek", fs_strerror(result));
	}
#if defined(__x86_64__)
	long new_bytes = (original_bytes & ~(long)0xff) | 0xcc;
#else
#if defined(__aarch64__)
	// TODO: add breakpoint
	long new_bytes = 0;
#else
#error "Unknown architecture"
#endif
#endif
	result = fs_ptrace(PTRACE_POKETEXT, tracee, (void *)child_main, (void *)new_bytes);
	if (result < 0) {
		DIE("failed to poke", fs_strerror(result));
	}
	// resume the program
	result = fs_ptrace(PTRACE_CONT, tracee, 0, 0);
	if (result < 0) {
		DIE("failed to continue", fs_strerror(result));
	}
	// wait for child to hit our breakpoint, or otherwise exit
	result = waitpid_uninterrupted(tracee, &status, 0);
	if (result < 0) {
		DIE("failed waiting for child to hit breakpoint", fs_strerror(result));
	}
	// ensure we're stopped at a signal
	if (!WIFSTOPPED(status)) {
		free_loaded_binary(analysis.loader.binaries);
		// early exit because the child died during startup
		if (WIFSIGNALED(status)) {
			ERROR_FLUSH();
			return 128 + WTERMSIG(status);
		}
		if (WIFEXITED(status)) {
			ERROR_FLUSH();
			return WEXITSTATUS(status);
		}
		ERROR_FLUSH();
		return 0;
	}
	// send the original main bytes back, restoring the main function back to its original state
	result = fs_ptrace(PTRACE_POKETEXT, tracee, (void *)child_main, (void *)original_bytes);
	if (result < 0) {
		DIE("failed to poke original breakpoint bytes back", fs_strerror(result));
	}
	// find where all the other library addresses are
	result = populate_child_addresses(tracee, &analysis.loader, allow_unexpected);
	if (result < 0) {
		DIE("failed to read child process map", fs_strerror(result));
	}
	for (struct loaded_binary *binary = analysis.loader.binaries; binary != NULL; binary = binary->next) {
		if (binary->child_base == 0) {
			DIE("failed to find base address for", binary->path);
		}
	}
	// patch in unreachable breakpoints
#if BREAK_ON_UNREACHABLES
	if (attach) {
		prune_unreachable_instructions(&analysis.unreachables, &analysis.loader);
		size_t breakpoint_count = analysis.unreachables.breakpoint_count;
		for (size_t i = 0; i < breakpoint_count; i++) {
			ins_ptr addr = analysis.unreachables.breakpoints[i];
			if (addr != NULL) {
				LOG("patching breakpoint to unreachable instruction", temp_str(copy_address_description(&analysis.loader, addr)));
				void *child_addr = (void *)translate_analysis_address_to_child(&analysis.loader, addr);
				if (child_addr != NULL) {
					result = fs_ptrace(PTRACE_PEEKTEXT, tracee, child_addr, &original_bytes);
					if (result < 0) {
						DIE("failed to peek", fs_strerror(result));
					}
					new_bytes = (original_bytes & ~(long)0xff) | 0xcc;
					result = fs_ptrace(PTRACE_POKETEXT, tracee, child_addr, (void *)new_bytes);
					if (result < 0) {
						DIE("failed to poke", fs_strerror(result));
					}
				}
			}
		}
	}
#endif
#if 0
	{
		for (uint32_t i = 0; i < analysis.search.mask; i++) {
			const void *address = analysis.search.table[i].address;
			if (address != NULL) {
				struct searched_instruction_data *data = &analysis.search.table[i];
				for (uint32_t j = 0; j < data->count; j++) {
					if (data->entries[j].effects == EFFECT_NONE) {
						ERROR("address was analyzed, but was missing effects", temp_str(copy_address_description(&analysis.loader, address)));
						ERROR("missing effects at index", (intptr_t)j);
					}
				}
			}
		}
	}
#endif
	cleanup_searched_instructions(&analysis.search);
#ifdef STATS
	ERROR("analyzed instruction count", analyzed_instruction_count);
#endif
	// prepare seccomp program to inject into child
	if (show_permitted) {
		log_used_syscalls(&analysis.loader, &analysis.syscalls, true, true, true);
	}
	if (show_binaries) {
		log_used_binaries(&analysis.loader);
	}
	if (profile_path != NULL && !has_read_profile) {
		write_profile(&analysis.loader, &analysis.syscalls, (ins_ptr)analysis.main, profile_path);
	}
	// read the registers
	struct user_regs_struct regs;
	result = ptrace_getregs(tracee, &regs);
	if (result < 0) {
		DIE("failed to read registers", fs_strerror(result));
	}
	// rewind back to where the breakpoint was
	if (regs.USER_REG_PC != child_main + BREAKPOINT_LEN) {
		DIE("interrupted at wrong child address", (uintptr_t)regs.USER_REG_PC);
	}
	regs.USER_REG_PC -= BREAKPOINT_LEN;
	for (uint32_t i = 0; i < analysis.known_symbols.blocked_symbol_count; i++) {
		struct blocked_symbol symbol = analysis.known_symbols.blocked_symbols[i];
		if (symbol.value == NULL) {
			if (!symbol.is_required) {
				continue;
			}
			DIE("failed to find blocked function", symbol.name);
		}
		uintptr_t addr = translate_analysis_address_to_child(&analysis.loader, symbol.value);
		result = fs_ptrace(PTRACE_PEEKTEXT, tracee, (void *)addr, &original_bytes);
		if (result < 0) {
			DIE("failed to peek at blocked function", fs_strerror(result));
		}
		new_bytes = (original_bytes & ~(long)0xff) | 0xcc;
		result = fs_ptrace(PTRACE_POKETEXT, tracee, (void *)addr, (void *)new_bytes);
		if (result < 0) {
			DIE("failed to poke at blocked function", fs_strerror(result));
		}
	}
	// map in anonymous pages to hold the program
	size_t allocation_size = sizeof(struct sock_fprog) + sizeof(struct sock_filter) * BPF_MAXINSNS;
	// set seccomp filters in the child
	struct sock_fprog prog;
	if (mutable_binary_mappings) {
		remote_apply_seccomp_filter_or_split(tracee, regs, regs.USER_REG_SP - allocation_size, &analysis.loader, &analysis.syscalls, NULL, 0, ~(uint32_t)0, &prog);
	} else {
		struct mapped_region_info regions = copy_sorted_mapped_regions(&analysis.loader);
		remote_apply_seccomp_filter_or_split(tracee, regs, regs.USER_REG_SP - allocation_size, &analysis.loader, &analysis.syscalls, &regions, 0, ~(uint32_t)0, &prog);
#if 0
		test_mprotect(prog, regions.list[0].start-0x2000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, SECCOMP_RET_ALLOW);
		test_mprotect(prog, regions.list[0].start-0x1000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, SECCOMP_RET_ALLOW);
		test_mprotect(prog, regions.list[0].start, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, SECCOMP_RET_TRAP);
		test_mprotect(prog, regions.list[0].start, regions.list[0].end-regions.list[0].start, PROT_READ|PROT_WRITE|PROT_EXEC, SECCOMP_RET_TRAP);
		test_mprotect(prog, regions.list[0].end-0x1000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, SECCOMP_RET_TRAP);
		test_mprotect(prog, regions.list[0].end, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, SECCOMP_RET_ALLOW);
		test_mprotect(prog, regions.list[0].end+0x1000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, SECCOMP_RET_ALLOW);
		ERROR_FLUSH();
		fs_exit(1);
#endif
		free(regions.list);
	}
	// free if not attaching
	if (!attach) {
		free(prog.filter);
		free_loaded_binary(analysis.loader.binaries);
	}
	// unmap the anonymous pages
	// TODO: allowlist this
	// result = remote_perform_syscall(tracee, regs, __NR_munmap, mmap_result, ceiled_allocation_size, 0, 0, 0, 0);
	// if (fs_is_map_failed((void *)mmap_result)) {
	// 	DIE("failed to munmap in child", fs_strerror(result));
	// }
	// restore the register state
	result = ptrace_setregs(tracee, &regs);
	if (result < 0) {
		DIE("failed to restore registers", fs_strerror(result));
	}
	if (attach == ATTACH_GDB || attach == ATTACH_STRACE) {
		result = fs_kill(tracee, SIGSTOP);
		if (result < 0) {
			DIE("failed to stop process", fs_strerror(result));
		}
		// detach from the child, it can proceed as normal
		result = fs_ptrace(PTRACE_DETACH, tracee, 0, 0);
		if (result < 0) {
			DIE("failed to detach", fs_strerror(result));
		}
		ERROR_FLUSH();
		char pid_buf[64];
		fs_itoa(tracee, pid_buf);
		const char *exec_path;
		const char *args[8];
		if (attach == ATTACH_STRACE) {
			exec_path = "/usr/bin/strace";
			args[0] = "strace";
			args[1] = "-p";
			args[2] = pid_buf;
			args[3] = "-i";
			args[4] = "-f";
			args[5] = NULL;
		} else {
			struct fs_stat sudo_stat;
			if (fs_stat("/usr/bin/sudo", &sudo_stat) == 0) {
				exec_path = "/usr/bin/sudo";
				args[0] = "sudo";
				args[1] = "gdb";
				args[2] = "--pid";
				args[3] = pid_buf;
				args[4] = "--eval-command=signal SIGCONT";
				args[5] = "--eval-command=handle SIGSTOP nostop noprint";
				// args[6] = "--eval-command=continue";
				args[6] = NULL;
			} else {
				exec_path = "/usr/bin/gdb";
				args[0] = "gdb";
				args[1] = "--pid";
				args[2] = pid_buf;
				args[3] = "--eval-command=signal SIGCONT";
				args[4] = "--eval-command=handle SIGSTOP nostop noprint";
				// args[5] = "--eval-command=continue";
				args[5] = NULL;
			}
		}
		result = fs_execve(exec_path, (void *)args, (char * const *)envp);
		if (result < 0) {
			DIE("failed to exec attaching program", fs_strerror(result));
		}
	} else {
		ERROR_FLUSH();
		if (attach == STAY_ATTACHED) {
			// continue executing in the child
			result = fs_ptrace(PTRACE_CONT, tracee, 0, 0);
			if (result < 0) {
				DIE("failed to continue", fs_strerror(result));
			}
		} else {
			// detach from the child, it can proceed as normal
			result = fs_ptrace(PTRACE_DETACH, tracee, 0, 0);
			if (result < 0) {
				DIE("failed to detach", fs_strerror(result));
			}
		}
#ifdef STANDALONE
		// return memory to the kernel
		dlmalloc_trim(0);
#endif
		// wait for the process to finish running
	wait_for_child:
		result = waitpid_uninterrupted(tracee, &status, 0);
		if (result < 0) {
			DIE("failed waiting for child", fs_strerror(result));
		}
		// pass through the exit status
		if (attach) {
			if (WIFSTOPPED(status)) {
				siginfo_t siginfo;
				result = fs_ptrace(PTRACE_GETSIGINFO, tracee, 0, &siginfo);
				if (result < 0) {
					DIE("failed to get signal info", fs_strerror(result));
				}
				if (siginfo.si_signo == SIGSYS) {
					uintptr_t call_addr = (uintptr_t)siginfo.si_call_addr - 2;
					ins_ptr analysis_addr = NULL;
					result = ptrace_getregs(tracee, &regs);
					if (result < 0) {
						DIE("failed to read registers back", fs_strerror(result));
					}
					uintptr_t nr = regs.USER_REG_SYSCALL;
					uint8_t config = nr < SYSCALL_COUNT ? analysis.syscalls.config[nr] : 0;
					if (config & SYSCALL_CONFIG_BLOCK) {
						ERROR("blocked syscall was issued", name_for_syscall(nr));
					} else {
						const struct loaded_binary *binary = binary_for_child_address(&analysis.loader, call_addr, &analysis_addr);
						if (binary != NULL) {
							ERROR("received an unexpected seccomp SIGSYS at", temp_str(copy_address_description(&analysis.loader, analysis_addr)));
							ERROR("binary mapped at address", binary->child_base);
						} else {
							ERROR("received an unexpected seccomp SIGSYS at", call_addr);
						}
						ERROR("faulting address", (uintptr_t)siginfo.si_call_addr);
						struct seccomp_data data = {
							.nr = nr,
							.arch = CURRENT_AUDIT_ARCH,
							.instruction_pointer = (uintptr_t)siginfo.si_call_addr,
							.args = {
								regs.USER_REG_ARG1,
								regs.USER_REG_ARG2,
								regs.USER_REG_ARG3,
								regs.USER_REG_ARG4,
								regs.USER_REG_ARG5,
								regs.USER_REG_ARG6,
							},
						};
						uint32_t bpf_result;
						const char *bpf_error = bpf_interpret(prog, (const char *)&data, sizeof(data), SHOULD_LOG, &bpf_result);
						if (bpf_error != NULL) {
							ERROR("error interpreting BPF program", bpf_error);
						} else {
							switch (bpf_result) {
								case SECCOMP_RET_ALLOW:
									ERROR("BPF result is SECCOMP_RET_ALLOW");
									break;
								case SECCOMP_RET_TRAP:
									ERROR("BPF result is SECCOMP_RET_TRAP");
									break;
								case SECCOMP_RET_KILL_PROCESS:
									ERROR("BPF result is SECCOMP_RET_KILL_PROCESS");
									break;
								default:
									ERROR("BPF result is", bpf_result);
									break;
							}
						}
						const char *name = name_for_syscall(nr);
						size_t name_len = fs_strlen(name);
						size_t len = name_len + 3; // '(' ... ')' '\0'
						int argc = info_for_syscall(nr).attributes & SYSCALL_ARGC_MASK;
						for (int i = 0; i < argc; i++) {
							if (i != 0) {
								len += 2; // ", "
							}
							char buf[10];
							len += data.args[i] < PAGE_SIZE ? fs_utoa(data.args[i], buf) : fs_utoah(data.args[i], buf);
						}
						char *buf = malloc(len);
						fs_memcpy(buf, name, name_len);
						char *cur = &buf[name_len];
						*cur++ = '(';
						for (int i = 0; i < argc; i++) {
							if (i != 0) {
								*cur++ = ',';
								*cur++ = ' ';
							}
							cur += data.args[i] < PAGE_SIZE ? fs_utoa(data.args[i], cur) : fs_utoah(data.args[i], cur);
						}
						*cur++ = ')';
						*cur++ = '\0';
						ERROR("syscall was", buf);
						free(buf);
						ERROR("perhaps callander's analysis is insufficient?");
					}
				} else if (siginfo.si_signo == SIGTRAP) {
					result = ptrace_getregs(tracee, &regs);
					if (result < 0) {
						DIE("failed to read registers back", fs_strerror(result));
					}
					uintptr_t breakpoint_address = regs.USER_REG_PC - BREAKPOINT_LEN;
					for (uint32_t i = 0; i < analysis.known_symbols.blocked_symbol_count; i++) {
						struct blocked_symbol symbol = analysis.known_symbols.blocked_symbols[i];
						uintptr_t addr = translate_analysis_address_to_child(&analysis.loader, symbol.value);
						if (addr == breakpoint_address) {
							if (symbol.is_dlopen) {
								char *dlopen_path = remote_read_string(tracee, regs.USER_REG_ARG1);
								if (dlopen_path != NULL) {
									ERROR("dlopen on an unexpected binary was called", dlopen_path);
									free(dlopen_path);
									break;
								}
							}
							ERROR("blocked function was called", symbol.name);
							break;
						}
					}
#if BREAK_ON_UNREACHABLES
					size_t breakpoint_count = analysis.unreachables.breakpoint_count;
					for (size_t i = 0; i < breakpoint_count; i++) {
						ins_ptr addr = analysis.unreachables.breakpoints[i];
						uintptr_t child_addr = translate_analysis_address_to_child(&analysis.loader, addr);
						if (child_addr == breakpoint_address) {
							ERROR("assumed unreachable instruction was somehow reached", temp_str(copy_address_description(&analysis.loader, addr)));
							ERROR("perhaps callander's analysis is insufficient?");
							break;
						}
					}
#endif
				} else {
					result = fs_ptrace(PTRACE_CONT, tracee, 0, 0);
					if (result < 0) {
						DIE("failed to continue child after receiving signal", fs_strerror(result));
					}
					goto wait_for_child;
				}
				free_loaded_binary(analysis.loader.binaries);
				ERROR_FLUSH();
				return 128 + WSTOPSIG(status);
			}
			free_loaded_binary(analysis.loader.binaries);
		}
		if (WIFSIGNALED(status)) {
			if (attach) {
				free(prog.filter);
			}
			ERROR_FLUSH();
			return 128 + WTERMSIG(status);
		}
		if (WIFEXITED(status)) {
			if (attach) {
				free(prog.filter);
			}
			ERROR_FLUSH();
			return WEXITSTATUS(status);
		}
	}
	ERROR_FLUSH();
	return 0;
}
#pragma GCC pop_options

#ifdef STANDALONE
__attribute__((used))
noreturn void release(size_t *sp, __attribute__((unused)) size_t *dynv)
{
	char **argv = (void *)(sp+1);
	char **current_argv = argv;
	while (*current_argv != NULL) {
		++current_argv;
	}
	char **envp = current_argv+1;
	char **current_envp = envp;
	bool bench = false;
	while (*current_envp != NULL) {
		if (UNLIKELY(fs_strcmp(*current_envp, "CALLANDER_BENCH=1") == 0)) {
			bench = true;
		}
		++current_envp;
	}
	ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(current_envp + 1);
	ElfW(auxv_t) *current_aux = aux;
	while (current_aux->a_type != AT_NULL) {
		switch (current_aux->a_type) {
			case AT_PHDR: {
				uintptr_t base = (uintptr_t)current_aux->a_un.a_val & (uintptr_t)-PAGE_SIZE;
				struct binary_info self_info;
				load_existing(&self_info, base);
				self_info.dynamic = _DYNAMIC;
				relocate_binary(&self_info);
				break;
			}
		}
		current_aux++;
	}
	if (UNLIKELY(bench)) {
		int result = 0;
		for (int i = 0; i < 64; i++) {
			result = main(argv, envp, aux);
		}
		ERROR_FLUSH();
		fs_exit(result);
	}
	int result = main(argv, envp, aux);
	ERROR_FLUSH();
	fs_exit(result);
	__builtin_unreachable();
}
#endif
