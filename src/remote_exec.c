#define _GNU_SOURCE
#define PATCH_EXPOSE_INTERNALS
#include "remote_exec.h"

#include <sched.h>
#ifdef __APPLE__
#include <pthread.h>
#endif

#include "axon.h"
#include "callander.h"
#include "exec.h"
#include "freestanding.h"
#include "linux.h"
#include "thandler.h"
#include "patch.h"
#include "proxy.h"
#include "search.h"

__attribute__((warn_unused_result))
static int remote_exec_fd_script(const char *sysroot, int fd, const char *named_path, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, int depth, size_t header_size, char header[header_size], bool debug, struct remote_handlers handlers, struct remote_exec_state *out_state);
__attribute__((warn_unused_result))
static int remote_exec_fd_elf(const char *sysroot, int fd, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, const char *exec_path, bool debug, struct remote_handlers handlers, struct remote_exec_state *out_state);

static size_t count_arg_bytes(const char *const *argv, size_t *out_total_bytes) {
	size_t argc = 0;
	if (argv) {
		while (argv[argc]) {
			if (out_total_bytes) {
				*out_total_bytes += fs_strlen(argv[argc]) + 1;
			}
			argc++;
		}
	}
	return argc;
}

int remote_exec_fd(const char *sysroot, int fd, const char *named_path, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, int depth, bool debug, struct remote_handlers handlers, struct remote_exec_state *out_state)
{
	char header[BINPRM_BUF_SIZE + 1];
	size_t header_size = fs_pread_all(fd, header, BINPRM_BUF_SIZE, 0);
	if ((int)header_size < 0) {
		fs_close(fd);
		ERROR("unable to read header", fs_strerror(header_size));
		return -ENOEXEC;
	}
	if (header_size < 4) {
		fs_close(fd);
		ERROR("header too small", header_size);
		return -ENOEXEC;
	}
	if (header[0] == '#' && header[1] == '!') {
		return remote_exec_fd_script(sysroot, fd, named_path, argv, envp, aux, comm, depth, header_size, header, debug, handlers, out_state);
	}
	if (header[0] == ELFMAG0 && header[1] == ELFMAG1 && header[2] == ELFMAG2 && header[3] == ELFMAG3) {
		return remote_exec_fd_elf(sysroot, fd, argv, envp, aux, comm, named_path, debug, handlers, out_state);
	}
	fs_close(fd);
	ERROR("not magic enough", named_path);
	return -ENOEXEC;
}

__attribute__((used)) __attribute__((visibility("hidden")))
void perform_analysis(struct program_state *analysis, const char *executable_path, int fd)
{
	// skip gconv. if something is using gconv, it can fail
	analysis->loader.loaded_gconv_libraries = true;
	// load the main executable
	struct loaded_binary *loaded;
	int result = load_binary_into_analysis(analysis, executable_path, executable_path, fd, NULL, &loaded);
	if (result != 0) {
		DIE("failed to load main binary", fs_strerror(result));
	}
	if (UNLIKELY(loaded->mode & S_ISUID)) {
		DIE("executable is setuid");
	}
	if (UNLIKELY(loaded->mode & S_ISGID) && loaded->gid != analysis->loader.gid) {
		DIE("executable is setgid");
	}

	// TODO: load LD_PRELOAD binaries

	// finish loading the main binary
	result = finish_loading_binary(analysis, loaded, EFFECT_AFTER_STARTUP | EFFECT_ENTER_CALLS, false);
	if (result != 0) {
		DIE("failed to finish loading main binary", fs_strerror(result));
	}
	analysis->main = (uintptr_t)loaded->info.entrypoint;

	LOG("base", (uintptr_t)loaded->info.base);
	LOG("entrypoint", temp_str(copy_address_description(&analysis->loader, loaded->info.entrypoint)));
	LOG("size", (uintptr_t)loaded->info.size);
	struct analysis_frame new_caller = { .address = loaded->info.base, .description = "entrypoint", .next = NULL, .current_state = empty_registers, .entry = loaded->info.base, .entry_state = &empty_registers, .token = { 0 } };
	struct registers registers = empty_registers;
	analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, loaded->info.entrypoint, &new_caller);

	// interpreter entrypoint
	struct loaded_binary *interpreter = analysis->loader.interpreter;
	if (interpreter != NULL) {
		LOG("assuming interpreter can run after startup");
		struct analysis_frame interpreter_caller = { .address = interpreter->info.base, .description = "interpreter", .next = NULL, .current_state = empty_registers, .entry = loaded->info.base, .entry_state = &empty_registers, .token = { 0 } };
		registers = empty_registers;
		analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, interpreter->info.entrypoint, &interpreter_caller);
	} else {
		LOG("no interpreter for this binary");
	}

	for (struct loaded_binary *binary = analysis->loader.binaries; binary != NULL; binary = binary->next) {
		ins_ptr libc_early_init = resolve_binary_loaded_symbol(&analysis->loader, binary, "__libc_early_init", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (libc_early_init != NULL) {
			registers = empty_registers;
			new_caller = (struct analysis_frame){ .address = binary->info.base, .description = "__libc_early_init", .next = NULL, .current_state = empty_registers, .entry = binary->info.base, .entry_state = &empty_registers, .token = { 0 } };
			analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, libc_early_init, &new_caller);
		}
		ins_ptr dl_runtime_resolve = resolve_binary_loaded_symbol(&analysis->loader, binary, "_dl_runtime_resolve", NULL, NORMAL_SYMBOL | LINKER_SYMBOL, NULL);
		if (dl_runtime_resolve != NULL) {
			registers = empty_registers;
			new_caller = (struct analysis_frame){ .address = binary->info.base, .description = "_dl_runtime_resolve", .next = NULL, .current_state = empty_registers, .entry = binary->info.base, .entry_state = &empty_registers, .token = { 0 } };
			analyze_function(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED | EFFECT_ENTER_CALLS, &registers, dl_runtime_resolve, &new_caller);
		}
	}

	LOG("finished initial pass, dequeuing instructions");
	ERROR_FLUSH();
	finish_analysis(analysis);
}

#ifndef __APPLE__
#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
#endif
__attribute__((noinline))
static void analyze_binary(struct program_state *analysis, const char *executable_path, int fd)
{
#ifdef MAP_STACK
	int stack_flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK;
#else
	int stack_flags = MAP_PRIVATE|MAP_ANONYMOUS;
#endif
	// allocate a temporary stack
	void *stack = fs_mmap(NULL, ALT_STACK_SIZE + STACK_GUARD_SIZE, PROT_READ|PROT_WRITE, stack_flags, -1, 0);
	if (fs_is_map_failed(stack)) {
		DIE("failed to allocate stack", fs_strerror((intptr_t)stack));
	}

	// apply the guard page
	intptr_t result = fs_mprotect(stack, STACK_GUARD_SIZE, PROT_NONE);
	if (result != 0) {
		DIE("failed to protect stack guard", fs_strerror(result));
	}
	CALL_ON_ALTERNATE_STACK_WITH_ARG(perform_analysis, analysis, executable_path, fd, (char *)stack + ALT_STACK_SIZE + STACK_GUARD_SIZE);
	// unmap the temporary stack
	fs_munmap(stack, ALT_STACK_SIZE + STACK_GUARD_SIZE);
}
#ifndef __APPLE__
#pragma GCC pop_options
#endif

static char *loader_address_formatter(const ins_ptr address, void *loader)
{
	return copy_address_description((const struct loader_context *)loader, address);
}

static bool find_remote_patch_target(const struct loader_context *loader, const ins_ptr target, const ins_ptr entry, struct instruction_range *out_result)
{
	struct instruction_range basic_block = (struct instruction_range){ .start = entry, .end = target };
	struct decoded_ins decoded_end;
	if (decode_ins(basic_block.end, &decoded_end)) {
		basic_block.end = next_ins(basic_block.end, &decoded_end);
	} else {
		return false;
	}
#ifdef PATCH_REQUIRES_MIGRATION
	if (decode_ins(basic_block.end, &decoded_end)) {
		basic_block.end = next_ins(basic_block.end, &decoded_end);
	}
	return find_patch_target(basic_block, target, PCREL_JUMP_SIZE, PCREL_JUMP_SIZE, loader_address_formatter, (void *)loader, out_result);
#else
	out_result->start = target;
	out_result->end = basic_block.end;
	return true;
#endif
}

static void ensure_all_syscalls_are_patchable(struct program_state *analysis)
{
	bool die = false;
	for (int i = 0; i < analysis->syscalls.count; i++) {
		if (remote_should_try_to_patch(&analysis->syscalls.list[i])) {
			struct instruction_range patch_target;
			if (!find_remote_patch_target(&analysis->loader, analysis->syscalls.list[i].ins, analysis->syscalls.list[i].entry, &patch_target)) {
				ERROR("instruction is not patchable", temp_str(copy_address_description(&analysis->loader, analysis->syscalls.list[i].ins)));
				ERROR("from entry", temp_str(copy_address_description(&analysis->loader, analysis->syscalls.list[i].entry)));
				die = true;
			} else {
				PATCH_LOG("patching from", temp_str(copy_address_description(&analysis->loader, patch_target.start)));
				PATCH_LOG("to", temp_str(copy_address_description(&analysis->loader, patch_target.end)));
				PATCH_LOG("for", temp_str(copy_address_description(&analysis->loader, analysis->syscalls.list[i].ins)));
			}
		}
	}
	if (die) {
		DIE("at least one instruction was not patchable");
	}
}

static inline bool addresses_are_within_s32(intptr_t addr1, intptr_t addr2)
{
	intptr_t delta = addr1 - addr2;
	return (delta < (intptr_t)0x70000000) && (delta > -(intptr_t)0x70000000);
}

static intptr_t alloc_remote_page_near_address(intptr_t address, size_t size, int prot)
{
	intptr_t attempt_low = address & -PAGE_SIZE;
	intptr_t attempt_high = attempt_low;
	size_t increment = PAGE_SIZE * 1024;
	int flags = MAP_PRIVATE|MAP_ANONYMOUS;
#ifdef MAP_JIT
	if ((prot & (PROT_WRITE|PROT_EXEC)) == (PROT_WRITE|PROT_EXEC)) {
		flags |= MAP_JIT;
	}
#endif
	for (;;) {
		attempt_low -= increment;
		intptr_t result = remote_mmap(attempt_low, size, prot, flags, -1, 0);
		if (!fs_is_map_failed((void *)result)) {
			if (addresses_are_within_s32(result, address)) {
				return result;
			}
			remote_munmap(result, size);
		}
		attempt_high += increment;
		result = remote_mmap(attempt_high, size, prot, flags, -1, 0);
		if (!fs_is_map_failed((void *)result)) {
			if (addresses_are_within_s32(result, address)) {
				return result;
			}
			remote_munmap(result, size);
		}
	}
}

struct remote_patch {
	uintptr_t address;
	uintptr_t trampoline;
	bool owns_trampoline;
};

static void init_remote_patches(struct remote_patches *patches)
{
	patches->list = NULL;
	patches->count = 0;
	patches->existing_trampoline = PAGE_SIZE-1;
}

static void free_remote_patches(struct remote_patches *patches, struct program_state *analysis)
{
	for (int i = 0; i < analysis->syscalls.count; i++) {
		if (patches->list[i].owns_trampoline) {
			remote_munmap(patches->list[i].trampoline, PAGE_SIZE);
		}
	}
	free(patches->list);
	patches->count = 0;
}

void remote_patch(struct remote_patches *patches, struct program_state *analysis, const ins_ptr addr, const ins_ptr entry, uintptr_t child_addr, struct patch_template template, uintptr_t remote_handler, size_t skip_len, uintptr_t data)
{
	PATCH_LOG("remotely patching", temp_str(copy_address_description(&analysis->loader, addr)));
	PATCH_LOG("with entry", temp_str(copy_address_description(&analysis->loader, entry)));
	// TODO: reprotect with correct protection
#if 0
	ERROR("mprotect", (uintptr_t)addr & -PAGE_SIZE);
	ERROR("mprotect", child_addr & -PAGE_SIZE);
	ERROR("size", PAGE_SIZE);
	ERROR("prot", PROT_READ | PROT_WRITE | PROT_EXEC);
	int protect_result = remote_mprotect(child_addr & -PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (protect_result < 0) {
		DIE("failed to remote mprotect", fs_strerror(protect_result));
		return protect_result;
	}
	char breakpoint = 0xcc;
	proxy_poke(child_addr, 1, &breakpoint);
#else
	struct instruction_range patch_target;
	if (!find_remote_patch_target(&analysis->loader, addr, entry, &patch_target)) {
		DIE("instruction is not patchable", temp_str(copy_address_description(&analysis->loader, addr)));
	}
	uintptr_t child_patch_start = translate_analysis_address_to_child(&analysis->loader, patch_target.start);
	uintptr_t child_patch_end = translate_analysis_address_to_child(&analysis->loader, patch_target.end);
	uintptr_t child_page_start = child_patch_start & -PAGE_SIZE;
	uintptr_t child_page_end = (child_patch_end + (PAGE_SIZE-1)) & -PAGE_SIZE;
#ifdef __APPLE__
	{
		void *copy = malloc(child_page_end - child_page_start);
		intptr_t result = proxy_peek(child_page_start, child_page_end - child_page_start, copy);
		if (result < 0) {
			DIE("failed reading copy", fs_strerror(result));
		}
		fs_memcpy(copy, (void *)child_page_start, child_page_end - child_page_start);
		fs_munmap((void *)child_page_start, child_page_end - child_page_start);
		intptr_t mmap_result = remote_mmap(child_page_start, child_page_end - child_page_start, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_JIT, -1, 0);
		if (mmap_result < 0) {
			DIE("failed to remote map_jit", fs_strerror(mmap_result));
		}
		pthread_jit_write_protect_np(false);
		result = proxy_poke(mmap_result, child_page_end - child_page_start, copy);
		if (result < 0) {
			DIE("failed writing copy", fs_strerror(result));
		}
		free(copy);
	}
#else
	int protect_result = remote_mprotect(child_page_start, child_page_end - child_page_start, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (protect_result < 0) {
		DIE("failed to remote mprotect", fs_strerror(protect_result));
	}
#endif
	// allocate a trampoline page
	uintptr_t trampoline;
	size_t bytes_remaining_in_existing = PAGE_SIZE - (patches->existing_trampoline & (PAGE_SIZE-1));
	size_t expected_size = (addr - patch_target.start) + ((uintptr_t)template.address - (uintptr_t)template.start) + 10 + ((uintptr_t)template.end - (uintptr_t)template.address) + 5;
	struct remote_patch patch;
	patch.address = child_addr;
	if (addresses_are_within_s32(patches->existing_trampoline, child_patch_start) && bytes_remaining_in_existing > expected_size) {
		trampoline = patches->existing_trampoline;
		patch.owns_trampoline = false;
	} else {
		trampoline = (uintptr_t)alloc_remote_page_near_address((intptr_t)child_patch_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
		patch.owns_trampoline = true;
	}
	patch.trampoline = trampoline;
	size_t patch_count = patches->count;
	patches->list = realloc(patches->list, (patch_count + 1) * sizeof(struct remote_patch));
	patches->list[patch_count] = patch;
	patches->count++;
	PATCH_LOG("target instruction is at", child_addr);
	PATCH_LOG("starting patch at", child_patch_start);
	PATCH_LOG("ending patch at", child_patch_end);
	PATCH_LOG("redirecting to trampoline at", trampoline);
	// prepare and poke the trampoline
	uint8_t trampoline_buf[PAGE_SIZE];
	size_t cur = 0;
	{
		// copy the prefix of the target instruction that is overwritten by the patch
#ifdef PATCH_REQUIRES_MIGRATION
		ssize_t delta = (uintptr_t)child_patch_start - (uintptr_t)trampoline;
		size_t head_size = addr - patch_target.start;
		if (head_size != 0) {
			head_size = migrate_instructions(&trampoline_buf[cur], patch_target.start, delta, head_size, loader_address_formatter, (void *)&analysis->loader);
			if (head_size == 0) {
				DIE("failed to migrate prefix");
			}
			cur += head_size;
		}
#endif
		// copy the prefix part of the trampoline
		size_t prefix_size = (uintptr_t)template.address - (uintptr_t)template.start - 2 * sizeof(uintptr_t);
		memcpy(&trampoline_buf[cur], template.start, prefix_size);
		cur += prefix_size;
		// move address of remote handler function into rcx
#if 1
		*(uintptr_t *)&trampoline_buf[cur] = data;
		cur += sizeof(uintptr_t);
		*(uintptr_t *)&trampoline_buf[cur] = remote_handler;
		cur += sizeof(uintptr_t);
#else
		trampoline_buf[cur++] = data;
		trampoline_buf[cur++] = data >> 8;
		trampoline_buf[cur++] = data >> 16;
		trampoline_buf[cur++] = data >> 24;
		trampoline_buf[cur++] = data >> 32;
		trampoline_buf[cur++] = data >> 40;
		trampoline_buf[cur++] = data >> 48;
		trampoline_buf[cur++] = data >> 56;
		trampoline_buf[cur++] = remote_handler;
		trampoline_buf[cur++] = remote_handler >> 8;
		trampoline_buf[cur++] = remote_handler >> 16;
		trampoline_buf[cur++] = remote_handler >> 24;
		trampoline_buf[cur++] = remote_handler >> 32;
		trampoline_buf[cur++] = remote_handler >> 40;
		trampoline_buf[cur++] = remote_handler >> 48;
		trampoline_buf[cur++] = remote_handler >> 56;
#endif
		// copy the suffix part of the trampoline
		memcpy(&trampoline_buf[cur], template.address, (uintptr_t)template.end - (uintptr_t)template.address);
		cur += (uintptr_t)template.end - (uintptr_t)template.address;
		// copy the suffix of the target instruction that is overwritten by the patch
		size_t tail_size = patch_target.end - (addr + skip_len);
		if (tail_size != 0) {
#ifdef PATCH_REQUIRES_MIGRATION
			delta = (uintptr_t)child_addr + skip_len - ((uintptr_t)trampoline + cur);
			tail_size = migrate_instructions(&trampoline_buf[cur], addr + skip_len, delta, tail_size, loader_address_formatter, (void *)&analysis->loader);
			if (tail_size == 0) {
				DIE("failed to migrate suffix");
			}
			cur += tail_size;
#else
			DIE("tail has size, but target doesn't support migration", tail_size);
#endif
		}
		// jump back to the resume point in the function
		int32_t resume_relative_offset = child_patch_end - (trampoline + cur /*+ PCREL_JUMP_SIZE*/);
		patch_write_pc_relative_jump((ins_ptr)&trampoline_buf[cur], resume_relative_offset);
		cur += PCREL_JUMP_SIZE;
	}
	intptr_t result = proxy_poke(trampoline, cur, trampoline_buf);
	if (result < 0) {
		DIE("failed writing trampoline", fs_strerror(result));
	}
	patches->existing_trampoline = trampoline + cur;
	// patch the original code to jump to the trampoline page
	int32_t detour_relative_offset = trampoline - (child_patch_start /*+ PCREL_JUMP_SIZE*/);
	uint8_t jump_buf[PCREL_JUMP_SIZE];
	patch_write_pc_relative_jump((ins_ptr)&jump_buf, detour_relative_offset);
	result = proxy_poke(child_patch_start, sizeof(jump_buf), jump_buf);
	if (result < 0) {
		DIE("failed writing detour jump", fs_strerror(result));
	}
#ifdef __APPLE__
	pthread_jit_write_protect_np(true);
#endif
#endif
}

static void patch_remote_syscalls(struct remote_patches *patches, struct program_state *analysis, struct remote_handlers *handlers)
{
	for (int i = 0; i < analysis->syscalls.count; i++) {
		if (remote_should_try_to_patch(&analysis->syscalls.list[i])) {
			const ins_ptr addr = analysis->syscalls.list[i].ins;
			uintptr_t child_addr = translate_analysis_address_to_child(&analysis->loader, addr);
			if (child_addr == 0 || child_addr == (uintptr_t)addr) {
				PATCH_LOG("missing child address", temp_str(copy_address_description(&analysis->loader, addr)));
			} else {
				bool found = false;
				for (size_t j = 0, count = patches->count; j < count; j++) {
					if (patches->list[i].address == child_addr) {
						found = true;
						break;
					}
				}
				if (!found) {
					bool is_clone = analysis->syscalls.list[i].nr == LINUX_SYS_clone;
					remote_patch(patches, analysis, addr, analysis->syscalls.list[i].entry, child_addr, PATCH_TEMPLATE(trampoline_call_handler), is_clone ? handlers->receive_clone_addr : handlers->receive_syscall_addr, is_clone ? 0 : (SYSCALL_INSTRUCTION_SIZE / sizeof(*addr)), 0);
				}
			}
		}
	}
}

#define STACK_SIZE (2 * 1024 * 1024)

static intptr_t prepare_and_send_program_stack(intptr_t stack, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, struct binary_info *main_info, struct binary_info *interpreter_info)
{
	size_t string_size = sizeof("x86_64") + 16;
	size_t argc = count_arg_bytes(argv, &string_size);
	size_t envc = count_arg_bytes(envp, &string_size);
	size_t header_size = sizeof(struct receive_start_args) + sizeof(argc) + (argc + 1 + envc + 1) * sizeof(const char *) + 20 * sizeof(ElfW(auxv_t));
#ifdef AT_MINSIGSTKSZ
	header_size += sizeof(ElfW(auxv_t));
#endif
	size_t dynv_size = ((string_size + header_size + (0xf + 8)) & ~0xf) - 8;
	intptr_t dynv_base = (stack + (STACK_SIZE - dynv_size - sizeof(uint32_t))) & ~0xf;
	char dynv_buf[dynv_size];
	int string_cur = header_size;
	size_t *argc_buf = (size_t *)&dynv_buf[0];
	*argc_buf++ = argc;
	intptr_t *argv_buf = (intptr_t *)argc_buf;
	for (size_t i = 0; i < argc; i++) {
		*argv_buf++ = dynv_base + string_cur;
		for (const char *arg = argv[i];;) {
			char c = *arg++;
			dynv_buf[string_cur++] = c;
			if (c == '\0') {
				break;
			}
		}
	}
	*argv_buf++ = 0;
	intptr_t *env_buf = argv_buf;
	for (size_t i = 0; i < envc; i++) {
		*env_buf++ = dynv_base + string_cur;
		for (const char *env = envp[i];;) {
			char c = *env++;
			dynv_buf[string_cur++] = c;
			if (c == '\0') {
				break;
			}
		}
	}
	*env_buf++ = 0;
	ElfW(auxv_t) *aux_buf = (ElfW(auxv_t) *)env_buf;
	if (aux == NULL) {
		aux_buf->a_type = AT_BASE;
		aux_buf->a_un.a_val = (intptr_t)(interpreter_info != NULL ? interpreter_info->base : main_info->base);
		aux_buf++;
		aux_buf->a_type = AT_PHDR;
		aux_buf->a_un.a_val = (intptr_t)main_info->program_header;
		aux_buf++;
		aux_buf->a_type = AT_PHENT;
		aux_buf->a_un.a_val = (intptr_t)main_info->header_entry_size;
		aux_buf++;
		aux_buf->a_type = AT_PHNUM;
		aux_buf->a_un.a_val = (intptr_t)main_info->header_entry_count;
		aux_buf++;
		aux_buf->a_type = AT_ENTRY;
		aux_buf->a_un.a_val = (intptr_t)main_info->entrypoint;
		aux_buf++;
		aux_buf->a_type = AT_EXECFN;
		aux_buf->a_un.a_val = dynv_base + string_cur;
		aux_buf++;
		aux_buf->a_type = AT_PLATFORM;
		aux_buf->a_un.a_val = dynv_base + string_cur;
		aux_buf++;
		aux_buf->a_type = AT_PAGESZ;
#if 1
		aux_buf->a_un.a_val = PAGE_SIZE;
#else
		aux_buf->a_un.a_val = 4096;
#endif
		aux_buf++;
		fs_memcpy(&dynv_buf[string_cur], ARCH_NAME, sizeof(ARCH_NAME));
		string_cur += sizeof(ARCH_NAME);
		aux_buf->a_type = AT_RANDOM;
		aux_buf->a_un.a_val = dynv_base + string_cur;
		aux_buf++;
		memset(&dynv_buf[string_cur], 0x66, 16);
		string_cur += 16;
		aux_buf->a_type = AT_NULL;
		aux_buf->a_un.a_val = 0;
		aux_buf++;
	} else {
		while (aux->a_type != AT_NULL) {
			aux_buf->a_type = aux->a_type;
			switch (aux->a_type) {
				case AT_BASE:
					aux_buf->a_un.a_val = (intptr_t)(interpreter_info != NULL ? interpreter_info->base : main_info->base);
					aux_buf++;
					break;
				case AT_PHDR:
					aux_buf->a_un.a_val = (intptr_t)main_info->program_header;
					aux_buf++;
					break;
				case AT_PHENT:
					aux_buf->a_un.a_val = (intptr_t)main_info->header_entry_size;
					aux_buf++;
					break;
				case AT_PHNUM:
					aux_buf->a_un.a_val = (intptr_t)main_info->header_entry_count;
					aux_buf++;
					break;
				case AT_ENTRY:
					aux_buf->a_un.a_val = (intptr_t)main_info->entrypoint;
					aux_buf++;
					break;
				case AT_EXECFN:
					aux_buf->a_un.a_val = dynv_base + string_cur;
					aux_buf++;
					break;
				case AT_CLKTCK:
				case AT_PAGESZ:
				case AT_FLAGS:
				case AT_UID:
				case AT_EUID:
				case AT_GID:
				case AT_EGID:
				case AT_SECURE:
				case AT_HWCAP:
#ifdef AT_MINSIGSTKSZ
				case AT_MINSIGSTKSZ:
#endif
#ifdef AT_HWCAP2
				case AT_HWCAP2:
#endif
					aux_buf->a_un.a_val = aux->a_un.a_val;
					aux_buf++;
					break;
				case AT_PLATFORM:
					aux_buf->a_un.a_val = dynv_base + string_cur;
					aux_buf++;
					fs_memcpy(&dynv_buf[string_cur], ARCH_NAME, sizeof(ARCH_NAME));
					string_cur += sizeof(ARCH_NAME);
					break;
				case AT_RANDOM:
					aux_buf->a_un.a_val = dynv_base + string_cur;
					aux_buf++;
					fs_memcpy(&dynv_buf[string_cur], (const char *)aux->a_un.a_val, 16);
					string_cur += 16;
					break;
				case AT_SYSINFO_EHDR:
					// TODO: system address page
					aux_buf->a_un.a_val = 0;
					aux_buf++;
					break;
				default:
					ERROR("unknown auxv type", (intptr_t)aux_buf->a_type);
					break;
			}
			++aux;
		}
		*aux_buf++ = *aux;
	}
	struct receive_start_args *args = (struct receive_start_args *)aux_buf;
	args->pc = interpreter_info != NULL ? interpreter_info->entrypoint : main_info->entrypoint;
	args->sp = dynv_base;
	args->arg1 = 0;
	args->arg2 = 0;
	args->arg3 = 0;
	intptr_t result = proxy_poke(dynv_base, dynv_size, dynv_buf);
	if (result < 0) {
		DIE("failed writing program stack", fs_strerror(result));
	}
	return dynv_base + ((intptr_t)args - (intptr_t)&dynv_buf[0]);
}

// remote_exec_fd_elf executes an elf binary from an open file
static int remote_exec_fd_elf(const char *sysroot, int fd, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, __attribute__((unused)) const char *comm, __attribute__((unused)) const char *exec_path, bool debug, struct remote_handlers handlers, struct remote_exec_state *out_state)
{
	// analyze the program
	struct program_state analysis = { 0 };
	analysis.loader.sysroot = sysroot;
	analysis.loader.ignore_dlopen = true;
	init_searched_instructions(&analysis.search);
	if (debug) {
		ERROR("analyzing program");
		ERROR_FLUSH();
	}
	analyze_binary(&analysis, exec_path, fd);
	if (debug) {
		ERROR("syscalls", temp_str(copy_used_syscalls(&analysis.loader, &analysis.syscalls, false, true, true)));
		ERROR_FLUSH();
	}
	if (debug) {
		ERROR("checking program for remote compatibility");
		ERROR_FLUSH();
	}
	// check that all libraries have a dynamic base address
	for (struct loaded_binary *binary = analysis.loader.binaries; binary != NULL; binary = binary->next) {
		if (binary->info.default_base != NULL) {
			ERROR("found library with a fixed base address", binary->path);
			return -ENOEXEC;
		}
	}
	// check if all instructions are patchable
	ensure_all_syscalls_are_patchable(&analysis);
	// load the main binary
	if (debug) {
		ERROR("remotely loading program", analysis.loader.main->path);
		ERROR_FLUSH();
	}
	struct binary_info main_info = { 0 };
	intptr_t result = remote_load_binary(fd, &main_info);
	if (result < 0) {
		ERROR("failed to load binary remotely", fs_strerror(result));
		return result;
	}
	if (debug) {
		ERROR("mapped main", exec_path);
		ERROR("at", (uintptr_t)main_info.base);
	}
	analysis.loader.main->child_base = (uintptr_t)main_info.base;
	// load the interpreter, if necessary
	struct binary_info interpreter_info = { 0 };
	bool has_interpreter = analysis.loader.main->info.interpreter != NULL;
	int interpreter_fd = -1;
	char sysroot_path_buf[PATH_MAX];
	if (has_interpreter) {
		if (debug) {
			ERROR("remotely loading interpreter", analysis.loader.main->info.interpreter);
			ERROR_FLUSH();
		}
		interpreter_fd = fs_openat(AT_FDCWD, apply_sysroot(sysroot, analysis.loader.main->info.interpreter, sysroot_path_buf), O_RDONLY | O_CLOEXEC, 0);
		if (UNLIKELY(interpreter_fd < 0)) {
			remote_unload_binary(&main_info);
			ERROR("unable to open ELF interpreter", fs_strerror(interpreter_fd));
			return interpreter_fd;
		}
		struct fs_stat stat;
		result = verify_allowed_to_exec(interpreter_fd, &stat, startup_euid, startup_egid);
		if (UNLIKELY(result < 0)) {
			remote_unload_binary(&main_info);
			fs_close(interpreter_fd);
			ERROR("ELF interpreter is not executable", fs_strerror(result));
			return result;
		}
		result = remote_load_binary(interpreter_fd, &interpreter_info);
		if (UNLIKELY(result != 0)) {
			remote_unload_binary(&main_info);
			DIE("unable to load ELF interpreter", fs_strerror(result));
			return result;
		}
		if (debug) {
			ERROR("mapped interpreter", analysis.loader.main->info.interpreter);
			ERROR("at", (uintptr_t)interpreter_info.base);
		}
		if (analysis.loader.interpreter != NULL) {
			analysis.loader.interpreter->child_base = (uintptr_t)interpreter_info.base;
		} else {
			DIE("could not find interpreter to set base");
		}
	}
	// create thread stack
	if (debug) {
		ERROR("creating remote stack");
		ERROR_FLUSH();
	}
	intptr_t stack = remote_mmap_stack(STACK_SIZE, PROT_READ | PROT_WRITE | (main_info.executable_stack == EXECUTABLE_STACK_REQUIRED ? PROT_EXEC : 0));
	if (fs_is_map_failed((void *)stack)) {
		if (has_interpreter) {
			remote_unload_binary(&interpreter_info);
			fs_close(interpreter_fd);
		}
		remote_unload_binary(&main_info);
		ERROR("creating stack failed", fs_strerror(stack));
		return stack;
	}
	LOG("stack", (uintptr_t)stack);

	// poke in breakpoints/patches
	if (debug) {
		ERROR("patching remote syscalls");
		ERROR_FLUSH();
	}
	struct remote_patches patches;
	init_remote_patches(&patches);
	patch_remote_syscalls(&patches, &analysis, &handlers);

	// prepare thread args and dynv
	intptr_t sp = prepare_and_send_program_stack(stack, argv, envp, aux, &main_info, has_interpreter ? &interpreter_info : NULL);

	// process syscalls until the remote exits
	*out_state = (struct remote_exec_state) {
		.handlers = handlers,
		.analysis = analysis,
		.patches = patches,
		.debug = debug,
		.has_interpreter = has_interpreter,
		.interpreter_info = interpreter_info,
		.interpreter_fd = interpreter_fd,
		.main_info = main_info,
		.stack = stack,
		.sp = sp,
		.stack_end = stack + STACK_SIZE,
		.comm = comm,
	};
	return 0;
}

void cleanup_remote_exec(struct remote_exec_state *remote) {
	// cleanup
	cleanup_searched_instructions(&remote->analysis.search);
	free_remote_patches(&remote->patches, &remote->analysis);
	remote_munmap(remote->stack, STACK_SIZE);
	if (remote->has_interpreter) {
		remote_unload_binary(&remote->interpreter_info);
		fs_close(remote->interpreter_fd);
	}
	remote_unload_binary(&remote->main_info);
}

void repatch_remote_syscalls(struct remote_exec_state *remote) {
	patch_remote_syscalls(&remote->patches, &remote->analysis, &remote->handlers);
}

static int remote_exec_fd_script(const char *sysroot, int fd, const char *named_path, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, int depth, size_t header_size, char header[header_size], bool debug, struct remote_handlers handlers, struct remote_exec_state *out_state)
{
	// Script binary format
	if (depth > 4) {
		fs_close(fd);
		return -ELOOP;
	}
	header[header_size] = '\0';
	// Parse #! line
	char *arg0 = &header[2];
	while (*arg0 == ' ' || *arg0 == '\t') {
		arg0++;
	}
	if (*arg0 == '\n' || *arg0 == '\0') {
		fs_close(fd);
		return -ENOEXEC;
	}
	char *arg1 = arg0;
	for (;; arg1++) {
		if (*arg1 == ' ' || *arg1 == '\0') {
			*arg1++ = '\0';
			for (char *terminator = arg1; ; ++terminator) {
				if (*terminator == '\0' || *terminator == '\n') {
					*terminator = '\0';
					break;
				}
			}
			break;
		}
		if (*arg1 == '\n' || *arg1 == '\0') {
			*arg1 = '\0';
			arg1 = NULL;
			break;
		}
	}
	char path_buf[PATH_MAX];
	if (named_path == NULL) {
		// Execed via execveat, readlink to get a path to pass to the interpreter
		int link_result = fs_fd_getpath(fd, path_buf);
		if (link_result < 0) {
			fs_close(fd);
			return link_result;
		}
		named_path = path_buf;
	}
	// Recreate arguments to pass to the interpreter script
	size_t argc = count_arg_bytes(argv, NULL);
	const char *new_argv[argc + 3];
	const char **dest_argv = new_argv;
	*dest_argv++ = arg0;
	if (arg1) {
		*dest_argv++ = arg1;
	}
	*dest_argv++ = named_path;
	for (size_t i = 1; i <= argc; i++) {
		*dest_argv++ = argv[i];
	}
	char sysrooted_buf[PATH_MAX];
	int interpreter_fd = fs_open(apply_sysroot(sysroot, arg0, sysrooted_buf), O_RDONLY, 0);
	if (interpreter_fd < 0) {
		fs_close(fd);
		return interpreter_fd;
	}
	struct fs_stat interpreter_stat;
	int result = verify_allowed_to_exec(interpreter_fd, &interpreter_stat, startup_euid, startup_egid);
	if (result < 0) {
		fs_close(fd);
		fs_close(interpreter_fd);
		return result;
	}
	result = remote_exec_fd(sysroot, interpreter_fd, new_argv[0], new_argv, envp, aux, comm, depth + 1, debug, handlers, out_state);
	fs_close(fd);
	return result;
}
