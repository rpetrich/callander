#include "libcallander.h"

#include "callander.h"

#include "freestanding.h"
#include "axon.h"
#include "mapped.h"

#include <linux/seccomp.h>
#include <sys/prctl.h>

FS_DEFINE_SYSCALL

__attribute__((used)) __attribute__((visibility("hidden")))
void callander_perform_analysis(struct program_state *analysis, callander_main_function main, void *data)
{
	int fd = fs_open("/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		DIE("unable to open self maps", fs_strerror(fd));
	}

	struct maps_file_state file;
	init_maps_file_state(&file);

	intptr_t result;
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
			if (find_loaded_binary(&analysis->loader, mapping.path) == NULL) {
				int binary_fd = fs_open(mapping.path, O_RDONLY | O_CLOEXEC, 0);
				if (binary_fd < 0) {
					ERROR("error opening binary", mapping.path);
					DIE("error was", fs_strerror(binary_fd));
				}
				struct loaded_binary *binary;
				size_t path_len = fs_strlen(mapping.path);
				char *path = malloc(path_len + 1);
				fs_memcpy(path, mapping.path, path_len + 1);
				int result = load_binary_into_analysis(analysis, path, binary_fd, (const void *)((uintptr_t)mapping.start - mapping.offset), &binary);
				fs_close(binary_fd);
				if (result < 0) {
					DIE("error loading binary", fs_strerror(result));
				}
				if (binary->device != mapping.device || binary->inode != mapping.inode) {
					DIE("binary on disk does not match what is loaded in memory", mapping.path);
				}
			}
		}
	}
	fs_close(fd);

	// analyze the program
	record_syscall(analysis, SYS_clock_gettime, (struct analysis_frame){
		.current = { .address = NULL, .description = "vDSO", .next = NULL },
		.current_state = empty_registers,
		.entry = NULL,
		.entry_state = &empty_registers,
		.token = { 0 },
	}, EFFECT_AFTER_STARTUP);

	// analyze the main function
	struct analysis_frame new_caller = { .current = { .address = NULL, .description = "main", .next = NULL }, .current_state = empty_registers, .entry = NULL, .entry_state = &empty_registers, .token = { 0 } };
	set_register(&new_caller.current_state.registers[sysv_argument_abi_register_indexes[0]], (uintptr_t)data);
	analyze_instructions(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED, &new_caller.current_state, (ins_ptr)main, &new_caller, true);

	// analyze the return from exit
	new_caller.current.description = "exit";
	set_register(&new_caller.current_state.registers[REGISTER_RAX], (uintptr_t)SYS_exit_group);
	analyze_instructions(analysis, EFFECT_AFTER_STARTUP | EFFECT_PROCESSED, &new_caller.current_state, (ins_ptr)&fs_syscall, &new_caller, true);

	LOG("finished initial pass, dequeuing instructions");
	ERROR_FLUSH();
	finish_analysis(analysis);
}

#ifdef LOGGING
extern bool should_log;
#endif

#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
__attribute__((visibility("default")))
void callander_run(callander_main_function main, void *data)
{
	struct program_state analysis = { 0 };
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
	CALL_ON_ALTERNATE_STACK_WITH_ARG(callander_perform_analysis, &analysis, main, data, (char *)stack + ALT_STACK_SIZE + STACK_GUARD_SIZE);
	// unmap the temporary stack
	fs_munmap(stack, ALT_STACK_SIZE + STACK_GUARD_SIZE);

	cleanup_searched_instructions(&analysis.search);
	// patch in child base addresses, which doesn't really apply since there is no child
	for (struct loaded_binary *binary = analysis.loader.last; binary != NULL; binary = binary->previous) {
		binary->child_base = (uintptr_t)binary->info.base;
	}

	struct sock_fprog prog = generate_seccomp_program(&analysis.loader, &analysis.syscalls, 0, ~(uint32_t)0, NULL);
	free_loaded_binary(analysis.loader.binaries);
	ERROR_FLUSH();
	result = FS_SYSCALL(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, (intptr_t)&prog);
	if (result < 0) {
		DIE("failed to apply program", fs_strerror(result));
	}
	free(prog.filter);
	fs_exit(main(data));
}
#pragma GCC pop_options
