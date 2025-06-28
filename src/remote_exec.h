#ifndef REMOTE_EXEC_H

#include "callander.h"
#include "loader.h"
#include "patch.h"

struct remote_handlers
{
	intptr_t receive_clone_addr;
	intptr_t receive_syscall_addr;
};

struct remote_patch;

struct remote_patches
{
	struct remote_patch *list;
	size_t count;
	uintptr_t existing_trampoline;
};

struct remote_exec_state
{
	struct remote_handlers handlers;
	struct program_state analysis;
	struct remote_patches patches;
	bool has_interpreter;
	bool debug;
	int interpreter_fd;
	struct binary_info main_info;
	struct binary_info interpreter_info;
	intptr_t sp;
	intptr_t stack;
	intptr_t stack_end;
	const char *comm;
};

int remote_exec_fd(const char *sysroot, int fd, const char *named_path, const char *const *argv, const char *const *envp, const ElfW(auxv_t) * aux, const char *comm, int depth, bool debug, struct remote_handlers handlers,
                   struct remote_exec_state *out_state);
void cleanup_remote_exec(struct remote_exec_state *remote);

void repatch_remote_syscalls(struct remote_exec_state *remote);
void remote_patch(struct remote_patches *patches, struct program_state *analysis, const ins_ptr addr, const ins_ptr entry, uintptr_t child_addr, struct patch_template template, uintptr_t receive_syscall_remote, size_t skip_len,
                  uintptr_t data);

// defined elsewhere
void remote_munmap(intptr_t addr, size_t length);

__attribute__((warn_unused_result)) intptr_t remote_mmap(intptr_t addr, size_t length, int prot, int flags, int fd, off_t offset);

__attribute__((warn_unused_result)) intptr_t remote_mmap_stack(size_t size, int prot);

__attribute__((warn_unused_result)) int remote_mprotect(intptr_t addr, size_t length, int prot);

__attribute__((warn_unused_result)) int remote_load_binary(int fd, struct binary_info *out_info);

void remote_unload_binary(struct binary_info *info);

struct recorded_syscall;
bool remote_should_try_to_patch(const struct recorded_syscall *syscall);

#endif
