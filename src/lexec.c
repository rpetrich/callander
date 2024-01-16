#include "axon.h"
#include "exec.h"
#include "remote_exec.h"
#include "search.h"
#include "thandler.h"

#include <mach/mach.h>

AXON_RESTORE_ASM
FS_DEFINE_SYSCALL

extern char **environ;

__attribute__((used))
noreturn void receive_start(const struct receive_start_args *args)
{
	JUMP(args->pc, args->sp, args->arg1, args->arg2, args->arg3);
	__builtin_unreachable();
}

void receive_syscall(__attribute__((unused)) intptr_t data[7])
{
	DIE("received syscall", data[6]);
}

int main(__attribute__((unused)) int argc_, char *argv[])
{
#ifndef STANDALONE
	char **envp = (char **)environ;
#ifdef __APPLE__
	// TODO: use the euid/egid versions of these
	startup_euid = fs_getuid();
	startup_egid = fs_getgid();
#else
	startup_euid = getauxval(AT_EUID);
	startup_egid = getauxval(AT_EGID);
	// TODO
	// analysis.loader.vdso = getauxval(AT_SYSINFO_EHDR);
#endif
#else
	while (aux->a_type != AT_NULL) {
		switch (aux->a_type) {
			case AT_EUID:
				startup_euid = aux->a_un.a_val;
				break;
			case AT_EGID:
				startup_egid = aux->a_un.a_val;
				break;
			case AT_SYSINFO_EHDR:
				// TODO
				// analysis.loader.vdso = aux->a_un.a_val;
				break;
		}
		aux++;
	}
#endif

	// Find PATH
	const char *path = "/bin:/usr/bin";
	const char **current_envp = (const char **)envp;
	while (*current_envp != NULL) {
		if (fs_strncmp(*current_envp, "PATH=", 5) == 0) {
			const char *new_path = &(*current_envp)[5];
			if (*new_path != '\0') {
				path = new_path;
			}
		}
		++current_envp;
	}

	// find debug
	bool debug = false;
	if (argv[0] != NULL && argv[1] != NULL && fs_strcmp(argv[1], "--debug") == 0) {
		debug = true;
		argv++;
	}

	// find the main path
	const char *executable_path = argv[1];
	if (executable_path == NULL) {
		DIE("expected a program to run");
	}
	const char *sysroot = ".";
	char path_buf[PATH_MAX];
	executable_path = apply_sysroot(sysroot, executable_path, path_buf);

	// figure out comm
	const char *comm = executable_path;
	const char *comm_attempt = comm;
	while (*comm_attempt) {
		if (*comm_attempt == '/') {
			comm = comm_attempt + 1;
		}
		comm_attempt++;
	}

	// open the main executable
	int fd = open_executable_in_paths(executable_path, path, true, startup_euid, startup_egid);
	if (UNLIKELY(fd < 0)) {
		DIE("could not find main executable", argv[1]);
	}

	// execute it via the "remote_exec" facilities
	struct remote_exec_state remote;
	int result = remote_exec_fd(sysroot, fd, executable_path, (const char *const *)&argv[1], (const char *const *)envp, NULL, comm, 0, debug, (struct remote_handlers){ .receive_syscall_addr = (intptr_t)&receive_syscall, .receive_clone_addr = (intptr_t)&receive_syscall }, &remote);
	if (result < 0) {
		DIE("remote exec failed", fs_strerror(result));
	}

	CALL_ON_ALTERNATE_STACK_WITH_ARG(receive_start, remote.sp, 0, 0, remote.sp);

	cleanup_remote_exec(&remote);

	ERROR_FLUSH();

	return 0;
}


uid_t startup_euid;
gid_t startup_egid;

intptr_t proxy_peek(intptr_t addr, size_t size, void *out_buffer)
{
	memcpy(out_buffer, (const void *)addr, size);
	return 0;
}

intptr_t proxy_poke(intptr_t addr, size_t size, const void *buffer)
{
	fs_memcpy((void *)addr, buffer, size);
	return 0;
}

intptr_t remote_mmap(intptr_t addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	return (intptr_t)fs_mmap((void *)addr, length, prot, flags, fd, offset);
}

void remote_munmap(intptr_t addr, size_t length)
{
	fs_munmap((void *)addr, length);
}

int remote_mprotect(intptr_t addr, size_t length, int prot)
{
	return fs_mprotect((void *)addr, length, prot);
}

intptr_t remote_mmap_stack(size_t size, int prot)
{
	if (prot & PROT_EXEC) {
		DIE("exectable stacks are not allowed");
	}
	return (intptr_t)fs_mmap(NULL, size, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

int remote_load_binary(int fd, struct binary_info *out_info)
{
	return load_binary(fd, out_info, 0, false);
}

void remote_unload_binary(struct binary_info *info)
{
	unload_binary(info);
}
