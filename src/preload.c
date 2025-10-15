#include "axon.h"
#include "freestanding.h"

#include <limits.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#ifdef ENABLE_TRACER

#define LD_PRELOAD "LD_PRELOAD="
#define BIN_AXON "/bin/axon"
#define SLASH_AXON "/axon"

__attribute__((weak)) const char *gnu_get_libc_version(void);

__attribute__((weak)) extern char **environ;

__attribute__((weak)) extern unsigned long getauxval(unsigned long type);

__attribute__((warn_unused_result)) static bool axon_path_from_preload(const char *preload, char buf[PATH_MAX])
{
	do {
		const char *next = fs_strpbrk(preload, ": ");
		if ((next - preload) >= ((int)sizeof(SLASH_AXON) - 1) && fs_strncmp(next - (sizeof(SLASH_AXON) - 1), SLASH_AXON, sizeof(SLASH_AXON) - 1) == 0) {
			fs_memcpy(buf, preload, next - preload);
			buf[next - preload] = '\0';
			return true;
		}
		preload = next;
	} while (*preload);
	return false;
}

// preload_main is setup as a static initializer
// it will reexec the program under axon when run from a ld.so's LD_PRELOAD
// or, in the future, setup uprobes
__attribute__((constructor)) void preload_main(int argc, char **argv, char **env)
{
	// Re-execs the program through axon
	if (&gnu_get_libc_version == NULL) {
		// Don't have glibc, have to use environ and heuristics to find argc/argv
		if (UNLIKELY(&environ == NULL)) {
			DIE("missing environ");
		}
		env = environ;
		argc = 0;
		argv = NULL;
	}
	// Parse environment
	const char *ld_preload = NULL;
	char **env_search = env;
	while (*env_search) {
		if (fs_strncmp(*env_search, AXON_TELE, sizeof(AXON_TELE) - 1) == 0) {
			// Found axon; this is where "uprobes" would be set, if they were supported yet
			return;
		} else if (fs_strncmp(*env_search, LD_PRELOAD, sizeof(LD_PRELOAD) - 1) == 0) {
			ld_preload = *env_search + sizeof(LD_PRELOAD) - 1;
		}
		++env_search;
	}
	// Find axon path
	const char *axon_path;
	char buf[PAGE_SIZE + 1];
	if (ld_preload && axon_path_from_preload(ld_preload, buf)) {
		axon_path = buf;
	} else {
		axon_path = NULL;
		// Try parsing /etc/ld.so.preload to find a path to axon
		int global_preload = fs_open("/etc/ld.so.preload", O_RDONLY | O_CLOEXEC, 0);
		if (global_preload >= 0) {
			int result = fs_read(global_preload, buf, PAGE_SIZE);
			if (result >= 0) {
				buf[result] = '\0';
				char *preload = buf;
				do {
					// Whitespace separated
					char *next = (char *)fs_strpbrk(preload, " \r\n\t");
					if ((next - preload) >= ((int)sizeof(SLASH_AXON) - 1) && fs_strncmp(next - (sizeof(SLASH_AXON) - 1), SLASH_AXON, sizeof(SLASH_AXON) - 1) == 0) {
						*next = '\0';
						axon_path = preload;
						break;
					}
					preload = next;
				} while (*preload);
			}
		}
		// Fallback to /bin/axon, where it's expected to be installed in container
		if (axon_path == NULL) {
			axon_path = BIN_AXON;
		}
	}
	// Find exec function
	if (UNLIKELY(&getauxval == NULL)) {
		DIE("missing auxv");
	}
	char *execfn = (char *)getauxval(AT_EXECFN);
	if (UNLIKELY(execfn == NULL)) {
		DIE("missing execfn");
	}
	if (!argv) {
		// Don't have argv, find it experimentally from environ
		if (UNLIKELY(!env[0] || !env[1])) {
			DIE("insufficient environ to extract args");
		}
		if (UNLIKELY((env[0] + fs_strlen(env[0]) + 1 != env[1]) || (env_search[-1] + fs_strlen(env_search[-1]) + 1 != execfn))) {
			DIE("environ modified between exec and program start");
		}
		uintptr_t *arg_search = (uintptr_t *)(env - 2);
		while (*arg_search & ~(uintptr_t)0x1ffff) { // Maximum of 128k arguments
			--arg_search;
		}
		argc = arg_search[0];
		argv = (char **)&arg_search[1];
	}
	char *newargv[argc + 2];
	newargv[0] = (char *)axon_path;
	newargv[1] = execfn;
	for (int i = 1; i < argc; i++) {
		newargv[i + 1] = argv[i];
	}
	newargv[argc + 1] = NULL;
	int exec_result = fs_execve(axon_path, newargv, env);
	DIE("unable to reexec axon: ", -exec_result);
}
#endif
