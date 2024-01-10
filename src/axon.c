#define _GNU_SOURCE
#include "axon.h"

#include "debugger.h"
#include "exec.h"
#include "fd_table.h"
#include "freestanding.h"
#include "handler.h"
#include "install.h"
#include "intercept.h"
#include "loader.h"
#include "patch.h"
#include "preload.h"
#include "proxy.h"
#include "search.h"
#include "seccomp.h"
#include "tracer.h"
#include "time.h"
#include "tls.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/prctl.h>
#ifdef __x86_64__
#include <asm/prctl.h>
#endif

AXON_BOOTSTRAP_ASM

typedef struct {
	uintptr_t interpreter_base;
	uintptr_t base_address;
	uintptr_t old_base_address;
	size_t self_size;
	size_t *sp;
#ifdef ENABLE_TRACER
	uint32_t traces;
#endif
	const char *comm;
	const char *exec_path;
	struct r_debug *debug;
	void (*debug_update)(void);
	bool patch_syscalls: 1;
	bool intercept: 1;
} bind_data;

static void bind_axon(const bind_data data);
static inline bool is_go_binary(int fd, const struct binary_info *info);

// release is called by the ELF entrypoint assembly stub when the main binary
// it's responsible for attaching the axon bootstraper into the fixed FD
// if missing or remapping the main binary to the fixed address if necessary
// before jumping to the bind stage
__attribute__((used))
noreturn void release(size_t *sp)
{
	bind_data data = {
		.interpreter_base = 0,
		.base_address = 0,
		.old_base_address = 0,
		.self_size = 0,
		.sp = sp,
		.comm = NULL,
		.exec_path = NULL,
#ifdef ENABLE_TRACER
		.traces = 0,
#endif
		.debug = NULL,
		.patch_syscalls = true,
		.intercept = true,
	};
	// Skip over arguments
	char **argv = (void *)(sp+1);
	char *arg0 = *argv;
	char *arg1 = argv[1];
	while (*argv != NULL) {
		++argv;
	}
	// Copy environment, skipping AXON_* variables
	char **envp = argv+1;
	char **envp_copy = envp;
	while (*envp != NULL) {
		if (fs_strncmp(*envp, AXON_ADDR, sizeof("AXON_") - 1) == 0) {
			if (fs_strncmp(*envp, AXON_ADDR, sizeof(AXON_ADDR) - 1) == 0) {
				char *address_str = &(*envp)[sizeof(AXON_ADDR) - 1];
				if (UNLIKELY(fs_scanu(address_str, &data.base_address) == NULL)) {
					DIE("failed to parse AXON_ADDR");
				}
				// Redact the AXON_ADDR environment variable, so that it's not
				// possible to predict the whitelisted syscall's address
				memset(address_str + 2, '0', fs_strlen(address_str + 2));
			} else if (fs_strncmp(*envp, AXON_COMM, sizeof(AXON_COMM) - 1) == 0) {
				data.comm = &(*envp)[sizeof(AXON_COMM) - 1];
			} else if (fs_strncmp(*envp, AXON_EXEC, sizeof(AXON_EXEC) - 1) == 0) {
				data.exec_path = &(*envp)[sizeof(AXON_EXEC) - 1];
#ifdef ENABLE_TRACER
			} else if (fs_strncmp(*envp, AXON_TRACER, sizeof(AXON_TRACER) - 1) == 0) {
				const char *tracer_str = &(*envp)[sizeof(AXON_TRACER) - 1];
				uintptr_t traces;
				if (UNLIKELY(fs_scanu(tracer_str, &traces) == NULL)) {
					DIE("failed to parse AXON_TELE");
				}
				data.traces = (uint32_t)traces;
				*envp_copy++ = *envp;
#endif
			} else if (fs_strncmp(*envp, "AXON_PATCH_SYSCALLS=false", sizeof("AXON_PATCH_SYSCALLS=false")) == 0) {
				data.patch_syscalls = false;
				*envp_copy++ = *envp;
			} else if (fs_strncmp(*envp, "AXON_INTERCEPT=false", sizeof("AXON_INTERCEPT=false")-1) == 0) {
				data.intercept = false;
			}
		} else {
			*envp_copy++ = *envp;
		}
		++envp;
	}
	*envp_copy = NULL;
	// Copy auxiliary variables, parsing AT_RANDOM and replacing AT_EXECFN
	ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(envp + 1);
	ElfW(auxv_t) *aux_copy = (ElfW(auxv_t) *)(envp_copy + 1);
	const uintptr_t *random = NULL;
	const char *self_path = NULL;
	while (aux->a_type != AT_NULL) {
		if (aux->a_type == AT_RANDOM) {
			random = (const uintptr_t *)aux->a_un.a_val;
		} else if (aux->a_type == AT_EXECFN) {
			self_path = (const char *)aux->a_un.a_val;
			aux->a_un.a_val = (intptr_t)arg0;
		} else if (aux->a_type == AT_PHDR) {
			data.old_base_address = (uintptr_t)aux->a_un.a_val & (uintptr_t)-PAGE_SIZE;
		} else if (aux->a_type == AT_BASE) {
			data.interpreter_base = (uintptr_t)aux->a_un.a_val & (uintptr_t)-PAGE_SIZE;
		}
		*aux_copy++ = *aux++;
	}
	*aux_copy = *aux;

	// relocate self asap
	uintptr_t old_base_address = data.interpreter_base != 0 ? data.interpreter_base : data.old_base_address;
	struct binary_info self_info;
	load_existing(&self_info, old_base_address);
	self_info.dynamic = _DYNAMIC;
	relocate_binary(&self_info);

	// Open the self fd in the special SELF_FD slot
	if (data.comm == NULL) {
		if (UNLIKELY(*sp <= 1 && data.interpreter_base == 0)) {
			DIE("a tiny intrusive tracer");
		}
		if (arg1 && fs_strcmp(arg1, "--install") == 0) {
			install();
			fs_exit(0);
		}
#ifdef ENABLE_TRACER
		install_tracer(&data.traces, argv+1);
#endif
		// Prefer /proc/self/exe, if it exists
		int self_fd;
		if (data.interpreter_base != 0) {
			struct binary_info main_info;
			load_existing(&main_info, data.old_base_address);
			self_fd = fs_openat(AT_FDCWD, main_info.interpreter, O_RDONLY, 0);
		} else {
			self_fd = fs_openat(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0);
			if (self_fd < 0) {
				if (UNLIKELY(self_path == NULL)) {
					DIE("unable to find axon path");
				}
				self_fd = fs_openat(AT_FDCWD, self_path, O_RDONLY, 0);
			}
		}
		if (UNLIKELY(self_fd < 0)) {
			DIE("unable to find open axon path");
		}
		int result = fs_dup2(self_fd, SELF_FD);
		if (UNLIKELY(result < 0)) {
			DIE("unable to assign axon to self fd");
		}
		result = fs_close(self_fd);
		if (UNLIKELY(result < 0)) {
			DIE("unable to close axon");
		}
	}

	// Decide the new base address
	if (data.base_address == 0) {
		if (random) {
			// Randomize the base address, if we don't have a proper one already
			// 28 is default value of /proc/sys/vm/mmap_rnd_bits
			// Maybe this should be dynamically loaded to match system ASLR config?
			data.base_address = (ELF_ET_DYN_BASE & -PAGE_SIZE) + ((*random & ((1UL << 28) - 1)) << PAGE_SHIFT);
		} else {
			// Otherwise use our current address as the base address
			data.base_address = old_base_address;
		}
	}
#ifdef STACK_PROTECTOR
	// Setup fs temporarily so that stack protection can work
	void **thread_data = fs_mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	*thread_data = thread_data;
	set_thread_register(thread_data);
#endif

	data.self_size = self_info.size;
	data.debug = &_r_debug;
	data.debug_update = &_dl_debug_state;

	// Remap self so that we can build our own ASLR
	if (data.base_address != old_base_address) {
		int result = load_binary(SELF_FD, &self_info, data.base_address, false);
		if (UNLIKELY(result != 0)) {
			DIE("unable to reload axon binary");
		}
		relocate_binary(&self_info);
	}
	__typeof__(&bind_axon) adjusted_bind = (void *)((uintptr_t)&bind_axon - old_base_address + self_info.base);
	adjusted_bind(data);
	__builtin_unreachable();
}

#if defined(__x86_64__)
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE (1 << 1)
#endif
#endif

// bind_axon is responsible for unmapping the original load address of
// axon, fixing up the auxiliary vector, mapping the target program and/or
// interpreter and jumping to the program/interpreter. If the seccomp filter
// hasn't been set yet it's responsible for attaching it
__attribute__((noinline))
noreturn static void bind_axon(bind_data data)
{
	struct binary_info self_info;
	load_existing(&self_info, data.base_address);

	debug_init(data.debug, data.debug_update);

	uintptr_t old_base_address = data.interpreter_base != 0 ? data.interpreter_base : data.old_base_address;
	if (old_base_address != data.base_address) {
		debug_register_relocated_self((void *)data.base_address);
	}
	// If gcov is enabled, run static initializers
#ifdef COVERAGE
	struct symbol_info symbols;
	if (parse_dynamic_symbols(&self_info, (void *)data.base_address, &symbols) != 0) {
		DIE("failed to parse main binary");
	}
	for (size_t i = 0; i < symbols.init_function_count; i++) {
		void (*fn)(int, char **, char **) = symbols.init_functions[i];
		// but not preload_main, since that will result in reexecing self
		if (fn != preload_main) {
			fn(0, NULL, NULL);
		}
	}
#endif
	// Set globals
#ifdef ENABLE_TRACER
	enabled_traces = data.traces;
#endif
	int stat_result = fs_fstat(SELF_FD, &axon_stat);
	if (UNLIKELY(stat_result != 0)) {
		DIE("unable to stat axon binary", fs_strerror(stat_result));
	}

#ifdef STACK_PROTECTOR
	// arch_prctl needs to be supported earlier, so assume multi-threaded all
	// the time
	became_multithreaded();
#endif

	// Set signal handlers
	int result = intercept_signals();
	if (UNLIKELY(result < 0)) {
		DIE("failed to intercept signals", fs_strerror(result));
	}

	// Unmap the old binary
	// if (old_base_address != data.base_address) {
	// 	result = fs_munmap((void *)old_base_address, data.self_size);
	// 	result = fs_mprotect((void *)old_base_address, data.self_size, PROT_READ);
	// 	if (UNLIKELY(result < 0)) {
	// 		DIE("failed to unmap self", -result);
	// 	}
	// }

	// Start pseudo-interpreter
	const char **argv = (void *)(data.sp+1);
	const char **current_argv = argv;
	while (*current_argv != NULL) {
		++current_argv;
	}
	const char **envp = current_argv+1;
	// Search useful environment variables
	const char *path = "/bin:/usr/bin";
	const char **current_envp = envp;
	intptr_t proxy_fd = -1;
	while (*current_envp != NULL) {
		if (fs_strncmp(*current_envp, "PATH=", 5) == 0) {
			const char *new_path = &(*current_envp)[5];
			if (*new_path != '\0') {
				path = new_path;
			}
		} else if (fs_strncmp(*current_envp, "PROXY_FD=", sizeof("PROXY_FD=")-1) == 0) {
			const char *proxy_fd_str = &(*current_envp)[sizeof("PROXY_FD=")-1];
			if (*fs_scans(proxy_fd_str, &proxy_fd) != '\0') {
				DIE("unexpected PROXY_FD", proxy_fd_str);
			}
		}
		++current_envp;
	}

	ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(current_envp + 1);
	ElfW(auxv_t) *vdso = NULL;
	while (aux->a_type != AT_NULL) {
		switch (aux->a_type) {
			case AT_PAGESZ:
				if (UNLIKELY(aux->a_un.a_val != PAGE_SIZE)) {
					DIE("unexpected page size", aux->a_un.a_val);
				}
				break;
			case AT_EUID:
				startup_euid = aux->a_un.a_val;
				break;
			case AT_EGID:
				startup_egid = aux->a_un.a_val;
				break;
			case AT_SYSINFO_EHDR:
				vdso = aux;
				break;
#if defined(__x86_64__)
			case AT_HWCAP2:
				if (aux->a_un.a_val & HWCAP2_FSGSBASE) {
					discovered_fsgsbase();
				}
				break;
#endif
		}
		++aux;
	}

	// Initialize the clock
	clock_load(vdso);

	// Setup seccomp and reexec if missing
#ifdef ENABLE_TRACER
	char filename[PATH_MAX+1];
#endif
	if (data.comm == NULL) {
		// Setup a seccomp policy so that syscalls will fault to userspace
		if (data.intercept) {
			result = apply_seccomp();
			if (UNLIKELY(result != 0)) {
				DIE("failed to apply seccomp filter", fs_strerror(result));
			}
#ifdef ENABLE_TRACER
			// Send initial working directory
			if (enabled_traces & TRACE_TYPE_UPDATE_WORKING_DIR) {
				int result = fs_getcwd(filename, PATH_MAX);
				if (UNLIKELY(result < 0)) {
					DIE("unable to read working directory", fs_strerror(result));
				}
				send_update_working_dir_event(get_thread_storage(), filename, result - 1);
			}
#endif
		}
		// Install the proxy page
		install_proxy(proxy_fd);
		if (data.intercept) {
			// Initialize the fd table
			initialize_fd_table();
		}
		// Find the executable to exec
		int fd = open_executable_in_paths(argv[data.interpreter_base == 0], path, true, startup_euid, startup_egid);
		if (UNLIKELY(fd < 0)) {
			DIE("could not find main executable", argv[1]);
		}
		if (data.intercept) {
			result = exec_fd(fd, NULL, argv + (data.interpreter_base == 0), envp, argv[1], 0);
		} else {
			char buf[PATH_MAX];
			intptr_t count = fs_readlink_fd(fd, buf, sizeof(buf)-1);
			if (count < 0) {
				DIE("unable to read exec path", fs_strerror(count));
			}
			buf[count] = '\0';
			result = fs_execve(buf, (char * const *)(argv + (data.interpreter_base == 0)), (char * const *)envp);
		}
		if (UNLIKELY(result < 0)) {
			DIE("unable to exec", fs_strerror(result));
		}
	}

	// Set comm so that pgrep, for example, will work
	int prctl_result = fs_prctl(PR_SET_NAME, (uintptr_t)data.comm, 0, 0, 0);
	if (prctl_result < 0) {
		DIE("failed to set name", fs_strerror(prctl_result));
	}

	// Map the main binary
	struct binary_info info = { 0 };
	result = load_binary(MAIN_FD, &info, 0, false);
	if (UNLIKELY(result != 0)) {
		DIE("unable to load main binary", fs_strerror(result));
	}

	// Try to set /proc/self/exe so that execs out of proc will work without
	// question, but don't exit if this fails since CAP_SYS_RESOURCE is often
	// unavailable
	result = fs_prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, MAIN_FD, 0, 0);

	// Initialize patching
	patch_init(data.patch_syscalls);

	// Patch the auxiliary vector in preparation for loading the new binary
	aux = (ElfW(auxv_t) *)(current_envp + 1);
	ElfW(auxv_t) *at_base = NULL;
	while (aux->a_type != AT_NULL) {
		switch (aux->a_type) {
			case AT_PHDR:
				aux->a_un.a_val = (intptr_t)info.program_header;
				break;
			case AT_PHENT:
				aux->a_un.a_val = (intptr_t)info.header_entry_size;
				break;
			case AT_PHNUM:
				aux->a_un.a_val = (intptr_t)info.header_entry_count;
				break;
			case AT_BASE:
				at_base = aux;
				break;
			case AT_ENTRY:
				aux->a_un.a_val = (intptr_t)info.entrypoint;
				break;
		}
		++aux;
	}

	// Update the link map for main
	debug_register(&info, argv[0]);

	// Setup fd remapping
	resurrect_fd_table();

	// Send exec trace
#ifdef ENABLE_TRACER
	if (enabled_traces & TRACE_TYPE_EXEC) {
		struct fs_stat main_stat;
		int result = fs_fstat(MAIN_FD, &main_stat);
		if (result < 0) {
			DIE("unable to fstat main binary", fs_strerror(result));
		}
		struct fs_stat path_stat;
		result = fs_stat(data.exec_path, &path_stat);
		if ((result == 0) && (main_stat.st_dev == path_stat.st_dev) && (main_stat.st_ino == path_stat.st_ino)) {
			// prefer arg 0 if it refers to the same binary as the one that's executing
			send_exec_event(get_thread_storage(), data.exec_path, fs_strlen(data.exec_path), argv, 0);
		} else {
			// otherwise readlink on the main binary
			result = fs_readlink_fd(MAIN_FD, filename, PATH_MAX);
			if (result < 0) {
				DIE("unable to read path of main binary", fs_strerror(result));
			}
			filename[result] = '\0';
			send_exec_event(get_thread_storage(), filename, result, argv, 0);
		}
	}

	// Send update credentials event
	if (enabled_traces & TRACE_TYPE_UPDATE_CREDENTIALS) {
		send_update_credentials_event(get_thread_storage(), startup_euid, startup_egid);
	}
#endif

	// Always use alternate stacks if a go program
#ifdef USE_PROGRAM_STACK
	if (is_go_binary(MAIN_FD, &info)) {
		use_alternate_stacks();
	}
#endif

	// Map the interpreter if need be
	struct binary_info interpreter_info = { 0 };
	if (info.interpreter) {
		// search for our ELF interpreter override, but fallback to normal
		// interpreter
		char buf[PATH_MAX];
		size_t interp_len = fs_strlen(info.interpreter);
		fs_memcpy(buf, info.interpreter, interp_len);
		fs_memcpy(&buf[interp_len], ".axon", sizeof(".axon"));
		int interpreter_fd = fs_openat(AT_FDCWD, buf, O_RDONLY | O_CLOEXEC, 0);
		if (interpreter_fd < 0) {
			interpreter_fd = fs_openat(AT_FDCWD, info.interpreter, O_RDONLY | O_CLOEXEC, 0);
		}
		if (UNLIKELY(interpreter_fd < 0)) {
			DIE("unable to open ELF interpreter", fs_strerror(interpreter_fd));
		}
		struct fs_stat stat;
		int err = verify_allowed_to_exec(interpreter_fd, &stat, startup_euid, startup_egid);
		if (UNLIKELY(err < 0)) {
			// fs_close(interpreter_fd);
			DIE("ELF interpreter is not executable");
		}
		result = load_binary(interpreter_fd, &interpreter_info, 0, false);
		if (UNLIKELY(result != 0)) {
			DIE("unable to load ELF interpreter", -result);
		}
#ifdef USE_PROGRAM_STACK
		// Always alternate stacks if a go program
		if (is_go_binary(interpreter_fd, &interpreter_info)) {
			use_alternate_stacks();
		}
#endif
		// Update the link map for the interpreter and observe its link maps
		debug_register(&interpreter_info, info.interpreter);
		debug_intercept_system_loader(interpreter_fd, &interpreter_info);
		fs_close(interpreter_fd);
	} else {
		debug_intercept_system_loader(MAIN_FD, &info);
	}

	if (at_base) {
		at_base->a_un.a_val = (intptr_t)(info.interpreter != NULL ? interpreter_info.base : info.base);
	}

	data.debug_update();
	// Make stack executable/non-executable as required
	if (info.executable_stack != EXECUTABLE_STACK_DEFAULT) {
		int mprotect_result = fs_mprotect((void *)((intptr_t)data.sp & -PAGE_SIZE), PAGE_SIZE, info.executable_stack == EXECUTABLE_STACK_REQUIRED ? (PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN) : (PROT_READ | PROT_WRITE | PROT_GROWSDOWN));
		if (mprotect_result < 0) {
			DIE("unable to update stack execute permission");
		}
	}

	// Jump to the actual program if statically linked or the interpreter if dynamically linked
	void *pc = info.interpreter != NULL ? interpreter_info.entrypoint : info.entrypoint;
	JUMP(pc, data.sp, 0, 0, 0);
	__builtin_unreachable();
}

static inline bool is_go_binary(int fd, const struct binary_info *info) {
	struct section_info section;
	int err = load_section_info(fd, info, &section);
	if (err != 0) {
		return false;
	}
	bool result = find_section(info, &section, ".note.go.buildid") != NULL;
	free_section_info(&section);
	return result;
}
