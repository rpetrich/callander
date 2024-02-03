#include "axon.h"
#include "exec.h"
#include "ins.h"
#include "linux.h"
#include "patch.h"
#include "remote_exec.h"
#include "search.h"
#include "thandler.h"
#include "tls.h"

#include <mach/mach.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/attr.h>

AXON_RESTORE_ASM
FS_DEFINE_SYSCALL

extern char **environ;

// const char *syscall_names[] = {
// #define SYSCALL_DEF(name, ...) [LINUX_SYS_ ## name] = #name,
// #define SYSCALL_DEF_EMPTY()
// #include "syscall_defs.h"
// #undef SYSCALL_DEF
// #undef SYSCALL_DEF_EMPTY
// };


__attribute__((used))
noreturn void receive_start(const struct receive_start_args *args)
{
	JUMP(args->pc, args->sp, args->arg1, args->arg2, args->arg3);
	__builtin_unreachable();
}

static int translate_at_fd_to_darwin(int fd)
{
	if (fd == LINUX_AT_FDCWD) {
		return AT_FDCWD;
	}
	return fd;
}

static struct remote_exec_state remote;

static void discovered_library_mapping(int fd, void *address)
{
	char buf[PATH_MAX];
	int result = fs_fd_getpath(fd, buf);
	if (result >= 0) {
		ERROR("mapped library", &buf[0]);
		ERROR("at", (uintptr_t)address);
		for (struct loaded_binary *binary = remote.analysis.loader.binaries; binary != NULL; binary = binary->next) {
			if (fs_strcmp(binary->loaded_path, buf) == 0) {
				if (binary->child_base != 0) {
					return;
				}
				ERROR("known library loaded", binary->path);
				binary->child_base = (uintptr_t)address;
				repatch_remote_syscalls(&remote);
				ERROR_FLUSH();
				return;
			}
			ERROR("didn't match", binary->loaded_path);
		}
		DIE("could not find library");
	}
}

void receive_syscall(__attribute__((unused)) intptr_t data[7])
{
	ERROR("thread register in", (uintptr_t)read_thread_register());
	intptr_t nr = data[6];
	{
		const char *name = name_for_syscall(nr);
		size_t name_len = fs_strlen(name);
		size_t len = name_len + 3; // '(' ... ')' '\0'
		int argc = info_for_syscall(nr).attributes & SYSCALL_ARGC_MASK;
		for (int i = 0; i < argc; i++) {
			if (i != 0) {
				len += 2; // ", "
			}
			char buf[10];
			len += data[i] < PAGE_SIZE ? fs_utoa(data[i], buf) : fs_utoah(data[i], buf);
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
			cur += data[i] < PAGE_SIZE ? fs_utoa(data[i], cur) : fs_utoah(data[i], cur);
		}
		*cur++ = ')';
		*cur++ = '\0';
		ERROR("received syscall", buf);
		free(buf);
	}
	// const char *name = NULL;
	// if (data[6] < sizeof(syscall_names)/sizeof(syscall_names[0])) {
	// 	name = syscall_names[nr];
	// }
	// if (name != NULL) {
	// 	ERROR("received syscall", name);
	// } else {
	// 	ERROR("received syscall", nr);
	// }
	switch (data[6]) {
		case LINUX_SYS_brk:
			data[0] = -ENOSYS;
			break;
		case LINUX_SYS_uname: {
			struct linux_new_utsname *out_result = (struct linux_new_utsname *)data[0];
			*out_result = (struct linux_new_utsname){0};
			fs_strcpy(out_result->linux_sysname, "Linux");
			fs_strcpy(out_result->linux_nodename, "lexec");
			fs_strcpy(out_result->linux_release, "4.8.0-lexec");
			fs_strcpy(out_result->linux_version, "");
			fs_strcpy(out_result->linux_machine, ARCH_NAME);
			fs_strcpy(out_result->linux_domainname, "");
			data[0] = 0;
			break;
		}
		case LINUX_SYS_openat: {
			int flags = data[2];
			const char *path = (const char *)data[1];
			ERROR("path", path);
			data[0] = fs_openat(translate_at_fd_to_darwin(data[0]), path, flags, data[3]);
			break;
		}
		case LINUX_SYS_exit_group:
			fs_exit(data[0]);
			break;
		case LINUX_SYS_exit:
			fs_exitthread(data[0]);
			break;
		case LINUX_SYS_newfstatat: {
			int resolved_flags = 0;
			int flags = data[3];
			if (flags & LINUX_AT_SYMLINK_NOFOLLOW) {
				flags |= AT_SYMLINK_NOFOLLOW;
			}
			if (flags & LINUX_AT_EACCESS) {
				flags |= AT_EACCESS;
			}
			if (flags & LINUX_AT_REMOVEDIR) {
				flags |= AT_REMOVEDIR;
			}
			if (flags & LINUX_AT_SYMLINK_FOLLOW) {
				flags |= AT_SYMLINK_FOLLOW;
			}
			// if (flags & LINUX_AT_EMPTY_PATH) {
			// 	flags |= AT_EMPTY_PATH;
			// }
			// if (flags & LINUX_AT_RECURSIVE) {
			// 	flags |= AT_RECURSIVE;
			// }
			int fd = translate_at_fd_to_darwin(data[0]);
			const char *path = (const char *)data[1];
			ERROR("path", path ? path : "(null)");
			struct fs_stat stat;
			intptr_t result;
			if ((flags & LINUX_AT_EMPTY_PATH) && (path == NULL || *path == '\0')) {
				result = fs_fstat(fd, &stat);
			} else {
				result = FS_SYSCALL(SYS_fstatat64, fd, (intptr_t)path, (intptr_t)&stat, resolved_flags);
			}
			if (result >= 0) {
				struct linux_stat *out_stat = (struct linux_stat *)data[2];
				*out_stat = (struct linux_stat){0};
				out_stat->st_dev = stat.st_dev;
				out_stat->st_ino = stat.st_ino;
				out_stat->st_mode = stat.st_mode;
				out_stat->st_nlink = stat.st_nlink;
				out_stat->st_uid = stat.st_uid;
				out_stat->st_gid = stat.st_gid;
				out_stat->st_rdev = stat.st_rdev;
				out_stat->st_size = stat.st_size;
				out_stat->st_blocks = stat.st_blocks;
				out_stat->st_atime_sec = stat.st_atimespec.tv_sec;
				out_stat->st_atime_nsec = stat.st_atimespec.tv_nsec;
				out_stat->st_mtime_sec = stat.st_mtimespec.tv_sec;
				out_stat->st_mtime_nsec = stat.st_mtimespec.tv_nsec;
				out_stat->st_ctime_sec = stat.st_ctimespec.tv_sec;
				out_stat->st_ctime_nsec = stat.st_ctimespec.tv_nsec;
			}
			data[0] = result;
			break;
		}
		case LINUX_SYS_writev: {
			data[0] = fs_writev(data[0], (const struct iovec *)data[1], data[2]);
			break;
		}
		case LINUX_SYS_read: {
			data[0] = fs_read(data[0], (char *)data[1], data[2]);
			break;
		}
		case LINUX_SYS_close: {
			data[0] = fs_close(data[0]);
			break;
		}
		case LINUX_SYS_getcwd: {
			struct attrlist attr = {0};
			attr.bitmapcount = ATTR_BIT_MAP_COUNT;
			attr.commonattr = ATTR_CMN_FULLPATH;
			struct {
				uint32_t length;
				attrreference_t name;
				char buf[PATH_MAX];
			} temp;
			// intptr_t result = FS_SYSCALL(SYS_GETATTRLIST, (intptr_t)".", (intptr_t)&attr, (intptr_t)&temp, sizeof(temp) - PATH_MAX + data[1], 0);
			intptr_t result = getattrlist(".", &attr, &temp, sizeof(temp) - PATH_MAX + data[1], 0);
			if (result == 0) {
				fs_memcpy((char *)data[0], &temp.buf[0], temp.name.attr_length);
				result = temp.name.attr_length;
			}
			data[0] = result;
			break;
		}
		case LINUX_SYS_mmap: {
			int prot = data[2];
			int resolved_prot = 0;
			if (prot & LINUX_PROT_READ) {
				resolved_prot |= PROT_READ;
				ERROR("read");
			}
			if (prot & LINUX_PROT_WRITE) {
				resolved_prot |= PROT_WRITE;
				ERROR("write");
			}
			if (prot & LINUX_PROT_EXEC) {
				resolved_prot |= PROT_EXEC;
				ERROR("exec");
			}
			int flags = data[3];
			int resolved_flags;
			if (flags & LINUX_MAP_ANONYMOUS) {
				resolved_flags = MAP_ANONYMOUS;
				ERROR("anonymous");
			} else {
				resolved_flags = MAP_FILE;
				ERROR("file");
			}
			if (flags & LINUX_MAP_FIXED) {
				resolved_flags |= MAP_FIXED;
				ERROR("fixed");
			}
			if (flags & LINUX_MAP_PRIVATE) {
				resolved_flags |= MAP_PRIVATE;
				ERROR("private");
			}
			if (flags & LINUX_MAP_SHARED) {
				resolved_flags |= MAP_SHARED;
				ERROR("shared");
			}
			size_t size = data[1];
			if (resolved_prot & PROT_EXEC) {
				if ((flags & LINUX_MAP_ANONYMOUS) == 0) {
					char *buf = malloc(size);
					intptr_t read_result = fs_pread_all(data[4], buf, size, data[5]);
					if (read_result < 0) {
						data[0] = read_result;
						break;
					}
					void *result = fs_mmap((void *)data[0], (size + (PAGE_SIZE-1)) & ~(uint64_t)(PAGE_SIZE-1), PROT_READ|PROT_WRITE|PROT_EXEC, (resolved_flags & MAP_FIXED) | MAP_ANONYMOUS | MAP_JIT, -1, 0);
					if ((intptr_t)result > 0) {
						ERROR("result", (uintptr_t)result);
						ERROR("size", (intptr_t)size);
						ERROR_FLUSH();
						pthread_jit_write_protect_np(false);
						fs_memcpy(result, buf, size);
						pthread_jit_write_protect_np(true);
						discovered_library_mapping(data[4], result - data[5]);
					}
					free(buf);
					data[0] = (intptr_t)result;
					break;
				}
				resolved_flags |= MAP_JIT;
			}
			data[0] = (intptr_t)fs_mmap((void *)data[0], data[1], resolved_prot, resolved_flags, data[4], data[5]);
			break;
		}
		case LINUX_SYS_faccessat: {
			data[0] = fs_faccessat(translate_at_fd_to_darwin(data[0]), (const char *)data[1], data[3]);
			break;
		}
		case LINUX_SYS_set_tid_address: {
			data[0] = 0;
			break;
		}
		case LINUX_SYS_set_robust_list: {
			data[0] = 0;
			break;
		}
		case LINUX_SYS_rseq: {
			data[0] = 0;
			break;
		}
		default: {
			DIE("unknown syscall");
			break;
		}
	}
	ERROR("=", data[0]);
	ERROR_FLUSH();
	ERROR("thread register out", (uintptr_t)read_thread_register());
	ERROR_FLUSH();
	ERROR("thread register out", (uintptr_t)read_thread_register());
	ERROR_FLUSH();
}

static intptr_t tls_handler(uintptr_t *arguments, intptr_t original)
{
	DIE("tls handler");
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
	char sysroot_buf[PATH_MAX];
	int result = fs_getcwd(sysroot_buf, sizeof(sysroot_buf));
	if (result < 0) {
		DIE("could not read cwd", fs_strerror(result));
	}
	char path_buf[PATH_MAX];
	executable_path = apply_sysroot(sysroot_buf, executable_path, path_buf);

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
	result = remote_exec_fd(sysroot_buf, fd, executable_path, (const char *const *)&argv[1], (const char *const *)envp, NULL, comm, 0, debug, (struct remote_handlers){ .receive_syscall_addr = (intptr_t)&receive_syscall, .receive_clone_addr = (intptr_t)&receive_syscall }, &remote);
	if (result < 0) {
		DIE("remote exec failed", fs_strerror(result));
	}

	uintptr_t *tls_addresses = remote.analysis.search.tls_addresses.addresses;
	for (size_t i = 0, count = remote.analysis.search.tls_addresses.count; i < count; i++) {
		ins_ptr addr = (ins_ptr)tls_addresses[i];
		ERROR("tls", temp_str(copy_address_description(&remote.analysis.loader, addr)));
		uintptr_t child_addr = translate_analysis_address_to_child(&remote.analysis.loader, addr);
		if (child_addr != 0 && child_addr != (uintptr_t)addr) {
			enum patch_status status = patch_function(get_thread_storage(), (ins_ptr)child_addr, tls_handler, -1);
			if (status != PATCH_STATUS_INSTALLED_TRAMPOLINE) {
				DIE("failed to patch", temp_str(copy_address_description(&remote.analysis.loader, addr)));
			}
		}
	}

	ERROR_FLUSH();
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

__attribute__((noinline))
intptr_t remote_mmap_stack(size_t size, int prot)
{
	if (prot & PROT_EXEC) {
		DIE("exectable stacks are not allowed");
	}
	return (intptr_t)fs_mmap(NULL, size, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

int remote_load_binary(int fd, struct binary_info *out_info)
{
	int result = load_binary(fd, out_info, 0, false);
	if (result == 0) {
		char path[PATH_MAX];
		if (fs_fd_getpath(fd, path) < 0) {
			DIE("could not query path");
		}
		ERROR("loaded", &path[0]);
		ERROR("remotely at", (uintptr_t)out_info->base);
		ERROR_FLUSH();
	}
	return result;
}

void remote_unload_binary(struct binary_info *info)
{
	unload_binary(info);
}

bool remote_should_try_to_patch(const struct recorded_syscall *syscall)
{
	return syscall->ins != NULL;
}
