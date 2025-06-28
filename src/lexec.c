#define PATCH_EXPOSE_INTERNALS
#include "axon.h"
#include "exec.h"
#include "ins.h"
#include "linux.h"
#include "remote_exec.h"
#include "search.h"
#include "thandler.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/attr.h>
#include <sys/random.h>

AXON_RESTORE_ASM
FS_DEFINE_SYSCALL

extern char **environ;

__attribute__((used)) noreturn void receive_start(const struct receive_start_args *args)
{
	JUMP(args->pc, args->sp, args->arg1, args->arg2, args->arg3);
}

static int translate_at_fd_to_darwin(int fd)
{
	if (fd == LINUX_AT_FDCWD) {
		return AT_FDCWD;
	}
	return fd;
}

static struct remote_exec_state remote;

static void update_patches(void);

static void discovered_library_mapping(int fd, void *address)
{
	char buf[PATH_MAX];
	int result = fs_fd_getpath(fd, buf);
	if (result >= 0) {
		PATCH_LOG("mapped library", &buf[0]);
		PATCH_LOG("at", (uintptr_t)address);
		for (struct loaded_binary *binary = remote.analysis.loader.binaries; binary != NULL; binary = binary->next) {
			if (fs_strcmp(binary->loaded_path, buf) == 0) {
				if (binary->child_base != 0) {
					return;
				}
				PATCH_LOG("known library loaded", binary->path);
				binary->child_base = (uintptr_t)address;
				update_patches();
				ERROR_FLUSH();
				return;
			}
			PATCH_LOG("didn't match", binary->loaded_path);
		}
		DIE("could not find library", &buf[0]);
	}
}

void receive_syscall(__attribute__((unused)) intptr_t data[7])
{
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
		PATCH_LOG("received syscall", buf);
		free(buf);
	}
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
			PATCH_LOG("path", path);
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
			PATCH_LOG("path", path ? path : "(null)");
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
		case LINUX_SYS_statfs: {
			data[0] = -ENOSYS;
			break;
		}
		case LINUX_SYS_writev: {
			data[0] = fs_writev(data[0], (const struct iovec *)data[1], data[2]);
			break;
		}
		case LINUX_SYS_write: {
			data[0] = fs_write(data[0], (const char *)data[1], data[2]);
			break;
		}
		case LINUX_SYS_readv: {
			data[0] = fs_readv(data[0], (const struct iovec *)data[1], data[2]);
			break;
		}
		case LINUX_SYS_read: {
			data[0] = fs_read(data[0], (char *)data[1], data[2]);
			break;
		}
		case LINUX_SYS_close: {
			if (data[0] == 2) {
				ERROR_FLUSH();
			}
			data[0] = fs_close(data[0]);
			break;
		}
		case LINUX_SYS_getcwd: {
			struct attrlist attr = {0};
			attr.bitmapcount = ATTR_BIT_MAP_COUNT;
			attr.commonattr = ATTR_CMN_FULLPATH;
			struct
			{
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
			void *address = (void *)data[0];
			int prot = data[2];
			int resolved_prot = 0;
			if (prot & LINUX_PROT_READ) {
				resolved_prot |= PROT_READ;
				PATCH_LOG("read");
			}
			if (prot & LINUX_PROT_WRITE) {
				resolved_prot |= PROT_WRITE;
				PATCH_LOG("write");
			}
			if (prot & LINUX_PROT_EXEC) {
				resolved_prot |= PROT_EXEC;
				PATCH_LOG("exec");
			}
			int flags = data[3];
			int resolved_flags;
			if (flags & LINUX_MAP_ANONYMOUS) {
				resolved_flags = MAP_ANONYMOUS;
				PATCH_LOG("anonymous");
			} else {
				resolved_flags = MAP_FILE;
				PATCH_LOG("file");
			}
			if (flags & LINUX_MAP_FIXED) {
				resolved_flags |= MAP_FIXED;
				PATCH_LOG("fixed");
			}
			if (flags & LINUX_MAP_PRIVATE) {
				resolved_flags |= MAP_PRIVATE;
				PATCH_LOG("private");
			}
			if (flags & LINUX_MAP_SHARED) {
				resolved_flags |= MAP_SHARED;
				PATCH_LOG("shared");
			}
			size_t size = data[1];
			if (resolved_prot & PROT_EXEC) {
				if ((flags & LINUX_MAP_ANONYMOUS) == 0) {
					size_t rounded_size = (size + (PAGE_SIZE - 1)) & ~(uint64_t)(PAGE_SIZE - 1);
					void *result = fs_mmap(address, rounded_size, PROT_READ | PROT_EXEC, (resolved_flags & MAP_FIXED) | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
					if ((intptr_t)result >= 0) {
						mach_vm_address_t writable_addr = 0;
						vm_prot_t cur, max;
						kern_return_t ret = mach_vm_remap(mach_task_self(), &writable_addr, rounded_size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, mach_task_self(), (mach_vm_address_t)result, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
						if (ret != KERN_SUCCESS) {
							PATCH_LOG("mach_vm_remap failed", ret);
							data[0] = -EINVAL;
							break;
						}
						intptr_t mprotect_result = fs_mprotect((void *)writable_addr, rounded_size, PROT_READ | PROT_WRITE);
						if (mprotect_result < 0) {
							data[0] = mprotect_result;
							PATCH_LOG("mprotect failed");
							break;
						}
						intptr_t read_result = fs_pread_all(data[4], (void *)writable_addr, size, data[5]);
						if (read_result < 0) {
							data[0] = read_result;
							PATCH_LOG("read failed");
							break;
						}
						fs_munmap((void *)writable_addr, rounded_size);
						discovered_library_mapping(data[4], result - data[5]);
					}
					data[0] = (intptr_t)result;
					break;
				}
				resolved_flags |= MAP_JIT;
			}
			data[0] = (intptr_t)fs_mmap(address, size, resolved_prot, resolved_flags, data[4], data[5]);
			break;
		}
		case LINUX_SYS_munmap: {
			data[0] = (intptr_t)fs_munmap((void *)data[0], data[1]);
			break;
		}
		case LINUX_SYS_mprotect: {
			data[0] = fs_mprotect((void *)data[0], data[1], data[2]);
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
		case LINUX_SYS_prlimit64: {
			data[0] = -EINVAL;
			break;
		}
		case LINUX_SYS_execve: {
			ERROR_FLUSH();
			data[0] = fs_execve((const char *)data[0], (void *)data[1], (void *)data[2]);
			break;
		}
		case LINUX_SYS_getrandom: {
			data[0] = getentropy((void *)data[0], data[1]);
			break;
		}
		case LINUX_SYS_clock_gettime: {
			data[0] = clock_gettime(data[0], (void *)data[1]);
			break;
		}
		case LINUX_SYS_ioctl: {
			data[0] = -ENOSYS;
			break;
		}
		case LINUX_SYS_statx: {
			data[0] = -ENOSYS;
			break;
		}
		case LINUX_SYS_lgetxattr: {
			data[0] = -ENOTSUP;
			break;
		}
		case LINUX_SYS_getxattr: {
			data[0] = -ENOTSUP;
			break;
		}
		case LINUX_SYS_socket: {
			data[0] = -ENOSYS;
			break;
		}
		case LINUX_SYS_lseek: {
			data[0] = fs_lseek(data[0], data[1], data[2]);
			break;
		}
		default: {
			DIE("unknown syscall", name_for_syscall(nr));
			break;
		}
	}
	if (data[0] < 0) {
		PATCH_LOG("=", fs_strerror(data[0]));
		data[0] = -translate_errno_to_linux(-data[0]);
	}
	if (data[0] > (intptr_t)PAGE_SIZE) {
		PATCH_LOG("=", (uintptr_t)data[0]);
	} else {
		PATCH_LOG("=", data[0]);
	}
	ERROR_FLUSH();
}

#ifdef __aarch64__

static uintptr_t tls_value;

static void tls_handler(uintptr_t *arguments, intptr_t original)
{
	ins_ptr ins = (ins_ptr)original;
	PATCH_LOG("tls handler", temp_str(copy_address_description(&remote.analysis.loader, ins)));
	struct decoded_ins decoded;
	if (!decode_ins(ins, &decoded)) {
		DIE("could not decode instruction");
	}
	switch (decoded.decomposed.operation) {
		case ARM64_MRS: {
			PATCH_LOG("reading tls", tls_value);
			PATCH_LOG("into", get_register_name(decoded.decomposed.operands[0].reg[0]));
			arguments[decoded.decomposed.operands[0].reg[0] - REG_X0] = tls_value;
			break;
		}
		case ARM64_MSR: {
			uintptr_t new_value = arguments[decoded.decomposed.operands[1].reg[0] - REG_X0];
			PATCH_LOG("storing tls", new_value);
			PATCH_LOG("from", get_register_name(decoded.decomposed.operands[1].reg[0]));
			tls_value = new_value;
			break;
		}
		default:
			DIE("tls handler received non-tls instruction");
	}
	ERROR_FLUSH();
}
#endif

static void update_patches(void)
{
	repatch_remote_syscalls(&remote);
#ifdef __aarch64__
	uintptr_t *tls_addresses = remote.analysis.search.tls_addresses.addresses;
	for (size_t i = 0, count = remote.analysis.search.tls_addresses.count; i < count; i++) {
		ins_ptr addr = (ins_ptr)tls_addresses[i];
		if (addr == NULL) {
			continue;
		}
		struct decoded_ins decoded;
		if (!decode_ins(addr, &decoded)) {
			DIE("could not decode instruction");
		}
		switch (decoded.decomposed.operation) {
			case ARM64_MRS:
				if (decoded.decomposed.operands[1].sysreg != REG_TPIDR_EL0) {
					continue;
				}
				break;
			case ARM64_MSR:
				if (decoded.decomposed.operands[0].sysreg != REG_TPIDR_EL0) {
					continue;
				}
				break;
			default:
				continue;
		}
		uintptr_t child_addr = translate_analysis_address_to_child(&remote.analysis.loader, addr);
		if (child_addr != 0 && child_addr != (uintptr_t)addr) {
			PATCH_LOG("patching tls instruction", temp_str(copy_address_description(&remote.analysis.loader, addr)));
			remote_patch(&remote.patches, &remote.analysis, addr, addr, child_addr, PATCH_TEMPLATE(breakpoint_call_handler), (uintptr_t)&tls_handler, (SYSCALL_INSTRUCTION_SIZE / sizeof(*addr)), (uintptr_t)addr);
			tls_addresses[i] = 0;
		}
	}
#endif
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
	result = remote_exec_fd(sysroot_buf,
	                        fd,
	                        executable_path,
	                        (const char *const *)&argv[1],
	                        (const char *const *)envp,
	                        NULL,
	                        comm,
	                        0,
	                        debug,
	                        (struct remote_handlers){.receive_syscall_addr = (intptr_t)&receive_syscall, .receive_clone_addr = (intptr_t)&receive_syscall},
	                        &remote);
	if (result < 0) {
		DIE("remote exec failed", fs_strerror(result));
	}

	update_patches();

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

__attribute__((noinline)) intptr_t remote_mmap_stack(size_t size, int prot)
{
	if (prot & PROT_EXEC) {
		DIE("exectable stacks are not allowed");
	}
	return (intptr_t)fs_mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

int remote_load_binary(int fd, struct binary_info *out_info)
{
	int result = load_binary(fd, out_info, 0, false);
	if (result == 0) {
		char path[PATH_MAX];
		if (fs_fd_getpath(fd, path) < 0) {
			DIE("could not query path");
		}
		PATCH_LOG("loaded", &path[0]);
		PATCH_LOG("remotely at", (uintptr_t)out_info->base);
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

intptr_t handle_syscall(struct thread_storage *thread, intptr_t syscall, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6, ucontext_t *context)
{
	return -ENOSYS;
}
