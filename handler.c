#define _GNU_SOURCE
#include "handler.h"

#include "coverage.h"
#include "defaultlibs.h"
#include "exec.h"
#include "fd_table.h"
#include "fork.h"
#include "axon.h"
#include "intercept.h"
#include "loader.h"
#include "paths.h"
#include "proxy.h"
#include "remote.h"
#include "sockets.h"
#include "target.h"
#include "telemetry.h"
#include "tls.h"

#include <arpa/inet.h>
#include <asm/prctl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <termios.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

#ifndef NS_GET_USERNS
#define NSIO    0xb7
#define NS_GET_USERNS   _IO(NSIO, 0x1)
#define NS_GET_PARENT   _IO(NSIO, 0x2)
#endif

__attribute__((always_inline))
static inline int translate_openat(int dirfd, const char *path, int flags, mode_t mode)
{
#ifdef __NR_open
	if (LIKELY(dirfd == AT_FDCWD) || (path != NULL && path[0] == '/')) {
		return fs_open(path, flags, mode);
	}
#endif
	return fs_openat(dirfd, path, flags, mode);
}

// wrapped_openat handles open syscalls
__attribute__((warn_unused_result))
static int wrapped_openat(struct thread_storage *thread, int dirfd, const char *path, int flags, mode_t mode)
{
	bool send_create;
	int fd;
	if (UNLIKELY(flags & O_CREAT) && UNLIKELY(enabled_telemetry & TELEMETRY_TYPE_CREATE)) {
		fd = translate_openat(dirfd, path, flags & ~O_CREAT, mode);
		send_create = fd == -ENOENT;
		if (send_create) {
			fd = translate_openat(dirfd, path, flags, mode);
		}
	} else {
		fd = translate_openat(dirfd, path, flags, mode);
		send_create = false;
	}
	if (fd >= 0) {
		struct attempt_cleanup_state state;
		attempt_push_close(thread, &state, fd);
		// fixup /proc/self/exe
		if (special_path_type(path) == SPECIAL_PATH_TYPE_EXE) {
			struct fs_stat stat;
			int stat_result = fs_fstat(fd, &stat);
			if (stat_result < 0) {
				attempt_pop_close(&state);
				return stat_result;
			}
			if (is_axon(&stat)) {
				attempt_pop_close(&state);
				fd = fixup_exe_open(dirfd, path, flags);
				if (fd < 0) {
					return fd;
				}
				attempt_push_close(thread, &state, fd);
			}
		}
		uint32_t mask = (flags & (O_RDONLY | O_RDWR | O_WRONLY)) != O_RDONLY ? TELEMETRY_TYPE_OPEN_FOR_MODIFY : TELEMETRY_TYPE_OPEN_READ_ONLY;
		if (send_create) {
			mask |= TELEMETRY_TYPE_CREATE;
		}
		if (enabled_telemetry & (mask | TELEMETRY_TYPE_PTRACE)) {
			// read file path, since it's required for enabled telemetry types
			char filename[PATH_MAX+1];
			int result = fs_readlink_fd(fd, filename, sizeof(filename)-1);
			if (result <= 0) {
				attempt_pop_close(&state);
				return result;
			}
			filename[result] = '\0';
			if (send_create) {
				send_create_event(thread, filename, result - 1, mode);
			}
			if ((flags & (O_RDONLY | O_RDWR | O_WRONLY)) != O_RDONLY) {
				if (enabled_telemetry & TELEMETRY_TYPE_OPEN_FOR_MODIFY) {
					send_open_for_modify_event(thread, filename, result - 1, flags, (flags & O_CREAT) ? mode : 0);
				}
			} else {
				if (enabled_telemetry & TELEMETRY_TYPE_OPEN_READ_ONLY) {
					send_open_read_only_event(thread, filename, result - 1, flags);
				}
			}
			if (special_path_type(filename) == SPECIAL_PATH_TYPE_MEM) {
				struct fs_stat stat;
				int stat_result = fs_fstat(fd, &stat);
				if (stat_result < 0) {
					attempt_pop_close(&state);
					return stat_result;
				}
				if (stat.st_size == 0) {
					struct fs_statfs fs;
					int result = fs_fstatfs(fd, &fs);
					if (result < 0) {
						attempt_pop_close(&state);
						return result;
					}
					if (fs.f_type == 0x9fa0) { // procfs
						// todo extract pid
						send_mm_access_fs_event(thread, 0, flags | 0x8); // PTRACE_MODE_FSCREDS
					}
				}
			}
		}
		attempt_pop_and_skip_cleanup(&state);
	}
	return fd;
}

__attribute__((warn_unused_result))
static int wrapped_readlinkat(struct thread_storage *thread, int dirfd, const char *path, char *buf, size_t bufsiz)
{
	if (special_path_type(path) != SPECIAL_PATH_TYPE_EXE) {
		return fs_readlinkat(dirfd, path, buf, bufsiz);
	}
	// readlinkat does NOT support AT_EMPTY_PATH
	int fd = fs_openat(dirfd, path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		return fd;
	}
	struct attempt_cleanup_state state;
	attempt_push_close(thread, &state, fd);
	struct fs_stat stat;
	int result = fs_fstat(fd, &stat);
	if (result >= 0) {
		if (is_axon(&stat)) {
			attempt_pop_close(&state);
			fd = fixup_exe_open(dirfd, path, O_RDONLY | O_CLOEXEC);
			if (fd < 0) {
				return fd;
			}
			attempt_push_close(thread, &state, fd);
		}
		result = fs_readlink_fd(fd, buf, bufsiz);
	}
	attempt_pop_close(&state);
	return result;
}

static int resolve_path_operation(struct thread_storage *thread, int dirfd, const char *path, char buffer[PATH_MAX], const char **out_filename, int *out_length)
{
	if (path == NULL) {
		return -EFAULT;
	}
	// resolve parent directory path expression
	const char *filename = fs_strrchr(path, '/');
	if (filename == NULL) {
		// filename without relative or absolute path
		filename = path;
		buffer[0] = '.';
		buffer[1] = '\0';
	} else if (filename == path) {
		// filename in /
		buffer[0] = '/';
		buffer[1] = '\0';
	} else {
		// regular full or regular path with more than one component
		fs_memcpy(buffer, path, filename - path);
		buffer[filename - path] = '\0';
		filename++;
	}
	// open parent directory
	int new_dirfd = fs_openat(dirfd, buffer, O_DIRECTORY | O_CLOEXEC, 0);
	if (new_dirfd < 0) {
		return new_dirfd;
	}
	struct attempt_cleanup_state state;
	attempt_push_close(thread, &state, new_dirfd);
	// readlink on the parent directory to get fully resolved path
	int dir_length = fs_readlink_fd(new_dirfd, buffer, PATH_MAX);
	if (dir_length < 0) {
		attempt_pop_close(&state);
		return dir_length;
	}
	// prepare the full path
	if (dir_length == 1) {
		// directory is /, avoid two slashes
		dir_length = 0;
	}
	buffer[dir_length] = '/';
	size_t filename_length = fs_strlen(filename);
	fs_memcpy(&buffer[dir_length + 1], filename, filename_length + 1);
	*out_filename = &buffer[dir_length + 1];
	*out_length = dir_length + filename_length + 1;
	attempt_pop_and_skip_cleanup(&state);
	return new_dirfd;
}

__attribute__((warn_unused_result))
static int wrapped_unlinkat(struct thread_storage *thread, int dirfd, const char *path, int flags)
{
	if (enabled_telemetry & TELEMETRY_TYPE_DELETE) {
		// resolve path
		char buffer[PATH_MAX];
		int length;
		dirfd = resolve_path_operation(thread, dirfd, path, buffer, &path, &length);
		if (dirfd < 0) {
			return dirfd;
		}
		// perform unlink
		int result = fs_unlinkat(dirfd, path, flags);
		fs_close(dirfd);
		// send event
		if (result == 0) {
			send_delete_event(thread, buffer, length);
		}
		return result;
	}
	return fs_unlinkat(dirfd, path, flags);
}

__attribute__((warn_unused_result))
static int wrapped_renameat(struct thread_storage *thread, int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags)
{
	if (enabled_telemetry & TELEMETRY_TYPE_RENAME) {
		// resolve old path
		char old_buffer[PATH_MAX];
		int old_length;
		old_dirfd = resolve_path_operation(thread, old_dirfd, old_path, old_buffer, &old_path, &old_length);
		if (old_dirfd < 0) {
			return old_dirfd;
		}
		struct attempt_cleanup_state state;
		attempt_push_close(thread, &state, old_dirfd);
		// resolve new path
		char new_buffer[PATH_MAX];
		int new_length;
		new_dirfd = resolve_path_operation(thread, new_dirfd, new_path, new_buffer, &new_path, &new_length);
		if (new_dirfd < 0) {
			attempt_pop_close(&state);
			return new_dirfd;
		}
		// perform rename
		int result;
		if (flags == 0) {
			result = fs_renameat(old_dirfd, old_path, new_dirfd, new_path);
		} else {
			result = fs_renameat2(old_dirfd, old_path, new_dirfd, new_path, flags);
		}
		fs_close(new_dirfd);
		attempt_pop_close(&state);
		// send event
		if (result == 0) {
			send_rename_event(thread, old_buffer, old_length, new_buffer, new_length);
			if (flags & RENAME_EXCHANGE) {
				// not strictly correct, but the protocol doesn't have enough fidelity to represent
				send_rename_event(thread, new_buffer, new_length, old_buffer, old_length);
			}
		}
		return result;
	}
	if (flags == 0) {
		return fs_renameat(old_dirfd, old_path, new_dirfd, new_path);
	}
	return fs_renameat2(old_dirfd, old_path, new_dirfd, new_path, flags);
}

__attribute__((warn_unused_result))
static int wrapped_linkat(struct thread_storage *thread, int old_dirfd, const char *old_path, int new_dirfd, const char *new_path, int flags)
{
	if (enabled_telemetry & TELEMETRY_TYPE_HARDLINK) {
		// resolve old path
		char old_buffer[PATH_MAX];
		int old_length;
		old_dirfd = resolve_path_operation(thread, old_dirfd, old_path, old_buffer, &old_path, &old_length);
		if (old_dirfd < 0) {
			return old_dirfd;
		}
		struct attempt_cleanup_state state;
		attempt_push_close(thread, &state, old_dirfd);
		// resolve new path
		char new_buffer[PATH_MAX];
		int new_length;
		new_dirfd = resolve_path_operation(thread, new_dirfd, new_path, new_buffer, &new_path, &new_length);
		if (new_dirfd < 0) {
			attempt_pop_close(&state);
			return new_dirfd;
		}
		// perform link
		int result = fs_linkat(old_dirfd, old_path, new_dirfd, new_path, flags);
		fs_close(new_dirfd);
		attempt_pop_close(&state);
		// send event
		if (result == 0) {
			send_hardlink_event(thread, old_buffer, old_length, new_buffer, new_length);
		}
		return result;
	}
	return fs_linkat(old_dirfd, old_path, new_dirfd, new_path, flags);
}

__attribute__((warn_unused_result))
static int wrapped_symlinkat(struct thread_storage *thread, const char *old_path, int new_dirfd, const char *new_path)
{
	if (enabled_telemetry & TELEMETRY_TYPE_SYMLINK) {
		// resolve path
		char buffer[PATH_MAX];
		int length;
		new_dirfd = resolve_path_operation(thread, new_dirfd, new_path, buffer, &new_path, &length);
		if (new_dirfd < 0) {
			return new_dirfd;
		}
		// perform symlink
		int result = fs_symlinkat(old_path, new_dirfd, new_path);
		fs_close(new_dirfd);
		// send event
		if (result == 0) {
			send_symlink_event(thread, old_path, fs_strlen(old_path), buffer, length);
		}
		return result;
	}
	return fs_symlinkat(old_path, new_dirfd, new_path);
}

__attribute__((warn_unused_result))
static int wrapped_chmodat(struct thread_storage *thread, int dirfd, const char *path, mode_t mode)
{
	int fd;
	if ((path != NULL && path[0] == '/') || dirfd == AT_FDCWD) {
		fd = fs_open(path, O_RDONLY | O_CLOEXEC, 0);
	} else {
		fd = fs_openat(dirfd, path, O_RDONLY | O_CLOEXEC, 0);
	}
	if (fd < 0) {
		return fd;
	}
	char filename[PATH_MAX];
	int filename_len = fs_readlink_fd(fd, filename, sizeof(filename));
	if (filename_len <= 0) {
		fs_close(fd);
		return filename_len;
	}
	int result = fs_fchmod(fd, mode);
	fs_close(fd);
	if (enabled_telemetry & TELEMETRY_TYPE_CHMOD) {
		send_chmod_event(thread, filename, filename_len, mode);
	}
	if (result == 0) {
		if (enabled_telemetry & TELEMETRY_TYPE_ATTRIBUTE_CHANGE) {
			send_attribute_change_event(thread, filename, filename_len);
		}
	}
	return result;
}

__attribute__((warn_unused_result))
static int wrapped_chownat(struct thread_storage *thread, int dirfd, const char *path, uid_t uid, gid_t gid, int flags)
{
	if (flags & AT_SYMLINK_NOFOLLOW) {
		// resolve path
		char buffer[PATH_MAX];
		int length;
		dirfd = resolve_path_operation(thread, dirfd, path, buffer, &path, &length);
		if (dirfd < 0) {
			return dirfd;
		}
		// chown the path
		int result = fs_fchownat(dirfd, path, uid, gid, flags);
		fs_close(dirfd);
		if (result == 0) {
			send_attribute_change_event(thread, buffer, length);
		}
	}
	// open the file
	int fd;
	if ((path != NULL && path[0] == '/') || dirfd == AT_FDCWD) {
		fd = fs_open(path, O_RDONLY | O_CLOEXEC, 0);
	} else {
		fd = fs_openat(dirfd, path, O_RDONLY | O_CLOEXEC, 0);
	}
	// read the path
	char filename[PATH_MAX];
	int filename_len = fs_readlink_fd(fd, filename, PATH_MAX);
	if (filename_len <= 0) {
		fs_close(fd);
		return filename_len;
	}
	// chown the file
	int result = fs_fchown(fd, uid, gid);
	fs_close(fd);
	if (result == 0) {
		send_attribute_change_event(thread, filename, filename_len);
	}
	return result;
}

static void working_dir_changed(struct thread_storage *thread)
{
	if (enabled_telemetry & TELEMETRY_TYPE_UPDATE_WORKING_DIR) {
		char path[PATH_MAX];
		intptr_t result = fs_getcwd(path, sizeof(path));
		if (result > 0) {
			send_update_working_dir_event(thread, path, result - 1);
		}
	}
}

static bool decode_sockaddr(struct telemetry_sockaddr *out, const union copied_sockaddr *data, size_t size) {
	switch ((out->sa_family = data->addr.sa_family)) {
		case AF_INET: {
			out->sin_port = data->in.sin_port;
			out->sin_addr = data->in.sin_addr.s_addr;
			out->sin6_port = 0;
			out->sin6_addr.high = 0;
			out->sin6_addr.low = 0;
			return true;
		}
		case AF_INET6: {
			out->sin_port = 0;
			out->sin_addr = 0;
			out->sin6_port = data->in6.sin6_port;
			const uint64_t *sin6_addr = (const uint64_t *)&data->in6.sin6_addr;
			out->sin6_addr.high = sin6_addr[0];
			out->sin6_addr.low = sin6_addr[1];
			return true;
		}
		case AF_UNIX: {
			memcpy(&out->sun_path, &data->un.sun_path, size-(sizeof(sa_family_t)));
			return true;
		}
		default: {
			return false;
		}
	}
}

static int assemble_remote_path(int real_fd, const char *path, char buf[PATH_MAX], const char **out_path)
{
	if (path == NULL || *path == '\0' || (path[0] == '.' && path[1] == '\0')) {
		int count = remote_readlink_fd(real_fd, buf, PATH_MAX);
		if (count < 0) {
			return count;
		}
		if (count >= PATH_MAX) {
			return -ENAMETOOLONG;
		}
		buf[count] = '\0';
		*out_path = buf;
		return 0;
	}
	if (path[0] == '/') {
		*out_path = path;
		return 0;
	}
	int count = remote_readlink_fd(real_fd, buf, PATH_MAX);
	if (count < 0) {
		return count;
	}
	if (count >= PATH_MAX - 2) {
		return -ENAMETOOLONG;
	}
	if (count && buf[count - 1] != '/') {
		buf[count] = '/';
		count++;
	}
	size_t len = fs_strlen(path);
	if (count + len + 1 > PATH_MAX) {
		return -ENAMETOOLONG;
	}
	fs_memcpy(&buf[count], path, len + 1);
	*out_path = buf;
	return 0;
}

static int become_remote_socket(int fd, int domain, int *out_real_fd)
{
	if (lookup_real_fd(fd, out_real_fd)) {
		return 0;
	}
	// int domain;
	// size_t size = sizeof(domain);
	// int result = fs_getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &size);
	// if (result < 0) {
	// 	return result;
	// }
	int type;
	size_t size = sizeof(type);
	int result = fs_getsockopt(*out_real_fd, SOL_SOCKET, SO_TYPE, &type, &size);
	if (result < 0) {
		return result;
	}
	int protocol;
	size = sizeof(protocol);
	result = fs_getsockopt(*out_real_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &size);
	if (result < 0) {
		return result;
	}
	int real_fd = remote_socket(domain, type | SOCK_CLOEXEC, protocol);
	if (real_fd < 0) {
		return real_fd;
	}
	result = become_remote_fd(fd, real_fd);
	if (result < 0) {
		remote_close(real_fd);
		return result;
	}
	*out_real_fd = real_fd;
	return 0;
}

static int become_local_socket(int fd, int *out_real_fd)
{
	if (!lookup_real_fd(fd, out_real_fd)) {
		return 0;
	}
	int domain;
	socklen_t optlen = sizeof(domain);
	int result = remote_getsockopt(*out_real_fd, SOL_SOCKET, SO_DOMAIN, &domain, &optlen);
	if (result < 0) {
		return result;
	}
	int type;
	optlen = sizeof(type);
	result = remote_getsockopt(*out_real_fd, SOL_SOCKET, SO_TYPE, &type, &optlen);
	if (result < 0) {
		return result;
	}
	int protocol;
	optlen = sizeof(protocol);
	result = remote_getsockopt(*out_real_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen);
	if (result < 0) {
		return result;
	}
	int temp_fd = install_local_fd(FS_SYSCALL(__NR_socket, domain, type | SOCK_CLOEXEC, protocol), O_CLOEXEC);
	if (temp_fd < 0) {
		return temp_fd;
	}
	// TODO: preserve O_CLOEXEC status
	result = perform_dup3(temp_fd, fd, O_CLOEXEC);
	perform_close(temp_fd);
	if (lookup_real_fd(fd, out_real_fd)) {
		DIE("expected fd to be local", fd);
	}
	return 0;
}

static void unmap_and_exit_thread(void *arg1, void *arg2)
{
	atomic_intptr_t *thread_id = clear_thread_storage();
	fs_munmap(arg1, (size_t)arg2);
	atomic_store_explicit(thread_id, 0, memory_order_release);
	fs_exitthread(0);
	__builtin_unreachable();
}

// handle_syscall handles a trapped syscall, potentially emulating or blocking as necessary
intptr_t handle_syscall(struct thread_storage *thread, intptr_t syscall, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6, ucontext_t *context)
{
	switch (syscall) {
		case __NR_arch_prctl: {
			switch (arg1) {
#if defined(__x86_64__)
				case ARCH_SET_FS: {
					int result = FS_SYSCALL(syscall, arg1, arg2);
					became_multithreaded();
					return result;
				}
#endif
			}
			break;
		}
#ifdef __NR_creat
		case __NR_creat: {
			const char *path = (const char *)arg1;
			mode_t mode = arg2;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return install_remote_fd(remote_openat(real.fd, real.path, O_CREAT|O_WRONLY|O_TRUNC, mode), 0);
			}
			if (real.fd != AT_FDCWD) {
				return install_local_fd(FS_SYSCALL(__NR_openat, real.fd, (intptr_t)real.path, O_CREAT|O_WRONLY|O_TRUNC, mode), 0);
			}
			return install_local_fd(FS_SYSCALL(syscall, (intptr_t)real.path, mode), 0);
		}
#endif
#ifdef __NR_open
		case __NR_open: {
			const char *path = (const char *)arg1;
			int flags = arg2;
			int mode = arg3;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return install_remote_fd(remote_openat(real.fd, real.path, flags, mode), flags);
			}
			return install_local_fd(wrapped_openat(thread, real.fd, real.path, flags, mode), flags);
		}
#endif
		case __NR_openat: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			int flags = arg3;
			int mode = arg4;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return install_remote_fd(remote_openat(real.fd, real.path, flags, mode), flags);
			}
			return install_local_fd(wrapped_openat(thread, real.fd, real.path, flags, mode), flags);
		}
#ifdef __NR_openat2
		case __NR_openat2: {
			// TODO: handle openat2
			return -ENOSYS;
		}
#endif
		case __NR_close: {
			return perform_close(arg1);
		}
		case __NR_execve: {
			const char *path = (const char *)arg1;
			const char *const *argv = (const char *const *)arg2;
			const char *const *envp = (const char *const *)arg3;
			return wrapped_execveat(thread, AT_FDCWD, path, argv, envp, 0);
		}
		case __NR_execveat: {
			int dirfd = arg1;
			if (dirfd != AT_FDCWD) {
				return -ENOEXEC;
			}
			const char *path = (const char *)arg2;
			const char *const *argv = (const char *const *)arg3;
			const char *const *envp = (const char *const *)arg4;
			int flags = arg5;
			return wrapped_execveat(thread, dirfd, path, argv, envp, flags);
		}
		case __NR_stat: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return remote_newfstatat(real.fd, real.path, (struct fs_stat *)arg2, 0);
			}
			if (real.fd != AT_FDCWD) {
				return FS_SYSCALL(__NR_newfstatat, real.fd, (intptr_t)real.path, arg2, 0);
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2);
		}
		case __NR_fstat: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return remote_fstat(real_fd, (struct fs_stat *)arg2);
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_lstat: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return remote_newfstatat(real.fd, real.path, (struct fs_stat *)arg2, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT);
			}
			if (real.fd != AT_FDCWD) {
				return FS_SYSCALL(__NR_newfstatat, real.fd, (intptr_t)real.path, arg2, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT);
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2);
		}
		case __NR_newfstatat: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return remote_newfstatat(real.fd, real.path, (struct fs_stat *)arg3, arg4);
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3, arg4);
		}
		case __NR_statx: {
			// TODO: handle statx
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3, arg4, arg5);
		}
		case __NR_poll: {
			struct pollfd *fds = (struct pollfd *)arg1;
			nfds_t nfds = arg2;
			int timeout = arg3;
			if (nfds == 0) {
				return FS_SYSCALL(syscall, arg1, arg2, arg3);
			}
			struct attempt_cleanup_state state;
			struct pollfd *real_fds = malloc(sizeof(struct pollfd) * nfds);
			attempt_push_free(thread, &state, real_fds);
			bool has_local = false;
			bool has_remote = false;
			for (nfds_t i = 0; i < nfds; i++) {
				if (lookup_real_fd(fds[i].fd, &real_fds[i].fd)) {
					if (has_local) {
						// cannot poll on both local and remote file descriptors
						attempt_pop_free(&state);
						return -EINVAL;
					}
					has_remote = true;
				} else {
					if (has_remote) {
						// cannot poll on both local and remote file descriptors
						attempt_pop_free(&state);
						return -EINVAL;
					}
					has_local = true;
				}
				real_fds[i].events = fds[i].events;
				real_fds[i].revents = fds[i].revents;
			}
			int result;
			if (has_remote) {
				result = remote_poll(real_fds, nfds, timeout);
			} else {
				result = FS_SYSCALL(syscall, (intptr_t)&real_fds[0], nfds, timeout);
			}
			attempt_pop_free(&state);
			return result;
		}
		case __NR_lseek: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return remote_lseek(real_fd, arg2, arg3);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_mmap: {
			// TODO: need to update seccomp policy to trap to userspace
			void *addr = (void *)arg1;
			size_t len = arg2;
			int prot = arg3;
			int flags = arg4;
			int fd = arg5;
			off_t off = arg6;
			int real_fd;
			if ((flags & MAP_ANONYMOUS) == 0) {
				if (lookup_real_fd(fd, &real_fd)) {
					if ((flags & (MAP_PRIVATE | MAP_SHARED | MAP_SHARED_VALIDATE)) != MAP_PRIVATE) {
						return -EINVAL;
					}
					void *result = fs_mmap(addr, len, PROT_READ | PROT_WRITE, flags | MAP_ANONYMOUS, -1, 0);
					if (!fs_is_map_failed(result)) {
						intptr_t read_result = remote_pread(real_fd, result, len, off);
						if (read_result < 0) {
							fs_munmap(result, len);
							return read_result;
						}
						if (prot != (PROT_READ | PROT_WRITE)) {
							int prot_result = fs_mprotect(result, len, prot);
							if (prot_result < 0) {
								fs_munmap(result, len);
								return prot_result;
							}
						}
					}
					return (intptr_t)result;
				}
			} else {
				real_fd = -1;
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, real_fd, arg6);
		}
		case __NR_pread64: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return remote_pread(real_fd, (char *)arg2, arg3, arg4);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
		case __NR_pwrite64: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return remote_pwrite(real_fd, (const char *)arg2, arg3, arg4);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
		case __NR_access: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return remote_faccessat(real.fd, real.path, arg2, 0);
			}
			if (real.fd != AT_FDCWD) {
				return FS_SYSCALL(__NR_faccessat, real.fd, (intptr_t)real.path, arg2, 0);
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2);
		}
		case __NR_faccessat: {
			int fd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(fd, path, &real)) {
				return remote_faccessat(real.fd, real.path, arg3, arg4);
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3, arg4);
		}
		case __NR_pipe: {
			int result = FS_SYSCALL(syscall, arg1);
			if (arg1 != 0 && result == 0) {
				int *fds = (int *)arg1;
				fds[0] = install_local_fd(fds[0], 0);
				fds[1] = install_local_fd(fds[1], 0);
			}
			return result;
		}
#ifdef __NR_chmod
		case __NR_chmod: {
			const char *path = (const char *)arg1;
			mode_t mode = arg2;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return PROXY_CALL(__NR_fchmodat, proxy_value(real.fd), proxy_string(real.path), proxy_value(mode), proxy_value(0));
			}
			if (enabled_telemetry & (TELEMETRY_TYPE_ATTRIBUTE_CHANGE | TELEMETRY_TYPE_CHMOD)) {
				return wrapped_chmodat(thread, AT_FDCWD, path, mode);
			}
			if (real.fd != AT_FDCWD) {
				return FS_SYSCALL(__NR_fchmodat, real.fd, (intptr_t)real.path, arg2, 0);
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2);
		}
#endif
#ifdef __NR_pipe2
		case __NR_pipe2: {
			int result = FS_SYSCALL(syscall, arg1, arg2);
			if (arg1 != 0 && result == 0) {
				int *fds = (int *)arg1;
				fds[0] = install_local_fd(fds[0], arg2);
				fds[1] = install_local_fd(fds[1], arg2);
			}
			return result;
		}
#endif
		case __NR_fchmod: {
			int fd = arg1;
			mode_t mode = arg2;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_fchmod, proxy_value(real_fd), proxy_value(mode));
			}
			if (enabled_telemetry & (TELEMETRY_TYPE_ATTRIBUTE_CHANGE | TELEMETRY_TYPE_CHMOD)) {
				return wrapped_chmodat(thread, real_fd, NULL, mode);
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
#ifdef __NR_chown
		case __NR_chown: {
			const char *path = (const char *)arg1;
			uid_t owner = arg2;
			gid_t group = arg3;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return PROXY_CALL(__NR_fchownat, proxy_value(real.fd), proxy_string(real.path), proxy_value(owner), proxy_value(group), proxy_value(0));
			}
			if (enabled_telemetry & TELEMETRY_TYPE_ATTRIBUTE_CHANGE) {
				return wrapped_chownat(thread, AT_FDCWD, path, owner, group, 0);
			}
			if (real.fd != AT_FDCWD) {
				return FS_SYSCALL(__NR_fchownat, real.fd, (intptr_t)real.path, arg2, arg3, 0);
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2, arg3);
		}
#endif
		case __NR_fchown: {
			int fd = arg1;
			uid_t owner = arg2;
			gid_t group = arg3;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_fchown, proxy_value(real_fd), proxy_value(owner), proxy_value(group));
			}
			if (enabled_telemetry & TELEMETRY_TYPE_ATTRIBUTE_CHANGE) {
				return wrapped_chownat(thread, real_fd, NULL, owner, group, 0);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
#ifdef __NR_lchown
		case __NR_lchown: {
			const char *path = (const char *)arg1;
			uid_t owner = arg2;
			gid_t group = arg3;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return PROXY_CALL(__NR_fchownat, proxy_value(real.fd), proxy_string(real.path), proxy_value(owner), proxy_value(group), proxy_value(AT_SYMLINK_NOFOLLOW));
			}
			if (enabled_telemetry & TELEMETRY_TYPE_ATTRIBUTE_CHANGE) {
				return wrapped_chownat(thread, AT_FDCWD, path, owner, group, AT_SYMLINK_NOFOLLOW);
			}
			if (real.fd != AT_FDCWD) {
				return FS_SYSCALL(__NR_fchownat, real.fd, (intptr_t)real.path, arg2, arg3, AT_SYMLINK_NOFOLLOW);
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2, arg3);
		}
#endif
		case __NR_fchownat: {
			int fd = arg1;
			const char *path = (const char *)arg2;
			uid_t owner = arg3;
			gid_t group = arg4;
			int flags = arg5;
			path_info real;
			if (lookup_real_path(fd, path, &real)) {
				return PROXY_CALL(__NR_fchownat, proxy_value(real.fd), proxy_string(real.path), proxy_value(owner), proxy_value(group), proxy_value(flags));
			}
			if (enabled_telemetry & TELEMETRY_TYPE_ATTRIBUTE_CHANGE) {
				return wrapped_chownat(thread, fd, path, owner, group, flags);
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3, arg4, arg5);
		}
		case __NR_select: {
			int n = arg1;
			fd_set *readfds = (fd_set *)arg2;
			fd_set *writefds = (fd_set *)arg3;
			fd_set *exceptfds = (fd_set *)arg4;
			for (int i = 0; i < n; i++) {
				if ((readfds != NULL && FD_ISSET(i, readfds)) || (writefds != NULL && FD_ISSET(i, writefds)) || (exceptfds != NULL && FD_ISSET(i, exceptfds))) {
					int real_fd;
					if (lookup_real_fd(i, &real_fd)) {
						// TODO: proxy remotely
						return -EBADF;
					}
					// TODO: support mapping back and forth
				}
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5);
		}
		case __NR_sendfile: {
			int out_real_fd;
			bool out_is_remote = lookup_real_fd(arg1, &out_real_fd);
			int in_real_fd;
			bool in_is_remote = lookup_real_fd(arg2, &in_real_fd);
			if (in_is_remote != out_is_remote) {
				return -EINVAL;
			}
			if (in_is_remote) {
				return PROXY_CALL(__NR_sendfile, proxy_value(out_real_fd), proxy_value(in_real_fd), proxy_inout((off_t *)arg3, sizeof(off_t)), proxy_value(arg4));
			}
			return FS_SYSCALL(syscall, out_real_fd, in_real_fd, arg3, arg4);
		}
		case __NR_recvfrom: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				socklen_t *len = (socklen_t *)arg6;
				return remote_recvfrom(real_fd, (void *)arg2, arg3, arg4, (struct sockaddr *)arg5, len);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_sendmsg: {
			// TODO: handle sendmsg
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_recvmsg: {
			// TODO: handle recvmsg
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_shutdown: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_shutdown, proxy_value(real_fd), proxy_value(arg2));
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_getsockname:
		case __NR_getpeername: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				socklen_t *outlen = (socklen_t *)arg3;
				return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_out((void *)arg2, *outlen), proxy_inout(outlen, sizeof(socklen_t)));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_getsockopt: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				socklen_t *optlen = (socklen_t *)arg5;
				return remote_getsockopt(real_fd, arg2, arg3, (void *)arg4, optlen);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_setsockopt: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_setsockopt(real_fd, arg2, arg3, (const void *)arg4, arg5);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_flock: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_flock(real_fd, arg2);
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_fsync: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_fsync(real_fd);
			}
			return FS_SYSCALL(syscall, real_fd);
		}
		case __NR_fdatasync: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_fdatasync(real_fd);
			}
			return FS_SYSCALL(syscall, real_fd);
		}
		case __NR_truncate: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				if (real.fd != AT_FDCWD) {
					// no ftruncateat; open, ftruncate, and close
					int temp_fd = remote_openat(real.fd, real.path, O_WRONLY | O_CLOEXEC, 0);
					if (temp_fd < 0) {
						return temp_fd;
					}
					intptr_t result = remote_ftruncate(temp_fd, arg2);
					remote_close(temp_fd);
					return result;
				}
				return remote_truncate(real.path, arg2);
			}
			if (real.fd != AT_FDCWD) {
				// no ftruncateat; open, ftruncate, and close
				int temp_fd = fs_openat(real.fd, real.path, O_WRONLY | O_CLOEXEC, 0);
				if (temp_fd < 0) {
					return temp_fd;
				}
				intptr_t result = fs_ftruncate(temp_fd, arg2);
				remote_close(temp_fd);
				return result;
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2);
		}
		case __NR_ftruncate: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_ftruncate(real_fd, arg2);
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_getdents: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_getdents, proxy_value(real_fd), proxy_out((void *)arg2, arg3), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_fstatfs: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_fstatfs, proxy_value(real_fd), proxy_out((void *)arg2, sizeof(struct fs_statfs)));
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_readahead: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_readahead(real_fd, arg2, arg3);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_setxattr:
		case __NR_lsetxattr: {
			const char *path = (const char *)arg1;
			const char *name = (const char *)arg2;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				if (real.fd != AT_FDCWD) {
					return -EINVAL;
				}
				if (proxy_get_target_platform() == TARGET_PLATFORM_DARWIN) {
					return -EINVAL;
				}
				return PROXY_CALL(syscall, proxy_string(real.path), proxy_string(name), proxy_in((void *)arg3, arg4), proxy_value(arg4), proxy_value(arg5));
			}
			if (real.fd != AT_FDCWD) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2, arg3, arg4, arg5);
		}
		case __NR_fsetxattr: {
			int fd = arg1;
			const char *name = (const char *)arg2;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				if (proxy_get_target_platform() == TARGET_PLATFORM_DARWIN) {
					return -EINVAL;
				}
				return PROXY_CALL(__NR_fsetxattr, proxy_value(real_fd), proxy_string(name), proxy_in((void *)arg3, arg4), proxy_value(arg4), proxy_value(arg5));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_getxattr:
		case __NR_lgetxattr: {
			const char *path = (const char *)arg1;
			const char *name = (const char *)arg2;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				char buf[PATH_MAX];
				if (real.fd != AT_FDCWD) {
					int result = assemble_remote_path(real.fd, real.path, buf, &real.path);
					if (result < 0) {
						return result;
					}
				}
				if (proxy_get_target_platform() == TARGET_PLATFORM_DARWIN) {
					return -ENODATA;
				}
				return PROXY_CALL(syscall, proxy_string(real.path), proxy_string(name), proxy_out((void *)arg3, arg4), proxy_value(arg4), proxy_value(arg5));
			}
			if (real.fd != AT_FDCWD) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2, arg3, arg4, arg5);
		}
		case __NR_fgetxattr: {
			int fd = arg1;
			const char *name = (const char *)arg2;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_fgetxattr, proxy_value(real_fd), proxy_string(name), proxy_out((void *)arg3, arg4), proxy_value(arg4), proxy_value(arg5));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_listxattr: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				char buf[PATH_MAX];
				if (real.fd != AT_FDCWD) {
					int result = assemble_remote_path(real.fd, real.path, buf, &real.path);
					if (result < 0) {
						return result;
					}
				}
				return PROXY_CALL(__NR_listxattr, proxy_string(real.path), proxy_out((void *)arg2, arg3), proxy_value(arg3));
			}
			if (real.fd != AT_FDCWD) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2, arg3);
		}
		case __NR_flistxattr: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_flistxattr, proxy_value(real_fd), proxy_out((void *)arg2, arg3), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_removexattr: {
			const char *path = (const char *)arg1;
			const char *name = (const char *)arg2;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				char buf[PATH_MAX];
				if (real.fd != AT_FDCWD) {
					int result = assemble_remote_path(real.fd, real.path, buf, &real.path);
					if (result < 0) {
						return result;
					}
				}
				return PROXY_CALL(__NR_removexattr, proxy_string(real.path), proxy_string(name));
			}
			if (real.fd != AT_FDCWD) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2);
		}
		case __NR_fremovexattr: {
			int fd = arg1;
			const char *name = (const char *)arg2;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_fremovexattr, proxy_value(real_fd), proxy_string(name));
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_getdents64: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_getdents64(real_fd, (void *)arg2, arg3);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_fadvise64: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return remote_fadvise64(real_fd, arg2, arg3, arg4);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
		case __NR_epoll_wait:
		case __NR_epoll_pwait: {
			int fd = arg1;
			int real_fd;
			struct epoll_event *events = (struct epoll_event *)arg2;
			int maxevents = arg3;
			int timeout = arg4;
			if (lookup_real_fd(fd, &real_fd)) {
				// TODO: support pwait properly when remote
				return PROXY_CALL(__NR_epoll_wait, proxy_value(real_fd), proxy_out(events, sizeof(struct epoll_event) * maxevents), proxy_value(maxevents), proxy_value(timeout));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_epoll_ctl: {
			// TODO: handle epoll_ctl with mixed remote and local fds
			int epfd = arg1;
			int op = arg2;
			int fd = arg3;
			struct epoll_event *event = (struct epoll_event *)arg4;
			int real_epfd;
			bool epfd_is_remote = lookup_real_fd(fd, &real_epfd);
			int real_fd;
			bool fd_is_remote = lookup_real_fd(fd, &real_fd);
			if (fd_is_remote) {
				if (!epfd_is_remote) {
					real_epfd = PROXY_CALL(__NR_epoll_create1 | PROXY_NO_WORKER, proxy_value(EPOLL_CLOEXEC));
					if (real_epfd < 0) {
						return real_epfd;
					}
					int result = become_remote_fd(epfd, real_epfd);
					if (result < 0) {
						remote_close(real_epfd);
						return result;
					}
				}
				return PROXY_CALL(syscall, proxy_value(real_epfd), proxy_value(op), proxy_value(real_fd), proxy_in(event, sizeof(*event)));
			}
			if (epfd_is_remote) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_epfd, arg2, real_fd, arg4);
		}
		case __NR_mq_open: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2, arg3, arg4), arg2);
		}
		case __NR_mq_timedsend: {
			// TODO: handle mq_timedsend
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_mq_timedreceive: {
			// TODO: handle mq_timedreceive
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_mq_notify: {
			// TODO: handle mq_notify
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg1, arg2);
		}
		case __NR_mq_getsetattr: {
			// TODO: handle mq_getsetattr
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg1, arg2, arg3);
		}
		case __NR_inotify_init: {
			return install_local_fd(FS_SYSCALL(syscall), 0);
		}
		case __NR_inotify_init1: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), arg1);
		}
		case __NR_inotify_add_watch: {
			// TODO: handle inotify_add_watch
			int fd = arg1;
			int real_fd;
			bool fd_is_remote = lookup_real_fd(fd, &real_fd);
			const char *path = (const char *)arg2;
			path_info real;
			bool path_is_remote = lookup_real_path(AT_FDCWD, path, &real);
			if (real.fd != AT_FDCWD) {
				return -EINVAL;
			}
			if (fd_is_remote != path_is_remote) {
				return -EINVAL;
			}
			if (fd_is_remote) {
				return PROXY_CALL(__NR_inotify_add_watch, proxy_value(real_fd), proxy_string(real.path), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, real_fd, (intptr_t)real.path, arg3);
		}
		case __NR_inotify_rm_watch: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_inotify_rm_watch, real_fd, arg2);
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_pselect6: {
			// TODO: handle pselect6
			int nfds = arg1;
			struct fs_fd_set *readfds = (struct fs_fd_set *)arg2;
			struct fs_fd_set *writefds = (struct fs_fd_set *)arg3;
			struct fs_fd_set *exceptfds = (struct fs_fd_set *)arg4;
			const struct timespec *timeout = (const struct timespec *)arg5;
			const struct fs_sigset_t *sigmask = (const struct fs_sigset_t *)arg6;
			for (int i = 0; i < nfds; i++) {
				bool has_read = readfds && fs_fd_isset(i, readfds);
				bool has_write = writefds && fs_fd_isset(i, writefds);
				bool has_except = exceptfds && fs_fd_isset(i, exceptfds);
				if (has_read || has_write || has_except) {
					int real_fd;
					if (lookup_real_fd(i, &real_fd)) {
						// TODO: handle more than one
						struct pollfd poll = {
							.fd = real_fd,
							.events = (has_read ? POLLIN : 0) | (has_write ? POLLOUT : 0) | (has_except ? POLLRDHUP : 0),
							.revents = 0,
						};
						int result = PROXY_CALL(__NR_ppoll, proxy_inout(&poll, sizeof(poll)), proxy_value(1), proxy_in(timeout, sizeof(struct timespec)), proxy_value(0), proxy_value(sizeof(*sigmask)));
						if (result < 0) {
							return result;
						}
						if (has_read && ((poll.revents & POLLIN) == 0)) {
							fs_fd_clr(i, readfds);
						}
						if (has_write && ((poll.revents & POLLOUT) == 0)) {
							fs_fd_clr(i, writefds);
						}
						if (has_write && ((poll.revents & POLLERR) == 0)) {
							fs_fd_clr(i, exceptfds);
						}
						for (i++; i < nfds; i++) {
							if (readfds && fs_fd_isset(i, readfds)) {
								fs_fd_clr(i, readfds);
							}
							if (writefds && fs_fd_isset(i, writefds)) {
								fs_fd_clr(i, writefds);
							}
							if (exceptfds && fs_fd_isset(i, exceptfds)) {
								fs_fd_clr(i, exceptfds);
							}
						}
						return (int)has_read + (int)has_write + (int)has_except;
					}
					// TODO: remap local fds
				}
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_ppoll: {
			// TODO: handle ppoll
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5);
		}
		case __NR_splice: {
			int fd_in_real;
			bool in_is_remote = lookup_real_fd(arg1, &fd_in_real);
			int fd_out_real;
			bool out_is_remote = lookup_real_fd(arg3, &fd_out_real);
			if (in_is_remote != out_is_remote) {
				return -EINVAL;
			}
			if (in_is_remote) {
				return PROXY_CALL(__NR_splice, proxy_value(fd_in_real), proxy_inout((void *)arg2, sizeof(off_t)), proxy_value(fd_out_real), proxy_inout((void *)arg4, sizeof(off_t)), proxy_value(arg5), proxy_value(arg6));
			}
			return FS_SYSCALL(syscall, fd_in_real, arg2, fd_out_real, arg4, arg5, arg6);
		}
		case __NR_tee: {
			int fd_in_real;
			bool in_is_remote = lookup_real_fd(arg1, &fd_in_real);
			int fd_out_real;
			bool out_is_remote = lookup_real_fd(arg2, &fd_out_real);
			if (in_is_remote != out_is_remote) {
				return -EINVAL;
			}
			if (in_is_remote) {
				return PROXY_CALL(__NR_tee, proxy_value(fd_in_real), proxy_value(fd_out_real), proxy_value(arg3), proxy_value(arg4));
			}
			return FS_SYSCALL(syscall, fd_in_real, fd_out_real, arg3, arg4);
		}
		case __NR_sync_file_range: {
			int real_fd;
			if (lookup_real_fd(arg2, &real_fd)) {
				return PROXY_CALL(__NR_sync_file_range, proxy_value(real_fd), proxy_value(arg2), proxy_value(arg3), proxy_value(arg4));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
		case __NR_vmsplice: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EBADF;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
		case __NR_utime: {
			// TODO: handle utime
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case __NR_utimensat: {
			// TODO: is this correct?
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return PROXY_CALL(__NR_utimensat, proxy_value(real.fd), proxy_string(real.path), proxy_in((void *)arg3, sizeof(struct timeval)), proxy_value(arg4));
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3, arg4);
		}
		case __NR_futimesat: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return PROXY_CALL(__NR_futimesat, proxy_value(real.fd), proxy_string(real.path), proxy_in((void *)arg3, sizeof(struct timeval)));
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3, arg4);
		}
		case __NR_signalfd: {
			int fd = arg1;
			int real_fd;
			if (fd == -1) {
				real_fd = -1;
			} else {
				if (lookup_real_fd(fd, &real_fd)) {
					return -EINVAL;
				}
			}
			int result = FS_SYSCALL(syscall, real_fd, arg2, arg3);
			if (fd == -1) {
				result = install_local_fd(result, 0);
			}
			return result;
		}
		case __NR_signalfd4: {
			int fd = arg1;
			int real_fd;
			if (fd == -1) {
				real_fd = -1;
			} else {
				if (lookup_real_fd(fd, &real_fd)) {
					return -EINVAL;
				}
			}
			int result = FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
			if (fd == -1) {
				result = install_local_fd(result, arg4);
			}
			return result;
		}
		case __NR_timerfd_create: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg2);
		}
		case __NR_eventfd: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), 0);
		}
		case __NR_eventfd2: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg2);
		}
		case __NR_fallocate: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_fallocate, proxy_value(real_fd), proxy_value(arg2), proxy_value(arg3), proxy_value(arg4));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
		case __NR_timerfd_settime: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
		case __NR_timerfd_gettime: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_epoll_create: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), 0);
		}
		case __NR_epoll_create1: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), arg1);
		}
		case __NR_readv:
		case __NR_preadv:
		case __NR_preadv2: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				const struct iovec *iov = (const struct iovec *)arg2;
				int iovcnt = arg3;
				// allocate buffer
				size_t total_bytes = 0;
				for (int i = 0; i < iovcnt; i++) {
					total_bytes += iov[i].iov_len;
				}
				size_t alloc_bytes = sizeof(*iov) * iovcnt + total_bytes;
				attempt_proxy_alloc_state remote_buf;
				attempt_proxy_alloc(alloc_bytes, thread, &remote_buf);
				// fill buffers
				intptr_t buf_cur = remote_buf.addr;
				struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
				struct attempt_cleanup_state state;
				attempt_push_free(thread, &state, iov_remote);
				for (int i = 0; i < iovcnt; i++) {
					iov_remote[i].iov_base = (void *)buf_cur;
					buf_cur += iov[i].iov_len;
					iov_remote[i].iov_len += iov[i].iov_len;
				}
				proxy_poke(buf_cur, sizeof(*iov) * iovcnt, &iov_remote[0]);
				attempt_pop_free(&state);
				// perform read remotely
				intptr_t result = PROXY_CALL(syscall, proxy_value(real_fd), proxy_value(remote_buf.addr), proxy_value(iovcnt), proxy_value(arg4), proxy_value(arg5), proxy_value(arg6));
				if (result >= 0) {
					// copy bytes into local buffers
					buf_cur = remote_buf.addr;
					for (int i = 0; i < iovcnt; i++) {
						if (result < (intptr_t)iov[i].iov_len) {
							proxy_peek(buf_cur, iov[i].iov_len, iov[i].iov_base);
							break;
						}
						proxy_peek(buf_cur, result, iov[i].iov_base);
						buf_cur += iov[i].iov_len;
					}
				}
				// free buffers
				attempt_proxy_free(&remote_buf);
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_writev:
		case __NR_pwritev:
		case __NR_pwritev2: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				const struct iovec *iov = (const struct iovec *)arg2;
				int iovcnt = arg3;
				// allocate buffer
				size_t total_bytes = 0;
				for (int i = 0; i < iovcnt; i++) {
					total_bytes += iov[i].iov_len;
				}
				size_t alloc_bytes = sizeof(*iov) * iovcnt + total_bytes;
				attempt_proxy_alloc_state remote_buf;
				attempt_proxy_alloc(alloc_bytes, thread, &remote_buf);
				// fill buffers
				intptr_t buf_cur = remote_buf.addr;
				struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
				struct attempt_cleanup_state state;
				for (int i = 0; i < iovcnt; i++) {
					iov_remote[i].iov_base = (void *)buf_cur;
					proxy_poke(buf_cur, iov[i].iov_len, iov[i].iov_base);
					buf_cur += iov[i].iov_len;
					iov_remote[i].iov_len += iov[i].iov_len;
				}
				proxy_poke(buf_cur, sizeof(*iov) * iovcnt, &iov_remote[0]);
				attempt_pop_free(&state);
				// perform write remotely
				intptr_t result = PROXY_CALL(syscall, proxy_value(real_fd), proxy_value(remote_buf.addr), proxy_value(iovcnt), proxy_value(arg4), proxy_value(arg5), proxy_value(arg6));
				// free buffers
				attempt_proxy_free(&remote_buf);
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_recvmmsg: {
			// TODO: handle recvmmsg
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_fanotify_init: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg1);
		}
		case __NR_fanotify_mark: {
			int fanotify_fd = arg1;
			unsigned int flags = arg2;
			uint64_t mask = arg3;
			int dirfd = arg4;
			const char *pathname = (const char *)arg5;
			int real_fanotify_fd;
			bool fanotify_fd_is_remote = lookup_real_fd(fd, &fanotify_fd);
			path_info real;
			bool path_is_remote = lookup_real_path(dirfd, pathname, &real);
			if (fanotify_fd_is_remote != path_is_remote) {
				return -EINVAL;
			}
			if (fanotify_fd_is_remote) {
				return PROXY_CALL(syscall, proxy_value(real_fanotify_fd), proxy_value(flags), proxy_value(mask), proxy_value(real.fd), proxy_string(real.path));
			}
			return FS_SYSCALL(syscall, real_fanotify_fd, flags, mask, real.fd, (intptr_t)real.path);
		}
		case __NR_name_to_handle_at: {
			// TODO: handle name_to_handle_at
			int dfd = arg1;
			int real_dfd;
			if (lookup_real_fd(dfd, &real_dfd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_dfd, arg2, arg3, arg4, arg5);
		}
		case __NR_open_by_handle_at: {
			// TODO: handle open_by_handle_at
			int dfd = arg1;
			int real_dfd;
			if (lookup_real_fd(dfd, &real_dfd)) {
				return -EINVAL;
			}
			return install_local_fd(FS_SYSCALL(syscall, real_dfd, arg2, arg3, arg4, arg5), arg5);
		}
		case __NR_syncfs: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(__NR_syncfs, proxy_value(real_fd));
			}
			return FS_SYSCALL(syscall, real_fd);
		}
		case __NR_sendmmsg: {
			// TODO: handle sendmmsg
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_setns: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_finit_module: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_memfd_create: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg2);
		}
		case __NR_copy_file_range: {
			int in_real_fd;
			bool in_is_remote = lookup_real_fd(arg1, &in_real_fd);
			int out_real_fd;
			bool out_is_remote = lookup_real_fd(arg3, &out_real_fd);
			if (in_is_remote != out_is_remote) {
				return -EXDEV;
			}
			if (in_is_remote) {
				return PROXY_CALL(__NR_copy_file_range, proxy_value(in_real_fd), proxy_inout((void *)arg2, sizeof(off_t)), proxy_value(out_real_fd), proxy_inout((void *)arg4, sizeof(off_t)), proxy_value(arg5), proxy_value(arg6));
			}
			return FS_SYSCALL(syscall, in_real_fd, arg2, out_real_fd, arg4, arg5, arg6);
		}
#ifdef __NR_readlink
		case __NR_readlink: {
			const char *path = (const char *)arg1;
			char *buf = (char *)arg2;
			size_t bufsiz = (size_t)arg3;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return remote_readlinkat(real.fd, real.path, buf, bufsiz);
			}
			return wrapped_readlinkat(thread, real.fd, real.path, buf, bufsiz);
		}
#endif
		case __NR_readlinkat: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			char *buf = (char *)arg3;
			size_t bufsiz = (size_t)arg4;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return remote_readlinkat(real.fd, real.path, buf, bufsiz);
			}
			return wrapped_readlinkat(thread, real.fd, real.path, buf, bufsiz);
		}
#ifdef __NR_mkdir
		case __NR_mkdir: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return PROXY_CALL(__NR_mkdirat, proxy_value(real.fd), proxy_string(real.path), proxy_value(arg2));
			}
			if (real.fd != AT_FDCWD) {
				return fs_mkdirat(real.fd, real.path, arg2);
			}
			return fs_mkdir(real.path, arg2);
		}
#endif
		case __NR_mkdirat: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return PROXY_CALL(__NR_mkdirat, proxy_value(real.fd), proxy_string(real.path), proxy_value(arg3));
			}
			return fs_mkdirat(real.fd, real.path, arg3);
		}
#ifdef __NR_mknod
		case __NR_mknod: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return PROXY_CALL(__NR_mknodat, proxy_value(real.fd), proxy_string(real.path), proxy_value(arg2), proxy_value(arg3));
			}
			if (real.fd != AT_FDCWD) {
				return FS_SYSCALL(__NR_mknodat, real.fd, (intptr_t)real.path, arg2, arg3);
			}
			return FS_SYSCALL(syscall, (intptr_t)real.path, arg2, arg3);
		}
#endif
		case __NR_mknodat: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return PROXY_CALL(__NR_mknodat, proxy_value(real.fd), proxy_string(real.path), proxy_value(arg3), proxy_value(arg4));
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3, arg4);
		}
#ifdef __NR_unlink
		case __NR_unlink: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return PROXY_CALL(__NR_unlinkat, proxy_value(real.fd), proxy_string(real.path), proxy_value(0));
			}
			return wrapped_unlinkat(thread, real.fd, real.path, 0);
		}
		case __NR_rmdir: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				return PROXY_CALL(__NR_unlinkat, proxy_value(real.fd), proxy_string(real.path), proxy_value(AT_REMOVEDIR));
			}
			return wrapped_unlinkat(thread, real.fd, path, AT_REMOVEDIR);
		}
#endif
		case __NR_unlinkat: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			int flag = arg3;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return PROXY_CALL(__NR_unlinkat, proxy_value(real.fd), proxy_string(real.path), proxy_value(flag));
			}
			return wrapped_unlinkat(thread, real.fd, real.path, flag);
		}
#ifdef __NR_rename
		case __NR_rename: {
			const char *oldpath = (const char *)arg1;
			const char *newpath = (const char *)arg2;
			path_info real_old;
			bool old_is_remote = lookup_real_path(AT_FDCWD, oldpath, &real_old);
			path_info real_new;
			bool new_is_remote = lookup_real_path(AT_FDCWD, newpath, &real_new);
			if (old_is_remote != new_is_remote) {
				return -EINVAL;
			}
			if (old_is_remote) {
				return PROXY_CALL(__NR_renameat, proxy_value(real_old.fd), proxy_string(real_old.path), proxy_value(real_new.fd), proxy_string(real_new.path));
			}
			return wrapped_renameat(thread, real_old.fd, real_old.path, real_new.fd, real_new.path, 0);
		}
#endif
		case __NR_renameat: {
			int old_dirfd = arg1;
			const char *oldpath = (const char *)arg2;
			int new_dirfd = arg3;
			const char *newpath = (const char *)arg4;
			path_info real_old;
			bool old_is_remote = lookup_real_path(old_dirfd, oldpath, &real_old);
			path_info real_new;
			bool new_is_remote = lookup_real_path(new_dirfd, newpath, &real_new);
			if (old_is_remote != new_is_remote) {
				return -EINVAL;
			}
			if (old_is_remote) {
				return PROXY_CALL(__NR_renameat, proxy_value(real_old.fd), proxy_string(real_old.path), proxy_value(real_new.fd), proxy_string(real_new.path));
			}
			return wrapped_renameat(thread, real_old.fd, real_old.path, real_new.fd, real_new.path, 0);
		}
		case __NR_renameat2: {
			int old_dirfd = arg1;
			const char *oldpath = (const char *)arg2;
			int new_dirfd = arg3;
			const char *newpath = (const char *)arg4;
			int flags = arg5;
			path_info real_old;
			bool old_is_remote = lookup_real_path(old_dirfd, oldpath, &real_old);
			path_info real_new;
			bool new_is_remote = lookup_real_path(new_dirfd, newpath, &real_new);
			if (old_is_remote != new_is_remote) {
				return -EINVAL;
			}
			if (old_is_remote) {
				return PROXY_CALL(__NR_renameat2, proxy_value(real_old.fd), proxy_string(real_old.path), proxy_value(real_new.fd), proxy_string(real_new.path), proxy_value(flags));
			}
			return wrapped_renameat(thread, real_old.fd, real_old.path, real_new.fd, real_new.path, flags);
		}
#ifdef __NR_link
		case __NR_link: {
			const char *oldpath = (const char *)arg1;
			const char *newpath = (const char *)arg2;
			path_info real_old;
			bool old_is_remote = lookup_real_path(AT_FDCWD, oldpath, &real_old);
			path_info real_new;
			bool new_is_remote = lookup_real_path(AT_FDCWD, newpath, &real_new);
			if (old_is_remote != new_is_remote) {
				return -EINVAL;
			}
			if (old_is_remote) {
				return PROXY_CALL(__NR_linkat, proxy_value(real_old.fd), proxy_string(real_old.path), proxy_value(real_new.fd), proxy_string(real_new.path));
			}
			return wrapped_linkat(thread, real_old.fd, real_old.path, real_new.fd, real_new.path, 0);
		}
#endif
		case __NR_linkat: {
			int old_dirfd = arg1;
			const char *oldpath = (const char *)arg2;
			int new_dirfd = arg3;
			const char *newpath = (const char *)arg4;
			int flags = arg5;
			path_info real_old;
			bool old_is_remote = lookup_real_path(old_dirfd, oldpath, &real_old);
			path_info real_new;
			bool new_is_remote = lookup_real_path(new_dirfd, newpath, &real_new);
			if (old_is_remote != new_is_remote) {
				return -EINVAL;
			}
			if (old_is_remote) {
				return PROXY_CALL(__NR_linkat, proxy_value(real_old.fd), proxy_string(real_old.path), proxy_value(real_new.fd), proxy_string(real_new.path));
			}
			return wrapped_linkat(thread, real_old.fd, real_old.path, real_old.fd, real_old.path, flags);
		}
#ifdef __NR_symlink
		case __NR_symlink: {
			const char *oldpath = (const char *)arg1;
			const char *newpath = (const char *)arg2;
			path_info real_new;
			if (lookup_real_path(AT_FDCWD, newpath, &real_new)) {
				return PROXY_CALL(__NR_symlinkat, proxy_string(oldpath), proxy_value(real_new.fd), proxy_string(real_new.path));
			}
			return wrapped_symlinkat(thread, oldpath, real_new.fd, real_new.path);
		}
#endif
		case __NR_symlinkat: {
			const char *oldpath = (const char *)arg1;
			int new_dirfd = arg2;
			const char *newpath = (const char *)arg3;
			path_info real_new;
			if (lookup_real_path(new_dirfd, newpath, &real_new)) {
				return PROXY_CALL(__NR_symlinkat, proxy_string(oldpath), proxy_value(real_new.fd), proxy_string(real_new.path));
			}
			return wrapped_symlinkat(thread, oldpath, real_new.fd, real_new.path);
		}
		case __NR_fchmodat: {
			int fd = arg1;
			const char *path = (const char *)arg2;
			mode_t mode = arg3;
			path_info real;
			if (lookup_real_path(fd, path, &real)) {
				return PROXY_CALL(__NR_fchmodat, proxy_value(real.fd), proxy_string(real.path), proxy_value(mode));
			}
			if (enabled_telemetry & (TELEMETRY_TYPE_ATTRIBUTE_CHANGE | TELEMETRY_TYPE_CHMOD)) {
				return wrapped_chmodat(thread, real.fd, real.path, mode);
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3);
		}
		case __NR_rt_sigaction: {
			return handle_sigaction((int)arg1, (const struct fs_sigaction *)arg2, (struct fs_sigaction *)arg3, (size_t)arg4);
		}
		case __NR_rt_sigprocmask: {
			int how = arg1;
			struct fs_sigset_t *nset = (struct fs_sigset_t *)arg2;
			struct fs_sigset_t *oset = (struct fs_sigset_t *)arg3;
			size_t sigsetsize = arg4;
			if (sigsetsize != sizeof(struct fs_sigset_t)) {
				return -EINVAL;
			}
			struct signal_state *signals = &thread->signals;
			if (context) {
				if (oset) {
					memcpy(oset, &signals->blocked_required, sizeof(struct fs_sigset_t));
				}
				if (nset) {
					switch (how) {
						case SIG_UNBLOCK: {
							signals->blocked_required.buf[0] &= ~nset->buf[0];
							struct fs_sigset_t *context_set = (struct fs_sigset_t *)&context->uc_sigmask;
							for (size_t i = 0; i < sigsetsize / sizeof(nset->buf[0]); i++) {
								context_set->buf[i] &= ~nset->buf[i];
							}
							// TODO: dispatch pending signals
							break;
						}
						case SIG_BLOCK: {
							signals->blocked_required.buf[0] |= nset->buf[0];
							struct fs_sigset_t *context_set = (struct fs_sigset_t *)&context->uc_sigmask;
							for (size_t i = 0; i < sigsetsize / sizeof(nset->buf[0]); i++) {
								context_set->buf[i] |= nset->buf[i];
							}
							context_set->buf[0] &= ~REQUIRED_SIGNALS;
							break;
						}
						case SIG_SETMASK: {
							signals->blocked_required.buf[0] = nset->buf[0];
							memcpy(&context->uc_sigmask, nset, sigsetsize);
							struct fs_sigset_t *context_set = (struct fs_sigset_t *)&context->uc_sigmask;
							context_set->buf[0] &= ~REQUIRED_SIGNALS;
							// TODO: dispatch pending signals
							break;
						}
					}
				}
				return 0;
			}
			struct fs_sigset_t copy;
			if (nset != NULL) {
				switch (how) {
					case SIG_UNBLOCK:
						signals->blocked_required.buf[0] &= ~nset->buf[0];
						// TODO: dispatch pending signals
						break;
					case SIG_BLOCK:
						signals->blocked_required.buf[0] |= nset->buf[0];
						if (nset->buf[0] & REQUIRED_SIGNALS) {
							// A required signal was blocked—copy to a local buffer and clear
							memcpy(&copy, nset, sigsetsize);
							copy.buf[0] &= ~REQUIRED_SIGNALS;
							nset = &copy;
						}
						break;
					case SIG_SETMASK:
						signals->blocked_required.buf[0] = nset->buf[0];
						if (nset->buf[0] & REQUIRED_SIGNALS) {
							// A required signal was blocked—copy to a local buffer and clear
							memcpy(&copy, nset, sigsetsize);
							copy.buf[0] &= ~REQUIRED_SIGNALS;
							nset = &copy;
							// TODO: dispatch pending signals
						}
						break;
				}
			}
			intptr_t result = fs_rt_sigprocmask(how, nset, oset, sigsetsize);
			if (result == 0 && oset) {
				oset->buf[0] = (oset->buf[0] & ~REQUIRED_SIGNALS) | (signals->blocked_required.buf[0] & REQUIRED_SIGNALS);
			}
			return result;
		}
#ifdef WATCH_ALTSTACKS
		case __NR_sigaltstack: {
			const stack_t *ss = (const stack_t *)arg1;
			stack_t *old_ss = (stack_t *)arg2;
			if (ss != NULL) {
				struct stack_data *data = &thread->stack;
				data->altstack = *ss;
				return fs_sigaltstack(ss, old_ss);
			}
			int result = fs_sigaltstack(ss, old_ss);
			if (result == 0 && old_ss) {
				struct stack_data *data = &thread->stack;
				data->altstack = *old_ss;
			}
			return result;
		}
#endif
#ifdef __NR_fork
		case __NR_fork: {
			return wrapped_fork(thread);
		}
#endif
#ifdef __NR_vfork
		case __NR_vfork: {
			return wrapped_vfork(thread);
		}
#endif
		case __NR_clone: {
			return wrapped_clone(thread, arg1, (void *)arg2, (int *)arg3, (int *)arg4, arg5);
		}
		case __NR_clone3: {
			// for now, disable support for clone3
			return -ENOSYS;
		}
		case __NR_munmap: {
			// workaround to handle case where a thread unmaps its stack and immediately exits
			// see musl's __pthread_exit function and the associated __unmapself helper
			intptr_t sp = context != NULL ? (intptr_t)context->uc_mcontext.REG_SP : (intptr_t)&sp;
			if (sp >= arg1 && sp <= arg1 + arg2) {
				if (enabled_telemetry & TELEMETRY_TYPE_EXIT && fs_gettid() == get_self_pid()) {
					send_exit_event(thread, arg1);
				}
#ifdef COVERAGE
				if (fs_gettid() == get_self_pid()) {
					coverage_flush();
				}
#endif
				if (fs_gettid() == get_self_pid()) {
					clear_fd_table();
				}
				attempt_exit(thread);
				call_on_alternate_stack(thread, unmap_and_exit_thread, (void *)arg1, (void *)arg2);
			}
			return FS_SYSCALL(__NR_munmap, arg1, arg2);
		}
		case __NR_exit:
			if (enabled_telemetry & TELEMETRY_TYPE_EXIT && fs_gettid() == get_self_pid()) {
				send_exit_event(thread, arg1);
			}
#ifdef COVERAGE
			if (fs_gettid() == get_self_pid()) {
				coverage_flush();
			}
#endif
			if (fs_gettid() == get_self_pid()) {
				clear_fd_table();
			}
			attempt_exit(thread);
			atomic_intptr_t *thread_id = clear_thread_storage();
			atomic_store_explicit(thread_id, 0, memory_order_release);
			fs_exitthread(arg1);
			__builtin_unreachable();
		case __NR_exit_group:
			if (enabled_telemetry & TELEMETRY_TYPE_EXIT) {
				send_exit_event(thread, arg1);
			}
#ifdef COVERAGE
			coverage_flush();
#endif
			clear_fd_table();
			return FS_SYSCALL(__NR_exit_group, arg1);
		case __NR_chdir: {
			const char *path = (const char *)arg1;
			path_info real;
			if (lookup_real_path(AT_FDCWD, path, &real)) {
				int real_fd = remote_openat(real.fd, real.path, O_PATH|O_DIRECTORY, 0);
				if (real_fd < 0) {
					return real_fd;
				}
				return chdir_become_remote_fd(real_fd);
			}
			if (real.fd != AT_FDCWD) {
				return -EINVAL;
			}
			int result = chdir_become_local_path(real.path);
			if (result == 0) {
				working_dir_changed(thread);
			}
			return result;
		}
		case __NR_fchdir: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				struct fs_stat stat;
				int result = remote_fstat(real_fd, &stat);
				if (result < 0) {
					return result;
				}
				if (!S_ISDIR(stat.st_mode)) {
					return -ENOTDIR;
				}
				// TODO: do this without a remote dup
				int new_remote_fd = PROXY_CALL(__NR_dup, proxy_value(real_fd));
				if (new_remote_fd < 0) {
					return new_remote_fd;
				}
				return chdir_become_remote_fd(new_remote_fd);
			}
			int result = chdir_become_local_fd(real_fd);
			if (result == 0) {
				working_dir_changed(thread);
			}
			return result;
		}
		case __NR_getcwd: {
			char *buf = (char *)arg1;
			size_t size = (size_t)arg2;
			int real_fd;
			if (lookup_real_fd(CWD_FD, &real_fd)) {
				// readlink the fd remotely
				return remote_readlink_fd(real_fd, buf, size);
			}
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case __NR_ptrace: {
			if (enabled_telemetry & TELEMETRY_TYPE_PTRACE) {
				send_ptrace_attempt_event(thread, (int)arg1, (pid_t)arg2, (void *)arg3, (void *)arg4);
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_process_vm_readv: {
			if (enabled_telemetry & TELEMETRY_TYPE_PTRACE) {
				send_process_vm_readv_attempt_event(thread, (pid_t)arg1, (const struct iovec *)arg2, (unsigned long)arg3, (const struct iovec *)arg4, (unsigned long)arg5, (unsigned long)arg6);
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_process_vm_writev: {
			if (enabled_telemetry & TELEMETRY_TYPE_PTRACE) {
				send_process_vm_writev_attempt_event(thread, (pid_t)arg1, (const struct iovec *)arg2, (unsigned long)arg3, (const struct iovec *)arg4, (unsigned long)arg5, (unsigned long)arg6);
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_socket: {
			return install_local_fd(FS_SYSCALL(__NR_socket, arg1, arg2, arg3), (arg2 & SOCK_CLOEXEC) ? O_CLOEXEC : 0);
		}
		case __NR_connect: {
			struct sockaddr *addr = (struct sockaddr *)arg2;
			union copied_sockaddr copied;
			size_t size = (uintptr_t)arg3;
			if (size > sizeof(copied)) {
				size = sizeof(copied);
			}
			memcpy(&copied, addr, size);
			if (decode_remote_addr(&copied, &size)) {
				int real_fd;
				int result = become_remote_socket(arg1, copied.addr.sa_family, &real_fd);
				if (result < 0) {
					return result;
				}
				return PROXY_CALL(__NR_connect, proxy_value(real_fd), proxy_in(&copied, size), proxy_value(size));
			}
			int real_fd;
			int result = become_local_socket(arg1, &real_fd);
			if (result < 0) {
				return result;
			}
			struct telemetry_sockaddr telemetry;
			memset(&telemetry, 0, sizeof(struct telemetry_sockaddr));
			if (enabled_telemetry & (TELEMETRY_TYPE_CONNECT | TELEMETRY_TYPE_CONNECT_CLOUD | TELEMETRY_TYPE_CONNECT_UNIX) && decode_sockaddr(&telemetry, &copied, size)) {
				// handle TCP first
				if (copied.addr.sa_family == AF_INET || copied.addr.sa_family == AF_INET6) {
					if (enabled_telemetry & TELEMETRY_TYPE_CONNECT) {
						send_connect_attempt_event(thread, arg1, telemetry);
					}
					if (enabled_telemetry & TELEMETRY_TYPE_CONNECT_CLOUD) {
						// only IPv4 to 169.254.129.254:80
						if (copied.addr.sa_family == AF_INET && copied.in.sin_addr.s_addr == fs_htonl(0xa9fea9fe) && copied.in.sin_port == fs_htons(80)) {
							send_connect_aws_attempt_event(thread);
						}
					}
				} else if (copied.addr.sa_family == AF_UNIX) {
					send_connect_unix_attempt_event(thread, (uint64_t *)&telemetry.sun_path, size);
				}
				intptr_t result = FS_SYSCALL(syscall, real_fd, (intptr_t)&copied, size);
				if (enabled_telemetry & TELEMETRY_TYPE_CONNECT) {
					send_connect_result_event(thread, result);
				}
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_bpf: {
			if (enabled_telemetry & TELEMETRY_TYPE_BPF) {
				send_bpf_attempt_event(thread, arg1, (union bpf_attr *)arg2, (unsigned int)arg3);
			}
			switch (arg1) {
				case BPF_PROG_LOAD:
				case BPF_MAP_CREATE:
					return install_local_fd(FS_SYSCALL(syscall, arg1, arg2, arg3), O_CLOEXEC);
				case BPF_MAP_LOOKUP_ELEM:
				case BPF_MAP_UPDATE_ELEM:
				case BPF_MAP_DELETE_ELEM:
				case BPF_MAP_GET_NEXT_KEY:
					return FS_SYSCALL(syscall, arg1, arg2, arg3);
				default:
					return -EINVAL;
			}
		}
		case __NR_brk: {
			intptr_t result = FS_SYSCALL(syscall, arg1);
			if (enabled_telemetry & TELEMETRY_TYPE_BRK) {
				send_brk_result_event(thread, result);
			}
			return result;
		}
		case __NR_ioctl: {
			if (enabled_telemetry & TELEMETRY_TYPE_IOCTL) {
				send_ioctl_attempt_event(thread, (int)arg1, (unsigned long)arg2, arg3);
			}
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				switch (arg2) {
					case TIOCGSID:
					case TIOCGPGRP: {
						// pid_t *out_pgid = (pid_t *)arg3;
						// pid_t result = fs_getpgid(0);
						// if (result < 0) {
						// 	return result;
						// }
						// *out_pgid = result;
						// return 0;
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_out((void *)arg3, sizeof(pid_t)));
					}
					case TIOCSPGRP: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_in((void *)arg3, sizeof(pid_t)));
					}
					case TIOCGLCKTRMIOS:
					case TCGETS: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_out((void *)arg3, sizeof(struct termios)));
					}
					case TIOCSLCKTRMIOS:
					case TCSETS:
					case TCSETSW:
					case TCSETSF: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_in((void *)arg3, sizeof(struct termios)));
					}
					// case TCGETA: {
					// 	return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_out((void *)arg3, sizeof(struct termio)));
					// }
					// case TCSETA:
					// case TCSETAW:
					// case TCSETAF: {
					// 	return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_in((void *)arg3, sizeof(struct termio)));
					// }
					case TIOCGWINSZ: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_out((void *)arg3, sizeof(struct winsize)));
					}
					case TIOCSBRK:
					case TCSBRK:
					case TCXONC:
					case TCFLSH:
					case TIOCSCTTY: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_value(arg3));
					}
					case TIOCCBRK:
					case TIOCCONS:
					case TIOCNOTTY:
					case TIOCEXCL:
					case TIOCNXCL: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2));
					}
					case FIONREAD:
					case TIOCOUTQ:
					case TIOCGETD:
					case TIOCMGET:
					case TIOCGSOFTCAR: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_out((void *)arg3, sizeof(int)));
					}
					case TIOCSETD:
					case TIOCPKT:
					case TIOCMSET:
					case TIOCMBIS:
					case TIOCSSOFTCAR: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_in((void *)arg3, sizeof(int)));
					}
					case TIOCSTI: {
						return PROXY_CALL(syscall | PROXY_NO_WORKER, proxy_value(real_fd), proxy_value(arg2), proxy_in((void *)arg3, sizeof(char)));
					}
				}
				return -EINVAL;
			}
			intptr_t result = FS_SYSCALL(syscall, real_fd, arg2, arg3);
			switch (arg2) {
				case NS_GET_USERNS:
				case NS_GET_PARENT:
					result = install_local_fd(result, O_CLOEXEC);
					break;
			}
			if (result == -ENOSYS && arg2 == TCGETS) {
				// TODO: Figure out why TCGETS returns -ENOSYS when called from
				// the trap, but not when called directly. This is only in test,
				// but something funky is going on.
				result = -ENOTTY;
			}
			return result;
		}
		case __NR_listen: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return PROXY_CALL(syscall, proxy_value(real_fd), proxy_value(arg2));
			}
			if (enabled_telemetry & TELEMETRY_TYPE_LISTEN) {
				send_listen_attempt_event(thread, arg1, arg2);
				intptr_t result = FS_SYSCALL(syscall, arg1, arg2);
				send_listen_result_event(thread, result);
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2);
		}
		case __NR_bind: {
			struct sockaddr *addr = (struct sockaddr *)arg2;
			union copied_sockaddr copied;
			size_t size = (uintptr_t)arg3;
			if (size > sizeof(copied)) {
				size = sizeof(copied);
			}
			memcpy(&copied, addr, size);
			if (decode_remote_addr(&copied, &size)) {
				int real_fd;
				int result = become_remote_socket(arg1, copied.addr.sa_family, &real_fd);
				if (result < 0) {
					return result;
				}
				return PROXY_CALL(__NR_bind, proxy_value(real_fd), proxy_in(&copied, size), proxy_value(size));
			}
			int real_fd;
			int result = become_local_socket(arg1, &real_fd);
			if (result < 0) {
				return result;
			}
			struct telemetry_sockaddr telemetry;
			if (enabled_telemetry & TELEMETRY_TYPE_BIND && (copied.addr.sa_family == AF_INET || copied.addr.sa_family == AF_INET6) && decode_sockaddr(&telemetry, &copied, size)) {
				send_bind_attempt_event(thread, arg1, telemetry);
				intptr_t result = FS_SYSCALL(syscall, real_fd, (intptr_t)&copied, size);
				send_bind_result_event(thread, result);
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_dup: {
			intptr_t result = perform_dup(arg1, 0);
			if (result >= 0) {
				if (enabled_telemetry & TELEMETRY_TYPE_DUP) {
					// emulate a dup3
					send_dup3_attempt_event(thread, arg1, result, 0);
				}
			}
			return result;
		}
#ifdef __NR_dup2
		case __NR_dup2: {
			if (enabled_telemetry & TELEMETRY_TYPE_DUP) {
				send_dup3_attempt_event(thread, arg1, arg2, 0);
			}
			if (arg1 == arg2) {
				return arg1;
			}
			return perform_dup3(arg1, arg2, 0);
		}
#endif
		case __NR_dup3: {
			if (arg1 == arg2) {
				return -EINVAL;
			}
			if (enabled_telemetry & TELEMETRY_TYPE_DUP) {
				send_dup3_attempt_event(thread, arg1, arg2, arg3);
			}
			return perform_dup3(arg1, arg2, arg3);
		}
		case __NR_fcntl: {
			int real_fd;
			switch (arg2) {
				case F_DUPFD: {
					intptr_t result = perform_dup(arg1, 0);
					if ((enabled_telemetry & TELEMETRY_TYPE_DUP) && result >= 0) {
						// emulate a dup3
						send_dup3_attempt_event(thread, arg1, result, arg2 == F_DUPFD_CLOEXEC ? O_CLOEXEC : 0);
					}
					return result;
				}
				case F_DUPFD_CLOEXEC: {
					intptr_t result = perform_dup(arg1, O_CLOEXEC);
					if ((enabled_telemetry & TELEMETRY_TYPE_DUP) && result >= 0) {
						// emulate a dup3
						send_dup3_attempt_event(thread, arg1, result, arg2 == F_DUPFD_CLOEXEC ? O_CLOEXEC : 0);
					}
					return result;
				}
				case F_SETFD:
					return perform_set_fd_flags(arg1, arg3);
				case F_GETFD:
					return perform_get_fd_flags(arg1);
				case F_SETFL:
				case F_GETFL:
				case F_SETLEASE:
				case F_GETLEASE:
				case F_SETPIPE_SZ:
				case F_GETPIPE_SZ:
				case F_ADD_SEALS:
				case F_GET_SEALS: {
					if (lookup_real_fd(arg1, &real_fd)) {
						return remote_fcntl_basic(real_fd, arg2, arg3);
					}
					break;
				}
				case F_GETLK:
				case F_SETLK:
				case F_SETLKW:
				case F_OFD_GETLK:
				case F_OFD_SETLK:
				case F_OFD_SETLKW: {
					if (lookup_real_fd(arg1, &real_fd)) {
						return remote_fcntl_lock(real_fd, arg2, (struct flock *)arg3);
					}
					break;
				}
				default: {
					if (lookup_real_fd(arg1, &real_fd)) {
						// don't know how to proxy this operation
						return -EINVAL;
					}
					break;
				}
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_setrlimit: {
			if (arg1 == RLIMIT_STACK && (enabled_telemetry & TELEMETRY_TYPE_RLIMIT) && arg2) {
				struct rlimit newlimit = *(const struct rlimit *)arg2;
				if (newlimit.rlim_cur == 18446744073709551615ull) {
					send_setrlimit_attempt_event(thread, 0, arg1, &newlimit);
				}
				return FS_SYSCALL(syscall, arg1, (intptr_t)&newlimit);
			}
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case __NR_prlimit64: {
			if (arg2 == RLIMIT_STACK && (enabled_telemetry & TELEMETRY_TYPE_RLIMIT) && arg3) {
				struct rlimit newlimit = *(const struct rlimit *)arg3;
				if (newlimit.rlim_cur == 18446744073709551615ull) {
					send_setrlimit_attempt_event(thread, arg1, arg2, &newlimit);
				}
				return FS_SYSCALL(syscall, arg1, arg2, (intptr_t)&newlimit, arg4);
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4);
		}
		case __NR_userfaultfd: {
			if (enabled_telemetry & TELEMETRY_TYPE_USER_FAULT) {
				send_userfaultfd_attempt_event(thread, arg1);
			}
			return install_local_fd(FS_SYSCALL(syscall, arg1), arg1);
		}
		case __NR_setuid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETUID) {
				send_setuid_attempt_event(thread, arg1);
			}
			return FS_SYSCALL(syscall, arg1);
		}
		case __NR_setreuid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETUID) {
				send_setreuid_attempt_event(thread, arg1, arg2);
			}
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case __NR_setresuid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETUID) {
				uid_t *ruid = (uid_t *)arg1;
				uid_t *euid = (uid_t *)arg2;
				uid_t *suid = (uid_t *)arg3;
				send_setresuid_attempt_event(thread, ruid ? *ruid : (uid_t)-1, euid ? *euid : (uid_t)-1, suid ? *suid : (uid_t)-1);
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3);
		}
		case __NR_setfsuid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETUID) {
				send_setfsuid_attempt_event(thread, arg1);
			}
			return FS_SYSCALL(syscall, arg1);
		}
		case __NR_setgid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETGID) {
				send_setgid_attempt_event(thread, arg1);
			}
			return FS_SYSCALL(syscall, arg1);
		}
		case __NR_setregid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETGID) {
				send_setregid_attempt_event(thread, arg1, arg2);
			}
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case __NR_setresgid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETGID) {
				gid_t *rgid = (gid_t *)arg1;
				gid_t *egid = (gid_t *)arg2;
				gid_t *sgid = (gid_t *)arg3;
				send_setresgid_attempt_event(thread, rgid ? *rgid : (gid_t)-1, egid ? *egid : (gid_t)-1, sgid ? *sgid : (gid_t)-1);
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3);
		}
		case __NR_setfsgid: {
			if (enabled_telemetry & TELEMETRY_TYPE_SETGID) {
				send_setfsgid_attempt_event(thread, arg1);
			}
			return FS_SYSCALL(syscall, arg1);
		}
		case __NR_sendto: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return remote_sendto(real_fd, (const void *)arg2, arg3, arg4, (const struct sockaddr *)arg5, arg6);
			}
			struct sockaddr *addr = (struct sockaddr *)arg5;
			union copied_sockaddr copied;
			size_t size = (uintptr_t)arg6;
			if (size > sizeof(copied)) {
				size = sizeof(copied);
			}
			memcpy(&copied, addr, size);
			struct telemetry_sockaddr telemetry;
			if (enabled_telemetry & TELEMETRY_TYPE_SENDTO && (copied.addr.sa_family == AF_INET || copied.addr.sa_family == AF_INET6) && decode_sockaddr(&telemetry, &copied, size)) {
				send_sendto_attempt_event(thread, arg1, telemetry);
				intptr_t result = FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, (intptr_t)&copied, size);
				send_sendto_result_event(thread, result);
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5, arg6);
		}
		case __NR_mprotect: {
			if (enabled_telemetry & TELEMETRY_TYPE_MEMORY_PROTECTION && arg3 & PROT_EXEC) {
				send_mprotect_attempt_event(thread, (void *)arg1, arg2, arg3);
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3);
		}
#ifdef __NR_accept4
		case __NR_accept4: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				struct sockaddr *addr = (struct sockaddr *)arg2;
				socklen_t *len = (socklen_t *)arg3;
				return install_remote_fd(PROXY_CALL(__NR_accept4, proxy_value(real_fd), proxy_out(addr, len ? *len : 0), proxy_inout(len, sizeof(*len)), proxy_value(arg4 | O_CLOEXEC)), (arg4 & SOCK_CLOEXEC) ? O_CLOEXEC : 0);
			}
			if (enabled_telemetry & TELEMETRY_TYPE_ACCEPT) {
				send_accept_attempt_event(thread, arg1);
				int result = FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
				send_accept_result_event(thread, result);
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
#endif
		case __NR_accept: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				struct sockaddr *addr = (struct sockaddr *)arg2;
				socklen_t *len = (socklen_t *)arg3;
				return install_remote_fd(PROXY_CALL(__NR_accept, proxy_value(real_fd), proxy_out(addr, len ? *len : 0), proxy_inout(len, sizeof(*len))), 0);
			}
			if (enabled_telemetry & TELEMETRY_TYPE_ACCEPT) {
				send_accept_attempt_event(thread, arg1);
				int result = FS_SYSCALL(syscall, real_fd, arg2, arg3);
				send_accept_result_event(thread, result);
				return result;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_read: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return remote_read(real_fd, (char *)arg2, arg3);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_write: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return remote_write(real_fd, (const char *)arg2, arg3);
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_semget:
		case __NR_shmget: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2, arg3), 0);
		}
		case __NR_perf_event_open: {
			int arg2_fd;
			if (arg5 & PERF_FLAG_PID_CGROUP) {
				if (lookup_real_fd(arg2, &arg2_fd)) {
					return -EBADF;
				}
			} else {
				arg2_fd = arg2;
			}
			int arg4_fd;
			if (lookup_real_fd(arg4, &arg4_fd)) {
				return -EBADF;
			}
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2_fd, arg3, arg4_fd, arg5), arg5 & PERF_FLAG_FD_CLOEXEC ? O_CLOEXEC : 0);
		}
		case __NR_kexec_file_load: {
			int kernel_fd;
			int initrd_fd;
			if (lookup_real_fd(arg1, &kernel_fd) || lookup_real_fd(arg2, &initrd_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, kernel_fd, initrd_fd, arg3, arg4, arg5);
		}
		case __NR_pidfd_open: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), O_CLOEXEC);
		}
		case __NR_pidfd_send_signal: {
			int real_fd;
			if (lookup_real_fd(arg1, &real_fd)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
		}
#ifdef __NR_pidfd_getfd
		case __NR_pidfd_getfd: {
			// disable pidfd_getfd because it's impossible
			return -ENOSYS;
		}
#endif
		case __NR_io_uring_setup:
		case __NR_io_uring_enter:
		case __NR_io_uring_register: {
			// disable io_uring because it's not possible to proxy it
			return -ENOSYS;
		}
		case __NR_open_tree: {
			int dirfd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(dirfd, path, &real)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, arg1, arg2, arg3);
		}
		case __NR_move_mount: {
			int from_dirfd = arg1;
			const char *from_path = (const char *)arg2;
			path_info from_real;
			bool from_is_remote = lookup_real_path(from_dirfd, from_path, &from_real);
			int to_dirfd = arg3;
			const char *to_path = (const char *)arg4;
			path_info to_real;
			bool to_is_remote = lookup_real_path(to_dirfd, to_path, &to_real);
			if (from_is_remote != to_is_remote) {
				return -EINVAL;
			}
			if (from_is_remote) {
				return PROXY_CALL(syscall, proxy_value(from_real.fd), proxy_string(from_real.path), proxy_value(to_real.fd), proxy_string(to_real.path), proxy_value(arg5));
			}
			return FS_SYSCALL(syscall, from_real.fd, (intptr_t)from_real.path, to_real.fd, (intptr_t)to_real.path, arg5);
		}
		case __NR_fsopen: {
			const char *fsname = (const char *)arg1;
			path_info real;
			bool is_remote = lookup_real_path(AT_FDCWD, fsname, &real);
			if (real.fd != AT_FDCWD) {
				return -EINVAL;
			}
			if (is_remote) {
				return install_remote_fd(PROXY_CALL(syscall, proxy_string(real.path), proxy_value(arg2)), (arg2 & FSOPEN_CLOEXEC) ? O_CLOEXEC : 0);
			}
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), (arg2 & FSOPEN_CLOEXEC) ? O_CLOEXEC : 0);
		}
		case __NR_fsconfig: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(syscall, proxy_value(real_fd), proxy_value(arg2), proxy_string((const char *)arg3), proxy_string((const char *)arg4), proxy_value(arg5));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4, arg5);
		}
		case __NR_fsmount: {
			int fd = arg1;
			int real_fd;
			if (lookup_real_fd(fd, &real_fd)) {
				return PROXY_CALL(syscall, proxy_value(real_fd), proxy_value(arg2), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, real_fd, arg2, arg3);
		}
		case __NR_fspick: {
			int fd = arg1;
			const char *path = (const char *)arg2;
			path_info real;
			if (lookup_real_path(fd, path, &real)) {
				return PROXY_CALL(syscall, proxy_value(real.fd), proxy_string(real.path), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, real.fd, (intptr_t)real.path, arg3);
		}
	}
	return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
}
