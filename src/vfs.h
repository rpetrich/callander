#ifndef VFS_H
#define VFS_H

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <sys/types.h>

#include "axon.h"
#include "fd_table.h"
#include "freestanding.h"
#include "linux.h"
#include "paths.h"
#include "proxy.h"
#include "sockets.h"

struct vfs_resolved_file
{
	const struct vfs_file_ops *ops;
	intptr_t handle;
};

struct vfs_poll_resolved_file
{
	struct vfs_resolved_file file;
	short events;
	short revents;
};

struct thread_storage;

// intptr_t remote_socket(int domain, int type, int protocol);

struct vfs_file_ops
{
	intptr_t (*socket)(struct thread_storage *, int domain, int type, int protocol, struct vfs_resolved_file *out_file);

	intptr_t (*close)(struct vfs_resolved_file);
	intptr_t (*read)(struct thread_storage *, struct vfs_resolved_file, char *buf, size_t bufsz);
	intptr_t (*write)(struct thread_storage *, struct vfs_resolved_file, const char *buf, size_t bufsz);
	intptr_t (*recvfrom)(struct thread_storage *, struct vfs_resolved_file, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
	intptr_t (*sendto)(struct thread_storage *, struct vfs_resolved_file, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
	intptr_t (*lseek)(struct thread_storage *, struct vfs_resolved_file, off_t offset, int whence);
	intptr_t (*fadvise64)(struct thread_storage *, struct vfs_resolved_file, size_t offset, size_t len, int advice);
	intptr_t (*readahead)(struct thread_storage *, struct vfs_resolved_file, off_t offset, size_t count);
	intptr_t (*pread)(struct thread_storage *, struct vfs_resolved_file, void *buf, size_t count, off_t offset);
	intptr_t (*pwrite)(struct thread_storage *, struct vfs_resolved_file, const void *buf, size_t count, off_t offset);
	intptr_t (*flock)(struct thread_storage *, struct vfs_resolved_file, int how);
	intptr_t (*fsync)(struct thread_storage *, struct vfs_resolved_file);
	intptr_t (*fdatasync)(struct thread_storage *, struct vfs_resolved_file);
	intptr_t (*syncfs)(struct thread_storage *, struct vfs_resolved_file);
	intptr_t (*sync_file_range)(struct thread_storage *, struct vfs_resolved_file, off_t offset, off_t nbytes, unsigned int flags);
	intptr_t (*ftruncate)(struct thread_storage *, struct vfs_resolved_file, off_t length);
	intptr_t (*fallocate)(struct thread_storage *, struct vfs_resolved_file, int mode, off_t offset, off_t len);
	intptr_t (*recvmsg)(struct thread_storage *, struct vfs_resolved_file, struct msghdr *msg, int flags);
	intptr_t (*sendmsg)(struct thread_storage *, struct vfs_resolved_file, const struct msghdr *msg, int flags);
	intptr_t (*fcntl_basic)(struct thread_storage *, struct vfs_resolved_file, int cmd, intptr_t argument);
	intptr_t (*fcntl_lock)(struct thread_storage *, struct vfs_resolved_file, int cmd, struct flock *lock);
	intptr_t (*fcntl_int)(struct thread_storage *, struct vfs_resolved_file, int cmd, int *value);
	intptr_t (*fcntl)(struct thread_storage *, struct vfs_resolved_file, unsigned int cmd, unsigned long arg);
	intptr_t (*fchmod)(struct thread_storage *, struct vfs_resolved_file, mode_t mode);
	intptr_t (*fchown)(struct thread_storage *, struct vfs_resolved_file, uid_t owner, gid_t group);
	intptr_t (*fstat)(struct thread_storage *, struct vfs_resolved_file, struct fs_stat *out_stat);
	intptr_t (*fstatfs)(struct thread_storage *, struct vfs_resolved_file, struct fs_statfs *out_buf);
	intptr_t (*readlink_fd)(struct thread_storage *, struct vfs_resolved_file, char *buf, size_t size);
	intptr_t (*getdents)(struct thread_storage *, struct vfs_resolved_file, char *buf, size_t size);
	intptr_t (*getdents64)(struct thread_storage *, struct vfs_resolved_file, char *buf, size_t size);
	intptr_t (*fgetxattr)(struct thread_storage *, struct vfs_resolved_file, const char *name, void *out_value, size_t size);
	intptr_t (*fsetxattr)(struct thread_storage *, struct vfs_resolved_file, const char *name, const void *value, size_t size, int flags);
	intptr_t (*fremovexattr)(struct thread_storage *, struct vfs_resolved_file, const char *name);
	intptr_t (*flistxattr)(struct thread_storage *, struct vfs_resolved_file, void *out_value, size_t size);
	intptr_t (*connect)(struct thread_storage *, struct vfs_resolved_file, const struct sockaddr *addr, size_t size);
	intptr_t (*bind)(struct thread_storage *, struct vfs_resolved_file, const struct sockaddr *addr, size_t size);
	intptr_t (*listen)(struct thread_storage *, struct vfs_resolved_file, int backlog);
	intptr_t (*accept4)(struct thread_storage *, struct vfs_resolved_file, struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags, struct vfs_resolved_file *out_file);
	intptr_t (*getsockopt)(struct thread_storage *, struct vfs_resolved_file, int level, int optname, void *restrict optval, socklen_t *restrict optlen);
	intptr_t (*setsockopt)(struct thread_storage *, struct vfs_resolved_file, int level, int optname, const void *optval, socklen_t optlen);
	intptr_t (*getsockname)(struct thread_storage *, struct vfs_resolved_file, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
	intptr_t (*getpeername)(struct thread_storage *, struct vfs_resolved_file, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
	intptr_t (*shutdown)(struct thread_storage *, struct vfs_resolved_file, int how);
	intptr_t (*sendfile)(struct thread_storage *, struct vfs_resolved_file out, struct vfs_resolved_file in, off_t *offset, size_t size);
	intptr_t (*splice)(struct thread_storage *, struct vfs_resolved_file in, off_t *off_in, struct vfs_resolved_file out, off_t *off_out, size_t size, unsigned int flags);
	intptr_t (*tee)(struct thread_storage *, struct vfs_resolved_file in, struct vfs_resolved_file out, size_t len, unsigned int flags);
	intptr_t (*copy_file_range)(struct thread_storage *, struct vfs_resolved_file in, uint64_t *off_in, struct vfs_resolved_file out, uint64_t *off_out, size_t len, unsigned int flags);
	intptr_t (*ioctl)(struct thread_storage *, struct vfs_resolved_file, unsigned int cmd, unsigned long arg);
	intptr_t (*ioctl_open_file)(struct thread_storage *, struct vfs_resolved_file, unsigned int cmd, unsigned long arg, struct vfs_resolved_file *out_file);
	intptr_t (*ppoll)(struct thread_storage *, struct vfs_poll_resolved_file *files, nfds_t nfiles, struct timespec *timeout, const sigset_t *sigmask);
	intptr_t (*mmap)(struct thread_storage *, struct vfs_resolved_file, void *addr, size_t length, int prot, int flags, size_t offset);
};

struct vfs_resolved_path
{
	const struct vfs_path_ops *ops;
	path_info info;
};

struct vfs_path_ops
{
	const struct vfs_file_ops dirfd_ops;
	intptr_t (*mkdirat)(struct thread_storage *, struct vfs_resolved_path, mode_t mode);
	intptr_t (*mknodat)(struct thread_storage *, struct vfs_resolved_path, mode_t mode, dev_t dev);
	intptr_t (*openat)(struct thread_storage *, struct vfs_resolved_path, int flags, mode_t mode, struct vfs_resolved_file *out_file);
	intptr_t (*unlinkat)(struct thread_storage *, struct vfs_resolved_path, int flags);
	intptr_t (*renameat2)(struct thread_storage *, struct vfs_resolved_path old, struct vfs_resolved_path new, int flags);
	intptr_t (*linkat)(struct thread_storage *, struct vfs_resolved_path old, struct vfs_resolved_path new, int flags);
	intptr_t (*symlinkat)(struct thread_storage *, struct vfs_resolved_path new, const char *old);
	intptr_t (*truncate)(struct thread_storage *, struct vfs_resolved_path, off_t length);
	intptr_t (*fchmodat)(struct thread_storage *, struct vfs_resolved_path, mode_t mode, int flags);
	intptr_t (*fchownat)(struct thread_storage *, struct vfs_resolved_path, uid_t owner, gid_t group, int flags);
	intptr_t (*utimensat)(struct thread_storage *, struct vfs_resolved_path, const struct timespec times[2], int flags);
	intptr_t (*newfstatat)(struct thread_storage *, struct vfs_resolved_path, struct fs_stat *out_stat, int flags);
	intptr_t (*statx)(struct thread_storage *, struct vfs_resolved_path, int flags, unsigned int mask, struct linux_statx *restrict statxbuf);
	intptr_t (*statfs)(struct thread_storage *, struct vfs_resolved_path, struct fs_statfs *out_buf);
	intptr_t (*faccessat)(struct thread_storage *, struct vfs_resolved_path, int mode, int flag);
	intptr_t (*readlinkat)(struct thread_storage *, struct vfs_resolved_path, char *buf, size_t bufsz);
	intptr_t (*getxattr)(struct thread_storage *, struct vfs_resolved_path, const char *name, void *out_value, size_t size, int flags);
	intptr_t (*setxattr)(struct thread_storage *, struct vfs_resolved_path, const char *name, const void *value, size_t size, int flags);
	intptr_t (*removexattr)(struct thread_storage *, struct vfs_resolved_path, const char *name, int flags);
	intptr_t (*listxattr)(struct thread_storage *, struct vfs_resolved_path, void *out_value, size_t size, int flags);
};

extern const struct vfs_path_ops local_path_ops;

static inline const struct vfs_path_ops *vfs_path_ops_for_remote(void)
{
	extern const struct vfs_path_ops linux_path_ops;
	extern const struct vfs_path_ops darwin_path_ops;
	extern const struct vfs_path_ops windows_path_ops;
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return &linux_path_ops;
		case TARGET_PLATFORM_DARWIN:
			return &darwin_path_ops;
		case TARGET_PLATFORM_WINDOWS:
			return &windows_path_ops;
		default:
			unknown_target();
	}
}

__attribute__((always_inline)) static inline const struct vfs_file_ops *vfs_file_ops_for_remote(void)
{
	return &vfs_path_ops_for_remote()->dirfd_ops;
}

static inline struct vfs_resolved_file vfs_resolve_file(int fd)
{
	struct vfs_resolved_file result;
	result.ops = lookup_real_fd(fd, &result.handle) ? vfs_file_ops_for_remote() : &local_path_ops.dirfd_ops;
	return result;
}

static inline bool vfs_is_remote_file(const struct vfs_resolved_file *file)
{
	return file->ops != &local_path_ops.dirfd_ops;
}

static inline struct vfs_resolved_path vfs_resolve_path(int fd, const char *path)
{
	struct vfs_resolved_path result;
	result.ops = lookup_real_path(fd, path, &result.info) ? vfs_path_ops_for_remote() : &local_path_ops;
	return result;
}

static inline bool vfs_is_remote_path(const struct vfs_resolved_path *path)
{
	return path->ops != &local_path_ops;
}

static inline struct vfs_resolved_file vfs_get_dir_file(struct vfs_resolved_path resolved)
{
	return (struct vfs_resolved_file){
		.handle = resolved.info.handle,
		.ops = &resolved.ops->dirfd_ops,
	};
}

static inline intptr_t vfs_install_file(intptr_t result, const struct vfs_resolved_file *file, int flags)
{
	if (result < 0) {
		return result;
	}
	if (file->ops == &local_path_ops.dirfd_ops) {
		return install_local_fd(file->handle, flags);
	}
	return install_remote_fd(file->handle, flags);
}

#define vfs_call(name, target, ...)                                                                                \
	({                                                                                                             \
		__typeof__(target) _target = target;                                                                       \
		LIKELY(_target.ops->name != NULL) ? _target.ops->name(thread, _target, ##__VA_ARGS__) : (intptr_t)-ENOSYS; \
	})

intptr_t vfs_truncate_via_open_and_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length);

intptr_t vfs_mmap_via_pread(struct thread_storage *thread, struct vfs_resolved_file file, void *addr, size_t length, int prot, int flags, size_t offset);

intptr_t vfs_assemble_simple_path(struct thread_storage *thread, struct vfs_resolved_path resolved, char buf[PATH_MAX], const char **out_path);

struct attempt_cleanup_state;
void vfs_attempt_push_close(struct thread_storage *thread, struct attempt_cleanup_state *state, const struct vfs_resolved_file *file);
void vfs_attempt_pop_close(struct attempt_cleanup_state *state);

static inline intptr_t vfs_resolve_socket_and_addr(struct thread_storage *thread, int fd, const struct sockaddr **addr, size_t *size, struct vfs_resolved_file *out_file, union copied_sockaddr *buf)
{
	struct vfs_resolved_file file = vfs_resolve_file(fd);
	if (*addr == NULL) {
		*out_file = file;
		return 0;
	}
	if (*size > sizeof(*buf)) {
		return -EINVAL;
	}
	memcpy(buf, *addr, *size);
	*addr = &buf->addr;
	bool is_remote = decode_target_addr(buf, size);
	const struct vfs_file_ops *ops = is_remote ? vfs_file_ops_for_remote() : &local_path_ops.dirfd_ops;
	if (ops == file.ops) {
		*out_file = file;
		return 0;
	}
	if (ops->socket == NULL) {
		return -EINVAL;
	}
	int domain;
	socklen_t optlen = sizeof(domain);
	intptr_t result = vfs_call(getsockopt, file, SOL_SOCKET, SO_DOMAIN, &domain, &optlen);
	if (result < 0) {
		return result;
	}
	int type;
	optlen = sizeof(type);
	result = vfs_call(getsockopt, file, SOL_SOCKET, SO_TYPE, &type, &optlen);
	if (result < 0) {
		return result;
	}
	int protocol;
	optlen = sizeof(protocol);
	result = vfs_call(getsockopt, file, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen);
	if (result < 0) {
		return result;
	}
	result = ops->socket(thread, domain, type | SOCK_CLOEXEC, protocol, &file);
	if (result < 0) {
		return result;
	}
	result = is_remote ? become_remote_fd(fd, result) : become_local_fd(fd, result);
	if (result < 0) {
		file.ops->close(file);
		return result;
	}
	*out_file = file;
	return 0;
}

#endif
