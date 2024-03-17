#ifndef VFS_H
#define VFS_H

#include <errno.h>
#include <stdint.h>

#include "fd_table.h"
#include "freestanding.h"
#include "linux.h"
#include "paths.h"

struct vfs_resolved_file {
	const struct vfs_file_ops *ops;
	int handle;
};

struct thread_storage;

// intptr_t remote_socket(int domain, int type, int protocol);

struct vfs_file_ops {
	intptr_t (*close)(struct thread_storage *, struct vfs_resolved_file);
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
	intptr_t (*fchmod)(struct thread_storage *, struct vfs_resolved_file, mode_t mode);
	intptr_t (*fchown)(struct thread_storage *, struct vfs_resolved_file, uid_t owner, gid_t group);
	intptr_t (*fstat)(struct thread_storage *, struct vfs_resolved_file, struct fs_stat *out_stat);
	intptr_t (*fstatfs)(struct thread_storage *, struct vfs_resolved_file, struct fs_statfs *out_buf);
	// intptr_t (*readlink_fd)(struct thread_storage *, struct vfs_resolved_file, char *buf, size_t size);
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
	intptr_t (*copy_file_range)(struct thread_storage *, struct vfs_resolved_file in, off64_t *off_in, struct vfs_resolved_file out, off64_t *off_out, size_t len, unsigned int flags);
	// intptr_t remote_poll(struct pollfd *fds, nfds_t nfds, int timeout);
	// intptr_t remote_ppoll(struct pollfd *fds, nfds_t nfds, struct timespec *timeout);
};

struct vfs_resolved_path {
	const struct vfs_path_ops *ops;
	path_info info;
};

struct vfs_path_ops {
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

extern struct vfs_file_ops local_file_ops;
extern struct vfs_path_ops local_path_ops;

extern struct vfs_file_ops remote_file_ops;
extern struct vfs_path_ops remote_path_ops;

static inline struct vfs_resolved_file vfs_resolve_file(int fd)
{
	struct vfs_resolved_file result;
	result.ops = lookup_real_fd(fd, &result.handle) ? &remote_file_ops : &local_file_ops;
	return result;
}

static inline struct vfs_resolved_path vfs_resolve_path(int fd, const char *path)
{
	struct vfs_resolved_path result;
	result.ops = lookup_real_path(fd, path, &result.info) ? &remote_path_ops : &local_path_ops;
	return result;
}

static inline intptr_t vfs_install_file(intptr_t result, const struct vfs_resolved_file *file, int flags)
{
	if (result < 0) {
		return result;
	}
	if (file->ops == &local_file_ops) {
		return install_local_fd(file->handle, flags);
	}
	return install_remote_fd(file->handle, flags);
}

#define vfs_call(name, target, ...) ({ __typeof__(target) _target = target; _target.ops->name != NULL ? _target.ops->name(thread, _target, ##__VA_ARGS__) : (intptr_t)-ENOSYS; })

intptr_t vfs_truncate_via_open_and_ftruncate(__attribute__((unused)) struct thread_storage *thread, struct vfs_resolved_path resolved, off_t length);

#endif
