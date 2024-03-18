#include "fd_table.h"

#include "darwin.h"
#include "freestanding.h"
#include "axon.h"
#include "proxy.h"
#include "vfs.h"

#include <errno.h>

#define vfs_remote_close(remote_fd) ({ \
	const struct vfs_file_ops *ops = vfs_file_ops_for_remote(); \
	ops->close((struct vfs_resolved_file){ .ops = ops, .handle = remote_fd }); \
})

int fd_table[MAX_TABLE_SIZE];
static struct fs_mutex table_lock;

void initialize_fd_table(void)
{
	struct fd_state *states = get_fd_states();
	int null = fs_open("/dev/null", O_RDONLY, 0);
	if (null < 0) {
		DIE("error opening /dev/null", fs_strerror(null));
	}
	int result = fs_dup3(null, DEAD_FD, 0);
	if (result < 0) {
		DIE("error duping /dev/null", fs_strerror(result));
	}
	result = fs_close(null);
	if (result < 0) {
		DIE("error closing", fs_strerror(result));
	}
	result = fs_dup3(DEAD_FD, CWD_FD, 0);
	if (result < 0) {
		DIE("error duping cwd", fs_strerror(result));
	}
	fd_table[CWD_FD] = HAS_LOCAL_FD;
#if 0
	// duplicate local standard err and standard out
	result = fs_dup3(0, 3, 0);
	if (result < 0) {
		DIE("error duping to 3", fs_strerror(result));
	}
	fd_table[3] = HAS_LOCAL_FD;
	result = fs_dup3(1, 4, 0);
	if (result < 0) {
		DIE("error duping to 4", fs_strerror(result));
	}
	fd_table[4] = HAS_LOCAL_FD;
	result = fs_dup3(2, 5, 0);
	if (result < 0) {
		DIE("error duping to 5", fs_strerror(result));
	}
	fd_table[5] = HAS_LOCAL_FD;
	// setup remote standard in, standard out and standard error
	fd_table[0] = (0 << USED_BITS) | HAS_REMOTE_FD;
	states[0].count = 2;
	result = fs_dup3(DEAD_FD, 0, 0);
	if (result < 0) {
		DIE("error duping to 0", fs_strerror(result));
	}
	fd_table[1] = (1 << USED_BITS) | HAS_REMOTE_FD;
	states[1].count = 2;
	result = fs_dup3(DEAD_FD, 1, 0);
	if (result < 0) {
		DIE("error duping to 1", fs_strerror(result));
	}
	fd_table[2] = (2 << USED_BITS) | HAS_REMOTE_FD;
	states[2].count = 2;
	result = fs_dup3(DEAD_FD, 2, 0);
	if (result < 0) {
		DIE("error duping to 2", fs_strerror(result));
	}
#else
	// setup standard in, standard out and standard error
	fd_table[0] = HAS_LOCAL_FD;
	fd_table[1] = HAS_LOCAL_FD;
	fd_table[2] = HAS_LOCAL_FD;
	// duplicate remote standard err and standard out
	result = fs_dup3(DEAD_FD, 3, 0);
	if (result < 0) {
		DIE("error duping to 3", fs_strerror(result));
	}
	fd_table[3] = (0 << USED_BITS) | HAS_REMOTE_FD;
	states[0].count = 2;
	result = fs_dup3(DEAD_FD, 4, 0);
	if (result < 0) {
		DIE("error duping to 4", fs_strerror(result));
	}
	fd_table[4] = (1 << USED_BITS) | HAS_REMOTE_FD;
	states[1].count = 2;
	result = fs_dup3(DEAD_FD, 5, 0);
	if (result < 0) {
		DIE("error duping to 4", fs_strerror(result));
	}
	fd_table[5] = (2 << USED_BITS) | HAS_REMOTE_FD;
	states[2].count = 2;
#endif
}

static void serialize_fd_table(int new_table[MAX_TABLE_SIZE]) {
	int memfd = fs_memfd_create("fdtable", 0);
	if (memfd < 0) {
		DIE("error creating memfd", fs_strerror(memfd));
	}
	int result = fs_pwrite(memfd, (char *)new_table, sizeof(fd_table), 0);
	if (result < 0) {
		DIE("error writing fd table", fs_strerror(result));
	}	
	result = fs_dup3(memfd, TABLE_FD, 0);
	if (result < 0) {
		DIE("error duping memfd", fs_strerror(result));
	}	
	result = fs_close(memfd);
	if (result < 0) {
		DIE("error closing", fs_strerror(result));
	}
}

void serialize_fd_table_for_exec(void)
{
	struct fd_state *states = get_fd_states();
	fs_mutex_lock(&table_lock);
	int copy[MAX_TABLE_SIZE];
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		int value = fd_table[i];
		if (value & HAS_CLOEXEC) {
			if ((value & HAS_REMOTE_FD)) {
				int remote_fd = value >> USED_BITS;
				if (atomic_fetch_sub_explicit(&states[remote_fd].count, 1, memory_order_relaxed) == 1) {
					vfs_remote_close(remote_fd);
				}
			}
			value = 0;
		}
		copy[i] = value;
	}
	serialize_fd_table(copy);
}

void serialize_fd_table_for_fork(void)
{
	struct fd_state *states = get_fd_states();
	fs_mutex_lock(&table_lock);
	int copy[MAX_TABLE_SIZE];
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		int value = fd_table[i];
		if (value & HAS_REMOTE_FD) {
			int remote_fd = value >> USED_BITS;
			atomic_fetch_add_explicit(&states[remote_fd].count, 1, memory_order_relaxed);
		}
		copy[i] = value;
	}
	serialize_fd_table(copy);
}

void finish_fd_table_fork(void)
{
	fs_mutex_unlock(&table_lock);
}

void resurrect_fd_table(void)
{
	int result = fs_pread_all(TABLE_FD, (char *)&fd_table, sizeof(fd_table), 0);
	if (result <= 0) {
		DIE("error reading fd table", fs_strerror(result));
	}
	result = fs_close(TABLE_FD);
	if (result < 0) {
		DIE("error closing", fs_strerror(result));
	}
}

void clear_fd_table_for_exit(__attribute__((unused)) int status)
{
	struct fd_state *states = get_fd_states();
	fs_mutex_lock(&table_lock);
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		int value = fd_table[i];
		if (value) {
			if (value & HAS_REMOTE_FD) {
				int remote_fd = value >> USED_BITS;
				if (atomic_fetch_sub_explicit(&states[remote_fd].count, 1, memory_order_relaxed) == 1) {
					vfs_remote_close(remote_fd);
				}
			}
			// fs_close(i);
			fd_table[i] = 0;
		}
	}
	fs_mutex_unlock(&table_lock);
}

__attribute__((warn_unused_result))
int install_local_fd(int fd, int flags)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		fd_table[fd] = HAS_LOCAL_FD | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
		fs_mutex_unlock(&table_lock);
	}
	return fd;
}

__attribute__((warn_unused_result))
int install_remote_fd(int remote_fd, int flags)
{
	if (remote_fd < 0) {
		return remote_fd;
	}
	fs_mutex_lock(&table_lock);
	int result = fs_fcntl(DEAD_FD, flags & O_CLOEXEC ? F_DUPFD_CLOEXEC : F_DUPFD, 0);
	if (result >= 0) {
		if (result >= MAX_TABLE_SIZE) {
			fs_mutex_unlock(&table_lock);
			vfs_remote_close(remote_fd);
			fs_close(result);
			return -EMFILE;
		}
		fd_table[result] = (remote_fd << USED_BITS) | HAS_REMOTE_FD | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
		struct fd_state *states = get_fd_states();
		atomic_fetch_add_explicit(&states[remote_fd].count, 1, memory_order_relaxed);
		fs_mutex_unlock(&table_lock);
	} else {
		fs_mutex_unlock(&table_lock);
		vfs_remote_close(remote_fd);
	}
	return result;
}

int become_remote_fd(int fd, int remote_fd) {
	if (remote_fd < 0) {
		return remote_fd;
	}
	if (fd > MAX_TABLE_SIZE || fd < 0) {
		vfs_remote_close(remote_fd);
		return -EMFILE;
	}
	fs_mutex_lock(&table_lock);
	int existing = fd_table[fd];
	if (existing == 0) {
		fs_mutex_unlock(&table_lock);
		vfs_remote_close(remote_fd);
		return -EINVAL;
	}
	struct fd_state *states = get_fd_states();
	if (existing & HAS_REMOTE_FD) {
		int old_remote_fd = existing >> USED_BITS;
		if (old_remote_fd == remote_fd) {
			fs_mutex_unlock(&table_lock);
			return 0;
		}
		if (atomic_fetch_sub_explicit(&states[old_remote_fd].count, 1, memory_order_relaxed) == 1) {
			vfs_remote_close(old_remote_fd);
		}
	} else {
		int result = fs_dup3(DEAD_FD, fd, (existing & HAS_CLOEXEC) ? O_CLOEXEC : 0);
		if (result < 0) {
			fs_mutex_unlock(&table_lock);
			vfs_remote_close(remote_fd);
			return -EINVAL;
		}
	}
	atomic_fetch_add_explicit(&states[remote_fd].count, 1, memory_order_relaxed);
	fd_table[fd] = (remote_fd << USED_BITS) | HAS_REMOTE_FD | (existing & HAS_CLOEXEC);
	fs_mutex_unlock(&table_lock);
	return 0;
}

int become_local_fd(int fd, int local_fd)
{
	// TODO: preserve O_CLOEXEC status
	int result = perform_dup3(local_fd, fd, O_CLOEXEC);
	if (result >= 0) {
		fs_close(local_fd);
	}
	return result;
}

__attribute__((warn_unused_result))
bool lookup_real_fd(int fd, intptr_t *out_real_fd)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		if (fd_table[fd] & HAS_REMOTE_FD) {
			*out_real_fd = fd_table[fd] >> USED_BITS;
			fs_mutex_unlock(&table_lock);
			return true;
		}
		fs_mutex_unlock(&table_lock);
	}
	*out_real_fd = fd;
	return false;
}

int perform_close(int fd)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		int value = fd_table[fd];
		if (value) {
			if (value & HAS_REMOTE_FD) {
				int remote_fd = value >> USED_BITS;
				struct fd_state *states = get_fd_states();
				if (atomic_fetch_sub_explicit(&states[remote_fd].count, 1, memory_order_relaxed) == 1) {
					vfs_remote_close(remote_fd);
				}
			}
			fd_table[fd] = 0;
			int result = fs_close(fd);
			fs_mutex_unlock(&table_lock);
			return result;
		}
		fs_mutex_unlock(&table_lock);
		return -EBADF;
	}
	return fs_close(fd);
}

__attribute__((warn_unused_result))
int perform_dup(int oldfd, int flags)
{
	if (oldfd < MAX_TABLE_SIZE && oldfd >= 0) {
		fs_mutex_lock(&table_lock);
		int old = fd_table[oldfd];
		if (!old) {
			fs_mutex_unlock(&table_lock);
			return -EBADF;
		}
		int result = fs_fcntl(oldfd, flags & O_CLOEXEC ? F_DUPFD_CLOEXEC : F_DUPFD, 0);
		if (result >= MAX_TABLE_SIZE) {
			fs_close(result);
			fs_mutex_unlock(&table_lock);
			return -EMFILE;
		}
		if (result < 0) {
			fs_mutex_unlock(&table_lock);
			return result;
		}
		fd_table[result] = (old & ~HAS_CLOEXEC) | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
		if (old & HAS_REMOTE_FD) {
			struct fd_state *states = get_fd_states();
			atomic_fetch_add_explicit(&states[old >> USED_BITS].count, 1, memory_order_relaxed);
		}
		fs_mutex_unlock(&table_lock);
		return result;
	}
	return fs_dup(oldfd);
}

__attribute__((warn_unused_result))
int perform_dup3(int oldfd, int newfd, int flags)
{
	if (oldfd < MAX_TABLE_SIZE && oldfd >= 0) {
		fs_mutex_lock(&table_lock);
		int old = fd_table[oldfd];
		if (!old) {
			fs_mutex_unlock(&table_lock);
			return -EBADF;
		}
		int result = fs_dup3(oldfd, newfd, flags);
		if (result >= MAX_TABLE_SIZE) {
			fs_close(result);
			fs_mutex_unlock(&table_lock);
			return -EMFILE;
		}
		if (result < 0) {
			fs_mutex_unlock(&table_lock);
			return result;
		}
		int old_table_value = fd_table[result];
		fd_table[result] = (old & ~HAS_CLOEXEC) | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
		struct fd_state *states = get_fd_states();
		if (old & HAS_REMOTE_FD) {
			atomic_fetch_add_explicit(&states[old >> USED_BITS].count, 1, memory_order_relaxed);
		}
		if (old_table_value & HAS_REMOTE_FD) {
			int remote_fd = old_table_value >> USED_BITS;
			if (atomic_fetch_sub_explicit(&states[remote_fd].count, 1, memory_order_relaxed) == 1) {
				vfs_remote_close(remote_fd);
			}
		}
		fs_mutex_unlock(&table_lock);
		return result;
	}
	return fs_dup3(oldfd, newfd, flags);
}

int perform_set_fd_flags(int fd, int flags)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		intptr_t result = FS_SYSCALL(__NR_fcntl, fd, F_SETFD, flags);
		if (result >= 0) {
			int old = fd_table[fd];
			if (old) {
				fd_table[fd] = (old & ~HAS_CLOEXEC) | ((flags & FD_CLOEXEC) ? HAS_CLOEXEC : 0);
			}
		}
		fs_mutex_unlock(&table_lock);
		return result;
	}
	return FS_SYSCALL(__NR_fcntl, fd, F_SETFD, flags);
}

__attribute__((warn_unused_result))
int perform_get_fd_flags(int fd)
{
	return FS_SYSCALL(__NR_fcntl, fd, F_GETFD);
}

__attribute__((warn_unused_result))
int chdir_become_local(void)
{
	fs_mutex_lock(&table_lock);
	int value = fd_table[CWD_FD];
	if (value & HAS_LOCAL_FD) {
		fs_mutex_unlock(&table_lock);
		return 0;
	}
	int result = fs_dup3(DEAD_FD, CWD_FD, 0);
	if (result < 0) {
		fs_mutex_unlock(&table_lock);
		return result;
	}
	fd_table[CWD_FD] = HAS_LOCAL_FD;
	fs_mutex_unlock(&table_lock);
	if (value & HAS_REMOTE_FD) {
		int remote_fd = value >> USED_BITS;
		struct fd_state *states = get_fd_states();
		if (atomic_fetch_sub_explicit(&states[remote_fd].count, 1, memory_order_relaxed) == 1) {
			vfs_remote_close(remote_fd);
		}
	}
	return result;
}

__attribute__((warn_unused_result))
int chdir_become_local_path(const char *path)
{
	int result = fs_chdir(path);
	if (result == 0) {
		result = chdir_become_local();
	}
	return result;
}

__attribute__((warn_unused_result))
int chdir_become_local_fd(int local_fd)
{
	int result = fs_fchdir(local_fd);
	if (result == 0) {
		result = chdir_become_local();
	}
	return result;
}
