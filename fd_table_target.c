#include "fd_table.h"

#include "freestanding.h"
#include "exec.h"
#include "proxy.h"
#include "remote.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

__attribute__((visibility("default")))
int fd_table[MAX_TABLE_SIZE];
static struct fs_mutex table_lock;

void clear_fd_table_for_exit(int status)
{
	PROXY_CALL(__NR_exit_group | PROXY_NO_RESPONSE, proxy_value(status));
	// hack assuming there are no outstanding threads
	if (fs_gettid() == get_self_pid()) {
		fs_exitthread(status);
	}
}

static int find_unused_slot(void)
{
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		if (fd_table[i] == 0) {
			return i;
		}
	}
	return -EMFILE;
}

static inline int install_underlying_fd(int underlying_fd, int underlying_type, int flags)
{
	if (underlying_fd < 0) {
		return underlying_fd;
	}
	int data = (underlying_fd << USED_BITS) | underlying_type | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
	fs_mutex_lock(&table_lock);
	int result = find_unused_slot();
	if (result >= 0) {
		fd_table[result] = data;
	}
	fs_mutex_unlock(&table_lock);
	return result;
}

__attribute__((warn_unused_result))
int install_local_fd(int local_fd, int flags)
{
	if (local_fd < 0) {
		return local_fd;
	}
	int result = install_underlying_fd(local_fd, HAS_LOCAL_FD, flags);
	if (result < 0) {
		fs_close(local_fd);
	}
	return result;
}

__attribute__((warn_unused_result))
int install_remote_fd(int remote_fd, int flags)
{
	if (remote_fd < 0) {
		return remote_fd;
	}
	int result = install_underlying_fd(remote_fd, HAS_REMOTE_FD, flags);
	if (result < 0) {
		remote_close(remote_fd);
	}
	return result;
}

static int become_underlying_fd(int fd, int underlying_fd, int type, bool require_existing) {
	if (underlying_fd < 0) {
		return underlying_fd;
	}
	if (fd > MAX_TABLE_SIZE || fd < 0) {
		return -EMFILE;
	}
	int *counts = get_fd_counts();
	fs_mutex_lock(&table_lock);
	int existing = fd_table[fd];
	if (require_existing && (existing == 0)) {
		fs_mutex_unlock(&table_lock);
		return -EINVAL;
	}
	int old_underlying_fd = existing >> USED_BITS;
	if (existing & HAS_REMOTE_FD) {
		if ((old_underlying_fd == underlying_fd) && (existing & type)) {
			fs_mutex_unlock(&table_lock);
			return 0;
		}
		if (atomic_fetch_sub_explicit(&counts[old_underlying_fd], 1, memory_order_relaxed) == 1) {
			remote_close(old_underlying_fd);
		}
	} else if (existing & HAS_LOCAL_FD) {
		fs_close(old_underlying_fd);
	}
	atomic_fetch_add_explicit(&counts[underlying_fd], 1, memory_order_relaxed);
	fd_table[fd] = (underlying_fd << USED_BITS) | type | (existing & HAS_CLOEXEC);
	fs_mutex_unlock(&table_lock);
	return 0;
}

int become_remote_fd(int fd, int remote_fd) {
	int result = become_underlying_fd(fd, remote_fd, HAS_REMOTE_FD, true);
	if (result < 0) {
		remote_close(remote_fd);
	}
	return result;
}

int become_local_fd(int fd, int local_fd)
{
	int result = become_underlying_fd(fd, local_fd, HAS_LOCAL_FD, true);
	if (result < 0) {
		fs_close(local_fd);
	}
	return result;
}

__attribute__((warn_unused_result))
bool lookup_real_fd(int fd, int *out_real_fd)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		int value = fd_table[fd];
		fs_mutex_unlock(&table_lock);
		*out_real_fd = value != 0 ? (value >> USED_BITS) : -EBADF;
		return (value & HAS_REMOTE_FD) == HAS_REMOTE_FD;
	}
	*out_real_fd = -EBADF;
	return false;
}

int perform_close(int fd)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		int value = fd_table[fd];
		fd_table[fd] = 0;
		fs_mutex_unlock(&table_lock);
		if (value != 0) {
			int underlying_fd = value >> USED_BITS;
			if (value & HAS_REMOTE_FD) {
				// decrement the reference count for the remote fd
				int *counts = get_fd_counts();
				if (atomic_fetch_sub_explicit(&counts[underlying_fd], 1, memory_order_relaxed) == 1) {
					remote_close(underlying_fd);
				}
			} else {
				// close the underlying local fd
				fs_close(underlying_fd);
			}
			return 0;
		}
	}
	return -EBADF;
}

__attribute__((warn_unused_result))
int perform_dup(int oldfd, int flags)
{
	int underlying_fd;
	bool is_remote = lookup_real_fd(oldfd, &underlying_fd);
	if (underlying_fd < 0) {
		return underlying_fd;
	}
	if (is_remote) {
		// increment the ref count for the remote underlying fd
		int *counts = get_fd_counts();
		atomic_fetch_add_explicit(&counts[underlying_fd], 1, memory_order_relaxed);
	} else {
		// duplicate the underlying local fd
		underlying_fd = fs_dup(underlying_fd);
		if (underlying_fd < 0) {
			return underlying_fd;
		}
	}
	// install the underlying fd in the new slot
	return install_underlying_fd(underlying_fd, is_remote ? HAS_REMOTE_FD : HAS_LOCAL_FD, flags);
}

__attribute__((warn_unused_result))
int perform_dup3(int oldfd, int newfd, int flags)
{
	// check if oldfd is valid
	if (oldfd < MAX_TABLE_SIZE && oldfd >= 0 && newfd < MAX_TABLE_SIZE && newfd >= 0) {
		int *counts = get_fd_counts();
		fs_mutex_lock(&table_lock);
		int old_data = fd_table[oldfd];
		if (old_data != 0) {
			fs_mutex_unlock(&table_lock);
			return -EBADF;
		}
		// interrogate the underlying file descriptor for oldfd
		int existing_value = fd_table[newfd];
		if (old_data & HAS_REMOTE_FD) {
			// increment the ref count on remote underlying fd and store into the new slot
			atomic_fetch_add_explicit(&counts[old_data >> USED_BITS], 1, memory_order_relaxed);
			fd_table[newfd] = (old_data & ~HAS_CLOEXEC) | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
		} else {
			// perform a local dup and store into the new slot
			int new_local = fs_dup(existing_value >> USED_BITS);
			if (new_local < 0) {
				fs_mutex_unlock(&table_lock);
				return new_local;
			}
			fd_table[newfd] = (new_local << USED_BITS) | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
		}
		fs_mutex_unlock(&table_lock);
		// close the evicted underlying file descriptor that was previously at newfd, if any
		int existing_underlying_fd = existing_value >> USED_BITS;
		if (existing_value & HAS_REMOTE_FD) {
			if (atomic_fetch_sub_explicit(&counts[existing_underlying_fd], 1, memory_order_relaxed) == 1) {
				remote_close(existing_underlying_fd);
			}
		} else if (existing_value & HAS_LOCAL_FD) {
			fs_close(existing_underlying_fd);
		}
		return newfd;
	}
	return -EBADF;
}

int perform_set_fd_flags(int fd, int flags)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		int value = fd_table[fd];
		if (value != 0) {
			fd_table[fd] = (value & ~HAS_CLOEXEC) | ((flags & FD_CLOEXEC) ? HAS_CLOEXEC : 0);
			fs_mutex_unlock(&table_lock);
			return 0;
		}
		fs_mutex_unlock(&table_lock);
	}
	return -EBADF;
}

__attribute__((warn_unused_result))
int perform_get_fd_flags(int fd)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		int value = fd_table[fd];
		fs_mutex_unlock(&table_lock);
		if (value != 0) {
			return (value & HAS_CLOEXEC) ? FD_CLOEXEC : 0;
		}
	}
	return -EBADF;
}

__attribute__((warn_unused_result))
int chdir_become_local_path(const char *path)
{
	int local_fd = fs_open(path, O_PATH|O_DIRECTORY, 0);
	if (local_fd < 0) {
		return local_fd;
	}
	int result = become_underlying_fd(CWD_FD, local_fd, HAS_LOCAL_FD, false);
	if (result < 0) {
		fs_close(local_fd);
	}
	return result;
}

__attribute__((warn_unused_result))
int chdir_become_local_fd(int local_fd)
{
	int new_local_fd = fs_dup(local_fd);
	if (new_local_fd < 0) {
		return new_local_fd;
	}
	int result = become_underlying_fd(CWD_FD, new_local_fd, HAS_LOCAL_FD, false);
	if (result < 0) {
		fs_close(new_local_fd);
	}
	return result;
}

const int *get_fd_table(void)
{
	return fd_table;
}
