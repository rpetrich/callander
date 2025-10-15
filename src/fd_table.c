#include "fd_table.h"

#include "axon.h"
#include "axon_shared.h"
#include "darwin.h"
#include "freestanding.h"
#include "tracer.h"
#include "proxy.h"
#include "vfs.h"

#include <errno.h>

static void vfs_remote_close(int remote_fd)
{
	const struct vfs_file_ops *ops = vfs_file_ops_for_remote();
	ops->close((struct vfs_resolved_file){.ops = ops, .handle = remote_fd}, &get_fd_global_state()->files[remote_fd].state);
}

int fd_table[MAX_TABLE_SIZE];
static struct fs_mutex table_lock;

static int pending_fd_count;
static int pending_fds[16];

static void flush_pending_fd(int fd)
{
	intptr_t result = fs_dup3(DEAD_FD, fd, fd_table[fd] & HAS_CLOEXEC ? O_CLOEXEC : 0);
	if (result != fd) {
		if (result < 0) {
			DIE("error duping pending fd: ", as_errno(result));
		}
		DIE("expected new file descriptor at index ", fd, ", instead received ", result);
	}
}

static void flush_pending_fds(void)
{
	int count = pending_fd_count;
	pending_fd_count = 0;
	for (int i = 0; i < count; i++) {
		flush_pending_fd(pending_fds[i]);
	}
}

void initialize_fd_table(void)
{
	int null = fs_open("/dev/null", O_RDONLY, 0);
	if (null < 0) {
		DIE("error opening /dev/null: ", as_errno(null));
	}
	int result = fs_dup3(null, DEAD_FD, 0);
	if (result < 0) {
		DIE("error duping /dev/null: ", as_errno(result));
	}
	result = fs_close(null);
	if (result < 0) {
		DIE("error closing: ", as_errno(result));
	}
	result = fs_dup3(DEAD_FD, CWD_FD, 0);
	if (result < 0) {
		DIE("error duping cwd: ", as_errno(result));
	}
	fd_table[CWD_FD] = HAS_LOCAL_FD;
	// setup existing local fds
	int dirfd = fs_open(DEV_FD, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	if (dirfd < 0) {
		DIE("error enumerating open file descriptors: ", as_errno(dirfd));
	}
	for (;;) {
		char buf[8192];
		int count = fs_getdents(dirfd, (struct fs_dirent *)&buf[0], sizeof(buf));
		if (count <= 0) {
			if (count < 0) {
				DIE("failed to read open file descriptors: ", as_errno(count));
			}
			break;
		}
		for (int offset = 0; offset < count;) {
			const struct fs_dirent *ent = (const struct fs_dirent *)&buf[offset];
			const char *name = ent->d_name;
			intptr_t fd;
			if (name[0] != '.' && *fs_scans(name, &fd) == '\0') {
				switch (fd) {
				case CWD_FD:
				case DEAD_FD:
				case SHARED_PAGE_FD:
				case PROXY_FD:
				case MAIN_FD:
#ifdef ENABLE_TRACER
				case TRACER_FD:
#endif
				case SELF_FD:
					break;
				default:
					if (fd != dirfd && fd < MAX_TABLE_SIZE) {
						fd_table[fd] = HAS_LOCAL_FD;
					}
					break;
				}
			}
			offset += ent->d_reclen;
		}
	}
	fs_close(dirfd);
}

static int create_serialized_fd_table(int new_table[MAX_TABLE_SIZE])
{
	int memfd = fs_memfd_create("fdtable", 0);
	if (memfd < 0) {
		DIE("error creating memfd: ", as_errno(memfd));
	}
	int result = fs_pwrite(memfd, (char *)new_table, sizeof(fd_table), 0);
	if (result < 0) {
		DIE("error writing fd table: ", as_errno(result));
	}
	return memfd;
}

int serialize_fd_table_for_exec(void)
{
	struct fd_global_state *state = get_fd_global_state();
	fs_mutex_lock(&table_lock);
	flush_pending_fds();
	int copy[MAX_TABLE_SIZE];
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		int value = fd_table[i];
		if (value & HAS_CLOEXEC) {
			if ((value & HAS_REMOTE_FD)) {
				int remote_fd = value >> USED_BITS;
				if (atomic_fetch_sub_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed) == 1) {
					vfs_remote_close(remote_fd);
					atomic_store(&state->files[remote_fd].claimed, false);
				}
			}
			value = 0;
		}
		copy[i] = value;
	}
	return create_serialized_fd_table(copy);
}

void serialize_fd_table_for_fork(void)
{
	struct fd_global_state *state = get_fd_global_state();
	fs_mutex_lock(&table_lock);
	flush_pending_fds();
	// int copy[MAX_TABLE_SIZE];
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		int value = fd_table[i];
		if (value & HAS_REMOTE_FD) {
			int remote_fd = value >> USED_BITS;
			atomic_fetch_add_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed);
		}
		// copy[i] = value;
	}
	// fs_close(create_serialized_fd_table(copy));
}

void finish_fd_table_fork(void)
{
	fs_mutex_unlock(&table_lock);
}

void resurrect_fd_table(int fd)
{
	int result = fs_pread_all(fd, (char *)&fd_table, sizeof(fd_table), 0);
	if (result <= 0) {
		DIE("error reading fd table: ", as_errno(result));
	}
}

void clear_fd_table_for_exit(__attribute__((unused)) int status)
{
	struct fd_global_state *state = get_fd_global_state();
	fs_mutex_lock(&table_lock);
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		int value = fd_table[i];
		if (value) {
			if (value & HAS_REMOTE_FD) {
				int remote_fd = value >> USED_BITS;
				if (atomic_fetch_sub_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed) == 1) {
					vfs_remote_close(remote_fd);
					atomic_store(&state->files[remote_fd].claimed, false);
				}
			}
			// fs_close(i);
			fd_table[i] = 0;
		}
	}
	fs_mutex_unlock(&table_lock);
}

static inline bool find_pending_fd_index(int fd, int *i)
{
	int count = pending_fd_count;
	for (*i = 0; *i < count; (*i)++) {
		if (pending_fds[*i] == fd) {
			return true;
		}
	}
	return false;
}

__attribute__((warn_unused_result)) int install_local_fd(int fd, int flags)
{
	if (fd >= MAX_TABLE_SIZE || fd < 0) {
		return fd;
	}
	fs_mutex_lock(&table_lock);
	int pending_index;
try_again:
	if (find_pending_fd_index(fd, &pending_index)) {
		// this fd number has already been dispensed!
		// relocate to another fd slot
		for (int i = 0; i < MAX_TABLE_SIZE; i++) {
			if (fd_table[i] == 0) {
				fd_table[i] = HAS_LOCAL_FD | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
				int result = fs_dup3(fd, i, flags);
				if (result < 0) {
					DIE("error relocating local fd ", fd, " to ", i, ": ", as_errno(result));
				}
				// flush the pending fd, which avoids having to close
				flush_pending_fd(pending_fds[pending_index]);
				pending_fds[pending_index] = pending_fds[--pending_fd_count];
				fs_mutex_unlock(&table_lock);
				return result;
			}
		}
		// could not find a slot, flush all pending fds and try again
		for (int i = 0; i < pending_fd_count; i++) {
			if (i != pending_index) {
				flush_pending_fd(pending_fds[i]);
			}
		}
		int result = fs_fcntl(fd, flags & O_CLOEXEC ? F_DUPFD_CLOEXEC : F_DUPFD, 0);
		flush_pending_fd(fd);
		pending_fd_count = 0;
		if (result >= MAX_TABLE_SIZE || result < 0) {
			fs_mutex_unlock(&table_lock);
			return fd;
		}
		fd = result;
		goto try_again;
	}
	// fd number hasn't already been dispensed, claim it
	fd_table[fd] = HAS_LOCAL_FD | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
	fs_mutex_unlock(&table_lock);
	return fd;
}

__attribute__((warn_unused_result)) int install_remote_fd(int remote_fd, int flags)
{
	if (remote_fd < 0) {
		return remote_fd;
	}
	fs_mutex_lock(&table_lock);
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		if (fd_table[i] == 0) {
			// save to the pending queue
			if (pending_fd_count < (ssize_t)(sizeof(pending_fds) / sizeof(pending_fds[0]))) {
				// add to the end
				pending_fds[pending_fd_count++] = i;
			} else {
				// queue is full, evict the first
				int old_pending = pending_fds[0];
				pending_fds[0] = i;
				flush_pending_fd(old_pending);
			}
			fd_table[i] = (remote_fd << USED_BITS) | HAS_REMOTE_FD | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
			fs_mutex_unlock(&table_lock);
			return i;
		}
	}
	// table is full and remote fd can't be supported
	fs_mutex_unlock(&table_lock);
	vfs_remote_close(remote_fd);
	return -EMFILE;
}

int become_remote_fd(int fd, int remote_fd)
{
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
	struct fd_global_state *state = get_fd_global_state();
	if (existing & HAS_REMOTE_FD) {
		int old_remote_fd = existing >> USED_BITS;
		if (old_remote_fd == remote_fd) {
			fs_mutex_unlock(&table_lock);
			return 0;
		}
		if (atomic_fetch_sub_explicit(&state->files[old_remote_fd].count, 1, memory_order_relaxed) == 1) {
			vfs_remote_close(old_remote_fd);
			atomic_store(&state->files[old_remote_fd].claimed, false);
		}
	} else {
		int result = fs_dup3(DEAD_FD, fd, (existing & HAS_CLOEXEC) ? O_CLOEXEC : 0);
		if (result < 0) {
			fs_mutex_unlock(&table_lock);
			vfs_remote_close(remote_fd);
			return -EINVAL;
		}
	}
	atomic_fetch_add_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed);
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

__attribute__((warn_unused_result)) bool lookup_real_fd(int fd, intptr_t *out_real_fd)
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
	if (fd >= MAX_TABLE_SIZE || fd < 0) {
		return fs_close(fd);
	}
	fs_mutex_lock(&table_lock);
	int value = fd_table[fd];
	if (value == 0) {
		fs_mutex_unlock(&table_lock);
		return -EBADF;
	}
	if (value & HAS_REMOTE_FD) {
		int remote_fd = value >> USED_BITS;
		struct fd_global_state *state = get_fd_global_state();
		if (atomic_fetch_sub_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed) == 1) {
			vfs_remote_close(remote_fd);
			atomic_store(&state->files[remote_fd].claimed, false);
		}
	}
	fd_table[fd] = 0;
	int index;
	if (find_pending_fd_index(fd, &index)) {
		// remove from pending fd queue
		pending_fds[index] = pending_fds[--pending_fd_count];
		fs_mutex_unlock(&table_lock);
		return 0;
	}
	int result = fs_close(fd);
	fs_mutex_unlock(&table_lock);
	return result;
}

__attribute__((warn_unused_result)) int perform_dup(int oldfd, int flags)
{
	if (oldfd < 0) {
		return oldfd;
	}
	if (oldfd >= MAX_TABLE_SIZE) {
		return install_local_fd(fs_fcntl(oldfd, flags & O_CLOEXEC ? F_DUPFD_CLOEXEC : F_DUPFD, 0), flags);
	}
	fs_mutex_lock(&table_lock);
	int old = fd_table[oldfd];
	if (old == 0) {
		fs_mutex_unlock(&table_lock);
		return -EBADF;
	}
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		if (fd_table[i] == 0) {
			fd_table[i] = (old & ~HAS_CLOEXEC) | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
			if (old & HAS_REMOTE_FD) {
				// save to the pending queue
				if (pending_fd_count < (ssize_t)(sizeof(pending_fds) / sizeof(pending_fds[0]))) {
					// add to the end
					pending_fds[pending_fd_count++] = i;
				} else {
					// queue is full, evict the first
					int old_pending = pending_fds[0];
					pending_fds[0] = i;
					flush_pending_fd(old_pending);
				}
				int remote_fd = old >> USED_BITS;
				struct fd_global_state *state = get_fd_global_state();
				atomic_fetch_add_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed);
			}
			fs_mutex_unlock(&table_lock);
			return i;
		}
	}
	fs_mutex_unlock(&table_lock);
	if (old & HAS_REMOTE_FD) {
		// table is full, cannot dup a remote fd
		return -EMFILE;
	}
	return install_local_fd(fs_fcntl(oldfd, flags & O_CLOEXEC ? F_DUPFD_CLOEXEC : F_DUPFD, 0), flags);
}

__attribute__((warn_unused_result)) int perform_dup3(int oldfd, int newfd, int flags)
{
	if (oldfd < 0 || newfd < 0) {
		return -EBADF;
	}
	if (oldfd == newfd) {
		return -EINVAL;
	}
	if (newfd >= MAX_TABLE_SIZE) {
		// duping to beyond the table end
		if (oldfd >= MAX_TABLE_SIZE) {
			return fs_dup3(oldfd, newfd, flags);
		}
		fs_mutex_lock(&table_lock);
		int old = fd_table[newfd];
		if (old == 0) {
			// old fd is not open
			fs_mutex_unlock(&table_lock);
			return -EBADF;
		}
		if (old & HAS_REMOTE_FD) {
			// old fd is a remote file, quit
			fs_mutex_unlock(&table_lock);
			return -EMFILE;
		}
		// old fd is a local file
		int result = fs_dup3(oldfd, newfd, flags);
		fs_mutex_unlock(&table_lock);
		return result;
	}
	// duping to the table
	fs_mutex_lock(&table_lock);
	int existing = fd_table[newfd];
	int old;
	if (oldfd >= MAX_TABLE_SIZE) {
		old = HAS_LOCAL_FD;
	} else {
		old = fd_table[oldfd];
		if (old == 0) {
			fs_mutex_unlock(&table_lock);
			return -EBADF;
		}
	}
	if (old & HAS_LOCAL_FD) {
		// install the new local fd
		int result = fs_dup3(oldfd, newfd, flags);
		if (result < 0) {
			fs_mutex_unlock(&table_lock);
			return result;
		}
	} else {
		if (existing & HAS_LOCAL_FD) {
			// transitioning from local to remote, dup in the empty placeholder
			int result = fs_dup3(DEAD_FD, newfd, flags);
			if (result < 0) {
				fs_mutex_unlock(&table_lock);
				return result;
			}
		} else {
			int index;
			if ((existing & HAS_REMOTE_FD) == 0 || !find_pending_fd_index(newfd, &index)) {
				// save to the pending queue, since transitioning to remote
				if (pending_fd_count < (ssize_t)(sizeof(pending_fds) / sizeof(pending_fds[0]))) {
					// add to the end
					pending_fds[pending_fd_count++] = newfd;
				} else {
					// queue is full, evict the first
					int old_pending = pending_fds[0];
					pending_fds[0] = newfd;
					flush_pending_fd(old_pending);
				}
			}
		}
		// increment the remote fd
		int remote_fd = old >> USED_BITS;
		struct fd_global_state *state = get_fd_global_state();
		atomic_fetch_add_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed);
	}
	// commit to the table
	fd_table[newfd] = (old & ~HAS_CLOEXEC) | (flags & O_CLOEXEC ? HAS_CLOEXEC : 0);
	fs_mutex_unlock(&table_lock);
	if (existing & HAS_REMOTE_FD) {
		// decrement the evicted remote fd
		int remote_fd = existing >> USED_BITS;
		struct fd_global_state *state = get_fd_global_state();
		if (atomic_fetch_sub_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed) == 1) {
			vfs_remote_close(remote_fd);
			atomic_store(&state->files[remote_fd].claimed, false);
			return newfd;
		}
	}
	return newfd;
}

int perform_set_fd_flags(int fd, int flags)
{
	if (fd < MAX_TABLE_SIZE && fd >= 0) {
		fs_mutex_lock(&table_lock);
		int index;
		fd_table[fd] = (fd_table[fd] & ~HAS_CLOEXEC) | ((flags & FD_CLOEXEC) ? HAS_CLOEXEC : 0);
		if (!find_pending_fd_index(fd, &index)) {
			intptr_t result = FS_SYSCALL(__NR_fcntl, fd, F_SETFD, flags);
			if (result < 0) {
				fs_mutex_unlock(&table_lock);
				return result;
			}
		}
		fs_mutex_unlock(&table_lock);
		return 0;
	}
	return fs_fcntl(fd, F_SETFD, flags);
}

__attribute__((warn_unused_result)) int perform_get_fd_flags(int fd)
{
	if (fd < MAX_TABLE_SIZE) {
		return (fd_table[fd] & HAS_CLOEXEC) ? FD_CLOEXEC : 0;
	}
	return fs_fcntl(fd, F_GETFD, 0);
}

__attribute__((warn_unused_result)) int chdir_become_local(void)
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
		struct fd_global_state *state = get_fd_global_state();
		if (atomic_fetch_sub_explicit(&state->files[remote_fd].count, 1, memory_order_relaxed) == 1) {
			vfs_remote_close(remote_fd);
			atomic_store(&state->files[remote_fd].claimed, false);
		}
	}
	return result;
}

__attribute__((warn_unused_result)) int chdir_become_local_path(const char *path)
{
	int result = fs_chdir(path);
	if (result == 0) {
		result = chdir_become_local();
	}
	return result;
}

__attribute__((warn_unused_result)) int chdir_become_local_fd(int local_fd)
{
	int result = fs_fchdir(local_fd);
	if (result == 0) {
		result = chdir_become_local();
	}
	return result;
}
