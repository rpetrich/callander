#define _GNU_SOURCE
#include "remote.h"

#include "axon.h"
#include "darwin.h"
#include "freestanding.h"
#include "proxy.h"
#include "windows.h"

#include <dirent.h>
#include <string.h>
#include <sched.h>

#define unknown_target() do { \
	ERROR("in function", __func__); \
	unknown_target(); \
} while(0)

void remote_spawn_worker(void)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX: {
			intptr_t worker_func_addr = (intptr_t)proxy_get_hello_message()->process_data;
			intptr_t stack_addr = PROXY_CALL(__NR_mmap | PROXY_NO_WORKER, proxy_value(0), proxy_value(PROXY_WORKER_STACK_SIZE), proxy_value(PROT_READ | PROT_WRITE), proxy_value(MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN), proxy_value(-1), proxy_value(0));
			if (fs_is_map_failed((void *)stack_addr)) {
				DIE("unable to map a worker stack", fs_strerror(stack_addr));
				return;
			}
			PROXY_CALL(__NR_clone | TARGET_NO_RESPONSE | PROXY_NO_WORKER, proxy_value(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS), proxy_value(stack_addr + PROXY_WORKER_STACK_SIZE), proxy_value(0), proxy_value(0), proxy_value(0), proxy_value(worker_func_addr));
			break;
		}
		case TARGET_PLATFORM_DARWIN:
		case TARGET_PLATFORM_WINDOWS:
			break;
		default:
			unknown_target();
	}
}

static inline void trim_size(size_t *size)
{
	if (UNLIKELY(*size >= PROXY_BUFFER_SIZE)) {
		*size = PROXY_BUFFER_SIZE;
	}
}

intptr_t remote_openat(int dirfd, const char *path, int flags, mode_t mode)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_openat, proxy_value(dirfd), proxy_string(path), proxy_value(flags), proxy_value(mode));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_openat, proxy_value(translate_at_fd_to_darwin(dirfd)), proxy_string(path), proxy_value(translate_open_flags_to_darwin(flags)), proxy_value(mode)));
		case TARGET_PLATFORM_WINDOWS: {
			if (dirfd != AT_FDCWD) {
				return -EINVAL;
			}
			WINDOWS_DWORD desired_access = translate_open_flags_to_windows_desired_access(flags);
			uint16_t buf[PATH_MAX];
			WINDOWS_CREATEFILE2_EXTENDED_PARAMETERS params;
			params.dwSize = sizeof(params);
			params.dwFileAttributes = WINDOWS_FILE_ATTRIBUTE_NORMAL;
			params.dwFileFlags = WINDOWS_FILE_FLAG_BACKUP_SEMANTICS;
			params.dwSecurityQosFlags = 0;
			params.lpSecurityAttributes = NULL;
			params.hTemplateFile = 0;
			return translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, CreateFile2, proxy_wide_string(translate_windows_wide_path(path, buf)), proxy_value(desired_access), proxy_value(WINDOWS_FILE_SHARE_DELETE | WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE), proxy_value(WINDOWS_OPEN_ALWAYS), proxy_in(&params, sizeof(params))));
		}
		default:
			unknown_target();
	}
}

intptr_t remote_truncate(const char *path, off_t length)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_truncate, proxy_string(path), proxy_value(length));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_truncate, proxy_string(path), proxy_value(length)));
		default:
			unknown_target();
	}
}

intptr_t remote_read(int fd, char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_read, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_read, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz)));
		case TARGET_PLATFORM_WINDOWS: {
			WINDOWS_DWORD numberOfBytesRead;
			intptr_t result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, ReadFile, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz), proxy_out(&numberOfBytesRead, sizeof(numberOfBytesRead))));
			return result == 0 ? numberOfBytesRead : result;
		}
		default:
			unknown_target();
	}
}

intptr_t remote_write(int fd, const char *buf, size_t bufsz)
{
	trim_size(&bufsz);
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_write, proxy_value(fd), proxy_in(buf, bufsz), proxy_value(bufsz));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_write, proxy_value(fd), proxy_in(buf, bufsz), proxy_value(bufsz)));
		default:
			unknown_target();
	}
}

intptr_t remote_recvfrom(int fd, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	trim_size(&bufsz);
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_recvfrom, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz), proxy_value(flags), src_addr ? proxy_out(src_addr, *addrlen) : proxy_value(0), proxy_inout(addrlen, sizeof(*addrlen)));
		case TARGET_PLATFORM_DARWIN:
			// TODO: translate addresses
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_recvfrom, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz), proxy_value(flags), proxy_out(src_addr, *addrlen), proxy_inout(addrlen, sizeof(*addrlen))));
		default:
			unknown_target();
	}
}

intptr_t remote_sendto(int fd, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
	trim_size(&bufsz);
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_sendto, proxy_value(fd), proxy_in(buf, bufsz), proxy_value(bufsz), proxy_value(flags), proxy_in(dest_addr, dest_len), proxy_value(dest_len));
		case TARGET_PLATFORM_DARWIN:
			// TODO: translate addresses
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_sendto, proxy_value(fd), proxy_in(buf, bufsz), proxy_value(bufsz), proxy_value(flags), proxy_in(dest_addr, dest_len), proxy_value(dest_len)));
		default:
			unknown_target();
	}
}

intptr_t remote_lseek(int fd, off_t offset, int whence)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_lseek, proxy_value(fd), proxy_value(offset), proxy_value(whence));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_lseek, proxy_value(fd), proxy_value(offset), proxy_value(translate_seek_whence_to_darwin(whence))));
		default:
			unknown_target();
	}
}

intptr_t remote_fadvise64(int fd, size_t offset, size_t len, int advice)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_fadvise64, proxy_value(fd), proxy_value(offset), proxy_value(len), proxy_value(advice));
		case TARGET_PLATFORM_DARWIN:
		case TARGET_PLATFORM_WINDOWS:
			// ignore fadvise
			return 0;
		default:
			unknown_target();
	}
}

intptr_t remote_readahead(int fd, off_t offset, size_t count)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_readahead, proxy_value(fd), proxy_value(offset), proxy_value(count));
		case TARGET_PLATFORM_DARWIN:
		case TARGET_PLATFORM_WINDOWS:
			// ignore readahead
			return 0;
		default:
			unknown_target();
	}
}

intptr_t remote_pread(int fd, void *buf, size_t count, off_t offset)
{
	trim_size(&count);
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_pread64, proxy_value(fd), proxy_out(buf, count), proxy_value(count), proxy_value(offset));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_pread, proxy_value(fd), proxy_out(buf, count), proxy_value(count), proxy_value(offset)));
		default:
			unknown_target();
	}
}

intptr_t remote_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	trim_size(&count);
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_pwrite64, proxy_value(fd), proxy_in(buf, count), proxy_value(count), proxy_value(offset));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_pwrite, proxy_value(fd), proxy_in(buf, count), proxy_value(count), proxy_value(offset)));
		default:
			unknown_target();
	}
}

intptr_t remote_flock(int fd, int how)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_flock, proxy_value(fd), proxy_value(how));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_flock, proxy_value(fd), proxy_value(how)));
		default:
			unknown_target();
	}
}

intptr_t remote_fsync(int fd)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_fsync, proxy_value(fd));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_fsync, proxy_value(fd)));
		default:
			unknown_target();
	}
}

intptr_t remote_fdatasync(int fd)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_fdatasync, proxy_value(fd));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_fdatasync, proxy_value(fd)));
		default:
			unknown_target();
	}
}

intptr_t remote_ftruncate(int fd, off_t length)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_ftruncate, proxy_value(fd), proxy_value(length));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_ftruncate, proxy_value(fd), proxy_value(length)));
		default:
			unknown_target();
	}
}

intptr_t remote_recvmsg(struct thread_storage *thread, int fd, struct msghdr *msghdr, int flags)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX: {
			if (msghdr->msg_name != NULL || msghdr->msg_namelen != 0 || msghdr->msg_control != NULL || msghdr->msg_controllen != 0) {
				// TODO: support names and control data
				return invalid_remote_operation();
			}
			int iovcnt = msghdr->msg_iovlen;
			// allocate a local iovec
			struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
			struct attempt_cleanup_state state;
			attempt_push_free(thread, &state, iov_remote);
			// calculate the total size
			size_t total_size = sizeof(struct iovec) * iovcnt;
			for (int i = 0; i < iovcnt; i++) {
				size_t len = msghdr->msg_iov[i].iov_len;
				iov_remote[i].iov_len = len;
				total_size += len;
			}
			// allocate a remote buffer
			attempt_proxy_alloc_state remote_buf;
			attempt_proxy_alloc(total_size, thread, &remote_buf);
			// set up the vectors
			intptr_t buf_cur = remote_buf.addr;
			for (int i = 0; i < iovcnt; i++) {
				size_t len = iov_remote[i].iov_len;
				iov_remote[i].iov_base = (void *)buf_cur;
				buf_cur += len;
			}
			// poke the iovec
			intptr_t result = proxy_poke(buf_cur, sizeof(struct iovec) * iovcnt, iov_remote);
			if (result < 0) {
				attempt_pop_free(&state);
				attempt_proxy_free(&remote_buf);
				return result;
			}
			// perform the recvmsg remotely
			struct msghdr copy = *msghdr;
			copy.msg_iov = (struct iovec *)buf_cur;
			result = PROXY_CALL(__NR_recvmsg, proxy_value(fd), proxy_in(&copy, sizeof(struct msghdr)), proxy_value(flags));
			if (result >= 0) {
				// peek the bytes we received
				buf_cur = remote_buf.addr;
				for (int i = 0; i < iovcnt; i++) {
					size_t len = iov_remote[i].iov_len;
					intptr_t peek_result = proxy_peek(buf_cur, len, msghdr->msg_iov[i].iov_base);
					if (peek_result < 0) {
						attempt_pop_free(&state);
						attempt_proxy_free(&remote_buf);
						return peek_result;
					}
					buf_cur += len;
				}
			}
			attempt_pop_free(&state);
			attempt_proxy_free(&remote_buf);
			return result;
		}
		default:
			unknown_target();
	}
}

intptr_t remote_sendmsg(struct thread_storage *thread, int fd, const struct msghdr *msghdr, int flags)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX: {
			if (msghdr->msg_name != NULL || msghdr->msg_namelen != 0 || msghdr->msg_control != NULL || msghdr->msg_controllen != 0) {
				// TODO: support names and control data
				return invalid_remote_operation();
			}
			int iovcnt = msghdr->msg_iovlen;
			// allocate a local iovec
			struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
			struct attempt_cleanup_state state;
			attempt_push_free(thread, &state, iov_remote);
			// calculate the total size
			size_t total_size = sizeof(struct iovec) * iovcnt;
			for (int i = 0; i < iovcnt; i++) {
				size_t len = msghdr->msg_iov[i].iov_len;
				iov_remote[i].iov_len = len;
				total_size += len;
			}
			// allocate a remote buffer
			attempt_proxy_alloc_state remote_buf;
			attempt_proxy_alloc(total_size, thread, &remote_buf);
			// poke the bytes to send
			intptr_t buf_cur = remote_buf.addr;
			for (int i = 0; i < iovcnt; i++) {
				size_t len = iov_remote[i].iov_len;
				intptr_t result = proxy_poke(buf_cur, len, msghdr->msg_iov[i].iov_base);
				if (result < 0) {
					attempt_pop_free(&state);
					attempt_proxy_free(&remote_buf);
					return result;
				}
				iov_remote[i].iov_base = (void *)buf_cur;
				buf_cur += len;
			}
			// poke the iovec
			intptr_t result = proxy_poke(buf_cur, sizeof(struct iovec) * iovcnt, iov_remote);
			attempt_pop_free(&state);
			if (result < 0) {
				attempt_proxy_free(&remote_buf);
				return result;
			}
			// perform the sendmsg remotely
			struct msghdr copy = *msghdr;
			copy.msg_iov = (struct iovec *)buf_cur;
			result = PROXY_CALL(__NR_sendmsg, proxy_value(fd), proxy_in(&copy, sizeof(struct msghdr)), proxy_value(flags));
			attempt_proxy_free(&remote_buf);
			return result;
		}
		default:
			unknown_target();
	}
}


void remote_close(int fd)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			PROXY_CALL(__NR_close | PROXY_NO_RESPONSE, proxy_value(fd));
			break;
		case TARGET_PLATFORM_DARWIN:
			PROXY_CALL(DARWIN_SYS_close | PROXY_NO_RESPONSE, proxy_value(fd));
			break;
		case TARGET_PLATFORM_WINDOWS:
			struct windows_state *state = &get_fd_states()[fd].windows;
			if (state->dir_handle != NULL) {
				PROXY_WIN32_BOOL_CALL(kernel32.dll, FindClose, proxy_value((intptr_t)state->dir_handle));
				state->dir_handle = NULL;
			}
			PROXY_WIN32_BOOL_CALL(kernel32.dll, CloseHandle, proxy_value(fd));
			break;
		default:
			unknown_target();
			break;
	}
}

intptr_t remote_fcntl_basic(int fd, int cmd, intptr_t argument)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(cmd), proxy_value(argument));
		case TARGET_PLATFORM_DARWIN: {
			int darwin_cmd;
			switch (cmd) {
				case F_SETFL:
					darwin_cmd = 4;
					break;
				case F_GETFL:
					darwin_cmd = 3;
					break;
				case F_SETLEASE:
					return -EINVAL;
				case F_GETLEASE:
					return -EINVAL;
				case F_SETPIPE_SZ:
					return -EINVAL;
				case F_GETPIPE_SZ:
					return -EINVAL;
				case F_ADD_SEALS:
					return -EINVAL;
				case F_GET_SEALS:
					return -EINVAL;
				default:
					unknown_target();
					break;
			}
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(darwin_cmd), proxy_value(argument)));
		}
		default:
			unknown_target();
			break;
	}
}

intptr_t remote_fcntl_lock(int fd, int cmd, struct flock *lock)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(cmd), proxy_inout(lock, sizeof(struct flock)));
		case TARGET_PLATFORM_DARWIN:
			return -EINVAL;
		default:
			unknown_target();
			break;
	}
}

intptr_t remote_fcntl_int(int fd, int cmd, int *value)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(cmd), proxy_inout(value, sizeof(int)));
		case TARGET_PLATFORM_DARWIN:
			return -EINVAL;
		default:
			unknown_target();
			break;
	}
}

intptr_t remote_fstat(int fd, struct fs_stat *buf)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_fstat, proxy_value(fd), proxy_out(buf, sizeof(*buf)));
		case TARGET_PLATFORM_DARWIN: {
			struct darwin_stat dstat;
			intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstat64, proxy_value(fd), proxy_out(&dstat, sizeof(struct darwin_stat))));
			if (result >= 0) {
				*buf = translate_darwin_stat(dstat);
			}
			return result;
		}
		case TARGET_PLATFORM_WINDOWS: {
			WINDOWS_BY_HANDLE_FILE_INFORMATION info;
			intptr_t result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, GetFileInformationByHandle, proxy_value(fd), proxy_out(&info, sizeof(info))));
			if (result >= 0) {
				*buf = translate_windows_by_handle_file_information(info);
			}
			return result;
		}
		default:
			unknown_target();
	}
}

intptr_t remote_newfstatat(int fd, const char *path, struct fs_stat *stat, int flags)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_newfstatat, proxy_value(fd), proxy_string(path), proxy_out(stat, sizeof(struct fs_stat)), proxy_value(flags));
		case TARGET_PLATFORM_DARWIN: {
			if ((flags & AT_EMPTY_PATH) && (path == NULL || *path == '\0')) {
				if (fd == AT_FDCWD) {
					path = ".";
				} else {
					return remote_fstat(fd, stat);
				}
			}
			struct darwin_stat dstat;
			intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstatat64, proxy_value(translate_at_fd_to_darwin(fd)), proxy_string(path), proxy_out(&dstat, sizeof(struct darwin_stat)), proxy_value(translate_at_flags_to_darwin(flags))));
			if (result >= 0) {
				*stat = translate_darwin_stat(dstat);
			}
			return result;
		}
		case TARGET_PLATFORM_WINDOWS: {
			if ((flags & AT_EMPTY_PATH) && (path == NULL || *path == '\0')) {
				if (fd == AT_FDCWD) {
					path = ".";
				} else {
					return remote_fstat(fd, stat);
				}
			}
			unknown_target();
		}
		default:
			unknown_target();
	}
}

intptr_t remote_statx(int fd, const char *path, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_statx, proxy_value(fd), proxy_string(path), proxy_value(flags), proxy_value(mask), proxy_inout(statxbuf, sizeof(struct statx)));
		case TARGET_PLATFORM_DARWIN: {
			struct darwin_stat dstat;
			intptr_t result;
			if ((flags & AT_EMPTY_PATH) && (path == NULL || *path == '\0')) {
				if (fd == AT_FDCWD) {
					result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstatat64, proxy_value(translate_at_fd_to_darwin(fd)), proxy_string("."), proxy_out(&dstat, sizeof(struct darwin_stat)), proxy_value(translate_at_flags_to_darwin(flags))));
				} else {
					result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstat64, proxy_value(fd), proxy_out(&dstat, sizeof(struct darwin_stat))));
				}
			} else {
				result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstatat64, proxy_value(translate_at_fd_to_darwin(fd)), proxy_string(path), proxy_out(&dstat, sizeof(struct darwin_stat)), proxy_value(translate_at_flags_to_darwin(flags))));
			}
			if (result >= 0) {
				translate_darwin_statx(statxbuf, dstat, mask);
			}
			return result;
		}
		case TARGET_PLATFORM_WINDOWS: {
			WINDOWS_BY_HANDLE_FILE_INFORMATION info;
			intptr_t handle;
			intptr_t result;
			if ((flags & AT_EMPTY_PATH) && (path == NULL || *path == '\0')) {
				if (fd == AT_FDCWD) {
					WINDOWS_CREATEFILE2_EXTENDED_PARAMETERS params;
					params.dwSize = sizeof(params);
					params.dwFileAttributes = WINDOWS_FILE_ATTRIBUTE_NORMAL;
					params.dwFileFlags = WINDOWS_FILE_FLAG_BACKUP_SEMANTICS;
					params.dwSecurityQosFlags = 0;
					params.lpSecurityAttributes = NULL;
					params.hTemplateFile = 0;
					uint16_t buf[2];
					buf[0] = '.';
					buf[1] = '\0';
					handle = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, CreateFile2, proxy_wide_string(buf), proxy_value(0), proxy_value(WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE | WINDOWS_FILE_SHARE_DELETE), proxy_value(WINDOWS_OPEN_EXISTING), proxy_in(&params, sizeof(params))));
					if (handle < 0) {
						return handle;
					}
				} else {
					result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, GetFileInformationByHandle, proxy_value(fd), proxy_out(&info, sizeof(info))));
					if (result >= 0) {
						translate_windows_by_handle_file_information_to_statx(statxbuf, info, mask);
					}
					return result;
				}
			} else {
				if (fd != AT_FDCWD) {
					return -EINVAL;
				}
				uint16_t buf[PATH_MAX];
				WINDOWS_CREATEFILE2_EXTENDED_PARAMETERS params;
				params.dwSize = sizeof(params);
				params.dwFileAttributes = WINDOWS_FILE_ATTRIBUTE_NORMAL;
				params.dwFileFlags = WINDOWS_FILE_FLAG_BACKUP_SEMANTICS;
				params.dwSecurityQosFlags = 0;
				params.lpSecurityAttributes = NULL;
				params.hTemplateFile = 0;
				handle = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, CreateFile2, proxy_wide_string(translate_windows_wide_path(path, buf)), proxy_value(WINDOWS_FILE_READ_ATTRIBUTES), proxy_value(WINDOWS_FILE_SHARE_DELETE | WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE), proxy_value(WINDOWS_OPEN_EXISTING), proxy_in(&params, sizeof(params))));
				if (handle < 0) {
					return handle;
				}
			}
			result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, GetFileInformationByHandle, proxy_value(handle), proxy_out(&info, sizeof(info))));
			PROXY_WIN32_BOOL_CALL(kernel32.dll, CloseHandle, proxy_value(handle));
			if (result < 0) {
				return result;
			}
			translate_windows_by_handle_file_information_to_statx(statxbuf, info, mask);
			return 0;
		}
		default:
			unknown_target();
	}
}

intptr_t remote_faccessat(int fd, const char *path, int mode, int flags)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_faccessat, proxy_value(fd), proxy_string(path), proxy_value(mode), proxy_value(flags));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_faccessat, proxy_value(translate_at_fd_to_darwin(fd)), proxy_string(path), proxy_value(mode), proxy_value(translate_at_flags_to_darwin(flags))));
		default:
			unknown_target();
	}
}

intptr_t remote_readlinkat(int dirfd, const char *path, char *buf, size_t bufsz)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_readlinkat, proxy_value(dirfd), proxy_string(path), proxy_out(buf, bufsz), proxy_value(bufsz));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_readlinkat, proxy_value(translate_at_fd_to_darwin(dirfd)), proxy_string(path), proxy_out(buf, bufsz), proxy_value(bufsz)));
		default:
			unknown_target();
	}
}

#define DEV_FD "/proc/self/fd/"

intptr_t remote_readlink_fd(int fd, char *buf, size_t size)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX: {
			// readlink the fd remotely
			char dev_path[64];
			memcpy(dev_path, DEV_FD, sizeof(DEV_FD) - 1);
			fs_utoa(fd, &dev_path[sizeof(DEV_FD) - 1]);
			return remote_readlinkat(AT_FDCWD, dev_path, buf, size);
		}
		case TARGET_PLATFORM_DARWIN: {
			if (size < 1024) {
				DIE("expected at least 1024 byte buffer", (int)size);
			}
			intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fcntl, proxy_value(fd), proxy_value(DARWIN_F_GETPATH), proxy_out(buf, size)));
			if (result >= 0) {
				return fs_strlen(buf);
			}
			return result;
		}
		default:
			unknown_target();
	}
}

intptr_t remote_getdents64(int fd, char *buf, size_t size)
{
	trim_size(&size);
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_getdents64, proxy_value(fd), proxy_out(buf, size), proxy_value(size));
		case TARGET_PLATFORM_DARWIN: {
			char temp[1024];
			uint64_t pos = 0;
			intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_getdirentries64, proxy_value(fd), proxy_out(temp, sizeof(temp)), proxy_value(sizeof(temp)), proxy_out(&pos, sizeof(uint64_t))));
			if (result <= 0) {
				return result;
			}
			struct darwin_dirent *dent = (struct darwin_dirent *)&temp[0];
			struct fs_dirent *dirp = (void *)buf;
			size_t consumed = 0;
			do {
				size_t name_len = dent->d_namlen;
				size_t rec_len = sizeof(struct fs_dirent) + name_len + 2;
				size_t aligned_len = (rec_len + 7) & ~7;
				if (consumed + aligned_len > size) {
					result = remote_lseek(fd, dent->d_seekoff, SEEK_SET);
					if (result < 0) {
						return 0;
					}
					break;
				}
				dirp->d_ino = dent->d_ino;
				dirp->d_off = consumed + aligned_len;
				dirp->d_reclen = aligned_len;
				dirp->d_type = dent->d_type;
				memcpy(dirp->d_name, dent->d_name, name_len);
				dirp->d_name[name_len] = '\0';
				// move to next record
				consumed += aligned_len;
				result -= dent->d_reclen;
				dirp = (struct fs_dirent *)((intptr_t)dirp + aligned_len);
				dent = (struct darwin_dirent *)((intptr_t)dent + dent->d_reclen);
			} while(result > 0);
			return consumed;
		}
		case TARGET_PLATFORM_WINDOWS: {
			struct windows_state *state = &get_fd_states()[fd].windows;
			WINDOWS_WIN32_FIND_DATAW find_data;
			intptr_t result;
			if (state->dir_handle == NULL) {
				uint16_t path_buf[PATH_MAX];
				result = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, GetFinalPathNameByHandleW, proxy_value(fd), proxy_out(path_buf, sizeof(path_buf)), proxy_value(PATH_MAX), proxy_value(0)));
				if (result < 0) {
					return result;
				}
				if (path_buf[result] != '\\') {
					path_buf[result++] = '\\';
				}
				path_buf[result++] = '*';
				path_buf[result++] = '\0';
				result = translate_windows_result(PROXY_WIN32_CALL(kernel32.dll, FindFirstFileW, proxy_in(path_buf, result * sizeof(uint16_t)), proxy_out(&find_data, sizeof(find_data))));
				if (result > 0) {
					state->dir_handle = (WINDOWS_HANDLE)result;
				}
			} else {
				result = translate_windows_result(PROXY_WIN32_BOOL_CALL(kernel32.dll, FindNextFileW, proxy_value((intptr_t)state->dir_handle), proxy_out(&find_data, sizeof(find_data))));
			}
			if (result < 0) {
				// convert -ENOENT to 0, representing end of directory listing
				return result == -ENOENT ? 0 : result;
			}
			// translate the single directory entry
			struct fs_dirent *dirp = (void *)buf;
			dirp->d_ino = 1;
			dirp->d_type = (find_data.dwFileAttributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY) ? DT_DIR : DT_REG;
			size_t i = 0;
			for (; i < WINDOWS_MAX_PATH; i++) {
				dirp->d_name[i] = find_data.cFileName[i];
				if (dirp->d_name[i] == '\0') {
					break;
				}
			}
			size_t rec_len = sizeof(struct fs_dirent) + i + 2;
			size_t aligned_len = (rec_len + 7) & ~7;
			dirp->d_reclen = aligned_len;
			dirp->d_off = aligned_len;
			return aligned_len;
		}
		default:
			unknown_target();
	}
}

intptr_t remote_getxattr(const char *path, const char *name, void *out_value, size_t size)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_getxattr, proxy_string(path), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
		default:
			return -ENODATA;
	}
}

intptr_t remote_lgetxattr(const char *path, const char *name, void *out_value, size_t size)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_lgetxattr, proxy_string(path), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
		default:
			return -ENODATA;
	}
}

intptr_t remote_fgetxattr(int fd, const char *name, void *out_value, size_t size)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_fgetxattr, proxy_value(fd), proxy_string(name), proxy_out(out_value, size), proxy_value(size));
		default:
			return -ENODATA;
	}
}

intptr_t remote_setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_setxattr, proxy_string(path), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
		default:
			return -ENOTSUP;
	}
}

intptr_t remote_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_lsetxattr, proxy_string(path), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
		default:
			return -ENOTSUP;
	}
}

intptr_t remote_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_fsetxattr, proxy_value(fd), proxy_string(name), proxy_in(value, size), proxy_value(size), proxy_value(flags));
		default:
			return -ENOTSUP;
	}
}

intptr_t remote_listxattr(const char *path, void *out_value, size_t size)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_listxattr, proxy_string(path), proxy_out(out_value, size), proxy_value(size));
		default:
			return -ENOTSUP;
	}
}

intptr_t remote_llistxattr(const char *path, void *out_value, size_t size)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_llistxattr, proxy_string(path), proxy_out(out_value, size), proxy_value(size));
		default:
			return -ENOTSUP;
	}
}

intptr_t remote_flistxattr(int fd, void *out_value, size_t size)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(LINUX_SYS_flistxattr, proxy_value(fd), proxy_out(out_value, size), proxy_value(size));
		default:
			return -ENOTSUP;
	}
}

intptr_t remote_socket(int domain, int type, int protocol)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_socket | PROXY_NO_WORKER, proxy_value(domain), proxy_value(type), proxy_value(protocol));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_socket, proxy_value(domain), proxy_value(type), proxy_value(protocol)));
		default:
			unknown_target();
	}
}

intptr_t remote_getsockopt(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_getsockopt | PROXY_NO_WORKER, proxy_value(sockfd), proxy_value(level), proxy_value(optname), proxy_out(optval, *optlen), proxy_inout(optlen, sizeof(*optlen)));
		case TARGET_PLATFORM_DARWIN:
			return -ENOPROTOOPT;
		default:
			unknown_target();
	}
}

intptr_t remote_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_setsockopt | PROXY_NO_WORKER, proxy_value(sockfd), proxy_value(level), proxy_value(optname), proxy_in(optval, optlen), proxy_value(optlen));
		case TARGET_PLATFORM_DARWIN:
			return -ENOPROTOOPT;
		default:
			unknown_target();
	}
}

intptr_t remote_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
#ifdef __NR_poll
			return PROXY_CALL(__NR_poll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_value(timeout));
#else
			if (timeout < 0) {
				return PROXY_CALL(__NR_ppoll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_value(0), proxy_value(0), proxy_value(0));
			} else {
				struct timespec timeout_spec;
				timeout_spec.tv_sec = timeout / 1000;
				timeout_spec.tv_nsec = (timeout % 1000) * 1000000;
				return PROXY_CALL(__NR_ppoll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_in(&timeout_spec, sizeof(struct timespec)), proxy_value(0), proxy_value(0));
			}
#endif
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_poll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_value(timeout)));
		default:
			unknown_target();
	}
}

intptr_t remote_ppoll(struct pollfd *fds, nfds_t nfds, struct timespec *timeout)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_ppoll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), timeout != NULL ? proxy_inout(timeout, sizeof(struct timespec)) : proxy_value(0), proxy_value(0), proxy_value(0));
		default:
			unknown_target();
	}
}

__attribute__((noinline))
intptr_t invalid_remote_operation(void)
{
	return -EINVAL;
}
