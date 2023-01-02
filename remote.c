#include "remote.h"

#include "darwin.h"
#include "freestanding.h"
#include "axon.h"
#include "proxy.h"

#include <string.h>

intptr_t remote_openat(int dirfd, const char *path, int flags, mode_t mode)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_openat, proxy_value(dirfd), proxy_string(path), proxy_value(flags), proxy_value(mode));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_openat, proxy_value(translate_at_fd_to_darwin(dirfd)), proxy_string(path), proxy_value(translate_open_flags_to_darwin(flags)), proxy_value(mode)));
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
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			return PROXY_CALL(__NR_read, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_read, proxy_value(fd), proxy_out(buf, bufsz), proxy_value(bufsz)));
		default:
			unknown_target();
	}
}

intptr_t remote_write(int fd, const char *buf, size_t bufsz)
{
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
			return 0;
		default:
			unknown_target();
	}
}

intptr_t remote_pread(int fd, void *buf, size_t count, off_t offset)
{
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

void remote_close(int fd)
{
	switch (proxy_get_target_platform()) {
		case TARGET_PLATFORM_LINUX:
			PROXY_SEND(__NR_close | PROXY_NO_RESPONSE, proxy_value(fd));
			break;
		case TARGET_PLATFORM_DARWIN:
			PROXY_SEND(DARWIN_SYS_close | PROXY_NO_RESPONSE, proxy_value(fd));
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
			return PROXY_CALL(__NR_fcntl | PROXY_NO_WORKER, proxy_value(fd), proxy_value(cmd), proxy_inout(lock, sizeof(struct flock)));
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
			return PROXY_CALL(__NR_fstat, proxy_value(fd), proxy_out(buf, sizeof(*buf)));
		case TARGET_PLATFORM_DARWIN: {
			struct darwin_stat dstat;
			intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fstat, proxy_value(fd), proxy_out(&dstat, sizeof(struct darwin_stat))));
			if (result >= 0) {
				*buf = translate_darwin_stat(dstat);
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
			return PROXY_CALL(__NR_newfstatat, proxy_value(fd), proxy_string(path), proxy_out(stat, sizeof(struct fs_stat)), proxy_value(flags));
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
	if (proxy_get_target_platform() == TARGET_PLATFORM_DARWIN) {
		if (size < 1024) {
			DIE("expected at least 1024 byte buffer", (int)size);
		}
		intptr_t result = translate_darwin_result(PROXY_CALL(DARWIN_SYS_fcntl, proxy_value(fd), proxy_value(DARWIN_F_GETPATH), proxy_out(buf, size)));
		if (result >= 0) {
			return fs_strlen(buf);
		}
		return result;
	} else {
		// readlink the fd remotely
		char dev_path[64];
		memcpy(dev_path, DEV_FD, sizeof(DEV_FD) - 1);
		fs_utoa(fd, &dev_path[sizeof(DEV_FD) - 1]);
		return remote_readlinkat(AT_FDCWD, dev_path, buf, size);
	}
}

intptr_t remote_getdents64(int fd, char *buf, size_t size)
{
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
		default:
			unknown_target();
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
			return PROXY_CALL(__NR_poll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_value(timeout));
		case TARGET_PLATFORM_DARWIN:
			return translate_darwin_result(PROXY_CALL(DARWIN_SYS_poll, proxy_inout(fds, sizeof(struct pollfd) * nfds), proxy_value(nfds), proxy_value(timeout)));
		default:
			unknown_target();
	}
}
