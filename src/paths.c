#include "paths.h"

#include "fd_table.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

__attribute__((warn_unused_result)) int fixup_exe_open(int dfd, const char *filename, int flags)
{
	char path[PATH_MAX];
	size_t len = fs_strlen(filename);
	fs_memcpy(path, filename, len - 3);
	path[len - 3] = 'f';
	path[len - 2] = 'd';
	path[len - 1] = '/';
	fs_utoa(MAIN_FD, &path[len]);
	int result = fs_openat(dfd, path, flags, 0);
	if (result >= 0) {
		return result;
	}
	if ((flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_RDONLY) {
		return fs_fcntl(MAIN_FD, flags & O_CLOEXEC ? F_DUPFD_CLOEXEC : F_DUPFD, 0);
	}
	memcpy(path, DEV_FD, sizeof(DEV_FD) - 1);
	fs_utoa(MAIN_FD, &path[sizeof(DEV_FD) - 1]);
	return fs_open(path, flags, 0);
}

__attribute__((warn_unused_result)) bool lookup_real_path(int fd, const char *path, path_info *out_path)
{
	if (path != NULL) {
		if (path[0] == '/') {
			if (path[1] == 't' && path[2] == 'a' && path[3] == 'r' && path[4] == 'g' && path[5] == 'e' && path[6] == 't') {
				if (path[7] == '/') {
					*out_path = (path_info){
						.handle = AT_FDCWD,
						.path = &path[7],
					};
					return true;
				}
				if (path[7] == '\0') {
					*out_path = (path_info){
						.handle = AT_FDCWD,
						.path = "/",
					};
					return true;
				}
			}
			out_path->handle = AT_FDCWD;
			out_path->path = path;
			return false;
		}
		out_path->path = path;
		if (fd == AT_FDCWD) {
			if (lookup_real_fd(CWD_FD, &out_path->handle)) {
				return true;
			}
			out_path->handle = AT_FDCWD;
			return false;
		}
		return lookup_real_fd(fd, &out_path->handle);
	}
	out_path->path = NULL;
	return lookup_real_fd(fd, &out_path->handle);
}
