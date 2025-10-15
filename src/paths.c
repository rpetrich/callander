#include "paths.h"

#include "fd_table.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "vfs.h"

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
	fs_memcpy(path, DEV_FD, sizeof(DEV_FD) - 1);
	fs_utoa(MAIN_FD, &path[sizeof(DEV_FD) - 1]);
	return fs_open(path, flags, 0);
}

__attribute__((warn_unused_result)) bool lookup_real_path(int fd, const char *path, path_info *out_path)
{
	return lookup_potential_mount_path("/target", sizeof("/target")-1, fd, path, out_path);
}
