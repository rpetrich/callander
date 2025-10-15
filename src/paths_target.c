#include "paths.h"

#include "fd_table.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

__attribute__((warn_unused_result)) int fixup_exe_open(int dfd, const char *filename, int flags)
{
	// TODO: fixup /proc/self/exe for target opens
	(void)dfd;
	(void)filename;
	(void)flags;
	return -EACCES;
}

__attribute__((warn_unused_result)) bool lookup_real_path(int fd, const char *path, path_info *out_path)
{
	if (path != NULL) {
		if (path[0] == '/') {
			if (fs_strncmp(path, "/target", sizeof("/target")-1) == 0) {
				if (path[sizeof("/target")-1] == '/') {
					*out_path = (path_info){
						.handle = AT_FDCWD,
						.path = &path[sizeof("/target")-1],
					};
					return false;
				}
				if (path[sizeof("/target")-1] == '\0') {
					*out_path = (path_info){
						.handle = AT_FDCWD,
						.path = "/",
					};
					return false;
				}
			}
			out_path->handle = AT_FDCWD;
			out_path->path = path;
			return true;
		}
		out_path->path = path;
		return lookup_real_fd(fd == AT_FDCWD ? CWD_FD : fd, &out_path->handle);
	}
	out_path->path = NULL;
	return lookup_real_fd(fd, &out_path->handle);
}
