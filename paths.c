#include "paths.h"

#include "fd_table.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

__attribute__((warn_unused_result))
bool lookup_real_path(int fd, const char *path, path_info *out_path)
{
	if (path != NULL) {
		if (path[0] == '/') {
			if (path[1] == 't' && path[2] == 'a' && path[3] == 'r'
				&& path[4] == 'g' && path[5] == 'e' && path[6] == 't')
			{
				if (path[7] == '/') {
					*out_path = (path_info){
						.fd = AT_FDCWD,
						.path = &path[7],
					};
					return true;
				}
				if (path[7] == '\0') {
					*out_path = (path_info){
						.fd = AT_FDCWD,
						.path = "/",
					};
					return true;
				}
			}
			out_path->fd = AT_FDCWD;
			out_path->path = path;
			return false;
		}
		out_path->path = path;
		if (fd == AT_FDCWD) {
			if (lookup_real_fd(CWD_FD, &out_path->fd)) {
				return true;
			}
			out_path->fd = AT_FDCWD;
			return false;
		}
		return lookup_real_fd(fd, &out_path->fd);
	}
	out_path->path = NULL;
	return lookup_real_fd(fd, &out_path->fd);
}
