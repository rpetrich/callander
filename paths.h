#ifndef PATHS_H
#define PATHS_H

#include "freestanding.h"
#include "axon.h"

#include <limits.h>
#include <string.h>

#define DEV_FD "/proc/self/fd/"

enum special_path_type {
	SPECIAL_PATH_TYPE_NONE,
	SPECIAL_PATH_TYPE_EXE,
	SPECIAL_PATH_TYPE_MEM,
};

__attribute__((warn_unused_result))
static inline enum special_path_type special_path_type(const char *filename) {
	if (filename == NULL) {
		return SPECIAL_PATH_TYPE_NONE;
	}
	size_t len = fs_strlen(filename);
	if (len < 3 || (len > 3 && filename[len - 4] != '/')) {
		return SPECIAL_PATH_TYPE_NONE;
	}
	if (fs_strcmp(filename + len - 3, "exe") == 0) {
		return SPECIAL_PATH_TYPE_EXE;
	}
	if (fs_strcmp(filename + len - 3, "mem") == 0) {
		return SPECIAL_PATH_TYPE_MEM;
	}
	return SPECIAL_PATH_TYPE_NONE;
}

static inline int fixup_exe_open(int dfd, const char *filename, int flags) {
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

typedef struct {
	int fd;
	const char *path;
} path_info;

__attribute__((warn_unused_result))
bool lookup_real_path(int fd, const char *path, path_info *out_path);

#endif
