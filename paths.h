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

__attribute__((warn_unused_result))
int fixup_exe_open(int dfd, const char *filename, int flags);

typedef struct {
	int fd;
	const char *path;
} path_info;

__attribute__((warn_unused_result))
bool lookup_real_path(int fd, const char *path, path_info *out_path);

#endif
