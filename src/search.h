#ifndef SEARCH_H
#define SEARCH_H

#include "axon.h"

#include <stdbool.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif
#include <limits.h>
#include <unistd.h>

// open_executable_in_paths looks for an executable file matching name in paths
__attribute__((warn_unused_result))
int open_executable_in_paths(const char *name, const char *paths, bool require_executable, uid_t uid, gid_t gid);

// find_executable_in_paths looks for an executable file matching name in paths
__attribute__((warn_unused_result))
int find_executable_in_paths(const char *name, const char *paths, bool require_executable, uid_t uid, gid_t gid, char buf[PATH_MAX], const char **out_path);

// apply_sysroot applies a sysroot to an absolute path to get a real absolute path
static inline const char *apply_sysroot(const char *sysroot, const char *path, char buf[PATH_MAX])
{
	if (LIKELY(path == NULL || *path != '/' || sysroot == NULL)) {
		return path;
	}
	size_t sysroot_len = fs_strlen(sysroot);
	size_t path_len = fs_strlen(path);
	if (sysroot_len + path_len + 1 > PATH_MAX) {
		DIE("adding sysroot to path exceeds path maximum", path);
	}
	fs_memcpy(buf, sysroot, sysroot_len);
	fs_memcpy(&buf[sysroot_len], path, path_len);
	return buf;
}


#endif
