#ifndef SEARCH_H
#define SEARCH_H

#include <stdbool.h>
#include <linux/limits.h>
#include <limits.h>
#include <unistd.h>

// open_executable_in_paths looks for an executable file matching name in paths
__attribute__((warn_unused_result))
int open_executable_in_paths(const char *name, const char *paths, bool require_executable, uid_t uid, gid_t gid);

// find_executable_in_paths looks for an executable file matching name in paths
__attribute__((warn_unused_result))
int find_executable_in_paths(const char *name, const char *paths, bool require_executable, uid_t uid, gid_t gid, char buf[PATH_MAX], const char **out_path);

#endif
